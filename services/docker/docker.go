package docker

/*
Docker 蜜罐服务（TCP 2375，Docker Engine API，JSON over HTTP，明文）。
参考文档：(并未实现完全)
https://docs.docker.com/reference/api/engine/version/v1.56/

低交互策略：
  - 用标准库解析 HTTP 请求（请求行/首部/body），keep-alive 循环，空闲超时后关闭。
  - 响应为手写 JSON（不引入第三方依赖），覆盖攻击者最常打的端点：
    /version、/info、/_ping、/system/df、/containers/json、/images/json、容器/镜像 inspect、
    /containers/create|start|stop|restart|kill|pause、/images/create（POST 拉取，流式 NDJSON）、
    /images/{name}/history（层历史）、/images/get 与 /images/{name}/get（tar 流）、
    /containers/{id}/export（tar 流）、/swarm（非 manager 503）、
    /networks（list/create/inspect/connect/disconnect/delete）、
    /volumes（list/create/inspect/delete）、各类删除。
  - 方法门控与真机一致：/containers/json、/images/json、/networks、/volumes 仅 GET；
    /containers/create、/images/create、/networks/create、/volumes/create 仅 POST，
    其余方法回 page not found。
  - 状态与时间自洽：start/stop/kill/pause 真实改写容器状态并记录 started/finished 时间戳，
    Status 按当前时间动态生成（Up X ago / Exited (N) X ago / Up X (Paused)）；
    预置容器的创建/启动时间错开，各容器 Up 时长不一（真机形态）。
  - 镜像先登记、容器再按 repo:tag 关联 imageID，`docker ps` 的 ImageID 与 `docker images` 的 Id 对得上；
    预置网络 bridge/host/none + 自定义网络、预置卷，容器默认挂 bridge。
  - 层 ID 在镜像登记时固化，inspect/history/save 多次查询一致；每个网络独立子网
    （bridge 172.17.0.0/16 起），容器 IP/PID/MAC/EndpointID 登记后不变，
    inspect 与 /networks 看到的始终是同一份数据。
  - 容器/镜像引用按真机规则解析：完整 id、id 前缀（唯一）、名称（容器可省略前导 /）、repo:tag；
    列表支持 ?filters= 与 all 参数；create 校验 Image 必填、镜像本地存在、名称合法，
    未指定名称时自动生成 adjective_surname 形式的名字。
  - 按镜像画像派生 Command/Args/Env/端口/进程列表（nginx/redis/mysql/mariadb/postgres/
    busybox/alpine），不同镜像的容器不共用一份硬编码值。
  - 版本指纹不写死：yaml 可配 api_version / version / min_api_version / experimental；
    二者都留空则回落默认构建（26.1.3 / 1.45）。/version 结构与真机一致
    （Platform + Components[Engine/containerd/runc/docker-init] + Experimental）。
  - 预置诱饵容器/镜像可在 yaml 配置（containers: name/image/state、images: repo/tag），
    二者都留空则回落内置默认（web/nginx + redis），看起来像真在跑业务；攻击者自己
    create 的容器也会被真实登记，后续 inspect/start 都能命中，自洽难识别。
  - 无认证：不校验任何凭证，Authorization 头原样落事件（暴露未授权访问与 Token 试探）。
  - 未知端点回 Docker 风格 404 JSON（{"message": "..."}），保持指纹一致。
  - 事件 docker-connect / docker-request / docker-close；docker-request 含
    method/url/path/query/host/user-agent/content-length/body/authorization 与
    解析出的 auth_username/auth_password，均带 docker.session-id(xid)。
*/

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"

	"github.com/rs/xid"
)

const (
	defaultAPIVersion    = "1.45"
	defaultMinAPIVersion = "1.24"
	defaultVersion       = "26.1.3"
	defaultGoVersion     = "go1.22.2"
	defaultContainerd    = "1.7.24"
	defaultRunc          = "1.1.12"
	defaultDockerInit    = "0.19.0"
	defaultKernel        = "5.4.0-216-generic"
	defaultBuildTime     = "2024-10-14T22:06:01.000000000+00:00"

	defaultHostname      = "docker-host"
	defaultOS            = "Ubuntu 22.04.3 LTS"
	defaultOSVersion     = "22.04"
	defaultArch          = "amd64"
	defaultNCPU          = 4
	defaultMemTotal      = int64(8370600960)
	defaultDockerRootDir = "/var/lib/docker"
	defaultCgroupDriver  = "systemd"
	defaultCgroupVersion = "2"
	defaultRuntime       = "runc"
	defaultStorageDriver = "overlay2"
	defaultBackingFS     = "extfs"
	defaultLoggingDriver = "json-file"
	defaultIndexServer   = "https://index.docker.io/v1/"

	maxBody         = 1 << 20
	containerIDLen  = 64
	defaultPullPace = 250 * time.Millisecond // pull/build 流的默认帧间隔
)

// defaultIdleTimeout 单连接空闲超时（yaml idle_timeout_sec 可覆盖）。
const defaultIdleTimeout = 300 * time.Second

var (
	serviceName        = "docker-api"
	_                  = services.Register(serviceName, DockerServiceInit)
	serverVersion      atomic.Value // 当前实例版本（string），响应头用，与 /version 一致
	serverAPIVersion   atomic.Value // 当前实例 API 版本（string），Api-Version 响应头用
	serverExperimental atomic.Bool  // 当前实例 experimental 开关，响应头用
	serverInfoID       atomic.Value // 守护进程 ID（string），一次运行内稳定，与真机 docker info 的 ID 一致
)

func DockerServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   dockerHandle,
		ServiceOptions: dockerConfig{store: newDockerStore()},
	}
}

// dockerConfig 协议专属配置。留空均回退内置默认值。
// 这里列出的是"随主机而变"的指纹/环境（版本细节、内核、主机名、资源、
// 存储驱动、种子网络与卷、空闲超时）；每镜像的进程/端口/大小等真实感
// 数据仍内置在代码里（见 services_conf/docker.yaml 的说明）。
type dockerConfig struct {
	store         *dockerStore
	APIVersion    string                  `mapstructure:"api_version"`
	Version       string                  `mapstructure:"version"`
	MinAPIVersion string                  `mapstructure:"min_api_version"`
	Experimental  bool                    `mapstructure:"experimental"`
	Containers    []dockerContainerConfig `mapstructure:"containers"`
	Images        []dockerImageConfig     `mapstructure:"images"`
	Networks      []dockerNetworkConfig   `mapstructure:"networks"`
	Volumes       []dockerVolumeConfig    `mapstructure:"volumes"`
	PullPaceMS    *int                    `mapstructure:"pull_pace_ms"`     // 拉取/构建流的帧间隔毫秒数；0=瞬时（测试用），留空=默认
	IdleTimeoutS  int                     `mapstructure:"idle_timeout_sec"` // 单连接空闲超时秒数，默认 300

	// 版本指纹细节（/version 的 Components 与 /info 共用）
	KernelVersion     string `mapstructure:"kernel_version"`
	GoVersion         string `mapstructure:"go_version"`
	ContainerdVersion string `mapstructure:"containerd_version"`
	RuncVersion       string `mapstructure:"runc_version"`
	DockerInitVersion string `mapstructure:"docker_init_version"`
	BuildTime         string `mapstructure:"build_time"`

	// 主机身份与资源（/info）
	Hostname        string   `mapstructure:"hostname"`
	OperatingSystem string   `mapstructure:"operating_system"`
	OSVersion       string   `mapstructure:"os_version"`
	Architecture    string   `mapstructure:"architecture"`
	NCPU            int      `mapstructure:"ncpu"`
	MemTotal        int64    `mapstructure:"mem_total"`
	DockerRootDir   string   `mapstructure:"docker_root_dir"`
	CgroupDriver    string   `mapstructure:"cgroup_driver"`
	CgroupVersion   string   `mapstructure:"cgroup_version"`
	DefaultRuntime  string   `mapstructure:"default_runtime"`
	StorageDriver   string   `mapstructure:"storage_driver"`
	BackingFS       string   `mapstructure:"backing_filesystem"`
	SecurityOptions []string `mapstructure:"security_options"`
}

// dockerNetworkConfig 预置的额外网络（bridge/host/none 始终存在）。
type dockerNetworkConfig struct {
	Name     string `mapstructure:"name"`
	Driver   string `mapstructure:"driver"`
	Internal bool   `mapstructure:"internal"`
}

// dockerVolumeConfig 预置卷。
type dockerVolumeConfig struct {
	Name   string `mapstructure:"name"`
	Driver string `mapstructure:"driver"`
}

// pullPace 拉取/构建流的帧间隔。真机的 pull 是秒级过程，一次性刷完很假；
// 配置 pull_pace_ms: 0 可关闭（测试用）。
func (c dockerConfig) pullPace() time.Duration {
	if c.PullPaceMS != nil {
		return time.Duration(*c.PullPaceMS) * time.Millisecond
	}
	return defaultPullPace
}

// strOr 空串回落默认值。
func strOr(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func (c dockerConfig) idleTimeout() time.Duration {
	if c.IdleTimeoutS > 0 {
		return time.Duration(c.IdleTimeoutS) * time.Second
	}
	return defaultIdleTimeout
}

func (c dockerConfig) kernelVersion() string { return strOr(c.KernelVersion, defaultKernel) }
func (c dockerConfig) goVersion() string     { return strOr(c.GoVersion, defaultGoVersion) }
func (c dockerConfig) containerdVersion() string {
	return strOr(c.ContainerdVersion, defaultContainerd)
}
func (c dockerConfig) runcVersion() string { return strOr(c.RuncVersion, defaultRunc) }
func (c dockerConfig) dockerInitVersion() string {
	return strOr(c.DockerInitVersion, defaultDockerInit)
}
func (c dockerConfig) buildTime() string       { return strOr(c.BuildTime, defaultBuildTime) }
func (c dockerConfig) hostname() string        { return strOr(c.Hostname, defaultHostname) }
func (c dockerConfig) operatingSystem() string { return strOr(c.OperatingSystem, defaultOS) }
func (c dockerConfig) osVersion() string       { return strOr(c.OSVersion, defaultOSVersion) }
func (c dockerConfig) architecture() string    { return strOr(c.Architecture, defaultArch) }
func (c dockerConfig) dockerRootDir() string   { return strOr(c.DockerRootDir, defaultDockerRootDir) }
func (c dockerConfig) cgroupDriver() string    { return strOr(c.CgroupDriver, defaultCgroupDriver) }
func (c dockerConfig) cgroupVersion() string   { return strOr(c.CgroupVersion, defaultCgroupVersion) }
func (c dockerConfig) defaultRuntime() string  { return strOr(c.DefaultRuntime, defaultRuntime) }
func (c dockerConfig) storageDriver() string   { return strOr(c.StorageDriver, defaultStorageDriver) }
func (c dockerConfig) backingFS() string       { return strOr(c.BackingFS, defaultBackingFS) }

func (c dockerConfig) ncpu() int {
	if c.NCPU > 0 {
		return c.NCPU
	}
	return defaultNCPU
}

func (c dockerConfig) memTotal() int64 {
	if c.MemTotal > 0 {
		return c.MemTotal
	}
	return defaultMemTotal
}

func (c dockerConfig) securityOptions() []string {
	if len(c.SecurityOptions) > 0 {
		return c.SecurityOptions
	}
	return []string{"name=apparmor", "name=seccomp,profile=builtin"}
}

// infoArch 真机 /info 的 Architecture 用 goarch 别名（amd64 -> x86_64）。
func (c dockerConfig) infoArch() string {
	switch a := c.architecture(); a {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return a
	}
}

// dockerContainerConfig 预置诱饵容器（yaml 可配，留空用内置默认）。
type dockerContainerConfig struct {
	Name  string `mapstructure:"name"`
	Image string `mapstructure:"image"`
	State string `mapstructure:"state"` // running / exited / created，默认 running
}

// dockerImageConfig 预置诱饵镜像（yaml 可配，留空用内置默认）。
type dockerImageConfig struct {
	Repo string `mapstructure:"repo"`
	Tag  string `mapstructure:"tag"`
}

func (c dockerConfig) apiVersion() string {
	if c.APIVersion != "" {
		return c.APIVersion
	}
	return defaultAPIVersion
}

func (c dockerConfig) version() string {
	if c.Version != "" {
		return c.Version
	}
	return defaultVersion
}

func (c dockerConfig) minAPIVersion() string {
	if c.MinAPIVersion != "" {
		return c.MinAPIVersion
	}
	return defaultMinAPIVersion
}

// humanDuration 模仿 Docker units.HumanDuration，把时长转成 "3 hours" 这类字符串。
func humanDuration(d time.Duration) string {
	if seconds := int(d.Seconds()); seconds < 1 {
		return "Less than a second"
	} else if seconds == 1 {
		return "1 second"
	} else if seconds < 60 {
		return fmt.Sprintf("%d seconds", seconds)
	} else if minutes := int(d.Minutes()); minutes == 1 {
		return "About a minute"
	} else if minutes < 60 {
		return fmt.Sprintf("%d minutes", minutes)
	} else if hours := int(d.Hours() + 0.5); hours == 1 {
		return "About an hour"
	} else if hours < 48 {
		return fmt.Sprintf("%d hours", hours)
	} else if hours < 24*7*2 {
		return fmt.Sprintf("%d days", hours/24)
	} else if hours < 24*30*2 {
		return fmt.Sprintf("%d weeks", hours/24/7)
	} else if hours < 24*365*2 {
		return fmt.Sprintf("%d months", hours/24/30)
	}
	return fmt.Sprintf("%d years", int(d.Hours())/24/365)
}

// humanBytes 模仿 Docker 的十进制体积显示（1024 B -> 1.02 kB）。
func humanBytes(b int) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := unit, 0
	for n := b / unit; n >= unit && exp < 3; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.3f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}

// splitRepoTag 把 "nginx:latest"/"nginx"/"localhost:5000/a:b" 拆成 repo/tag。
func splitRepoTag(image string) (repo, tag string) {
	image = strings.TrimSpace(image)
	if image == "" {
		return "", "latest"
	}
	if i := strings.LastIndex(image, ":"); i > strings.LastIndex(image, "/") {
		return image[:i], image[i+1:]
	}
	return image, "latest"
}

// ---- 数据存储（真实登记容器/镜像，使 create -> inspect/start 自洽）----

type dockerContainer struct {
	id         string
	name       string
	image      string // repo:tag
	imageID    string // 关联 images 里的镜像 id
	state      string
	exitCode   int
	created    int64
	startedAt  int64
	finishedAt int64
	pid        int               // 宿主可见 PID（仅运行中有值）
	endpointID string            // 网络端点 ID（64 hex，一次运行内稳定）
	netIPs     map[string]string // 网络名 -> 该网络内的 IP（bridge: 172.17.0.x 等）
}

// statusString 按当前时间动态生成 Docker 风格 Status（Up X ago / Exited (N) X ago）。
func (c *dockerContainer) statusString() string {
	now := time.Now()
	switch c.state {
	case "running":
		return "Up " + humanDuration(now.Sub(time.Unix(c.startedAt, 0)))
	case "paused":
		return "Up " + humanDuration(now.Sub(time.Unix(c.startedAt, 0))) + " (Paused)"
	case "restarting":
		return "Restarting (1) Less than a second ago"
	case "exited", "dead":
		return fmt.Sprintf("Exited (%d) %s ago", c.exitCode, humanDuration(now.Sub(time.Unix(c.finishedAt, 0))))
	default: // created
		return "Created"
	}
}

type dockerImage struct {
	id        string
	repo      string
	tag       string
	created   int64
	digest    string
	size      int64    // 磁盘占用（字节），按镜像类型取基准 ± 抖动，与真机量级一致
	layers    []string // 固化的层 ID（sha256:...），查询/历史/导出共用，保证同一镜像多次查询一致
	extraTags []string // 主标签之外的 repo:tag（docker tag 产生，同一镜像 ID 多标签）
}

func (i *dockerImage) ref() string { return i.repo + ":" + i.tag }

// tags 返回镜像的全部引用（主标签在前，与真机 RepoTags 一致）。
func (i *dockerImage) tags() []string {
	out := make([]string, 0, 1+len(i.extraTags))
	out = append(out, i.ref())
	out = append(out, i.extraTags...)
	return out
}

// isImageAction 判断 /images/{name}/<action> 的最后一段是否为已知动作
// （名称可能带 registry/命名空间，不能按第一个 / 切）。
func isImageAction(a string) bool {
	switch a {
	case "json", "history", "get", "export", "push", "tag":
		return true
	}
	return false
}

// imageProfile 按镜像类型给出可信的进程/端口/环境变量画像。历史上容器详情、
// ps 列表、top、stats 全是硬编码的 nginx 值，redis/mysql 容器会露出马脚，
// 现在统一按 repo 派生。
type imageProfile struct {
	entrypoint string            // inspect 的 Path
	args       []string          // inspect 的 Args
	command    string            // ps / system.df 列表里的 Command
	env        []string          // inspect Config.Env
	exposed    []string          // inspect Config.ExposedPorts 的键（如 "80/tcp"）
	published  map[string]string // 私有端口号 -> 宿主端口号（-p 发布过的）
	pids       int               // stats pids_stats.current
	top        [][]string        // top 进程行（Titles 固定 8 列）
}

var imageProfiles = map[string]imageProfile{
	"nginx": {
		entrypoint: "/docker-entrypoint.sh",
		args:       []string{"nginx", "-g", "daemon off;"},
		command:    "nginx -g 'daemon off;'",
		env: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"NGINX_VERSION=1.25.3",
			"NJS_VERSION=0.8.2",
			"PKG_RELEASE=1",
		},
		exposed:   []string{"80/tcp"},
		published: map[string]string{"80": "8080"},
		pids:      3,
		top: [][]string{
			{"root", "1", "0", "0", "17:00", "?", "00:00:01", "nginx: master process nginx -g daemon off;"},
			{"nginx", "29", "1", "0", "17:00", "?", "00:00:00", "nginx: worker process"},
			{"nginx", "30", "1", "0", "17:00", "?", "00:00:00", "nginx: worker process"},
		},
	},
	"redis": {
		entrypoint: "docker-entrypoint.sh",
		args:       []string{"redis-server"},
		command:    "redis-server",
		env: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"REDIS_VERSION=7.0.15",
			"REDIS_DOWNLOAD_URL=redis:7.0.15",
		},
		exposed: []string{"6379/tcp"},
		pids:    5,
		top: [][]string{
			{"redis", "1", "0", "0", "17:00", "?", "00:00:02", "redis-server *:6379"},
		},
	},
	"mysql": {
		entrypoint: "docker-entrypoint.sh",
		args:       []string{"mysqld"},
		command:    "mysqld",
		env: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"GOSU_VERSION=1.16",
			"MYSQL_MAJOR=8.0",
			"MYSQL_VERSION=8.0.36-1.el8",
		},
		exposed: []string{"3306/tcp", "33060/tcp"},
		pids:    41,
		top: [][]string{
			{"mysql", "1", "0", "0", "17:00", "?", "00:00:03", "mysqld"},
		},
	},
	"mariadb": {
		entrypoint: "docker-entrypoint.sh",
		args:       []string{"mysqld"},
		command:    "mysqld",
		env: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"MARIADB_VERSION=11.1.2",
		},
		exposed: []string{"3306/tcp"},
		pids:    38,
		top: [][]string{
			{"mysql", "1", "0", "0", "17:00", "?", "00:00:03", "mysqld"},
		},
	},
	"postgres": {
		entrypoint: "docker-entrypoint.sh",
		args:       []string{"postgres"},
		command:    "postgres",
		env: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"PG_VERSION=16.1",
			"PG_DATA=/var/lib/postgresql/data",
		},
		exposed: []string{"5432/tcp"},
		pids:    6,
		top: [][]string{
			{"postgres", "1", "0", "0", "17:00", "?", "00:00:01", "postgres"},
			{"postgres", "66", "1", "0", "17:00", "?", "00:00:00", "postgres: checkpointer"},
		},
	},
	"busybox": {
		args:    []string{"sh"},
		command: "sh",
		env: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		},
		pids: 1,
		top: [][]string{
			{"root", "1", "0", "0", "17:00", "?", "00:00:00", "sh"},
		},
	},
	"alpine": {
		args:    []string{"/bin/sh"},
		command: "/bin/sh",
		env: []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		},
		pids: 1,
		top: [][]string{
			{"root", "1", "0", "0", "17:00", "?", "00:00:00", "/bin/sh"},
		},
	},
}

// defaultImageProfile 未知镜像的兜底画像（通用 Linux 容器形态）。
var defaultImageProfile = imageProfile{
	entrypoint: "/bin/sh",
	args:       []string{"sh"},
	command:    "sh",
	env: []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	},
	pids: 1,
	top: [][]string{
		{"root", "1", "0", "0", "17:00", "?", "00:00:00", "sh"},
	},
}

// imageLayerCounts 常见官方镜像的层数（history 端点据此展开，量级真实）。
var imageLayerCounts = map[string]int{
	"nginx": 7, "redis": 3, "mysql": 8, "mariadb": 8, "postgres": 12,
	"busybox": 1, "alpine": 1,
}

// imageSizes 常见镜像的磁盘占用基准（字节，贴近真机 docker images 的 SIZE）。
var imageSizes = map[string]int64{
	"nginx":    187_000_000,
	"redis":    117_000_000,
	"mysql":    602_000_000,
	"mariadb":  401_000_000,
	"postgres": 432_000_000,
	"alpine":   7_300_000,
	"busybox":  4_260_000,
	"debian":   124_000_000,
	"ubuntu":   78_000_000,
	"python":   132_000_000,
	"node":     1_100_000_000,
	"httpd":    148_000_000,
	"mongo":    750_000_000,
}

// imageSizeFor 按镜像类型给出磁盘占用：已知镜像用基准值 ±8% 抖动，
// 未知镜像在 40MB ~ 1.2GB 内随机取（真机各镜像 SIZE 各不相同，
// 全部固定 150MB 一眼假）。
func imageSizeFor(repo string) int64 {
	base := repo
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if size, ok := imageSizes[base]; ok {
		jitter := size * 8 / 100
		return size - jitter + randRange(0, 2*jitter)
	}
	return randRange(40_000_000, 1_200_000_001)
}

// randRange 返回 [min,max) 的随机数（crypto/rand，取 8 字节）。
func randRange(min, max int64) int64 {
	if max <= min {
		return min
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return min
	}
	v := int64(binary.BigEndian.Uint64(b[:]) & (1<<62 - 1))
	return min + v%(max-min)
}

// profileForImage 按 repo 末段取画像（兼容 library/nginx、registry:5000/a/b 形式）。
func profileForImage(image string) imageProfile {
	base := image
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.LastIndex(base, ":"); i >= 0 {
		base = base[:i]
	}
	if p, ok := imageProfiles[base]; ok {
		return p
	}
	return defaultImageProfile
}

// imageLayers 生成固化的层 ID 列表（同 repo 层数量级与真机接近）。
func imageLayers(repo string) []string {
	base := repo
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	n := imageLayerCounts[base]
	if n == 0 {
		n = 2
	}
	layers := make([]string, n)
	for i := range layers {
		layers[i] = "sha256:" + randomID()
	}
	return layers
}

type dockerNetwork struct {
	id         string
	name       string
	driver     string
	scope      string
	internal   bool
	created    int64
	subnet     int               // 第三段网关基号：bridge=17 -> 172.17.0.0/16，自定义网络依次 18/19...
	nextIP     int               // 下一个待分配 IPv4 末字节（从 2 开始）
	containers map[string]string // 容器 id -> 容器 name
}

type dockerVolume struct {
	name       string
	driver     string
	mountpoint string
	created    int64
}

type dockerStore struct {
	mu              sync.Mutex
	containers      map[string]*dockerContainer
	images          map[string]*dockerImage
	networks        map[string]*dockerNetwork
	volumes         map[string]*dockerVolume
	execs           map[string]*dockerExec
	seeded          bool
	builderCacheID  string    // 构建缓存 ID，一次运行内稳定
	builderCacheUse time.Time // 构建缓存创建时间，一次运行内稳定
}

func newDockerStore() *dockerStore {
	return &dockerStore{
		containers: make(map[string]*dockerContainer),
		images:     make(map[string]*dockerImage),
		networks:   make(map[string]*dockerNetwork),
		volumes:    make(map[string]*dockerVolume),
		execs:      make(map[string]*dockerExec),
	}
}

// ensureSeeded 按 yaml 配置的容器/镜像预置诱饵（仅首次生效）；两者都留空则
// 回落内置默认（web/nginx + redis），看起来像真在跑业务。
// 镜像先登记、容器再按 repo:tag 关联 imageID，保证 `docker ps` 的 ImageID
// 与 `docker images` 的 Id 对得上。创建/启动时间按序号错开（真机上各容器
// 各自在不同时间创建、启动，Status 的 Up X 因此长短不一）。
func (s *dockerStore) ensureSeeded(cfg dockerConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seeded {
		return
	}
	s.seeded = true
	now := time.Now()

	// 1) 镜像先入库（创建时间错开，层 ID 固化）
	images := cfg.Images
	if len(images) == 0 {
		images = []dockerImageConfig{
			{Repo: "nginx", Tag: "latest"},
			{Repo: "redis", Tag: "7"},
		}
	}
	for i, ic := range images {
		s.putImageLockedAt(ic.Repo, ic.Tag, now.Add(-time.Duration(72+i*29)*time.Hour))
	}

	// 2) 预置网络：bridge/host/none 是 Docker 自带网络（始终存在），
	//    再按 yaml 的 networks 追加自定义网络（留空默认 potagent_default）。
	//    每个网络分配不同子网段：bridge=172.17.0.0/16，其后 172.18/172.19...
	subnet := 17
	for _, nc := range []struct{ name, driver string }{
		{"bridge", "bridge"},
		{"host", "host"},
		{"none", "null"},
	} {
		id := randomID()
		s.networks[id] = &dockerNetwork{
			id: id, name: nc.name, driver: nc.driver, scope: "local",
			created: now.Add(-3 * time.Hour).Unix(), subnet: subnet, nextIP: 2,
			containers: map[string]string{},
		}
		subnet++
	}
	customNets := cfg.Networks
	if len(customNets) == 0 {
		customNets = []dockerNetworkConfig{{Name: "potagent_default", Driver: "bridge"}}
	}
	for _, nc := range customNets {
		name := strings.TrimSpace(nc.Name)
		if name == "" || s.networkByNameLocked(name) != nil {
			continue
		}
		driver := strOr(nc.Driver, "bridge")
		id := randomID()
		s.networks[id] = &dockerNetwork{
			id: id, name: name, driver: driver, scope: "local", internal: nc.Internal,
			created: now.Add(-3 * time.Hour).Unix(), subnet: subnet, nextIP: 2,
			containers: map[string]string{},
		}
		subnet++
	}
	// 3) 预置卷（yaml volumes 可配，留空默认 potagent-data / redis-data）
	vols := cfg.Volumes
	if len(vols) == 0 {
		vols = []dockerVolumeConfig{{Name: "potagent-data"}, {Name: "redis-data"}}
	}
	for _, vc := range vols {
		name := strings.TrimSpace(vc.Name)
		if name == "" {
			continue
		}
		s.volumes[name] = &dockerVolume{
			name: name, driver: strOr(vc.Driver, "local"),
			mountpoint: "/var/lib/docker/volumes/" + name + "/_data",
			created:    now.Add(-3 * time.Hour).Unix(),
		}
	}
	s.builderCacheID = "cache-" + randomID()[:12]
	s.builderCacheUse = now.Add(-48 * time.Hour)

	// 4) 容器（关联镜像 id，并挂到 bridge 网络，分配 IP/PID）
	containers := cfg.Containers
	if len(containers) == 0 {
		containers = []dockerContainerConfig{
			{Name: "web", Image: "nginx:latest", State: "running"},
			{Name: "redis", Image: "redis:7", State: "running"},
		}
	}
	bridge := s.networkByNameLocked("bridge")
	for i, cc := range containers {
		id := randomID()
		state := cc.State
		if state == "" {
			state = "running"
		}
		repo, tag := splitRepoTag(cc.Image)
		im := s.putImageLockedAt(repo, tag, now.Add(-time.Duration(72+i*29)*time.Hour))
		created := now.Add(-time.Duration(240-i*95) * time.Minute).Unix()
		c := &dockerContainer{
			id:         id,
			name:       "/" + strings.TrimPrefix(cc.Name, "/"),
			image:      im.ref(),
			imageID:    im.id,
			state:      state,
			created:    created,
			endpointID: randomID(),
			netIPs:     map[string]string{},
		}
		switch state {
		case "running":
			// 启动比创建晚几十秒，运行中的容器才有 IP 与 PID
			c.startedAt = created + int64(20+i*37)
			if bridge != nil {
				c.netIPs["bridge"] = s.assignIPLocked(bridge)
			}
			c.pid = 1200 + i*2713
		case "exited", "dead":
			c.finishedAt = created + int64(90+i*41)
		}
		s.containers[id] = c
		if bridge != nil {
			bridge.containers[id] = c.name
		}
	}
}

// assignIPLocked 从网络的子网里分配下一个空闲 IPv4（172.<subnet>.0.2 起），
// 跳过已被容器占用的地址；耗尽返回空串。调用方需持有锁。
func (s *dockerStore) assignIPLocked(n *dockerNetwork) string {
	used := map[string]bool{}
	for _, c := range s.containers {
		for _, ip := range c.netIPs {
			used[ip] = true
		}
	}
	for i := n.nextIP; i <= 254; i++ {
		ip := fmt.Sprintf("172.%d.0.%d", n.subnet, i)
		if !used[ip] {
			n.nextIP = i + 1
			return ip
		}
	}
	return ""
}

// listContainers 返回全部容器，按创建时间倒序（与真机 docker ps 一致），
// 创建时间相同按 id 兜底保证输出稳定。
func (s *dockerStore) listContainers() []*dockerContainer {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*dockerContainer, 0, len(s.containers))
	for _, c := range s.containers {
		out = append(out, c)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].created != out[b].created {
			return out[a].created > out[b].created
		}
		return out[a].id > out[b].id
	})
	return out
}

// resolveContainerLocked 按真机规则解析容器引用：完整 id -> id 前缀（唯一才命中）
// -> 名称（带或不带前导 /）。调用方需持有锁。
func (s *dockerStore) resolveContainerLocked(idOrName string) *dockerContainer {
	if c, ok := s.containers[idOrName]; ok {
		return c
	}
	if idOrName == "" {
		return nil
	}
	// id 前缀：多个匹配视为歧义，不解析（与真机一致，避免指错容器）
	var hit *dockerContainer
	hits := 0
	for _, c := range s.containers {
		if strings.HasPrefix(c.id, idOrName) {
			hits++
			hit = c
		}
	}
	if hits == 1 {
		return hit
	}
	if hits > 1 {
		return nil
	}
	// 名称：允许省略前导 /
	trimmed := strings.TrimPrefix(idOrName, "/")
	for _, c := range s.containers {
		if c.name == idOrName || c.name == "/"+trimmed {
			return c
		}
	}
	return nil
}

func (s *dockerStore) getContainer(id string) (*dockerContainer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.resolveContainerLocked(id)
	return c, c != nil
}

// createContainer 登记一个新容器。镜像必须已在本地存在（与真机一致：
// create 一个本地没有的镜像返回 404），容器与镜像的 imageID 精确关联。
// 返回最终 id；镜像不存在返回 ("", false)。
func (s *dockerStore) createContainer(name, image string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	im := s.findImageRefLocked(image)
	if im == nil {
		return "", false
	}
	id := randomID()
	s.containers[id] = &dockerContainer{
		id:         id,
		name:       name,
		image:      im.ref(),
		imageID:    im.id,
		state:      "created",
		created:    time.Now().Unix(),
		endpointID: randomID(),
		netIPs:     map[string]string{},
	}
	return id, true
}

func (s *dockerStore) deleteContainer(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.containers[id]; !ok {
		return false
	}
	delete(s.containers, id)
	return true
}

// setContainerState 修改容器运行状态与退出码，并记录 started/finished 时间戳，
// 使 Status 里的 "Up X ago"/"Exited (N) X ago" 随时间真实变化。
// 启动时分配 bridge 网络 IP 与宿主 PID（与 /networks 保持一致），停止时释放。
func (s *dockerStore) setContainerState(id, state string, exitCode int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.resolveContainerLocked(id)
	if c == nil {
		return false
	}
	c.state = state
	c.exitCode = exitCode
	now := time.Now().Unix()
	switch state {
	case "running":
		c.startedAt = now
		if c.netIPs == nil {
			c.netIPs = map[string]string{}
		}
		if _, ok := c.netIPs["bridge"]; !ok {
			if b := s.networkByNameLocked("bridge"); b != nil {
				c.netIPs["bridge"] = s.assignIPLocked(b)
			}
		}
		if c.pid == 0 {
			c.pid = 3000 + int(now%9000)
		}
	case "exited", "dead":
		c.finishedAt = now
		delete(c.netIPs, "bridge")
		c.pid = 0
	}
	return true
}

// containerNameExists 按名字（含前导 /）查是否已存在同名容器，返回其 id。
func (s *dockerStore) containerNameExists(name string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.containers {
		if c.name == name {
			return c.id, true
		}
	}
	return "", false
}

// renameContainer 容器改名，并同步各网络里登记的容器名。调用方需持有锁。
func (s *dockerStore) renameContainer(id, newName string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.containers[id]
	if !ok {
		return false
	}
	c.name = newName
	for _, n := range s.networks {
		if _, ok := n.containers[id]; ok {
			n.containers[id] = newName
		}
	}
	return true
}

// ---- exec 实例 ----

// dockerExec 一次 exec 会话（POST /containers/{id}/exec 创建）。
type dockerExec struct {
	id          string
	containerID string
	cmd         []string
}

// createExec 登记 exec 实例，返回实例 id；容器不存在返回 ("", false)。
func (s *dockerStore) createExec(containerID string, cmd []string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.resolveContainerLocked(containerID)
	if c == nil {
		return "", false
	}
	id := randomID()
	s.execs[id] = &dockerExec{id: id, containerID: c.id, cmd: cmd}
	return id, true
}

// getExec 按 id 查 exec 实例。
func (s *dockerStore) getExec(id string) (*dockerExec, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.execs[id]
	return e, ok
}

// listImages 返回全部镜像，按创建时间倒序（与真机 docker images 一致）。
func (s *dockerStore) listImages() []*dockerImage {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*dockerImage, 0, len(s.images))
	for _, i := range s.images {
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].created != out[b].created {
			return out[a].created > out[b].created
		}
		return out[a].id > out[b].id
	})
	return out
}

func (s *dockerStore) getImage(id string) (*dockerImage, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.images[id]
	return i, ok
}

func (s *dockerStore) deleteImage(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.images[id]; !ok {
		return false
	}
	delete(s.images, id)
	return true
}

// putImageLockedAt 登记镜像（同 repo:tag 复用），调用方需持有锁。
// 层 ID 在登记时一次性生成并固化，之后 inspect/history/get 多次查询完全一致。
func (s *dockerStore) putImageLockedAt(repo, tag string, created time.Time) *dockerImage {
	if repo == "" {
		repo, tag = "busybox", "latest"
	}
	if tag == "" {
		tag = "latest"
	}
	for _, im := range s.images {
		if im.repo == repo && im.tag == tag {
			return im
		}
	}
	im := &dockerImage{
		id:      randomID(),
		repo:    repo,
		tag:     tag,
		created: created.Unix(),
		digest:  "sha256:" + randomID(),
		size:    imageSizeFor(repo),
		layers:  imageLayers(repo),
	}
	s.images[im.id] = im
	return im
}

// addImage 登记一个新镜像（pull 时用），返回最终 id。
func (s *dockerStore) addImage(repo, tag string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putImageLockedAt(repo, tag, time.Now()).id
}

// commitImage 由容器提交生成新镜像（POST /commit），返回镜像 id。
func (s *dockerStore) commitImage(repo, tag string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	im := s.putImageLockedAt(repo, tag, time.Now())
	if im.layers == nil {
		im.layers = imageLayers(repo)
	}
	return im.id
}

// findImageRefLocked 按真机规则解析镜像引用：完整 id -> repo:tag -> repo(默认
// :latest) -> id 前缀（唯一才命中）。调用方需持有锁。
func (s *dockerStore) findImageRefLocked(ref string) *dockerImage {
	if ref == "" {
		return nil
	}
	if im, ok := s.images[ref]; ok {
		return im
	}
	for _, im := range s.images {
		if im.ref() == ref {
			return im
		}
		for _, t := range im.extraTags {
			if t == ref {
				return im
			}
		}
	}
	// "nginx" 这类省略 tag 的引用按 :latest 解析
	if !strings.Contains(ref, ":") && !strings.Contains(ref, "@") {
		for _, im := range s.images {
			if im.ref() == ref+":latest" {
				return im
			}
		}
	}
	// id 前缀：多个匹配视为歧义
	var hit *dockerImage
	hits := 0
	for id, im := range s.images {
		if strings.HasPrefix(id, ref) {
			hits++
			hit = im
		}
	}
	if hits == 1 {
		return hit
	}
	return nil
}

// getImageByName 按 id、repo:tag 或 id 前缀查找镜像。
func (s *dockerStore) getImageByName(name string) (*dockerImage, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	im := s.findImageRefLocked(name)
	return im, im != nil
}

// deleteImageByName 按 id、repo:tag 或 id 前缀删除镜像。与真机一致：
// 删附加标签只去掉该标签；删主标签时若还有附加标签则提升第一个，否则整条删除。
func (s *dockerStore) deleteImageByName(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	im := s.findImageRefLocked(name)
	if im == nil {
		return false
	}
	for i, t := range im.extraTags {
		if t == name {
			im.extraTags = append(im.extraTags[:i], im.extraTags[i+1:]...)
			return true
		}
	}
	if len(im.extraTags) > 0 {
		repo, tag := splitRepoTag(im.extraTags[0])
		im.repo, im.tag = repo, tag
		im.extraTags = im.extraTags[1:]
		return true
	}
	delete(s.images, im.id)
	return true
}

// tagImage 给镜像追加一个 repo:tag 引用（docker tag：同一镜像 ID 多标签）。
func (s *dockerStore) tagImage(id, repo, tag string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	im, ok := s.images[id]
	if !ok {
		return false
	}
	ref := repo + ":" + tag
	for _, t := range im.tags() {
		if t == ref {
			return true
		}
	}
	// 该引用已被别的镜像占用时不重复登记（真机会重新指向，蜜罐保持简单）
	if s.findImageRefLocked(ref) != nil {
		return true
	}
	im.extraTags = append(im.extraTags, ref)
	return true
}

// ---- 网络 / 卷 ----

func (s *dockerStore) listNetworks() []*dockerNetwork {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*dockerNetwork, 0, len(s.networks))
	for _, n := range s.networks {
		out = append(out, n)
	}
	return out
}

// networkByNameLocked 按名字查网络，调用方需持有锁。
func (s *dockerStore) networkByNameLocked(name string) *dockerNetwork {
	for _, n := range s.networks {
		if n.name == name {
			return n
		}
	}
	return nil
}

// getNetwork 按 id 或名字查网络。
func (s *dockerStore) getNetwork(idOrName string) (*dockerNetwork, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.networks[idOrName]; ok {
		return n, true
	}
	if n := s.networkByNameLocked(idOrName); n != nil {
		return n, true
	}
	return nil, false
}

func (s *dockerStore) createNetwork(name, driver string, internal bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if driver == "" {
		driver = "bridge"
	}
	if name == "" {
		name = "net-" + randomID()[:12]
	}
	// 新网络分配下一个空闲子网段（bridge=17 起，真机同样 172.18/172.19 递增）
	subnet := 17
	for _, n := range s.networks {
		if n.subnet >= subnet {
			subnet = n.subnet + 1
		}
	}
	id := randomID()
	s.networks[id] = &dockerNetwork{
		id: id, name: name, driver: driver, scope: "local", internal: internal,
		created: time.Now().Unix(), subnet: subnet, nextIP: 2,
		containers: map[string]string{},
	}
	return id
}

func (s *dockerStore) deleteNetwork(idOrName string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := ""
	if _, ok := s.networks[idOrName]; ok {
		id = idOrName
	} else if n := s.networkByNameLocked(idOrName); n != nil {
		id = n.id
	}
	if id == "" {
		return false
	}
	delete(s.networks, id)
	return true
}

// connectContainer 把容器接入网络；network/container 任一不存在返回 false。
// 容器引用支持 id/前缀/名称；接入时在该网络子网内分配 IP（与 inspect 一致）。
func (s *dockerStore) connectContainer(idOrName, containerID string) (*dockerNetwork, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.networks[idOrName]
	if !ok {
		n = s.networkByNameLocked(idOrName)
	}
	if n == nil {
		return nil, false
	}
	c := s.resolveContainerLocked(containerID)
	if c == nil {
		return nil, false
	}
	if n.containers == nil {
		n.containers = map[string]string{}
	}
	n.containers[c.id] = c.name
	if c.netIPs == nil {
		c.netIPs = map[string]string{}
	}
	if _, ok := c.netIPs[n.name]; !ok {
		c.netIPs[n.name] = s.assignIPLocked(n)
	}
	return n, true
}

func (s *dockerStore) disconnectContainer(idOrName, containerID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.networks[idOrName]
	if !ok {
		n = s.networkByNameLocked(idOrName)
	}
	if n == nil {
		return false
	}
	c := s.resolveContainerLocked(containerID)
	if c == nil {
		return false
	}
	if _, ok := n.containers[c.id]; !ok {
		return false
	}
	delete(n.containers, c.id)
	delete(c.netIPs, n.name)
	return true
}

func (s *dockerStore) listVolumes() []*dockerVolume {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*dockerVolume, 0, len(s.volumes))
	for _, v := range s.volumes {
		out = append(out, v)
	}
	return out
}

func (s *dockerStore) getVolume(name string) (*dockerVolume, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.volumes[name]
	return v, ok
}

// getVolumeByName 按名字查卷，不存在返回 nil。
func (s *dockerStore) getVolumeByName(name string) *dockerVolume {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.volumes[name]; ok {
		return v
	}
	return nil
}

// createVolume 创建卷（同名已存在则复用），返回卷名。
func (s *dockerStore) createVolume(name, driver string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name == "" {
		name = "vol-" + randomID()[:12]
	}
	if v, ok := s.volumes[name]; ok {
		return v.name
	}
	if driver == "" {
		driver = "local"
	}
	s.volumes[name] = &dockerVolume{
		name: name, driver: driver,
		mountpoint: "/var/lib/docker/volumes/" + name + "/_data",
		created:    time.Now().Unix(),
	}
	return name
}

func (s *dockerStore) deleteVolume(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.volumes[name]; !ok {
		return false
	}
	delete(s.volumes, name)
	return true
}

// counts 汇总容器/镜像统计（/info 用），避免无锁读 map。
func (s *dockerStore) counts() (containers, running, paused, stopped, images int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	containers = len(s.containers)
	for _, c := range s.containers {
		switch c.state {
		case "running":
			running++
		case "paused", "restarting":
			paused++
		default:
			stopped++
		}
	}
	return containers, running, paused, stopped, len(s.images)
}

// ---- 连接处理 ----

func dockerHandle(ctx context.Context, service *services.Service) {
	baseOptions := service.BaseOptions
	cfg := service.ServiceOptions.(dockerConfig)
	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	listen, err := net.Listen("tcp4", address)
	if err != nil {
		logger.Log.Errorln(err)
		service.ReportError(err)
		return
	}
	defer listen.Close()
	logger.Log.Infof("%s listen on %s", baseOptions.Application, address)

	service.MarkReady()

	connChan := common.ForwardListenerToChan(listen)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case conn := <-connChan:
			go handleConn(conn, service, cfg)
		}
	}
}

func handleConn(conn net.Conn, service *services.Service, cfg dockerConfig) {
	defer conn.Close()
	baseOptions := service.BaseOptions
	cfg.store.ensureSeeded(cfg)
	serverVersion.Store(cfg.version())
	serverAPIVersion.CompareAndSwap(nil, cfg.apiVersion())
	serverExperimental.Store(cfg.Experimental)
	// 守护进程 ID 一次运行内稳定（真机 docker info 的 ID 不变）
	serverInfoID.CompareAndSwap(nil, randomID()[:12])

	id := xid.New()
	srcAddr, err := common.GetConnSrcIPAndSrcPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}
	dstAddr, err := common.GetConnDstIPAndDstPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}

	event.EventPush(event.NewEvent(serviceName, "docker-connect", srcAddr, dstAddr, map[string]interface{}{
		"protocol":              baseOptions.Protocol,
		"application":           baseOptions.Application,
		"docker.session-id":     id.String(),
		"docker.server_version": cfg.version(),
	}))

	pushClose := func() {
		event.EventPush(event.NewEvent(serviceName, "docker-close", srcAddr, dstAddr, map[string]interface{}{
			"protocol":          baseOptions.Protocol,
			"application":       baseOptions.Application,
			"docker.session-id": id.String(),
		}))
	}

	reader := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(cfg.idleTimeout()))
		req, err := http.ReadRequest(reader)
		if err != nil {
			pushClose()
			return
		}
		body := readRequestBody(req)
		handleRequest(conn, req, service, cfg, id, srcAddr, dstAddr, body)
	}
}

func readRequestBody(req *http.Request) []byte {
	if req.Body == nil {
		return nil
	}
	defer req.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
	if len(data) > maxBody {
		data = data[:maxBody]
	}
	_, _ = io.Copy(io.Discard, req.Body)
	return data
}

func handleRequest(conn net.Conn, req *http.Request, service *services.Service, cfg dockerConfig,
	id xid.ID, srcAddr, dstAddr common.Addr, body []byte) {
	baseOptions := service.BaseOptions
	path := req.URL.Path
	method := strings.ToUpper(req.Method)

	details := map[string]interface{}{
		"protocol":              baseOptions.Protocol,
		"application":           baseOptions.Application,
		"docker.session-id":     id.String(),
		"docker.method":         req.Method,
		"docker.url":            req.URL.String(),
		"docker.path":           path,
		"docker.query":          req.URL.RawQuery,
		"docker.host":           req.Host,
		"docker.user_agent":     req.UserAgent(),
		"docker.content_length": req.ContentLength,
		"docker.body":           string(body),
	}
	if auth := req.Header.Get("Authorization"); auth != "" {
		details["docker.authorization"] = auth
		if user, pass, ok := parseBasicAuth(auth); ok {
			details["docker.auth_username"] = user
			details["docker.auth_password"] = pass
		}
	}
	// X-Registry-Auth：镜像仓库凭证（官方示例「带认证拉取」用），base64 的
	// {"username","password","serveraddress"}，同样是高价值泄露点。
	if ra := req.Header.Get("X-Registry-Auth"); ra != "" {
		details["docker.registry_auth"] = ra
		if user, pass, server, ok := parseRegistryAuth(ra); ok {
			details["docker.registry_auth_username"] = user
			details["docker.registry_auth_password"] = pass
			details["docker.registry_auth_server"] = server
		}
	}
	event.EventPush(event.NewEvent(serviceName, "docker-request", srcAddr, dstAddr, details))

	route(conn, req, cfg, method, path, body)
}

// ---- 路由 ----

func route(conn net.Conn, req *http.Request, cfg dockerConfig, method, path string, body []byte) {
	// Docker API 允许 /v1.45/... 这种带版本前缀的路径，剥离后再按常规路由。
	path = stripVersionPrefix(path)
	// all=true 时返回全部（含已停止），否则只返回 running。
	// 注意：docker CLI 发的是 all=1，必须兼容 true/1/t 三种写法。
	all := boolQuery(req.URL.Query(), "all")
	filters, filterErr := parseListFilters(req.URL.Query().Get("filters"))
	switch {
	case path == "/_ping" || path == "/_ping/":
		respondText(conn, req, http.StatusOK, "OK")
		return
	case path == "/version" || path == "/version/":
		respondJSON(conn, req, http.StatusOK, versionInfo(cfg))
		return
	case path == "/info" || path == "/info/":
		respondJSON(conn, req, http.StatusOK, infoInfo(cfg))
		return
	case strings.HasPrefix(path, "/containers/json"):
		if method != "GET" {
			respondNotFound(conn, req, "page not found")
			return
		}
		if filterErr != "" {
			respondError(conn, req, http.StatusBadRequest, filterErr)
			return
		}
		respondJSON(conn, req, http.StatusOK, listContainers(cfg, all, filters))
		return
	case strings.HasPrefix(path, "/images/json"):
		if method != "GET" {
			respondNotFound(conn, req, "page not found")
			return
		}
		if filterErr != "" {
			respondError(conn, req, http.StatusBadRequest, filterErr)
			return
		}
		respondJSON(conn, req, http.StatusOK, listImages(cfg, filters))
		return
	case path == "/swarm" || path == "/swarm/":
		// 非 manager 节点查 swarm：真机回 503
		respondError(conn, req, http.StatusServiceUnavailable, "This node is not a swarm manager")
		return
	case path == "/build" || path == "/build/": // POST /build（docker build）
		if method != "POST" {
			respondNotFound(conn, req, "page not found")
			return
		}
		respondStreamTimed(conn, req, buildStreamSteps(cfg.pullPace()))
		return
	case path == "/commit" || path == "/commit/": // POST /commit（官方示例：容器提交成镜像）
		handleCommit(conn, req, cfg, method, path)
		return
	case strings.HasPrefix(path, "/networks"):
		handleNetworks(conn, req, cfg, method, path, body)
		return
	case strings.HasPrefix(path, "/volumes"):
		handleVolumes(conn, req, cfg, method, path, body)
		return
	case path == "/system/df" || path == "/system/df/":
		respondJSON(conn, req, http.StatusOK, systemDF(cfg))
		return
	case path == "/events":
		respondText(conn, req, http.StatusOK, "")
		return
	case strings.HasPrefix(path, "/containers/"):
		handleContainers(conn, req, cfg, method, path, body)
		return
	case strings.HasPrefix(path, "/images/"):
		handleImages(conn, req, cfg, method, path, body)
		return
	case strings.HasPrefix(path, "/exec/"):
		handleExec(conn, req, cfg, method, path, body)
		return
	}
	respondError(conn, req, http.StatusNotFound, "page not found")
}

// stripVersionPrefix 把 /v1.45/containers/json 剥成 /containers/json；
// 普通路径（如 /version）不受影响。
func stripVersionPrefix(p string) string {
	rest := strings.TrimPrefix(p, "/")
	if !strings.HasPrefix(rest, "v") {
		return p
	}
	i := 1
	for i < len(rest) && (rest[i] == '.' || (rest[i] >= '0' && rest[i] <= '9')) {
		i++
	}
	if i > 1 && i < len(rest) && rest[i] == '/' {
		return "/" + rest[i+1:]
	}
	return p
}

// handleContainers 路由 /containers/... 系列端点。
func handleContainers(conn net.Conn, req *http.Request, cfg dockerConfig, method, path string, body []byte) {
	// /containers/create（仅 POST；真机该路由不注册其它方法）
	if path == "/containers/create" {
		if method != "POST" {
			respondNotFound(conn, req, "page not found")
			return
		}
		var spec map[string]interface{}
		_ = json.Unmarshal(body, &spec)
		image, _ := spec["Image"].(string)
		if strings.TrimSpace(image) == "" {
			// 真机：未指定 Image 回 400
			respondError(conn, req, http.StatusBadRequest, "No image specified")
			return
		}
		var name string
		if raw := req.URL.Query().Get("name"); raw != "" {
			if !validContainerName(raw) {
				respondError(conn, req, http.StatusBadRequest, fmt.Sprintf(
					"Invalid container name (%s), only [a-zA-Z0-9][a-zA-Z0-9_.-] are allowed", raw))
				return
			}
			name = "/" + strings.TrimPrefix(raw, "/")
			if existing, found := cfg.store.containerNameExists(name); found {
				respondError(conn, req, http.StatusConflict,
					fmt.Sprintf("Conflict. The container name %q is already in use by container %q. You have to remove (or rename) that container to be able to reuse that name.", name, existing))
				return
			}
		} else {
			// 未指定名称时真机会自动生成 adjective_surname 形式的名字
			name = "/" + randomName()
		}
		id, ok := cfg.store.createContainer(name, image)
		if !ok {
			// 真机：本地没有该镜像时 create 失败（需先 pull）
			respondNotFound(conn, req, "No such image: "+image)
			return
		}
		respondJSON(conn, req, http.StatusCreated, map[string]interface{}{
			"Id":       id,
			"Warnings": []interface{}{},
		})
		return
	}

	// /containers/{id}/{action}
	rest := strings.TrimPrefix(path, "/containers/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	switch action {
	case "json": // inspect
		c, ok := cfg.store.getContainer(id)
		if !ok {
			respondNotFound(conn, req, "No such container: "+id)
			return
		}
		respondJSON(conn, req, http.StatusOK, inspectContainer(cfg, c))
		return
	case "start", "stop", "restart", "kill", "pause", "unpause", "rename", "update", "resize":
		c, ok := cfg.store.getContainer(id)
		if !ok {
			respondNotFound(conn, req, "No such container: "+id)
			return
		}
		switch action {
		case "start":
			if c.state == "running" {
				respondEmpty(conn, req, http.StatusNotModified) // 304: container already started
				return
			}
			cfg.store.setContainerState(id, "running", 0)
		case "restart", "unpause":
			cfg.store.setContainerState(id, "running", 0)
		case "stop":
			cfg.store.setContainerState(id, "exited", 0)
		case "kill":
			if c.state != "running" {
				respondError(conn, req, http.StatusConflict, "Container is not running")
				return
			}
			cfg.store.setContainerState(id, "exited", 137)
		case "pause":
			cfg.store.setContainerState(id, "paused", 0)
		case "rename":
			// POST /containers/{id}/rename?name=<new>：真实改名并同步网络里的名称
			newName := req.URL.Query().Get("name")
			if newName == "" {
				respondError(conn, req, http.StatusBadRequest, "name parameter is required")
				return
			}
			if !validContainerName(newName) {
				respondError(conn, req, http.StatusBadRequest, fmt.Sprintf(
					"Invalid container name (%s), only [a-zA-Z0-9][a-zA-Z0-9_.-] are allowed", newName))
				return
			}
			full := "/" + strings.TrimPrefix(newName, "/")
			if existing, found := cfg.store.containerNameExists(full); found && existing != c.id {
				respondError(conn, req, http.StatusConflict,
					fmt.Sprintf("Conflict. The container name %q is already in use by container %q. You have to remove (or rename) that container to be able to reuse that name.", full, existing))
				return
			}
			cfg.store.renameContainer(c.id, full)
		}
		respondEmpty(conn, req, http.StatusNoContent)
		return
	case "exec": // POST /containers/{id}/exec：创建 exec 实例（官方端点）
		if method != "POST" {
			respondNotFound(conn, req, "page not found")
			return
		}
		var spec map[string]interface{}
		_ = json.Unmarshal(body, &spec)
		var cmd []string
		if raw, ok := spec["Cmd"].([]interface{}); ok {
			for _, v := range raw {
				if s, ok := v.(string); ok {
					cmd = append(cmd, s)
				}
			}
		}
		eid, ok := cfg.store.createExec(id, cmd)
		if !ok {
			respondNotFound(conn, req, "No such container: "+id)
			return
		}
		respondJSON(conn, req, http.StatusCreated, map[string]interface{}{"Id": eid})
		return
	case "wait": // 官方示例：POST /containers/{id}/wait -> {"StatusCode":0}
		c, ok := cfg.store.getContainer(id)
		if !ok {
			respondNotFound(conn, req, "No such container: "+id)
			return
		}
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{
			"StatusCode": c.exitCode,
			"Error":      nil,
		})
		return
	case "logs": // 官方示例：GET /containers/{id}/logs?stdout=1 -> 帧复用流
		c, ok := cfg.store.getContainer(id)
		if !ok {
			respondNotFound(conn, req, "No such container: "+id)
			return
		}
		// 非 TTY 容器：真机把日志包装成 8 字节帧流（类型1=stdout + 大端长度）
		respond(conn, req, http.StatusOK, "application/vnd.docker.multiplexed-stream", frameLogs(containerLogs(c)))
		return
	case "stats": // 流式单帧统计
		c, ok := cfg.store.getContainer(id)
		if !ok {
			respondNotFound(conn, req, "No such container: "+id)
			return
		}
		respondStream(conn, req, http.StatusOK, []interface{}{containerStats(cfg, c)})
		return
	case "top": // 进程列表（按镜像画像给出真实进程，不再共用 nginx 条目）
		c, ok := cfg.store.getContainer(id)
		if !ok {
			respondNotFound(conn, req, "No such container: "+id)
			return
		}
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{
			"Titles":    []string{"UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"},
			"Processes": profileForImage(c.image).top,
		})
		return
	case "attach": // POST /containers/{id}/attach：真机以 101 接管连接持续输出
		if method != "POST" {
			respondNotFound(conn, req, "page not found")
			return
		}
		c, ok := cfg.store.getContainer(id)
		if !ok {
			respondNotFound(conn, req, "No such container: "+id)
			return
		}
		if isHijack(req) {
			// 附着后连接保持（真机 attach 会持续附着直到 detach）
			respondHijack(conn, req, frameLogs(containerLogs(c)), false)
			return
		}
		respond(conn, req, http.StatusOK, "application/vnd.docker.multiplexed-stream", frameLogs(containerLogs(c)))
		return
	case "changes":
		if _, ok := cfg.store.getContainer(id); !ok {
			respondNotFound(conn, req, "No such container: "+id)
			return
		}
		respondJSON(conn, req, http.StatusOK, []map[string]interface{}{
			{"Path": "/etc", "Kind": 0},
			{"Path": "/var", "Kind": 1},
		})
		return
	case "export", "archive":
		if _, ok := cfg.store.getContainer(id); !ok {
			respondNotFound(conn, req, "No such container: "+id)
			return
		}
		respondTar(conn, req, containerExportTar(cfg, id))
		return
	case "":
		// /containers/{id} 的 DELETE
		if method == "DELETE" {
			c, ok := cfg.store.getContainer(id)
			if !ok {
				respondNotFound(conn, req, "No such container: "+id)
				return
			}
			if c.state == "running" {
				respondError(conn, req, http.StatusConflict, "You cannot remove a running container")
				return
			}
			cfg.store.deleteContainer(id)
			respondEmpty(conn, req, http.StatusNoContent) // 204 不允许带 body
			return
		}
		respondNotFound(conn, req, "page not found")
		return
	}
	respondNotFound(conn, req, "page not found")
}

// handleImages 路由 /images/... 系列端点。
func handleImages(conn net.Conn, req *http.Request, cfg dockerConfig, method, path string, body []byte) {
	// POST /images/create：拉取镜像（docker.txt 仅此一个，且只接受 POST）
	if path == "/images/create" {
		if method != "POST" {
			respondNotFound(conn, req, "page not found")
			return
		}
		q := req.URL.Query()
		repo := q.Get("fromImage")
		if repo == "" {
			var spec map[string]interface{}
			_ = json.Unmarshal(body, &spec)
			if s, ok := spec["fromImage"].(string); ok && s != "" {
				repo = s
			}
		}
		if repo == "" {
			respondError(conn, req, http.StatusNotFound, "Invalid repository name")
			return
		}
		r, t := splitRepoTag(repo)
		if q.Get("tag") != "" {
			t = q.Get("tag")
		}
		if _, exists := cfg.store.getImageByName(r + ":" + t); exists {
			// 本地已有：真机返回 up to date，不重复入库
			respondStream(conn, req, http.StatusOK, []interface{}{
				map[string]interface{}{"status": "Image is up to date for " + r + ":" + t},
			})
			return
		}
		cfg.store.addImage(r, t)
		respondStreamTimed(conn, req, pullStreamSteps(r, t, cfg.pullPace()))
		return
	}
	// POST /images/load、/images/import（docker load / docker import）
	if path == "/images/load" || path == "/images/import" {
		if method != "POST" {
			respondNotFound(conn, req, "page not found")
			return
		}
		respondStream(conn, req, http.StatusOK, []interface{}{
			map[string]interface{}{"stream": "Loaded image: " + randomID()[:12] + "\n"},
		})
		return
	}

	rest := strings.TrimPrefix(path, "/images/")
	// 镜像名可能带 registry/命名空间（ghcr.io/astral-sh/uv:tag），
	// 动作固定在最后一段，名称是其余部分。
	id := rest
	action := ""
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		if a := rest[i+1:]; isImageAction(a) {
			id = rest[:i]
			action = a
		}
	}

	// GET /images/get?names=nginx:latest（docker save 的新式入口，返回 tar 流）
	if id == "get" && method == "GET" {
		names := req.URL.Query().Get("names")
		if names == "" {
			respondNotFound(conn, req, "No such image: ")
			return
		}
		ref := strings.Split(names, ",")[0]
		im, ok := cfg.store.getImageByName(ref)
		if !ok {
			respondNotFound(conn, req, "No such image: "+ref)
			return
		}
		respondTar(conn, req, imageSaveTar(im))
		return
	}

	switch action {
	case "json": // inspect
		im, ok := cfg.store.getImageByName(id)
		if !ok {
			respondNotFound(conn, req, "No such image: "+id)
			return
		}
		respondJSON(conn, req, http.StatusOK, inspectImage(cfg, im))
		return
	case "tag": // POST /images/{name}/tag?repo=myapp&tag=1.0（同一 ID 多标签）
		if method != "POST" {
			respondNotFound(conn, req, "page not found")
			return
		}
		im, ok := cfg.store.getImageByName(id)
		if !ok {
			respondNotFound(conn, req, "No such image: "+id)
			return
		}
		repo := req.URL.Query().Get("repo")
		if repo == "" {
			respondError(conn, req, http.StatusBadRequest, "repo parameter is required")
			return
		}
		full := repo
		if t := req.URL.Query().Get("tag"); t != "" {
			full = repo + ":" + t
		}
		r, t := splitRepoTag(full)
		if !cfg.store.tagImage(im.id, r, t) {
			respondError(conn, req, http.StatusInternalServerError, "failed to tag image")
			return
		}
		respondEmpty(conn, req, http.StatusCreated)
		return
	case "history":
		im, ok := cfg.store.getImageByName(id)
		if !ok {
			respondNotFound(conn, req, "No such image: "+id)
			return
		}
		respondJSON(conn, req, http.StatusOK, imageHistory(im))
		return
	case "get", "export":
		im, ok := cfg.store.getImageByName(id)
		if !ok {
			respondNotFound(conn, req, "No such image: "+id)
			return
		}
		respondTar(conn, req, imageSaveTar(im))
		return
	case "push": // POST /images/{name}/push，未认证时真机即拒绝
		im, ok := cfg.store.getImageByName(id)
		if !ok {
			respondNotFound(conn, req, "An image does not exist locally with the tag: "+id)
			return
		}
		respondStream(conn, req, http.StatusOK, []interface{}{
			map[string]interface{}{"status": "The push refers to repository [docker.io/" + im.ref() + "]"},
			map[string]interface{}{"status": "Preparing", "progressDetail": map[string]interface{}{}, "id": randomID()[:12]},
			map[string]interface{}{"errorDetail": map[string]interface{}{
				"message": "denied: requested access to the resource is denied",
			}, "error": "denied: requested access to the resource is denied"},
		})
		return
	case "":
		if method == "DELETE" {
			im, ok := cfg.store.getImageByName(id)
			if !ok {
				respondNotFound(conn, req, "No such image: "+id)
				return
			}
			// 被删的引用（短 ID 删除时按主标签记）
			target := im.ref()
			for _, t := range im.tags() {
				if t == id {
					target = t
					break
				}
			}
			wasPrimary := target == im.ref()
			imgID := "sha256:" + im.id
			if !cfg.store.deleteImageByName(id) {
				respondNotFound(conn, req, "No such image: "+id)
				return
			}
			// 真机返回数组：[{"Untagged":"repo:tag"},{"Deleted":"sha256:..."}]
			out := []map[string]interface{}{{"Untagged": target}}
			if wasPrimary {
				out = append(out, map[string]interface{}{"Deleted": imgID})
			}
			respondJSON(conn, req, http.StatusOK, out)
			return
		}
		respondNotFound(conn, req, "page not found")
		return
	}
	respondNotFound(conn, req, "page not found")
}

// handleNetworks 路由 /networks 与 /networks/{id}/... 系列端点。
func handleNetworks(conn net.Conn, req *http.Request, cfg dockerConfig, method, path string, body []byte) {
	// POST /networks/create
	if path == "/networks/create" {
		if method != "POST" {
			respondNotFound(conn, req, "page not found")
			return
		}
		var spec map[string]interface{}
		_ = json.Unmarshal(body, &spec)
		name, _ := spec["Name"].(string)
		driver, _ := spec["Driver"].(string)
		internal, _ := spec["Internal"].(bool)
		if existing, found := cfg.store.getNetwork(name); found && name != "" {
			respondError(conn, req, http.StatusConflict,
				fmt.Sprintf("network with name %s already exists", existing.name))
			return
		}
		id := cfg.store.createNetwork(name, driver, internal)
		respondJSON(conn, req, http.StatusCreated, map[string]interface{}{
			"Id":      id,
			"Warning": "",
		})
		return
	}

	// GET /networks（列表）
	if path == "/networks" || path == "/networks/" {
		if method != "GET" {
			respondNotFound(conn, req, "page not found")
			return
		}
		respondJSON(conn, req, http.StatusOK, listNetworks(cfg))
		return
	}

	rest := strings.TrimPrefix(path, "/networks/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}

	switch action {
	case "json": // inspect
		n, ok := cfg.store.getNetwork(id)
		if !ok {
			respondNotFound(conn, req, "network "+id+" not found")
			return
		}
		respondJSON(conn, req, http.StatusOK, inspectNetwork(cfg, n))
		return
	case "connect":
		if _, ok := cfg.store.getNetwork(id); !ok {
			respondNotFound(conn, req, "network "+id+" not found")
			return
		}
		var spec map[string]interface{}
		_ = json.Unmarshal(body, &spec)
		containerID, _ := spec["Container"].(string)
		if containerID == "" {
			respondError(conn, req, http.StatusBadRequest, "Invalid Container")
			return
		}
		if _, ok := cfg.store.connectContainer(id, containerID); !ok {
			respondNotFound(conn, req, "No such container: "+containerID)
			return
		}
		respondEmpty(conn, req, http.StatusOK)
		return
	case "disconnect":
		var spec map[string]interface{}
		_ = json.Unmarshal(body, &spec)
		containerID, _ := spec["Container"].(string)
		if containerID == "" {
			respondError(conn, req, http.StatusBadRequest, "Invalid Container")
			return
		}
		if !cfg.store.disconnectContainer(id, containerID) {
			respondNotFound(conn, req, "network "+id+" not found")
			return
		}
		respondEmpty(conn, req, http.StatusOK)
		return
	case "":
		if method == "DELETE" {
			if !cfg.store.deleteNetwork(id) {
				respondNotFound(conn, req, "network "+id+" not found")
				return
			}
			respondEmpty(conn, req, http.StatusNoContent)
			return
		}
		// GET /networks/{id}：真机的网络 inspect 端点没有 /json 后缀
		if method == "GET" {
			n, ok := cfg.store.getNetwork(id)
			if !ok {
				respondNotFound(conn, req, "network "+id+" not found")
				return
			}
			respondJSON(conn, req, http.StatusOK, inspectNetwork(cfg, n))
			return
		}
		respondNotFound(conn, req, "page not found")
		return
	}
	respondNotFound(conn, req, "page not found")
}

// handleExec 路由 /exec/{id}/... 系列端点（exec 实例的 start/resize/inspect）。
func handleExec(conn net.Conn, req *http.Request, cfg dockerConfig, method, path string, body []byte) {
	rest := strings.TrimPrefix(path, "/exec/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}
	switch action {
	case "start":
		if method != "POST" {
			respondNotFound(conn, req, "page not found")
			return
		}
		e, ok := cfg.store.getExec(id)
		if !ok {
			respondNotFound(conn, req, "No such exec instance: "+id)
			return
		}
		// CLI 带 Hijack/Upgrade 头发起连接升级：真机回 101 后接管连接，
		// 输出完命令结果即关闭（docker exec 的行为）
		if isHijack(req) {
			respondHijack(conn, req, frameLogs(execOutput(e)), true)
			return
		}
		// 无 Hijack 时真机回 200 空响应
		respondEmpty(conn, req, http.StatusOK)
		return
	case "resize":
		if method != "POST" {
			respondNotFound(conn, req, "page not found")
			return
		}
		if _, ok := cfg.store.getExec(id); !ok {
			respondNotFound(conn, req, "No such exec instance: "+id)
			return
		}
		respondEmpty(conn, req, http.StatusCreated)
		return
	case "json":
		if method != "GET" {
			respondNotFound(conn, req, "page not found")
			return
		}
		e, ok := cfg.store.getExec(id)
		if !ok {
			respondNotFound(conn, req, "No such exec instance: "+id)
			return
		}
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{
			"ID":            e.id,
			"Running":       false,
			"ExitCode":      nil,
			"ProcessConfig": map[string]interface{}{"privileged": false, "user": "", "tty": false, "entrypoint": "sh", "arguments": e.cmd},
			"OpenStdin":     false,
			"OpenStderr":    false,
			"OpenStdout":    false,
			"ContainerID":   e.containerID,
			"DetachKeys":    "ctrl-p,ctrl-q",
		})
		return
	}
	respondNotFound(conn, req, "page not found")
}

// handleVolumes 路由 /volumes 与 /volumes/{name} 系列端点。
func handleVolumes(conn net.Conn, req *http.Request, cfg dockerConfig, method, path string, body []byte) {
	// POST /volumes/create
	if path == "/volumes/create" {
		if method != "POST" {
			respondNotFound(conn, req, "page not found")
			return
		}
		var spec map[string]interface{}
		_ = json.Unmarshal(body, &spec)
		name, _ := spec["Name"].(string)
		driver, _ := spec["Driver"].(string)
		v := cfg.store.getVolumeByName(name)
		if v == nil {
			cfg.store.createVolume(name, driver)
			v = cfg.store.getVolumeByName(name)
		}
		respondJSON(conn, req, http.StatusCreated, inspectVolume(v))
		return
	}

	// GET /volumes（列表）
	if path == "/volumes" || path == "/volumes/" {
		if method != "GET" {
			respondNotFound(conn, req, "page not found")
			return
		}
		respondJSON(conn, req, http.StatusOK, map[string]interface{}{
			"Volumes":  listVolumes(cfg),
			"Warnings": []interface{}{},
		})
		return
	}

	name := strings.TrimPrefix(path, "/volumes/")
	if name == "" || strings.Contains(name, "/") {
		respondNotFound(conn, req, "page not found")
		return
	}
	if method == "DELETE" {
		if !cfg.store.deleteVolume(name) {
			respondNotFound(conn, req, "volume "+name+" not found")
			return
		}
		respondEmpty(conn, req, http.StatusNoContent)
		return
	}
	v := cfg.store.getVolumeByName(name)
	if v == nil {
		respondNotFound(conn, req, "volume "+name+" not found")
		return
	}
	respondJSON(conn, req, http.StatusOK, inspectVolume(v))
}

// containerLogs 按镜像类型生成一段可信的容器日志（GET /containers/{id}/logs）。
func containerLogs(c *dockerContainer) string {
	switch {
	case strings.Contains(c.image, "nginx"):
		return "2026/10/19 09:00:00 [notice] 1#1: using the \"epoll\" event method\n" +
			"2026/10/19 09:00:00 [notice] 1#1: nginx/1.25.3\n" +
			"2026/10/19 09:00:00 [notice] 1#1: start worker processes\n" +
			"172.17.0.1 - - [19/Oct/2026:09:00:01 +0000] \"GET / HTTP/1.1\" 200 615 \"-\" \"curl/7.81.0\" \"-\"\n"
	case strings.Contains(c.image, "redis"):
		return "1:M 19 Oct 2026 09:00:00.123 * Running mode=standalone, port=6379.\n" +
			"1:M 19 Oct 2026 09:00:00.124 # Server initialized\n" +
			"1:M 19 Oct 2026 09:00:00.125 # WARNING Memory overcommit must be enabled!\n" +
			"1:M 19 Oct 2026 09:00:00.130 * Ready to accept connections tcp\n"
	case strings.Contains(c.image, "mysql"), strings.Contains(c.image, "mariadb"):
		return "2026-10-19T09:00:00.123456Z 0 [System] [MY-010116] [Server] /usr/sbin/mysqld (mysqld 8.0.36) starting as process 1\n" +
			"2026-10-19T09:00:00.234567Z 1 [System] [MY-013576] [InnoDB] InnoDB initialization has started.\n" +
			"2026-10-19T09:00:00.345678Z 1 [System] [MY-013577] [InnoDB] InnoDB initialization has ended.\n" +
			"2026-10-19T09:00:00.456789Z 0 [System] [MY-010229] [Server] /usr/sbin/mysqld: ready for connections.\n"
	default:
		return "hello world\n"
	}
}

// isHijack 判断请求是否要求连接升级（docker CLI 的 exec/attach 带
// Hijack/Upgrade 头，真机回 101 后接管连接）。
func isHijack(req *http.Request) bool {
	return req.Header.Get("Hijack") != "" ||
		strings.Contains(req.Header.Get("Connection"), "Upgrade")
}

// respondHijack 以 101 UPGRADED 接管连接（真机 exec/attach 的行为），
// 写入负载后按需关闭连接。
func respondHijack(conn net.Conn, req *http.Request, payload []byte, closeAfter bool) {
	head := "HTTP/1.1 101 UPGRADED\r\n" +
		"Content-Type: application/vnd.docker.multiplexed-stream\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: tcp\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(head)); err != nil {
		return
	}
	if len(payload) > 0 {
		_, _ = conn.Write(payload)
	}
	if closeAfter {
		// 命令结束即关闭，客户端读到 EOF 后退出（真机 exec 的行为）
		_ = conn.Close()
	}
}

// execOutput 按 exec 的命令给出可信输出（id/whoami/ls/ps 等常见命令）。
func execOutput(e *dockerExec) string {
	if len(e.cmd) == 0 {
		return ""
	}
	switch e.cmd[0] {
	case "id":
		return "uid=0(root) gid=0(root) groups=0(root)\n"
	case "whoami":
		return "root\n"
	case "pwd":
		return "/\n"
	case "uname":
		return "Linux\n"
	case "hostname":
		return "host\n"
	case "ls":
		return "bin\netc\nlib\nproc\nsys\nusr\nvar\n"
	case "ps":
		return "  PID TTY          TIME CMD\n    1 ?        00:00:00 sh\n"
	default:
		return ""
	}
}

// frameLogs 按真机非 TTY 容器的行为，把纯文本日志包装成 8 字节帧流：
// 首字节流类型（1=stdout，2=stderr），第 2-4 字节保留为 0，第 5-8 字节
// 大端存放后续负载长度。docker CLI/API 客户端均按此格式解复用。
func frameLogs(text string) []byte {
	var buf bytes.Buffer
	for _, line := range strings.SplitAfter(text, "\n") {
		if line == "" {
			continue
		}
		var hdr [8]byte
		hdr[0] = 1 // stdout
		binary.BigEndian.PutUint32(hdr[4:], uint32(len(line)))
		buf.Write(hdr[:])
		buf.Write([]byte(line))
	}
	return buf.Bytes()
}

// containerStats 生成一帧容器统计（GET /containers/{id}/stats）。
func containerStats(cfg dockerConfig, c *dockerContainer) map[string]interface{} {
	read := time.Now().Format(time.RFC3339Nano)
	prof := profileForImage(c.image)
	pids := 0
	if c.state == "running" {
		pids = prof.pids
	}
	return map[string]interface{}{
		"read": read,
		"cpu_stats": map[string]interface{}{
			"cpu_usage": map[string]interface{}{
				"total_usage":         1234567890,
				"percpu_usage":        []uint64{617283945, 617283945},
				"usage_in_kernelmode": 20000000,
				"usage_in_usermode":   40000000,
			},
			"system_cpu_usage": 9876543210,
			"online_cpus":      cfg.ncpu(),
			"throttling_data":  map[string]interface{}{"periods": 0, "throttled_periods": 0, "throttled_time": 0},
		},
		"precpu_stats": map[string]interface{}{
			"cpu_usage":        map[string]interface{}{"total_usage": 1200000000},
			"system_cpu_usage": 9800000000,
			"online_cpus":      cfg.ncpu(),
		},
		"memory_stats": map[string]interface{}{
			"usage": 131072000,
			"stats": map[string]interface{}{
				"active_anon": 8388608, "active_file": 4194304, "inactive_anon": 0,
				"inactive_file": 2097152, "total_cache": 6291456, "total_rss": 8388608,
			},
			"limit": cfg.memTotal(),
		},
		"networks": map[string]interface{}{
			"eth0": map[string]interface{}{
				"rx_bytes": 2048, "rx_packets": 24, "rx_errors": 0, "rx_dropped": 0,
				"tx_bytes": 1024, "tx_packets": 16, "tx_errors": 0, "tx_dropped": 0,
			},
		},
		"blkio_stats": map[string]interface{}{
			"io_service_bytes_recursive": nil,
			"io_serviced_recursive":      nil,
		},
		"pids_stats": map[string]interface{}{"current": pids},
		"name":       c.name,
		"id":         c.id,
	}
}

// handleCommit 路由 POST /commit：把容器变更提交成新镜像（官方示例）。
func handleCommit(conn net.Conn, req *http.Request, cfg dockerConfig, method, path string) {
	if method != "POST" {
		respondNotFound(conn, req, "page not found")
		return
	}
	q := req.URL.Query()
	container := q.Get("container")
	if container == "" {
		respondError(conn, req, http.StatusBadRequest, "container parameter is required")
		return
	}
	c, ok := cfg.store.getContainer(container)
	if !ok {
		respondNotFound(conn, req, "No such container: "+container)
		return
	}
	repo := q.Get("repo")
	if repo == "" {
		repo = strings.TrimPrefix(c.name, "/")
	}
	r, t := splitRepoTag(repo)
	if r == "" {
		r, t = "busybox", "latest"
	}
	im := cfg.store.commitImage(r, t)
	respondJSON(conn, req, http.StatusCreated, map[string]interface{}{
		"Id": "sha256:" + im,
	})
}

// streamStep 流式响应的一帧及其前置停顿（模拟进度流速）。
type streamStep struct {
	obj   interface{}
	delay time.Duration
}

// pullStreamSteps 生成接近真机的 pull 流式输出：两个层依次拉取，下载/解压
// 进度递进，帧间隔按 pace 缩放并带快慢波动（网速时快时慢），最后一帧
// "Downloaded newer image" 与真机一致。
func pullStreamSteps(repo, tag string, pace time.Duration) []streamStep {
	ns := repo
	if !strings.ContainsAny(ns, "/:") {
		ns = "library/" + repo
	}
	layers := []string{randomID()[:12], randomID()[:12]}
	total := 2244027
	// 进度序列（占总量/层数的比例）与各档间隔系数（>1 变慢、<1 变快）
	fracs := []float64{0.05, 0.3, 0.7, 1.0}
	dlPace := []float64{0.4, 0.9, 1.3, 0.6}
	exPace := []float64{0.6, 1.0, 0.7, 0.4}

	steps := []streamStep{
		{obj: map[string]interface{}{"status": "Pulling from " + ns, "id": "3.1"}},
	}
	for _, layer := range layers {
		steps = append(steps, streamStep{
			obj:   map[string]interface{}{"status": "Pulling fs layer", "progressDetail": map[string]interface{}{}, "id": layer},
			delay: pace / 3,
		})
	}
	emit := func(status string, paces []float64) {
		for _, layer := range layers {
			for i, frac := range fracs {
				cur := int(float64(total) * frac / float64(len(layers)))
				steps = append(steps, streamStep{
					obj: map[string]interface{}{
						"status":         status,
						"progressDetail": map[string]interface{}{"current": cur, "total": total},
						"progress":       progressBar(cur, total),
						"id":             layer,
					},
					delay: time.Duration(float64(pace) * paces[i]),
				})
			}
			done := "Download complete"
			if status == "Extracting" {
				done = "Pull complete"
			}
			steps = append(steps, streamStep{
				obj:   map[string]interface{}{"status": done, "progressDetail": map[string]interface{}{}, "id": layer},
				delay: pace / 4,
			})
		}
	}
	emit("Downloading", dlPace)
	emit("Extracting", exPace)
	steps = append(steps,
		streamStep{obj: map[string]interface{}{"status": "Digest: sha256:" + randomID()}, delay: pace / 2},
		streamStep{obj: map[string]interface{}{"status": "Status: Downloaded newer image for " + repo + ":" + tag}},
	)
	return steps
}

// buildStreamSteps POST /build 的分步流式输出（同样带停顿）。
func buildStreamSteps(pace time.Duration) []streamStep {
	return []streamStep{
		{obj: map[string]interface{}{"stream": "Step 1/3 : FROM busybox\n"}},
		{obj: map[string]interface{}{"stream": " ---> 1234567890ab\n"}, delay: pace / 3},
		{obj: map[string]interface{}{"stream": "Step 2/3 : COPY . /app\n"}, delay: pace / 2},
		{obj: map[string]interface{}{"stream": " ---> Using cache\n"}, delay: pace / 3},
		{obj: map[string]interface{}{"stream": "Step 3/3 : CMD [\"sh\"]\n"}, delay: pace / 2},
		{obj: map[string]interface{}{"stream": "Successfully built " + randomID()[:12] + "\n"}, delay: pace / 2},
	}
}

// respondStreamTimed 分时段写出流式响应（Content-Length 已知）：先发响应头，
// 再逐帧写出并按 delay 停顿——客户端按到达时机逐行渲染进度，与真机拉取/
// 构建的观感一致。
func respondStreamTimed(conn net.Conn, req *http.Request, steps []streamStep) {
	var lines [][]byte
	var delays []time.Duration
	total := 0
	for _, s := range steps {
		b, err := json.Marshal(s.obj)
		if err != nil {
			continue
		}
		b = append(b, '\n')
		lines = append(lines, b)
		delays = append(delays, s.delay)
		total += len(b)
	}
	var head bytes.Buffer
	fmt.Fprintf(&head, "%s 200 OK\r\n", req.Proto)
	head.WriteString("Content-Type: application/json\r\n")
	head.WriteString("Api-Version: " + serverAPIVersionString() + "\r\n")
	head.WriteString("Ostype: linux\r\n")
	head.WriteString("Docker-Experimental: " + fmt.Sprintf("%t", serverExperimental.Load()) + "\r\n")
	head.WriteString("Server: Docker/" + serverVersionString() + " (linux)\r\n")
	fmt.Fprintf(&head, "Content-Length: %d\r\n\r\n", total)
	if _, err := conn.Write(head.Bytes()); err != nil {
		return
	}
	if req.Method == "HEAD" {
		return
	}
	for i, ln := range lines {
		if i > 0 && delays[i] > 0 {
			time.Sleep(delays[i])
		}
		if _, err := conn.Write(ln); err != nil {
			return
		}
	}
}

func progressBar(cur, total int) string {
	const width = 50
	filled := 0
	if total > 0 {
		filled = cur * width / total
	}
	bar := strings.Repeat("=", filled) + ">" + strings.Repeat(" ", width-filled)
	return fmt.Sprintf("[%s] %s/%s", bar, humanBytes(cur), humanBytes(total))
}

func versionInfo(cfg dockerConfig) map[string]interface{} {
	v := cfg.version()
	gitCommit := v + "-0ubuntu1~20.04.1" // ubuntu 构建里 GitCommit 即包版本串
	return map[string]interface{}{
		"Platform": map[string]interface{}{"Name": ""},
		"Components": []map[string]interface{}{
			{
				"Name":    "Engine",
				"Version": v,
				"Details": map[string]interface{}{
					"ApiVersion":    cfg.apiVersion(),
					"Arch":          cfg.architecture(),
					"BuildTime":     cfg.buildTime(),
					"Experimental":  fmt.Sprintf("%t", cfg.Experimental), // Details 是 map[string]string，真机这里是字符串
					"GitCommit":     gitCommit,
					"GoVersion":     cfg.goVersion(),
					"KernelVersion": cfg.kernelVersion(),
					"MinAPIVersion": cfg.minAPIVersion(),
					"Os":            "linux",
				},
			},
			{"Name": "containerd", "Version": cfg.containerdVersion(), "Details": map[string]interface{}{"GitCommit": ""}},
			{"Name": "runc", "Version": cfg.runcVersion(), "Details": map[string]interface{}{"GitCommit": ""}},
			{"Name": "docker-init", "Version": cfg.dockerInitVersion(), "Details": map[string]interface{}{"GitCommit": ""}},
		},
		"Version":       v,
		"ApiVersion":    cfg.apiVersion(),
		"MinAPIVersion": cfg.minAPIVersion(),
		"GitCommit":     gitCommit,
		"GoVersion":     cfg.goVersion(),
		"Os":            "linux",
		"Arch":          cfg.architecture(),
		"KernelVersion": cfg.kernelVersion(),
		"Experimental":  cfg.Experimental,
		"BuildTime":     cfg.buildTime(),
	}
}

func infoInfo(cfg dockerConfig) map[string]interface{} {
	containers, running, paused, stopped, images := cfg.store.counts()
	infoID := ""
	if v, ok := serverInfoID.Load().(string); ok {
		infoID = v
	}
	if infoID == "" {
		infoID = randomID()[:12]
		serverInfoID.Store(infoID)
	}
	info := map[string]interface{}{
		"ID":                infoID,
		"Containers":        containers,
		"ContainersRunning": running,
		"ContainersPaused":  paused,
		"ContainersStopped": stopped,
		"Images":            images,
		"Driver":            cfg.storageDriver(),
		"DriverStatus":      [][]string{{"Backing Filesystem", cfg.backingFS()}},
		"Plugins": map[string]interface{}{
			"Volume":        []string{"local"},
			"Network":       []string{"bridge", "host", "none", "overlay"},
			"Authorization": nil,
			"Log":           []string{"json-file", "syslog", "journald"},
		},
		"MemoryLimit":        true,
		"SwapLimit":          true,
		"CpuCfsPeriod":       true,
		"CpuCfsQuota":        true,
		"CPUShares":          true,
		"CPUSet":             true,
		"OomKillDisable":     false,
		"IPv4Forwarding":     true,
		"BridgeNfIptables":   true,
		"BridgeNfIp6tables":  true,
		"NCPU":               cfg.ncpu(),
		"MemTotal":           cfg.memTotal(),
		"PidsLimit":          true,
		"IndexServerAddress": defaultIndexServer,
		"RegistryConfig":     map[string]interface{}{},
		"DockerRootDir":      cfg.dockerRootDir(),
		"Name":               cfg.hostname(),
		"ServerVersion":      cfg.version(),
		"OperatingSystem":    cfg.operatingSystem(),
		"OSType":             "linux",
		"OSVersion":          cfg.osVersion(),
		"Architecture":       cfg.infoArch(),
		"NEventsListener":    0,
		"KernelVersion":      cfg.kernelVersion(),
		"Debug":              false,
		"NFd":                20,
		"NGoroutines":        40,
		"SystemTime":         time.Now().Format(time.RFC3339),
		"LoggingDriver":      defaultLoggingDriver,
		"CgroupDriver":       cfg.cgroupDriver(),
		"CgroupVersion":      cfg.cgroupVersion(),
		"DefaultRuntime":     cfg.defaultRuntime(),
		"Runtimes":           map[string]interface{}{cfg.defaultRuntime(): map[string]interface{}{"path": cfg.defaultRuntime()}},
		"Swarm":              map[string]interface{}{"NodeID": "", "LocalNodeState": "inactive"},
		"LiveRestoreEnabled": false,
		"Isolation":          "",
		"Labels":             []interface{}{},
		"Warnings":           []interface{}{},
		"InitBinary":         "docker-init",
		"SecurityOptions":    cfg.securityOptions(),
		"KernelMemoryTCP":    true,
		"HttpProxy":          "",
		"HttpsProxy":         "",
		"NoProxy":            "",
		"CDISpecDirs":        []interface{}{},
		"GenericResources":   nil,
		"ContainerdCommit":   map[string]interface{}{"ID": "", "Expected": ""},
		"InitCommit":         map[string]interface{}{"ID": "", "Expected": ""},
		"RuncCommit":         map[string]interface{}{"ID": "", "Expected": ""},
		"ExperimentalBuild":  true,
	}
	if cfg.Experimental {
		// 真机 Experimental 是 omitempty：false 时整个键不下发
		info["Experimental"] = true
	}
	return info
}

// listContainers 容器列表（GET /containers/json）。Command/Ports 按镜像画像
// 派生；支持 name/status/label 过滤与 all 参数。
func listContainers(cfg dockerConfig, all bool, filters map[string][]string) []map[string]interface{} {
	out := make([]map[string]interface{}, 0)
	for _, c := range cfg.store.listContainers() {
		if !all && c.state != "running" {
			continue
		}
		if !matchContainerFilters(c, filters) {
			continue
		}
		prof := profileForImage(c.image)
		ports := make([]map[string]interface{}, 0, len(prof.exposed))
		for _, proto := range prof.exposed {
			name := strings.SplitN(proto, "/", 2)[0]
			port := map[string]interface{}{"PrivatePort": atoiSafe(name), "Type": "tcp"}
			if hp, ok := prof.published[name]; ok {
				port["PublicPort"] = atoiSafe(hp)
			}
			ports = append(ports, port)
		}
		out = append(out, map[string]interface{}{
			"Id":         c.id,
			"Names":      []string{c.name},
			"Image":      c.image,
			"ImageID":    "sha256:" + c.imageID,
			"Command":    prof.command,
			"Created":    c.created,
			"Ports":      ports,
			"SizeRw":     0,
			"SizeRootFs": 0,
			"State":      c.state,
			"Status":     c.statusString(),
			"Labels":     map[string]interface{}{},
		})
	}
	return out
}

func listImages(cfg dockerConfig, filters map[string][]string) []map[string]interface{} {
	out := make([]map[string]interface{}, 0)
	for _, im := range cfg.store.listImages() {
		if !matchImageFilters(im, filters) {
			continue
		}
		out = append(out, map[string]interface{}{
			"Id":          "sha256:" + im.id,
			"ParentId":    "",
			"RepoTags":    im.tags(),
			"RepoDigests": []string{im.ref() + "@" + im.digest},
			"Created":     im.created,
			"Size":        im.size,
			"SharedSize":  0,
			"VirtualSize": im.size,
			"Labels":      nil,
		})
	}
	return out
}

// atoiSafe 把端口号字符串转 int，失败回 0。
func atoiSafe(s string) int {
	n := 0
	fmt.Sscanf(s, "%d", &n)
	return n
}

// boolQuery 解析 Docker 风格布尔查询参数。docker CLI 发的是 all=1/size=1，
// 只认 "true" 会把 ps -a 当成 ps（停止的容器全被过滤）。
func boolQuery(q url.Values, key string) bool {
	v := q.Get(key)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	return err == nil && b
}

// parseListFilters 解析 ?filters={"name":["web"],"status":["running"]}。
// 兼容两种写法：值为数组（["web"]，API 文档/旧客户端）或为对象
// （{"web":true}，docker CLI 的 --filter 实际发出的格式）。
// 返回 nil 表示无过滤；第二个返回值为非空时是错误信息（真机回 400）。
func parseListFilters(raw string) (map[string][]string, string) {
	if strings.TrimSpace(raw) == "" {
		return nil, ""
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &rawMap); err != nil {
		return nil, "Invalid filters"
	}
	f := make(map[string][]string, len(rawMap))
	for k, v := range rawMap {
		// 数组形式：["a","b"]
		var arr []string
		if err := json.Unmarshal(v, &arr); err == nil {
			f[k] = arr
			continue
		}
		// 对象形式：{"a":true,"b":true}
		var obj map[string]interface{}
		if err := json.Unmarshal(v, &obj); err == nil {
			vals := make([]string, 0, len(obj))
			for key := range obj {
				vals = append(vals, key)
			}
			f[k] = vals
			continue
		}
		return nil, "Invalid filters"
	}
	return f, ""
}

// matchContainerFilters 按 name（子串）/ status / label 过滤。
func matchContainerFilters(c *dockerContainer, f map[string][]string) bool {
	if len(f) == 0 {
		return true
	}
	bare := strings.TrimPrefix(c.name, "/")
	for key, vals := range f {
		switch key {
		case "name":
			hit := false
			for _, v := range vals {
				if strings.Contains(bare, v) {
					hit = true
				}
			}
			if !hit {
				return false
			}
		case "status":
			hit := false
			for _, v := range vals {
				if c.state == v {
					hit = true
				}
			}
			if !hit {
				return false
			}
		case "label", "labels":
			// 诱饵容器不带标签，任何 label 过滤都匹配不上
			return false
		}
	}
	return true
}

// matchImageFilters 按 reference（repo:tag 子串）过滤。
func matchImageFilters(im *dockerImage, f map[string][]string) bool {
	if len(f) == 0 {
		return true
	}
	for key, vals := range f {
		switch key {
		case "reference":
			hit := false
			for _, v := range vals {
				if strings.Contains(im.ref(), v) {
					hit = true
				}
			}
			if !hit {
				return false
			}
		case "label", "labels", "dangling":
			return false
		}
	}
	return true
}

func listNetworks(cfg dockerConfig) []map[string]interface{} {
	nets := cfg.store.listNetworks()
	// 按名字排序，输出稳定（真机 docker network ls 亦按名称）
	sort.Slice(nets, func(a, b int) bool { return nets[a].name < nets[b].name })
	out := make([]map[string]interface{}, 0)
	for _, n := range nets {
		out = append(out, map[string]interface{}{
			"Name":       n.name,
			"Id":         n.id,
			"Created":    time.Unix(n.created, 0).Format(time.RFC3339Nano),
			"Scope":      n.scope,
			"Driver":     n.driver,
			"EnableIPv6": false,
			"IPAM": map[string]interface{}{
				"Driver":  "default",
				"Options": nil,
				"Config":  []interface{}{},
			},
			"Internal":   n.internal,
			"Attachable": false,
			"Ingress":    false,
			"Containers": networkContainers(cfg, n),
			"Options":    map[string]interface{}{},
			"Labels":     map[string]interface{}{},
		})
	}
	return out
}

func inspectNetwork(cfg dockerConfig, n *dockerNetwork) map[string]interface{} {
	return map[string]interface{}{
		"Name":       n.name,
		"Id":         n.id,
		"Created":    time.Unix(n.created, 0).Format(time.RFC3339Nano),
		"Scope":      n.scope,
		"Driver":     n.driver,
		"EnableIPv6": false,
		"IPAM": map[string]interface{}{
			"Driver":  "default",
			"Options": nil,
			"Config": []map[string]interface{}{
				{"Subnet": fmt.Sprintf("172.%d.0.0/16", n.subnet), "Gateway": fmt.Sprintf("172.%d.0.1", n.subnet)},
			},
		},
		"Internal":   n.internal,
		"Attachable": false,
		"Ingress":    false,
		"Containers": networkContainers(cfg, n),
		"Options":    map[string]interface{}{},
		"Labels":     map[string]interface{}{},
	}
}

// networkContainers 生成网络里已接入容器的详情映射。IP/MAC 取容器登记的
// 稳定值（与 inspectContainer 一致），EndpointID 由容器 id 派生，多次查询不变。
func networkContainers(cfg dockerConfig, n *dockerNetwork) map[string]interface{} {
	out := map[string]interface{}{}
	for cid, cname := range n.containers {
		c, ok := cfg.store.getContainer(cid)
		if !ok {
			continue
		}
		ip := c.netIPs[n.name]
		mac := ""
		if ip != "" {
			mac = macFromIP(ip)
		}
		ipv4 := ""
		if ip != "" {
			ipv4 = ip + "/16"
		}
		out[cid] = map[string]interface{}{
			"Name":        cname,
			"EndpointID":  c.endpointID,
			"MacAddress":  mac,
			"IPv4Address": ipv4,
			"IPv6Address": "",
		}
	}
	return out
}

func listVolumes(cfg dockerConfig) []map[string]interface{} {
	out := make([]map[string]interface{}, 0)
	for _, v := range cfg.store.listVolumes() {
		out = append(out, map[string]interface{}{
			"CreatedAt":  time.Unix(v.created, 0).Format(time.RFC3339Nano),
			"Driver":     v.driver,
			"Labels":     nil,
			"Mountpoint": v.mountpoint,
			"Name":       v.name,
			"Options":    nil,
			"Scope":      "local",
		})
	}
	return out
}

func inspectVolume(v *dockerVolume) map[string]interface{} {
	return map[string]interface{}{
		"CreatedAt":  time.Unix(v.created, 0).Format(time.RFC3339Nano),
		"Driver":     v.driver,
		"Labels":     nil,
		"Mountpoint": v.mountpoint,
		"Name":       v.name,
		"Options":    nil,
		"Scope":      "local",
	}
}

// systemDF 生成 /system/df 的磁盘占用视图（容器/镜像/卷/BuildCache 计数与真实一致）。
func systemDF(cfg dockerConfig) map[string]interface{} {
	allContainers := cfg.store.listContainers()
	containers := make([]map[string]interface{}, 0)
	for _, c := range allContainers {
		containers = append(containers, map[string]interface{}{
			"Id":         c.id,
			"Names":      []string{c.name},
			"Image":      c.image,
			"ImageID":    "sha256:" + c.imageID,
			"Command":    profileForImage(c.image).command,
			"Created":    c.created,
			"SizeRw":     0,
			"SizeRootFs": 0,
			"State":      c.state,
			"Status":     c.statusString(),
			"Labels":     map[string]interface{}{},
		})
	}
	// 每个镜像被多少个容器引用（真机 docker system df 的 CONTAINERS 列）
	useCount := map[string]int{}
	for _, c := range allContainers {
		useCount[c.imageID]++
	}
	images := make([]map[string]interface{}, 0)
	for _, im := range cfg.store.listImages() {
		images = append(images, map[string]interface{}{
			"Id":          "sha256:" + im.id,
			"ParentId":    "",
			"RepoTags":    im.tags(),
			"RepoDigests": []string{im.ref() + "@" + im.digest},
			"Created":     im.created,
			"Size":        im.size,
			"SharedSize":  -1,
			"Labels":      nil,
			"Containers":  useCount[im.id],
		})
	}
	volumes := make([]map[string]interface{}, 0)
	for _, v := range cfg.store.listVolumes() {
		volumes = append(volumes, map[string]interface{}{
			"CreatedAt":  time.Unix(v.created, 0).Format(time.RFC3339Nano),
			"Name":       v.name,
			"Driver":     v.driver,
			"Mountpoint": v.mountpoint,
			"Labels":     nil,
			"Options":    nil,
			"Scope":      "local",
			"Size":       -1,
			"UsageData":  map[string]interface{}{"RefCount": 0, "Size": -1},
		})
	}
	cacheID, cacheCreated := cfg.store.builderCache()
	var layersSize int64
	for _, im := range cfg.store.listImages() {
		layersSize += im.size
	}
	return map[string]interface{}{
		"LayersSize": layersSize,
		"Images":     images,
		"Containers": containers,
		"Volumes":    volumes,
		"BuilderCache": []map[string]interface{}{{
			"ID":          cacheID,
			"Parent":      "",
			"Type":        "regular",
			"Description": "",
			"InUse":       false,
			"Shared":      true,
			"Size":        0,
			"CreatedAt":   cacheCreated.Format(time.RFC3339Nano),
			"LastUsedAt":  cacheCreated.Add(24 * time.Hour).Format(time.RFC3339Nano),
			"UsageCount":  0,
		}},
	}
}

// builderCache 返回一次运行内稳定的构建缓存 ID 与创建时间（与镜像 seed 同步）。
func (s *dockerStore) builderCache() (string, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.builderCacheID == "" {
		s.builderCacheID = "cache-" + randomID()[:12]
		s.builderCacheUse = time.Now().Add(-48 * time.Hour)
	}
	return s.builderCacheID, s.builderCacheUse
}

// dockerTime 把 unix 时间戳格式化成 RFC3339Nano；0 值按真机输出 "0001-01-01T00:00:00Z"。
func dockerTime(ts int64) string {
	if ts <= 0 {
		return "0001-01-01T00:00:00Z"
	}
	return time.Unix(ts, 0).Format(time.RFC3339Nano)
}

// inspectContainer 容器详情。进程参数/环境变量/端口按镜像画像派生，
// IP/PID/NetworkID 取容器登记的稳定值（与 /networks 一致），未启动的
// 容器没有 IP 与 PID（真机行为）。
func inspectContainer(cfg dockerConfig, c *dockerContainer) map[string]interface{} {
	prof := profileForImage(c.image)
	running := c.state == "running"
	state := map[string]interface{}{
		"Status":     c.state,
		"Running":    running,
		"Paused":     c.state == "paused",
		"Restarting": c.state == "restarting",
		"OOMKilled":  false,
		"Dead":       c.state == "dead",
		"Pid":        0,
		"ExitCode":   c.exitCode,
		"Error":      "",
		"StartedAt":  dockerTime(c.startedAt),
		"FinishedAt": dockerTime(c.finishedAt),
	}
	if running {
		state["Pid"] = c.pid
	}

	// 端口：已发布的给 HostIp/HostPort，仅 EXPOSE 的给 null（真机两种形态都有）
	ports := map[string]interface{}{}
	for _, proto := range prof.exposed {
		name := proto
		if hp, ok := prof.published[strings.SplitN(proto, "/", 2)[0]]; ok && running {
			ports[name] = []map[string]interface{}{
				{"HostIp": "0.0.0.0", "HostPort": hp},
			}
		} else {
			ports[name] = nil
		}
	}

	// 网络：列出容器接入的全部网络（通常只有 bridge），IP/端点 ID 为登记值
	networks := map[string]interface{}{}
	hostname := strings.TrimPrefix(c.name, "/")
	names := make([]string, 0, len(c.netIPs))
	for name := range c.netIPs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		subnet := 17
		networkID := ""
		if n, ok := cfg.store.getNetwork(name); ok {
			subnet = n.subnet
			networkID = n.id
		}
		networks[name] = map[string]interface{}{
			"IPAMConfig":          map[string]interface{}{},
			"Links":               nil,
			"Aliases":             []string{hostname},
			"MacAddress":          macFromIP(c.netIPs[name]),
			"NetworkID":           networkID,
			"EndpointID":          c.endpointID,
			"Gateway":             fmt.Sprintf("172.%d.0.1", subnet),
			"IPAddress":           c.netIPs[name],
			"IPPrefixLen":         16,
			"IPv6Gateway":         "",
			"GlobalIPv6Address":   "",
			"GlobalIPv6PrefixLen": 0,
		}
	}

	exposed := map[string]interface{}{}
	for _, proto := range prof.exposed {
		exposed[proto] = map[string]interface{}{}
	}
	return map[string]interface{}{
		"Id":           c.id,
		"Created":      time.Unix(c.created, 0).Format(time.RFC3339Nano),
		"Path":         prof.entrypoint,
		"Args":         prof.args,
		"State":        state,
		"Image":        "sha256:" + c.imageID,
		"Name":         c.name,
		"RestartCount": 0,
		"Driver":       "overlay2",
		"Platform":     "linux",
		"Config": map[string]interface{}{
			"Hostname":     hostname,
			"Image":        c.image,
			"Labels":       map[string]interface{}{},
			"Env":          prof.env,
			"Cmd":          prof.args,
			"Entrypoint":   entrypointOf(prof),
			"ExposedPorts": exposed,
		},
		"NetworkSettings": map[string]interface{}{
			"Bridge":                 "",
			"SandboxID":              c.id,
			"SandboxKey":             "/var/run/docker/netns/" + c.id[:12],
			"HairpinMode":            false,
			"LinkLocalIPv6Address":   "",
			"LinkLocalIPv6PrefixLen": 0,
			"SecondaryIPAddresses":   nil,
			"SecondaryIPv6Addresses": nil,
			"EndpointID":             "",
			"Gateway":                "",
			"GlobalIPv6Address":      "",
			"GlobalIPv6PrefixLen":    0,
			"IPAddress":              "",
			"IPPrefixLen":            0,
			"IPv6Gateway":            "",
			"MacAddress":             "",
			"Ports":                  ports,
			"Networks":               networks,
		},
	}
}

// entrypointOf 返回画像的 Entrypoint 列表形式（Path 为空表示无 Entrypoint）。
func entrypointOf(prof imageProfile) []string {
	if prof.entrypoint == "" {
		return nil
	}
	return []string{prof.entrypoint}
}

// inspectImage 镜像详情。层 ID 使用登记时固化的值，多次查询一致；
// DockerVersion/Comment 补齐 API 规范字段。
func inspectImage(cfg dockerConfig, im *dockerImage) map[string]interface{} {
	prof := profileForImage(im.ref())
	return map[string]interface{}{
		"Id":              "sha256:" + im.id,
		"RepoTags":        im.tags(),
		"RepoDigests":     []string{im.ref() + "@" + im.digest},
		"Created":         time.Unix(im.created, 0).Format(time.RFC3339Nano),
		"Os":              "linux",
		"Architecture":    cfg.architecture(),
		"Size":            im.size,
		"VirtualSize":     im.size,
		"Parent":          "",
		"Comment":         "",
		"Author":          "",
		"DockerVersion":   cfg.version(),
		"GraphDriver":     map[string]interface{}{"Name": "overlay2", "Data": nil},
		"RootFS":          map[string]interface{}{"Type": "layers", "Layers": im.layers},
		"Config":          imageConfigFor(prof),
		"ContainerConfig": imageConfigFor(prof),
	}
}

// imageConfigFor 镜像/容器配置块（真机 inspect 的 Config/ContainerConfig）。
func imageConfigFor(prof imageProfile) map[string]interface{} {
	exposed := map[string]interface{}{}
	for _, proto := range prof.exposed {
		exposed[proto] = map[string]interface{}{}
	}
	return map[string]interface{}{
		"Hostname":     "",
		"Image":        "",
		"Labels":       nil,
		"Env":          prof.env,
		"Cmd":          prof.args,
		"Entrypoint":   entrypointOf(prof),
		"ExposedPorts": exposed,
	}
}

// macFromIP 由 IPv4 生成 Docker 风格的 MAC（02:42:xx:xx:xx:xx）。
func macFromIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	oct := make([]int, 4)
	for i, p := range parts {
		fmt.Sscanf(p, "%d", &oct[i])
	}
	return fmt.Sprintf("02:42:%02x:%02x:%02x:%02x", oct[0], oct[1], oct[2], oct[3])
}

// ---- 响应辅助 ----

func wantPretty(req *http.Request) bool {
	q := req.URL.Query()
	if !q.Has("pretty") {
		return false
	}
	return !strings.EqualFold(q.Get("pretty"), "false")
}

func respondJSON(conn net.Conn, req *http.Request, status int, payload interface{}) {
	var data []byte
	var err error
	if wantPretty(req) {
		data, err = json.MarshalIndent(payload, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	} else {
		data, err = json.Marshal(payload)
	}
	if err != nil {
		logger.Log.Debug(serviceName, " marshal error:", err)
		data = []byte(`{"message":"internal error"}`)
		status = http.StatusInternalServerError
	}
	respond(conn, req, status, "application/json", data)
}

func respondText(conn net.Conn, req *http.Request, status int, text string) {
	respond(conn, req, status, "text/plain; charset=utf-8", []byte(text))
}

func respondEmpty(conn net.Conn, req *http.Request, status int) {
	respond(conn, req, status, "application/json", nil)
}

// respondStream 以换行分隔的 JSON 对象流响应（Docker /images/create 等流式端点）。
func respondStream(conn net.Conn, req *http.Request, status int, objects []interface{}) {
	var buf bytes.Buffer
	for _, o := range objects {
		b, err := json.Marshal(o)
		if err != nil {
			continue
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	respond(conn, req, status, "application/json", buf.Bytes())
}

func respond(conn net.Conn, req *http.Request, status int, contentType string, body []byte) {
	resp := http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Proto:         req.Proto,
		ProtoMajor:    req.ProtoMajor,
		ProtoMinor:    req.ProtoMinor,
		Header:        http.Header{},
		Body:          http.NoBody,
		ContentLength: int64(len(body)),
		Request:       req,
	}
	resp.Header.Set("Content-Type", contentType)
	resp.Header.Set("Api-Version", serverAPIVersionString())
	resp.Header.Set("Ostype", "linux")
	resp.Header.Set("Docker-Experimental", fmt.Sprintf("%t", serverExperimental.Load()))
	resp.Header.Set("Server", "Docker/"+serverVersionString()+" (linux)")
	if req.Method != "HEAD" {
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	if err := resp.Write(conn); err != nil {
		logger.Log.Debug(serviceName, " write error:", err)
	}
}

// serverVersionString 读出版本字符串；未初始化（理论上不会）时回落默认值。
func serverVersionString() string {
	if v, ok := serverVersion.Load().(string); ok && v != "" {
		return v
	}
	return defaultVersion
}

// serverAPIVersionString 读出 API 版本字符串；未初始化时回落默认值。
func serverAPIVersionString() string {
	if v, ok := serverAPIVersion.Load().(string); ok && v != "" {
		return v
	}
	return defaultAPIVersion
}

// respondError Docker 风格 404/错误 JSON。
func respondError(conn net.Conn, req *http.Request, status int, message string) {
	respondJSON(conn, req, status, map[string]interface{}{
		"message": message,
	})
}

func respondNotFound(conn net.Conn, req *http.Request, message string) {
	respondJSON(conn, req, http.StatusNotFound, map[string]interface{}{
		"message": message,
	})
}

// parseRegistryAuth 解析 X-Registry-Auth（base64 的 JSON 凭证）。
func parseRegistryAuth(auth string) (user, pass, server string, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth))
	if err != nil {
		// 有些客户端用 url-safe/无 padding 变体
		if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(auth)); err != nil {
			return "", "", "", false
		}
	}
	var cred struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		ServerAddress string `json:"serveraddress"`
	}
	if err := json.Unmarshal(raw, &cred); err != nil {
		return "", "", "", false
	}
	return cred.Username, cred.Password, cred.ServerAddress, true
}

// ---- 解析辅助 ----

func parseBasicAuth(auth string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	cred := string(raw)
	i := strings.IndexByte(cred, ':')
	if i < 0 {
		return cred, "", true
	}
	return cred[:i], cred[i+1:], true
}

func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("0", containerIDLen)
	}
	return hex.EncodeToString(b)
}

// ---- 名称生成 / 校验 ----

// randomName 生成 Docker 风格的随机容器名（adjective_surname，如 boring_feynman）。
func randomName() string {
	left := []string{
		"admiring", "adoring", "affectionate", "agitated", "amazing", "awesome",
		"blissful", "bold", "boring", "brave", "busy", "calm", "charming", "clever",
		"cool", "cranky", "crazy", "dazzling", "determined", "dreamy",
	}
	right := []string{
		"almeida", "bassi", "bernes", "bhabha", "blackwell", "bohr", "booth",
		"borg", "bose", "boyd", "brahmagupta", "brattain", "brown", "carson",
		"cartwright", "carver", "cerf", "chandrasekhar", "chapman", "cocks",
	}
	return left[randIndex(len(left))] + "_" + right[randIndex(len(right))]
}

// randIndex 取 [0,n) 的随机下标（crypto/rand，失败退 0）。
func randIndex(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		return 0
	}
	return int(b[0]) % n
}

// validContainerName 真机容器名规则：[a-zA-Z0-9][a-zA-Z0-9_.-]*。
func validContainerName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// ---- tar 流（docker save / docker export）----

// tarEntry 一个 tar 条目（目录或文件）。
type tarEntry struct {
	name string
	data []byte
	dir  bool
}

// writeTar 生成最小合法 tar（含两个结束块）。
func writeTar(entries []tarEntry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Mode: 0644, ModTime: time.Now()}
		if e.dir {
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0755
			hdr.Name = e.name + "/"
		} else {
			hdr.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			continue
		}
		if !e.dir {
			_, _ = tw.Write(e.data)
		}
	}
	_ = tw.Close()
	return buf.Bytes()
}

// respondTar 以 tar 流响应（真机 docker save / export 的 Content-Type）。
func respondTar(conn net.Conn, req *http.Request, data []byte) {
	respond(conn, req, http.StatusOK, "application/x-tar", data)
}

// imageSaveTar 生成 docker save 风格的镜像 tar：
// manifest.json + <id>.json(config) + <layer>/{VERSION,json,layer.tar} + repositories。
func imageSaveTar(im *dockerImage) []byte {
	prof := profileForImage(im.ref())
	layers := make([]string, 0, len(im.layers))
	layerEntries := make([]tarEntry, 0, len(im.layers)*4)
	for _, layer := range im.layers {
		dir := strings.TrimPrefix(layer, "sha256:")
		layers = append(layers, dir+"/layer.tar")
		layerEntries = append(layerEntries,
			tarEntry{name: dir, dir: true},
			tarEntry{name: dir + "/VERSION", data: []byte("1.0\n")},
			tarEntry{name: dir + "/json", data: []byte("{}")},
			tarEntry{name: dir + "/layer.tar", data: writeTar(nil)},
		)
	}
	manifest, _ := json.Marshal([]map[string]interface{}{{
		"Config":   im.id + ".json",
		"RepoTags": im.tags(),
		"Layers":   layers,
	}})
	config, _ := json.Marshal(map[string]interface{}{
		"id":           im.id,
		"architecture": "amd64",
		"os":           "linux",
		"created":      time.Unix(im.created, 0).Format(time.RFC3339Nano),
		"config":       imageConfigFor(prof),
		"rootfs": map[string]interface{}{
			"type":     "layers",
			"diff_ids": im.layers,
		},
	})
	repositories, _ := json.Marshal(map[string]interface{}{
		im.ref(): map[string]string{im.id: strings.TrimPrefix(im.layers[len(im.layers)-1], "sha256:")},
	})
	entries := []tarEntry{
		{name: im.id + ".json", data: config},
		{name: "manifest.json", data: manifest},
		{name: "repositories", data: repositories},
	}
	entries = append(entries, layerEntries...)
	return writeTar(entries)
}

// containerExportTar 生成 docker export 风格的文件系统 tar（目录骨架 +
// etc 下的身份文件 + 镜像入口点占位）。
func containerExportTar(cfg dockerConfig, id string) []byte {
	c, _ := cfg.store.getContainer(id)
	hostname := "host"
	if c != nil && c.name != "" {
		hostname = strings.TrimPrefix(c.name, "/")
	}
	entries := []tarEntry{
		{name: "bin", dir: true},
		{name: "etc", dir: true},
		{name: "etc/hostname", data: []byte(hostname + "\n")},
		{name: "etc/hosts", data: []byte("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n")},
		{name: "etc/resolv.conf", data: []byte("nameserver 8.8.8.8\n")},
		{name: "lib", dir: true},
		{name: "usr", dir: true},
		{name: "var", dir: true},
	}
	if c != nil {
		prof := profileForImage(c.image)
		if prof.entrypoint != "" {
			entries = append(entries, tarEntry{
				name: strings.TrimPrefix(prof.entrypoint, "/"),
				data: []byte("#!/bin/sh\n"),
			})
		}
	}
	return writeTar(entries)
}

// imageHistory 生成 /images/{name}/history（顶层在上，与真机一致）；
// 每层一条记录，大小按镜像总大小均分。
func imageHistory(im *dockerImage) []map[string]interface{} {
	prof := profileForImage(im.ref())
	n := len(im.layers)
	if n == 0 {
		return []map[string]interface{}{}
	}
	size := int(im.size) / n // 各层均分镜像总大小
	out := make([]map[string]interface{}, 0, n)
	for i := n - 1; i >= 0; i-- {
		createdBy := "/bin/sh -c #(nop) ADD file:5f5f3d8b3d1b7d8ab8b4b7c9c1f4b3a2 in / "
		if i == n-1 {
			createdBy = "/bin/sh -c #(nop)  CMD [" + cmdString(prof.args) + "]"
		}
		// 顶层层兜底余数，保证各层之和正好等于镜像 Size
		layerSize := size
		if i == n-1 {
			layerSize = int(im.size) - size*(n-1)
		}
		entry := map[string]interface{}{
			"Id":        im.layers[i],
			"Created":   im.created - int64((n-1-i)*137), // 真机 history 的 Created 是 int64 unix 时间戳
			"CreatedBy": createdBy,
			"Size":      layerSize,
			"Comment":   "",
		}
		if i == n-1 {
			entry["Tags"] = im.tags()
		} else {
			entry["Tags"] = nil
		}
		out = append(out, entry)
	}
	return out
}

// cmdString 按真机 history 的样式拼 CMD：["nginx" "-g" "daemon off;"]。
func cmdString(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = `"` + a + `"`
	}
	return strings.Join(parts, " ")
}
