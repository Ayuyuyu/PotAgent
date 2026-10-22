package docker

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"potAgent/global"
	"potAgent/services"
)

// ---- 测试基建 ----

func testConfig() dockerConfig {
	zero := 0
	return dockerConfig{
		store:      newDockerStore(),
		APIVersion: "1.45",
		Version:    "26.1.3",
		PullPaceMS: &zero, // 测试里拉取/构建流瞬时输出，不等进度停顿
	}
}

// startTestServer 起一个 127.0.0.1 随机端口的实例，按 handleConn 处理连接。
func startTestServer(t *testing.T, cfg dockerConfig) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	svc := &services.Service{
		BaseOptions:    global.ServiceBaseConfig{Protocol: "docker-api", Application: "docker-api"},
		ServiceOptions: cfg,
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(c, svc, cfg)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func do(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

// decode 把响应体解析成 map/slice，失败即挂测试。
func decode(t *testing.T, body string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return m
}

func decodeList(t *testing.T, body string) []map[string]interface{} {
	t.Helper()
	var l []map[string]interface{}
	if err := json.Unmarshal([]byte(body), &l); err != nil {
		t.Fatalf("decodeList %q: %v", body, err)
	}
	return l
}

func mustField(t *testing.T, m map[string]interface{}, key string) interface{} {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("missing field %q in %v", key, m)
	}
	return v
}

// ---- 纯函数 ----

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "Less than a second"},
		{1 * time.Second, "1 second"},
		{30 * time.Second, "30 seconds"},
		{90 * time.Second, "About a minute"},
		{5 * time.Minute, "5 minutes"},
		{time.Hour, "About an hour"},
		{2 * time.Hour, "2 hours"},
		{3 * time.Hour, "3 hours"},
		{24 * time.Hour, "24 hours"},
		{50 * time.Hour, "2 days"},
	}
	for _, c := range cases {
		if got := humanDuration(c.in); got != c.want {
			t.Fatalf("humanDuration(%v)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{512, "512 B"},
		{32768, "32.768 kB"},
		{2244027, "2.244 MB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Fatalf("humanBytes(%d)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestSplitRepoTag(t *testing.T) {
	cases := []struct {
		in       string
		wantRepo string
		wantTag  string
	}{
		{"nginx:latest", "nginx", "latest"},
		{"nginx", "nginx", "latest"},
		{"redis:7", "redis", "7"},
		{"localhost:5000/app:v1", "localhost:5000/app", "v1"},
		{"", "", "latest"},
	}
	for _, c := range cases {
		repo, tag := splitRepoTag(c.in)
		if repo != c.wantRepo || tag != c.wantTag {
			t.Fatalf("splitRepoTag(%q)=(%q,%q) want (%q,%q)", c.in, repo, tag, c.wantRepo, c.wantTag)
		}
	}
}

func TestStripVersionPrefix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/v1.45/containers/json", "/containers/json"},
		{"/v1.45/version", "/version"},
		{"/v1.45/images/create", "/images/create"},
		{"/version", "/version"},
		{"/volumes", "/volumes"},                 // 以 v 开头但不是版本号
		{"/volumes/db-data", "/volumes/db-data"}, // 同上
		{"/containers/json", "/containers/json"},
	}
	for _, c := range cases {
		if got := stripVersionPrefix(c.in); got != c.want {
			t.Fatalf("stripVersionPrefix(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestParseBasicAuth(t *testing.T) {
	user, pass, ok := parseBasicAuth("Basic ZG9ja2VyOnNlY3JldA==") // docker:secret
	if !ok || user != "docker" || pass != "secret" {
		t.Fatalf("parseBasicAuth=(%q,%q,%v)", user, pass, ok)
	}
	if _, _, ok := parseBasicAuth("Bearer abc"); ok {
		t.Fatalf("Bearer should not parse")
	}
	if _, _, ok := parseBasicAuth(""); ok {
		t.Fatalf("empty should not parse")
	}
}

func TestContainerStatusString(t *testing.T) {
	now := time.Now()
	c := &dockerContainer{state: "running", startedAt: now.Add(-3 * time.Hour).Unix()}
	if got := c.statusString(); got != "Up 3 hours" {
		t.Fatalf("running status=%q", got)
	}
	c = &dockerContainer{state: "exited", finishedAt: now.Add(-90 * time.Second).Unix()}
	if got := c.statusString(); got != "Exited (0) About a minute ago" {
		t.Fatalf("exited status=%q", got)
	}
	c = &dockerContainer{state: "exited", exitCode: 137, finishedAt: now.Unix()}
	if got := c.statusString(); got != "Exited (137) Less than a second ago" {
		t.Fatalf("killed status=%q", got)
	}
	c = &dockerContainer{state: "paused", startedAt: now.Add(-time.Hour).Unix()}
	if got := c.statusString(); got != "Up About an hour (Paused)" {
		t.Fatalf("paused status=%q", got)
	}
	c = &dockerContainer{state: "created"}
	if got := c.statusString(); got != "Created" {
		t.Fatalf("created status=%q", got)
	}
}

// ---- 数据层 ----

func TestStoreSeedImageLink(t *testing.T) {
	cfg := testConfig()
	cfg.store.ensureSeeded(cfg)

	// 镜像先登记：容器 imageID 必须能在 images 里找到
	imgIDs := map[string]bool{}
	for _, im := range cfg.store.listImages() {
		imgIDs[im.id] = true
	}
	if len(imgIDs) == 0 {
		t.Fatalf("no seeded images")
	}
	for _, c := range cfg.store.listContainers() {
		if c.imageID == "" || !imgIDs[c.imageID] {
			t.Fatalf("container %s imageID %q not in images", c.name, c.imageID)
		}
		if c.image != "nginx:latest" && c.image != "redis:7" {
			t.Fatalf("unexpected seeded image %q", c.image)
		}
	}

	// 预置网络/卷
	if len(cfg.store.listNetworks()) == 0 || len(cfg.store.listVolumes()) == 0 {
		t.Fatalf("networks/volumes not seeded")
	}
	if _, ok := cfg.store.getNetwork("bridge"); !ok {
		t.Fatalf("bridge network missing")
	}

	containers, running, _, stopped, images := cfg.store.counts()
	if containers != 2 || running != 2 || stopped != 0 || images == 0 {
		t.Fatalf("counts=(%d,%d,%d,%d)", containers, running, stopped, images)
	}
}

func TestContainerStateTransitions(t *testing.T) {
	cfg := testConfig()
	cfg.store.ensureSeeded(cfg)

	// create 一个本地已有的镜像（nginx:latest 已 seed）
	id, ok := cfg.store.createContainer("/demo", "nginx:latest")
	if !ok {
		t.Fatalf("createContainer with existing image failed")
	}
	c, ok := cfg.store.getContainer(id)
	if !ok || c.state != "created" {
		t.Fatalf("after create state=%q ok=%v", c.state, ok)
	}
	// create 与已有镜像精确关联，未重复登记镜像
	if c.imageID == "" {
		t.Fatalf("created container has no imageID")
	}
	im, ok := cfg.store.getImageByName("nginx:latest")
	if !ok || im.id != c.imageID {
		t.Fatalf("created container not linked to nginx:latest")
	}
	if n := len(cfg.store.listImages()); n != 2 {
		t.Fatalf("create should not register new images, got %d", n)
	}
	// 本地没有的镜像拒绝创建
	if _, ok := cfg.store.createContainer("/x", "no/such:1.0"); ok {
		t.Fatalf("create with missing image should fail")
	}

	cfg.store.setContainerState(id, "running", 0)
	if c.state != "running" || c.startedAt == 0 {
		t.Fatalf("after start state=%q startedAt=%d", c.state, c.startedAt)
	}
	// 启动后分配到 bridge IP 与 PID
	if c.netIPs["bridge"] == "" || c.pid == 0 {
		t.Fatalf("after start ip=%q pid=%d", c.netIPs["bridge"], c.pid)
	}

	cfg.store.setContainerState(id, "paused", 0)
	if c.state != "paused" {
		t.Fatalf("after pause state=%q", c.state)
	}

	cfg.store.setContainerState(id, "exited", 137)
	if c.state != "exited" || c.exitCode != 137 || c.finishedAt == 0 {
		t.Fatalf("after kill state=%q code=%d finishedAt=%d", c.state, c.exitCode, c.finishedAt)
	}
	// 停止后释放 IP 与 PID
	if _, ok := c.netIPs["bridge"]; ok || c.pid != 0 {
		t.Fatalf("after stop ip/pid not released: %v %d", c.netIPs, c.pid)
	}

	// 不存在的容器
	if cfg.store.setContainerState("nope", "running", 0) {
		t.Fatalf("setContainerState on missing id should fail")
	}
}

// TestContainerResolveByNameAndPrefix 覆盖按名称/短 ID 前缀解析容器。
func TestContainerResolveByNameAndPrefix(t *testing.T) {
	cfg := testConfig()
	cfg.store.ensureSeeded(cfg)

	list := cfg.store.listContainers()
	if len(list) != 2 {
		t.Fatalf("seeded containers=%d", len(list))
	}
	// 按名称（带/不带前导 /）
	if c, ok := cfg.store.getContainer("web"); !ok || c.name != "/web" {
		t.Fatalf("resolve by bare name: %v %v", c, ok)
	}
	if c, ok := cfg.store.getContainer("/web"); !ok || c.name != "/web" {
		t.Fatalf("resolve by name with slash: %v %v", c, ok)
	}
	// 按短 ID 前缀
	short := list[0].id[:12]
	if c, ok := cfg.store.getContainer(short); !ok || c.id != list[0].id {
		t.Fatalf("resolve by short id %s: %v %v", short, c, ok)
	}
	// 不存在的引用
	if _, ok := cfg.store.getContainer("nosuch"); ok {
		t.Fatalf("missing name should not resolve")
	}
}

// TestSeedTimesDiffer seed 容器的创建/启动时间应错开（Status 长短不一）。
func TestSeedTimesDiffer(t *testing.T) {
	cfg := testConfig()
	cfg.store.ensureSeeded(cfg)

	list := cfg.store.listContainers()
	created := map[int64]bool{}
	for _, c := range list {
		created[c.created] = true
		if c.state == "running" && (c.startedAt <= c.created || c.pid == 0 || c.netIPs["bridge"] == "") {
			t.Fatalf("running container %s missing startedAt/pid/ip: %+v", c.name, c)
		}
	}
	if len(created) < 2 {
		t.Fatalf("seeded containers share created time, looks fake")
	}
}

// TestImageLayersStable 同一镜像多次查询层 ID 必须一致。
func TestImageLayersStable(t *testing.T) {
	cfg := testConfig()
	cfg.store.ensureSeeded(cfg)

	im, ok := cfg.store.getImageByName("nginx:latest")
	if !ok || len(im.layers) == 0 {
		t.Fatalf("nginx:latest missing layers")
	}
	again, _ := cfg.store.getImageByName(im.id)
	if len(again.layers) != len(im.layers) {
		t.Fatalf("layer count changed")
	}
	for i := range im.layers {
		if im.layers[i] != again.layers[i] {
			t.Fatalf("layer %d changed: %s vs %s", i, im.layers[i], again.layers[i])
		}
	}
	// 短 ID 前缀也能查
	if got, ok := cfg.store.getImageByName(im.id[:12]); !ok || got.id != im.id {
		t.Fatalf("image short-id prefix lookup failed")
	}
}

func TestContainerNameConflict(t *testing.T) {
	cfg := testConfig()
	cfg.store.ensureSeeded(cfg)

	if id, found := cfg.store.containerNameExists("/web"); !found || id == "" {
		t.Fatalf("seeded /web not found: %q %v", id, found)
	}
	if _, found := cfg.store.containerNameExists("/nope"); found {
		t.Fatalf("unexpected name hit")
	}
}

func TestImagePullInspectDelete(t *testing.T) {
	cfg := testConfig()
	cfg.store.ensureSeeded(cfg)

	id := cfg.store.addImage("alpine", "3.19")
	im, ok := cfg.store.getImageByName(id)
	if !ok || im.ref() != "alpine:3.19" {
		t.Fatalf("getImageByName(id)=(%v,%v)", im, ok)
	}
	// 同名复用，不重复入库
	if cfg.store.addImage("alpine", "3.19") != id {
		t.Fatalf("duplicate image should be reused")
	}
	// 按 repo:tag 删除
	if !cfg.store.deleteImageByName("alpine:3.19") {
		t.Fatalf("deleteImageByName failed")
	}
	if _, ok := cfg.store.getImageByName("alpine:3.19"); ok {
		t.Fatalf("image still present after delete")
	}
	if cfg.store.deleteImageByName("alpine:3.19") {
		t.Fatalf("second delete should fail")
	}
}

func TestVolumeCRUD(t *testing.T) {
	cfg := testConfig()
	cfg.store.ensureSeeded(cfg)

	cfg.store.createVolume("db-data", "")
	if cfg.store.getVolumeByName("db-data") == nil {
		t.Fatalf("volume not created")
	}
	if got := cfg.store.createVolume("db-data", ""); got != "db-data" {
		t.Fatalf("recreate volume=%q", got)
	}
	if !cfg.store.deleteVolume("db-data") {
		t.Fatalf("delete volume failed")
	}
	if cfg.store.deleteVolume("db-data") {
		t.Fatalf("second delete should fail")
	}
}

func TestNetworkCRUDAndConnect(t *testing.T) {
	cfg := testConfig()
	cfg.store.ensureSeeded(cfg)

	id := cfg.store.createNetwork("app-net", "", false)
	n, ok := cfg.store.getNetwork(id)
	if !ok || n.name != "app-net" || n.driver != "bridge" {
		t.Fatalf("getNetwork=(%v,%v)", n, ok)
	}
	// 名字也能查
	if _, ok := cfg.store.getNetwork("app-net"); !ok {
		t.Fatalf("getNetwork by name failed")
	}
	// 接一个容器
	cid := cfg.store.listContainers()[0].id
	if _, ok := cfg.store.connectContainer("app-net", cid); !ok {
		t.Fatalf("connectContainer failed")
	}
	// 新网络有独立子网（不复用 bridge 的 17），接入容器分到该子网内的 IP
	appNet, _ := cfg.store.getNetwork("app-net")
	if appNet.subnet <= 17 {
		t.Fatalf("app-net subnet=%d should be beyond bridge(17)", appNet.subnet)
	}
	c, _ := cfg.store.getContainer(cid)
	if ip := c.netIPs["app-net"]; !strings.HasPrefix(ip, fmt.Sprintf("172.%d.0.", appNet.subnet)) {
		t.Fatalf("connected ip=%q not in subnet 172.%d.0.0/16", ip, appNet.subnet)
	}
	if _, ok := cfg.store.connectContainer("app-net", "missing"); ok {
		t.Fatalf("connect to missing container should fail")
	}
	if !cfg.store.disconnectContainer("app-net", cid) {
		t.Fatalf("disconnectContainer failed")
	}
	if cfg.store.disconnectContainer("app-net", cid) {
		t.Fatalf("second disconnect should fail")
	}
	if !cfg.store.deleteNetwork("app-net") {
		t.Fatalf("deleteNetwork failed")
	}
	if _, ok := cfg.store.getNetwork("app-net"); ok {
		t.Fatalf("network still present after delete")
	}
}

// ---- HTTP 端到端 ----

func TestHTTPVersionPingInfo(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	if code, body := do(t, "GET", base+"/version", ""); code != 200 {
		t.Fatalf("GET /version code=%d", code)
	} else {
		v := decode(t, body)
		if mustField(t, v, "Version") != "26.1.3" || mustField(t, v, "ApiVersion") != "1.45" {
			t.Fatalf("version fields: %v", v)
		}
		if mustField(t, v, "Experimental") != false {
			t.Fatalf("Experimental should be false")
		}
		comps, ok := mustField(t, v, "Components").([]interface{})
		if !ok || len(comps) != 4 {
			t.Fatalf("Components: %v", v["Components"])
		}
		names := []string{}
		for _, c := range comps {
			names = append(names, decode(t, mustJSON(t, c))["Name"].(string))
		}
		if strings.Join(names, ",") != "Engine,containerd,runc,docker-init" {
			t.Fatalf("component names: %v", names)
		}
	}

	if code, body := do(t, "GET", base+"/_ping", ""); code != 200 || body != "OK" {
		t.Fatalf("GET /_ping = %d %q", code, body)
	}

	if code, body := do(t, "GET", base+"/info", ""); code != 200 {
		t.Fatalf("GET /info code=%d", code)
	} else {
		info := decode(t, body)
		if mustField(t, info, "Containers").(float64) != 2 {
			t.Fatalf("info Containers: %v", info["Containers"])
		}
		if mustField(t, info, "ContainersRunning").(float64) != 2 {
			t.Fatalf("info ContainersRunning: %v", info["ContainersRunning"])
		}
	}
}

// mustJSON 把 interface{} 再编码回字符串，便于复用 decode。
func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHTTPExperimentalHeader(t *testing.T) {
	cfg := testConfig()
	cfg.Experimental = true
	addr, stop := startTestServer(t, cfg)
	defer stop()

	resp, err := http.Get("http://" + addr + "/version")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Docker-Experimental"); got != "true" {
		t.Fatalf("Docker-Experimental=%q", got)
	}
	if got := resp.Header.Get("Server"); got != "Docker/26.1.3 (linux)" {
		t.Fatalf("Server=%q", got)
	}
	if decode(t, mustRead(t, resp))["Experimental"] != true {
		t.Fatalf("/version Experimental should be true")
	}
}

func mustRead(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestHTTPVersionPrefix(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 带版本前缀的路径照常路由
	if code, _ := do(t, "GET", base+"/v1.45/containers/json", ""); code != 200 {
		t.Fatalf("/v1.45/containers/json code=%d", code)
	}
	if code, body := do(t, "GET", base+"/v1.45/_ping", ""); code != 200 || body != "OK" {
		t.Fatalf("/v1.45/_ping = %d %q", code, body)
	}
}

func TestHTTPPageNotFound(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	for _, tc := range []struct{ method, path string }{
		{"GET", "/containers"},           // 无 /json
		{"GET", "/images/create"},        // create 仅 POST
		{"GET", "/containers/create"},    // create 仅 POST
		{"GET", "/containers/abc/bogus"}, // 未知子路径
		{"GET", "/volumes/a/b"},          // 卷名不含 /
		{"GET", "/nosuchapi"},
	} {
		code, body := do(t, tc.method, base+tc.path, "")
		if code != 404 {
			t.Fatalf("%s %s code=%d want 404", tc.method, tc.path, code)
		}
		if !strings.Contains(body, `"message":"page not found"`) {
			t.Fatalf("%s %s body=%q want page not found", tc.method, tc.path, body)
		}
	}
}

func TestHTTPContainersListAll(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 默认只回 running
	code, body := do(t, "GET", base+"/containers/json", "")
	if code != 200 {
		t.Fatalf("list code=%d", code)
	}
	list := decodeList(t, body)
	if len(list) != 2 {
		t.Fatalf("default list len=%d want 2", len(list))
	}
	for _, c := range list {
		if c["State"] != "running" {
			t.Fatalf("default list contains non-running: %v", c)
		}
		if !strings.Contains(c["Status"].(string), "Up ") {
			t.Fatalf("status not 'Up ...': %v", c["Status"])
		}
	}

	// all=true 回全部
	_, body = do(t, "GET", base+"/containers/json?all=true", "")
	if got := len(decodeList(t, body)); got != 2 {
		t.Fatalf("all list len=%d want 2", got)
	}
}

func TestHTTPContainerLifecycle(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// create（201）
	code, body := do(t, "POST", base+"/containers/create?name=demo", `{"Image":"nginx:latest"}`)
	if code != 201 {
		t.Fatalf("create code=%d body=%s", code, body)
	}
	id := decode(t, body)["Id"].(string)
	if id == "" {
		t.Fatalf("empty container id")
	}

	// created 状态不出现在默认列表里
	_, body = do(t, "GET", base+"/containers/json", "")
	if len(decodeList(t, body)) != 2 {
		t.Fatalf("created container should not be in default list")
	}
	// 但 all=true 能看到
	_, body = do(t, "GET", base+"/containers/json?all=true", "")
	if len(decodeList(t, body)) != 3 {
		t.Fatalf("all list should contain the created container")
	}

	// inspect：state=created，StartedAt 为零值
	code, body = do(t, "GET", base+"/containers/"+id+"/json", "")
	if code != 200 {
		t.Fatalf("inspect code=%d", code)
	}
	insp := decode(t, body)
	state := decode(t, mustJSON(t, insp["State"]))
	if state["Status"] != "created" {
		t.Fatalf("inspect state=%v", state["Status"])
	}
	if state["StartedAt"] != "0001-01-01T00:00:00Z" {
		t.Fatalf("StartedAt=%v want zero time", state["StartedAt"])
	}
	if insp["Image"] != "sha256:"+imageIDOf(t, addr, "nginx:latest") {
		t.Fatalf("inspect Image=%v not linked to images", insp["Image"])
	}

	// start -> running（重复 start 回 304）
	if code, _ := do(t, "POST", base+"/containers/"+id+"/start", ""); code != 204 {
		t.Fatalf("start code=%d", code)
	}
	if code, _ := do(t, "POST", base+"/containers/"+id+"/start", ""); code != 304 {
		t.Fatalf("second start code=%d want 304", code)
	}
	_, body = do(t, "GET", base+"/containers/"+id+"/json", "")
	if st := decode(t, mustJSON(t, decode(t, body)["State"])); st["Status"] != "running" {
		t.Fatalf("after start state=%v", st["Status"])
	}

	// 默认列表现在有 3 个
	_, body = do(t, "GET", base+"/containers/json", "")
	if len(decodeList(t, body)) != 3 {
		t.Fatalf("running list should be 3")
	}

	// pause -> 状态与 Status 文案
	if code, _ := do(t, "POST", base+"/containers/"+id+"/pause", ""); code != 204 {
		t.Fatalf("pause code=%d", code)
	}
	_, body = do(t, "GET", base+"/containers/"+id+"/json", "")
	if st := decode(t, mustJSON(t, decode(t, body)["State"])); st["Paused"] != true {
		t.Fatalf("after pause Paused=%v", st["Paused"])
	}
	if code, _ := do(t, "POST", base+"/containers/"+id+"/unpause", ""); code != 204 {
		t.Fatalf("unpause code=%d", code)
	}

	// stop -> exited
	if code, _ := do(t, "POST", base+"/containers/"+id+"/stop", ""); code != 204 {
		t.Fatalf("stop code=%d", code)
	}
	_, body = do(t, "GET", base+"/containers/"+id+"/json", "")
	st := decode(t, mustJSON(t, decode(t, body)["State"]))
	if st["Status"] != "exited" || st["ExitCode"].(float64) != 0 || st["FinishedAt"] == "0001-01-01T00:00:00Z" {
		t.Fatalf("after stop state=%v", st)
	}

	// 删除（已停止 -> 204）
	if code, _ := do(t, "DELETE", base+"/containers/"+id, ""); code != 204 {
		t.Fatalf("delete code=%d", code)
	}
	if code, _ := do(t, "GET", base+"/containers/"+id+"/json", ""); code != 404 {
		t.Fatalf("inspect after delete code=%d", code)
	}
}

func TestHTTPContainerErrors(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 容器名冲突（/web 已预置）
	code, body := do(t, "POST", base+"/containers/create?name=web", `{"Image":"x"}`)
	if code != 409 {
		t.Fatalf("name conflict code=%d want 409", code)
	}
	if !strings.Contains(body, "Conflict. The container name") ||
		!strings.Contains(body, "already in use by container") {
		t.Fatalf("conflict body=%q", body)
	}

	// 不存在的容器
	for _, p := range []string{"/containers/nosuch/start", "/containers/nosuch/json", "/containers/nosuch/stop"} {
		if code, body := do(t, "POST", base+p, ""); code != 404 || !strings.Contains(body, "No such container") {
			t.Fatalf("%s = %d %q", p, code, body)
		}
	}

	// 非运行容器 kill -> 409
	_, body = do(t, "POST", base+"/containers/create", `{"Image":"nginx:latest"}`)
	id := decode(t, body)["Id"].(string)
	if code, body := do(t, "POST", base+"/containers/"+id+"/kill", ""); code != 409 ||
		!strings.Contains(body, "Container is not running") {
		t.Fatalf("kill not-running = %d %q", code, body)
	}

	// 运行中删除 -> 409
	if code, _ := do(t, "POST", base+"/containers/"+id+"/start", ""); code != 204 {
		t.Fatalf("start code=%d", code)
	}
	if code, body := do(t, "DELETE", base+"/containers/"+id, ""); code != 409 ||
		!strings.Contains(body, "You cannot remove a running container") {
		t.Fatalf("delete running = %d %q", code, body)
	}
}

func TestHTTPImageIDMatchesContainer(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	_, body := do(t, "GET", base+"/images/json", "")
	imgIDs := map[string]bool{}
	for _, im := range decodeList(t, body) {
		imgIDs[im["Id"].(string)] = true
	}
	if len(imgIDs) == 0 {
		t.Fatalf("no images")
	}

	_, body = do(t, "GET", base+"/containers/json?all=true", "")
	for _, c := range decodeList(t, body) {
		if !imgIDs[c["ImageID"].(string)] {
			t.Fatalf("container %s ImageID %v not in images %v",
				c["Names"].([]interface{})[0], c["ImageID"], imgIDs)
		}
	}
}

func TestHTTPPullStream(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	code, body := do(t, "POST", base+"/images/create?fromImage=alpine", "")
	if code != 200 {
		t.Fatalf("pull code=%d", code)
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) < 6 {
		t.Fatalf("pull stream too short: %q", body)
	}
	// 逐行都是合法 JSON
	for _, ln := range lines {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("pull line not JSON: %q", ln)
		}
	}
	for _, want := range []string{
		`"status":"Pulling from library/alpine"`,
		`"status":"Pulling fs layer"`,
		`"status":"Downloading"`,
		`"progress":"[`,
		`"progressDetail":{"current":`,
		`"status":"Pull complete"`,
		`"status":"Digest: sha256:`,
		`"status":"Status: Downloaded newer image for alpine:latest"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("pull stream missing %s\nbody: %s", want, body)
		}
	}

	// 拉取后镜像真的入库，可 inspect / 删除
	_, body = do(t, "GET", base+"/images/alpine:latest/json", "")
	if decode(t, body)["Id"] == "" {
		t.Fatalf("pulled image not inspectable")
	}
	if code, _ := do(t, "DELETE", base+"/images/alpine:latest", ""); code != 200 {
		t.Fatalf("delete pulled image code=%d", code)
	}
	if code, _ := do(t, "GET", base+"/images/alpine:latest/json", ""); code != 404 {
		t.Fatalf("inspect after delete code=%d", code)
	}
}

func TestHTTPImageErrors(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	if code, body := do(t, "GET", base+"/images/nope:latest/json", ""); code != 404 ||
		!strings.Contains(body, "No such image: nope:latest") {
		t.Fatalf("inspect missing image = %d %q", code, body)
	}
	if code, _ := do(t, "DELETE", base+"/images/nope:latest", ""); code != 404 {
		t.Fatalf("delete missing image code=%d", code)
	}
}

func TestHTTPNetworks(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 预置 4 个网络，bridge 上挂着预置容器
	code, body := do(t, "GET", base+"/networks", "")
	if code != 200 {
		t.Fatalf("networks code=%d", code)
	}
	nets := decodeList(t, body)
	if len(nets) != 4 {
		t.Fatalf("networks len=%d want 4", len(nets))
	}
	names := map[string]bool{}
	for _, n := range nets {
		names[n["Name"].(string)] = true
	}
	for _, want := range []string{"bridge", "host", "none"} {
		if !names[want] {
			t.Fatalf("default network %s missing", want)
		}
	}

	// 按名字 inspect bridge，应含容器
	_, body = do(t, "GET", base+"/networks/bridge/json", "")
	bridge := decode(t, body)
	conts := bridge["Containers"].(map[string]interface{})
	if len(conts) != 2 {
		t.Fatalf("bridge containers=%v", conts)
	}

	// 创建 / inspect / 连接 / 断开 / 删除
	code, body = do(t, "POST", base+"/networks/create", `{"Name":"app-net","Driver":"bridge"}`)
	if code != 201 {
		t.Fatalf("network create code=%d", code)
	}
	netID := decode(t, body)["Id"].(string)

	if code, body := do(t, "GET", base+"/networks/app-net/json", ""); code != 200 {
		t.Fatalf("network inspect by name code=%d body=%s", code, body)
	}
	// 重名创建 -> 409
	if code, body := do(t, "POST", base+"/networks/create", `{"Name":"app-net"}`); code != 409 ||
		!strings.Contains(body, "already exists") {
		t.Fatalf("duplicate network = %d %q", code, body)
	}

	// connect 需要一个容器 id
	_, body = do(t, "GET", base+"/containers/json", "")
	cid := decodeList(t, body)[0]["Id"].(string)
	if code, _ := do(t, "POST", base+"/networks/"+netID+"/connect", `{"Container":"`+cid+`"}`); code != 200 {
		t.Fatalf("connect code=%d", code)
	}
	_, body = do(t, "GET", base+"/networks/app-net/json", "")
	if len(decode(t, body)["Containers"].(map[string]interface{})) != 1 {
		t.Fatalf("connected container missing in inspect")
	}
	if code, _ := do(t, "POST", base+"/networks/"+netID+"/disconnect", `{"Container":"`+cid+`"}`); code != 200 {
		t.Fatalf("disconnect code=%d", code)
	}
	// connect 到不存在的容器 -> 404
	if code, _ := do(t, "POST", base+"/networks/"+netID+"/connect", `{"Container":"nosuch"}`); code != 404 {
		t.Fatalf("connect missing container code=%d", code)
	}
	if code, _ := do(t, "DELETE", base+"/networks/app-net", ""); code != 204 {
		t.Fatalf("network delete code=%d", code)
	}
	if code, _ := do(t, "GET", base+"/networks/app-net/json", ""); code != 404 {
		t.Fatalf("inspect after delete code=%d", code)
	}
}

func TestHTTPVolumes(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	code, body := do(t, "GET", base+"/volumes", "")
	if code != 200 {
		t.Fatalf("volumes code=%d", code)
	}
	vols := decode(t, body)["Volumes"].([]interface{})
	if len(vols) != 2 {
		t.Fatalf("seeded volumes len=%d want 2", len(vols))
	}

	// create -> inspect -> delete
	code, body = do(t, "POST", base+"/volumes/create", `{"Name":"db-data"}`)
	if code != 201 {
		t.Fatalf("volume create code=%d", code)
	}
	created := decode(t, body)
	if created["Name"] != "db-data" || created["Driver"] != "local" ||
		!strings.Contains(created["Mountpoint"].(string), "/var/lib/docker/volumes/db-data/_data") {
		t.Fatalf("volume create body=%v", created)
	}

	if code, body := do(t, "GET", base+"/volumes/db-data", ""); code != 200 {
		t.Fatalf("volume inspect code=%d body=%s", code, body)
	}
	if code, _ := do(t, "GET", base+"/volumes/redis-data", ""); code != 200 {
		t.Fatalf("seeded volume inspect code=%d", code)
	}
	if code, body := do(t, "GET", base+"/volumes/nope", ""); code != 404 ||
		!strings.Contains(body, "volume nope not found") {
		t.Fatalf("volume inspect missing = %d %q", code, body)
	}
	if code, _ := do(t, "DELETE", base+"/volumes/db-data", ""); code != 204 {
		t.Fatalf("volume delete code=%d", code)
	}
	if code, _ := do(t, "DELETE", base+"/volumes/db-data", ""); code != 404 {
		t.Fatalf("second volume delete code=%d", code)
	}
}

func TestHTTPSystemDF(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	code, body := do(t, "GET", base+"/system/df", "")
	if code != 200 {
		t.Fatalf("system/df code=%d", code)
	}
	df := decode(t, body)
	for _, k := range []string{"LayersSize", "Images", "Containers", "Volumes", "BuilderCache"} {
		if _, ok := df[k]; !ok {
			t.Fatalf("system/df missing %q", k)
		}
	}
	if len(df["Images"].([]interface{})) != len(df["Containers"].([]interface{}))+0 &&
		len(df["Images"].([]interface{})) == 0 {
		t.Fatalf("system/df images empty")
	}
}

// TestHTTPKeepAlive 验证同一连接上可连续处理多个请求。
func TestHTTPKeepAlive(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	br := bufio.NewReader(c)
	for i := 0; i < 3; i++ {
		if _, err := c.Write([]byte("GET /_ping HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest("GET", "http://x/_ping", nil)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			t.Fatalf("request #%d: %v", i+1, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "OK" {
			t.Fatalf("ping #%d = %d %q", i+1, resp.StatusCode, body)
		}
	}
}

// ---- 官方 SDK 示例（docs.docker.com/reference/api/engine/sdk/examples）----

// TestOfficialRunExample 覆盖「Run a container」示例的 4 步：
// create -> start -> wait -> logs?stdout=1。
func TestOfficialRunExample(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 0) 先 pull（create 只接受本地已有的镜像，与真机一致）
	if code, _ := do(t, "POST", base+"/images/create?fromImage=alpine", ""); code != 200 {
		t.Fatalf("pull alpine code=%d", code)
	}

	// 1) POST /containers/create
	code, body := do(t, "POST", base+"/v1.56/containers/create",
		`{"Image":"alpine","Cmd":["echo","hello world"]}`)
	if code != 201 {
		t.Fatalf("create code=%d body=%s", code, body)
	}
	created := decode(t, body)
	id, ok := created["Id"].(string)
	if !ok || id == "" {
		t.Fatalf("create body=%v", created)
	}
	if _, ok := created["Warnings"]; !ok {
		t.Fatalf("create response missing Warnings")
	}

	// 2) POST /containers/{id}/start（空响应）
	if code, body := do(t, "POST", base+"/containers/"+id+"/start", ""); code != 204 || body != "" {
		t.Fatalf("start = %d %q", code, body)
	}

	// 3) POST /containers/{id}/wait -> {"StatusCode":0}
	code, body = do(t, "POST", base+"/containers/"+id+"/wait", "")
	if code != 200 {
		t.Fatalf("wait code=%d body=%s", code, body)
	}
	if got := decode(t, body)["StatusCode"].(float64); got != 0 {
		t.Fatalf("wait StatusCode=%v", got)
	}

	// 4) GET /containers/{id}/logs?stdout=1 -> 帧复用流（非 TTY 容器，真机同格式）
	code, body = do(t, "GET", base+"/containers/"+id+"/logs?stdout=1", "")
	if code != 200 {
		t.Fatalf("logs code=%d", code)
	}
	if got := unframeLogs(body); got != "hello world\n" {
		t.Fatalf("logs payload=%q", got)
	}
}

// unframeLogs 解掉 8 字节帧头（类型+3 保留+大端长度），还原纯文本负载。
func unframeLogs(body string) string {
	var out strings.Builder
	b := []byte(body)
	for len(b) >= 8 {
		n := int(binary.BigEndian.Uint32(b[4:8]))
		if 8+n > len(b) {
			break
		}
		out.Write(b[8 : 8+n])
		b = b[8+n:]
	}
	return out.String()
}

// TestOfficialLogsByImage 验证 logs 按镜像给出可信内容。
func TestOfficialLogsByImage(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	_, body := do(t, "GET", base+"/containers/json", "")
	for _, c := range decodeList(t, body) {
		id := c["Id"].(string)
		_, logs := do(t, "GET", base+"/containers/"+id+"/logs?stdout=1", "")
		if logs == "" {
			t.Fatalf("empty logs for %v", c["Names"])
		}
		if !strings.Contains(logs, "\n") {
			t.Fatalf("logs should be multi-line: %q", logs)
		}
	}
}

// TestOfficialCommitExample 覆盖「Commit a container」示例：
// POST /commit?container=<id>&repo=helloworld -> {"Id":"sha256:..."}
func TestOfficialCommitExample(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	_, body := do(t, "POST", base+"/containers/create", `{"Image":"nginx:latest"}`)
	id := decode(t, body)["Id"].(string)

	code, body := do(t, "POST", base+"/commit?container="+id+"&repo=helloworld", "")
	if code != 201 {
		t.Fatalf("commit code=%d body=%s", code, body)
	}
	newID := decode(t, body)["Id"].(string)
	if !strings.HasPrefix(newID, "sha256:") {
		t.Fatalf("commit Id=%q", newID)
	}
	// 提交出的镜像真的能查到
	if code, _ := do(t, "GET", base+"/images/helloworld:latest/json", ""); code != 200 {
		t.Fatalf("committed image not inspectable, code=%d", code)
	}
	// 容器不存在 -> 404
	if code, body := do(t, "POST", base+"/commit?container=nosuch&repo=x", ""); code != 404 ||
		!strings.Contains(body, "No such container") {
		t.Fatalf("commit missing container = %d %q", code, body)
	}
	// 仅 POST
	if code, _ := do(t, "GET", base+"/commit", ""); code != 404 {
		t.Fatalf("GET /commit code=%d", code)
	}
}

// TestOfficialPullWithAuth 覆盖「Pull an image with authentication」示例的
// X-Registry-Auth 头（凭证应被采集）。
func TestOfficialPullWithAuth(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// {"username":"docker","password":"secret","serveraddress":"https://index.docker.io/v1/"}
	const auth = "eyJ1c2VybmFtZSI6ImRvY2tlciIsInBhc3N3b3JkIjoic2VjcmV0Iiwic2VydmVyYWRkcmVzcyI6Imh0dHBzOi8vaW5kZXguZG9ja2VyLmlvL3YxLyJ9"
	req, err := http.NewRequest("POST", base+"/images/create?fromImage=alpine", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Registry-Auth", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := mustRead(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("auth pull code=%d", resp.StatusCode)
	}
	if !strings.Contains(body, `"status":"Status: Downloaded newer image for alpine:latest"`) {
		t.Fatalf("auth pull stream: %s", body)
	}
}

func TestParseRegistryAuth(t *testing.T) {
	// {"username":"docker","password":"secret","serveraddress":"https://index.docker.io/v1/"}
	const auth = "eyJ1c2VybmFtZSI6ImRvY2tlciIsInBhc3N3b3JkIjoic2VjcmV0Iiwic2VydmVyYWRkcmVzcyI6Imh0dHBzOi8vaW5kZXguZG9ja2VyLmlvL3YxLyJ9"
	user, pass, server, ok := parseRegistryAuth(auth)
	if !ok || user != "docker" || pass != "secret" || server != "https://index.docker.io/v1/" {
		t.Fatalf("parseRegistryAuth=(%q,%q,%q,%v)", user, pass, server, ok)
	}
	if _, _, _, ok := parseRegistryAuth("!!!not-base64!!!"); ok {
		t.Fatalf("garbage should not parse")
	}
	if _, _, _, ok := parseRegistryAuth(base64Of(t, `{"foo":1}`)); !ok {
		t.Fatalf("valid json without creds should still parse")
	}
}

func base64Of(t *testing.T, s string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// TestBuildAndPushEndpoints 覆盖 POST /build 与 POST /images/{name}/push。
func TestBuildAndPushEndpoints(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// POST /build 流式输出
	code, body := do(t, "POST", base+"/build", "FROM busybox")
	if code != 200 {
		t.Fatalf("build code=%d", code)
	}
	if !strings.Contains(body, `"stream":"Step 1/3 : FROM busybox\n"`) ||
		!strings.Contains(body, "Successfully built") {
		t.Fatalf("build stream: %s", body)
	}
	if code, _ := do(t, "GET", base+"/build", ""); code != 404 {
		t.Fatalf("GET /build code=%d", code)
	}

	// 假端点不再存在
	if code, _ := do(t, "POST", base+"/images/build", ""); code != 404 {
		t.Fatalf("/images/build should not exist, code=%d", code)
	}
	if code, _ := do(t, "POST", base+"/images/commit", ""); code != 404 {
		t.Fatalf("/images/commit should not exist, code=%d", code)
	}

	// push 未认证 -> denied 流
	code, body = do(t, "POST", base+"/images/nginx:latest/push", "")
	if code != 200 {
		t.Fatalf("push code=%d", code)
	}
	if !strings.Contains(body, "The push refers to repository") ||
		!strings.Contains(body, "denied: requested access to the resource is denied") {
		t.Fatalf("push stream: %s", body)
	}
	if code, _ := do(t, "POST", base+"/images/nope:latest/push", ""); code != 404 {
		t.Fatalf("push missing image code=%d", code)
	}

	// load / import 保留（真实端点）
	if code, _ := do(t, "POST", base+"/images/load", ""); code != 200 {
		t.Fatalf("images/load code=%d", code)
	}
}

// TestContainerStatsTopChanges 覆盖 stats/top/changes。
func TestContainerStatsTopChanges(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	_, body := do(t, "GET", base+"/containers/json", "")
	id := decodeList(t, body)[0]["Id"].(string)

	if code, body := do(t, "GET", base+"/containers/"+id+"/stats", ""); code != 200 {
		t.Fatalf("stats code=%d", code)
	} else {
		st := decode(t, strings.Split(strings.TrimSpace(body), "\n")[0])
		for _, k := range []string{"read", "cpu_stats", "memory_stats", "networks", "pids_stats", "name", "id"} {
			if _, ok := st[k]; !ok {
				t.Fatalf("stats missing %q", k)
			}
		}
	}

	if code, body := do(t, "GET", base+"/containers/"+id+"/top", ""); code != 200 {
		t.Fatalf("top code=%d", code)
	} else {
		top := decode(t, body)
		// 进程数按镜像画像给出（nginx 多进程、redis 单进程），至少 1 条
		if len(top["Titles"].([]interface{})) != 8 || len(top["Processes"].([]interface{})) < 1 {
			t.Fatalf("top body=%v", top)
		}
	}

	if code, body := do(t, "GET", base+"/containers/"+id+"/changes", ""); code != 200 {
		t.Fatalf("changes code=%d", code)
	} else if len(decodeList(t, body)) != 2 {
		t.Fatalf("changes body=%s", body)
	}

	// 容器不存在时同样回 404
	if code, _ := do(t, "GET", base+"/containers/nosuch/logs", ""); code != 404 {
		t.Fatalf("logs missing container code=%d", code)
	}
	if code, _ := do(t, "POST", base+"/containers/nosuch/wait", ""); code != 404 {
		t.Fatalf("wait missing container code=%d", code)
	}
}

// TestHTTPContainerLookupByNameAndPrefix 覆盖按名称/短 ID 前缀 inspect 容器。
func TestHTTPContainerLookupByNameAndPrefix(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 名称（省略前导 /）
	if code, body := do(t, "GET", base+"/containers/web/json", ""); code != 200 {
		t.Fatalf("inspect by name code=%d body=%s", code, body)
	} else if decode(t, body)["Name"] != "/web" {
		t.Fatalf("inspect by name returned %v", decode(t, body)["Name"])
	}
	// 名称（带前导 /）
	if code, _ := do(t, "GET", base+"/containers//web/json", ""); code != 404 {
		t.Fatalf("double slash should 404, got %d", code)
	}

	// 短 ID 前缀
	_, body := do(t, "GET", base+"/containers/json", "")
	id := decodeList(t, body)[0]["Id"].(string)
	short := id[:12]
	if code, body := do(t, "GET", base+"/containers/"+short+"/json", ""); code != 200 {
		t.Fatalf("inspect by short id code=%d body=%s", code, body)
	} else if decode(t, body)["Id"] != id {
		t.Fatalf("short id resolved to wrong container")
	}
	// 短 ID 也支持其它动作
	if code, _ := do(t, "POST", base+"/containers/"+short+"/stop", ""); code != 204 {
		t.Fatalf("stop by short id code=%d", code)
	}
}

// TestHTTPImageLayerStableAndHistory 覆盖层 ID 稳定性与 history 端点。
func TestHTTPImageLayerStableAndHistory(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	_, b1 := do(t, "GET", base+"/images/nginx:latest/json", "")
	_, b2 := do(t, "GET", base+"/images/nginx:latest/json", "")
	l1 := decode(t, b1)["RootFS"].(map[string]interface{})["Layers"].([]interface{})
	l2 := decode(t, b2)["RootFS"].(map[string]interface{})["Layers"].([]interface{})
	if len(l1) == 0 || len(l1) != len(l2) {
		t.Fatalf("layers not stable: %v vs %v", l1, l2)
	}
	for i := range l1 {
		if l1[i] != l2[i] {
			t.Fatalf("layer %d differs: %v vs %v", i, l1[i], l2[i])
		}
	}
	// API 规范字段齐全
	for _, k := range []string{"DockerVersion", "Comment", "Config", "ContainerConfig"} {
		if _, ok := decode(t, b1)[k]; !ok {
			t.Fatalf("image inspect missing %q", k)
		}
	}

	// history：非空、顶层带 Tags
	code, body := do(t, "GET", base+"/images/nginx:latest/history", "")
	if code != 200 {
		t.Fatalf("history code=%d", code)
	}
	hist := decodeList(t, body)
	if len(hist) != len(l1) {
		t.Fatalf("history len=%d want %d", len(hist), len(l1))
	}
	if tags, ok := hist[0]["Tags"].([]interface{}); !ok || len(tags) == 0 || tags[0] != "nginx:latest" {
		t.Fatalf("history top Tags=%v", hist[0]["Tags"])
	}
	for _, h := range hist {
		if _, ok := h["CreatedBy"].(string); !ok {
			t.Fatalf("history entry missing CreatedBy")
		}
		// 真机 history 的 Created 是 int64 unix 时间戳（docker history  CLI 依赖）
		if _, ok := h["Created"].(float64); !ok {
			t.Fatalf("history Created should be int64, got %#v", h["Created"])
		}
	}

	// 短 ID 前缀 inspect 镜像
	_, b3 := do(t, "GET", base+"/images/"+strings.TrimPrefix(l1[0].(string), "sha256:")[:12]+"/json", "")
	_ = b3
	imgID := strings.TrimPrefix(decode(t, b1)["Id"].(string), "sha256:")
	if code, body := do(t, "GET", base+"/images/"+imgID[:12]+"/json", ""); code != 200 ||
		decode(t, body)["Id"] != "sha256:"+imgID {
		t.Fatalf("image inspect by short id failed: %d", code)
	}
}

// TestHTTPListFilters 覆盖 ?filters= 过滤参数。
func TestHTTPListFilters(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 容器按 name 过滤（子串）
	_, body := do(t, "GET", base+`/containers/json?filters={"name":["web"]}`, "")
	list := decodeList(t, body)
	if len(list) != 1 || list[0]["Names"].([]interface{})[0] != "/web" {
		t.Fatalf("name filter returned %v", list)
	}
	// 容器按 status 过滤
	_, body = do(t, "GET", base+`/containers/json?filters={"status":["running"]}`, "")
	if len(decodeList(t, body)) != 2 {
		t.Fatalf("status filter should match 2 running")
	}
	_, body = do(t, "GET", base+`/containers/json?all=true&filters={"status":["exited"]}`, "")
	if len(decodeList(t, body)) != 0 {
		t.Fatalf("status=exited should be empty")
	}
	// 镜像按 reference 过滤
	_, body = do(t, "GET", base+`/images/json?filters={"reference":["nginx"]}`, "")
	if len(decodeList(t, body)) != 1 {
		t.Fatalf("reference filter should match 1 image")
	}
	// docker CLI 的对象写法：{"name":{"web":true}}（值不是数组）
	_, body = do(t, "GET", base+`/containers/json?filters={"name":{"web":true}}`, "")
	if l := decodeList(t, body); len(l) != 1 || l[0]["Names"].([]interface{})[0] != "/web" {
		t.Fatalf("object-form name filter returned %v", l)
	}
	_, body = do(t, "GET", base+`/containers/json?all=true&filters={"status":{"exited":true}}`, "")
	if len(decodeList(t, body)) != 0 {
		t.Fatalf("object-form status=exited should be empty")
	}
	// 非法 filters -> 400
	if code, _ := do(t, "GET", base+`/containers/json?filters=not-json`, ""); code != 400 {
		t.Fatalf("invalid filters code=%d want 400", code)
	}
}

// TestHTTPSwarmNotManager 非 manager 节点查 swarm 回 503。
func TestHTTPSwarmNotManager(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	if code, body := do(t, "GET", base+"/swarm", ""); code != 503 ||
		!strings.Contains(body, "not a swarm manager") {
		t.Fatalf("swarm = %d %q", code, body)
	}
}

// doRaw 发请求并返回完整响应（用于校验 Content-Type 等首部）。
func doRaw(t *testing.T, method, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return resp
}

// TestHTTPImageSaveTar 覆盖 docker save 两个入口均返回 tar 流。
func TestHTTPImageSaveTar(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 新式入口：GET /images/get?names=
	resp := doRaw(t, "GET", base+"/images/get?names=nginx:latest")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("images/get code=%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-tar" {
		t.Fatalf("images/get content-type=%q", ct)
	}
	data := mustRead(t, resp)
	if len(data) < 1024 || string(data[257:262]) != "ustar" {
		t.Fatalf("images/get body not a tar (len=%d)", len(data))
	}

	// 旧式入口：GET /images/{name}/get
	resp2 := doRaw(t, "GET", base+"/images/redis:7/get")
	defer resp2.Body.Close()
	if resp2.StatusCode != 200 || resp2.Header.Get("Content-Type") != "application/x-tar" {
		t.Fatalf("images/{name}/get = %d %q", resp2.StatusCode, resp2.Header.Get("Content-Type"))
	}
	data2 := mustRead(t, resp2)
	if len(data2) < 1024 {
		t.Fatalf("images/{name}/get body too small")
	}

	// 不存在的镜像 -> 404
	if code, _ := do(t, "GET", base+"/images/get?names=nope:1", ""); code != 404 {
		t.Fatalf("images/get missing code=%d", code)
	}
}

// TestHTTPContainerExportTar 容器 export 返回 tar 流。
func TestHTTPContainerExportTar(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	_, body := do(t, "GET", base+"/containers/json", "")
	id := decodeList(t, body)[0]["Id"].(string)
	resp := doRaw(t, "GET", base+"/containers/"+id+"/export")
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-tar" {
		t.Fatalf("export = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	data := mustRead(t, resp)
	if len(data) < 1024 || string(data[257:262]) != "ustar" {
		t.Fatalf("export body not a tar (len=%d)", len(data))
	}
}

// TestHTTPCreateValidation 覆盖 create 的参数校验与自动命名。
func TestHTTPCreateValidation(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 缺 Image -> 400
	if code, body := do(t, "POST", base+"/containers/create", `{}`); code != 400 ||
		!strings.Contains(body, "No image specified") {
		t.Fatalf("create without image = %d %q", code, body)
	}
	// 本地没有的镜像 -> 404
	if code, body := do(t, "POST", base+"/containers/create", `{"Image":"ghost:1.0"}`); code != 404 ||
		!strings.Contains(body, "No such image: ghost:1.0") {
		t.Fatalf("create missing image = %d %q", code, body)
	}
	// 非法名称 -> 400
	if code, _ := do(t, "POST", base+`/containers/create?name=-bad`, `{"Image":"nginx:latest"}`); code != 400 {
		t.Fatalf("create invalid name code=%d", code)
	}
	// 省略名称 -> 自动生成 adjective_surname
	code, body := do(t, "POST", base+"/containers/create", `{"Image":"nginx:latest"}`)
	if code != 201 {
		t.Fatalf("create code=%d body=%s", code, body)
	}
	id := decode(t, body)["Id"].(string)
	_, body = do(t, "GET", base+"/containers/"+id+"/json", "")
	name := decode(t, body)["Name"].(string)
	if !validContainerName(strings.TrimPrefix(name, "/")) || !strings.Contains(name, "_") {
		t.Fatalf("generated name %q not docker-style", name)
	}
}

// TestHTTPContainerProfileConsistency 各镜像容器的 Command/Args/端口/IP 互不串台。
func TestHTTPContainerProfileConsistency(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	inspect := func(name string) map[string]interface{} {
		code, body := do(t, "GET", base+"/containers/"+name+"/json", "")
		if code != 200 {
			t.Fatalf("inspect %s code=%d", name, code)
		}
		return decode(t, body)
	}
	web := inspect("web")
	redis := inspect("redis")

	// 镜像引用与参数各归各
	if web["Config"].(map[string]interface{})["Image"] != "nginx:latest" {
		t.Fatalf("web Config.Image=%v", web["Config"])
	}
	if got := web["Args"].([]interface{}); len(got) != 3 || got[0] != "nginx" {
		t.Fatalf("web Args=%v", got)
	}
	if got := redis["Args"].([]interface{}); len(got) != 1 || got[0] != "redis-server" {
		t.Fatalf("redis Args=%v (nginx 值串台了?)", got)
	}

	// 端口：nginx 80->8080 已发布；redis 6379 仅 EXPOSE
	webPorts := web["NetworkSettings"].(map[string]interface{})["Ports"].(map[string]interface{})
	if b, ok := webPorts["80/tcp"].([]interface{}); !ok || len(b) != 1 ||
		b[0].(map[string]interface{})["HostPort"] != "8080" {
		t.Fatalf("web Ports=%v", webPorts)
	}
	redisPorts := redis["NetworkSettings"].(map[string]interface{})["Ports"].(map[string]interface{})
	if v, ok := redisPorts["6379/tcp"]; !ok || v != nil {
		t.Fatalf("redis Ports=%v (80/8080 串台了?)", redisPorts)
	}

	// IP：两容器不同，且与 /networks 一致
	webIP := web["NetworkSettings"].(map[string]interface{})["Networks"].(map[string]interface{})["bridge"].(map[string]interface{})["IPAddress"].(string)
	redisIP := redis["NetworkSettings"].(map[string]interface{})["Networks"].(map[string]interface{})["bridge"].(map[string]interface{})["IPAddress"].(string)
	if webIP == "" || webIP == redisIP {
		t.Fatalf("container ips collide: web=%q redis=%q", webIP, redisIP)
	}
	webNet := web["NetworkSettings"].(map[string]interface{})["Networks"].(map[string]interface{})["bridge"].(map[string]interface{})["NetworkID"].(string)
	if webNet == "" || webNet == "placeholder" {
		t.Fatalf("NetworkID=%q should be the real bridge id", webNet)
	}
	_, nbody := do(t, "GET", base+"/networks/bridge/json", "")
	conts := decode(t, nbody)["Containers"].(map[string]interface{})
	for cid, v := range conts {
		e := v.(map[string]interface{})
		ip := strings.TrimSuffix(e["IPv4Address"].(string), "/16")
		if cid == web["Id"] && ip != webIP {
			t.Fatalf("networks web ip=%s inspect=%s", ip, webIP)
		}
		if cid == redis["Id"] && ip != redisIP {
			t.Fatalf("networks redis ip=%s inspect=%s", ip, redisIP)
		}
	}

	// ps 列表 Command 与 stats name 同样按画像派生
	_, body := do(t, "GET", base+"/containers/json", "")
	for _, c := range decodeList(t, body) {
		name := c["Names"].([]interface{})[0].(string)
		want := "nginx -g 'daemon off;'"
		if name == "/redis" {
			want = "redis-server"
		}
		if c["Command"] != want {
			t.Fatalf("%s Command=%q want %q", name, c["Command"], want)
		}
	}

	// stats 的 name 带前导 /
	_, sbody := do(t, "GET", base+"/containers/web/stats", "")
	st := decode(t, strings.Split(strings.TrimSpace(sbody), "\n")[0])
	if st["name"] != "/web" {
		t.Fatalf("stats name=%v want /web", st["name"])
	}

	// system/df 的 Images[].Containers 是真实引用计数
	_, dbody := do(t, "GET", base+"/system/df", "")
	for _, im := range decode(t, dbody)["Images"].([]interface{}) {
		if im.(map[string]interface{})["Containers"].(float64) != 1 {
			t.Fatalf("system/df image Containers=%v want 1", im.(map[string]interface{})["Containers"])
		}
	}
}

// TestHTTPInfoDetails 覆盖 /info 的细节字段。
func TestHTTPInfoDetails(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	_, b1 := do(t, "GET", base+"/info", "")
	info := decode(t, b1)
	if info["Isolation"] != "" {
		t.Fatalf("Isolation=%v want empty on linux", info["Isolation"])
	}
	if info["OomKillDisable"] != false {
		t.Fatalf("OomKillDisable=%v want false", info["OomKillDisable"])
	}
	if _, ok := info["Warnings"]; !ok {
		t.Fatalf("info missing Warnings")
	}
	// ID 一次运行内稳定
	_, b2 := do(t, "GET", base+"/info", "")
	if decode(t, b2)["ID"] != info["ID"] {
		t.Fatalf("info ID changed between requests")
	}
	// 与真机对齐的字段
	for _, k := range []string{"OSType", "OSVersion", "SecurityOptions", "KernelMemoryTCP",
		"CDISpecDirs", "GenericResources", "ExperimentalBuild", "PidsLimit"} {
		if _, ok := info[k]; !ok {
			t.Fatalf("info missing %q", k)
		}
	}
	if info["PidsLimit"] != true {
		t.Fatalf("PidsLimit should be bool true, got %#v", info["PidsLimit"])
	}
	// Experimental 是 omitempty：false 时整个键不下发
	if _, ok := info["Experimental"]; ok {
		t.Fatalf("Experimental should be omitted when false")
	}
}

// TestHTTPExecHijack 覆盖 exec start 的 101 连接升级与输出后关闭。
func TestHTTPExecHijack(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	_, body := do(t, "GET", base+"/containers/json", "")
	id := decodeList(t, body)[0]["Id"].(string)
	_, body = do(t, "POST", base+"/containers/"+id+"/exec", `{"Cmd":["id"]}`)
	eid := decode(t, body)["Id"].(string)

	// 原生连接发带 Hijack 头的 start（net/http 会吞掉 101）
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := fmt.Sprintf("POST /exec/%s/start HTTP/1.1\r\nHost: x\r\nHijack: True\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n", eid)
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, _ := c.Read(buf)
	raw := string(buf[:n])
	if !strings.HasPrefix(raw, "HTTP/1.1 101") || !strings.Contains(raw, "Upgrade: tcp") {
		t.Fatalf("exec start response=%q", raw)
	}
	payload := raw[strings.Index(raw, "\r\n\r\n")+4:]
	if !strings.Contains(unframeLogs(payload), "uid=0(root)") {
		t.Fatalf("exec payload=%q", payload)
	}
	// exec 结束即关闭连接（真机行为）
	n2, err := c.Read(buf)
	if err == nil && n2 > 0 {
		t.Fatalf("connection should be closed after exec output, got %q", buf[:n2])
	}
}

// TestHTTPAttachHijack attach 同样 101 升级，且连接保持（持续附着）。
func TestHTTPAttachHijack(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	_, body := do(t, "GET", base+"/containers/json", "")
	id := decodeList(t, body)[0]["Id"].(string)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := fmt.Sprintf("POST /containers/%s/attach?logs=1&stdout=1&stream=1 HTTP/1.1\r\nHost: x\r\nHijack: True\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n", id)
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, _ := c.Read(buf)
	raw := string(buf[:n])
	if !strings.HasPrefix(raw, "HTTP/1.1 101") {
		t.Fatalf("attach response=%q", raw)
	}
	payload := raw[strings.Index(raw, "\r\n\r\n")+4:]
	if !strings.Contains(unframeLogs(payload), "\n") {
		t.Fatalf("attach payload=%q", payload)
	}
}

// TestHTTPResponseHeadersAndVersionDetails 覆盖真机同款响应头与 /version 细节类型。
func TestHTTPResponseHeadersAndVersionDetails(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 真机每个响应都带 Api-Version / Ostype
	resp := doRaw(t, "GET", base+"/_ping")
	defer resp.Body.Close()
	if resp.Header.Get("Api-Version") != "1.45" || resp.Header.Get("Ostype") != "linux" {
		t.Fatalf("response headers: %v", resp.Header)
	}

	// /version Components[0].Details 是 map[string]string，Experimental 为字符串
	_, body := do(t, "GET", base+"/version", "")
	comps := decode(t, body)["Components"].([]interface{})
	details := comps[0].(map[string]interface{})["Details"].(map[string]interface{})
	if v, ok := details["Experimental"].(string); !ok || v != "false" {
		t.Fatalf("Details.Experimental=%#v want string \"false\"", details["Experimental"])
	}
	// 顶层 Experimental 仍是 bool
	if _, ok := decode(t, body)["Experimental"].(bool); !ok {
		t.Fatalf("top-level Experimental should be bool")
	}

	// logs 是 multiplexed 帧流，Content-Type 与真机一致
	_, lbody := do(t, "GET", base+"/containers/json", "")
	id := decodeList(t, lbody)[0]["Id"].(string)
	lresp := doRaw(t, "GET", base+"/containers/"+id+"/logs?stdout=1")
	defer lresp.Body.Close()
	if ct := lresp.Header.Get("Content-Type"); ct != "application/vnd.docker.multiplexed-stream" {
		t.Fatalf("logs content-type=%q", ct)
	}
	ldata := mustRead(t, lresp)
	if len(ldata) < 8 || ldata[0] != 1 {
		t.Fatalf("logs not framed: %x", ldata[:min(8, len(ldata))])
	}
	if !strings.Contains(unframeLogs(string(ldata)), "\n") {
		t.Fatalf("logs payload empty after unframing")
	}
}

// TestHTTPNetworkInspectNoJSONSuffix 真机网络 inspect 端点没有 /json 后缀。
func TestHTTPNetworkInspectNoJSONSuffix(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	if code, body := do(t, "GET", base+"/networks/bridge", ""); code != 200 {
		t.Fatalf("GET /networks/bridge code=%d body=%s", code, body)
	} else {
		n := decode(t, body)
		if n["Name"] != "bridge" || len(n["Containers"].(map[string]interface{})) != 2 {
			t.Fatalf("network inspect: %v", n)
		}
	}
	// 带 /json 的路径也保留（两种都认）
	if code, _ := do(t, "GET", base+"/networks/bridge/json", ""); code != 200 {
		t.Fatalf("GET /networks/bridge/json code=%d", code)
	}
	if code, _ := do(t, "GET", base+"/networks/nosuch", ""); code != 404 {
		t.Fatalf("missing network code=%d", code)
	}
}

// TestHTTPContainerRename 改名真实生效并同步网络视图。
func TestHTTPContainerRename(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	_, body := do(t, "POST", base+"/containers/create?name=oldname", `{"Image":"nginx:latest"}`)
	id := decode(t, body)["Id"].(string)
	if code, _ := do(t, "POST", base+"/containers/"+id+"/rename?name=newname", ""); code != 204 {
		t.Fatalf("rename code=%d", code)
	}
	code, body := do(t, "GET", base+"/containers/"+id+"/json", "")
	if code != 200 || decode(t, body)["Name"] != "/newname" {
		t.Fatalf("after rename: %d %s", code, body)
	}
	// 旧名字查不到，新名字查得到
	if code, _ := do(t, "GET", base+"/containers/oldname/json", ""); code != 404 {
		t.Fatalf("old name should 404")
	}
	if code, _ := do(t, "GET", base+"/containers/newname/json", ""); code != 200 {
		t.Fatalf("new name should resolve")
	}
	// 重名 -> 409；缺 name -> 400
	if code, _ := do(t, "POST", base+"/containers/"+id+"/rename?name=web", ""); code != 409 {
		t.Fatalf("rename to existing name code=%d want 409", code)
	}
	if code, _ := do(t, "POST", base+"/containers/"+id+"/rename", ""); code != 400 {
		t.Fatalf("rename without name code=%d want 400", code)
	}
	// 启动后网络视图同步新名
	if code, _ := do(t, "POST", base+"/containers/"+id+"/start", ""); code != 204 {
		t.Fatalf("start code=%d", code)
	}
	_, nbody := do(t, "GET", base+"/networks/bridge/json", "")
	for _, v := range decode(t, nbody)["Containers"].(map[string]interface{}) {
		if v.(map[string]interface{})["Name"] == "/oldname" {
			t.Fatalf("network view still shows old name")
		}
	}
}

// TestHTTPExecEndpoints 覆盖 exec 创建/inspect/start/resize。
func TestHTTPExecEndpoints(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	_, body := do(t, "GET", base+"/containers/json", "")
	id := decodeList(t, body)[0]["Id"].(string)

	// 创建 exec 实例
	code, body := do(t, "POST", base+"/containers/"+id+"/exec", `{"Cmd":["id"],"AttachStdout":true}`)
	if code != 201 {
		t.Fatalf("exec create code=%d body=%s", code, body)
	}
	eid := decode(t, body)["Id"].(string)
	if eid == "" {
		t.Fatalf("empty exec id")
	}
	// inspect：能按 id 查到，且关联到容器
	code, body = do(t, "GET", base+"/exec/"+eid+"/json", "")
	if code != 200 || decode(t, body)["ContainerID"] != id {
		t.Fatalf("exec inspect: %d %s", code, body)
	}
	// start -> 200 空响应；resize -> 201
	if code, b := do(t, "POST", base+"/exec/"+eid+"/start", ""); code != 200 || b != "" {
		t.Fatalf("exec start = %d %q", code, b)
	}
	if code, _ := do(t, "POST", base+"/exec/"+eid+"/resize?h=24&w=80", ""); code != 201 {
		t.Fatalf("exec resize code=%d", code)
	}
	// 不存在的实例 -> 404（与真机文案一致）
	if code, body := do(t, "GET", base+"/exec/deadbeef/json", ""); code != 404 ||
		!strings.Contains(body, "No such exec instance") {
		t.Fatalf("exec inspect missing = %d %q", code, body)
	}
	// 容器不存在 -> 404
	if code, _ := do(t, "POST", base+"/containers/nosuch/exec", `{"Cmd":["id"]}`); code != 404 {
		t.Fatalf("exec on missing container code=%d", code)
	}
}

// TestHTTPAllParamCLIForm 覆盖 all=1（CLI 写法）与 all=true 的兼容。
// docker CLI 的 ps -a 发的是 all=1，只认 "true" 会把停止的容器全过滤掉。
func TestHTTPAllParamCLIForm(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// 停掉一个容器
	_, body := do(t, "GET", base+"/containers/json", "")
	id := decodeList(t, body)[0]["Id"].(string)
	if code, _ := do(t, "POST", base+"/containers/"+id+"/stop", ""); code != 204 {
		t.Fatalf("stop code=%d", code)
	}
	// all=1（CLI 写法）必须含已停止容器
	_, body = do(t, "GET", base+"/containers/json?all=1", "")
	list := decodeList(t, body)
	if len(list) != 2 {
		t.Fatalf("all=1 list len=%d want 2", len(list))
	}
	states := map[string]int{}
	for _, c := range list {
		states[c["State"].(string)]++
	}
	if states["running"] != 1 || states["exited"] != 1 {
		t.Fatalf("all=1 states=%v", states)
	}
	// 无 all 参数只回 running
	_, body = do(t, "GET", base+"/containers/json", "")
	if len(decodeList(t, body)) != 1 {
		t.Fatalf("default list should have 1 running")
	}
	// all=true 同样兼容
	_, body = do(t, "GET", base+"/containers/json?all=true", "")
	if len(decodeList(t, body)) != 2 {
		t.Fatalf("all=true list len=%d", len(decodeList(t, body)))
	}
}

// TestHTTPImageSizes 镜像 SIZE 不能是固定值：按类型取基准 ± 抖动，未知镜像随机区间。
func TestHTTPImageSizes(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	_, body := do(t, "GET", base+"/images/json", "")
	sizes := map[string]float64{}
	for _, im := range decodeList(t, body) {
		sizes[im["RepoTags"].([]interface{})[0].(string)] = im["Size"].(float64)
	}
	nginx, redis := sizes["nginx:latest"], sizes["redis:7"]
	if nginx <= 0 || redis <= 0 {
		t.Fatalf("missing sizes: %v", sizes)
	}
	// 不同镜像大小不同，且在真机量级附近（nginx ~187MB、redis ~117MB，±8%）
	if nginx == redis {
		t.Fatalf("all images share the same size %v", nginx)
	}
	if nginx < 170e6 || nginx > 205e6 {
		t.Fatalf("nginx size=%v out of plausible range", nginx)
	}
	if redis < 105e6 || redis > 130e6 {
		t.Fatalf("redis size=%v out of plausible range", redis)
	}
	// VirtualSize 与 Size 一致
	for _, im := range decodeList(t, body) {
		if im["VirtualSize"] != im["Size"] {
			t.Fatalf("VirtualSize=%v Size=%v", im["VirtualSize"], im["Size"])
		}
	}

	// system/df 的 LayersSize = 各镜像大小之和
	_, dbody := do(t, "GET", base+"/system/df", "")
	df := decode(t, dbody)
	var sum float64
	for _, im := range df["Images"].([]interface{}) {
		sum += im.(map[string]interface{})["Size"].(float64)
	}
	if df["LayersSize"].(float64) != sum {
		t.Fatalf("LayersSize=%v want %v", df["LayersSize"], sum)
	}

	// history 各层之和 = 镜像 Size
	_, hbody := do(t, "GET", base+"/images/nginx:latest/history", "")
	var hsum float64
	for _, h := range decodeList(t, hbody) {
		hsum += h["Size"].(float64)
	}
	if hsum != nginx {
		t.Fatalf("history sizes sum=%v want %v", hsum, nginx)
	}

	// 未知镜像：pull 后大小落在 40MB~1.2GB 区间
	if code, _ := do(t, "POST", base+"/images/create?fromImage=ghcr.io/astral-sh/uv&tag=python3.12-bookworm-slim", ""); code != 200 {
		t.Fatalf("pull uv code=%d", code)
	}
	code, ibody := do(t, "GET", base+"/images/ghcr.io/astral-sh/uv:python3.12-bookworm-slim/json", "")
	if code != 200 {
		t.Fatalf("inspect uv code=%d", code)
	}
	uvSize := decode(t, ibody)["Size"].(float64)
	if uvSize < 40e6 || uvSize > 1.2e9 {
		t.Fatalf("uv size=%v out of 40MB~1.2GB range", uvSize)
	}
}

// TestHTTPNamespacedImageAndTag 带 registry/命名空间的镜像可 inspect/history/tag，
// docker tag 后同一 ID 多标签，rmi 返回真机数组格式。
func TestHTTPNamespacedImageAndTag(t *testing.T) {
	addr, stop := startTestServer(t, testConfig())
	defer stop()
	base := "http://" + addr

	// pull 一个带 registry 前缀的镜像
	const ref = "ghcr.io/astral-sh/uv:python3.12-bookworm-slim"
	if code, _ := do(t, "POST", base+"/images/create?fromImage=ghcr.io/astral-sh/uv&tag=python3.12-bookworm-slim", ""); code != 200 {
		t.Fatalf("pull namespaced image code=%d", code)
	}
	// inspect（名称带斜杠，动作在最后一段）
	code, body := do(t, "GET", base+"/images/"+ref+"/json", "")
	if code != 200 {
		t.Fatalf("inspect namespaced image = %d %s", code, body)
	}
	imID := decode(t, body)["Id"].(string)
	// history / push 同样可用
	if code, _ := do(t, "GET", base+"/images/"+ref+"/history", ""); code != 200 {
		t.Fatalf("history namespaced image code=%d", code)
	}
	if code, _ := do(t, "POST", base+"/images/"+ref+"/push", ""); code != 200 {
		t.Fatalf("push namespaced image code=%d", code)
	}

	// docker tag：同一镜像 ID 增加标签
	if code, _ := do(t, "POST", base+"/images/"+ref+"/tag?repo=myapp&tag=1.0", ""); code != 201 {
		t.Fatalf("tag code=%d", code)
	}
	_, body = do(t, "GET", base+"/images/json", "")
	var uvEntry map[string]interface{}
	for _, im := range decodeList(t, body) {
		if im["Id"] == imID {
			uvEntry = im
		}
	}
	if uvEntry == nil {
		t.Fatalf("tagged image not in list")
	}
	tags := uvEntry["RepoTags"].([]interface{})
	if len(tags) != 2 || tags[1] != "myapp:1.0" {
		t.Fatalf("RepoTags after tag = %v", tags)
	}
	// 两个标签都能 inspect 到同一个 ID
	if code, body := do(t, "GET", base+"/images/myapp:1.0/json", ""); code != 200 ||
		decode(t, body)["Id"] != imID {
		t.Fatalf("inspect by new tag: %d", code)
	}
	// 删除附加标签：只 Untagged，不 Deleted
	code, body = do(t, "DELETE", base+"/images/myapp:1.0", "")
	if code != 200 {
		t.Fatalf("rmi tag code=%d", code)
	}
	list := decodeList(t, body)
	if len(list) != 1 || list[0]["Untagged"] != "myapp:1.0" {
		t.Fatalf("rmi tag response=%v", list)
	}
	// 主标签还在
	if code, _ := do(t, "GET", base+"/images/"+ref+"/json", ""); code != 200 {
		t.Fatalf("primary tag should remain")
	}
	// 删主标签：Untagged + Deleted 两项
	code, body = do(t, "DELETE", base+"/images/"+ref, "")
	if code != 200 {
		t.Fatalf("rmi primary code=%d", code)
	}
	list = decodeList(t, body)
	if len(list) != 2 || list[0]["Untagged"] != ref || !strings.HasPrefix(list[1]["Deleted"].(string), "sha256:") {
		t.Fatalf("rmi primary response=%v", list)
	}
}

// TestConfigOverrides 覆盖 yaml 可配项：版本指纹细节、主机身份/资源、种子网络与卷、空闲超时。
func TestConfigOverrides(t *testing.T) {
	zero := 0
	cfg := dockerConfig{
		store:             newDockerStore(),
		APIVersion:        "1.43",
		Version:           "25.0.5",
		MinAPIVersion:     "1.20",
		PullPaceMS:        &zero,
		IdleTimeoutS:      30,
		KernelVersion:     "6.8.0-45-generic",
		GoVersion:         "go1.23.2",
		ContainerdVersion: "2.0.0",
		RuncVersion:       "1.2.0",
		BuildTime:         "2025-01-02T03:04:05.000000000+00:00",
		Hostname:          "prod-node-7",
		OperatingSystem:   "Debian GNU/Linux 12 (bookworm)",
		OSVersion:         "12",
		Architecture:      "arm64",
		NCPU:              16,
		MemTotal:          int64(64) << 30,
		DockerRootDir:     "/data/docker",
		CgroupDriver:      "cgroupfs",
		CgroupVersion:     "1",
		DefaultRuntime:    "crun",
		BackingFS:         "xfs",
		SecurityOptions:   []string{"name=selinux"},
		Networks:          []dockerNetworkConfig{{Name: "app-net", Driver: "bridge"}},
		Volumes:           []dockerVolumeConfig{{Name: "app-data"}},
	}
	if got := cfg.idleTimeout(); got != 30*time.Second {
		t.Fatalf("idleTimeout=%v want 30s", got)
	}
	addr, stop := startTestServer(t, cfg)
	defer stop()
	base := "http://" + addr

	// /version 的版本指纹细节
	_, body := do(t, "GET", base+"/version", "")
	v := decode(t, body)
	if v["Version"] != "25.0.5" || v["ApiVersion"] != "1.43" ||
		v["KernelVersion"] != "6.8.0-45-generic" || v["GoVersion"] != "go1.23.2" ||
		v["BuildTime"] != "2025-01-02T03:04:05.000000000+00:00" || v["Arch"] != "arm64" {
		t.Fatalf("/version=%v", v)
	}
	comps := v["Components"].([]interface{})
	versions := map[string]string{}
	for _, c := range comps {
		m := c.(map[string]interface{})
		versions[m["Name"].(string)] = m["Version"].(string)
	}
	if versions["containerd"] != "2.0.0" || versions["runc"] != "1.2.0" || versions["docker-init"] != "0.19.0" {
		t.Fatalf("components=%v", versions)
	}

	// /info 的主机身份与资源
	_, body = do(t, "GET", base+"/info", "")
	info := decode(t, body)
	if info["Name"] != "prod-node-7" || info["OperatingSystem"] != "Debian GNU/Linux 12 (bookworm)" ||
		info["OSVersion"] != "12" || info["Architecture"] != "aarch64" ||
		info["NCPU"].(float64) != 16 || info["MemTotal"].(float64) != float64(int64(64)<<30) ||
		info["DockerRootDir"] != "/data/docker" || info["CgroupDriver"] != "cgroupfs" ||
		info["CgroupVersion"] != "1" || info["DefaultRuntime"] != "crun" ||
		info["KernelVersion"] != "6.8.0-45-generic" {
		t.Fatalf("/info=%v", info)
	}
	driverStatus := info["DriverStatus"].([]interface{})[0].([]interface{})
	if driverStatus[1] != "xfs" {
		t.Fatalf("DriverStatus=%v", driverStatus)
	}
	if sec := info["SecurityOptions"].([]interface{}); len(sec) != 1 || sec[0] != "name=selinux" {
		t.Fatalf("SecurityOptions=%v", sec)
	}
	if _, ok := info["Runtimes"].(map[string]interface{})["crun"]; !ok {
		t.Fatalf("Runtimes=%v", info["Runtimes"])
	}

	// 种子网络：bridge/host/none 始终在，自定义网络按配置，不含默认 potagent_default
	_, body = do(t, "GET", base+"/networks", "")
	netNames := map[string]bool{}
	for _, n := range decodeList(t, body) {
		netNames[n["Name"].(string)] = true
	}
	if !netNames["app-net"] || !netNames["bridge"] || netNames["potagent_default"] {
		t.Fatalf("networks=%v", netNames)
	}

	// 种子卷按配置，不含默认项
	_, body = do(t, "GET", base+"/volumes", "")
	volNames := map[string]bool{}
	for _, v := range decode(t, body)["Volumes"].([]interface{}) {
		volNames[v.(map[string]interface{})["Name"].(string)] = true
	}
	if !volNames["app-data"] || volNames["redis-data"] {
		t.Fatalf("volumes=%v", volNames)
	}

	// 镜像详情架构跟随配置
	_, body = do(t, "GET", base+"/images/nginx:latest/json", "")
	if decode(t, body)["Architecture"] != "arm64" {
		t.Fatalf("image Architecture=%v", decode(t, body)["Architecture"])
	}
	// stats 的 CPU 核数/内存上限跟随配置
	_, body = do(t, "GET", base+"/containers/json", "")
	cid := decodeList(t, body)[0]["Id"].(string)
	_, sbody := do(t, "GET", base+"/containers/"+cid+"/stats", "")
	st := decode(t, strings.Split(strings.TrimSpace(sbody), "\n")[0])
	if st["cpu_stats"].(map[string]interface{})["online_cpus"].(float64) != 16 ||
		st["memory_stats"].(map[string]interface{})["limit"].(float64) != float64(int64(64)<<30) {
		t.Fatalf("stats=%v", st)
	}
}

// imageIDOf 从 /images/json 里取指定 repo:tag 的 Id（去掉 sha256: 前缀）。
func imageIDOf(t *testing.T, addr, ref string) string {
	t.Helper()
	_, body := do(t, "GET", "http://"+addr+"/images/json", "")
	for _, im := range decodeList(t, body) {
		for _, tag := range im["RepoTags"].([]interface{}) {
			if tag == ref {
				return strings.TrimPrefix(im["Id"].(string), "sha256:")
			}
		}
	}
	t.Fatalf("image %s not found", ref)
	return ""
}
