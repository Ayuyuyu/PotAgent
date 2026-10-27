// Package cmdsim 为 SSH / Telnet 这类交互式蜜罐提供内置的基础命令模拟。
//
// 设计原则：
//   - 绝不读取真实系统信息（hostname / uname / 网卡 / 内存等全部是伪造数据），
//     避免蜜罐本身泄露宿主机信息；
//   - 不执行任何真实命令，全部是内存里的虚拟文件系统与固定文本；
//   - 命令表覆盖攻击者上来最常敲的探测命令，未命中仍回 "command not found"，
//     让行为与真实 shell 一致（同时由调用方照常记录事件）。
package cmdsim

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// Result 是一条命令的执行结果。
type Result struct {
	// Output 已带行尾 \n；交互式调用方直接写出即可。
	Output string
	// ExitCode 供 exec 请求回 exit-status。
	ExitCode int
	// Exit 表示需要结束会话（exit / logout / quit）。
	Exit bool
}

// SystemInfo 是伪造的系统信息，全部可在 yaml 里配置；留空的字段用内置默认值。
// 这些值只影响 uname / /etc/os-release / /proc/version 等命令输出，与宿主机无关。
type SystemInfo struct {
	Distro        string `mapstructure:"distro" yaml:"distro"`                 // Ubuntu
	Version       string `mapstructure:"version" yaml:"version"`               // 22.04.3 LTS
	VersionID     string `mapstructure:"version_id" yaml:"version_id"`         // 22.04
	Codename      string `mapstructure:"codename" yaml:"codename"`             // Jammy Jellyfish
	CodenameID    string `mapstructure:"codename_id" yaml:"codename_id"`       // jammy
	Kernel        string `mapstructure:"kernel" yaml:"kernel"`                 // 5.15.0-91-generic
	KernelVersion string `mapstructure:"kernel_version" yaml:"kernel_version"` // #101-Ubuntu SMP ...
	Machine       string `mapstructure:"machine" yaml:"machine"`               // x86_64
}

// defaultSystemInfo 内置默认值（未在 yaml 中配置时使用）。
func defaultSystemInfo() SystemInfo {
	return SystemInfo{
		Distro:        "Ubuntu",
		Version:       "22.04.3 LTS",
		VersionID:     "22.04",
		Codename:      "Jammy Jellyfish",
		CodenameID:    "jammy",
		Kernel:        "5.15.0-91-generic",
		KernelVersion: "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023",
		Machine:       "x86_64",
	}
}

// withDefaults 用默认值补齐配置里留空的字段。
func (s SystemInfo) withDefaults() SystemInfo {
	def := defaultSystemInfo()

	if s.Distro == "" {
		s.Distro = def.Distro
	}
	if s.Version == "" {
		s.Version = def.Version
	}
	if s.VersionID == "" {
		s.VersionID = def.VersionID
	}
	if s.Codename == "" {
		s.Codename = def.Codename
	}
	if s.CodenameID == "" {
		s.CodenameID = def.CodenameID
	}
	if s.Kernel == "" {
		s.Kernel = def.Kernel
	}
	if s.KernelVersion == "" {
		s.KernelVersion = def.KernelVersion
	}
	if s.Machine == "" {
		s.Machine = def.Machine
	}

	return s
}

// Config 构造会话的初始状态。
type Config struct {
	User     string
	Hostname string
	// Home 默认 /root
	Home string
	// System 伪造的系统版本信息，留空用内置默认
	System SystemInfo
	// Files / Dirs 可覆盖内置的虚拟文件系统
	Files map[string]string
	Dirs  map[string][]string
	// Now 便于测试注入；为空时用 time.Now
	Now func() time.Time
}

// Session 是一个连接级别的命令模拟会话（保存 cwd、历史等状态）。
type Session struct {
	user     string
	hostname string
	home     string
	cwd      string
	started  time.Time
	bootAt   time.Time
	now      func() time.Time
	sys      SystemInfo
	history  []string
	files    map[string]string
	dirs     map[string][]string
}

// New 创建一个会话。
func New(cfg Config) *Session {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	user := cfg.User
	if user == "" {
		user = "root"
	}

	hostname := cfg.Hostname
	if hostname == "" {
		hostname = "ubuntu"
	}

	home := cfg.Home
	if home == "" {
		home = "/root"
	}

	started := now()

	s := &Session{
		user:     user,
		hostname: hostname,
		home:     path.Clean(home),
		cwd:      path.Clean(home),
		started:  started,
		// 伪造的开机时间：让 uptime 看起来像跑了十来天
		bootAt: started.Add(-11*24*time.Hour - 3*time.Hour - 41*time.Minute),
		now:    now,
		sys:    cfg.System.withDefaults(),
		dirs:   defaultDirs(),
	}

	s.files = defaultFiles(s.hostname, s.sys)

	for name, content := range cfg.Files {
		s.files[path.Clean(name)] = content
	}

	for name, entries := range cfg.Dirs {
		s.dirs[path.Clean(name)] = entries
	}

	return s
}

// User 返回当前登录用户。
func (s *Session) User() string { return s.user }

// Cwd 返回当前目录。
func (s *Session) Cwd() string { return s.cwd }

// Prompt 返回形如 root@ubuntu:~$ 的提示符（家目录显示为 ~）。
func (s *Session) Prompt() string {
	dir := s.cwd

	switch {
	case dir == s.home:
		dir = "~"
	case strings.HasPrefix(dir, s.home+"/"):
		dir = "~" + strings.TrimPrefix(dir, s.home)
	}

	return fmt.Sprintf("%s@%s:%s$ ", s.user, s.hostname, dir)
}

type handler func(s *Session, args []string) Result

var commands map[string]handler

func init() {
	commands = map[string]handler{
		"whoami":   cmdWhoami,
		"id":       cmdID,
		"hostname": cmdHostname,
		"uname":    cmdUname,
		"pwd":      cmdPwd,
		"cd":       cmdCd,
		"ls":       cmdLs,
		"cat":      cmdCat,
		"echo":     cmdEcho,
		"date":     cmdDate,
		"uptime":   cmdUptime,
		"history":  cmdHistory,
		"exit":     cmdExit,
		"logout":   cmdExit,
		"quit":     cmdExit,
	}
}

// Run 执行一行命令。支持用 ; 串联多条命令（不做 && / || / 管道）。
func (s *Session) Run(line string) Result {
	line = strings.TrimSpace(line)
	if line == "" {
		return Result{}
	}

	s.history = append(s.history, line)

	var (
		out  strings.Builder
		code int
	)

	for _, part := range splitStatements(line) {
		res := s.runOne(part)
		out.WriteString(res.Output)

		if res.ExitCode != 0 {
			code = res.ExitCode
		}

		if res.Exit {
			return Result{Output: out.String(), ExitCode: code, Exit: true}
		}
	}

	return Result{Output: out.String(), ExitCode: code}
}

// runOne 执行单条命令。
func (s *Session) runOne(line string) Result {
	fields := tokenize(line)
	if len(fields) == 0 {
		return Result{}
	}

	name := fields[0]
	args := fields[1:]

	if fn, ok := commands[name]; ok {
		return fn(s, args)
	}

	return Result{
		Output:   fmt.Sprintf("-bash: %s: command not found\n", name),
		ExitCode: 127,
	}
}

// splitStatements 按分号切分命令，忽略引号内的分号。
func splitStatements(line string) []string {
	var (
		parts    []string
		cur      strings.Builder
		inSingle bool
		inDouble bool
	)

	for _, r := range line {
		switch {
		case r == '\'' && !inDouble:
			inSingle = !inSingle
			cur.WriteRune(r)
		case r == '"' && !inSingle:
			inDouble = !inDouble
			cur.WriteRune(r)
		case r == ';' && !inSingle && !inDouble:
			if part := strings.TrimSpace(cur.String()); part != "" {
				parts = append(parts, part)
			}

			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}

	if part := strings.TrimSpace(cur.String()); part != "" {
		parts = append(parts, part)
	}

	return parts
}

func cmdWhoami(s *Session, _ []string) Result {
	return Result{Output: s.user + "\n"}
}

func cmdID(s *Session, _ []string) Result {
	if s.user == "root" {
		return Result{Output: "uid=0(root) gid=0(root) groups=0(root)\n"}
	}

	return Result{Output: fmt.Sprintf("uid=1000(%s) gid=1000(%s) groups=1000(%s)\n", s.user, s.user, s.user)}
}

func cmdHostname(s *Session, args []string) Result {
	// 支持 hostname -I / -s 之类的常见查询，返回伪造值
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue
		}

		return Result{Output: arg + "\n"}
	}

	return Result{Output: s.hostname + "\n"}
}

func cmdUname(s *Session, args []string) Result {
	const sysname = "Linux"

	node := s.hostname
	release := s.sys.Kernel
	version := s.sys.KernelVersion
	machine := s.sys.Machine

	all := strings.Join([]string{sysname, node, release, version, machine, "x86_64", "x86_64"}, " ")

	if len(args) == 0 {
		return Result{Output: sysname + "\n"}
	}

	parts := make([]string, 0, len(args))
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			continue
		}

		for _, flag := range arg[1:] {
			switch flag {
			case 'a':
				return Result{Output: all + "\n"}
			case 's':
				parts = append(parts, sysname)
			case 'n':
				parts = append(parts, node)
			case 'r':
				parts = append(parts, release)
			case 'v':
				parts = append(parts, version)
			case 'm', 'p':
				parts = append(parts, machine)
			case 'o':
				parts = append(parts, "GNU/Linux")
			}
		}
	}

	if len(parts) == 0 {
		return Result{Output: sysname + "\n"}
	}

	return Result{Output: strings.Join(parts, " ") + "\n"}
}

func cmdPwd(s *Session, _ []string) Result {
	return Result{Output: s.cwd + "\n"}
}

func cmdCd(s *Session, args []string) Result {
	target := s.home
	if len(args) > 0 && args[0] != "" {
		target = args[0]
	}

	var next string
	switch target {
	case "~":
		next = s.home
	case "-":
		next = s.home
	default:
		if strings.HasPrefix(target, "/") {
			next = path.Clean(target)
		} else {
			next = path.Clean(path.Join(s.cwd, target))
		}
	}

	if _, ok := s.dirs[next]; !ok {
		return Result{
			Output:   fmt.Sprintf("-bash: cd: %s: No such file or directory\n", target),
			ExitCode: 1,
		}
	}

	s.cwd = next

	return Result{}
}

func cmdLs(s *Session, args []string) Result {
	long, all := false, false
	paths := make([]string, 0, len(args))

	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			for _, flag := range arg[1:] {
				switch flag {
				case 'l':
					long = true
				case 'a':
					all = true
				}
			}

			continue
		}

		paths = append(paths, arg)
	}

	if len(paths) == 0 {
		paths = []string{s.cwd}
	}

	var out strings.Builder
	for i, item := range paths {
		target := item
		if !strings.HasPrefix(target, "/") {
			target = path.Join(s.cwd, target)
		}

		target = path.Clean(target)

		entries, ok := s.dirs[target]
		if !ok {
			out.WriteString(fmt.Sprintf("ls: cannot access '%s': No such file or directory\n", item))

			continue
		}

		if i > 0 {
			out.WriteString("\n")
		}

		visible := make([]string, 0, len(entries)+2)
		if all {
			visible = append(visible, ".", "..")
		}

		for _, name := range entries {
			// 与真实 ls 一致：不带 -a 时不显示隐藏文件
			if !all && strings.HasPrefix(name, ".") {
				continue
			}

			visible = append(visible, name)
		}

		if long {
			out.WriteString(fmt.Sprintf("total %d\n", len(visible)*4))
			for _, name := range visible {
				full := path.Join(target, name)
				if _, isDir := s.dirs[full]; isDir {
					out.WriteString(fmt.Sprintf("drwxr-xr-x 2 root root 4096 Oct 20 10:12 %s\n", name))

					continue
				}

				out.WriteString(fmt.Sprintf("-rw-r--r-- 1 root root 220 Oct 20 10:12 %s\n", name))
			}

			continue
		}

		out.WriteString(strings.Join(visible, "  ") + "\n")
	}

	return Result{Output: out.String()}
}

func cmdCat(s *Session, args []string) Result {
	if len(args) == 0 {
		return Result{Output: "cat: missing operand\n", ExitCode: 1}
	}

	var out strings.Builder
	for _, name := range args {
		if strings.HasPrefix(name, "-") {
			continue
		}

		target := name
		if !strings.HasPrefix(target, "/") {
			target = path.Join(s.cwd, target)
		}

		target = path.Clean(target)

		if target == "/etc/shadow" && s.user != "root" {
			out.WriteString("cat: /etc/shadow: Permission denied\n")

			continue
		}

		content, ok := s.files[target]
		if !ok {
			out.WriteString(fmt.Sprintf("cat: %s: No such file or directory\n", name))

			continue
		}

		out.WriteString(content)
		if !strings.HasSuffix(content, "\n") {
			out.WriteString("\n")
		}
	}

	return Result{Output: out.String()}
}

func cmdEcho(s *Session, args []string) Result {
	newline := true

	for len(args) > 0 && (args[0] == "-n" || args[0] == "-e") {
		if args[0] == "-n" {
			newline = false
		}

		args = args[1:]
	}

	text := strings.Join(args, " ")
	if newline {
		text += "\n"
	}

	return Result{Output: text}
}

func cmdDate(s *Session, args []string) Result {
	now := s.now()

	// 简单支持 +%Y-%m-%d 之类的格式化，够用即可
	if len(args) > 0 && strings.HasPrefix(args[0], "+") {
		layout := args[0][1:]
		replacer := strings.NewReplacer(
			"%Y", "2006", "%m", "01", "%d", "02",
			"%H", "15", "%M", "04", "%S", "05",
			"%F", "2006-01-02", "%T", "15:04:05",
		)

		return Result{Output: now.Format(replacer.Replace(layout)) + "\n"}
	}

	return Result{Output: now.Format("Mon Jan _2 15:04:05 MST 2006") + "\n"}
}

func cmdUptime(s *Session, _ []string) Result {
	now := s.now()
	up := now.Sub(s.bootAt)

	days := int(up.Hours()) / 24
	hours := int(up.Hours()) % 24
	minutes := int(up.Minutes()) % 60

	return Result{Output: fmt.Sprintf("%s up %d days, %2d:%02d,  2 users,  load average: 0.08, 0.12, 0.09\n",
		now.Format("15:04:05"), days, hours, minutes)}
}

func cmdHistory(s *Session, _ []string) Result {
	// bash 的 history 不含当前这一条
	items := s.history[:len(s.history)-1]

	var out strings.Builder
	for i, line := range items {
		out.WriteString(fmt.Sprintf("%5d  %s\n", i+1, line))
	}

	return Result{Output: out.String()}
}

func cmdExit(_ *Session, _ []string) Result {
	return Result{Exit: true}
}

// tokenize 按空白切分，支持单/双引号包裹的参数。
func tokenize(line string) []string {
	var (
		out      []string
		cur      strings.Builder
		inSingle bool
		inDouble bool
	)

	flush := func() {
		out = append(out, cur.String())
		cur.Reset()
	}

	for _, r := range line {
		switch {
		case r == '\'' && !inDouble:
			inSingle = !inSingle
		case r == '"' && !inSingle:
			inDouble = !inDouble
		case (r == ' ' || r == '\t') && !inSingle && !inDouble:
			if cur.Len() > 0 {
				flush()
			}
		default:
			cur.WriteRune(r)
		}
	}

	if cur.Len() > 0 {
		flush()
	}

	return out
}

func defaultDirs() map[string][]string {
	dirs := map[string][]string{
		"/": {
			"bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt",
			"opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var",
		},
		"/root": {
			".bash_history", ".bashrc", ".cache", ".profile", ".ssh",
			"Documents", "Downloads", "Music", "Pictures", "Videos",
		},
		"/root/Documents": {},
		"/root/Downloads": {},
		"/root/Music":     {},
		"/root/Pictures":  {},
		"/root/Videos":    {},
		"/home":           {"ubuntu"},
		"/home/ubuntu":    {".bashrc", ".profile", "Documents"},
		"/tmp":            {".X11-unix", "systemd-private-a1b2c3"},
		"/var":            {"backups", "cache", "lib", "log", "mail", "spool", "tmp", "www"},
		"/var/log":        {"auth.log", "syslog", "dpkg.log", "kern.log"},
		"/var/www":        {"html"},
		"/var/www/html":   {"index.html"},
		"/etc": {
			"hostname", "hosts", "issue", "os-release", "passwd", "shadow", "group",
			"nginx", "ssh", "crontab", "fstab", "resolv.conf",
		},
		"/etc/ssh":   {"ssh_config", "sshd_config"},
		"/etc/nginx": {"nginx.conf", "sites-enabled"},
		"/usr":       {"bin", "lib", "local", "sbin", "share"},
		"/usr/bin":   {"bash", "ls", "cat", "curl", "wget", "python3", "vim", "sudo"},
		"/usr/sbin":  {"sshd", "nginx"},
		"/opt":       {},
		"/proc":      {"cpuinfo", "meminfo", "version"},
	}

	return dirs
}

func defaultFiles(hostname string, sys SystemInfo) map[string]string {
	return map[string]string{
		"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n" +
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
			"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n" +
			"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n" +
			"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
		"/etc/shadow":   "root:$6$Kd8fhs2l$Q0Zf9m4nB1yT7cV3pR6sW2xL5aJ7hN4eU9dG0iK8bM1oP/q:19000:0:99999:7:::\n",
		"/etc/hostname": hostname + "\n",
		"/etc/hosts":    "127.0.0.1\tlocalhost\n127.0.1.1\t" + hostname + "\n\n::1\tlocalhost ip6-localhost ip6-loopback\n",
		"/etc/os-release": fmt.Sprintf("PRETTY_NAME=\"%s %s\"\nNAME=\"%s\"\nVERSION_ID=\"%s\"\n"+
			"VERSION=\"%s (%s)\"\nVERSION_CODENAME=%s\nID=%s\nID_LIKE=debian\n",
			sys.Distro, sys.Version, sys.Distro, sys.VersionID, sys.Version, sys.Codename, sys.CodenameID, strings.ToLower(sys.Distro)),
		"/etc/issue": fmt.Sprintf("%s %s \\n \\l\n\n", sys.Distro, sys.Version),
		"/proc/version": fmt.Sprintf("Linux version %s (buildd@lcy02-amd64-045) "+
			"(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) %s\n",
			sys.Kernel, sys.KernelVersion),
		"/etc/ssh/sshd_config":     "Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\n",
		"/root/.bashrc":            "# ~/.bashrc\nexport PS1='\\u@\\h:\\w\\$ '\n",
		"/var/www/html/index.html": "<html><body><h1>It works!</h1></body></html>\n",
	}
}

// Snapshot 返回当前虚拟目录下的条目（排序后），主要供测试使用。
func (s *Session) Snapshot(dir string) []string {
	entries := append([]string(nil), s.dirs[path.Clean(dir)]...)
	sort.Strings(entries)

	return entries
}
