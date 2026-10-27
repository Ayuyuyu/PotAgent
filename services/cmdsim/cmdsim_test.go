package cmdsim

import (
	"strings"
	"testing"
	"time"
)

func newTestSession() *Session {
	fixed := time.Date(2026, 10, 27, 17, 20, 31, 0, time.Local)

	return New(Config{
		User:     "root",
		Hostname: "ubuntu",
		Now:      func() time.Time { return fixed },
	})
}

func TestUnknownCommand(t *testing.T) {
	s := newTestSession()

	res := s.Run("nmap 127.0.0.1")
	if res.ExitCode != 127 {
		t.Fatalf("exit code = %d, want 127", res.ExitCode)
	}
	if res.Output != "-bash: nmap: command not found\n" {
		t.Fatalf("output = %q", res.Output)
	}
}

func TestBasicIdentityCommands(t *testing.T) {
	s := newTestSession()

	cases := map[string]string{
		"whoami":   "root\n",
		"id":       "uid=0(root) gid=0(root) groups=0(root)\n",
		"hostname": "ubuntu\n",
		"pwd":      "/root\n",
	}

	for cmd, want := range cases {
		if got := s.Run(cmd).Output; got != want {
			t.Errorf("%s = %q, want %q", cmd, got, want)
		}
	}
}

func TestUname(t *testing.T) {
	s := newTestSession()

	if got := s.Run("uname").Output; got != "Linux\n" {
		t.Fatalf("uname = %q", got)
	}

	all := s.Run("uname -a").Output
	for _, part := range []string{"Linux", "ubuntu", "5.15.0-91-generic", "x86_64"} {
		if !strings.Contains(all, part) {
			t.Errorf("uname -a 缺少 %q: %q", part, all)
		}
	}

	if got := s.Run("uname -r").Output; got != "5.15.0-91-generic\n" {
		t.Fatalf("uname -r = %q", got)
	}
}

func TestCdAndLs(t *testing.T) {
	s := newTestSession()

	if res := s.Run("cd /etc"); res.Output != "" {
		t.Fatalf("cd /etc 输出 = %q", res.Output)
	}
	if s.Cwd() != "/etc" {
		t.Fatalf("cwd = %q", s.Cwd())
	}
	if got := s.Run("pwd").Output; got != "/etc\n" {
		t.Fatalf("pwd = %q", got)
	}

	ls := s.Run("ls").Output
	if !strings.Contains(ls, "passwd") || !strings.Contains(ls, "os-release") {
		t.Fatalf("ls 输出异常: %q", ls)
	}

	// 默认不显示隐藏文件，-a 才显示
	if got := s.Run("ls /root").Output; strings.Contains(got, ".bashrc") {
		t.Fatalf("ls 不应显示隐藏文件: %q", got)
	}
	if got := s.Run("ls -a /root").Output; !strings.Contains(got, ".bashrc") || !strings.Contains(got, "..") {
		t.Fatalf("ls -a 应显示隐藏文件: %q", got)
	}

	long := s.Run("ls -l /etc").Output
	if !strings.HasPrefix(long, "total ") || !strings.Contains(long, "passwd") {
		t.Fatalf("ls -l 输出异常: %q", long)
	}

	if res := s.Run("cd /nope"); res.ExitCode == 0 || !strings.Contains(res.Output, "No such file or directory") {
		t.Fatalf("cd 不存在的目录 = %+v", res)
	}

	if res := s.Run("cd .."); res.Output != "" || s.Cwd() != "/" {
		t.Fatalf("cd .. 后 cwd = %q, res=%+v", s.Cwd(), res)
	}
}

func TestCat(t *testing.T) {
	s := newTestSession()

	passwd := s.Run("cat /etc/passwd").Output
	if !strings.Contains(passwd, "root:x:0:0") || !strings.Contains(passwd, "/bin/bash") {
		t.Fatalf("cat /etc/passwd = %q", passwd)
	}

	// root 可以读 shadow，普通用户应当被拒绝
	if got := s.Run("cat /etc/shadow").Output; !strings.Contains(got, "root:$6$") {
		t.Fatalf("root 读 shadow = %q", got)
	}

	user := New(Config{User: "ubuntu", Hostname: "ubuntu"})
	if got := user.Run("cat /etc/shadow").Output; !strings.Contains(got, "Permission denied") {
		t.Fatalf("普通用户读 shadow = %q", got)
	}

	if got := s.Run("cat /etc/nothing").Output; !strings.Contains(got, "No such file or directory") {
		t.Fatalf("cat 不存在文件 = %q", got)
	}
}

func TestEchoWithQuotes(t *testing.T) {
	s := newTestSession()

	if got := s.Run(`echo "hello world"`).Output; got != "hello world\n" {
		t.Fatalf("echo 双引号 = %q", got)
	}
	if got := s.Run("echo hello   world").Output; got != "hello world\n" {
		t.Fatalf("echo 多空格 = %q", got)
	}
	if got := s.Run("echo -n hi").Output; got != "hi" {
		t.Fatalf("echo -n = %q", got)
	}
}

func TestDateAndUptime(t *testing.T) {
	s := newTestSession()

	if got := s.Run("date").Output; got != "Tue Oct 27 17:20:31 CST 2026\n" {
		t.Fatalf("date = %q", got)
	}
	if got := s.Run("date +%F").Output; got != "2026-10-27\n" {
		t.Fatalf("date +%%F = %q", got)
	}

	uptime := s.Run("uptime").Output
	if !strings.Contains(uptime, "up 11 days") || !strings.Contains(uptime, "load average") {
		t.Fatalf("uptime = %q", uptime)
	}
}

func TestHistoryAndExit(t *testing.T) {
	s := newTestSession()

	s.Run("whoami")
	s.Run("pwd")

	hist := s.Run("history").Output
	if !strings.Contains(hist, "1  whoami") || !strings.Contains(hist, "2  pwd") {
		t.Fatalf("history = %q", hist)
	}

	for _, cmd := range []string{"exit", "logout", "quit"} {
		if res := s.Run(cmd); !res.Exit {
			t.Errorf("%s 未标记退出", cmd)
		}
	}
}

func TestPrompt(t *testing.T) {
	s := newTestSession()

	if got := s.Prompt(); got != "root@ubuntu:~$ " {
		t.Fatalf("prompt = %q", got)
	}

	s.Run("cd /tmp")

	if got := s.Prompt(); got != "root@ubuntu:/tmp$ " {
		t.Fatalf("prompt = %q", got)
	}
}

func TestSystemInfoOverride(t *testing.T) {
	s := New(Config{
		User:     "root",
		Hostname: "web01",
		System: SystemInfo{
			Distro:  "Debian GNU/Linux",
			Version: "12 (bookworm)",
			Kernel:  "6.1.0-18-amd64",
			Machine: "aarch64",
		},
	})

	uname := s.Run("uname -a").Output
	for _, want := range []string{"web01", "6.1.0-18-amd64", "aarch64"} {
		if !strings.Contains(uname, want) {
			t.Errorf("uname -a 缺少 %q: %q", want, uname)
		}
	}

	osRelease := s.Run("cat /etc/os-release").Output
	if !strings.Contains(osRelease, `NAME="Debian GNU/Linux"`) {
		t.Errorf("os-release NAME 未生效: %q", osRelease)
	}
	// 没配的字段应回落到内置默认值
	if !strings.Contains(osRelease, "#101-Ubuntu") && !strings.Contains(s.Run("uname -v").Output, "#101-Ubuntu") {
		t.Errorf("未配置字段没有回落默认: %q", osRelease)
	}

	procVersion := s.Run("cat /proc/version").Output
	if !strings.Contains(procVersion, "6.1.0-18-amd64") {
		t.Errorf("/proc/version 未生效: %q", procVersion)
	}
}

func TestSemicolonStatements(t *testing.T) {
	s := newTestSession()

	got := s.Run("pwd; whoami").Output
	if got != "/root\nroot\n" {
		t.Fatalf("分号串联 = %q", got)
	}

	// 引号内的分号不切分
	if got := s.Run(`echo "a;b"`).Output; got != "a;b\n" {
		t.Fatalf("引号内分号 = %q", got)
	}
}

func TestBlankLine(t *testing.T) {
	s := newTestSession()

	if res := s.Run("   "); res.Output != "" || res.Exit {
		t.Fatalf("空行 = %+v", res)
	}
	if len(s.history) != 0 {
		t.Fatalf("空行不应进入历史: %v", s.history)
	}
}
