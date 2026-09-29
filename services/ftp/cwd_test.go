package ftp

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"potAgent/logger"
)

func TestCWDAbsolute(t *testing.T) {
	logger.InitLog("info")
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	addr, cancel := startFTP(t, ftpConfig{Mode: "ftp", ShareDir: root})
	defer cancel()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cr := bufio.NewReader(conn)
	read := func() string {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		l, _ := cr.ReadString('\n')
		return l
	}
	_ = read() // banner
	conn.Write([]byte("USER anon\r\n"))
	_ = read()
	conn.Write([]byte("PASS anon\r\n"))
	_ = read()

	// CWD / 根目录（真实存在）应 250
	conn.Write([]byte("CWD /\r\n"))
	if r := read(); !strings.HasPrefix(r, "250") {
		t.Fatalf("CWD / 期望 250, 实际 %q", r)
	}
	// CWD /sub 子目录（真实存在）应 250
	conn.Write([]byte("CWD /sub\r\n"))
	if r := read(); !strings.HasPrefix(r, "250") {
		t.Fatalf("CWD /sub 期望 250, 实际 %q", r)
	}
	// CWD /nope 不存在应 550
	conn.Write([]byte("CWD /nope\r\n"))
	if r := read(); !strings.HasPrefix(r, "550") {
		t.Fatalf("CWD /nope 期望 550, 实际 %q", r)
	}
	// CWD /../etc 越界应 550（不能逃出 share_dir 根）
	conn.Write([]byte("CWD /../etc\r\n"))
	if r := read(); !strings.HasPrefix(r, "550") {
		t.Fatalf("CWD /../etc 期望 550(越界), 实际 %q", r)
	}
}

// TestCWDFakeMode：未配置 share_dir 时（默认伪目录模式），CWD 应走默认伪树，
// CWD / 与 CWD /documents 回 250，文件/不存在回 550，而不是一律 550。
func TestCWDFakeMode(t *testing.T) {
	logger.InitLog("info")
	addr, cancel := startFTP(t, ftpConfig{Mode: "ftp", ShareDir: ""})
	defer cancel()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cr := bufio.NewReader(conn)
	read := func() string {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		l, _ := cr.ReadString('\n')
		return l
	}
	_ = read() // banner
	conn.Write([]byte("USER anon\r\n"))
	_ = read()
	conn.Write([]byte("PASS anon\r\n"))
	_ = read()

	conn.Write([]byte("CWD /\r\n"))
	if r := read(); !strings.HasPrefix(r, "250") {
		t.Fatalf("默认模式 CWD / 期望 250, 实际 %q", r)
	}
	conn.Write([]byte("CWD /documents\r\n"))
	if r := read(); !strings.HasPrefix(r, "250") {
		t.Fatalf("默认模式 CWD /documents 期望 250, 实际 %q", r)
	}
	conn.Write([]byte("CWD /readme.txt\r\n"))
	if r := read(); !strings.HasPrefix(r, "550") {
		t.Fatalf("默认模式 CWD /readme.txt(文件) 期望 550, 实际 %q", r)
	}
	conn.Write([]byte("CWD /nope\r\n"))
	if r := read(); !strings.HasPrefix(r, "550") {
		t.Fatalf("默认模式 CWD /nope 期望 550, 实际 %q", r)
	}
}
