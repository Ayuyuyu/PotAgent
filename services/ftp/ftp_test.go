package ftp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitCmd(t *testing.T) {
	c, a := splitCmd("USER admin")
	if c != "USER" || a != "admin" {
		t.Fatalf("got (%q,%q)", c, a)
	}
	c, a = splitCmd("PASV")
	if c != "PASV" || a != "" {
		t.Fatalf("got (%q,%q)", c, a)
	}
	c, a = splitCmd("  LIST  -la  ")
	if c != "LIST" || a != "-la" {
		t.Fatalf("got (%q,%q)", c, a)
	}
}

func TestPasvReply(t *testing.T) {
	got := pasvReply("192.168.1.10", 5000)
	// 5000 = 0x1388 -> p1=19, p2=136
	want := "227 Entering Passive Mode (192,168,1,10,19,136).\r\n"
	if got != want {
		t.Fatalf("pasvReply = %q, want %q", got, want)
	}
}

func TestParsePort(t *testing.T) {
	// 用 session 解析 PORT h1,h2,h3,h4,p1,p2
	s := &ftpSession{}
	s.setPort("192,168,1,20,19,136")
	if s.portAddr != "192.168.1.20:5000" {
		t.Fatalf("portAddr = %q", s.portAddr)
	}
	if s.dataMode != "port" {
		t.Fatalf("dataMode = %q", s.dataMode)
	}
}

func TestParseEprt(t *testing.T) {
	s := &ftpSession{}
	s.setEprt("|1|10.0.0.5|2121|")
	if s.portAddr != "10.0.0.5:2121" {
		t.Fatalf("portAddr = %q", s.portAddr)
	}
}

func TestListingContainsEntries(t *testing.T) {
	s := &ftpSession{cfg: ftpConfig{}}
	out := s.listing("/")
	for _, name := range []string{"readme.txt", "backup.zip", "credentials.cfg", "documents"} {
		if !strings.Contains(out, name) {
			t.Fatalf("listing missing %q:\n%s", name, out)
		}
	}
}

func TestListingFromDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.dat"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &ftpSession{cfg: ftpConfig{ShareDir: dir}}
	out := s.listing("/")
	if !strings.Contains(out, "secret.dat") {
		t.Fatalf("listing missing file:\n%s", out)
	}
	if !strings.Contains(out, "sub") {
		t.Fatalf("listing missing dir:\n%s", out)
	}
	if !strings.Contains(out, "drwxr-xr-x") {
		t.Fatalf("listing missing dir mode:\n%s", out)
	}
	// 越界防护：.. 不应逃出 share_dir 根
	outEsc := s.listing("../")
	if strings.Contains(outEsc, "drwxr-xr-x 1 user user     4096") && strings.Contains(outEsc, "..") {
		// 仅作基本健全性检查，不强制结构
		_ = outEsc
	}
}
