package tftp

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"potAgent/global"
	"potAgent/services"
)

func buildRRQ(name, mode string) []byte {
	p := []byte{0, opRRQ}
	return append(p, []byte(name+"\x00"+mode+"\x00")...)
}

func buildWRQ(name, mode string) []byte {
	p := []byte{0, opWRQ}
	return append(p, []byte(name+"\x00"+mode+"\x00")...)
}

func TestParseReq(t *testing.T) {
	// RRQ: filename + mode + options(blksize=512)
	pkt := buildRRQ("boot.bin", "octet")
	pkt = append(pkt, []byte("blksize\x00512\x00")...)
	fn, mode, opts, ok := parseReq(pkt)
	if !ok || fn != "boot.bin" || mode != "octet" {
		t.Fatalf("parseReq RRQ: fn=%q mode=%q ok=%v", fn, mode, ok)
	}
	if opts["blksize"] != "512" {
		t.Fatalf("options blksize = %q", opts["blksize"])
	}
	if _, _, _, ok2 := parseReq([]byte{0, opRRQ, 'a'}); ok2 {
		t.Fatal("parseReq should fail without mode")
	}
}

func TestBuilders(t *testing.T) {
	d := buildData(1, []byte("hi"))
	if binary.BigEndian.Uint16(d[0:2]) != opDATA || binary.BigEndian.Uint16(d[2:4]) != 1 || string(d[4:]) != "hi" {
		t.Fatalf("buildData wrong: %x", d)
	}
	a := buildACK(0)
	if binary.BigEndian.Uint16(a[0:2]) != opACK || binary.BigEndian.Uint16(a[2:4]) != 0 {
		t.Fatalf("buildACK wrong: %x", a)
	}
}

func newTestService(cfg tftpConfig) (*services.Service, *net.UDPConn, *net.UDPConn) {
	srv, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	srvAddr := srv.LocalAddr().(*net.UDPAddr)
	cli, _ := net.DialUDP("udp4", nil, srvAddr)
	svc := &services.Service{
		BaseOptions:    global.ServiceBaseConfig{Host: "127.0.0.1", Port: uint16(srvAddr.Port), Protocol: "tftp", Application: "tftp"},
		ServiceOptions: cfg,
	}
	return svc, srv, cli
}

func TestRRQResponse(t *testing.T) {
	svc, srv, cli := newTestService(tftpConfig{FileContent: "hello"})
	defer srv.Close()
	defer cli.Close()
	cfg := svc.ServiceOptions.(tftpConfig)

	cli.Write(buildRRQ("a.bin", "octet"))
	buf := make([]byte, 65535)
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, raddr, err := srv.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	go handleTFTP(srv, buf[:n], raddr, svc, &cfg)

	resp := make([]byte, 65535)
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err := cli.Read(resp)
	if err != nil {
		t.Fatal("client should receive DATA:", err)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != opDATA {
		t.Fatalf("expected DATA, got %x", resp[0:2])
	}
	if string(resp[4:m]) != "hello" {
		t.Fatalf("DATA payload = %q, want hello", string(resp[4:m]))
	}
}

func TestWRQCapture(t *testing.T) {
	svc, srv, cli := newTestService(tftpConfig{FileContent: "hello"})
	defer srv.Close()
	defer cli.Close()
	cfg := svc.ServiceOptions.(tftpConfig)

	cli.Write(buildWRQ("drop", "octet"))
	buf := make([]byte, 65535)
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, raddr, err := srv.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	go handleTFTP(srv, buf[:n], raddr, svc, &cfg)

	// 服务器应先回 ACK(0)
	resp := make([]byte, 65535)
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cli.Read(resp); err != nil {
		t.Fatal("client should receive ACK(0):", err)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != opACK || binary.BigEndian.Uint16(resp[2:4]) != 0 {
		t.Fatalf("expected ACK(0), got %x", resp[:4])
	}

	// 客户端发送 DATA(1, "evil")
	cli.Write(buildData(1, []byte("evil")))

	// 服务器应回 ACK(1)
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err := cli.Read(resp)
	if err != nil {
		t.Fatal("client should receive ACK(1):", err)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != opACK || binary.BigEndian.Uint16(resp[2:4]) != 1 {
		t.Fatalf("expected ACK(1), got %x", resp[:m])
	}
	time.Sleep(50 * time.Millisecond) // 等待 recvWrite 收尾
}

func TestResolveSharePath(t *testing.T) {
	dir := t.TempDir()
	c := tftpConfig{ShareDir: dir}
	if p, ok := c.resolveSharePath("a/b.txt"); !ok || p != filepath.Join(dir, "a/b.txt") {
		t.Fatalf("resolveSharePath normal: %q %v", p, ok)
	}
	if _, ok := c.resolveSharePath("../escape.txt"); ok {
		t.Fatal("resolveSharePath should reject ../ traversal")
	}
	if _, ok := c.resolveSharePath("sub/../../etc"); ok {
		t.Fatal("resolveSharePath should reject embedded ../ traversal")
	}
	// 前导 '/' 视为相对 share_dir 根（与 FTP 一致），不是越界
	if p, ok := c.resolveSharePath("/etc/passwd"); !ok || p != filepath.Join(dir, "etc/passwd") {
		t.Fatalf("resolveSharePath leading-slash: %q %v", p, ok)
	}
	if _, ok := (tftpConfig{}).resolveSharePath("x"); ok {
		t.Fatal("resolveSharePath should fail when ShareDir empty")
	}
}

func TestRRQFromShareDir(t *testing.T) {
	dir := t.TempDir()
	real := []byte("real-file-bytes")
	if err := os.WriteFile(filepath.Join(dir, "config.bin"), real, 0644); err != nil {
		t.Fatal(err)
	}
	svc, srv, cli := newTestService(tftpConfig{ShareDir: dir, FileContent: "fake"})
	defer srv.Close()
	defer cli.Close()
	cfg := svc.ServiceOptions.(tftpConfig)

	cli.Write(buildRRQ("config.bin", "octet"))
	buf := make([]byte, 65535)
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, raddr, err := srv.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	go handleTFTP(srv, buf[:n], raddr, svc, &cfg)

	// 应收到真实文件内容（多块流式）
	var got []byte
	block := uint16(0)
	for {
		resp := make([]byte, 65535)
		cli.SetReadDeadline(time.Now().Add(2 * time.Second))
		m, err := cli.Read(resp)
		if err != nil {
			t.Fatal("read DATA:", err)
		}
		if binary.BigEndian.Uint16(resp[0:2]) != opDATA {
			t.Fatalf("expected DATA, got %x", resp[0:2])
		}
		b := binary.BigEndian.Uint16(resp[2:4])
		if b != block+1 {
			t.Fatalf("block out of order: got %d want %d", b, block+1)
		}
		block = b
		got = append(got, resp[4:m]...)
		cli.Write(buildACK(block)) // ACK
		if m-4 < tftpBlockSize {
			break // EOF
		}
	}
	if string(got) != string(real) {
		t.Fatalf("RRQ served %q, want %q", string(got), string(real))
	}
}

func TestRRQMissingFile(t *testing.T) {
	dir := t.TempDir()
	svc, srv, cli := newTestService(tftpConfig{ShareDir: dir})
	defer srv.Close()
	defer cli.Close()
	cfg := svc.ServiceOptions.(tftpConfig)

	cli.Write(buildRRQ("nope.bin", "octet"))
	buf := make([]byte, 65535)
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, raddr, err := srv.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	go handleTFTP(srv, buf[:n], raddr, svc, &cfg)

	resp := make([]byte, 65535)
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = cli.Read(resp)
	if err != nil {
		t.Fatal("read ERROR:", err)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != opERR {
		t.Fatalf("expected ERROR, got %x", resp[0:2])
	}
}

func TestWRQToShareDir(t *testing.T) {
	dir := t.TempDir()
	svc, srv, cli := newTestService(tftpConfig{ShareDir: dir})
	defer srv.Close()
	defer cli.Close()
	cfg := svc.ServiceOptions.(tftpConfig)

	cli.Write(buildWRQ("drop.bin", "octet"))
	buf := make([]byte, 65535)
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, raddr, err := srv.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	go handleTFTP(srv, buf[:n], raddr, svc, &cfg)

	resp := make([]byte, 65535)
	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cli.Read(resp); err != nil {
		t.Fatal("client should receive ACK(0):", err)
	}
	cli.Write(buildData(1, []byte("payload123")))

	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cli.Read(resp); err != nil {
		t.Fatal("client should receive ACK(1):", err)
	}
	time.Sleep(50 * time.Millisecond)

	got, err := os.ReadFile(filepath.Join(dir, "drop.bin"))
	if err != nil {
		t.Fatal("uploaded file not written:", err)
	}
	if string(got) != "payload123" {
		t.Fatalf("uploaded content = %q, want payload123", string(got))
	}
}
