package tftp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"
)

var _ = services.Register("tftp", tftpServiceInit)

// TFTP 低交互蜜罐：监听 UDP 69，实现 RFC 1350 的 RRQ/WRQ/DATA/ACK/ERROR。
// 重点捕获攻击者请求/写入的文件名（设备配置、恶意 payload 落盘等，属高价值情报）。
const (
	opRRQ  = 1
	opWRQ  = 2
	opDATA = 3
	opACK  = 4
	opERR  = 5

	tftpBlockSize  = 512
	tftpMaxUpload  = 1 << 16 // 单文件上传上限 64KB，防止内存膨胀
	tftpWrqTimeout = 5 * time.Second
)

// defaultFileContent 为 RRQ（读请求）回应的伪文件内容；<512 字节即视为 EOF，
// 客户端 ACK 后传输结束。可用 yaml 的 file_content 覆盖。
const defaultFileContent = "# PotAgent TFTP honeypot\n" +
	"# This is a fake file returned to attackers performing read requests.\n"

type tftpConfig struct {
	// FileContent 为 RRQ 回应的伪文件内容（share_dir 未配置时生效）；<512 字节视为 EOF。
	FileContent string `mapstructure:"file_content"`
	// ShareDir 共享目录（绝对路径，或相对进程 CWD 的相对路径）：配置后 RRQ 读取本目录内真实文件下发、
	// WRQ 把上传内容真实落盘；留空则 RRQ 用 FileContent、WRQ 仅内存捕获。路径做 ../ 越界防护。
	ShareDir string `mapstructure:"share_dir"`
}

// shareRoot 返回 share_dir 的绝对根：绝对路径原样返回；相对路径基于进程 CWD（os.Getwd）解析。
func (c tftpConfig) shareRoot() string {
	dir := c.ShareDir
	if dir == "" {
		return ""
	}
	if filepath.IsAbs(dir) {
		return filepath.Clean(dir)
	}
	wd, err := os.Getwd()
	if err != nil {
		wd = "."
	}
	return filepath.Clean(filepath.Join(wd, dir))
}

// resolveSharePath 把 TFTP 文件名解析为 share_dir 内的绝对路径并做越界防护。
// 去掉前导分隔符再拼接，避免 filepath.Join 把 "/" 当绝对元素重置导致误判越界。
// share_dir 未配置或逃出根（含 ../ 穿越）返回 ("", false)。
func (c tftpConfig) resolveSharePath(name string) (string, bool) {
	if c.ShareDir == "" {
		return "", false
	}
	root := c.shareRoot()
	rel := strings.TrimLeft(name, "/")
	target := filepath.Clean(filepath.Join(root, rel))
	relpath, err := filepath.Rel(root, target)
	if err != nil || strings.HasPrefix(relpath, "..") {
		return "", false
	}
	return target, true
}

func tftpServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   tftpHandle,
		ServiceOptions: tftpConfig{},
	}
}

func tftpHandle(ctx context.Context, service *services.Service) {
	cfg := service.ServiceOptions.(tftpConfig)
	if cfg.FileContent == "" {
		cfg.FileContent = defaultFileContent
	}

	address := fmt.Sprintf("%v:%v", service.BaseOptions.Host, service.BaseOptions.Port)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(service.BaseOptions.Host), Port: int(service.BaseOptions.Port)})
	if err != nil {
		logger.Log.Fatalln(err)
		return
	}
	defer conn.Close()
	logger.Log.Infoln(service.BaseOptions.Application, "listen on", address)

	// 单读者内联处理：WRQ 会话需要就地读取 DATA 流，若与主循环并发读同一 socket
	// 会出现数据包串台，故不使用 ForwardUDPPacketToChan，自行 ReadFromUDP 并按
	// 来源地址在会话内闭环。读取超时可周期性检查 ctx 退出。
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", service.BaseOptions.Protocol)
			return
		default:
		}
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			logger.Log.Debug("tftp: set read deadline:", err)
		}
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			logger.Log.Debug("tftp: read error:", err)
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		handleTFTP(conn, pkt, raddr, service, &cfg)
	}
}

func handleTFTP(conn *net.UDPConn, pkt []byte, raddr *net.UDPAddr, service *services.Service, cfg *tftpConfig) {
	if len(pkt) < 2 {
		return
	}
	op := binary.BigEndian.Uint16(pkt[:2])

	switch op {
	case opRRQ:
		filename, mode, options, ok := parseReq(pkt)
		if !ok {
			writeErr(conn, raddr, 4, "Illegal TFTP operation")
			return
		}
		hasShare := cfg.ShareDir != ""
		if hasShare {
			// 从共享目录读真实文件下发；缺失/越界/目录均回 File not found（贴近真实 TFTP）
			if path, ok := cfg.resolveSharePath(filename); ok {
				if fi, e := os.Stat(path); e == nil && !fi.IsDir() {
					if data, e := os.ReadFile(path); e == nil {
						pushRequest(service, conn, raddr, "RRQ", filename, mode, options, pkt, nil, map[string]interface{}{"tftp.served_path": path})
						streamFile(conn, raddr, data)
						return
					}
				}
			}
			writeErr(conn, raddr, 1, "File not found")
			return
		}
		// 未配置 share_dir：回一段伪文件内容（<512 视为 EOF，客户端 ACK 后传输结束）
		pushRequest(service, conn, raddr, "RRQ", filename, mode, options, pkt, nil, nil)
		conn.WriteToUDP(buildData(1, []byte(cfg.FileContent)), raddr)

	case opWRQ:
		filename, mode, options, ok := parseReq(pkt)
		if !ok {
			writeErr(conn, raddr, 4, "Illegal TFTP operation")
			return
		}
		hasShare := cfg.ShareDir != ""
		var path string
		resolveOK := false
		if hasShare {
			path, resolveOK = cfg.resolveSharePath(filename)
		}
		// 先 ACK(0) 接受写入，再接收 DATA 块捕获落盘内容
		conn.WriteToUDP(buildACK(0), raddr)
		received, _ := recvWrite(conn, raddr)
		// 落盘：仅在解析成功（未越界）且确有数据时写入共享目录
		if resolveOK && len(received) > 0 {
			if dir := filepath.Dir(path); dir != "" {
				_ = os.MkdirAll(dir, 0755)
			}
			_ = os.WriteFile(path, received, 0644)
		}
		pushRequest(service, conn, raddr, "WRQ", filename, mode, options, pkt, received, nil)

	default:
		// DATA/ACK/ERR 等非首包：属于已建立会话的后续包，忽略
		return
	}
}

// streamFile 将真实文件内容按 512 字节分块下发，每块等待客户端 ACK(block)。
// 末块 <512 视为 EOF，发送后结束（与 RFC 1350 一致）。
func streamFile(conn *net.UDPConn, raddr *net.UDPAddr, data []byte) {
	var block uint16 = 1
	for off := 0; off < len(data) || (block == 1 && len(data) == 0); {
		end := off + tftpBlockSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]
		conn.WriteToUDP(buildData(block, chunk), raddr)
		if !recvACK(conn, raddr, block) {
			return // 超时/异常，中止传输
		}
		off = end
		if len(chunk) < tftpBlockSize {
			return // EOF
		}
		block++
	}
}

// recvACK 等待来自 raddr 的对 block 的 ACK；来源不符或类型错误返回 false。
func recvACK(conn *net.UDPConn, raddr *net.UDPAddr, block uint16) bool {
	if err := conn.SetReadDeadline(time.Now().Add(tftpWrqTimeout)); err != nil {
		return false
	}
	buf := make([]byte, 65535)
	n, from, err := conn.ReadFromUDP(buf)
	if err != nil {
		return false
	}
	if from.String() != raddr.String() || n < 4 {
		return false
	}
	if binary.BigEndian.Uint16(buf[:2]) != opACK {
		return false
	}
	return binary.BigEndian.Uint16(buf[2:4]) == block
}

// recvWrite 读取 WRQ 之后的 DATA 流，按块号递增 ACK，返回拼接的全部数据。
// 仅接受来自同一源地址的包；超时/末块/超上限即结束。
func recvWrite(conn *net.UDPConn, raddr *net.UDPAddr) ([]byte, bool) {
	var received []byte
	var block uint16
	for {
		if err := conn.SetReadDeadline(time.Now().Add(tftpWrqTimeout)); err != nil {
			break
		}
		buf := make([]byte, 65535)
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if from.String() != raddr.String() {
			continue // 忽略其他来源
		}
		if n < 4 {
			break
		}
		if binary.BigEndian.Uint16(buf[:2]) != opDATA {
			break
		}
		blk := binary.BigEndian.Uint16(buf[2:4])
		if blk != block+1 {
			continue // 乱序/重复，不 ACK 错序块
		}
		block = blk
		received = append(received, buf[4:n]...)
		conn.WriteToUDP(buildACK(block), raddr)
		if n-4 < tftpBlockSize {
			break // 末块
		}
		if len(received) > tftpMaxUpload {
			break
		}
	}
	return received, len(received) > 0
}

// parseReq 解析 RRQ/WRQ：opcode(2) + filename\0 + mode\0 + [opt\0val\0...]。
func parseReq(pkt []byte) (filename, mode string, options map[string]string, ok bool) {
	if len(pkt) < 4 {
		return
	}
	parts := bytes.Split(pkt[2:], []byte{0})
	nonempty := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			nonempty = append(nonempty, string(p))
		}
	}
	if len(nonempty) < 2 {
		return
	}
	filename = nonempty[0]
	mode = strings.ToLower(nonempty[1])
	options = map[string]string{}
	for i := 2; i+1 < len(nonempty); i += 2 {
		options[nonempty[i]] = nonempty[i+1]
	}
	ok = true
	return
}

func pushRequest(service *services.Service, conn *net.UDPConn, raddr *net.UDPAddr,
	opName, filename, mode string, options map[string]string, raw, upload []byte, extra map[string]interface{}) {
	src := common.Addr{IP: raddr.IP.String(), Port: uint16(raddr.Port)}
	var dst common.Addr
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		dst = common.Addr{IP: la.IP.String(), Port: uint16(la.Port)}
	}
	details := map[string]interface{}{
		"ip_protocol":    "udp",
		"protocol":       service.BaseOptions.Protocol,
		"application":    service.BaseOptions.Application,
		"tftp.operation": opName,
		"tftp.filename":  filename,
		"tftp.mode":      mode,
		"tftp.options":   options,
		"tftp.raw":       fmt.Sprintf("%x", raw),
	}
	if len(upload) > 0 {
		details["tftp.data"] = fmt.Sprintf("%x", upload)
		details["tftp.data_size"] = len(upload)
	}
	for k, v := range extra {
		details[k] = v
	}
	event.EventPush(event.NewEvent(service.BaseOptions.Protocol, "tftp-request", src, dst, details))
}

func buildData(block uint16, data []byte) []byte {
	b := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(b[0:2], opDATA)
	binary.BigEndian.PutUint16(b[2:4], block)
	copy(b[4:], data)
	return b
}

func buildACK(block uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:2], opACK)
	binary.BigEndian.PutUint16(b[2:4], block)
	return b
}

func writeErr(conn *net.UDPConn, raddr *net.UDPAddr, code uint16, msg string) {
	b := make([]byte, 4+len(msg)+1)
	binary.BigEndian.PutUint16(b[0:2], opERR)
	binary.BigEndian.PutUint16(b[2:4], code)
	copy(b[4:], msg)
	b[4+len(msg)] = 0
	conn.WriteToUDP(b, raddr)
}
