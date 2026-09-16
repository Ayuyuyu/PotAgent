package smb

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"
	"time"
)

var (
	serviceName = "smb"
	_           = services.Register(serviceName, SMBServiceInit)
)

func SMBServiceInit() services.Service {
	s := services.Service{
		WorkerHandle:   smbHandle,
		ServiceOptions: smbConfig{},
	}
	return s
}

type smbConfig struct {
	Version    string `mapstructure:"version"`
	ServerName string `mapstructure:"server_name"`
}

// SMB 低交互蜜罐：接受连接、识别协议版本、记录事件，不实现完整协议。
func smbHandle(ctx context.Context, service *services.Service) {
	var (
		serviceOptions = service.ServiceOptions.(smbConfig)
		baseOptions    = service.BaseOptions
	)
	logger.Log.Debugln(serviceOptions, baseOptions)

	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	listen, err := net.Listen("tcp4", address)
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer listen.Close()
	logger.Log.Infoln(baseOptions.Application, "listen on ", address)

	connChan := common.ForwardListenerToChan(listen)

	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case conn := <-connChan:
			go handleServiceConn(conn, service)
		}
	}
}

func handleServiceConn(conn net.Conn, service *services.Service) {
	defer conn.Close()
	protocol := service.BaseOptions.Protocol
	app := service.BaseOptions.Application

	srcAddr, err := common.GetConnSrcIPAndSrcPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}
	dstAddr, err := common.GetConnDstIPAndDstPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}

	event.EventPush(event.NewEvent(serviceName, "smb-connect", srcAddr, dstAddr, map[string]interface{}{
		"protocol":    protocol,
		"application": app,
	}))

	// 读取首个包头部，判断 SMB 版本
	br := bufio.NewReader(conn)
	header := make([]byte, 4)
	if _, err := br.Read(header); err != nil {
		logger.Log.Debug("smb: read header failed:", err)
		return
	}
	smbVersion := identifySMBVersion(header)

	event.EventPush(event.NewEvent(serviceName, "smb-negotiate", srcAddr, dstAddr, map[string]interface{}{
		"protocol":     protocol,
		"application":  app,
		"smb.version":  smbVersion,
		"smb.raw-head": fmt.Sprintf("%x", header),
	}))

	// 低交互：回复最小 SMB2 NEGOTIATE 响应头，让端口扫描器认为服务在线
	writeMinimalSMB2Response(conn, protocol, app)
}

// identifySMBVersion 根据前 4 字节识别 SMB 大版本
func identifySMBVersion(header []byte) string {
	if len(header) < 4 {
		return "unknown"
	}
	// SMB1: 0xFF 'S' 'M' 'B'
	if header[0] == 0xFF && header[1] == 'S' && header[2] == 'M' && header[3] == 'B' {
		return "SMB1"
	}
	// SMB2/3: 协议 ID 前 4 字节为 "FIP\0" (0x46495000)
	if header[0] == 'F' && header[1] == 'I' && header[2] == 'P' && header[3] == 0 {
		return "SMB2+"
	}
	return "unknown"
}

// writeMinimalSMB2Response 回复一个最小的 SMB2 NEGOTIATE 响应头，
// 并在客户端继续发包时记录一次数据事件（低交互，不实现完整协议）。
func writeMinimalSMB2Response(conn net.Conn, protocol, app string) {
	resp := make([]byte, 64)
	binary.BigEndian.PutUint32(resp[0:4], 0x46495000) // "FIP\0"
	binary.BigEndian.PutUint16(resp[4:6], 64)         // StructureSize
	binary.BigEndian.PutUint16(resp[6:8], 1)          // Credits
	binary.BigEndian.PutUint16(resp[8:10], 1)         // Type = NEGOTIATE
	if _, err := conn.Write(resp); err != nil {
		logger.Log.Debug("smb: write response failed:", err)
	}

	// 若 2 秒内客户端继续发包，记录数据事件后关闭
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n > 0 {
		srcAddr, _ := common.GetConnSrcIPAndSrcPort(&conn)
		dstAddr, _ := common.GetConnDstIPAndDstPort(&conn)
		event.EventPush(event.NewEvent(serviceName, "smb-data", srcAddr, dstAddr, map[string]interface{}{
			"protocol":    protocol,
			"application": app,
			"smb.bytes":   n,
			"smb.raw":     fmt.Sprintf("%x", buf[:n]),
		}))
	}
}
