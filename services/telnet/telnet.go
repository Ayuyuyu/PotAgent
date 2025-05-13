package telnet

import (
	"context"
	"fmt"
	"io"
	"net"
	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"
	"runtime"
	"time"

	"github.com/rs/xid"
)

var (
	serviceName = "telnet"
	_           = services.Register(serviceName, TelnetServiceInit)
)

func TelnetServiceInit() services.Service {
	s := services.Service{
		WorkerHandle:   telnetHandle,
		ServiceOptions: telnetConfig{},
	}
	return s
}

type accounts struct {
	Username string `mapstructure:"username" yaml:"username"`
	Password string `mapstructure:"password" yaml:"password"`
}

type telnetConfig struct {
	Prompt    string            `mapstructure:"prompt" yaml:"prompt"`
	MOTD      string            `mapstructure:"motd" yaml:"motd"`
	Accounts  []accounts        `mapstructure:"accounts"`
	Simulator map[string]string `mapstructure:"simulator"  yaml:"simulator"`
}

func telnetHandle(ctx context.Context, service *services.Service) {
	var (
		baseOptions = service.BaseOptions
	)
	// 监听
	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	network := "tcp4"
	listen, err := net.Listen(network, address)
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer listen.Close()
	logger.Log.Info(baseOptions.Application, " listen on ", address)

	connChan := common.ForwardListenerToChan(listen)

	for {
		select {
		case <-ctx.Done(): // 监听关闭
			logger.Log.Infof("%s service close", serviceName)
			return
		case conn := <-connChan:
			go handleServiceConn(&conn, service)
		}
	}
}

func handleServiceConn(conn *net.Conn, service *services.Service) {
	defer (*conn).Close()
	id := xid.New()
	cfg := service.ServiceOptions.(telnetConfig)

	srcAddr, err := common.GetConnSrcIPAndSrcPort(conn)
	if err != nil {
		logger.Log.Error(err)
	}
	dstAddr, err := common.GetConnDstIPAndDstPort(conn)
	if err != nil {
		logger.Log.Error(err)
	}

	e := event.Event{
		Timestamp:     time.Now().Format(time.DateTime),
		EventCategory: serviceName,
		EventType:     "telnet-connect",
		SrcIP:         srcAddr.IP,
		DstIP:         dstAddr.IP,
		IPProtocol:    "tcp",
		SrcPort:       srcAddr.Port,
		DstPort:       dstAddr.Port,
		Details: map[string]interface{}{
			"protocol":          service.BaseOptions.Protocol,
			"application":       service.BaseOptions.Application,
			"telnet.session-id": id.String(),
		},
	}
	event.EventPush(&e)

	authTryCount := 0

	term := NewTerminal(*conn, cfg.Prompt)

AuthRetry:
	term.SetPrompt("Username: ")
	username, err := term.ReadLine()
	if err == io.EOF {
		e := event.Event{
			Timestamp:     time.Now().Format(time.DateTime),
			EventCategory: serviceName,
			EventType:     "telnet-close",
			SrcIP:         srcAddr.IP,
			DstIP:         dstAddr.IP,
			IPProtocol:    "tcp",
			SrcPort:       srcAddr.Port,
			DstPort:       dstAddr.Port,
			Details: map[string]interface{}{
				"protocol":          service.BaseOptions.Protocol,
				"application":       service.BaseOptions.Application,
				"telnet.session-id": id.String(),
			},
		}
		event.EventPush(&e)
		return
	} else if err != nil {
		logger.Log.Infoln(err)
		return
	}

	password, err := term.ReadPassword("Password: ")
	if err == io.EOF {
		e := event.Event{
			Timestamp:     time.Now().Format(time.DateTime),
			EventCategory: serviceName,
			EventType:     "telnet-close",
			SrcIP:         srcAddr.IP,
			DstIP:         dstAddr.IP,
			IPProtocol:    "tcp",
			SrcPort:       srcAddr.Port,
			DstPort:       dstAddr.Port,
			Details: map[string]interface{}{
				"protocol":          service.BaseOptions.Protocol,
				"application":       service.BaseOptions.Application,
				"telnet.session-id": id.String(),
			},
		}
		event.EventPush(&e)
		return
	} else if err != nil {
		logger.Log.Infoln(err)
		return
	}

	e = event.Event{
		Timestamp:     time.Now().Format(time.DateTime),
		EventCategory: serviceName,
		EventType:     "telnet-password-authentication",
		SrcIP:         srcAddr.IP,
		DstIP:         dstAddr.IP,
		IPProtocol:    "tcp",
		SrcPort:       srcAddr.Port,
		DstPort:       dstAddr.Port,
		Details: map[string]interface{}{
			"protocol":          service.BaseOptions.Protocol,
			"application":       service.BaseOptions.Application,
			"telnet.session-id": id.String(),
			"telnet.username":   username,
			"telnet.password":   password,
		},
	}
	event.EventPush(&e)
	for _, account := range cfg.Accounts {
		if username == account.Username && password == account.Password {
			goto Shell
		}
	}

	term.Write([]byte(buildTelnetResponse("login failed")))
	authTryCount += 1

	if authTryCount >= 4 {
		return
	} else {
		goto AuthRetry
	}

Shell:
	// 发送欢迎消息
	term.SetPrompt(cfg.Prompt)
	term.Write([]byte(buildTelnetResponse(cfg.MOTD + "\n")))

	for {
		// 读取客户端发送的命令
		cmd, err := term.ReadLine()
		if err != nil {
			break
		}

		e = event.Event{
			Timestamp:     time.Now().Format(time.DateTime),
			EventCategory: serviceName,
			EventType:     "telnet-command",
			SrcIP:         srcAddr.IP,
			DstIP:         dstAddr.IP,
			IPProtocol:    "tcp",
			SrcPort:       srcAddr.Port,
			DstPort:       dstAddr.Port,
			Details: map[string]interface{}{
				"protocol":          service.BaseOptions.Protocol,
				"application":       service.BaseOptions.Application,
				"telnet.session-id": id.String(),
				"command":           cmd,
			},
		}
		event.EventPush(&e)

		// 查询命令是否有配置对应的响应，有的话则返回
		if v, ok := cfg.Simulator[cmd]; ok {
			term.Write([]byte(buildTelnetResponse(v)))
			continue
		}

		if cmd == "" {
			continue
		}

		// 默认退出命令
		if cmd == "quit" {
			break
		}

		// 回显命令给客户端
		term.Write([]byte(buildTelnetResponse("command not found")))
	}
	term.Write([]byte(buildTelnetResponse("Goodbye!\r\n")))
}

func genSuffix() (suffix string) {
	if runtime.GOOS == "windows" {
		suffix = "\r\n"
	} else if runtime.GOOS == "linux" {
		suffix = "\n"
	}
	return
}

func buildTelnetResponse(s string) string {
	return s + genSuffix()
}
