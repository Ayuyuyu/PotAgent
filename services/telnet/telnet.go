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

	event.EventPush(event.NewEvent(serviceName, "telnet-connect", srcAddr, dstAddr, map[string]interface{}{
		"protocol":          service.BaseOptions.Protocol,
		"application":       service.BaseOptions.Application,
		"telnet.session-id": id.String(),
	}))

	term := NewTerminal(*conn, cfg.Prompt)

	// 推送 telnet-close 事件
	pushCloseEvent := func() {
		event.EventPush(event.NewEvent(serviceName, "telnet-close", srcAddr, dstAddr, map[string]interface{}{
			"protocol":          service.BaseOptions.Protocol,
			"application":       service.BaseOptions.Application,
			"telnet.session-id": id.String(),
		}))
	}

	// 认证，最多尝试 4 次
	authenticated := false
	for i := 0; i < 4; i++ {
		term.SetPrompt("Username: ")
		username, err := term.ReadLine()
		if err == io.EOF {
			pushCloseEvent()
			return
		} else if err != nil {
			logger.Log.Infoln(err)
			return
		}

		password, err := term.ReadPassword("Password: ")
		if err == io.EOF {
			pushCloseEvent()
			return
		} else if err != nil {
			logger.Log.Infoln(err)
			return
		}

		event.EventPush(event.NewEvent(serviceName, "telnet-password-authentication", srcAddr, dstAddr, map[string]interface{}{
			"protocol":          service.BaseOptions.Protocol,
			"application":       service.BaseOptions.Application,
			"telnet.session-id": id.String(),
			"telnet.username":   username,
			"telnet.password":   password,
		}))
		for _, account := range cfg.Accounts {
			if username == account.Username && password == account.Password {
				authenticated = true
				break
			}
		}
		if authenticated {
			break
		}

		term.Write([]byte(buildTelnetResponse("login failed")))
	}
	if !authenticated {
		return
	}

	// 发送欢迎消息
	term.SetPrompt(cfg.Prompt)
	term.Write([]byte(buildTelnetResponse(cfg.MOTD + "\n")))

	for {
		// 读取客户端发送的命令
		cmd, err := term.ReadLine()
		if err != nil {
			break
		}

		event.EventPush(event.NewEvent(serviceName, "telnet-command", srcAddr, dstAddr, map[string]interface{}{
			"protocol":          service.BaseOptions.Protocol,
			"application":       service.BaseOptions.Application,
			"telnet.session-id": id.String(),
			"command":           cmd,
		}))

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

func buildTelnetResponse(s string) string {
	return s + "\r\n"
}
