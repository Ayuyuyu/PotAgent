package telnet

/*
Telnet 蜜罐服务（TCP 23，telnet 文本协议；实现为行交互，不做 IAC 选项协商）。

低交互策略：
  - 每连接一个 Terminal（prompt/MOTD 可配，ReadPassword 关闭回显）；登录循环最多 4 次，
    成功后进入命令循环：命中 simulator 回配置内容，空行忽略，quit 退出，其余回
    command not found，结束回 Goodbye!。无存储。
  - 校验配置的 accounts（用户名+口令完全匹配）；accounts 为空时永远认证失败（4 次后断开），
    但每次尝试的用户名/口令都落事件（与 ftp/smtp 的「空配置=全通过」相反）。
  - 未知命令回 command not found 且不断开（宽容）。
  - 事件 telnet-connect / telnet-password-authentication / telnet-command / telnet-close，
    字段含 session-id(xid)/username/password/command。
*/

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
