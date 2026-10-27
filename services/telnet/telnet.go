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
	"strings"

	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"
	"potAgent/services/cmdsim"

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
	Hostname  string            `mapstructure:"hostname" yaml:"hostname"`
	Accounts  []accounts        `mapstructure:"accounts"`
	Simulator map[string]string `mapstructure:"simulator"  yaml:"simulator"`
	// CommandSim 是否启用内置命令模拟（whoami/ls/cd/cat…），不配则默认启用。
	// 配了 simulator 的整行命令仍然优先。
	CommandSim *bool `mapstructure:"command_sim" yaml:"command_sim"`
	// System 内置命令里显示的伪造系统版本（uname/os-release 等），留空用内置默认
	System cmdsim.SystemInfo `mapstructure:"system" yaml:"system"`
}

// commandSimEnabled 内置命令模拟的开关判定。
func (c telnetConfig) commandSimEnabled() bool {
	return c.CommandSim == nil || *c.CommandSim
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
		logger.Log.Errorln(err)
		service.ReportError(err)
		return
	}
	defer listen.Close()
	logger.Log.Infof("%s listen on %s", baseOptions.Application, address)

	service.MarkReady()

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
	loginUser := ""

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
				loginUser = username
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

	// 命令模拟会话：cwd/历史按连接保持
	var sim *cmdsim.Session
	if cfg.commandSimEnabled() {
		user := loginUser
		if user == "" {
			user = "root"
		}

		sim = cmdsim.New(cmdsim.Config{
			User:     user,
			Hostname: cfg.Hostname,
			System:   cfg.System,
		})
	}

	prompt := cfg.Prompt
	if prompt == "" && sim != nil {
		prompt = sim.Prompt()
	}

	// 发送欢迎消息
	term.SetPrompt(prompt)
	term.Write([]byte(buildTelnetResponse(cfg.MOTD)))

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

		if sim != nil {
			res := sim.Run(cmd)
			if res.Output != "" {
				term.Write([]byte(buildTelnetResponse(res.Output)))
			}

			if res.Exit {
				break
			}

			term.SetPrompt(promptFor(sim, cfg.Prompt))

			continue
		}

		// 回显命令给客户端
		term.Write([]byte(buildTelnetResponse("command not found")))
	}
	term.Write([]byte(buildTelnetResponse("Goodbye!\r\n")))
}

// promptFor 优先用配置的固定提示符，否则跟随模拟会话的 cwd。
func promptFor(sim *cmdsim.Session, fixed string) string {
	if fixed != "" {
		return fixed
	}

	return sim.Prompt()
}

// buildTelnetResponse 统一行尾：Terminal.Write 会把 \n 转成 \r\n，
// 所以这里只保证"以单个 \n 结尾"，避免出现 \r\r\n。
func buildTelnetResponse(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")

	return strings.TrimSuffix(s, "\n") + "\n"
}
