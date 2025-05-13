package ssh

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"net"
	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"
	"potAgent/services/decoder"
	"strings"
	"time"

	"github.com/rs/xid"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var (
	serviceName = "ssh"
	_           = services.Register(serviceName, SSHServiceInit)
)

func SSHServiceInit() services.Service {
	s := services.Service{
		WorkerHandle:   sshHandle,
		ServiceOptions: sshConfig{},
	}

	return s
}

type sshData struct {
	hostKey  *privateKey
	metadata map[string]string // 临时维持ssh登录成功后的一些数据
}

type accounts struct {
	Username string `mapstructure:"username" yaml:"username"`
	Password string `mapstructure:"password" yaml:"password"`
}

type sshConfig struct {
	Version         string            `mapstructure:"version"`
	SimulatorEnable bool              `mapstructure:"simulator_enable"`
	Hostname        string            `mapstructure:"hostname"`
	Motd            string            `mapstructure:"motd"`
	Accounts        []accounts        `mapstructure:"accounts"`
	MaxAuthTries    int               `mapstructure:"max_auth_tries"`
	Simulator       map[string]string `mapstructure:"simulator"  yaml:"simulator"`
}

func sshHandle(ctx context.Context, service *services.Service) {
	var (
		serviceOptions = service.ServiceOptions.(sshConfig)
		baseOptions    = service.BaseOptions
	)
	logger.Log.Debug(serviceOptions)

	//每次启动创建新key
	sData := sshData{metadata: make(map[string]string)}
	keyBytes, err := generateKey()
	if err != nil {
		logger.Log.Fatalln(fmt.Sprintf("Could not generate ssh key: %s", err.Error()))
	}
	sData.hostKey = makePrivateKey(keyBytes)
	// 监听
	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	network := "tcp4"
	listen, err := net.Listen(network, address)
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer listen.Close()
	logger.Log.Infoln(baseOptions.Application, " listen on ", address)

	connChan := common.ForwardListenerToChan(listen)

	// 配置ServerConfig
	var config *ssh.ServerConfig

	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case conn := <-connChan:
			// remoteIP := conn.RemoteAddr().String()
			// if !service.Limiter.Pass(conn) {
			// 	logger.Log.Warnln("触发访问速率限制", service.BaseOptions.Application, remoteIP)
			// 	conn.Close()
			// 	continue
			// }
			//handle := service.Handle.(*SSHHandle)
			id := xid.New()
			if serviceOptions.MaxAuthTries == 0 {
				serviceOptions.MaxAuthTries = 3
				logger.Log.Warnln("MaxAuthTries is 0, set to 3")
			}

			config = simulatorConfig(&serviceOptions, id, sData)
			config.AddHostKey(sData.hostKey)
			go handleServiceConn(conn, config, id, service, sData)

		}
	}
}

func simulatorConfig(cfg *sshConfig, sessionID xid.ID, sdata sshData) *ssh.ServerConfig {
	config := ssh.ServerConfig{
		ServerVersion: cfg.Version,
		MaxAuthTries:  cfg.MaxAuthTries,
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			srcAddr, err := common.GetSSHConnSrcIPAndSrcPort(&conn)
			if err != nil {
				logger.Log.Error(err)
			}
			dstAddr, err := common.GetSSHConnDstIPAndDstPort(&conn)
			if err != nil {
				logger.Log.Error(err)
			}
			e := event.Event{
				Timestamp:     time.Now().Format(time.DateTime),
				EventCategory: serviceName,
				EventType:     "ssh-publickey-authentication",
				SrcIP:         srcAddr.IP,
				DstIP:         dstAddr.IP,
				IPProtocol:    "tcp",
				SrcPort:       srcAddr.Port,
				DstPort:       dstAddr.Port,
				Details: map[string]interface{}{
					"protocol":           serviceName,
					"ssh.publickey-type": key.Type(),
					"ssh.publickey":      hex.EncodeToString(key.Marshal()),
					"ssh.session-id":     sessionID.String(),
				},
			}

			event.EventPush(&e)

			return nil, errors.New("unknown key")
		},
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			srcAddr, err := common.GetSSHConnSrcIPAndSrcPort(&conn)
			if err != nil {
				logger.Log.Error(err)
			}
			dstAddr, err := common.GetSSHConnDstIPAndDstPort(&conn)
			if err != nil {
				logger.Log.Error(err)
			}
			e := event.Event{
				Timestamp:     time.Now().Format(time.DateTime),
				EventCategory: serviceName,
				EventType:     "ssh-password-authentication",
				SrcIP:         srcAddr.IP,
				DstIP:         dstAddr.IP,
				IPProtocol:    "tcp",
				SrcPort:       srcAddr.Port,
				DstPort:       dstAddr.Port,
				Details: map[string]interface{}{
					"protocol":       serviceName,
					"ssh.username":   conn.User(),
					"ssh.password":   string(password),
					"ssh.session-id": sessionID.String(),
				},
			}
			event.EventPush(&e)
			for _, account := range cfg.Accounts {
				if account.Username == "*" {
					// 如果配置了通配符的用户名，就什么账户都能登录
					sdata.metadata[sessionID.String()] = account.Username
					return nil, nil
				}

				if conn.User() == account.Username && string(password) == account.Password {
					sdata.metadata[sessionID.String()] = account.Username
					logger.Log.Debugf("ssh user authenticated successfully. user=%s password=%s", conn.User(), string(password))
					return nil, nil
				}
			}

			return nil, fmt.Errorf("password rejected for %q", conn.User())
		},
	}
	return &config
}

func handleServiceConn(conn net.Conn, config *ssh.ServerConfig, sessionID xid.ID, service *services.Service, sdata sshData) {
	defer conn.Close()
	cfg := service.ServiceOptions.(sshConfig)
	srcAddr, err := common.GetConnSrcIPAndSrcPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}
	dstAddr, err := common.GetConnDstIPAndDstPort(&conn)
	if err != nil {
		logger.Log.Error(err)
	}
	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err == io.EOF {
		// server closed connection
		return
	} else if err != nil {
		e := event.Event{
			Timestamp:     time.Now().Format(time.DateTime),
			EventCategory: serviceName,
			EventType:     "ssh-connect-failed",
			SrcIP:         srcAddr.IP,
			DstIP:         dstAddr.IP,
			IPProtocol:    "tcp",
			SrcPort:       srcAddr.Port,
			DstPort:       dstAddr.Port,
			Details: map[string]interface{}{
				"protocol":       serviceName,
				"error":          err.Error(),
				"ssh.session-id": sessionID.String(),
			},
		}
		event.EventPush(&e)
	}

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		// 连接ssh成功之后，建立的channel，处理收到的请求
		switch newChannel.ChannelType() {
		case "session":
			// 此处是最常用的shell，可以进行下一步
		case "forwarded-tcpip":
			decoder := PayloadDecoder(newChannel.ExtraData())
			e := event.Event{
				Timestamp:     time.Now().Format(time.DateTime),
				EventCategory: serviceName,
				EventType:     "ssh-channel",
				SrcIP:         srcAddr.IP,
				DstIP:         dstAddr.IP,
				IPProtocol:    "tcp",
				SrcPort:       srcAddr.Port,
				DstPort:       dstAddr.Port,
				Details: map[string]interface{}{
					"protocol":         serviceName,
					"ssh.session-id":   sessionID.String(),
					"ssh.channel-type": newChannel.ChannelType(),
					"ssh.forwarded-tcpip.address-that-was-connected": decoder.String(),
					"ssh.forwarded-tcpip.port-that-was-connected":    fmt.Sprintf("%d", decoder.Uint32()),
					"ssh.forwarded-tcpip.originator-host":            decoder.String(),
					"ssh.forwarded-tcpip.originator-port":            fmt.Sprintf("%d", decoder.Uint32()),
					"payload":                                        newChannel.ExtraData(),
				},
			}
			event.EventPush(&e)

			newChannel.Reject(ssh.UnknownChannelType, "not allowed")
			continue
		case "direct-tcpip":
			decoder := PayloadDecoder(newChannel.ExtraData())

			e := event.Event{
				Timestamp:     time.Now().Format(time.DateTime),
				EventCategory: serviceName,
				EventType:     "ssh-channel",
				SrcIP:         srcAddr.IP,
				DstIP:         dstAddr.IP,
				IPProtocol:    "tcp",
				SrcPort:       srcAddr.Port,
				DstPort:       dstAddr.Port,
				Details: map[string]interface{}{
					"protocol":                         serviceName,
					"ssh.session-id":                   sessionID.String(),
					"ssh.channel-type":                 newChannel.ChannelType(),
					"ssh.direct-tcpip.host-to-connect": decoder.String(),
					"ssh.direct-tcpip.port-to-connect": fmt.Sprintf("%d", decoder.Uint32()),
					"ssh.direct-tcpip.originator-host": decoder.String(),
					"ssh.direct-tcpip.originator-port": fmt.Sprintf("%d", decoder.Uint32()),
					"payload":                          newChannel.ExtraData(),
				},
			}
			event.EventPush(&e)

			newChannel.Reject(ssh.UnknownChannelType, "not allowed")
			continue
		default:
			e := event.Event{
				Timestamp:     time.Now().Format(time.DateTime),
				EventCategory: serviceName,
				EventType:     "ssh-channel",
				SrcIP:         srcAddr.IP,
				DstIP:         dstAddr.IP,
				IPProtocol:    "tcp",
				SrcPort:       srcAddr.Port,
				DstPort:       dstAddr.Port,
				Details: map[string]interface{}{
					"protocol":         serviceName,
					"ssh.sessionid":    sessionID.String(),
					"ssh.channel-type": newChannel.ChannelType(),
					"payload":          newChannel.ExtraData(),
				}}
			event.EventPush(&e)

			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			logger.Log.Debugf("Unknown channel type: %s\n", newChannel.ChannelType())
			continue
		}

		// channel应答	requests请求
		channel, requests, err := newChannel.Accept()
		if err == io.EOF {
			continue
		} else if err != nil {
			logger.Log.Errorf("Could not accept server channel: %s", err.Error())
			continue
		}

		func() {
			// 接收请求
			for req := range requests {
				// logger.Log.Debugf("Request: %s %s %s %s\n", channel, req.Type, req.WantReply, req.Payload)

				e := event.Event{
					Timestamp:     time.Now().Format(time.DateTime),
					EventCategory: serviceName,
					EventType:     "ssh-request",
					SrcIP:         srcAddr.IP,
					DstIP:         dstAddr.IP,
					IPProtocol:    "tcp",
					SrcPort:       srcAddr.Port,
					DstPort:       dstAddr.Port,
					Details: map[string]interface{}{
						"protocol":         serviceName,
						"ssh.sessionid":    sessionID.String(),
						"ssh.request-type": req.Type,
						"payload":          req.Payload,
					}}

				needResponse := false

				payloads := []string{}
				switch req.Type {
				case "shell":
					needResponse = true
				case "pty-req":
					needResponse = true
					event.EventPush(&e)
				case "env":
					needResponse = true
					decoder := PayloadDecoder(req.Payload)
					for {
						if decoder.Available() == 0 {
							break
						}
						payload := decoder.String()
						payloads = append(payloads, payload)
					}

					e.Details["ssh.env"] = payloads
					event.EventPush(&e)
				case "tcpip-forward":
					decoder := PayloadDecoder(req.Payload)

					e.Details["ssh.tcpip-forward.address-to-bind"] = decoder.String()
					e.Details["ssh.tcpip-forward.port-to-bind"] = fmt.Sprintf("%d", decoder.Uint32())

					event.EventPush(&e)
				case "exec":
					needResponse = true
					decoder := PayloadDecoder(req.Payload)

					for {
						if decoder.Available() == 0 {
							break
						}
						payload := decoder.String()
						payloads = append(payloads, payload)
					}
					e.Details["ssh.exec"] = payloads
				case "subsystem":
					needResponse = true
					decoder := PayloadDecoder(req.Payload)
					e.Details["ssh.subsystem"] = decoder.String()
					event.EventPush(&e)
				default:
					logger.Log.Errorf("Unsupported request type=%s payload=%s", req.Type, string(req.Payload))
					event.EventPush(&e)
				}

				if needResponse {
					// 应答请求
					if err := req.Reply(needResponse, nil); err != nil {
						logger.Log.Errorf("wantreply: %v", err)
					}
				}

				// 响应shell、exec
				func() {
					if req.Type == "shell" {
						defer channel.Close()

						twrc := NewTypeWriterReadCloser(channel)
						var wrappedChannel io.ReadWriteCloser = twrc
						//取出存储的username
						username := sdata.metadata[sessionID.String()]
						prompt := fmt.Sprintf("%v@%v:~$ ", username, cfg.Hostname)

						term := term.NewTerminal(wrappedChannel, prompt)
						motd := []byte("Last login: Wed Sep 14 14:11:49 2024 from 172.31.60.24\n")
						if len(cfg.Motd) > 0 {
							motd = []byte(cfg.Motd)
						}
						term.Write([]byte(motd))

						for {
							line, err := term.ReadLine()
							if err == io.EOF {
								return
							} else if err != nil {
								logger.Log.Errorf("Error reading from connection: %s", err.Error())
								return
							}

							if line == "exit" {
								channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								return
							}

							if line == "" {
								continue
							}

							e := event.Event{
								Timestamp:     time.Now().Format(time.DateTime),
								EventCategory: serviceName,
								EventType:     "ssh-shell",
								SrcIP:         srcAddr.IP,
								DstIP:         dstAddr.IP,
								IPProtocol:    "tcp",
								SrcPort:       srcAddr.Port,
								DstPort:       dstAddr.Port,
								Details: map[string]interface{}{
									"protocol":      serviceName,
									"ssh.sessionid": sessionID.String(),
									"ssh.shell":     line,
								}}
							event.EventPush(&e)

							if v, ok := cfg.Simulator[line]; ok {
								term.Write([]byte(v))
								continue
							}
							term.Write([]byte(fmt.Sprintf("-bash: %v: command not found\n", GetFirstCommandLineArgument(line))))
						}
					} else if req.Type == "exec" {
						defer channel.Close()
						channel.Write([]byte(fmt.Sprintf("-bash: %v: command not found\n", payloads[0])))
						channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})

						e := event.Event{
							Timestamp:     time.Now().Format(time.DateTime),
							EventCategory: serviceName,
							SrcIP:         srcAddr.IP,
							DstIP:         dstAddr.IP,
							IPProtocol:    "tcp",
							SrcPort:       srcAddr.Port,
							DstPort:       dstAddr.Port,
							Details: map[string]interface{}{
								"protocol":      serviceName,
								"ssh.sessionid": sessionID.String(),
								"ssh.exec":      payloads,
							}}
						event.EventPush(&e)
						return
					} else {
						return
					}
				}()
			}
		}()
	}

}

type payloadDecoder struct {
	decoder.Decoder
}

// 报文格式为 内容的长度+内容
func (pd *payloadDecoder) String() string {
	length := int(pd.Uint32())
	payload := pd.Copy(length)
	return string(payload)
}

func PayloadDecoder(payload []byte) *payloadDecoder {
	return &payloadDecoder{
		decoder.NewDecoder(payload),
	}
}

// 切割命令行
func SplitCommandLine(cmd string) []string {
	cmd = strings.ReplaceAll(cmd, "\\\\", "\\")
	res := strings.Split(cmd, " ")
	if len(res) == 0 {
		return []string{}
	} else {
		return res
	}
}

// 获取第一个命令行参数
func GetFirstCommandLineArgument(cmd string) string {
	res := SplitCommandLine(cmd)
	if len(res) == 0 {
		return ""
	} else {
		return res[0]
	}
}
