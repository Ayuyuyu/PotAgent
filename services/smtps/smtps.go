package smtps

/*
SMTPS 蜜罐服务（TCP 465，RFC 8314 隐式 TLS / 连接即 SSL/TLS）。

与 smtp（端口 25/587，明文 + STARTTLS）的区别仅在传输层：
  - 本服务在连接建立时立即以 tls.Server 包裹，完成 TLS 握手后才发送 220 欢迎语；
  - 之后复用 smtp.Serve 跑同一套命令循环（MAIL/RCPT/DATA/AUTH…），不再响应 STARTTLS。
  - 证书优先取 cert_file/key_file，未配置则自动生成自签 RSA2048（每次连接）。
*/

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"potAgent/common"
	"potAgent/logger"
	"potAgent/services"
	"potAgent/services/smtp"
)

var (
	serviceName = "smtps"
	_           = services.Register(serviceName, SmtpsServiceInit)
)

// smtpsConfig 与 smtp.TLSConfig 同一类型（别名），共享 banner + 证书配置。
type smtpsConfig = smtp.TLSConfig

func SmtpsServiceInit() services.Service {
	return services.Service{
		WorkerHandle:   smtpsHandle,
		ServiceOptions: smtpsConfig{},
	}
}

func smtpsHandle(ctx context.Context, service *services.Service) {
	baseOptions := service.BaseOptions
	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	listen, err := net.Listen("tcp4", address)
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer listen.Close()
	logger.Log.Info(baseOptions.Application, " listen on ", address)

	connChan := common.ForwardListenerToChan(listen)
	for {
		select {
		case <-ctx.Done():
			logger.Log.Infof("%s service close", serviceName)
			return
		case conn := <-connChan:
			go func(c net.Conn) {
				defer c.Close()
				cfg := service.ServiceOptions.(smtpsConfig)
				banner := cfg.Banner
				if banner == "" {
					banner = smtp.DefaultBanner
				}
				host := smtp.GreetingHost(banner)
				cert, cerr := common.LoadOrGenCert(cfg.CertFile, cfg.KeyFile, host)
				if cerr != nil {
					logger.Log.Error(serviceName, " load cert error:", cerr)
					return
				}
				tlsConn := tls.Server(c, &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				})
				if herr := tlsConn.Handshake(); herr != nil {
					logger.Log.Debug(serviceName, " handshake error:", herr)
					return
				}
				// 握手成功后复用 smtp 命令循环（已处于 TLS，不再响应 STARTTLS）
				smtp.Serve(tlsConn, service, serviceName, false)
			}(conn)
		}
	}
}
