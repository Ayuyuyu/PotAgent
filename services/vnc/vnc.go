package vnc

/*
VNC 蜜罐服务（TCP 5900/5901，RFB 3.3 / 3.7 / 3.8）。

低交互策略：
  - 服务端主动发 RFB 003.008 并校验客户端版本；RFB>=3.7 只通告一种安全类型 1（None）
    且客户端必须选 1，否则断开；3.8 回 SecurityResult OK。
  - ServerInit 固定 16bpp true-colour，宽高取自加载的 PNG；命令循环处理
    SetPixelFormat/SetEncodings/FramebufferUpdateRequest/PointerEvent/KeyEvent，
    其余命令直接断开；桌面帧按 30fps 从 PNG 推 FramebufferUpdate（Raw/CopyRect）。
  - 无认证——只支持 authNone，永远"成功"（与真实 VNC 的 VNC Auth 最大差异，
    目的是让攻击工具直接进入以捕获键鼠）。
  - 不支持的客户端命令/安全类型直接断开。
  - 事件目前只有 vnc-connect（protocol/application）；键鼠输入尚未落盘。
*/

import (
	"context"
	"fmt"
	"image/png"
	"path/filepath"
	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"

	"net"
	"os"
	"time"
)

var (
	serviceName = "vnc"
	_           = services.Register(serviceName, VNCServiceInit)
)

func VNCServiceInit() services.Service {
	s := services.Service{
		WorkerHandle:   vncHandle,
		ServiceOptions: vncConfig{},
	}

	return s
}

type vncConfig struct {
	Version   string `mapstructure:"version"`
	ImagePath string `mapstructure:"img_path"`
	li        *LockableImage
}

func vncHandle(ctx context.Context, service *services.Service) {
	var (
		serviceOptions = service.ServiceOptions.(vncConfig)
		baseOptions    = service.BaseOptions
	)
	if pwd, err := os.Getwd(); err != nil {
	} else if !filepath.IsAbs(serviceOptions.ImagePath) {
		serviceOptions.ImagePath = filepath.Join(pwd, serviceOptions.ImagePath)
	}
	logger.Log.Infoln("加载图像: ", serviceOptions.ImagePath)
	r, err := os.Open(serviceOptions.ImagePath)
	if err != nil {
		logger.Log.Fatalf("无法打开图像: %s", serviceOptions.ImagePath)
	}
	defer r.Close()

	im, err := png.Decode(r)
	if err != nil {
		logger.Log.Fatalf("无法解码图像: %s", serviceOptions.ImagePath)
	}

	serviceOptions.li = &LockableImage{
		Img: im,
	}
	service.ServiceOptions = serviceOptions
	// 监听
	address := fmt.Sprintf("%v:%v", baseOptions.Host, baseOptions.Port)
	network := "tcp4"
	listen, err := net.Listen(network, address)
	if err != nil {
		logger.Log.Fatalln(err)
	}
	defer listen.Close()
	logger.Log.Infoln(baseOptions.Application, "listen on ", address)
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

	cfg := service.ServiceOptions.(vncConfig)
	bounds := cfg.li.Img.Bounds()
	c := newConn(bounds.Dx(), bounds.Dy(), *conn)
	c.serverName = cfg.Version
	go c.serve()
	srcAddr, err := common.GetConnSrcIPAndSrcPort(conn)
	if err != nil {
		logger.Log.Error(err)
	}
	dstAddr, err := common.GetConnDstIPAndDstPort(conn)
	if err != nil {
		logger.Log.Error(err)
	}

	event.EventPush(event.NewEvent(serviceName, "vnc-connect", srcAddr, dstAddr, map[string]interface{}{
		"protocol":    service.BaseOptions.Protocol,
		"application": service.BaseOptions.Application,
	}))

	closec := make(chan bool)
	go func() {
		slide := 0
		tick := time.NewTicker(time.Second / 30)
		defer tick.Stop()

		haveNewFrame := false
		for {
			feed := c.Feed
			if !haveNewFrame {
				feed = nil
			}
			_ = feed
			select {
			case feed <- cfg.li:
				haveNewFrame = false
			case <-closec:
				return
			case <-tick.C:
				slide++

				haveNewFrame = true
			}
		}
	}()

	for e := range c.Event {
		_ = e
		/*
			s.c.Send(event.New(
				EventOptions,
				event.Category("vnc"),
				event.Type("vnc-event"),
				event.SourceAddr(conn.RemoteAddr()),
				event.DestinationAddr(conn.LocalAddr()),
				event.Payload(e)
			))
		*/
	}

	close(closec)
}
