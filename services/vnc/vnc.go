package vnc

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

	e := event.Event{
		Timestamp:     time.Now().Format(time.DateTime),
		EventCategory: serviceName,
		EventType:     "vnc-connect",
		SrcIP:         srcAddr.IP,
		DstIP:         dstAddr.IP,
		IPProtocol:    "tcp",
		SrcPort:       srcAddr.Port,
		DstPort:       dstAddr.Port,
		Details: map[string]interface{}{
			"protocol":    service.BaseOptions.Protocol,
			"application": service.BaseOptions.Application,
		},
	}
	event.EventPush(&e)

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
