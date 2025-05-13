package http

/*
HTTP 服务自定义响应处理
*/
import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"
	"time"
)

var (
	serviceName = "http"
	_           = services.Register(serviceName, HTTPServiceInit)
)

func HTTPServiceInit() services.Service {
	s := services.Service{
		WorkerHandle:   httpHandle,
		ServiceOptions: httpConfig{},
	}
	return s
}

type response struct {
	Type  string
	Value string
}

type request_simulator struct {
	URI      string   `mapstructure:"uri"`
	Metchod  string   `mapstructure:"method"`
	Response response `mapstructure:"response"`
}

type httpConfig struct {
	Index            string              `mapstructure:"index"`
	AssetDir         string              `mapstructure:"assets_dir"`
	RequestSimulator []request_simulator `mapstructure:"request_simulator"`
}

func httpHandle(ctx context.Context, service *services.Service) {
	var (
		serviceOptions = service.ServiceOptions.(httpConfig)
		baseOptions    = service.BaseOptions
	)
	logger.Log.Infoln(serviceOptions, baseOptions)
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
	// 解析HTTP请求内容
	br := bufio.NewReader(*conn)
	req, err := http.ReadRequest(br)
	if err == io.EOF {
		logger.Log.Warning(err)
		return
	} else if err != nil {
		logger.Log.Warning(err)
		return
	}
	defer req.Body.Close()
	body := make([]byte, 1024)
	// 读取请求体
	n, err := req.Body.Read(body)
	if err == io.EOF {
	} else if err != nil {
		return
	}

	body = body[:n]

	//io.Copy(io.Discard, req.Body)
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
		EventType:     "http-access",
		SrcIP:         srcAddr.IP,
		DstIP:         dstAddr.IP,
		IPProtocol:    "tcp",
		SrcPort:       srcAddr.Port,
		DstPort:       dstAddr.Port,
		Details: map[string]interface{}{
			"protocol":             service.BaseOptions.Protocol,
			"application":          service.BaseOptions.Application,
			"http.method":          req.Method,
			"http.host":            req.Host,
			"http.url":             req.URL.String(),
			"http.request_headers": req.Header,
			"http.request_body":    body,
		},
	}
	event.EventPush(&e)
	// 构造HTTP响应内容
	resp := http.Response{
		StatusCode: http.StatusOK,
		Status:     http.StatusText(http.StatusOK),
		Proto:      req.Proto,
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
		Request:    req,
		Header:     http.Header{},
	}

	//优先进行资源配置处判断
	if resource, err := requestFromYamlCheck(req.URL.Path, service); err == nil {
		resp.Header.Add("content-type", resource.ContentType)
		resp.Header.Add("content-length", fmt.Sprintf("%d", len(resource.Data)))
		resp.Body = io.NopCloser(bytes.NewReader(resource.Data))
		logger.Log.Debug("requestFromYamlCheck req.URL.Path:", req.URL.Path)
		// 在资源文件中获取，有就返回，没有就404
	} else if resource, err := httpAssetsRead(req.URL.Path, service); req.Method == "GET" && err == nil {
		resp.Header.Add("content-type", resource.ContentType)
		resp.Header.Add("content-length", fmt.Sprintf("%d", len(resource.Data)))
		resp.Body = io.NopCloser(bytes.NewReader(resource.Data))
		logger.Log.Debug("httpAssetsRead req.URL.Path:", req.URL.Path)
	} else {
		resp.StatusCode = http.StatusNotFound
		resp.Status = http.StatusText(http.StatusNotFound)
		logger.Log.Debug("Requreq.URL.PathestURI(404):", req.URL.Path)
	}

	if err := resp.Write(*conn); err != nil {
		logger.Log.Warning(err)
	}
}
