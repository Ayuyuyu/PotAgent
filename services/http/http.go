package http

/*
HTTP 服务自定义响应处理
*/
import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"potAgent/common"
	"potAgent/event"
	"potAgent/logger"
	"potAgent/services"
)

var (
	serviceName = "http"
	// http 与 https 复用同一套请求处理逻辑，是否走 TLS 由配置里的 tls 块驱动
	_ = services.Register(serviceName, HTTPServiceInit)
	_ = services.Register("https", HTTPServiceInit)
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

// tlsConfig 可选的 TLS(HTTPS) 配置，配置 cert_file 后该实例以 TLS 方式响应
type tlsConfig struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type httpConfig struct {
	Index            string              `mapstructure:"index"`
	AssetDir         string              `mapstructure:"assets_dir"`
	RequestSimulator []request_simulator `mapstructure:"request_simulator"`
	Tls              tlsConfig           `mapstructure:"tls"`
}

func httpHandle(ctx context.Context, service *services.Service) {
	var (
		serviceOptions = service.ServiceOptions.(httpConfig)
		baseOptions    = service.BaseOptions
	)
	logger.Log.Debugln(serviceOptions, baseOptions)

	// 可选 TLS(HTTPS)：配置了 cert_file 则以 TLS 方式握手，证书只加载一次
	var tlsConf *tls.Config
	if serviceOptions.Tls.CertFile != "" {
		certFile := resolvePathRelativeToCwd(serviceOptions.Tls.CertFile)
		keyFile := resolvePathRelativeToCwd(serviceOptions.Tls.KeyFile)
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			logger.Log.Fatalf("加载 TLS 证书失败: %v", err)
		}
		tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

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
			go handleServiceConn(&conn, service, tlsConf)
		}
	}
}

// resolvePathRelativeToCwd 相对路径按当前工作目录解析（与 httpAssetsRead 一致）
func resolvePathRelativeToCwd(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	if pwd, err := os.Getwd(); err == nil {
		return filepath.Join(pwd, p)
	}
	return p
}

func handleServiceConn(conn *net.Conn, service *services.Service, tlsConf *tls.Config) {
	defer (*conn).Close()

	// 配置了 TLS 则先作为服务端握手，后续读写都走 TLS 连接
	if tlsConf != nil {
		tlsConn := tls.Server(*conn, tlsConf)
		if err := tlsConn.Handshake(); err != nil {
			logger.Log.Warning("tls handshake failed:", err)
			return
		}
		c := net.Conn(tlsConn)
		conn = &c
	}

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

	event.EventPush(event.NewEvent(serviceName, "http-access", srcAddr, dstAddr, map[string]interface{}{
		"protocol":             service.BaseOptions.Protocol,
		"application":          service.BaseOptions.Application,
		"http.method":          req.Method,
		"http.host":            req.Host,
		"http.url":             req.URL.String(),
		"http.request_headers": req.Header,
		"http.request_body":    body,
	}))
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
