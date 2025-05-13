package http

import (
	"errors"
	"math/rand"
	"os"
	"potAgent/logger"
	"potAgent/services"
	"time"

	"net/http"
	"path/filepath"
	"strings"

	"github.com/duke-git/lancet/v2/fileutil"
)

var fileHeaders = map[string][]byte{
	".exe":  {0x4D, 0x5A}, // MZ
	".dll":  {0x4D, 0x5A}, // MZ
	".png":  {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
	".jpg":  {0xFF, 0xD8, 0xFF, 0xE0},
	".jpeg": {0xFF, 0xD8, 0xFF, 0xE0},
	".gif":  {0x47, 0x49, 0x46, 0x38, 0x39, 0x61}, // GIF89a
	".pdf":  {0x25, 0x50, 0x44, 0x46},             // %PDF
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

type HTTPResponseData struct {
	Data        []byte
	ContentType string
}

// 把文件写到结构体
// 同时解析文件的MIME类型
func loadFile(path string) HTTPResponseData {
	buf, err := os.ReadFile(path)
	if err != nil {
		logger.Log.Error(err)
		return HTTPResponseData{}
	}

	respData := HTTPResponseData{
		Data:        buf,
		ContentType: http.DetectContentType(buf),
	}
	// 部分没法通过mime正确解析，用后缀来判断
	if strings.HasSuffix(path, ".js") {
		respData.ContentType = "application/javascript"
	} else if strings.HasSuffix(path, ".css") {
		respData.ContentType = "text/css"
	} else if strings.HasSuffix(path, ".html") {
		respData.ContentType = "text/html; charset=utf-8"
	} else if strings.HasSuffix(path, ".svg") {
		respData.ContentType = "image/svg+xml"
	} else if strings.HasSuffix(path, "i18n.jsp") {
		respData.ContentType = "text/x-json;charset=UTF-8"
	}

	return respData
}

// TODO 增加读取文件cache
func httpAssetsRead(url string, service *services.Service) (*HTTPResponseData, error) {
	serviceOption := service.ServiceOptions.(httpConfig)
	dirPath := serviceOption.AssetDir
	if pwd, err := os.Getwd(); err != nil {
	} else if !filepath.IsAbs(dirPath) {
		dirPath = filepath.Join(pwd, dirPath)
	}
	var assetPath string
	if url == "/" {
		assetPath = filepath.Join(dirPath, serviceOption.Index)
	} else {
		assetPath = filepath.Join(dirPath, url)
	}
	// subPrefix := strings.ReplaceAll(p, dirPath, "")
	// uri := filepath.Join("/", subPrefix)
	// // windows下路径斜杠转为反斜杠
	// if runtime.GOOS == "windows" {
	// 	uri = strings.ReplaceAll(uri, "\\", "/")
	// }

	logger.Log.Debugln("find resource", url, assetPath)
	respData := loadFile(assetPath)
	if respData.Data == nil {
		return nil, errors.New("file not found")
	}
	return &respData, nil
}

// 处理配置好的URL的请求
func requestFromYamlCheck(url string, service *services.Service) (*HTTPResponseData, error) {
	serviceOptions := service.ServiceOptions.(httpConfig)
	respData := HTTPResponseData{}
	for _, v := range serviceOptions.RequestSimulator {
		if v.URI == url {
			if v.Response.Type == "file" {
				filePath := v.Response.Value
				//文件不存在或者为空
				if len(filePath) == 0 || !fileutil.IsExist(filePath) {
					//随机生成一个小文件
					data, res := generateFakeFileContent(url)
					if !res {
						return nil, errors.New("file generage failed")
					}
					respData.Data = data
					respData.ContentType = "application/octet-stream"
					return &respData, nil
				}
				//文件存在就进行读取
				if pwd, err := os.Getwd(); err != nil {
				} else if !filepath.IsAbs(filePath) {
					filePath = filepath.Join(pwd, filePath)
				}
				respData = loadFile(filePath)
				if respData.Data == nil {
					return nil, errors.New("file not found")
				}
			}
			if v.Response.Type == "json" {
				respData.ContentType = "application/json; charset=utf-8"
				respData.Data = []byte(v.Response.Value)
			}
			if v.Response.Type == "string" {
				respData.ContentType = "text/html; charset=utf-8"
				respData.Data = []byte(v.Response.Value)
			}

		}
	}
	if respData.Data == nil {
		return nil, errors.New("resource not found")
	}
	return &respData, nil
}

func randStringBytes(n int) []byte {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return b
}

func generateFakeFileContent(url string) ([]byte, bool) {
	ext := filepath.Ext(url)
	header, ok := fileHeaders[ext]
	if !ok {
		logger.Log.Warn("不支持的文件类型")
		return nil, false
	}

	// 构造伪造的完整内容
	content := append(header, randStringBytes(1024)...) // 魔数 + 1KB 随机内容
	return content, true
}
