package services

import (
	"context"
	"fmt"
	"potAgent/global"
	"potAgent/logger"
)

// 服务的代码组织结构
type Service struct {
	Running        bool
	WorkerHandle   func(context.Context, *Service)
	ServiceOptions interface{}
	BaseOptions    global.ServiceBaseConfig // 服务的基础配置，比如 enable、application

	// OnError 由管理端（manager）注入：服务在监听失败等启动期错误时调用它，
	// 而不是 Fatalln 直接退出进程，这样热加载时单个实例失败不会带走整个进程。
	// 保持为函数字段（而非锁），Service 仍是可复制的值类型。
	OnError func(error)

	// OnReady 由管理端（manager）注入：服务在 Listen 成功后调用一次，
	// 让 manager 能区分"协程已拉起"和"端口真的在监听"。
	// 同样保持为函数字段，Service 仍是可复制的值类型。
	OnReady func()
}

// MarkReady 由各协议在 Listen 成功后调用；未注入回调时是空操作（例如单测直接起服务）。
func (s *Service) MarkReady() {
	if s.OnReady != nil {
		s.OnReady()
	}
}

// ReportError 上报启动期错误：已注入 OnError 时交给管理端记录，否则仅打印日志。
func (s *Service) ReportError(err error) {
	if err == nil {
		return
	}

	if s.OnError != nil {
		s.OnError(err)

		return
	}

	logger.Log.Errorln(err)
}

type FuncServiceInit func() Service

var mapServicesFunc map[string]FuncServiceInit

func init() {
	mapServicesFunc = make(map[string]FuncServiceInit)
}

func Register(serviceKey string, fn FuncServiceInit) error {
	if _, ok := mapServicesFunc[serviceKey]; ok {
		return fmt.Errorf("key already registed, serviceKey: %v", serviceKey)
	} else {
		mapServicesFunc[serviceKey] = fn
		return nil
	}
}

func Get(serviceKey string) (FuncServiceInit, error) {
	if s, ok := mapServicesFunc[serviceKey]; ok {
		return s, nil
	} else {
		return nil, fmt.Errorf("service not found %s", serviceKey)
	}
}
