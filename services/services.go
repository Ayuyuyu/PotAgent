package services

import (
	"context"
	"fmt"
	"potAgent/global"
)

// 服务的代码组织结构
type Service struct {
	Running        bool
	WorkerHandle   func(context.Context, *Service)
	ServiceOptions interface{}
	BaseOptions    global.ServiceBaseConfig // 服务的基础配置，比如 enable、application
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
