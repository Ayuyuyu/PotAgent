package imp

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"potAgent/common"
	"potAgent/config"
	"potAgent/event"
	"potAgent/global"
	"potAgent/logger"
	"potAgent/services"
	"strings"
	"syscall"
)

// InitServicesRun 初始化并启动全部（或指定）服务。
// protocolFilter 为空时启动 services_dir 下所有 enable 的服务；非空时只启动
// 逗号分隔列表中存在的协议（按服务 yaml 的 protocol 字段匹配）。
func InitServicesRun(confPath string, protocolFilter string) error {
	vip, err := config.YamlConfigHandle(confPath)
	if err != nil {
		logger.Log.Fatalln("初始化服务失败", err.Error())
	}
	gOption := global.Options{}
	config.ReadConfigFile(vip, &gOption)
	// 应用配置文件里的日志等级（留空则不覆盖编译期/默认设定）
	if gOption.LogLevel != "" {
		logger.InitLog(gOption.LogLevel)
	}
	logger.Log.Println("开始初始化服务")
	// 按需解压服务资源包 (services_dir/assets.zip -> services_dir/assets)，仅当资源目录缺失时
	if err := common.EnsureAssets(gOption.ServicesDir); err != nil {
		logger.Log.Errorf("解压资源包失败: %v", err)
	}
	//res, err := fileutil.ReadFileToString(common.InsertRootDirIfNotAbsolutePath(gOption.ServicesDir))

	//logger.Log.Info(gOption.ServicesDir, r)
	//pwd, _ := os.Getwd()
	//yamlFiles, err := common.FindConfigFile(filepath.Join(pwd, filepath.Base(gOption.ServicesDir))) // DEBUG
	yamlFiles, err := common.FindConfigFile(gOption.ServicesDir) //RELEASE
	if err != nil {
		logger.Log.Fatalln("读取服务目录失败", err.Error())
		return err
	} else {
		logger.Log.Println("读取服务目录成功", yamlFiles)
	}
	if len(yamlFiles) == 0 {
		logger.Log.Fatalln(gOption.ServicesDir, "没有找到服务")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	//事件记录初始化
	eventInit(&gOption)
	// 启动前按 --protocol 过滤
	allowed := splitProtocols(protocolFilter)
	started := make([]string, 0, len(yamlFiles))

	//开启服务
	for _, yamlService := range yamlFiles {
		logger.Log.Debugln("service yaml file:", yamlService)
		baseOptions := global.ServiceBaseConfig{}
		vipService, err := config.YamlConfigHandle(yamlService)
		if err != nil {
			logger.Log.Errorf("%s 初始化服务失败 %v", yamlService, err.Error())
			continue
		}
		err = config.ReadConfigFile(vipService, &baseOptions)
		if err != nil {
			return err
		}
		// 协议过滤：指定了协议列表则只启动命中的（不逐个打印跳过，末尾统一汇总）
		if len(allowed) > 0 && !contains(allowed, strings.ToLower(baseOptions.Protocol)) {
			continue
		}
		funcServiceHandle, err := services.Get(baseOptions.Protocol)
		if err != nil {
			logger.Log.Warn(err)
			return err
		}
		if !baseOptions.Enable {
			logger.Log.Infof("%v disable", baseOptions.Application)
			continue
		}

		//load service config
		serviceApp := funcServiceHandle()
		serviceApp.BaseOptions = baseOptions
		err = config.ReadConfigFile(vipService, &serviceApp.ServiceOptions)
		if err != nil {
			return err
		}
		//logger.Log.Info(serviceApp)
		Start(ctx, &serviceApp)
		started = append(started, baseOptions.Application)
	}

	// 汇总实际启动的服务（不逐个打印跳过）
	if len(started) == 0 {
		logger.Log.Warnf("未启动任何服务（--protocol=%q 无匹配或服务目录为空）", protocolFilter)
	} else {
		logger.Log.Infof("已启动服务: %s", strings.Join(started, ", "))
	}

	// 整体 等待退出
	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt)
	signal.Notify(s, syscall.SIGTERM)

	// 替换 select 为直接的通道接收
	<-s
	cancel()
	logger.Log.Println("服务退出")
	return nil
}

func Start(ctx context.Context, service *services.Service) error {
	if !service.Running {
		service.Running = true
		go service.WorkerHandle(ctx, service)
	} else {
		return fmt.Errorf("worker already start")
	}
	return nil
}

// 暂未使用！
func Stop(service *services.Service) error {
	if service.Running {
		//close(service.StopChan)
	} else {
		return fmt.Errorf("worker not running")
	}
	return nil
}

// 事件输出初始化
func eventInit(opt *global.Options) {
	if err := event.EventInit(opt); err != nil {
		logger.Log.Error(err)
	}
}

// splitProtocols 把逗号分隔的协议列表拆成去空白、转小写的切片；空串返回 nil。
func splitProtocols(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// contains 判断切片是否包含目标字符串。
func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
