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
	"syscall"
)

func InitServicesRun(confPath string) error {
	logger.Log.Println("开始初始化服务")
	vip, err := config.YamlConfigHandle(confPath)
	if err != nil {
		logger.Log.Fatalln("初始化服务失败", err.Error())
	}
	gOption := global.Options{}
	config.ReadConfigFile(vip, &gOption)
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	//事件记录初始化
	eventInit(&gOption)
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
		funcServiceHandle, err := services.Get(baseOptions.Protocol)
		if err != nil {
			logger.Log.Warn(err)
			//services.Register(baseOptions.Application, funcServiceHandle)
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
		logger.Log.Info(serviceApp)
		//serviceApp.WorkerHandle(&serviceApp)
		Start(ctx, &serviceApp)
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
	err := event.EventInit(opt)
	fmt.Println(err.Error())
}
