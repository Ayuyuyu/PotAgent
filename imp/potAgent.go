package imp

import (
	"context"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"potAgent/common"
	"potAgent/config"
	"potAgent/event"
	"potAgent/global"
	"potAgent/logger"
	"potAgent/manager"
	"potAgent/web/server"
	"strings"
	"syscall"
	"time"
)

// InitServicesRun 初始化并启动全部（或指定）服务，随后托管管理台。
// protocolFilter 为空时启动 services_dir 下所有 enable 的服务；非空时只启动
// 逗号分隔列表中存在的协议（按服务 yaml 的 protocol 字段匹配）。
//
// 服务的启动/停止由 manager 统一管理，因此管理台可以按 yaml 差异热加载实例，
// 不需要重启进程。
func InitServicesRun(confPath string, protocolFilter string) error {
	vip, err := config.YamlConfigHandle(confPath)
	if err != nil {
		// 只报一行可读错误，不打 goroutine 栈：配置文件缺失/语法错误属于使用问题
		logger.Log.Fatalf("初始化服务失败: %v（可用 -c 指定配置文件路径，默认 pot.yaml）", err)
	}
	gOption := global.Options{}
	if err := config.ReadConfigFile(vip, &gOption); err != nil {
		logger.Log.Fatalf("初始化服务失败: %v（配置文件 %s）", err, confPath)
	}
	// 应用配置文件里的日志等级（留空则不覆盖编译期/默认设定）
	if gOption.LogLevel != "" {
		logger.InitLog(gOption.LogLevel)
	}
	logger.Log.Println("开始初始化服务")

	// 单实例锁：同一份配置只允许一个进程托管，否则第二个进程会把每个端口都 bind 失败，
	// 却仍然带着一堆空壳实例往外写日志/统计。锁句柄由 common 包内部持有到进程退出。
	if lockErr := common.LockInstance(filepath.Join(filepath.Dir(confPath), "potagent.lock")); lockErr != nil {
		logger.Log.Fatalln(lockErr.Error())
	}

	// 管理台端口优先预占：web.enable 为 true 时先判断端口是否可用，
	// 不可用直接退出，避免先把几十个蜜罐实例拉起来再发现管理台起不来。
	// 这里直接 Listen 而不是"探测后关闭"，避免探测与实际绑定之间的竞态。
	var adminListener net.Listener
	if gOption.Web.Enable {
		listener, listenErr := net.Listen("tcp", gOption.Web.Addr())
		if listenErr != nil {
			logger.Log.Fatalf("管理台端口 %s 不可用（是否已有实例在运行？）: %v", gOption.Web.Addr(), listenErr)
		}

		adminListener = listener
	}

	// 按需解压服务资源包 (services_dir/assets.zip -> services_dir/assets)，仅当资源目录缺失时
	if err := common.EnsureAssets(gOption.ServicesDir); err != nil {
		logger.Log.Errorf("解压资源包失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 事件记录初始化
	eventInit(&gOption)

	// 服务实例统一交给 manager，支持后续差异热加载
	mgr := manager.New(ctx, gOption.ServicesDir, splitProtocols(protocolFilter))

	_, failedCount, startErr := mgr.Start()
	if startErr != nil {
		logger.Log.Fatalln("读取服务目录失败", startErr.Error())

		return startErr
	}

	started := make([]string, 0)
	for _, info := range mgr.Snapshot() {
		if info.Running {
			started = append(started, info.Application)
		}
	}

	if len(started) == 0 {
		// 一个都没起来且确实有失败项（不是 --protocol 过滤导致的空集），属于致命错误：
		// 典型原因是端口被另一个 PotAgent 或其它进程占用，继续跑只会产生空壳实例。
		if failedCount > 0 {
			logger.Log.Fatalf("全部 %d 个服务实例启动失败，进程退出（请检查上方错误，端口可能已被占用）", failedCount)
		}

		logger.Log.Warnf("未启动任何服务（--protocol=%q 无匹配或服务目录为空）", protocolFilter)
	} else {
		logger.Log.Infof("已启动服务: %s", strings.Join(started, ", "))
	}

	// 管理台：编译进主进程，独立端口与独立路由
	var admin *server.Server
	if gOption.Web.Enable {
		logPath := gOption.Outputs.File.FilePath
		if logPath == "" {
			logPath = "event.log"
		}

		srv, srvErr := server.New(gOption.Web, mgr, logPath, adminListener)
		if srvErr != nil {
			// 管理台初始化失败（统计库打不开等）同样致命：进程继续跑但没有可见入口，没有意义
			logger.Log.Fatalf("管理台初始化失败: %v", srvErr)
		} else {
			admin = srv
			go admin.Run()
		}
	}

	// 整体等待退出
	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt)
	signal.Notify(s, syscall.SIGTERM)

	<-s
	logger.Log.Println("服务退出")
	cancel()

	if admin != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = admin.Shutdown(shutdownCtx)
		shutdownCancel()
	}

	mgr.StopAll()

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
