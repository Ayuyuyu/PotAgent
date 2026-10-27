package manager

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"potAgent/global"
	"potAgent/logger"
	"potAgent/services"
)

// startReadyTimeout 等待服务确认监听的上限。
//
// 大多数服务是毫秒级，但有几个在 Listen 之前要做重活：
// ssh 生成 RSA-2048 host key、kubernetes 生成自签证书、rdp 生成专有密钥并解码桌面图，
// 慢机器上单次可以到 2~4 秒，所以这里给到 10 秒，避免把正常启动误判成失败。
const startReadyTimeout = 10 * time.Second

// slowStartThreshold 超过这个时间才确认监听就记一条 warning，便于发现异常慢启动。
const slowStartThreshold = 2 * time.Second

// 以 UDP 收包的服务，端口预检要用 ListenPacket。
var udpProtocols = map[string]bool{
	"dns":    true,
	"ntp":    true,
	"sntp":   true,
	"snmp":   true,
	"sip":    true,
	"tftp":   true,
	"bacnet": true,
}

const portReleaseTimeout = 800 * time.Millisecond

// IsUDPProtocol 报告该协议是否以 UDP 收包，端口预检与冲突检测需要区分 TCP/UDP。
func IsUDPProtocol(protocol string) bool {
	return udpProtocols[strings.ToLower(protocol)]
}

// startLocked 解析服务私有配置、预检端口并拉起 goroutine。
func (m *Manager) startLocked(inst *Instance) error {
	initFn, err := services.Get(inst.Base.Protocol)
	if err != nil {
		return fmt.Errorf("协议 %q 未注册: %w", inst.Base.Protocol, err)
	}

	app := initFn()
	app.BaseOptions = inst.Base

	// 监听成功/失败的就绪信号：用于等端口真正在监听，而不是协程刚拉起就认为成功
	var readyOnce sync.Once
	ready := make(chan struct{})
	startFailed := make(chan error, 1)

	app.OnReady = func() {
		readyOnce.Do(func() { close(ready) })
	}

	// 服务在监听失败时通过回调上报，而不是退出进程。
	// 这里额外把首个错误塞进 startFailed：startLocked 持有写锁期间 OnError 的
	// 加锁路径会被阻塞，不走这条通道就只能等超时，还会丢掉真实失败原因。
	app.OnError = func(err error) {
		select {
		case startFailed <- err:
		default:
		}

		m.mu.Lock()
		defer m.mu.Unlock()

		inst.LastError = err.Error()
		logger.Log.Errorf("%s 启动失败: %v", inst.Rel, err)
	}

	if err := safeReadOptions(inst.File, &app.ServiceOptions); err != nil {
		return err
	}

	if err := checkPortAvailable(inst.Base); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(m.ctx)
	inst.cancel = cancel
	inst.Service = &app
	inst.Running = true
	inst.StartedAt = time.Now()

	go func() {
		app.WorkerHandle(ctx, &app)
		m.handleExit(inst, ctx)
	}()

	// 等端口真正在监听：既保证各服务的 listen 日志排在"已启动服务"汇总行之前，
	// 也让 Running 的语义从"协程已拉起"变成"确认在监听"。
	waitStarted := time.Now()

	select {
	case <-ready:
		if cost := time.Since(waitStarted); cost > slowStartThreshold {
			logger.Log.Warnf("%s 启动较慢: 耗时 %s 才确认监听", inst.Base.Application, cost.Round(time.Millisecond))
		}
	case err := <-startFailed:
		cancel()
		inst.Running = false

		return err
	case <-time.After(startReadyTimeout):
		cancel()
		inst.Running = false

		return fmt.Errorf("%s 未在 %s 内确认监听", inst.Base.Application, startReadyTimeout)
	}

	return nil
}

// handleExit 在 WorkerHandle 返回后区分「主动停止」与「异常退出」。
func (m *Manager) handleExit(inst *Instance, ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	inst.Running = false
	inst.cancel = nil

	if inst.LastError != "" {
		logger.Log.Errorf("%s 异常退出: %s", inst.Rel, inst.LastError)

		return
	}

	inst.LastError = "服务意外退出"
	logger.Log.Errorf("%s 意外退出", inst.Rel)
}

// stopLocked 取消上下文并等待端口释放，保证紧接着的重启能成功 bind。
func (m *Manager) stopLocked(inst *Instance) {
	wasRunning := inst.Running

	if inst.cancel != nil {
		inst.cancel()
		inst.cancel = nil
	}

	inst.Running = false

	if wasRunning && inst.Base.Port > 0 {
		waitPortReleased(inst.Base, portReleaseTimeout)
	}
}

func checkPortAvailable(base global.ServiceBaseConfig) error {
	addr := net.JoinHostPort(base.Host, strconv.Itoa(int(base.Port)))

	if udpProtocols[base.Protocol] {
		conn, err := net.ListenPacket("udp4", addr)
		if err != nil {
			return fmt.Errorf("UDP 端口 %s 不可用: %w", addr, err)
		}

		return conn.Close()
	}

	listener, err := net.Listen("tcp4", addr)
	if err != nil {
		return fmt.Errorf("TCP 端口 %s 不可用: %w", addr, err)
	}

	return listener.Close()
}

func waitPortReleased(base global.ServiceBaseConfig, timeout time.Duration) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if checkPortAvailable(base) == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}

	logger.Log.Warnf("端口 %d 未在 %s 内释放，重启该实例可能失败", base.Port, timeout)
}
