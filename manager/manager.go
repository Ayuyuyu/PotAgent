// Package manager 负责蜜罐服务实例的生命周期：初次加载、差异热加载、
// 单实例启停。管理台（web/server）只依赖本包的导出方法，不直接操作 services。
package manager

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"potAgent/global"
	"potAgent/logger"
	"potAgent/services"
)

// Instance 是一个 yaml 文件对应的运行时实例。
type Instance struct {
	File      string
	Rel       string
	Base      global.ServiceBaseConfig
	Hash      string
	Service   *services.Service
	Running   bool
	StartedAt time.Time
	LastError string

	cancel context.CancelFunc
}

// InstanceInfo 是暴露给管理台的只读快照。
type InstanceInfo struct {
	File        string
	Rel         string
	Protocol    string
	Application string
	Host        string
	Port        uint16
	Enabled     bool
	Running     bool
	StartedAt   time.Time
	LastError   string
}

// Manager 持有全部服务实例。
type Manager struct {
	mu        sync.RWMutex
	ctx       context.Context
	dir       string
	allow     map[string]bool
	instances map[string]*Instance
	startedAt time.Time
}

// New 创建管理器。allowProtocols 为空表示不限制（与 --protocol 参数对应）。
func New(ctx context.Context, servicesDir string, allowProtocols []string) *Manager {
	abs, err := filepath.Abs(servicesDir)
	if err != nil {
		abs = servicesDir
	}

	allow := make(map[string]bool, len(allowProtocols))
	for _, item := range allowProtocols {
		item = strings.ToLower(strings.TrimSpace(item))
		if item != "" {
			allow[item] = true
		}
	}

	return &Manager{
		ctx:       ctx,
		dir:       abs,
		allow:     allow,
		instances: make(map[string]*Instance),
		startedAt: time.Now(),
	}
}

func (m *Manager) Dir() string { return m.dir }

func (m *Manager) Uptime() time.Duration { return time.Since(m.startedAt) }

func (m *Manager) allowed(base global.ServiceBaseConfig) bool {
	if len(m.allow) == 0 {
		return true
	}

	return m.allow[strings.ToLower(base.Protocol)]
}

// Start 初次加载 services_dir 下全部 yaml，返回启动成功与失败的实例数。
// 调用方可据此判断"一个都没起来"这种致命情况（典型场景：已有实例在运行，端口全被占用）。
func (m *Manager) Start() (started, failed int, err error) {
	started, failed, err = m.Reload()
	if err != nil {
		return 0, 0, err
	}
	if failed > 0 {
		logger.Log.Warnf("有 %d 个服务实例启动失败，可在管理台查看原因", failed)
	}

	return started, failed, nil
}

// StopAll 主动停止所有实例（进程退出时调用）。
func (m *Manager) StopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, inst := range m.instances {
		m.stopLocked(inst)
	}
}

// Reload 按文件差异重启变更实例，未变化的实例保持监听，实现不关机热加载。
func (m *Manager) Reload() (reloaded, failed int, err error) {
	files, scanErr := m.scan()
	if scanErr != nil {
		return 0, 0, scanErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	seen := make(map[string]struct{}, len(files))
	for _, path := range files {
		seen[path] = struct{}{}
		started, ok := m.applyLocked(path)
		if started {
			reloaded++
		}
		if !ok {
			failed++
		}
	}

	for path, inst := range m.instances {
		if _, exists := seen[path]; !exists {
			logger.Log.Infof("配置已删除，停止实例 %s", inst.Rel)
			m.stopLocked(inst)
			delete(m.instances, path)
		}
	}

	return reloaded, failed, nil
}

// applyLocked 处理单个 yaml：新增启动、变更重启、未变跳过。
// 返回是否发生了启动/重启动作，以及该实例是否处于健康状态。
func (m *Manager) applyLocked(path string) (started bool, healthy bool) {
	base, hash, parseErr := parseBaseFile(path)
	rel := m.rel(path)

	inst := m.instances[path]
	if inst == nil {
		inst = &Instance{File: path, Rel: rel}
		m.instances[path] = inst
	}

	if parseErr != nil {
		m.stopLocked(inst)
		inst.Base = base
		inst.Hash = hash
		inst.LastError = parseErr.Error()
		logger.Log.Errorf("%s 解析失败: %v", rel, parseErr)

		return false, false
	}

	if !m.allowed(base) {
		m.stopLocked(inst)
		inst.Base = base
		inst.Hash = hash
		inst.LastError = "协议未在当前进程启用（--protocol 过滤）"

		return false, true
	}

	unchanged := inst.Hash == hash &&
		inst.Base.Protocol == base.Protocol &&
		inst.Base.Application == base.Application &&
		inst.Base.Host == base.Host &&
		inst.Base.Port == base.Port &&
		inst.Base.Enable == base.Enable

	if unchanged && (inst.Running || !base.Enable) {
		inst.LastError = ""
		return false, true
	}

	wasRunning := inst.Running
	m.stopLocked(inst)
	inst.Base = base
	inst.Hash = hash
	inst.LastError = ""

	if !base.Enable {
		if wasRunning {
			logger.Log.Infof("%s 已停用", rel)
		}

		return wasRunning, true
	}

	if !wasRunning && unchanged {
		return false, true
	}

	if startErr := m.startLocked(inst); startErr != nil {
		inst.LastError = startErr.Error()
		logger.Log.Errorf("%s 启动失败: %v", rel, startErr)

		return true, false
	}

	return true, true
}

// Snapshot 返回全部实例的只读快照（按文件名排序）。
func (m *Manager) Snapshot() []InstanceInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]InstanceInfo, 0, len(m.instances))
	for _, inst := range m.instances {
		out = append(out, InstanceInfo{
			File:        inst.File,
			Rel:         inst.Rel,
			Protocol:    inst.Base.Protocol,
			Application: inst.Base.Application,
			Host:        inst.Base.Host,
			Port:        inst.Base.Port,
			Enabled:     inst.Base.Enable,
			Running:     inst.Running,
			StartedAt:   inst.StartedAt,
			LastError:   inst.LastError,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })

	return out
}

// Find 按相对文件名查找实例快照。
func (m *Manager) Find(rel string) (InstanceInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, inst := range m.instances {
		if inst.Rel == rel || inst.File == rel {
			return InstanceInfo{
				File:        inst.File,
				Rel:         inst.Rel,
				Protocol:    inst.Base.Protocol,
				Application: inst.Base.Application,
				Host:        inst.Base.Host,
				Port:        inst.Base.Port,
				Enabled:     inst.Base.Enable,
				Running:     inst.Running,
				StartedAt:   inst.StartedAt,
				LastError:   inst.LastError,
			}, true
		}
	}

	return InstanceInfo{}, false
}

// SetEnabled 修改 yaml 里的 enable 并立即生效（启停该实例）。
func (m *Manager) SetEnabled(rel string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	inst := m.findLocked(rel)
	if inst == nil {
		return fmt.Errorf("配置 %s 不存在", rel)
	}

	if err := rewriteEnable(inst.File, enabled); err != nil {
		return err
	}

	return m.reloadInstanceLocked(inst)
}

// Restart 重读该 yaml 并重启实例。
func (m *Manager) Restart(rel string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	inst := m.findLocked(rel)
	if inst == nil {
		return fmt.Errorf("配置 %s 不存在", rel)
	}

	return m.reloadInstanceLocked(inst)
}

func (m *Manager) reloadInstanceLocked(inst *Instance) error {
	base, hash, err := parseBaseFile(inst.File)
	if err != nil {
		inst.LastError = err.Error()

		return err
	}

	if !m.allowed(base) {
		return fmt.Errorf("协议 %s 未在当前进程启用（启动时使用了 --protocol 过滤）", base.Protocol)
	}

	m.stopLocked(inst)
	inst.Base = base
	inst.Hash = hash
	inst.LastError = ""

	if !base.Enable {
		return nil
	}

	if startErr := m.startLocked(inst); startErr != nil {
		inst.LastError = startErr.Error()

		return startErr
	}

	return nil
}

func (m *Manager) findLocked(rel string) *Instance {
	for _, inst := range m.instances {
		if inst.Rel == rel || inst.File == rel {
			return inst
		}
	}

	return nil
}
