package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	"potAgent/logger"
	"potAgent/manager"

	"gopkg.in/yaml.v3"
)

func (s *Server) configFileOf(info manager.InstanceInfo) (configFile, error) {
	data, err := os.ReadFile(info.File)
	if err != nil {
		return configFile{}, err
	}

	updated := ""
	if stat, statErr := os.Stat(info.File); statErr == nil {
		updated = stat.ModTime().Format(time.DateTime)
	}

	return configFile{
		File:        info.Rel,
		Protocol:    info.Protocol,
		Application: info.Application,
		Path:        path.Join(filepath.Base(s.mgr.Dir()), info.Rel),
		Content:     string(data),
		UpdatedAt:   updated,
	}, nil
}

func (s *Server) handleConfigList(w http.ResponseWriter, r *http.Request) {
	snapshot := s.mgr.Snapshot()
	items := make([]configFile, 0, len(snapshot))

	for _, info := range snapshot {
		item, err := s.configFileOf(info)
		if err != nil {
			logger.Log.Warnf("读取配置 %s 失败: %v", info.Rel, err)

			continue
		}

		items = append(items, item)
	}

	writeOK(w, items)
}

func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")

	info, ok := s.mgr.Find(file)
	if !ok {
		writeError(w, http.StatusNotFound, "配置不存在")

		return
	}

	item, err := s.configFileOf(info)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取配置失败: "+err.Error())

		return
	}

	writeOK(w, item)
}

func (s *Server) handleConfigValidate(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")

	var payload contentPayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")

		return
	}

	if _, ok := s.mgr.Find(file); !ok {
		writeError(w, http.StatusNotFound, "配置不存在")

		return
	}

	writeOK(w, s.validateConfig(file, payload.Content))
}

func (s *Server) handleConfigSave(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")

	var payload contentPayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")

		return
	}

	info, ok := s.mgr.Find(file)
	if !ok {
		writeError(w, http.StatusNotFound, "配置不存在")

		return
	}

	// 语法硬校验：拒绝落盘无法解析的 yaml，避免下次重载把实例打挂
	if err := yaml.Unmarshal([]byte(payload.Content), &rawServiceConfig{}); err != nil {
		writeError(w, http.StatusBadRequest, "YAML 语法错误："+compactYAMLError(err.Error()))

		return
	}

	mode := os.FileMode(0o644)
	if stat, statErr := os.Stat(info.File); statErr == nil {
		mode = stat.Mode()
	}

	if err := os.WriteFile(info.File, []byte(payload.Content), mode); err != nil {
		writeError(w, http.StatusInternalServerError, "写入配置失败: "+err.Error())

		return
	}

	logger.Log.Infof("管理台已保存配置 %s", info.Rel)

	updated, err := s.configFileOf(info)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "回读配置失败: "+err.Error())

		return
	}

	writeOK(w, updated)
}

func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	started := time.Now()

	reloaded, failed, err := s.mgr.Reload()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "热加载失败: "+err.Error())

		return
	}

	message := fmt.Sprintf("已热加载 %d 个实例", reloaded)
	if failed > 0 {
		message += fmt.Sprintf("，%d 个启动失败，详见服务列表", failed)
	} else {
		message += "，未中断其它监听"
	}

	logger.Log.Infof("管理台触发热加载: reloaded=%d failed=%d", reloaded, failed)

	writeOK(w, reloadResult{
		Reloaded:   reloaded,
		Failed:     failed,
		DurationMs: time.Since(started).Milliseconds(),
		Message:    message,
	})
}
