package server

import (
	"encoding/json"
	"net/http"
	"time"

	"potAgent/logger"
	"potAgent/manager"
)

func (s *Server) serviceItemOf(info manager.InstanceInfo, totals map[string]struct {
	Count int64
	Last  time.Time
}) serviceItem {
	stat := totals[info.Protocol]

	status := "stopped"
	if info.Running {
		status = "running"
	} else if info.Enabled && info.LastError != "" {
		status = "error"
	} else if info.Enabled && !info.StartedAt.IsZero() {
		// 曾经启动过但现在没在跑：视为异常，避免"开关是开的却静默不响应"
		status = "error"
	}

	item := serviceItem{
		File:        info.Rel,
		Protocol:    info.Protocol,
		Application: info.Application,
		Host:        info.Host,
		Port:        info.Port,
		Enabled:     info.Enabled,
		Status:      status,
		Events:      stat.Count,
		LastError:   info.LastError,
	}

	if status == "error" && item.LastError == "" {
		item.LastError = "实例未在监听，可能被其它进程占用端口或被主动停止"
	}

	if !info.StartedAt.IsZero() {
		value := info.StartedAt.Format(time.DateTime)
		item.StartedAt = &value
	}

	if !stat.Last.IsZero() {
		value := stat.Last.Format(time.DateTime)
		item.LastEventAt = &value
	}

	return item
}

func (s *Server) listServiceItems() []serviceItem {
	snapshot := s.mgr.Snapshot()
	totals := s.stats.ProtocolTotals()

	items := make([]serviceItem, 0, len(snapshot))
	for _, info := range snapshot {
		items = append(items, s.serviceItemOf(info, totals))
	}

	return items
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	writeOK(w, s.listServiceItems())
}

func (s *Server) handleServiceEnable(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")

	var payload enablePayload
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")

		return
	}

	if err := s.mgr.SetEnabled(file, payload.Enabled); err != nil {
		logger.Log.Errorf("切换 %s 状态失败: %v", file, err)
		writeError(w, http.StatusInternalServerError, err.Error())

		return
	}

	info, ok := s.mgr.Find(file)
	if !ok {
		writeError(w, http.StatusNotFound, "配置不存在")

		return
	}

	writeOK(w, s.serviceItemOf(info, s.stats.ProtocolTotals()))
}

func (s *Server) handleServiceRestart(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")

	if err := s.mgr.Restart(file); err != nil {
		logger.Log.Errorf("重启 %s 失败: %v", file, err)
		writeError(w, http.StatusInternalServerError, err.Error())

		return
	}

	info, ok := s.mgr.Find(file)
	if !ok {
		writeError(w, http.StatusNotFound, "配置不存在")

		return
	}

	writeOK(w, s.serviceItemOf(info, s.stats.ProtocolTotals()))
}
