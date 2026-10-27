package server

import (
	"net/http"
	"strconv"
)

func parseLogQuery(r *http.Request) logQuery {
	params := r.URL.Query()

	return logQuery{
		keyword:  params.Get("keyword"),
		protocol: params.Get("protocol"),
		srcIP:    params.Get("srcIp"),
		rangeKey: params.Get("range"),
	}
}

func (s *Server) handleLogTail(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	limit := atoiDefault(params.Get("limit"), 200)
	cursor := int64(0)

	if raw := params.Get("cursor"); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
			cursor = parsed
		}
	}

	result, err := s.reader.Tail(parseLogQuery(r), cursor, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取日志失败: "+err.Error())

		return
	}

	writeOK(w, result)
}

func (s *Server) handleLogSearch(w http.ResponseWriter, r *http.Request) {
	limit := atoiDefault(r.URL.Query().Get("limit"), 200)

	result, err := s.reader.Search(parseLogQuery(r), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查询日志失败: "+err.Error())

		return
	}

	writeOK(w, result)
}
