// Package server 是管理台的 HTTP 后端：独立端口、独立路由树，
// 编译进 PotAgent 主进程，但实现上不依赖 services 包的具体协议代码。
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"potAgent/global"
	"potAgent/logger"
	"potAgent/manager"
)

// Server 持有管理台运行期状态。
type Server struct {
	cfg      global.WebConfig
	mgr      *manager.Manager
	logPath  string
	sessions *sessionStore
	limiter  *loginLimiter
	stats    *statsStore
	reader   *logReader
	http     *http.Server
	listener net.Listener

	ctx    context.Context
	cancel context.CancelFunc
}

// New 组装管理台。logPath 为 event.log 路径（可为相对 CWD 的路径）。
// listener 允许调用方提前占用端口（启动阶段优先判定端口冲突），传 nil 时由这里自行 Listen。
func New(cfg global.WebConfig, mgr *manager.Manager, logPath string, listener net.Listener) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	store, err := openStats(cfg.StatsDBPath)
	if err != nil {
		cancel()

		return nil, err
	}

	s := &Server{
		cfg:      cfg,
		mgr:      mgr,
		logPath:  logPath,
		sessions: newSessionStore(cfg.SessionTTL()),
		limiter:  newLoginLimiter(),
		stats:    store,
		reader:   newLogReader(logPath),
		ctx:      ctx,
		cancel:   cancel,
	}

	s.http = &http.Server{
		Addr:              cfg.Addr(),
		Handler:           s.withLogging(s.routes()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// 端口必须在返回前占住：绑定失败要在启动阶段暴露，而不是等 Run 里打一条"已启动"再静默退出
	if listener == nil {
		owned, listenErr := net.Listen("tcp", cfg.Addr())
		if listenErr != nil {
			store.Close()
			cancel()

			return nil, fmt.Errorf("管理台端口 %s 不可用: %w", cfg.Addr(), listenErr)
		}

		listener = owned
	}

	s.listener = listener

	return s, nil
}

// Run 阻塞运行，直到 Shutdown 被调用。
func (s *Server) Run() {
	go s.aggregateLoop()

	logger.Log.Infof("管理台已启动: http://%s （账号 %s）", s.cfg.Addr(), s.cfg.Username)

	if err := s.http.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Log.Errorf("管理台退出: %v", err)
	}
}

// Shutdown 停止 HTTP 服务、聚合协程与统计库。
func (s *Server) Shutdown(ctx context.Context) error {
	s.cancel()

	if s.stats != nil {
		defer s.stats.Close()
	}

	return s.http.Shutdown(ctx)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	// 登出必须幂等：会话已过期时也要返回成功并清掉 cookie，
	// 否则前端会卡在"本地认为已登录、服务端全 401"的状态。
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/auth/me", s.withAuth(s.handleMe))

	mux.HandleFunc("GET /api/stats/overview", s.withAuth(s.handleOverview))
	mux.HandleFunc("GET /api/stats/trend", s.withAuth(s.handleTrend))
	mux.HandleFunc("GET /api/stats/top-sources", s.withAuth(s.handleTopSources))
	mux.HandleFunc("POST /api/stats/reset", s.withAuth(s.handleStatsReset))

	mux.HandleFunc("GET /api/services", s.withAuth(s.handleServices))
	mux.HandleFunc("POST /api/services/{file}/enable", s.withAuth(s.handleServiceEnable))
	mux.HandleFunc("POST /api/services/{file}/restart", s.withAuth(s.handleServiceRestart))

	mux.HandleFunc("GET /api/logs/tail", s.withAuth(s.handleLogTail))
	mux.HandleFunc("GET /api/logs/search", s.withAuth(s.handleLogSearch))

	mux.HandleFunc("GET /api/config", s.withAuth(s.handleConfigList))
	mux.HandleFunc("POST /api/config/reload", s.withAuth(s.handleConfigReload))
	mux.HandleFunc("GET /api/config/{file}", s.withAuth(s.handleConfigGet))
	mux.HandleFunc("POST /api/config/{file}/validate", s.withAuth(s.handleConfigValidate))
	mux.HandleFunc("POST /api/config/{file}", s.withAuth(s.handleConfigSave))

	mux.Handle("/", staticHandler())

	return mux
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var payload loginPayload

	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "请求格式错误")

		return
	}

	ip := clientIP(r)
	if s.limiter.blocked(ip) {
		writeError(w, http.StatusTooManyRequests, "失败次数过多，请 5 分钟后再试")

		return
	}

	if !s.verifyCredentials(payload.Username, payload.Password) {
		s.limiter.record(ip)
		logger.Log.Warnf("管理台登录失败: user=%q from %s", payload.Username, ip)
		writeError(w, http.StatusUnauthorized, "用户名或密码不正确")

		return
	}

	token, expiresIn := s.sessions.create(payload.Username)
	if token == "" {
		writeError(w, http.StatusInternalServerError, "生成会话失败")

		return
	}

	s.limiter.reset(ip)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   expiresIn,
	})

	writeOK(w, sessionUser{Username: payload.Username, ExpiresIn: expiresIn})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "跨站请求被拒绝")

		return
	}

	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.sessions.remove(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	writeOK(w, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "未登录")

		return
	}

	item, ok := s.sessions.get(cookie.Value)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未登录")

		return
	}

	writeOK(w, sessionUser{
		Username:  item.username,
		ExpiresIn: int(time.Until(item.expires).Seconds()),
	})
}

func writeOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	_ = json.NewEncoder(w).Encode(apiResult{Code: 0, Message: "ok", Data: data})
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(apiResult{Code: status, Message: message})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(recorder, r)

		elapsed := time.Since(started)
		if elapsed > time.Second || recorder.status >= http.StatusInternalServerError {
			logger.Log.Warnf("管理台 %s %s -> %d (%s)", r.Method, r.URL.Path, recorder.status, elapsed)
		}
	})
}
