package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookieName = "potagent_session"

type session struct {
	username string
	expires  time.Time
}

type sessionStore struct {
	mu    sync.Mutex
	items map[string]session
	ttl   time.Duration
}

func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{items: make(map[string]session), ttl: ttl}
}

func (s *sessionStore) create(username string) (string, int) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", 0
	}

	token := hex.EncodeToString(buf)
	expires := time.Now().Add(s.ttl)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked()
	s.items[token] = session{username: username, expires: expires}

	return token, int(s.ttl.Seconds())
}

func (s *sessionStore) get(token string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, ok := s.items[token]
	if !ok {
		return session{}, false
	}

	if time.Now().After(item.expires) {
		delete(s.items, token)

		return session{}, false
	}

	return item, true
}

func (s *sessionStore) remove(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, token)
}

func (s *sessionStore) cleanupLocked() {
	now := time.Now()

	for token, item := range s.items {
		if now.After(item.expires) {
			delete(s.items, token)
		}
	}
}

// loginLimiter 对同一来源的连续失败做简单节流，避免口令被在线爆破。
type loginLimiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

const (
	loginFailWindow = 5 * time.Minute
	loginFailLimit  = 5
)

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{fails: make(map[string][]time.Time)}
}

func (l *loginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-loginFailWindow)
	kept := l.fails[ip][:0]

	for _, at := range l.fails[ip] {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}

	l.fails[ip] = kept

	return len(kept) >= loginFailLimit
}

func (l *loginLimiter) record(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails[ip] = append(l.fails[ip], time.Now())
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}

// verifyCredentials 支持明文口令与 bcrypt:<hash> 两种配置写法。
func (s *Server) verifyCredentials(username, password string) bool {
	expectUser := s.cfg.Username
	if expectUser == "" {
		expectUser = "admin"
	}

	if subtle.ConstantTimeCompare([]byte(expectUser), []byte(username)) != 1 {
		return false
	}

	expectPass := s.cfg.Password

	if strings.HasPrefix(expectPass, "bcrypt:") {
		hash := strings.TrimPrefix(expectPass, "bcrypt:")

		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}

	return subtle.ConstantTimeCompare([]byte(expectPass), []byte(password)) == 1
}

// sameOrigin 拒绝跨站写请求：SameSite=Lax 已挡住大部分场景，这里再加一道 Origin 校验。
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}

	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}

	host := parsed.Host
	if host == "" {
		return false
	}

	return strings.EqualFold(host, r.Host)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "跨站请求被拒绝")

			return
		}

		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "未登录或会话已过期")

			return
		}

		item, ok := s.sessions.get(cookie.Value)
		if !ok {
			writeError(w, http.StatusUnauthorized, "未登录或会话已过期")

			return
		}

		r.Header.Set("X-Potagent-User", item.username)
		next(w, r)
	}
}
