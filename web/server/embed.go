package server

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// dist 由 `make web` 生成：前端构建产物会复制到这里。
// 仓库内只保留 .gitkeep，未构建前端时使用 notBuiltPage 兜底。
//
//go:embed all:dist
var distFS embed.FS

const notBuiltPage = `<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>PotAgent 控制台 · 前端未构建</title>
    <style>
      body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
        background: #f5f6f8; color: #1f2937;
        font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif; }
      main { max-width: 560px; padding: 24px; border: 1px solid #e5e7eb; border-radius: 4px; background: #fff; }
      h1 { margin: 0 0 8px; font-size: 18px; }
      p { margin: 6px 0; font-size: 13px; line-height: 20px; color: #6b7280; }
      code { padding: 1px 4px; border-radius: 3px; background: #f3f4f6; color: #2563eb;
        font-family: ui-monospace, Menlo, monospace; }
    </style>
  </head>
  <body>
    <main>
      <h1>前端资源尚未构建</h1>
      <p>API 已可用（例如 <code>GET /api/stats/overview</code>），但静态页面还没打包进二进制。</p>
      <p>在仓库根目录执行 <code>make web</code>（会自动构建前端并复制到 web/server/dist），然后重新编译。</p>
      <p>开发调试可直接运行 <code>cd web/frontend &amp;&amp; npm run dev</code>，Vite 会把 /api 代理到本服务。</p>
    </main>
  </body>
</html>`

// staticHandler 托管前端单页应用，未知路径回落到 index.html。
func staticHandler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return notBuiltHandler()
	}

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)

			return
		}

		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}

		if _, statErr := fs.Stat(sub, name); statErr != nil {
			index, readErr := fs.ReadFile(sub, "index.html")
			if readErr != nil {
				writeNotBuilt(w)

				return
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = w.Write(index)

			return
		}

		if name == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		}

		fileServer.ServeHTTP(w, r)
	})
}

func notBuiltHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)

			return
		}

		writeNotBuilt(w)
	})
}

func writeNotBuilt(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(notBuiltPage))
}
