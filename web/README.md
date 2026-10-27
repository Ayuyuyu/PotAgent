# PotAgent 管理台

管理台由两部分组成，均不在 `services/` 内：

- `web/frontend`：Vue 3 + TypeScript + Vite + 自研 CSS（无 UI 组件库），构建产物由 Go 嵌入二进制。
- `web/server`：Go 包，**编译进 PotAgent 主进程**，独立端口（默认 `127.0.0.1:58090`）与独立路由树。

新增或删除协议时需要同步的前端文件，见 [docs/adding-service.md](../docs/adding-service.md)。

服务实例的生命周期由 `manager` 包统一管理，因此配置改动可以按 yaml 差异**热加载**（只重启变更的实例），不需要重启进程。

## 构建与启动

```bash
make web-deps     # 首次：安装前端依赖
make web          # 构建前端并复制到 web/server/dist
make release      # 或 make debug，编译带管理台的二进制
./PotAgent        # 管理台 http://127.0.0.1:58090
```

开发态（前端热更新）：

```bash
make debug && ./PotAgent   # 后端与管理台在 58090
make web-dev               # 前端 dev server 5173，/api 自动代理到 58090
```

未执行 `make web` 时也能编译：静态页会显示"前端未构建"的提示，API 仍然可用。

## 配置（pot.yaml）

```yaml
web:
  enable: true
  host: "127.0.0.1"        # 需要远程访问改 0.0.0.0，并务必改掉默认口令
  port: 58090
  username: "admin"
  password: "potagent"     # 支持明文，或 bcrypt:<hash>
  stats_db_path: "./potagent_stats.db"
  session_ttl_minutes: 480
```

生成 bcrypt 口令：`htpasswd -bnBC 10 "" '你的口令' | tr -d ':\n'`，把结果前面加 `bcrypt:`。

登录态是 HttpOnly + SameSite=Lax 的会话 Cookie；写请求额外校验 Origin；同一来源 5 分钟内失败 5 次会被临时拒绝。

## 页面

| 路由 | 页面 | 关键交互 |
| --- | --- | --- |
| `/login` | 登录 | 表单校验、loading、错误行、回车提交 |
| `/overview` | 概览 | 统计卡（含环比与迷你趋势）、小时/日/周趋势图（hover 十字线）、服务健康、最新事件、攻击来源 Top |
| `/logs` | 实时日志 | 3/5/10 秒轮询追加、暂停/继续、关键字 + 协议 + 源 IP + 时间范围组合查询、行内高亮（行高 34px、摘要 13px）、详情抽屉（字段表 + 原始 JSON + 复制） |
| `/services` | 服务管理 | 真实实例列表、状态筛选、开关（二次确认影响说明）、单实例重启、异常行标红并展示 lastError、热加载全部 |
| `/config` | 配置管理 | 按协议分组的文件树、YAML 行号 + 着色编辑、语法/必填/端口冲突校验、保存、生效（热加载） |

## 两套配色

右上角切换，`html[data-theme]` 驱动，只替换 CSS 变量，布局完全一致，选择写入 `localStorage`：

- **精工蓝**（默认）：中性灰底 `#F5F6F8` + 靛蓝 `#2563EB` + 琥珀 `#F59E0B`。
- **翡翠绿**：冷绿灰底 `#F4F7F6` + 深青 `#0F766E` + 青绿 `#14B8A6`。

顶栏为纯白实底：最上沿 2px 主色→强调色渐变细带，底部 `line-strong` 分割线加一层极轻投影。

## 编辑器外观（配置管理页）

路径行右侧的「编辑器」分段控件提供三档，写入 `localStorage`（`potagent.admin.editor-theme`），与右上角配色互相独立：

| 档位 | 底色 | 行号栏 | 说明 |
| --- | --- | --- | --- |
| 浅色 | `#FFFFFF` | `#FAFBFC` | 与卡片同色 |
| 纸灰（默认） | `#F7F8FA` | `#EEF1F5` | 与白色页头、外层边框形成清晰边界 |
| 深色 | `#1E2430` | `#181D27` | 深底亮字（正文 `#E2E8F0`） |

三档共用 13px 等宽正文与 **20px 行高**（`jumpToLine()` 依赖该行高定位，改字号需同步 `web/frontend/src/pages/config/index.vue` 的 `LINE_HEIGHT`）、12px 行号。

## 后端实现

- **日志读取**（`web/server/logreader.go`）：`event.log` 为 JSON Lines 单文件追加，`tail` 以字节偏移为游标增量读取；`search` 从文件尾按 64KB 块倒读，最多扫描 8MB / 返回 500 条；文件被截断或重建时游标归零并返回 `truncated`。
- **统计**（`web/server/stats.go` + `aggregate.go`）：SQLite（`modernc.org/sqlite`，纯 Go，无 cgo）。`event_hourly` / `source_hourly` 按小时桶 `ON CONFLICT DO UPDATE` 累加，游标存 `meta` 表；每 5 秒聚合一次，首次索引大文件时按 8MB 分批推进，不阻塞启动。
- **服务管理**（`manager/`）：`Reload()` 对比文件摘要与基础字段，只重启新增/变更实例；启动前做 TCP/UDP 端口预检，停实例后等待端口释放再重启。
- **配置**（`web/server/config_validate.go` + `api_config.go`）：用 `yaml.v3` 解析（**不复用 `config` 包**，它在解析失败时 `panic`），校验语法、必填字段、端口范围与 TCP/UDP 端口冲突并返回行号；保存前做语法硬校验；启停只改 yaml 里 `enable` 那一行，保留注释排版。
- **启动故障隔离**：各服务监听失败处原先调用 `logger.Log.Fatalln`（会杀掉整个进程），已改为 `service.ReportError(err)` + `return`，由 manager 记录到实例状态，因此热加载时单个实例失败不影响进程与其它服务。

## 接口

```
POST /api/auth/login              {username,password} -> {username,expiresIn}
POST /api/auth/logout
GET  /api/auth/me
GET  /api/stats/overview
GET  /api/stats/trend?range=hour|day|week
GET  /api/stats/top-sources?limit=
GET  /api/services
POST /api/services/{file}/enable   {enabled}
POST /api/services/{file}/restart
GET  /api/logs/tail?cursor=&keyword=&protocol=&srcIp=&range=&limit=
GET  /api/logs/search?keyword=&protocol=&srcIp=&range=&limit=
GET  /api/config
GET  /api/config/{file}
POST /api/config/{file}/validate   {content}
POST /api/config/{file}            {content}
POST /api/config/reload
```

统一响应体 `{ code: 0, message: "ok", data: ... }`，非 0 或非 2xx 时前端抛 `ApiError` 并弹提示。

## 已知限制

- `connections`（当前连接数）暂未统计，接口固定返回 0；需要时可在各服务加连接计数后由 manager 汇总。
- Top 来源的 `location`（归属地）暂无离线库，返回空字符串，前端自动隐藏该列。
- `event.log` 没有内置轮转；若外部按天切割，统计游标会检测到文件变小并从头部重新累积，旧统计数据保留但不回填。
- 管理台默认只监听 `127.0.0.1`；暴露到公网前请改口令、加反向代理与 TLS。

## 前端目录

```
web/frontend/src/
├── api/            # 契约 types.ts、统一出口 client.ts、mock/ 假数据源（VITE_USE_MOCK=true 时启用）
├── components/     # common 基础组件、charts 自研 SVG 图表、logs 日志组件、config 配置组件、layout 顶栏
├── composables/    # use-polling / use-theme / use-auth / use-toast
├── constants/      # 协议元数据、主题与编辑器外观定义
├── layouts/        # DefaultLayout（顶栏）、BlankLayout（登录）
├── pages/          # login / overview / logs / services / config
├── router/         # 懒加载 + 登录守卫
├── store/          # auth / theme / editor-theme / services（Pinia）
├── styles/         # variables → themes → base → tailwind → utilities
└── utils/          # 格式化、关键词高亮、日志摘要、YAML 着色
```
