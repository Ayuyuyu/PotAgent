# 新增 / 删除蜜罐服务时的改动清单

本文说明新增或删除一个协议（服务）时，**前端需要改哪些文件**，以及为什么大部分文件不用改。
后端改动也附在后面，便于对照。

## 结论先行

新增协议时，前端**只有一处必改**：

```
web/frontend/src/constants/protocol.ts   →  PROTOCOL_META 里加一条
```

协议徽标、日志页的协议筛选下拉、配置页的文件树分组、登录页的分类列表、概览/服务页的协议标签，
全部从这份常量派生，不需要逐个文件去改。

## 一、必改：`web/frontend/src/constants/protocol.ts`

```ts
export const PROTOCOL_META: Record<string, IProtocolMeta> = {
  // ...
  'docker-api': { key: 'docker-api', label: 'Docker API', group: '容器编排', tone: 'info' },
};
```

三个字段都要注意：

| 字段 | 要求 |
|---|---|
| `key` | **必须与后端完全一致**：Go 里 `services.Register("<key>", ...)` 的 key，以及 yaml 里 `protocol:` 字段的值。含大小写、连字符/下划线（`docker-api`、`mitsubishi_a1e`、`mitsubishi_qna3e`） |
| `group` | 必须是 `ProtocolGroup` 联合类型里已有的值；写错会直接编译报错 |
| `tone` | 徽标配色，可选 `primary / info / success / warning / danger / accent` |

`key` 写错的后果（不会报错，但表现不对）：

- 日志行 / 服务列表里的协议徽标显示原始字符串，走 `FALLBACK_META` 的灰色样式；
- 日志页"协议"下拉里没有这一项，按协议过滤失效；
- 配置页文件树里该 yaml 落到"其它"分组。

### 需要新增一个分类时

改两处（都在同一个文件）：

```ts
export type ProtocolGroup =
  | '远程登录'
  | 'Web 服务'
  | '容器编排'    // ← 新增
  | '数据库与缓存'
  // ...

export const PROTOCOL_GROUPS: ProtocolGroup[] = [
  '远程登录',
  'Web 服务',
  '容器编排',      // ← 顺序决定登录页分类列表、配置页分组顺序
  // ...
];
```

只加 `ProtocolGroup` 不加 `PROTOCOL_GROUPS` 的话，该分类不会出现在登录页/配置页的分组里。

## 二、无需修改（自动派生）

| 文件 | 为什么不用改 |
|---|---|
| `components/logs/ProtocolTag.vue` | 内部调用 `getProtocolMeta(protocol)`，未知 key 自动回落 `FALLBACK_META` |
| `pages/logs/index.vue` | `PROTOCOL_OPTIONS` 由 `Object.values(PROTOCOL_META)` 生成 |
| `components/config/ConfigFileTree.vue` | 按 `PROTOCOL_GROUPS` 分组 |
| `pages/login/index.vue` | 左栏分类列表直接渲染 `PROTOCOL_GROUPS` |
| `pages/overview/index.vue`、`pages/services/index.vue` | 只展示后端返回的 `protocol` 字符串 + `ProtocolTag` |
| `api/types.ts` | `protocol` 是 `string`，没有枚举约束 |

## 三、只在 mock 模式下需要改（`VITE_USE_MOCK=true`）

生产环境走真实接口，以下文件只在本地原型模式生效：

| 文件 | 要做什么 | 不改的后果 |
|---|---|---|
| `api/mock/services.ts` | `SERVICE_SEEDS` 里加一行实例（file/protocol/application/port/enabled） | mock 服务列表里看不到新协议 |
| `api/mock/log-templates.ts` | `buildDetails()` 的 `switch` 加一个 `case` | 走 `default: return { ...base }`，只带 `protocol`/`application` 两个字段——而这两个字段在摘要里是隐藏的，于是日志摘要退化成事件类型（如 `docker-connect`） |
| `api/mock/configs.ts` | 若有按协议生成的 yaml 模板，补一份 | mock 配置页里没有对应文件 |

## 四、后端配套（背景，非前端）

1. 新建 `services/<pkg>/<pkg>.go`，实现 `WorkerHandle(ctx, *services.Service)` 并注册：

   ```go
   var (
       serviceName = "docker-api"
       _           = services.Register(serviceName, DockerServiceInit)
   )
   ```

2. **监听成功后必须调用 `service.MarkReady()`**：

   ```go
   listen, err := net.Listen("tcp4", address)
   if err != nil { service.ReportError(err); return }
   defer listen.Close()
   logger.Log.Infof("%s listen on %s", baseOptions.Application, address)
   service.MarkReady()   // ← 漏了会被判定"未在 10s 内确认监听"，实例状态变 error
   ```

3. 在 `services_conf/` 下加 yaml：

   ```yaml
   protocol: "docker-api"   # 与 Register 的 key、前端 PROTOCOL_META 的 key 三者一致
   application: "docker-api"
   enable: true
   host: "0.0.0.0"
   port: 2375
   ```

4. 交互式协议（SSH/Telnet 这类需要模拟 shell 的）可复用 `services/cmdsim`，普通协议不需要。

## 五、删除服务

- 后端：把 yaml 的 `enable` 改成 `false` 即可停止实例；彻底删除则删 yaml（热加载会把实例停掉），Go 包可保留。
- 前端：**可以什么都不改**。多出来的 `PROTOCOL_META` 条目没有副作用，历史日志还需要它来渲染徽标与筛选。
- 只有这两种情况需要动前端：
  1. 希望它从"协议筛选下拉"里彻底消失 → 删掉 `PROTOCOL_META` 里对应的条目（下拉选项自动少一项）；
  2. 某个分类下的协议全删光了，想清掉这个分类 → 同时删 `ProtocolGroup` 联合类型与 `PROTOCOL_GROUPS` 数组里的那一项（两处必须一致，否则编译失败）。

## 六、验证清单

```bash
cd web/frontend
npx vue-tsc --noEmit -p tsconfig.json   # 类型检查（group 写错会在这里报）

cd ../..
make web && make debug                 # 前端重新构建 + 二进制内嵌新资源
./PotAgent                             # 管理台 http://127.0.0.1:58090
```

- [ ] 日志页"协议"下拉里能看到新协议
- [ ] 新协议产生的日志，徽标文案/配色正确（不是灰色兜底样式）
- [ ] 配置页文件树里，新 yaml 落在预期分组
- [ ] 概览"服务健康"里能看到该实例
- [ ] 服务列表里状态是 `running`（`error` 多半是端口占用或漏了 `MarkReady()`）

## 附：默认端口

管理台默认监听 `127.0.0.1:58090`（高位端口，避免与 8090 之类常用端口冲突），
可在 `pot.yaml` 的 `web.port` 覆盖；`make web-dev` 的 Vite dev server 会把 `/api` 代理到该端口
（见 `web/frontend/vite.config.ts`）。
