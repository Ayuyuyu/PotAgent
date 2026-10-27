/**
 * 管理端数据契约。
 * 日志字段与 event/event.go::Event 的 JSON 一一对应（event.log 每行一个对象），
 * 后续接口直接返回该结构时前端无需调整。
 */

export type ServiceStatus = 'running' | 'stopped' | 'error';

export type EventCategory = string;

/** 单条事件，字段对齐 event.log */
export interface ILogEntry {
  /** 前端生成的行标识（mock 用序号，真实接口用 offset 或自增 id） */
  id: string;
  /** YYYY-MM-DD HH:mm:ss，与 Event.Timestamp 一致 */
  timestamp: string;
  eventCategory: EventCategory;
  eventType: string;
  srcIp: string;
  dstIp: string;
  ipProtocol: string;
  srcPort: number;
  dstPort: number;
  details: Record<string, unknown>;
}

/** 服务实例，对应 services_conf 下的一个 yaml */
export interface IServiceItem {
  file: string;
  protocol: string;
  application: string;
  host: string;
  port: number;
  enabled: boolean;
  status: ServiceStatus;
  /** 当前活跃连接数 */
  connections: number;
  /** 累计接收事件数（本次进程生命周期内） */
  events: number;
  /** 最近一次事件时间 */
  lastEventAt: string | null;
  startedAt: string | null;
  lastError?: string;
}

export interface IServiceSummary {
  total: number;
  running: number;
  stopped: number;
  error: number;
}

export interface IOverviewStats {
  totalEvents: number;
  todayEvents: number;
  todayDeltaPercent: number;
  uniqueSources: number;
  uniqueSourcesDelta: number;
  activeServices: number;
  totalServices: number;
  connections: number;
  /** 事件日志文件大小（字节） */
  logFileSize: number;
  /** 日志最后写入时间 */
  lastLogAt: string | null;
  uptimeSeconds: number;
}

export type TrendRange = 'hour' | 'day' | 'week';

/** 别名：与 I 前缀风格保持一致，便于组件内使用 */
export type ITrendRange = TrendRange;

export interface ITrendPoint {
  /** X 轴显示标签 */
  label: string;
  /** 完整时间（tooltip 用） */
  at: string;
  value: number;
  /** 次要指标：独立源 IP 数 */
  sources: number;
}

export interface ITrendSeries {
  range: TrendRange;
  points: ITrendPoint[];
  total: number;
  /** 环比变化百分比 */
  deltaPercent: number;
  peakLabel: string;
}

export interface ITopSource {
  ip: string;
  count: number;
  /** 归属地展示文本，真实接口可由离线库补全 */
  location: string;
  /** 命中协议数 */
  protocols: number;
  lastSeen: string;
}

export interface ILogQuery {
  keyword: string;
  protocol: string;
  srcIp: string;
  /** 时间范围：all / 5m / 1h / 24h */
  range: 'all' | '5m' | '1h' | '24h';
  limit: number;
}

export interface ILogTailResult {
  entries: ILogEntry[];
  /** 下次轮询携带的游标 */
  cursor: string;
  /** 文件已被截断或重建，前端应清空缓冲 */
  truncated: boolean;
  logFileSize: number;
  /** 命中条数（有查询条件时有效） */
  matched: number;
}

export interface IConfigFile {
  file: string;
  protocol: string;
  application: string;
  /** 相对仓库根目录的展示路径 */
  path: string;
  content: string;
  /** 与磁盘内容不一致（前端本地脏标记之外的后端判定） */
  dirty: boolean;
  updatedAt: string;
}

export type ValidationLevel = 'error' | 'warning' | 'info';

export interface IValidationIssue {
  level: ValidationLevel;
  /** 1 起始行号，0 表示与具体行无关 */
  line: number;
  field: string;
  message: string;
}

export interface IValidationResult {
  valid: boolean;
  /** 已通过的检查项数量 */
  passed: number;
  issues: IValidationIssue[];
  checkedAt: string;
}

export interface IReloadResult {
  reloaded: number;
  failed: number;
  durationMs: number;
  message: string;
}

/** 统一响应包装，与 Go 端保持一致 */
export interface IApiResult<T> {
  code: number;
  message: string;
  data: T;
}

export interface ILoginPayload {
  username: string;
  password: string;
}

export interface ISessionUser {
  username: string;
  /** 登录后有效期剩余秒数 */
  expiresIn: number;
}
