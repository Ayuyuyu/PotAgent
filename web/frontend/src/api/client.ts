import type {
  IApiResult,
  IConfigFile,
  ILogQuery,
  ILogTailResult,
  IOverviewStats,
  IReloadResult,
  IServiceItem,
  ISessionUser,
  ITopSource,
  ITrendRange,
  ITrendSeries,
  IValidationResult,
} from './types';
import { mockApi } from './mock';

// 默认连接真实后端；只有显式 VITE_USE_MOCK=true 才走 mock（开发环境由 .env.development 打开）
const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';

export const API_BASE = '/api';

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status = 0) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export type TUnauthorizedHandler = () => void;

let unauthorizedHandler: TUnauthorizedHandler | null = null;

/**
 * 注入全局 401 处理。会话过期、或服务重启导致内存里的会话丢失时，
 * 由上层清掉本地登录态并跳回登录页，避免停在一个永远空数据的页面。
 */
export function setUnauthorizedHandler(handler: TUnauthorizedHandler | null): void {
  unauthorizedHandler = handler;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    ...init,
  });

  const payload = (await response.json().catch(() => null)) as IApiResult<T> | null;

  // 登录接口的 401 是"密码错误"，不能当成会话过期处理
  if (response.status === 401 && !path.startsWith('/auth/login')) {
    unauthorizedHandler?.();
  }

  if (!response.ok || payload?.code !== 0) {
    throw new ApiError(payload?.message ?? `请求失败（HTTP ${response.status}）`, response.status);
  }

  return payload.data;
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, { method: 'POST', body: JSON.stringify(body ?? {}) });
}

/**
 * 统一业务出口。原型阶段走 mock；后端就绪后把 .env 的 VITE_USE_MOCK 设为 false
 * 即可切到真实接口，视图层不需要修改。
 */
export const adminApi = {
  useMock: USE_MOCK,

  login(username: string, password: string): Promise<ISessionUser> {
    return USE_MOCK ? mockApi.login(username, password) : post<ISessionUser>('/auth/login', { username, password });
  },

  logout(): Promise<void> {
    return USE_MOCK ? Promise.resolve() : post<void>('/auth/logout');
  },

  me(): Promise<ISessionUser> {
    return USE_MOCK ? mockApi.me() : request<ISessionUser>('/auth/me');
  },

  overview(): Promise<IOverviewStats> {
    return USE_MOCK ? mockApi.overview() : request<IOverviewStats>('/stats/overview');
  },

  trend(range: ITrendRange): Promise<ITrendSeries> {
    return USE_MOCK ? mockApi.trend(range) : request<ITrendSeries>(`/stats/trend?range=${range}`);
  },

  topSources(limit = 6): Promise<ITopSource[]> {
    return USE_MOCK ? mockApi.topSources(limit) : request<ITopSource[]>(`/stats/top-sources?limit=${limit}`);
  },

  resetStats(): Promise<void> {
    return USE_MOCK ? mockApi.resetStats() : post<void>('/stats/reset');
  },

  services(): Promise<IServiceItem[]> {
    return USE_MOCK ? mockApi.services() : request<IServiceItem[]>('/services');
  },

  setServiceEnabled(file: string, enabled: boolean): Promise<IServiceItem> {
    return USE_MOCK
      ? mockApi.setServiceEnabled(file, enabled)
      : post<IServiceItem>(`/services/${encodeURIComponent(file)}/enable`, { enabled });
  },

  restartService(file: string): Promise<IServiceItem> {
    return USE_MOCK
      ? mockApi.restartService(file)
      : post<IServiceItem>(`/services/${encodeURIComponent(file)}/restart`);
  },

  tailLogs(query: ILogQuery, cursor: string): Promise<ILogTailResult> {
    if (USE_MOCK) {
      return mockApi.tailLogs(query, cursor);
    }

    const params = new URLSearchParams({
      cursor,
      keyword: query.keyword,
      protocol: query.protocol,
      srcIp: query.srcIp,
      range: query.range,
      limit: String(query.limit),
    });

    return request<ILogTailResult>(`/logs/tail?${params.toString()}`);
  },

  searchLogs(query: ILogQuery): Promise<ILogTailResult> {
    if (USE_MOCK) {
      return mockApi.searchLogs(query);
    }

    const params = new URLSearchParams({
      keyword: query.keyword,
      protocol: query.protocol,
      srcIp: query.srcIp,
      range: query.range,
      limit: String(query.limit),
    });

    return request<ILogTailResult>(`/logs/search?${params.toString()}`);
  },

  configFiles(): Promise<IConfigFile[]> {
    return USE_MOCK ? mockApi.configFiles() : request<IConfigFile[]>('/config');
  },

  config(file: string): Promise<IConfigFile> {
    return USE_MOCK
      ? mockApi.config(file)
      : request<IConfigFile>(`/config/${encodeURIComponent(file)}`);
  },

  validateConfig(file: string, content: string): Promise<IValidationResult> {
    return USE_MOCK
      ? mockApi.validateConfig(file, content)
      : post<IValidationResult>(`/config/${encodeURIComponent(file)}/validate`, { content });
  },

  saveConfig(file: string, content: string): Promise<IConfigFile> {
    return USE_MOCK
      ? mockApi.saveConfig(file, content)
      : post<IConfigFile>(`/config/${encodeURIComponent(file)}`, { content });
  },

  reload(): Promise<IReloadResult> {
    return USE_MOCK ? mockApi.reload() : post<IReloadResult>('/config/reload');
  },
};
