import type { ILogEntry, IServiceItem } from '../types';

/**
 * mock 的共享可变状态。
 * 页面刷新会重置，行为上等价于"守护进程刚重启"；同一次会话内所有页面读到同一份数据，
 * 避免概览与日志页数字互相矛盾。
 */
export interface IMockState {
  services: IServiceItem[];
  /** 进程内累计事件数（含历史基线） */
  totalEvents: number;
  /** 今日事件数 */
  todayEvents: number;
  /** 今日独立来源数 */
  uniqueSources: number;
  /** 日志自增序号，用作前端行 id 与轮询游标 */
  seq: number;
  /** 最近生成的事件，供最新事件流使用 */
  recent: ILogEntry[];
  startedAt: Date;
  lastLogAt: Date;
  /** 已保存的配置内容，file -> yaml 文本 */
  configs: Map<string, string>;
}

export const mockState: IMockState = {
  services: [],
  totalEvents: 12840,
  todayEvents: 386,
  uniqueSources: 326,
  seq: 0,
  recent: [],
  startedAt: new Date(Date.now() - 4 * 3600 * 1000 - 12 * 60 * 1000),
  lastLogAt: new Date(),
  configs: new Map<string, string>(),
};

export function pushRecent(entry: ILogEntry): void {
  mockState.recent.unshift(entry);

  if (mockState.recent.length > 60) {
    mockState.recent.length = 60;
  }
}

/** 模拟"清空统计"：累计数、来源数、事件流归零，实例本身保留 */
export function resetStatsState(): void {
  mockState.totalEvents = 0;
  mockState.todayEvents = 0;
  mockState.uniqueSources = 0;
  mockState.recent = [];

  for (const service of mockState.services) {
    service.events = 0;
    service.lastEventAt = null;
  }
}
