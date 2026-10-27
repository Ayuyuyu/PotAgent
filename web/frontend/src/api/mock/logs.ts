import type { ILogEntry, ILogQuery, ILogTailResult, IServiceItem } from '../types';
import { buildDetails, buildEventType } from './log-templates';
import { ATTACKER_POOL, createRng, formatTimestamp, intBetween, type Rng } from './rng';
import { listServices, noteEvent } from './services';
import { mockState, pushRecent } from './state';

const DST_IP = '10.0.3.17';
const RANGE_MS: Record<ILogQuery['range'], number> = {
  all: Number.POSITIVE_INFINITY,
  '5m': 5 * 60 * 1000,
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
};

let lastEmitAt = Date.now() - 3000;

function runningServices(): IServiceItem[] {
  const running = listServices().filter((item) => item.status === 'running');

  return running.length > 0 ? running : listServices();
}

/** 热门协议被扫得更频繁：按事件计数做加权抽样 */
function pickService(rng: Rng, services: IServiceItem[]): IServiceItem {
  const total = services.reduce((sum, item) => sum + item.events, 0);
  let ticket = rng() * total;

  for (const item of services) {
    ticket -= item.events;

    if (ticket <= 0) {
      return item;
    }
  }

  return services[services.length - 1];
}

function buildEntry(rng: Rng, service: IServiceItem, at: Date, id: string): ILogEntry {
  const attacker = ATTACKER_POOL[Math.floor(rng() * ATTACKER_POOL.length) % ATTACKER_POOL.length];

  return {
    id,
    timestamp: formatTimestamp(at),
    eventCategory: service.protocol,
    eventType: buildEventType(rng, service.protocol),
    srcIp: attacker.ip,
    dstIp: DST_IP,
    ipProtocol: service.protocol === 'dns' || service.protocol === 'ntp' || service.protocol === 'sntp' ? 'udp' : 'tcp',
    srcPort: intBetween(rng, 32768, 60999),
    dstPort: service.port,
    details: buildDetails(rng, service),
  };
}

function matches(entry: ILogEntry, query: ILogQuery): boolean {
  if (query.protocol && entry.eventCategory !== query.protocol) {
    return false;
  }

  if (query.srcIp && !entry.srcIp.startsWith(query.srcIp.trim())) {
    return false;
  }

  if (query.range !== 'all') {
    const age = Date.now() - new Date(entry.timestamp.replace(' ', 'T')).getTime();

    if (age > RANGE_MS[query.range]) {
      return false;
    }
  }

  const keyword = query.keyword.trim().toLowerCase();

  if (keyword && !JSON.stringify(entry).toLowerCase().includes(keyword)) {
    return false;
  }

  return true;
}

/** 文件大小随事件数线性增长，模拟 event.log 追加 */
export function getLogFileSize(): number {
  return 3.7 * 1024 * 1024 + mockState.totalEvents * 412;
}

/** 增量拉取：每次轮询产生 1~4 条新事件，并累加统计 */
export function tailLogs(query: ILogQuery, cursor: string): ILogTailResult {
  const services = runningServices();
  const rng = createRng(Date.now() & 0xffff);
  const count = intBetween(rng, 1, 4);
  const now = Date.now();
  const entries: ILogEntry[] = [];

  for (let i = 0; i < count; i += 1) {
    lastEmitAt = Math.min(now, lastEmitAt + intBetween(rng, 400, 2200));
    const service = pickService(rng, services);
    const at = new Date(lastEmitAt);
    mockState.seq += 1;

    const entry = buildEntry(rng, service, at, String(mockState.seq));

    noteEvent(service.file, at);
    pushRecent(entry);
    entries.push(entry);
  }

  mockState.lastLogAt = new Date(lastEmitAt);

  const visible = entries.filter((entry) => matches(entry, query)).reverse();

  return {
    entries: visible,
    cursor: String(mockState.seq),
    truncated: cursor === 'reset',
    logFileSize: getLogFileSize(),
    matched: visible.length,
  };
}

/** 历史查询：生成最近 24h 的稳定样本（固定种子）后过滤，结果按时间倒序 */
export function searchLogs(query: ILogQuery): ILogTailResult {
  const services = runningServices();
  const limit = Math.max(20, Math.min(query.limit, 500));
  const rng = createRng(20261023);
  const now = Date.now();
  const span = query.range === 'all' ? RANGE_MS['24h'] : RANGE_MS[query.range];
  const entries: ILogEntry[] = [];

  for (let i = 0; i < 600 && entries.length < limit; i += 1) {
    const at = new Date(now - Math.floor(rng() * span));
    const service = pickService(rng, services);
    const entry = buildEntry(rng, service, at, `h-${i}`);

    if (matches(entry, query)) {
      entries.push(entry);
    }
  }

  entries.sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));

  return {
    entries,
    cursor: String(mockState.seq),
    truncated: false,
    logFileSize: getLogFileSize(),
    matched: entries.length,
  };
}

export function getRecentEntries(limit = 8): ILogEntry[] {
  if (mockState.recent.length === 0) {
    const services = runningServices();
    const rng = createRng(77001);
    const now = Date.now();

    for (let i = 0; i < 24; i += 1) {
      const service = pickService(rng, services);
      const entry = buildEntry(rng, service, new Date(now - i * 17000), `seed-${i}`);
      pushRecent(entry);
    }
  }

  return mockState.recent.slice(0, limit);
}
