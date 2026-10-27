import type { ILogEntry } from '@/api/types';

export interface IDetailRow {
  key: string;
  value: string;
}

/** 与日志行已有字段重复的键，摘要里不再重复展示 */
const HIDDEN_IN_SUMMARY = new Set(['protocol', 'application']);

/** 会话 ID 类字段对单行阅读无信息量，仅在详情里保留 */
const HIDDEN_KEY_SUFFIXES = ['session-id', 'session_id', 'sessionid'];

function isHiddenKey(key: string): boolean {
  const lower = key.toLowerCase();

  if (HIDDEN_IN_SUMMARY.has(lower)) {
    return true;
  }

  return HIDDEN_KEY_SUFFIXES.some((suffix) => lower.endsWith(suffix));
}

const SUMMARY_MAX_PAIRS = 4;
const SUMMARY_VALUE_LIMIT = 40;
const TITLE_VALUE_LIMIT = 120;

/** 摘要必须单行显示：把换行/制表等空白折叠成单个空格 */
function normalizeText(value: string): string {
  return value.replace(/\s+/g, ' ').trim();
}

function truncate(value: string, limit: number): string {
  return value.length > limit ? `${value.slice(0, limit)}…` : value;
}

function formatScalar(value: unknown, limit: number): string {
  if (typeof value === 'string') {
    return truncate(normalizeText(value), limit);
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }

  return '';
}

/**
 * 通用值格式化：不区分协议，避免每新增一种服务就要改前端。
 * 数组/对象只给预览，完整内容在详情抽屉里看。
 */
function formatValue(value: unknown, limit: number): string {
  if (value === null || value === undefined) {
    return '';
  }

  if (Array.isArray(value)) {
    const preview = value.slice(0, 3).map((item) => formatScalar(item, 24)).join(', ');
    const rest = value.length - 3;

    return `[${preview}${rest > 0 ? `, +${rest}` : ''}]`;
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value as Record<string, unknown>);

    if (keys.length === 0) {
      return '{}';
    }

    return `{${keys.slice(0, 2).join(', ')}${keys.length > 2 ? ', …' : ''}}`;
  }

  return formatScalar(value, limit);
}

function collectPairs(entry: ILogEntry, limit: number, maxPairs: number): string[] {
  const parts: string[] = [];
  let rest = 0;

  for (const [key, value] of Object.entries(entry.details ?? {})) {
    if (isHiddenKey(key)) {
      continue;
    }

    const text = formatValue(value, limit);

    if (!text) {
      continue;
    }

    if (parts.length < maxPairs) {
      parts.push(`${key}=${text}`);
    } else {
      rest += 1;
    }
  }

  if (rest > 0) {
    parts.push(`+${rest}`);
  }

  return parts;
}

/**
 * 日志摘要：直接摊平 details 的键值对，不做任何协议特定拼接。
 * 这样新增协议/新增 details 字段时前端无需改动，展示内容与 event.log 完全一致。
 */
export function summarizeLog(entry: ILogEntry): string {
  const parts = collectPairs(entry, SUMMARY_VALUE_LIMIT, SUMMARY_MAX_PAIRS);

  return parts.length > 0 ? parts.join(' · ') : entry.eventType;
}

/** 悬停提示用：比列表更长，但不含完整对象内容 */
export function summarizeLogFull(entry: ILogEntry): string {
  const parts = collectPairs(entry, TITLE_VALUE_LIMIT, Number.POSITIVE_INFINITY);

  return parts.length > 0 ? parts.join(' · ') : entry.eventType;
}

/** details 展平为两列表格，嵌套对象序列化为 JSON */
export function logDetailRows(entry: ILogEntry): IDetailRow[] {
  return Object.entries(entry.details ?? {}).map(([key, value]) => ({
    key,
    value: typeof value === 'string' ? value : JSON.stringify(value),
  }));
}

/** 与 event.log 完全一致的行格式（snake_case + 2 空格缩进） */
export function logRawJson(entry: ILogEntry): string {
  return JSON.stringify(
    {
      timestamp: entry.timestamp,
      event_category: entry.eventCategory,
      event_type: entry.eventType,
      src_ip: entry.srcIp,
      dst_ip: entry.dstIp,
      ip_protocol: entry.ipProtocol,
      src_port: entry.srcPort,
      dst_port: entry.dstPort,
      details: entry.details,
    },
    null,
    2,
  );
}
