export function formatNumber(value: number): string {
  return value.toLocaleString('en-US');
}

/** 大数字压缩为 12.8k / 1.2M，用于空间紧张的卡片 */
export function formatCompact(value: number): string {
  if (value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(1)}M`;
  }

  if (value >= 1000) {
    return `${(value / 1000).toFixed(1)}k`;
  }

  return String(value);
}

/** event.log 的时间格式是 `YYYY-MM-DD HH:mm:ss`，Safari 需要替换空格 */
export function parseTimestamp(value: string | null | undefined): Date | null {
  if (!value) {
    return null;
  }

  const normalized = value.includes('T') ? value : value.replace(' ', 'T');
  const date = new Date(normalized);

  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatRelative(value: string | null | undefined): string {
  const date = parseTimestamp(value);

  if (!date) {
    return '—';
  }

  const diff = Math.floor((Date.now() - date.getTime()) / 1000);

  if (diff < 5) return '刚刚';
  if (diff < 60) return `${diff} 秒前`;
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`;

  return `${Math.floor(diff / 86400)} 天前`;
}

export function formatDuration(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  if (days > 0) {
    return `${days} 天 ${hours} 小时`;
  }

  if (hours > 0) {
    return `${hours} 小时 ${minutes} 分`;
  }

  return `${minutes} 分`;
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }

  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  return `${bytes} B`;
}

export function formatSignedPercent(value: number): string {
  const sign = value >= 0 ? '+' : '';

  return `${sign}${value.toFixed(1)}%`;
}

/** 从 host:port 里只取端口，用于紧凑展示 */
export function formatEndpoint(host: string, port: number): string {
  return `${host === '0.0.0.0' ? '*' : host}:${port}`;
}
