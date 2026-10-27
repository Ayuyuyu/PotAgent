import type { IOverviewStats, ITopSource, ITrendPoint, ITrendRange, ITrendSeries } from '../types';
import { getLogFileSize } from './logs';
import { getServiceSummary, totalConnections } from './services';
import { ATTACKER_POOL, createRng, formatTimestamp, intBetween } from './rng';
import { mockState } from './state';

/** 一天内的扫描强度曲线：凌晨低谷，工作日白天高峰 */
function hourFactor(hour: number): number {
  if (hour < 5) return 0.28;
  if (hour < 8) return 0.52;
  if (hour < 11) return 1.06;
  if (hour < 14) return 1.22;
  if (hour < 18) return 1.12;
  if (hour < 22) return 0.86;

  return 0.55;
}

function buildPoints(range: ITrendRange): ITrendPoint[] {
  const rng = createRng(range === 'hour' ? 3101 : range === 'day' ? 3102 : 3103);
  const now = new Date();
  const points: ITrendPoint[] = [];

  if (range === 'hour') {
    for (let i = 23; i >= 0; i -= 1) {
      const at = new Date(now.getTime() - i * 3600 * 1000);
      const base = 42 * hourFactor(at.getHours());
      const value = Math.round(base * (0.82 + rng() * 0.4));

      points.push({
        label: `${String(at.getHours()).padStart(2, '0')}:00`,
        at: formatTimestamp(at),
        value,
        sources: Math.max(3, Math.round(value * (0.42 + rng() * 0.2))),
      });
    }

    return points;
  }

  if (range === 'day') {
    for (let i = 13; i >= 0; i -= 1) {
      const at = new Date(now.getTime() - i * 24 * 3600 * 1000);
      const weekend = at.getDay() === 0 || at.getDay() === 6;
      const value = Math.round(880 * (weekend ? 0.74 : 1) * (0.86 + rng() * 0.3));

      points.push({
        label: `${at.getMonth() + 1}/${at.getDate()}`,
        at: formatTimestamp(at),
        value,
        sources: Math.max(20, Math.round(value * (0.3 + rng() * 0.14))),
      });
    }

    return points;
  }

  for (let i = 7; i >= 0; i -= 1) {
    const at = new Date(now.getTime() - i * 7 * 24 * 3600 * 1000);
    const value = Math.round(6100 * (0.84 + rng() * 0.34));

    points.push({
      label: i === 0 ? '本周' : `W-${i}`,
      at: formatTimestamp(at),
      value,
      sources: Math.max(80, Math.round(value * (0.24 + rng() * 0.1))),
    });
  }

  return points;
}

export function getTrend(range: ITrendRange): ITrendSeries {
  const points = buildPoints(range);
  const total = points.reduce((sum, point) => sum + point.value, 0);
  const peak = points.reduce((best, point) => (point.value > best.value ? point : best), points[0]);
  const rng = createRng(range.length * 97 + 11);

  return {
    range,
    points,
    total,
    deltaPercent: Number(((0.06 + rng() * 0.26) * 100).toFixed(1)),
    peakLabel: peak.label,
  };
}

export function getTopSources(limit = 6): ITopSource[] {
  const rng = createRng(51003);
  let count = 1284;

  return ATTACKER_POOL.slice(0, limit).map((item) => {
    const current = count;
    count = Math.max(24, Math.round(count * (0.58 + rng() * 0.22)));

    return {
      ip: item.ip,
      location: item.location,
      count: current,
      protocols: intBetween(rng, 1, 7),
      lastSeen: formatTimestamp(new Date(Date.now() - intBetween(rng, 30, 3600) * 1000)),
    };
  });
}

export function getOverview(): IOverviewStats {
  const summary = getServiceSummary();

  return {
    totalEvents: mockState.totalEvents,
    todayEvents: mockState.todayEvents,
    todayDeltaPercent: 18.6,
    uniqueSources: mockState.uniqueSources,
    uniqueSourcesDelta: 12,
    activeServices: summary.running,
    totalServices: summary.total,
    connections: totalConnections(),
    logFileSize: getLogFileSize(),
    lastLogAt: formatTimestamp(mockState.lastLogAt),
    uptimeSeconds: Math.floor((Date.now() - mockState.startedAt.getTime()) / 1000),
  };
}
