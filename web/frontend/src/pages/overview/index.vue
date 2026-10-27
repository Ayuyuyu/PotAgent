<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import { Activity, ArrowRight, Database, Globe2, Radio, RefreshCw, Server, Trash2 } from 'lucide-vue-next';

import BarChart from '@/components/charts/BarChart.vue';
import LineChart from '@/components/charts/LineChart.vue';
import type { IBarItem } from '@/components/charts/types';
import AppBadge from '@/components/common/AppBadge.vue';
import AppButton from '@/components/common/AppButton.vue';
import AppCard from '@/components/common/AppCard.vue';
import AppModal from '@/components/common/AppModal.vue';
import EmptyState from '@/components/common/EmptyState.vue';
import StatCard from '@/components/common/StatCard.vue';
import PageShell from '@/components/layout/PageShell.vue';
import ProtocolTag from '@/components/logs/ProtocolTag.vue';
import { adminApi } from '@/api/client';
import type { ILogEntry, ILogQuery, IOverviewStats, IServiceItem, ITopSource, ITrendRange, ITrendSeries } from '@/api/types';
import { usePolling } from '@/composables/use-polling';
import { useToast } from '@/composables/use-toast';
import { formatBytes, formatNumber, formatRelative } from '@/utils/format';
import { summarizeLog, summarizeLogFull } from '@/utils/log-format';

const router = useRouter();
const toast = useToast();

const overview = ref<IOverviewStats | null>(null);
const trendRange = ref<ITrendRange>('hour');
const trend = ref<ITrendSeries | null>(null);
const topSources = ref<ITopSource[]>([]);
const recent = ref<ILogEntry[]>([]);
const services = ref<IServiceItem[]>([]);
const trendLoading = ref(false);

const TREND_OPTIONS: Array<{ value: ITrendRange; label: string }> = [
  { value: 'hour', label: '小时' },
  { value: 'day', label: '日' },
  { value: 'week', label: '周' },
];

const EMPTY_QUERY: ILogQuery = { keyword: '', protocol: '', srcIp: '', range: 'all', limit: 8 };

const STATUS_ORDER = { error: 0, running: 1, stopped: 2 } as const;

/** 按事件数从多到少；事件数相同时异常/运行中优先，再按名称稳定排序 */
const healthList = computed(() =>
  [...services.value]
    .sort(
      (a, b) =>
        b.events - a.events ||
        STATUS_ORDER[a.status] - STATUS_ORDER[b.status] ||
        a.application.localeCompare(b.application),
    )
    .slice(0, 5),
);

const topSourceItems = computed<IBarItem[]>(() =>
  topSources.value.map((item, index) => ({
    id: item.ip,
    label: item.ip,
    value: item.count,
    hint: `#${index + 1}`,
    meta: item.location,
  })),
);

const trendPoints = computed(() =>
  (trend.value?.points ?? []).map((point) => ({
    label: point.label,
    value: point.value,
    secondary: point.sources,
    secondaryLabel: '来源 IP',
  })),
);

const sparkValues = computed(() => (trend.value?.points ?? []).map((point) => point.value));
const sparkSources = computed(() => (trend.value?.points ?? []).map((point) => point.sources));

async function loadOverview(): Promise<void> {
  await adminApi
    .overview()
    .then((data) => {
      overview.value = data;
    })
    .catch((reason: unknown) => console.error('加载概览失败', reason));
}

async function loadTrend(): Promise<void> {
  trendLoading.value = true;

  await adminApi
    .trend(trendRange.value)
    .then((data) => {
      trend.value = data;
    })
    .catch((reason: unknown) => console.error('加载趋势失败', reason));

  trendLoading.value = false;
}

async function loadRecent(): Promise<void> {
  await adminApi
    .tailLogs(EMPTY_QUERY, '')
    .then((result) => {
      // 服务端按时间倒序返回，直接取前 8 条即最新的 8 条
      recent.value = result.entries.slice(0, EMPTY_QUERY.limit);
    })
    .catch((reason: unknown) => console.error('加载最新事件失败', reason));
}

async function loadSidebar(): Promise<void> {
  await Promise.all([
    adminApi.services().then((list) => {
      services.value = list;
    }),
    adminApi.topSources(6).then((list) => {
      topSources.value = list;
    }),
  ]).catch((reason: unknown) => console.error('加载侧栏数据失败', reason));
}

const polling = usePolling(
  async () => {
    await Promise.all([loadOverview(), loadRecent()]);
  },
  { interval: 5000, pauseWhenHidden: true },
);

function refreshAll(): void {
  void Promise.all([loadOverview(), loadTrend(), loadRecent(), loadSidebar()]);
}

const resetOpen = ref(false);
const resetting = ref(false);

/** 清空统计库里的历史数据（不动 event.log 本身） */
async function confirmReset(): Promise<void> {
  resetting.value = true;

  try {
    await adminApi.resetStats();

    resetOpen.value = false;
    toast.success('统计已清空', '累计事件与来源已归零，服务事件数同步重置');
    await Promise.all([loadOverview(), loadTrend(), loadRecent(), loadSidebar()]);
  } catch (reason: unknown) {
    toast.error('清空统计失败', reason instanceof Error ? reason.message : '请查看主进程日志');
  } finally {
    resetting.value = false;
  }
}

function switchRange(range: ITrendRange): void {
  if (trendRange.value === range) {
    return;
  }

  trendRange.value = range;
  void loadTrend();
}

function openLogs(entry?: ILogEntry): void {
  void router.push({
    name: 'logs',
    query: entry ? { keyword: entry.srcIp } : {},
  });
}

onMounted(() => {
  void loadSidebar();
  void loadTrend();
});

const lastUpdated = computed(() => (polling.lastRunAt.value ? formatRelative(polling.lastRunAt.value.toISOString()) : '—'));
</script>

<template>
  <PageShell title="概览" description="蜜罐事件实时汇总与运行状态">
    <template #actions>
      <span class="hidden items-center gap-1.5 text-2xs text-subtle sm:flex">
        <Radio class="h-3 w-3 text-success" />
        {{ lastUpdated }}更新
      </span>
      <AppButton size="sm" variant="subtle" title="清空统计库中的历史统计" @click="resetOpen = true">
        <template #icon>
          <Trash2 class="h-3.5 w-3.5" />
        </template>
        清空统计
      </AppButton>
      <AppButton size="sm" :loading="polling.isRunning.value" @click="refreshAll">
        <template #icon>
          <RefreshCw class="h-3.5 w-3.5" />
        </template>
        刷新
      </AppButton>
    </template>

    <div class="grid grid-cols-1 gap-3 md:grid-cols-3">
      <StatCard
        label="累计事件"
        :value="formatNumber(overview?.totalEvents ?? 0)"
        :hint="`今日 +${formatNumber(overview?.todayEvents ?? 0)} · ${overview?.lastLogAt ?? '—'}`"
        :delta="overview?.todayDeltaPercent ?? null"
        tone="primary"
        :icon="Database"
        :spark="sparkValues"
      />
      <StatCard
        label="活跃服务"
        :value="`${overview?.activeServices ?? 0}/${overview?.totalServices ?? 0}`"
        :hint="`${(overview?.totalServices ?? 0) - (overview?.activeServices ?? 0)} 个未启用 · ${overview?.connections ?? 0} 条连接`"
        tone="success"
        :icon="Server"
      />
      <StatCard
        label="独立来源 IP"
        :value="formatNumber(overview?.uniqueSources ?? 0)"
        :hint="`近 24 小时 · 日志 ${formatBytes(overview?.logFileSize ?? 0)}`"
        :delta="overview?.uniqueSourcesDelta ?? null"
        tone="accent"
        :icon="Globe2"
        :spark="sparkSources"
      />
    </div>

    <div class="grid min-h-0 grid-cols-1 gap-3 lg:grid-cols-3">
      <AppCard
        class="lg:col-span-2"
        title="事件趋势"
        :subtitle="trend ? `峰值 ${trend.peakLabel} · 环比 +${trend.deltaPercent}%` : ''"
        collapsible
      >
        <template #actions>
          <div class="flex items-center rounded-card border border-line bg-surface-alt p-0.5">
            <button
              v-for="option in TREND_OPTIONS"
              :key="option.value"
              type="button"
              class="h-5 rounded-[3px] px-1.5 text-2xs font-medium transition-all duration-150"
              :class="
                trendRange === option.value
                  ? 'bg-surface text-primary-ink shadow-sm ring-1 ring-line'
                  : 'text-muted hover:text-ink'
              "
              @click="switchRange(option.value)"
            >
              {{ option.label }}
            </button>
          </div>
        </template>

        <div v-if="trendLoading && !trend" class="flex h-[208px] items-center justify-center text-xs text-subtle">
          加载趋势…
        </div>
        <LineChart v-else-if="trendPoints.length > 0" :points="trendPoints" :height="208" />

        <div class="mt-1 flex items-center gap-4 border-t border-line pt-2 text-2xs text-muted">
          <span class="flex items-center gap-1">
            <span class="h-1.5 w-1.5 rounded-full bg-primary" />事件数
          </span>
          <span class="flex items-center gap-1">
            <span class="h-1.5 w-1.5 rounded-full bg-accent" />独立来源
          </span>
          <span class="ml-auto text-subtle">累计 {{ formatNumber(trend?.total ?? 0) }} 条</span>
        </div>
      </AppCard>

      <AppCard title="服务健康" :subtitle="`${services.length} 个实例 · 按事件数排序`" collapsible>
        <template #actions>
          <button
            type="button"
            class="flex items-center gap-0.5 text-2xs text-primary hover:underline"
            @click="router.push({ name: 'services' })"
          >
            全部
            <ArrowRight class="h-2.5 w-2.5" />
          </button>
        </template>

        <ul class="flex flex-col">
          <li
            v-for="item in healthList"
            :key="item.file"
            class="edge-bar flex items-center gap-2 border-b border-line/70 py-2 pl-2.5 last:border-0"
            :class="
              item.status === 'error'
                ? 'edge-bar--danger'
                : item.status === 'running'
                  ? 'edge-bar--success'
                  : 'edge-bar--muted'
            "
          >
            <ProtocolTag :protocol="item.protocol" />
            <div class="min-w-0 flex-1">
              <p class="truncate text-xs font-medium text-ink">{{ item.application }}</p>
              <p class="mono-num truncate text-2xs text-subtle">
                {{ item.host }}:{{ item.port }} · {{ item.events }} 事件
              </p>
            </div>
            <AppBadge
              :tone="item.status === 'error' ? 'danger' : item.status === 'running' ? 'success' : 'neutral'"
              :label="item.status === 'error' ? '异常' : item.status === 'running' ? '运行中' : '已停止'"
              dot
              :pulse="item.status === 'running'"
            />
          </li>
        </ul>

        <EmptyState v-if="healthList.length === 0" title="暂无服务实例" description="请检查 services_conf 目录" />
      </AppCard>
    </div>

    <div class="grid min-h-0 grid-cols-1 gap-3 lg:grid-cols-3">
      <AppCard class="lg:col-span-2" title="最新事件" subtitle="每 5 秒自动刷新" collapsible>
        <template #actions>
          <AppButton size="sm" variant="subtle" @click="openLogs()">
            查看全部
            <template #icon>
              <ArrowRight class="h-3 w-3" />
            </template>
          </AppButton>
        </template>

        <ul class="flex flex-col">
          <li v-for="entry in recent" :key="entry.id">
            <button
              type="button"
              class="flex w-full items-center gap-2 rounded-[3px] border-b border-line/60 px-1 py-1.5 text-left transition-colors duration-100 last:border-0 hover:bg-surface-hover"
              @click="openLogs(entry)"
            >
              <span class="mono-num w-[58px] shrink-0 text-2xs text-subtle">
                {{ entry.timestamp.slice(11) }}
              </span>
              <ProtocolTag :protocol="entry.eventCategory" />
              <span class="mono-num w-[108px] shrink-0 truncate text-2xs text-muted">{{ entry.srcIp }}</span>
              <span class="min-w-0 flex-1 truncate text-xs text-ink" :title="summarizeLogFull(entry)">
                {{ summarizeLog(entry) }}
              </span>
            </button>
          </li>
        </ul>

        <EmptyState
          v-if="recent.length === 0"
          title="还没有事件"
          description="服务启动后，攻击探测会实时出现在这里"
        />
      </AppCard>

      <AppCard title="攻击来源 Top" subtitle="近 24 小时" collapsible>
        <BarChart v-if="topSourceItems.length > 0" :items="topSourceItems" />
        <EmptyState v-else title="暂无来源数据" />
        <template #footer>
          <p class="flex items-center gap-1 text-2xs text-subtle">
            <Activity class="h-3 w-3" />
            按源 IP 聚合，含未命中协议的探测
          </p>
        </template>
      </AppCard>
    </div>

    <AppModal
      v-model="resetOpen"
      title="清空统计数据？"
      confirm-text="清空"
      tone="danger"
      :loading="resetting"
      @confirm="confirmReset"
    >
      <ul class="flex flex-col gap-1.5 text-xs leading-relaxed text-muted">
        <li>累计事件、趋势图、独立来源 IP、攻击来源 Top 会归零</li>
        <li>服务健康里各实例的事件数同样归零</li>
        <li>不会删除 event.log 文件本身</li>
        <li>清空后从当前日志末尾继续累计，历史日志不会被重新统计</li>
      </ul>
    </AppModal>
  </PageShell>
</template>
