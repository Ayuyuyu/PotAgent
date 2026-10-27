<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { Pause, Play, Search, Timer, Trash2 } from 'lucide-vue-next';

import AppButton from '@/components/common/AppButton.vue';
import AppCard from '@/components/common/AppCard.vue';
import AppInput from '@/components/common/AppInput.vue';
import AppSelect from '@/components/common/AppSelect.vue';
import type { ISelectOption } from '@/components/common/types';
import PageShell from '@/components/layout/PageShell.vue';
import LogDetailDrawer from '@/components/logs/LogDetailDrawer.vue';
import LogStream from '@/components/logs/LogStream.vue';
import { adminApi } from '@/api/client';
import type { ILogEntry, ILogQuery } from '@/api/types';
import { PROTOCOL_META } from '@/constants/protocol';
import { usePolling } from '@/composables/use-polling';
import { formatBytes, formatNumber } from '@/utils/format';

const MAX_BUFFER = 500;

const route = useRoute();

const query = reactive<ILogQuery>({
  keyword: typeof route.query.keyword === 'string' ? route.query.keyword : '',
  protocol: '',
  srcIp: '',
  range: 'all',
  limit: MAX_BUFFER,
});

const entries = ref<ILogEntry[]>([]);
const cursor = ref('');
const matched = ref(0);
const logFileSize = ref(0);
const selected = ref<ILogEntry | null>(null);
const searching = ref(false);

const PROTOCOL_OPTIONS: ISelectOption[] = [
  { label: '全部协议', value: '' },
  ...Object.values(PROTOCOL_META)
    .map((meta) => ({ label: `${meta.label} · ${meta.group}`, value: meta.key }))
    .sort((a, b) => a.label.localeCompare(b.label)),
];

const RANGE_OPTIONS: ISelectOption[] = [
  { label: '不限时间', value: 'all' },
  { label: '最近 5 分钟', value: '5m' },
  { label: '最近 1 小时', value: '1h' },
  { label: '最近 24 小时', value: '24h' },
];

const INTERVAL_OPTIONS: ISelectOption[] = [
  { label: '3 秒', value: '3000' },
  { label: '5 秒', value: '5000' },
  { label: '10 秒', value: '10000' },
];

const intervalValue = ref('3000');

const isFiltering = computed(
  () =>
    query.keyword.trim().length > 0 ||
    query.protocol.length > 0 ||
    query.srcIp.trim().length > 0 ||
    query.range !== 'all',
);

const lastUpdated = computed(() => {
  const stamp = polling.lastRunAt.value;

  return stamp ? stamp.toLocaleTimeString('zh-CN', { hour12: false }) : '—';
});

const modeLabel = computed(() => (isFiltering.value ? '查询结果' : '实时追加'));

/** 后端按时间倒序返回，新日志整体插到最前面；裁剪时丢掉最旧的一段 */
function prependEntries(list: ILogEntry[]): void {
  if (list.length === 0) {
    return;
  }

  entries.value = [...list, ...entries.value].slice(0, MAX_BUFFER);
}

async function tick(): Promise<void> {
  searching.value = true;

  if (isFiltering.value) {
    await adminApi
      .searchLogs(query)
      .then((result) => {
        entries.value = result.entries;
        matched.value = result.matched;
        logFileSize.value = result.logFileSize;
      })
      .catch((reason: unknown) => console.error('查询日志失败', reason));

    searching.value = false;

    return;
  }

  await adminApi
    .tailLogs(query, cursor.value)
    .then((result) => {
      if (result.truncated) {
        // 日志被截断/轮转，服务端已回退到文件尾部，直接整体替换
        entries.value = result.entries;
      } else {
        prependEntries(result.entries);
      }

      cursor.value = result.cursor;
      logFileSize.value = result.logFileSize;
      matched.value = entries.value.length;
    })
    .catch((reason: unknown) => console.error('拉取日志失败', reason));

  searching.value = false;
}

const polling = usePolling(tick, { interval: 3000, pauseWhenHidden: true });

let debounceTimer: number | null = null;

function scheduleSearch(): void {
  if (debounceTimer !== null) {
    window.clearTimeout(debounceTimer);
  }

  debounceTimer = window.setTimeout(() => {
    if (polling.isPaused.value) {
      void tick();

      return;
    }

    void tick();
  }, 320);
}

watch(
  () => [query.keyword, query.protocol, query.srcIp, query.range],
  () => scheduleSearch(),
);

watch(
  () => route.query.keyword,
  (value) => {
    if (typeof value === 'string' && value !== query.keyword) {
      query.keyword = value;
    }
  },
);

watch(intervalValue, (value) => {
  polling.setInterval(Number(value));
});

function clearFilters(): void {
  query.keyword = '';
  query.protocol = '';
  query.srcIp = '';
  query.range = 'all';
}

function toggleAutoRefresh(): void {
  if (polling.isPaused.value) {
    polling.resume();
  } else {
    polling.pause();
  }
}

onMounted(() => {
  cursor.value = '';
});
</script>

<template>
  <PageShell title="实时日志" description="读取 event.log，按行追加并支持关键字高亮" fill>
    <template #actions>
      <span class="text-2xs text-subtle">
        {{ polling.isPaused.value ? '自动刷新已暂停' : `每 ${Number(intervalValue) / 1000} 秒拉取` }}
      </span>
      <AppSelect v-model="intervalValue" :options="INTERVAL_OPTIONS" size="sm" class="w-[88px]" />
      <AppButton
        size="sm"
        :variant="polling.isPaused.value ? 'primary' : 'ghost'"
        @click="toggleAutoRefresh"
      >
        <template #icon>
          <Play v-if="polling.isPaused.value" class="h-3.5 w-3.5" />
          <Pause v-else class="h-3.5 w-3.5" />
        </template>
        {{ polling.isPaused.value ? '继续' : '暂停' }}
      </AppButton>
    </template>

    <AppCard class="min-h-0 flex-1" :padded="false">
      <div class="flex h-full min-h-0 flex-col">
        <div class="flex shrink-0 flex-wrap items-center gap-2 border-b border-line px-2 py-2">
          <AppInput
            v-model="query.keyword"
            class="min-w-[220px] flex-1"
            :prefix-icon="Search"
            placeholder="搜索 IP、用户名、命令、URI…（回车立即查询）"
            clearable
            @enter="tick"
          />
          <AppSelect v-model="query.protocol" :options="PROTOCOL_OPTIONS" class="w-[168px]" />
          <AppInput
            v-model="query.srcIp"
            class="w-[150px]"
            placeholder="来源 IP 前缀"
            mono
            clearable
          />
          <AppSelect v-model="query.range" :options="RANGE_OPTIONS" class="w-[128px]" />
          <AppButton size="sm" variant="subtle" title="清空筛选" @click="clearFilters">
            <template #icon>
              <Trash2 class="h-3.5 w-3.5" />
            </template>
            清空
          </AppButton>
        </div>

        <div
          class="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1 border-b border-line bg-surface-alt px-2.5 py-1.5 text-xs text-muted"
        >
          <span class="flex items-center gap-1 font-medium text-primary-ink">
            <Timer class="h-3 w-3" />
            {{ modeLabel }}
          </span>
          <span class="mono-num">
            命中 <strong class="text-ink">{{ formatNumber(matched) }}</strong> 条
          </span>
          <span class="mono-num hidden sm:inline">缓冲 {{ entries.length }}/{{ MAX_BUFFER }}</span>
          <span class="mono-num hidden md:inline">日志大小 {{ formatBytes(logFileSize) }}</span>
          <span class="ml-auto mono-num">更新于 {{ lastUpdated }}</span>
          <span v-if="searching" class="text-primary">同步中…</span>
        </div>

        <LogStream
          :entries="entries"
          :keyword="query.keyword"
          :selected-id="selected?.id ?? ''"
          @select="selected = $event"
        />
      </div>
    </AppCard>

    <LogDetailDrawer :entry="selected" @close="selected = null" />
  </PageShell>
</template>
