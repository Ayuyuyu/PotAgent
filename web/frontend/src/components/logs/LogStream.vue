<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue';

import type { ILogEntry } from '@/api/types';
import EmptyState from '@/components/common/EmptyState.vue';
import LogRow from './LogRow.vue';

const props = withDefaults(
  defineProps<{
    entries: ILogEntry[];
    keyword?: string;
    selectedId?: string;
  }>(),
  { keyword: '', selectedId: '' },
);

const emit = defineEmits<{ select: [entry: ILogEntry] }>();

const scroller = ref<HTMLElement | null>(null);

const rowCount = computed(() => props.entries.length);

/**
 * 新日志从顶部插入。用户正停在顶部时无需处理；已经往下翻时按新增内容的高度
 * 补偿 scrollTop，避免每次轮询都把正在看的内容顶走。
 */
watch(rowCount, async (next, prev) => {
  const element = scroller.value;

  if (!element || next <= prev) {
    return;
  }

  const anchorTop = element.scrollTop;
  const beforeHeight = element.scrollHeight;

  if (anchorTop <= 0) {
    return;
  }

  await nextTick();

  element.scrollTop = anchorTop + (element.scrollHeight - beforeHeight);
});

function scrollToTop(): void {
  scroller.value?.scrollTo({ top: 0 });
}
</script>

<template>
  <div class="flex min-h-0 flex-1 flex-col">
    <div
      class="grid h-8 shrink-0 grid-cols-[64px_84px_116px_1fr_16px] items-center gap-2.5 border-b border-line bg-surface-alt px-2.5 text-xs font-medium text-muted"
    >
      <span>时间</span>
      <span>协议</span>
      <span>来源 IP</span>
      <span>摘要</span>
      <span />
    </div>

    <div ref="scroller" class="min-h-0 flex-1 overflow-y-auto">
      <LogRow
        v-for="entry in props.entries"
        :key="entry.id"
        :entry="entry"
        :keyword="props.keyword"
        :selected="entry.id === props.selectedId"
        @select="emit('select', $event)"
      />

      <EmptyState
        v-if="props.entries.length === 0"
        title="没有匹配的日志"
        description="调整关键字或时间范围后重试；服务未启用时不会产生事件"
      />
    </div>

    <div
      class="flex h-7 shrink-0 items-center justify-between border-t border-line bg-surface-alt px-2.5 text-xs text-subtle"
    >
      <span class="mono-num">共 {{ props.entries.length }} 行</span>
      <button
        type="button"
        class="flex items-center gap-1 rounded-[3px] px-1 py-0.5 transition-colors hover:bg-surface-hover hover:text-ink"
        @click="scrollToTop"
      >
        <span class="status-dot status-dot--live text-success" />
        最新在上
      </button>
    </div>
  </div>
</template>
