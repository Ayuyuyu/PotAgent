<script setup lang="ts">
import { computed } from 'vue';
import { ChevronRight } from 'lucide-vue-next';

import type { ILogEntry } from '@/api/types';
import { summarizeLog, summarizeLogFull } from '@/utils/log-format';
import HighlightText from './HighlightText.vue';
import ProtocolTag from './ProtocolTag.vue';

const props = withDefaults(
  defineProps<{
    entry: ILogEntry;
    keyword?: string;
    selected?: boolean;
  }>(),
  { keyword: '', selected: false },
);

const emit = defineEmits<{ select: [entry: ILogEntry] }>();

const summary = computed(() => summarizeLog(props.entry));
const summaryTitle = computed(() => summarizeLogFull(props.entry));
const endpoint = computed(() => `${props.entry.dstIp}:${props.entry.dstPort}`);
</script>

<template>
  <button
    type="button"
    class="group grid h-[34px] w-full grid-cols-[64px_84px_116px_1fr_16px] items-center gap-2.5 border-b border-line/60 px-2.5 text-left transition-colors duration-100 hover:bg-surface-hover"
    :class="props.selected ? 'bg-primary-soft/70' : ''"
    @click="emit('select', props.entry)"
  >
    <span class="mono-num truncate text-xs text-muted">{{ props.entry.timestamp.slice(11) }}</span>

    <ProtocolTag :protocol="props.entry.eventCategory" />

    <span class="mono-num truncate text-xs text-muted">
      <HighlightText :text="props.entry.srcIp" :keyword="props.keyword" />
    </span>

    <span class="flex min-w-0 items-center gap-2">
      <span class="truncate text-sm text-ink" :title="summaryTitle">
        <HighlightText :text="summary" :keyword="props.keyword" />
      </span>
      <span class="mono-num hidden shrink-0 text-xs text-subtle xl:inline">
        → <HighlightText :text="endpoint" :keyword="props.keyword" />
      </span>
    </span>

    <ChevronRight
      class="h-3 w-3 text-subtle opacity-0 transition-opacity duration-150 group-hover:opacity-100"
    />
  </button>
</template>
