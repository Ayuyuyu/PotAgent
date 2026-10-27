<script setup lang="ts">
import { computed, type Component } from 'vue';
import { TrendingDown, TrendingUp } from 'lucide-vue-next';

import { formatSignedPercent } from '@/utils/format';

type StatTone = 'primary' | 'success' | 'accent' | 'info' | 'danger';

const props = withDefaults(
  defineProps<{
    label: string;
    value: string;
    hint?: string;
    delta?: number | null;
    tone?: StatTone;
    icon: Component;
    /** 底部迷你趋势数据，传空则不渲染 */
    spark?: number[];
  }>(),
  { hint: '', delta: null, tone: 'primary', spark: () => [] },
);

const TONE_BLOCK: Record<StatTone, string> = {
  primary: 'bg-primary/10 text-primary',
  success: 'bg-success/10 text-success',
  accent: 'bg-accent/12 text-accent',
  info: 'bg-info/10 text-info',
  danger: 'bg-danger/10 text-danger',
};

const sparkPath = computed(() => {
  const points = props.spark;

  if (points.length < 2) {
    return '';
  }

  const max = Math.max(...points);
  const min = Math.min(...points);
  const span = max - min || 1;

  return points
    .map((value, index) => {
      const x = (index / (points.length - 1)) * 100;
      const y = 22 - ((value - min) / span) * 18;

      return `${index === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(' ');
});
</script>

<template>
  <article
    class="lift-on-hover group relative flex min-w-0 flex-col gap-2 rounded-card border border-line bg-surface p-3 shadow-card"
  >
    <div class="flex items-start gap-2.5">
      <span
        class="flex h-9 w-9 shrink-0 items-center justify-center rounded-card transition-transform duration-200 group-hover:scale-[1.04]"
        :class="TONE_BLOCK[props.tone]"
      >
        <component :is="props.icon" class="h-[18px] w-[18px]" />
      </span>

      <div class="min-w-0 flex-1">
        <p class="truncate text-2xs font-medium uppercase tracking-wider text-muted">
          {{ props.label }}
        </p>
        <p class="mono-num mt-0.5 text-stat font-semibold text-ink">{{ props.value }}</p>
      </div>

      <span
        v-if="props.delta !== null"
        class="inline-flex shrink-0 items-center gap-0.5 rounded-[3px] px-1 py-0 text-2xs font-medium"
        :class="props.delta >= 0 ? 'bg-success-soft text-success' : 'bg-danger-soft text-danger'"
      >
        <TrendingUp v-if="props.delta >= 0" class="h-2.5 w-2.5" />
        <TrendingDown v-else class="h-2.5 w-2.5" />
        {{ formatSignedPercent(props.delta) }}
      </span>
    </div>

    <div class="flex items-end justify-between gap-2">
      <p v-if="props.hint" class="truncate text-2xs text-subtle">{{ props.hint }}</p>
      <svg v-if="sparkPath" class="h-6 w-16 shrink-0" viewBox="0 0 100 24" preserveAspectRatio="none">
        <path
          :d="sparkPath"
          fill="none"
          :class="props.tone === 'success' ? 'stroke-success' : 'stroke-primary'"
          stroke-width="1.6"
          stroke-linecap="round"
          vector-effect="non-scaling-stroke"
        />
      </svg>
    </div>
  </article>
</template>
