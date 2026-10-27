<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';

import type { ILinePoint } from './types';

const props = withDefaults(
  defineProps<{
    points: ILinePoint[];
    height?: number;
    /** 主轴名称，用于 tooltip */
    valueLabel?: string;
    tone?: 'primary' | 'success';
    /** X 轴最多显示多少个标签 */
    maxLabels?: number;
  }>(),
  { height: 208, valueLabel: '事件数', tone: 'primary', maxLabels: 7 },
);

const container = ref<HTMLElement | null>(null);
const width = ref(640);
const hoverIndex = ref<number | null>(null);

const PADDING = { top: 14, right: 12, bottom: 22, left: 40 };
const gradientId = `chart-gradient-${Math.random().toString(36).slice(2, 8)}`;

let observer: ResizeObserver | null = null;

onMounted(() => {
  if (!container.value) {
    return;
  }

  observer = new ResizeObserver((entries) => {
    const entry = entries[0];

    if (entry) {
      width.value = Math.max(240, entry.contentRect.width);
    }
  });
  observer.observe(container.value);
  width.value = Math.max(240, container.value.clientWidth);
});

onUnmounted(() => observer?.disconnect());

const plotWidth = computed(() => Math.max(80, width.value - PADDING.left - PADDING.right));
const plotHeight = computed(() => Math.max(60, props.height - PADDING.top - PADDING.bottom));

const maxValue = computed(() => {
  const max = Math.max(...props.points.map((point) => point.value), 1);

  return max * 1.15;
});

function xFor(index: number): number {
  if (props.points.length <= 1) {
    return PADDING.left + plotWidth.value / 2;
  }

  return PADDING.left + (index / (props.points.length - 1)) * plotWidth.value;
}

function yFor(value: number): number {
  return PADDING.top + plotHeight.value - (value / maxValue.value) * plotHeight.value;
}

const linePath = computed(() =>
  props.points.map((point, index) => `${index === 0 ? 'M' : 'L'}${xFor(index).toFixed(1)},${yFor(point.value).toFixed(1)}`).join(' '),
);

const areaPath = computed(() => {
  if (props.points.length === 0) {
    return '';
  }

  const bottom = PADDING.top + plotHeight.value;

  return `${linePath.value} L${xFor(props.points.length - 1).toFixed(1)},${bottom} L${PADDING.left},${bottom} Z`;
});

/** 4 条参考线，刻度取整到易读的数量级 */
const gridLines = computed(() => {
  const steps = 4;
  const rawStep = maxValue.value / steps;
  const magnitude = 10 ** Math.floor(Math.log10(Math.max(rawStep, 1)));
  const step = Math.ceil(rawStep / magnitude) * magnitude;

  return Array.from({ length: steps + 1 }, (_, index) => {
    const value = step * index;

    return { value, y: yFor(value) };
  }).filter((item) => item.value <= maxValue.value);
});

const labelStep = computed(() => Math.max(1, Math.ceil(props.points.length / props.maxLabels)));

const activePoint = computed(() => {
  if (hoverIndex.value === null) {
    return null;
  }

  const point = props.points[hoverIndex.value];

  if (!point) {
    return null;
  }

  return {
    ...point,
    x: xFor(hoverIndex.value),
    y: yFor(point.value),
    /** tooltip 左右翻转，避免贴边溢出 */
    flip: xFor(hoverIndex.value) > width.value - 130,
  };
});

function onMove(event: MouseEvent): void {
  const rect = (event.currentTarget as SVGElement).getBoundingClientRect();
  const offsetX = event.clientX - rect.left - PADDING.left;
  const ratio = offsetX / plotWidth.value;
  const index = Math.round(ratio * (props.points.length - 1));

  hoverIndex.value = Math.min(props.points.length - 1, Math.max(0, index));
}
</script>

<template>
  <div ref="container" class="relative w-full">
    <svg
      :viewBox="`0 0 ${width} ${props.height}`"
      :width="width"
      :height="props.height"
      class="block overflow-visible"
      role="img"
      :aria-label="`${props.valueLabel}趋势图`"
      @mousemove="onMove"
      @mouseleave="hoverIndex = null"
    >
      <defs>
        <linearGradient :id="gradientId" x1="0" y1="0" x2="0" y2="1">
          <stop
            offset="0%"
            :stop-color="props.tone === 'success' ? 'rgb(var(--c-success))' : 'rgb(var(--c-primary))'"
            stop-opacity="0.22"
          />
          <stop
            offset="100%"
            :stop-color="props.tone === 'success' ? 'rgb(var(--c-success))' : 'rgb(var(--c-primary))'"
            stop-opacity="0"
          />
        </linearGradient>
      </defs>

      <g>
        <line
          v-for="line in gridLines"
          :key="line.value"
          :x1="PADDING.left"
          :x2="PADDING.left + plotWidth"
          :y1="line.y"
          :y2="line.y"
          class="stroke-line"
          stroke-dasharray="3 4"
          stroke-width="1"
        />
        <text
          v-for="line in gridLines"
          :key="`label-${line.value}`"
          :x="PADDING.left - 6"
          :y="line.y + 3"
          text-anchor="end"
          class="fill-subtle text-[9px] mono-num"
        >
          {{ line.value >= 1000 ? `${(line.value / 1000).toFixed(1)}k` : line.value }}
        </text>
      </g>

      <path :d="areaPath" :fill="`url(#${gradientId})`" />
      <path
        :d="linePath"
        fill="none"
        :class="props.tone === 'success' ? 'stroke-success' : 'stroke-primary'"
        stroke-width="1.8"
        stroke-linecap="round"
        stroke-linejoin="round"
      />

      <g>
        <template v-for="(point, index) in props.points" :key="`${point.label}-${index}`">
          <text
            v-if="index % labelStep === 0 || index === props.points.length - 1"
            :x="xFor(index)"
            :y="props.height - 6"
            text-anchor="middle"
            class="fill-subtle text-[9px]"
          >
            {{ point.label }}
          </text>
        </template>
      </g>

      <g v-if="activePoint">
        <line
          :x1="activePoint.x"
          :x2="activePoint.x"
          :y1="PADDING.top"
          :y2="PADDING.top + plotHeight"
          class="stroke-line-strong"
          stroke-dasharray="3 3"
          stroke-width="1"
        />
        <circle
          :cx="activePoint.x"
          :cy="activePoint.y"
          r="3.5"
          class="fill-surface"
          :class="props.tone === 'success' ? 'stroke-success' : 'stroke-primary'"
          stroke-width="2"
        />
      </g>
    </svg>

    <div
      v-if="activePoint"
      class="pointer-events-none absolute top-1 z-10 min-w-[112px] rounded-card border border-line bg-surface px-2 py-1.5 shadow-lift"
      :style="{ left: `${activePoint.x}px`, transform: activePoint.flip ? 'translateX(calc(-100% - 10px))' : 'translateX(10px)' }"
    >
      <p class="text-2xs text-subtle">{{ activePoint.label }}</p>
      <p class="mono-num mt-0.5 text-sm font-semibold text-ink">
        {{ activePoint.value.toLocaleString('en-US') }}
      </p>
      <p v-if="activePoint.secondary !== undefined" class="text-2xs text-muted">
        {{ activePoint.secondaryLabel ?? '来源 IP' }} {{ activePoint.secondary }}
      </p>
    </div>
  </div>
</template>
