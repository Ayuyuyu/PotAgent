<script setup lang="ts">
import { computed } from 'vue';

import type { IBarItem } from './types';

const props = withDefaults(
  defineProps<{
    items: IBarItem[];
    /** 数值单位，用于右侧说明 */
    unit?: string;
  }>(),
  { unit: '次' },
);

const maxValue = computed(() => Math.max(...props.items.map((item) => item.value), 1));

function widthOf(value: number): string {
  return `${Math.max(2, (value / maxValue.value) * 100).toFixed(1)}%`;
}
</script>

<template>
  <ul class="flex flex-col gap-2">
    <li v-for="(item, index) in props.items" :key="item.id" class="group">
      <div class="flex items-baseline justify-between gap-2">
        <div class="flex min-w-0 items-baseline gap-1.5">
          <span class="mono-num truncate text-xs font-medium text-ink">{{ item.label }}</span>
          <span v-if="item.meta" class="truncate text-2xs text-subtle">{{ item.meta }}</span>
        </div>
        <span class="mono-num shrink-0 text-xs text-muted">
          {{ item.value.toLocaleString('en-US') }}
          <span class="text-2xs text-subtle">{{ props.unit }}</span>
        </span>
      </div>

      <div class="mt-1 flex items-center gap-2">
        <div class="h-1.5 flex-1 overflow-hidden rounded-full bg-canvas-tint">
          <div
            class="h-full rounded-full transition-all duration-300"
            :class="index === 0 ? 'bg-accent' : 'bg-primary/65 group-hover:bg-primary'"
            :style="{ width: widthOf(item.value) }"
          />
        </div>
        <span v-if="item.hint" class="shrink-0 text-2xs text-subtle">{{ item.hint }}</span>
      </div>
    </li>
  </ul>
</template>
