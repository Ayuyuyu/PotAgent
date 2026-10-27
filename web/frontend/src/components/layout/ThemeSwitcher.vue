<script setup lang="ts">
import { computed } from 'vue';

import { useThemeStore } from '@/store/theme';

const theme = useThemeStore();

const currentHint = computed(() => theme.options.find((item) => item.name === theme.current)?.hint ?? '');
</script>

<template>
  <div
    class="flex items-center gap-0.5 rounded-card border border-line bg-surface-alt p-0.5"
    :title="currentHint"
  >
    <button
      v-for="option in theme.options"
      :key="option.name"
      type="button"
      class="flex h-6 items-center gap-1 rounded-[3px] px-1.5 text-2xs font-medium transition-all duration-150"
      :class="
        theme.current === option.name
          ? 'bg-surface text-ink shadow-sm ring-1 ring-line'
          : 'text-muted hover:text-ink'
      "
      :title="option.hint"
      @click="theme.setTheme(option.name)"
    >
      <span class="flex overflow-hidden rounded-[2px] ring-1 ring-black/5">
        <span
          v-for="color in option.swatches"
          :key="color"
          class="h-3 w-1.5"
          :style="{ backgroundColor: color }"
        />
      </span>
      {{ option.label }}
    </button>
  </div>
</template>
