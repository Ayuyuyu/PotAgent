<script setup lang="ts">
import type { Component } from 'vue';
import { Inbox } from 'lucide-vue-next';

const props = withDefaults(
  defineProps<{
    title: string;
    description?: string;
    icon?: Component;
    tone?: 'neutral' | 'danger';
  }>(),
  { description: '', icon: undefined, tone: 'neutral' },
);
</script>

<template>
  <div class="flex flex-col items-center justify-center gap-2 px-4 py-8 text-center">
    <span
      class="flex h-10 w-10 items-center justify-center rounded-full"
      :class="props.tone === 'danger' ? 'bg-danger-soft text-danger' : 'bg-canvas-tint text-subtle'"
    >
      <component :is="props.icon ?? Inbox" class="h-[18px] w-[18px]" />
    </span>
    <p class="text-sm font-medium text-ink">{{ props.title }}</p>
    <p v-if="props.description" class="max-w-[320px] text-xs leading-relaxed text-muted">
      {{ props.description }}
    </p>
    <div v-if="$slots.default" class="mt-1">
      <slot />
    </div>
  </div>
</template>
