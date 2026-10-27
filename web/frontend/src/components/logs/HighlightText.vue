<script setup lang="ts">
import { computed } from 'vue';

import { splitHighlight } from '@/utils/highlight';

const props = withDefaults(
  defineProps<{
    text: string;
    keyword?: string;
  }>(),
  { keyword: '' },
);

const segments = computed(() => splitHighlight(props.text, props.keyword));

const hasMatch = computed(() => segments.value.some((segment) => segment.matched));
</script>

<template>
  <span class="break-all">
    <template v-for="(segment, index) in segments" :key="`${index}-${segment.matched}`">
      <mark
        v-if="segment.matched"
        class="rounded-[2px] bg-mark px-[1px] text-ink"
        :class="hasMatch ? 'font-medium' : ''"
      >
        {{ segment.text }}
      </mark>
      <span v-else>{{ segment.text }}</span>
    </template>
  </span>
</template>
