<script setup lang="ts">
import { computed } from 'vue';

import { getProtocolMeta, type ProtocolTone } from '@/constants/protocol';

const props = withDefaults(
  defineProps<{
    protocol: string;
    /** 徽标宽度固定，避免日志列表里参差不齐 */
    fixedWidth?: boolean;
  }>(),
  { fixedWidth: true },
);

const meta = computed(() => getProtocolMeta(props.protocol));

const TONE_CLASS: Record<ProtocolTone, string> = {
  primary: 'bg-primary-soft text-primary-ink border-primary/20',
  info: 'bg-info-soft text-info border-info/20',
  success: 'bg-success-soft text-success border-success/20',
  warning: 'bg-warning-soft text-warning border-warning/20',
  danger: 'bg-danger-soft text-danger border-danger/20',
  accent: 'bg-accent-soft text-accent border-accent/25',
};
</script>

<template>
  <span
    class="inline-flex shrink-0 items-center justify-center overflow-hidden whitespace-nowrap rounded-[3px] border px-1 text-xs font-medium leading-[18px]"
    :class="[TONE_CLASS[meta.tone], props.fixedWidth ? 'w-[84px]' : '']"
    :title="`${meta.group} · ${meta.label}`"
  >
    {{ meta.label }}
  </span>
</template>
