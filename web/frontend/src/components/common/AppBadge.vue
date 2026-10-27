<script setup lang="ts">
import { computed } from 'vue';

type BadgeTone = 'success' | 'warning' | 'danger' | 'info' | 'primary' | 'accent' | 'neutral';

const props = withDefaults(
  defineProps<{
    tone?: BadgeTone;
    label?: string;
    dot?: boolean;
    pulse?: boolean;
    /** 实心样式用于强调，描边样式用于列表内 */
    solid?: boolean;
  }>(),
  { tone: 'neutral', label: '', dot: false, pulse: false, solid: false },
);

const TONE_SOFT: Record<BadgeTone, string> = {
  success: 'bg-success-soft text-success border-success/25',
  warning: 'bg-warning-soft text-warning border-warning/25',
  danger: 'bg-danger-soft text-danger border-danger/25',
  info: 'bg-info-soft text-info border-info/25',
  primary: 'bg-primary-soft text-primary-ink border-primary/25',
  accent: 'bg-accent-soft text-accent border-accent/30',
  neutral: 'bg-surface-alt text-muted border-line',
};

const TONE_SOLID: Record<BadgeTone, string> = {
  success: 'bg-success text-white border-success',
  warning: 'bg-warning text-white border-warning',
  danger: 'bg-danger text-white border-danger',
  info: 'bg-info text-white border-info',
  primary: 'bg-primary text-white border-primary',
  accent: 'bg-accent text-white border-accent',
  neutral: 'bg-ink text-white border-ink',
};

const classes = computed(() => [
  'inline-flex items-center gap-1 rounded-[3px] border px-1.5 py-0 text-2xs font-medium leading-[17px] whitespace-nowrap',
  props.solid ? TONE_SOLID[props.tone] : TONE_SOFT[props.tone],
]);
</script>

<template>
  <span :class="classes">
    <span
      v-if="props.dot"
      class="status-dot"
      :class="props.pulse ? 'status-dot--live' : ''"
      aria-hidden="true"
    />
    <slot>{{ props.label }}</slot>
  </span>
</template>
