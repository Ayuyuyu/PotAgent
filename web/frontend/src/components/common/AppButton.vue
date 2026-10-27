<script setup lang="ts">
import { computed } from 'vue';
import { Loader2 } from 'lucide-vue-next';

type ButtonVariant = 'primary' | 'ghost' | 'danger' | 'subtle';

const props = withDefaults(
  defineProps<{
    variant?: ButtonVariant;
    size?: 'sm' | 'md';
    loading?: boolean;
    disabled?: boolean;
    block?: boolean;
    type?: 'button' | 'submit';
    title?: string;
  }>(),
  {
    variant: 'ghost',
    size: 'md',
    loading: false,
    disabled: false,
    block: false,
    type: 'button',
    title: undefined,
  },
);

const VARIANT_CLASS: Record<ButtonVariant, string> = {
  primary:
    'bg-primary text-white border border-primary shadow-sm hover:bg-primary-hover hover:border-primary-hover',
  ghost:
    'bg-surface text-ink border border-line hover:bg-surface-hover hover:border-line-strong',
  danger:
    'bg-danger text-white border border-danger hover:brightness-95',
  subtle:
    'bg-transparent text-muted border border-transparent hover:text-ink hover:bg-surface-hover',
};

const classes = computed(() => [
  'inline-flex items-center justify-center gap-1.5 rounded-card font-medium tracking-wide transition-all duration-150 active:translate-y-px disabled:pointer-events-none disabled:opacity-50',
  props.size === 'sm' ? 'h-7 px-2.5 text-xs' : 'h-8 px-3 text-sm',
  VARIANT_CLASS[props.variant],
  props.block ? 'w-full' : '',
]);
</script>

<template>
  <button
    :type="props.type"
    :class="classes"
    :disabled="props.disabled || props.loading"
    :title="props.title"
  >
    <Loader2 v-if="props.loading" class="h-3.5 w-3.5 animate-spin" />
    <slot v-else name="icon" />
    <slot />
  </button>
</template>
