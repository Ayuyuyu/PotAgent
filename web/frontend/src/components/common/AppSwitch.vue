<script setup lang="ts">
import { computed } from 'vue';
import { Loader2 } from 'lucide-vue-next';

const props = withDefaults(
  defineProps<{
    modelValue: boolean;
    disabled?: boolean;
    loading?: boolean;
    size?: 'sm' | 'md';
    label?: string;
  }>(),
  { disabled: false, loading: false, size: 'md', label: '' },
);

const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>();

const isBlocked = computed(() => props.disabled || props.loading);

function toggle(): void {
  if (isBlocked.value) {
    return;
  }

  emit('update:modelValue', !props.modelValue);
}
</script>

<template>
  <button
    type="button"
    role="switch"
    :aria-checked="props.modelValue"
    :aria-label="props.label || '切换开关'"
    :disabled="isBlocked"
    class="relative inline-flex shrink-0 cursor-pointer items-center rounded-full border transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-60"
    :class="[
      props.size === 'sm' ? 'h-4 w-7' : 'h-[18px] w-8',
      props.modelValue ? 'border-primary bg-primary' : 'border-line-strong bg-canvas-tint',
    ]"
    @click="toggle"
  >
    <span
      class="pointer-events-none inline-flex items-center justify-center rounded-full bg-white shadow-sm transition-transform duration-150"
      :class="[
        props.size === 'sm' ? 'h-3 w-3' : 'h-3.5 w-3.5',
        props.modelValue
          ? props.size === 'sm'
            ? 'translate-x-[13px]'
            : 'translate-x-[15px]'
          : 'translate-x-[1px]',
      ]"
    >
      <Loader2 v-if="props.loading" class="h-2 w-2 animate-spin text-primary" />
    </span>
  </button>
</template>
