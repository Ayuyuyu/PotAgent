<script setup lang="ts">
import { computed, type Component } from 'vue';
import { X } from 'lucide-vue-next';

const props = withDefaults(
  defineProps<{
    modelValue: string;
    placeholder?: string;
    type?: 'text' | 'search' | 'password' | 'number';
    size?: 'sm' | 'md';
    prefixIcon?: Component;
    clearable?: boolean;
    disabled?: boolean;
    maxlength?: number;
    /** 是否使用等宽字体（IP、端口等输入） */
    mono?: boolean;
  }>(),
  {
    placeholder: '',
    type: 'text',
    size: 'md',
    prefixIcon: undefined,
    clearable: false,
    disabled: false,
    maxlength: undefined,
    mono: false,
  },
);

const emit = defineEmits<{ 'update:modelValue': [value: string]; enter: [] }>();

const hasValue = computed(() => props.modelValue.length > 0);

function onInput(event: Event): void {
  emit('update:modelValue', (event.target as HTMLInputElement).value);
}

function clear(): void {
  emit('update:modelValue', '');
}
</script>

<template>
  <div
    class="group flex items-center gap-1.5 rounded-card border border-line bg-surface px-2 transition-all duration-150 focus-within:border-primary focus-within:ring-2 focus-within:ring-primary/15"
    :class="[props.size === 'sm' ? 'h-7' : 'h-8', props.disabled ? 'opacity-60' : '']"
  >
    <component
      :is="props.prefixIcon"
      v-if="props.prefixIcon"
      class="h-3.5 w-3.5 shrink-0 text-subtle transition-colors group-focus-within:text-primary"
    />
    <input
      :value="props.modelValue"
      :type="props.type"
      :placeholder="props.placeholder"
      :disabled="props.disabled"
      :maxlength="props.maxlength"
      class="h-full w-full min-w-0 border-0 bg-transparent p-0 text-sm text-ink outline-none placeholder:text-subtle focus:outline-none"
      :class="props.mono ? 'mono-num text-xs' : ''"
      @input="onInput"
      @keyup.enter="emit('enter')"
    />
    <button
      v-if="props.clearable && hasValue"
      type="button"
      class="flex h-4 w-4 shrink-0 items-center justify-center rounded-full text-subtle transition-colors hover:bg-canvas-tint hover:text-ink"
      title="清除"
      @click="clear"
    >
      <X class="h-3 w-3" />
    </button>
  </div>
</template>
