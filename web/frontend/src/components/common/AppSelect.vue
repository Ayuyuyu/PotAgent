<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { Check, ChevronDown } from 'lucide-vue-next';

import type { ISelectOption } from './types';

const props = withDefaults(
  defineProps<{
    modelValue: string;
    options: ISelectOption[];
    placeholder?: string;
    size?: 'sm' | 'md';
    disabled?: boolean;
  }>(),
  { placeholder: '请选择', size: 'md', disabled: false },
);

const emit = defineEmits<{ 'update:modelValue': [value: string] }>();

const open = ref(false);
const root = ref<HTMLElement | null>(null);

const currentLabel = computed(() => {
  const found = props.options.find((item) => item.value === props.modelValue);

  return found?.label ?? props.placeholder;
});

function choose(value: string): void {
  emit('update:modelValue', value);
  open.value = false;
}

function onDocumentClick(event: MouseEvent): void {
  if (!root.value?.contains(event.target as Node)) {
    open.value = false;
  }
}

onMounted(() => document.addEventListener('click', onDocumentClick));
onUnmounted(() => document.removeEventListener('click', onDocumentClick));
</script>

<template>
  <div ref="root" class="relative">
    <button
      type="button"
      class="flex w-full items-center justify-between gap-2 rounded-card border border-line bg-surface px-2 text-left text-sm text-ink transition-colors duration-150 hover:border-line-strong disabled:opacity-60"
      :class="[
        props.size === 'sm' ? 'h-7' : 'h-8',
        open ? 'border-primary ring-2 ring-primary/15' : '',
      ]"
      :disabled="props.disabled"
      :aria-expanded="open"
      @click="open = !open"
    >
      <span class="truncate">{{ currentLabel }}</span>
      <ChevronDown
        class="h-3.5 w-3.5 shrink-0 text-subtle transition-transform duration-150"
        :class="open ? 'rotate-180' : ''"
      />
    </button>

    <Transition name="dropdown">
      <div
        v-if="open"
        class="absolute left-0 right-0 z-[60] mt-1 max-h-64 overflow-y-auto rounded-card border border-line bg-surface py-1 shadow-lift"
      >
        <button
          v-for="option in props.options"
          :key="option.value"
          type="button"
          class="flex w-full items-center justify-between gap-2 px-2.5 py-1.5 text-left text-sm transition-colors duration-100 hover:bg-surface-hover"
          :class="option.value === props.modelValue ? 'text-primary-ink font-medium' : 'text-ink'"
          @click="choose(option.value)"
        >
          <span class="truncate">{{ option.label }}</span>
          <Check v-if="option.value === props.modelValue" class="h-3.5 w-3.5 text-primary" />
        </button>
      </div>
    </Transition>
  </div>
</template>

<style scoped>
.dropdown-enter-active,
.dropdown-leave-active {
  transition:
    opacity 120ms ease-out,
    transform 120ms ease-out;
}

.dropdown-enter-from,
.dropdown-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}
</style>
