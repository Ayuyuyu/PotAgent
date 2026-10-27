<script setup lang="ts">
import { onUnmounted, watch } from 'vue';
import { AlertTriangle, X } from 'lucide-vue-next';

import AppButton from './AppButton.vue';

const props = withDefaults(
  defineProps<{
    modelValue: boolean;
    title: string;
    description?: string;
    confirmText?: string;
    cancelText?: string;
    tone?: 'primary' | 'danger';
    loading?: boolean;
  }>(),
  {
    description: '',
    confirmText: '确认',
    cancelText: '取消',
    tone: 'primary',
    loading: false,
  },
);

const emit = defineEmits<{ 'update:modelValue': [value: boolean]; confirm: [] }>();

function close(): void {
  if (props.loading) {
    return;
  }

  emit('update:modelValue', false);
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape') {
    close();
  }
}

watch(
  () => props.modelValue,
  (open) => {
    document.body.style.overflow = open ? 'hidden' : '';

    if (open) {
      document.addEventListener('keydown', onKeydown);
    } else {
      document.removeEventListener('keydown', onKeydown);
    }
  },
);

onUnmounted(() => {
  document.body.style.overflow = '';
  document.removeEventListener('keydown', onKeydown);
});
</script>

<template>
  <Teleport to="body">
    <Transition name="modal">
      <div
        v-if="props.modelValue"
        class="fixed inset-0 z-[80] flex items-center justify-center bg-ink/25 px-4 backdrop-blur-[2px]"
        role="dialog"
        aria-modal="true"
        @click.self="close"
      >
        <div class="w-full max-w-[420px] overflow-hidden rounded-card border border-line bg-surface shadow-lift">
          <header class="flex items-start gap-2.5 border-b border-line px-4 py-3">
            <span
              v-if="props.tone === 'danger'"
              class="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-danger-soft text-danger"
            >
              <AlertTriangle class="h-3.5 w-3.5" />
            </span>
            <div class="min-w-0 flex-1">
              <h3 class="text-sm font-semibold text-ink">{{ props.title }}</h3>
              <p v-if="props.description" class="mt-1 text-xs leading-relaxed text-muted">
                {{ props.description }}
              </p>
            </div>
            <button
              type="button"
              class="flex h-5 w-5 items-center justify-center rounded-[3px] text-subtle transition-colors hover:bg-surface-hover hover:text-ink"
              title="关闭"
              @click="close"
            >
              <X class="h-3.5 w-3.5" />
            </button>
          </header>

          <div v-if="$slots.default" class="px-4 py-3">
            <slot />
          </div>

          <footer class="flex items-center justify-end gap-2 border-t border-line bg-surface-alt px-4 py-2.5">
            <AppButton size="sm" :disabled="props.loading" @click="close">{{ props.cancelText }}</AppButton>
            <AppButton
              size="sm"
              :variant="props.tone === 'danger' ? 'danger' : 'primary'"
              :loading="props.loading"
              @click="emit('confirm')"
            >
              {{ props.confirmText }}
            </AppButton>
          </footer>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.modal-enter-active,
.modal-leave-active {
  transition: opacity 160ms ease-out;
}

.modal-enter-active > div,
.modal-leave-active > div {
  transition: transform 180ms cubic-bezier(0.22, 1, 0.36, 1);
}

.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}

.modal-enter-from > div,
.modal-leave-to > div {
  transform: translateY(8px) scale(0.985);
}
</style>
