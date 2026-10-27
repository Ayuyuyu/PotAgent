<script setup lang="ts">
import { CheckCircle2, Info, X, XCircle } from 'lucide-vue-next';

import { useToast, type ToastTone } from '@/composables/use-toast';

const { toasts, dismiss } = useToast();

const TONE_STYLE: Record<ToastTone, { bar: string; icon: string; component: typeof Info }> = {
  success: { bar: 'bg-success', icon: 'text-success', component: CheckCircle2 },
  error: { bar: 'bg-danger', icon: 'text-danger', component: XCircle },
  info: { bar: 'bg-primary', icon: 'text-primary', component: Info },
};
</script>

<template>
  <div class="pointer-events-none fixed bottom-3 right-3 z-[90] flex w-[320px] flex-col gap-2">
    <TransitionGroup name="toast">
      <div
        v-for="item in toasts"
        :key="item.id"
        class="pointer-events-auto relative flex items-start gap-2 overflow-hidden rounded-card border border-line bg-surface py-2 pl-3 pr-2 shadow-lift"
      >
        <span class="absolute left-0 top-0 h-full w-[3px]" :class="TONE_STYLE[item.tone].bar" />
        <component
          :is="TONE_STYLE[item.tone].component"
          class="mt-0.5 h-3.5 w-3.5 shrink-0"
          :class="TONE_STYLE[item.tone].icon"
        />
        <div class="min-w-0 flex-1">
          <p class="text-sm font-medium leading-tight text-ink">{{ item.title }}</p>
          <p v-if="item.description" class="mt-0.5 text-2xs leading-relaxed text-muted">
            {{ item.description }}
          </p>
        </div>
        <button
          type="button"
          class="flex h-4 w-4 shrink-0 items-center justify-center rounded-[3px] text-subtle transition-colors hover:bg-surface-hover hover:text-ink"
          title="关闭提示"
          @click="dismiss(item.id)"
        >
          <X class="h-3 w-3" />
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.toast-enter-active,
.toast-leave-active {
  transition:
    opacity 180ms ease-out,
    transform 180ms cubic-bezier(0.22, 1, 0.36, 1);
}

.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateX(16px);
}
</style>
