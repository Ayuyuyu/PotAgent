import { ref } from 'vue';

export type ToastTone = 'success' | 'error' | 'info';

export interface IToast {
  id: number;
  tone: ToastTone;
  title: string;
  description?: string;
}

const toasts = ref<IToast[]>([]);
let nextId = 1;

function dismiss(id: number): void {
  toasts.value = toasts.value.filter((item) => item.id !== id);
}

function push(tone: ToastTone, title: string, description?: string): number {
  const id = nextId;
  nextId += 1;
  toasts.value = [...toasts.value, { id, tone, title, description }];

  window.setTimeout(() => dismiss(id), 3200);

  return id;
}

export function useToast() {
  return {
    toasts,
    dismiss,
    success: (title: string, description?: string) => push('success', title, description),
    error: (title: string, description?: string) => push('error', title, description),
    info: (title: string, description?: string) => push('info', title, description),
  };
}
