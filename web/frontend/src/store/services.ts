import { defineStore } from 'pinia';
import { computed, ref } from 'vue';

import { adminApi } from '@/api/client';
import type { IServiceItem, ServiceStatus } from '@/api/types';

export const useServicesStore = defineStore('services', () => {
  const items = ref<IServiceItem[]>([]);
  const loading = ref(false);
  const error = ref<string | null>(null);
  const keyword = ref('');
  const statusFilter = ref<ServiceStatus | 'all'>('all');

  const summary = computed(() => {
    const base = { total: items.value.length, running: 0, stopped: 0, error: 0 };

    for (const item of items.value) {
      base[item.status] += 1;
    }

    return base;
  });

  const filtered = computed(() => {
    const term = keyword.value.trim().toLowerCase();

    return items.value.filter((item) => {
      if (statusFilter.value !== 'all' && item.status !== statusFilter.value) {
        return false;
      }

      if (!term) {
        return true;
      }

      return (
        item.application.toLowerCase().includes(term) ||
        item.protocol.toLowerCase().includes(term) ||
        item.file.toLowerCase().includes(term) ||
        String(item.port).includes(term)
      );
    });
  });

  async function load(): Promise<void> {
    loading.value = true;
    error.value = null;

    await adminApi
      .services()
      .then((list) => {
        items.value = list;
      })
      .catch((reason: unknown) => {
        error.value = reason instanceof Error ? reason.message : '加载服务列表失败';
        console.error('加载服务列表失败', reason);
      });

    loading.value = false;
  }

  function replace(updated: IServiceItem): void {
    const index = items.value.findIndex((item) => item.file === updated.file);

    if (index >= 0) {
      items.value[index] = updated;
    }
  }

  async function toggle(item: IServiceItem, enabled: boolean): Promise<IServiceItem> {
    const updated = await adminApi.setServiceEnabled(item.file, enabled);
    replace(updated);

    return updated;
  }

  async function restart(item: IServiceItem): Promise<IServiceItem> {
    const updated = await adminApi.restartService(item.file);
    replace(updated);

    return updated;
  }

  return {
    items,
    loading,
    error,
    keyword,
    statusFilter,
    summary,
    filtered,
    load,
    toggle,
    restart,
    replace,
  };
});
