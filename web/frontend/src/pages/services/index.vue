<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';
import {
  AlertTriangle,
  FileCog,
  Filter,
  Power,
  RefreshCw,
  RotateCw,
  Search,
  Server,
  Zap,
} from 'lucide-vue-next';

import AppBadge from '@/components/common/AppBadge.vue';
import AppButton from '@/components/common/AppButton.vue';
import AppCard from '@/components/common/AppCard.vue';
import AppInput from '@/components/common/AppInput.vue';
import AppModal from '@/components/common/AppModal.vue';
import AppSwitch from '@/components/common/AppSwitch.vue';
import EmptyState from '@/components/common/EmptyState.vue';
import PageShell from '@/components/layout/PageShell.vue';
import ProtocolTag from '@/components/logs/ProtocolTag.vue';
import { adminApi } from '@/api/client';
import type { IServiceItem, ServiceStatus } from '@/api/types';
import { useToast } from '@/composables/use-toast';
import { useServicesStore } from '@/store/services';
import { formatNumber, formatRelative } from '@/utils/format';

const store = useServicesStore();
const router = useRouter();
const toast = useToast();

type FilterValue = ServiceStatus | 'all';

const filters: Array<{ value: FilterValue; label: string }> = [
  { value: 'all', label: '全部' },
  { value: 'running', label: '运行中' },
  { value: 'stopped', label: '已停止' },
  { value: 'error', label: '异常' },
];

const pendingFile = ref('');
const reloading = ref(false);

const dialog = reactive<{
  open: boolean;
  item: IServiceItem | null;
  action: 'enable' | 'disable' | 'restart';
  submitting: boolean;
}>({ open: false, item: null, action: 'enable', submitting: false });

const errorCount = computed(() => store.items.filter((item) => item.status === 'error').length);

const filterCounts = computed<Record<FilterValue, number>>(() => {
  const counts: Record<FilterValue, number> = {
    all: store.items.length,
    running: 0,
    stopped: 0,
    error: 0,
  };

  for (const item of store.items) {
    counts[item.status] += 1;
  }

  return counts;
});

const dialogTitle = computed(() => {
  if (!dialog.item) {
    return '';
  }

  if (dialog.action === 'restart') {
    return `重启 ${dialog.item.application}？`;
  }

  return dialog.action === 'enable' ? `启用 ${dialog.item.application}？` : `停用 ${dialog.item.application}？`;
});

const dialogDescription = computed(() => {
  const item = dialog.item;

  if (!item) {
    return '';
  }

  if (dialog.action === 'enable') {
    return `将在 ${item.host}:${item.port} 开始监听。若端口已被占用，该实例会启动失败并在列表中标红。`;
  }

  if (dialog.action === 'disable') {
    return `将断开当前 ${item.connections} 条活动连接，并停止捕获 ${item.port} 端口的新事件。`;
  }

  return `重启会断开当前 ${item.connections} 条连接，重新读取 ${item.file} 后拉起监听，约 1 秒完成。`;
});

function setFilter(value: FilterValue): void {
  store.statusFilter = value;
}

function openDialog(item: IServiceItem, action: 'enable' | 'disable' | 'restart'): void {
  dialog.item = item;
  dialog.action = action;
  dialog.open = true;
}

function onSwitch(item: IServiceItem, value: boolean): void {
  openDialog(item, value ? 'enable' : 'disable');
}

async function submitDialog(): Promise<void> {
  const item = dialog.item;

  if (!item) {
    return;
  }

  dialog.submitting = true;
  pendingFile.value = item.file;

  if (dialog.action === 'restart') {
    await store
      .restart(item)
      .then(() => toast.success('已重启', `${item.application} 已重新监听 ${item.port}`))
      .catch((reason: unknown) => {
        toast.error('重启失败', reason instanceof Error ? reason.message : '请查看主进程日志');
      });
  } else {
    const enabled = dialog.action === 'enable';

    await store
      .toggle(item, enabled)
      .then((updated) => {
        toast.success(enabled ? '已启用' : '已停用', `${updated.application} · ${updated.host}:${updated.port}`);
      })
      .catch((reason: unknown) => {
        toast.error('操作失败', reason instanceof Error ? reason.message : '请查看主进程日志');
      });
  }

  pendingFile.value = '';
  dialog.submitting = false;
  dialog.open = false;
}

async function reloadAll(): Promise<void> {
  reloading.value = true;

  await adminApi
    .reload()
    .then((result) => {
      toast.success('热加载完成', result.message);
    })
    .catch((reason: unknown) => {
      toast.error('热加载失败', reason instanceof Error ? reason.message : '请检查 yaml');
    });

  reloading.value = false;
  await store.load();
}

function goConfig(item: IServiceItem): void {
  void router.push({ name: 'config', query: { file: item.file } });
}

onMounted(() => {
  void store.load();
});
</script>

<template>
  <PageShell title="服务管理" description="按 services_conf 下每个 yaml 实例管理启停，修改后热加载生效">
    <template #actions>
      <AppInput
        v-model="store.keyword"
        class="w-[200px]"
        :prefix-icon="Search"
        placeholder="实例 / 协议 / 端口"
        clearable
        size="sm"
      />
      <AppButton size="sm" :loading="store.loading" @click="store.load()">
        <template #icon>
          <RefreshCw class="h-3.5 w-3.5" />
        </template>
        刷新
      </AppButton>
      <AppButton size="sm" variant="primary" :loading="reloading" @click="reloadAll">
        <template #icon>
          <Zap class="h-3.5 w-3.5" />
        </template>
        热加载全部
      </AppButton>
    </template>

    <div class="flex flex-wrap items-center gap-2">
      <div class="flex items-center gap-1 rounded-card border border-line bg-surface p-1 shadow-card">
        <button
          v-for="item in filters"
          :key="item.value"
          type="button"
          class="flex h-6 items-center gap-1 rounded-[3px] px-2 text-xs font-medium transition-colors duration-150"
          :class="
            store.statusFilter === item.value
              ? 'bg-primary text-white shadow-sm'
              : 'text-muted hover:bg-surface-hover hover:text-ink'
          "
          @click="setFilter(item.value)"
        >
          {{ item.label }}
          <span
            class="mono-num rounded-[2px] px-1 text-2xs"
            :class="store.statusFilter === item.value ? 'bg-white/20 text-white' : 'bg-canvas-tint text-subtle'"
          >
            {{ filterCounts[item.value] }}
          </span>
        </button>
      </div>

      <div class="ml-auto flex items-center gap-3 text-2xs text-muted">
        <span class="flex items-center gap-1">
          <span class="status-dot status-dot--live text-success" />
          运行中 {{ filterCounts.running }}
        </span>
        <span class="flex items-center gap-1">
          <span class="status-dot text-subtle" />
          已停止 {{ filterCounts.stopped }}
        </span>
        <span class="flex items-center gap-1" :class="errorCount > 0 ? 'text-danger' : ''">
          <AlertTriangle class="h-3 w-3" />
          异常 {{ errorCount }}
        </span>
      </div>
    </div>

    <div
      v-if="errorCount > 0"
      class="flex items-start gap-2 rounded-card border border-danger/25 bg-danger-soft px-2.5 py-2 text-xs text-danger"
    >
      <AlertTriangle class="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <p>
        有 {{ errorCount }} 个实例启动失败，通常为端口占用或 yaml 字段非法。展开异常行查看具体错误，
        或到「配置管理」校验对应文件后热加载。
      </p>
    </div>

    <AppCard class="min-h-0" :padded="false">
      <div
        class="grid grid-cols-[minmax(0,1.4fr)_110px_88px_96px_110px_84px] items-center gap-2 border-b border-line bg-surface-alt px-3 py-1.5 text-2xs font-medium uppercase tracking-wider text-subtle"
      >
        <span>实例</span>
        <span>监听</span>
        <span class="text-right">连接</span>
        <span class="text-right">事件</span>
        <span>状态</span>
        <span class="text-right">操作</span>
      </div>

      <div v-if="store.loading && store.items.length === 0" class="px-3 py-6 text-center text-xs text-subtle">
        加载服务列表…
      </div>

      <ul v-else class="flex flex-col">
        <li
          v-for="item in store.filtered"
          :key="item.file"
          class="edge-bar lift-on-hover grid grid-cols-[minmax(0,1.4fr)_110px_88px_96px_110px_84px] items-center gap-2 border-b border-line/70 py-2 pl-3 pr-3 last:border-0 hover:bg-surface-hover"
          :class="
            item.status === 'error'
              ? 'edge-bar--danger'
              : item.status === 'running'
                ? 'edge-bar--success'
                : 'edge-bar--muted'
          "
        >
          <div class="flex min-w-0 items-center gap-2">
            <ProtocolTag :protocol="item.protocol" />
            <div class="min-w-0">
              <p class="truncate text-sm font-medium text-ink">{{ item.application }}</p>
              <p class="mono-num truncate text-2xs text-subtle">
                {{ item.file }}
                <span v-if="item.lastEventAt"> · {{ formatRelative(item.lastEventAt) }}有事件</span>
              </p>
            </div>
          </div>

          <span class="mono-num truncate text-xs text-muted">{{ item.host }}:{{ item.port }}</span>

          <span class="mono-num text-right text-xs text-ink">{{ item.connections }}</span>

          <span class="mono-num text-right text-xs text-muted">{{ formatNumber(item.events) }}</span>

          <div class="flex items-center gap-1.5">
            <AppBadge
              :tone="item.status === 'error' ? 'danger' : item.status === 'running' ? 'success' : 'neutral'"
              :label="item.status === 'error' ? '异常' : item.status === 'running' ? '运行中' : '已停止'"
              dot
              :pulse="item.status === 'running'"
            />
            <AppSwitch
              :model-value="item.status === 'running'"
              :loading="pendingFile === item.file"
              size="sm"
              :label="`切换 ${item.application}`"
              @update:model-value="onSwitch(item, $event)"
            />
          </div>

          <div class="flex items-center justify-end gap-0.5">
            <button
              type="button"
              class="flex h-6 w-6 items-center justify-center rounded-[3px] text-subtle transition-colors hover:bg-surface-alt hover:text-primary"
              title="重新读取该实例"
              @click="openDialog(item, 'restart')"
            >
              <RotateCw class="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              class="flex h-6 w-6 items-center justify-center rounded-[3px] text-subtle transition-colors hover:bg-surface-alt hover:text-primary"
              title="查看 / 编辑配置"
              @click="goConfig(item)"
            >
              <FileCog class="h-3.5 w-3.5" />
            </button>
          </div>

          <p
            v-if="item.status === 'error' && item.lastError"
            class="mono-num col-span-full mt-1 flex items-start gap-1 rounded-[3px] bg-danger-soft px-1.5 py-1 text-2xs text-danger"
          >
            <Power class="mt-0.5 h-2.5 w-2.5 shrink-0" />
            {{ item.lastError }}
          </p>
        </li>
      </ul>

      <EmptyState
        v-if="!store.loading && store.filtered.length === 0"
        :icon="Filter"
        title="没有符合条件的实例"
        description="调整筛选条件，或到配置管理新增服务 yaml"
      >
        <AppButton size="sm" @click="store.keyword = ''; store.statusFilter = 'all'">
          <template #icon>
            <Server class="h-3.5 w-3.5" />
          </template>
          重置筛选
        </AppButton>
      </EmptyState>
    </AppCard>

    <AppModal
      v-model="dialog.open"
      :title="dialogTitle"
      :description="dialogDescription"
      :tone="dialog.action === 'disable' ? 'danger' : 'primary'"
      :confirm-text="dialog.action === 'restart' ? '立即重启' : dialog.action === 'enable' ? '启用' : '停用'"
      :loading="dialog.submitting"
      @confirm="submitDialog"
    />
  </PageShell>
</template>
