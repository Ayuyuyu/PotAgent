<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue';
import { Check, Copy, X } from 'lucide-vue-next';

import type { ILogEntry } from '@/api/types';
import AppBadge from '@/components/common/AppBadge.vue';
import ProtocolTag from './ProtocolTag.vue';
import { logDetailRows, logRawJson } from '@/utils/log-format';

const props = defineProps<{ entry: ILogEntry | null }>();

const emit = defineEmits<{ close: [] }>();

const showRaw = ref(false);
const copied = ref(false);

const rows = computed(() => (props.entry ? logDetailRows(props.entry) : []));
const rawJson = computed(() => (props.entry ? logRawJson(props.entry) : ''));

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape') {
    emit('close');
  }
}

watch(
  () => props.entry,
  (entry) => {
    showRaw.value = false;
    copied.value = false;

    if (entry) {
      document.addEventListener('keydown', onKeydown);
    } else {
      document.removeEventListener('keydown', onKeydown);
    }
  },
);

onUnmounted(() => document.removeEventListener('keydown', onKeydown));

function copyRaw(): void {
  void navigator.clipboard.writeText(rawJson.value).then(() => {
    copied.value = true;
    window.setTimeout(() => (copied.value = false), 1600);
  });
}
</script>

<template>
  <Teleport to="body">
    <Transition name="drawer">
      <div v-if="props.entry" class="fixed inset-0 z-[70] flex justify-end">
        <div class="absolute inset-0 bg-ink/20 backdrop-blur-[1px]" @click="emit('close')" />

        <aside
          class="relative flex h-full w-full max-w-[440px] flex-col border-l border-line bg-surface shadow-drawer"
        >
          <header class="flex items-start gap-2 border-b border-line px-3 py-2.5">
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-1.5">
                <ProtocolTag :protocol="props.entry.eventCategory" :fixed-width="false" />
                <span class="mono-num truncate text-xs text-muted">{{ props.entry.timestamp }}</span>
              </div>
              <p class="mt-1 truncate text-sm font-medium text-ink">{{ props.entry.eventType }}</p>
            </div>
            <button
              type="button"
              class="flex h-6 w-6 items-center justify-center rounded-[3px] text-subtle transition-colors hover:bg-surface-hover hover:text-ink"
              title="关闭（Esc）"
              @click="emit('close')"
            >
              <X class="h-3.5 w-3.5" />
            </button>
          </header>

          <div class="min-h-0 flex-1 overflow-y-auto">
            <section class="border-b border-line px-3 py-2">
              <h3 class="mb-1.5 text-2xs font-medium uppercase tracking-wider text-subtle">连接信息</h3>
              <dl class="grid grid-cols-[88px_1fr] gap-x-2 gap-y-1 text-xs">
                <dt class="text-muted">来源</dt>
                <dd class="mono-num text-ink">
                  <AppBadge tone="info" :label="props.entry.ipProtocol" />
                  {{ props.entry.srcIp }}:{{ props.entry.srcPort }}
                </dd>
                <dt class="text-muted">目标</dt>
                <dd class="mono-num text-ink">{{ props.entry.dstIp }}:{{ props.entry.dstPort }}</dd>
                <dt class="text-muted">事件分类</dt>
                <dd class="text-ink">{{ props.entry.eventCategory }}</dd>
              </dl>
            </section>

            <section class="border-b border-line px-3 py-2">
              <div class="mb-1.5 flex items-center justify-between">
                <h3 class="text-2xs font-medium uppercase tracking-wider text-subtle">details 字段</h3>
                <span class="text-2xs text-subtle">{{ rows.length }} 项</span>
              </div>

              <dl class="flex flex-col gap-1">
                <div
                  v-for="row in rows"
                  :key="row.key"
                  class="grid grid-cols-[136px_1fr] gap-2 rounded-[3px] px-1 py-1 odd:bg-surface-alt"
                >
                  <dt class="mono-num truncate text-xs text-muted" :title="row.key">{{ row.key }}</dt>
                  <dd class="mono-num break-all text-xs text-ink">{{ row.value }}</dd>
                </div>
              </dl>
            </section>

            <section class="px-3 py-2">
              <button
                type="button"
                class="flex w-full items-center justify-between text-2xs font-medium uppercase tracking-wider text-subtle transition-colors hover:text-ink"
                @click="showRaw = !showRaw"
              >
                原始 JSON
                <span class="text-[10px] normal-case">{{ showRaw ? '收起' : '展开' }}</span>
              </button>

              <pre
                v-if="showRaw"
                class="mono-num mt-1.5 max-h-[280px] overflow-auto rounded-card border border-line bg-surface-alt p-2 text-xs leading-relaxed text-ink"
              >{{ rawJson }}</pre>
            </section>
          </div>

          <footer class="flex items-center justify-between gap-2 border-t border-line bg-surface-alt px-3 py-2">
            <span class="text-2xs text-subtle">来自 event.log</span>
            <button
              type="button"
              class="inline-flex h-7 items-center gap-1 rounded-card border border-line bg-surface px-2 text-xs text-ink transition-colors hover:bg-surface-hover"
              @click="copyRaw"
            >
              <Check v-if="copied" class="h-3 w-3 text-success" />
              <Copy v-else class="h-3 w-3 text-subtle" />
              {{ copied ? '已复制' : '复制 JSON' }}
            </button>
          </footer>
        </aside>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.drawer-enter-active,
.drawer-leave-active {
  transition: opacity 180ms ease-out;
}

.drawer-enter-active aside,
.drawer-leave-active aside {
  transition: transform 220ms cubic-bezier(0.22, 1, 0.36, 1);
}

.drawer-enter-from,
.drawer-leave-to {
  opacity: 0;
}

.drawer-enter-from aside,
.drawer-leave-to aside {
  transform: translateX(24px);
}
</style>
