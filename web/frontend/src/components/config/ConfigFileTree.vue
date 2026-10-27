<script setup lang="ts">
import { computed } from 'vue';
import { FileCode2 } from 'lucide-vue-next';

import type { IConfigFile } from '@/api/types';
import { PROTOCOL_GROUPS, getProtocolMeta } from '@/constants/protocol';

const props = withDefaults(
  defineProps<{
    files: IConfigFile[];
    activeFile: string;
    dirtyFiles?: string[];
  }>(),
  { dirtyFiles: () => [] },
);

const emit = defineEmits<{ select: [file: string] }>();

const grouped = computed(() =>
  PROTOCOL_GROUPS.map((group) => ({
    group,
    items: props.files.filter((file) => getProtocolMeta(file.protocol).group === group),
  })).filter((entry) => entry.items.length > 0),
);
</script>

<template>
  <nav class="flex h-full min-h-0 w-[228px] shrink-0 flex-col border-r border-line bg-surface">
    <div class="flex shrink-0 items-center justify-between border-b border-line px-2.5 py-2">
      <span class="text-2xs font-medium uppercase tracking-wider text-subtle">配置文件</span>
      <span class="mono-num text-2xs text-subtle">{{ props.files.length }}</span>
    </div>

    <div class="min-h-0 flex-1 overflow-y-auto pb-1">
      <div
        v-for="(entry, index) in grouped"
        :key="entry.group"
        :class="index > 0 ? 'border-t border-line/70' : ''"
      >
        <p class="flex items-center gap-1.5 px-2.5 pb-1 pt-2">
          <span class="h-1 w-1 shrink-0 rounded-full bg-primary/60" aria-hidden="true" />
          <span class="text-xs font-semibold text-ink">{{ entry.group }}</span>
          <span class="mono-num text-[10px] font-normal text-muted">({{ entry.items.length }})</span>
        </p>

        <ul>
          <li v-for="file in entry.items" :key="file.file">
            <button
              type="button"
              class="edge-bar flex w-full items-center gap-1.5 py-1 pl-3 pr-2 text-left transition-colors duration-100"
              :class="
                file.file === props.activeFile
                  ? 'edge-bar--primary bg-primary-soft/60'
                  : 'hover:bg-surface-hover'
              "
              @click="emit('select', file.file)"
            >
              <FileCode2
                class="h-3 w-3 shrink-0"
                :class="file.file === props.activeFile ? 'text-primary' : 'text-subtle'"
              />
              <span class="min-w-0 flex-1">
                <span
                  class="block truncate text-xs"
                  :class="file.file === props.activeFile ? 'font-medium text-primary-ink' : 'text-ink'"
                >
                  {{ file.application }}
                </span>
                <span class="mono-num block truncate text-[10px] leading-3 text-subtle">{{ file.file }}</span>
              </span>
              <span
                v-if="props.dirtyFiles.includes(file.file)"
                class="h-1.5 w-1.5 shrink-0 rounded-full bg-accent"
                title="有未保存修改"
              />
            </button>
          </li>
        </ul>
      </div>
    </div>
  </nav>
</template>
