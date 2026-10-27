<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { CircleDot, Save, ShieldQuestion, Zap } from 'lucide-vue-next';

import AppBadge from '@/components/common/AppBadge.vue';
import AppButton from '@/components/common/AppButton.vue';
import AppModal from '@/components/common/AppModal.vue';
import ConfigFileTree from '@/components/config/ConfigFileTree.vue';
import EditorThemeSwitcher from '@/components/config/EditorThemeSwitcher.vue';
import ValidationPanel from '@/components/config/ValidationPanel.vue';
import PageShell from '@/components/layout/PageShell.vue';
import ProtocolTag from '@/components/logs/ProtocolTag.vue';
import { adminApi } from '@/api/client';
import type { IConfigFile, IValidationResult } from '@/api/types';
import { useToast } from '@/composables/use-toast';
import { useEditorThemeStore } from '@/store/editor-theme';
import { formatRelative } from '@/utils/format';
import { highlightYaml } from '@/utils/yaml-highlight';

const LINE_HEIGHT = 20;

const route = useRoute();
const toast = useToast();
const editorTheme = useEditorThemeStore();

const files = ref<IConfigFile[]>([]);
const drafts = ref<Record<string, string>>({});
const activeFile = ref('');
const content = ref('');
const savedContent = ref('');
const validation = ref<IValidationResult | null>(null);
const loading = ref(false);
const validating = ref(false);
const saving = ref(false);
const reloading = ref(false);

const editor = ref<HTMLTextAreaElement | null>(null);
const highlightLayer = ref<HTMLElement | null>(null);
const gutter = ref<HTMLElement | null>(null);

const reloadDialogOpen = ref(false);

const activeConfig = computed(() => files.value.find((item) => item.file === activeFile.value) ?? null);
const isDirty = computed(() => content.value !== savedContent.value);
const highlighted = computed(() => highlightYaml(content.value));
const lineCount = computed(() => content.value.split('\n').length);
const dirtyFiles = computed(() => Object.keys(drafts.value));
const hasUnsaved = computed(() => dirtyFiles.value.length > 0);

watch(content, () => {
  if (!activeFile.value) {
    return;
  }

  if (content.value !== savedContent.value) {
    drafts.value = { ...drafts.value, [activeFile.value]: content.value };
  } else if (drafts.value[activeFile.value] !== undefined) {
    const next = { ...drafts.value };
    delete next[activeFile.value];
    drafts.value = next;
  }
});

function syncScroll(): void {
  const element = editor.value;

  if (!element) {
    return;
  }

  if (highlightLayer.value) {
    highlightLayer.value.scrollTop = element.scrollTop;
    highlightLayer.value.scrollLeft = element.scrollLeft;
  }

  if (gutter.value) {
    gutter.value.scrollTop = element.scrollTop;
  }
}

function selectFile(file: string): void {
  const found = files.value.find((item) => item.file === file);

  if (!found) {
    return;
  }

  activeFile.value = file;
  savedContent.value = found.content;
  content.value = drafts.value[file] ?? found.content;
  validation.value = null;

  void nextTick(() => {
    if (editor.value) {
      editor.value.scrollTop = 0;
    }

    syncScroll();
  });
}

async function loadFiles(): Promise<void> {
  loading.value = true;

  await adminApi
    .configFiles()
    .then((list) => {
      files.value = list;

      const requested = typeof route.query.file === 'string' ? route.query.file : '';
      const initial =
        list.find((item) => item.file === requested)?.file ??
        list.find((item) => item.file === 'docker.yaml')?.file ??
        list[0]?.file ??
        '';

      if (initial) {
        selectFile(initial);
      }
    })
    .catch((reason: unknown) => {
      toast.error('加载配置失败', reason instanceof Error ? reason.message : undefined);
    });

  loading.value = false;
}

async function validate(): Promise<void> {
  if (!activeFile.value) {
    return;
  }

  validating.value = true;

  await adminApi
    .validateConfig(activeFile.value, content.value)
    .then((result) => {
      validation.value = result;

      if (result.valid) {
        toast.success('校验通过', `${result.passed} 项检查全部通过`);
      } else {
        toast.error('校验未通过', `${result.issues.filter((issue) => issue.level === 'error').length} 个错误`);
      }
    })
    .catch((reason: unknown) => {
      toast.error('校验失败', reason instanceof Error ? reason.message : undefined);
    });

  validating.value = false;
}

async function save(): Promise<void> {
  if (!activeFile.value || saving.value) {
    return;
  }

  saving.value = true;

  await adminApi
    .saveConfig(activeFile.value, content.value)
    .then((updated) => {
      files.value = files.value.map((item) =>
        item.file === updated.file ? { ...item, content: updated.content } : item,
      );
      savedContent.value = content.value;

      const next = { ...drafts.value };
      delete next[updated.file];
      drafts.value = next;

      toast.success('已保存', `services_conf/${updated.file}，需要点「生效」才会热加载`);
    })
    .catch((reason: unknown) => {
      toast.error('保存失败', reason instanceof Error ? reason.message : undefined);
    });

  saving.value = false;
}

async function applyReload(): Promise<void> {
  reloadDialogOpen.value = false;
  reloading.value = true;

  await adminApi
    .reload()
    .then((result) => {
      toast.success('热加载完成', result.message);
    })
    .catch((reason: unknown) => {
      toast.error('热加载失败', reason instanceof Error ? reason.message : '请检查主进程日志');
    });

  reloading.value = false;
}

async function requestReload(): Promise<void> {
  if (hasUnsaved.value) {
    toast.error('存在未保存修改', '请先保存当前文件，再触发热加载');
    validation.value = {
      valid: false,
      passed: 0,
      checkedAt: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
      issues: [
        { level: 'error', line: 0, field: 'draft', message: '有未保存的修改，热加载会忽略这些改动' },
      ],
    };

    return;
  }

  await validate();

  if (validation.value?.valid) {
    reloadDialogOpen.value = true;
  }
}

function jumpToLine(line: number): void {
  const element = editor.value;

  if (!element || line <= 0) {
    return;
  }

  const lines = content.value.split('\n');
  const offset = lines.slice(0, line - 1).reduce((sum, item) => sum + item.length + 1, 0);

  element.focus();
  element.setSelectionRange(offset, offset + (lines[line - 1]?.length ?? 0));
  element.scrollTop = Math.max(0, (line - 3) * LINE_HEIGHT);
  syncScroll();
}

onMounted(() => {
  void loadFiles();
});
</script>

<template>
  <PageShell
    title="配置管理"
    description="编辑 services_conf 下的 yaml，校验通过后可热加载生效"
    fill
    :padded="false"
  >
    <template #actions>
      <span v-if="loading" class="text-2xs text-subtle">加载中…</span>
      <AppBadge v-if="hasUnsaved" tone="accent" :label="`${dirtyFiles.length} 个文件未保存`" />
      <AppButton size="sm" :loading="validating" @click="validate">
        <template #icon>
          <ShieldQuestion class="h-3.5 w-3.5" />
        </template>
        校验
      </AppButton>
      <AppButton size="sm" :loading="saving" :disabled="!isDirty" @click="save">
        <template #icon>
          <Save class="h-3.5 w-3.5" />
        </template>
        保存
      </AppButton>
      <AppButton size="sm" variant="primary" :loading="reloading" @click="requestReload">
        <template #icon>
          <Zap class="h-3.5 w-3.5" />
        </template>
        生效（热加载）
      </AppButton>
    </template>

    <div class="flex min-h-0 flex-1">
      <ConfigFileTree
        :files="files"
        :active-file="activeFile"
        :dirty-files="dirtyFiles"
        @select="selectFile"
      />

      <div class="flex min-w-0 flex-1 flex-col">
        <div class="flex shrink-0 flex-wrap items-center gap-2 border-b border-line bg-surface px-3 py-2">
          <ProtocolTag v-if="activeConfig" :protocol="activeConfig.protocol" :fixed-width="false" />
          <span class="mono-num truncate text-xs font-medium text-ink">
            {{ activeConfig?.path ?? '未选择文件' }}
          </span>
          <span v-if="isDirty" class="flex items-center gap-1 text-2xs text-accent">
            <CircleDot class="h-2.5 w-2.5" />
            未保存
          </span>
          <span v-if="activeConfig?.updatedAt" class="ml-auto text-2xs text-subtle">
            读取于 {{ formatRelative(activeConfig.updatedAt) }}
          </span>
          <div class="flex items-center gap-1.5" :class="activeConfig?.updatedAt ? '' : 'ml-auto'">
            <span class="text-2xs text-subtle">编辑器</span>
            <EditorThemeSwitcher />
          </div>
        </div>

        <div
          class="editor-surface relative min-h-0 flex-1"
          :data-editor-theme="editorTheme.current"
          :style="{ backgroundColor: 'rgb(var(--editor-bg))' }"
        >
          <div class="absolute inset-0 flex">
            <div
              ref="gutter"
              class="mono-num w-11 shrink-0 overflow-hidden border-r py-2 text-right text-xs leading-5"
              :style="{
                backgroundColor: 'rgb(var(--editor-gutter-bg))',
                borderColor: 'rgb(var(--editor-border))',
                color: 'rgb(var(--editor-gutter-text))',
              }"
              aria-hidden="true"
            >
              <div v-for="line in lineCount" :key="line" class="pr-1.5">{{ line }}</div>
            </div>

            <div class="relative min-w-0 flex-1">
              <div ref="highlightLayer" class="pointer-events-none absolute inset-0 overflow-hidden">
                <!-- 高亮层内容已整体转义，仅用于着色 -->
                <pre
                  class="editor-layer mono-num m-0 p-2 text-sm leading-5"
                  :style="{ color: 'rgb(var(--editor-text))' }"
                  v-html="highlighted"
                />
              </div>

              <textarea
                ref="editor"
                v-model="content"
                class="editor-layer mono-num absolute inset-0 h-full w-full resize-none border-0 bg-transparent p-2 text-sm leading-5 text-transparent outline-none"
                :style="{ caretColor: 'rgb(var(--editor-caret))' }"
                spellcheck="false"
                wrap="off"
                aria-label="编辑 YAML 配置"
                @scroll="syncScroll"
              />
            </div>
          </div>
        </div>

        <ValidationPanel :result="validation" :validating="validating" @jump="jumpToLine" />
      </div>
    </div>

    <AppModal
      v-model="reloadDialogOpen"
      title="热加载配置？"
      description="将重新读取 services_conf 下的全部 yaml，以差异方式重启变更的实例；未变更的服务保持监听，短暂中断通常小于 1 秒。"
      confirm-text="立即热加载"
      :loading="reloading"
      @confirm="applyReload"
    />
  </PageShell>
</template>

<style scoped>
textarea::selection {
  background-color: rgb(var(--editor-selection) / 0.26);
}
</style>
