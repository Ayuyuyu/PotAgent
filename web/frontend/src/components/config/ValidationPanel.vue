<script setup lang="ts">
import { computed, ref } from 'vue';
import { AlertCircle, AlertTriangle, CheckCircle2, ChevronDown, Info } from 'lucide-vue-next';

import type { IValidationResult, ValidationLevel } from '@/api/types';

const props = defineProps<{
  result: IValidationResult | null;
  validating?: boolean;
}>();

const emit = defineEmits<{ jump: [line: number] }>();

const collapsed = ref(false);

const LEVEL_STYLE: Record<ValidationLevel, { icon: typeof Info; color: string; label: string }> = {
  error: { icon: AlertCircle, color: 'text-danger', label: '错误' },
  warning: { icon: AlertTriangle, color: 'text-warning', label: '警告' },
  info: { icon: Info, color: 'text-info', label: '提示' },
};

const errorCount = computed(() => props.result?.issues.filter((issue) => issue.level === 'error').length ?? 0);
const warningCount = computed(
  () => props.result?.issues.filter((issue) => issue.level === 'warning').length ?? 0,
);
</script>

<template>
  <section class="shrink-0 border-t border-line bg-surface">
    <header class="flex items-center gap-2 px-2.5 py-1.5">
      <button
        type="button"
        class="flex h-4 w-4 items-center justify-center rounded-[2px] text-subtle transition-colors hover:bg-surface-hover hover:text-ink"
        :aria-expanded="!collapsed"
        @click="collapsed = !collapsed"
      >
        <ChevronDown class="h-3 w-3 transition-transform duration-150" :class="collapsed ? '-rotate-90' : ''" />
      </button>

      <template v-if="props.validating">
        <span class="text-xs text-muted">正在校验…</span>
      </template>

      <template v-else-if="!props.result">
        <span class="text-xs text-muted">尚未校验</span>
      </template>

      <template v-else-if="props.result.valid">
        <span class="flex items-center gap-1 text-xs font-medium text-success">
          <CheckCircle2 class="h-3.5 w-3.5" />
          {{ props.result.passed }} 项检查通过
        </span>
        <span v-if="warningCount > 0" class="flex items-center gap-1 text-2xs text-warning">
          <AlertTriangle class="h-3 w-3" />
          {{ warningCount }} 条警告
        </span>
      </template>

      <template v-else>
        <span class="flex items-center gap-1 text-xs font-medium text-danger">
          <AlertCircle class="h-3.5 w-3.5" />
          {{ errorCount }} 个错误
        </span>
        <span v-if="warningCount > 0" class="text-2xs text-warning">{{ warningCount }} 条警告</span>
      </template>

      <span class="ml-auto text-2xs text-subtle">{{ props.result?.checkedAt ?? '' }}</span>
    </header>

    <div v-show="!collapsed" class="max-h-[124px] min-h-[52px] overflow-y-auto border-t border-line/70 px-2 py-1.5">
      <ul v-if="props.result && props.result.issues.length > 0" class="flex flex-col gap-1">
        <li v-for="(issue, index) in props.result.issues" :key="`${issue.field}-${index}`">
          <button
            type="button"
            class="flex w-full items-start gap-1.5 rounded-[3px] px-1 py-0.5 text-left transition-colors hover:bg-surface-hover"
            @click="emit('jump', issue.line)"
          >
            <component
              :is="LEVEL_STYLE[issue.level].icon"
              class="mt-0.5 h-3 w-3 shrink-0"
              :class="LEVEL_STYLE[issue.level].color"
            />
            <span class="mono-num w-12 shrink-0 text-2xs text-subtle">
              {{ issue.line > 0 ? `L${issue.line}` : '—' }}
            </span>
            <span class="mono-num shrink-0 text-2xs text-muted">{{ issue.field }}</span>
            <span class="min-w-0 text-2xs text-ink">{{ issue.message }}</span>
          </button>
        </li>
      </ul>

      <p v-else-if="props.result" class="flex items-center gap-1.5 px-1 py-1 text-2xs text-muted">
        <CheckCircle2 class="h-3 w-3 text-success" />
        语法、必填字段与端口冲突检查全部通过，可以保存并热加载。
      </p>

      <p v-else class="px-1 py-1 text-2xs text-subtle">
        点击右上角「校验」检查 YAML 语法、必填字段与端口冲突。
      </p>
    </div>
  </section>
</template>
