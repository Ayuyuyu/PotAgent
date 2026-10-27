<script setup lang="ts">
import { useEditorThemeStore } from '@/store/editor-theme';

const editorTheme = useEditorThemeStore();
</script>

<template>
  <div
    class="flex items-center gap-0.5 rounded-card border border-line bg-surface-alt p-0.5"
    :title="editorTheme.currentOption.hint"
  >
    <button
      v-for="option in editorTheme.options"
      :key="option.name"
      type="button"
      class="flex h-6 items-center gap-1 rounded-[3px] px-1.5 text-xs font-medium transition-all duration-150"
      :class="
        editorTheme.current === option.name
          ? 'bg-surface text-ink shadow-sm ring-1 ring-line'
          : 'text-muted hover:text-ink'
      "
      :title="option.hint"
      @click="editorTheme.setTheme(option.name)"
    >
      <span class="flex overflow-hidden rounded-[2px] ring-1 ring-black/10">
        <span
          v-for="color in option.swatches"
          :key="color"
          class="h-3 w-1.5"
          :style="{ backgroundColor: color }"
        />
      </span>
      {{ option.label }}
    </button>
  </div>
</template>
