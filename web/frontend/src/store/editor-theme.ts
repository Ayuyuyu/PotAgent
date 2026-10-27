import { defineStore } from 'pinia';
import { computed, ref } from 'vue';

import {
  DEFAULT_EDITOR_THEME,
  EDITOR_THEMES,
  EDITOR_THEME_STORAGE_KEY,
  isEditorThemeName,
  type EditorThemeName,
} from '@/constants/editor-theme';

function readStored(): EditorThemeName {
  const stored = localStorage.getItem(EDITOR_THEME_STORAGE_KEY);

  return isEditorThemeName(stored) ? stored : DEFAULT_EDITOR_THEME;
}

/**
 * 编辑器外观与站点配色相互独立：不改 html[data-theme]，
 * 只把 data-editor-theme 挂在编辑区容器上，切换时纯 CSS 变量替换。
 */
export const useEditorThemeStore = defineStore('editorTheme', () => {
  const current = ref<EditorThemeName>(readStored());

  const options = computed(() => EDITOR_THEMES);

  const currentOption = computed(
    () => EDITOR_THEMES.find((item) => item.name === current.value) ?? EDITOR_THEMES[1],
  );

  function setTheme(name: EditorThemeName): void {
    current.value = name;
    localStorage.setItem(EDITOR_THEME_STORAGE_KEY, name);
  }

  return { current, options, currentOption, setTheme };
});
