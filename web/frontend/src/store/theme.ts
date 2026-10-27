import { defineStore } from 'pinia';
import { computed, ref } from 'vue';

import { DEFAULT_THEME, THEMES, type ThemeName } from '@/constants/theme';
import { applyTheme, persistTheme, readStoredTheme } from '@/composables/use-theme';

export const useThemeStore = defineStore('theme', () => {
  const current = ref<ThemeName>(readStoredTheme() ?? DEFAULT_THEME);

  const options = computed(() => THEMES);

  function setTheme(name: ThemeName): void {
    current.value = name;
    applyTheme(name);
    persistTheme(name);
  }

  function init(): void {
    applyTheme(current.value);
  }

  function toggle(): void {
    const index = THEMES.findIndex((item) => item.name === current.value);
    const next = THEMES[(index + 1) % THEMES.length];

    setTheme(next.name);
  }

  return { current, options, setTheme, init, toggle };
});
