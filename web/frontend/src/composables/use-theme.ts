import { isThemeName, THEME_STORAGE_KEY, type ThemeName } from '@/constants/theme';

export function applyTheme(name: ThemeName): void {
  document.documentElement.setAttribute('data-theme', name);
}

export function readStoredTheme(): ThemeName | null {
  const stored = localStorage.getItem(THEME_STORAGE_KEY);

  return isThemeName(stored) ? stored : null;
}

export function persistTheme(name: ThemeName): void {
  localStorage.setItem(THEME_STORAGE_KEY, name);
}
