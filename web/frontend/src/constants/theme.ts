export type ThemeName = 'console-blue' | 'emerald';

export interface IThemeOption {
  name: ThemeName;
  label: string;
  hint: string;
  /** 用于切换器里的小色块，顺序：底 / 主色 / 强调 */
  swatches: [string, string, string];
}

export const THEME_STORAGE_KEY = 'potagent.admin.theme';

export const DEFAULT_THEME: ThemeName = 'console-blue';

export const THEMES: IThemeOption[] = [
  {
    name: 'console-blue',
    label: '精工蓝',
    hint: '中性灰底 + 靛蓝主色 + 琥珀强调，最贴近参考截图',
    swatches: ['#F5F6F8', '#2563EB', '#F59E0B'],
  },
  {
    name: 'emerald',
    label: '翡翠绿',
    hint: '冷绿灰底 + 深青主色 + 青绿强调，参考站 emerald 主题',
    swatches: ['#F4F7F6', '#0F766E', '#14B8A6'],
  },
];

export function isThemeName(value: unknown): value is ThemeName {
  return value === 'console-blue' || value === 'emerald';
}
