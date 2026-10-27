export type EditorThemeName = 'light' | 'paper' | 'dark';

export interface IEditorThemeOption {
  name: EditorThemeName;
  label: string;
  hint: string;
  /** 切换器色块：底 / 关键字 / 正文 */
  swatches: [string, string, string];
}

export const EDITOR_THEME_STORAGE_KEY = 'potagent.admin.editor-theme';

export const DEFAULT_EDITOR_THEME: EditorThemeName = 'paper';

export const EDITOR_THEMES: IEditorThemeOption[] = [
  {
    name: 'light',
    label: '浅色',
    hint: '纯白底，与页面卡片同色，适合偏爱极简的人',
    swatches: ['#FFFFFF', '#2563EB', '#374151'],
  },
  {
    name: 'paper',
    label: '纸灰',
    hint: '浅灰底，与白色页头、外层边框形成清晰区隔（默认）',
    swatches: ['#F7F8FA', '#2563EB', '#9CA3AF'],
  },
  {
    name: 'dark',
    label: '深色',
    hint: '墨蓝底亮字，长时间盯日志与配置更省眼',
    swatches: ['#1E2430', '#7DB4FF', '#E2E8F0'],
  },
];

export function isEditorThemeName(value: unknown): value is EditorThemeName {
  return value === 'light' || value === 'paper' || value === 'dark';
}
