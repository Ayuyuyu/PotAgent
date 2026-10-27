export interface ILinePoint {
  label: string;
  value: number;
  /** 次要指标，用于 tooltip 第二行 */
  secondary?: number;
  secondaryLabel?: string;
}

export interface IBarItem {
  id: string;
  label: string;
  value: number;
  hint?: string;
  meta?: string;
}
