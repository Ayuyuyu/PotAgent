import type {
  IConfigFile,
  ILogQuery,
  ILogTailResult,
  IOverviewStats,
  IReloadResult,
  IServiceItem,
  ISessionUser,
  ITopSource,
  ITrendRange,
  ITrendSeries,
  IValidationResult,
} from '../types';
import { getConfig, listConfigFiles, login, reloadServices, saveConfig, validateConfig } from './configs';
import { searchLogs, tailLogs } from './logs';
import { getServiceSummary, listServices, restartService, setServiceEnabled } from './services';
import { getOverview, getTopSources, getTrend } from './stats';
import { resetStatsState } from './state';

/** 模拟网络延迟，让 loading 态在原型阶段真实可见 */
function withDelay<T>(value: T, ms = 180): Promise<T> {
  return new Promise((resolve) => {
    setTimeout(() => resolve(value), ms);
  });
}

export const mockApi = {
  login: (username: string, password: string): Promise<ISessionUser> =>
    withDelay(login(username, password), 420),

  me: (): Promise<ISessionUser> => withDelay(login('admin', 'potagent'), 60),

  overview: (): Promise<IOverviewStats> => withDelay(getOverview()),

  trend: (range: ITrendRange): Promise<ITrendSeries> => withDelay(getTrend(range)),

  topSources: (limit?: number): Promise<ITopSource[]> => withDelay(getTopSources(limit)),

  resetStats: (): Promise<void> => withDelay(resetStatsState(), 320),

  services: (): Promise<IServiceItem[]> => withDelay(listServices()),

  serviceSummary: () => getServiceSummary(),

  setServiceEnabled: (file: string, enabled: boolean): Promise<IServiceItem> =>
    withDelay(setServiceEnabled(file, enabled), 520),

  restartService: (file: string): Promise<IServiceItem> => withDelay(restartService(file), 680),

  tailLogs: (query: ILogQuery, cursor: string): Promise<ILogTailResult> => withDelay(tailLogs(query, cursor), 80),

  searchLogs: (query: ILogQuery): Promise<ILogTailResult> => withDelay(searchLogs(query), 320),

  configFiles: (): Promise<IConfigFile[]> => withDelay(listConfigFiles(), 220),

  config: (file: string): Promise<IConfigFile> => withDelay(getConfig(file), 160),

  validateConfig: (file: string, content: string): Promise<IValidationResult> =>
    withDelay(validateConfig(file, content), 380),

  saveConfig: (file: string, content: string): Promise<IConfigFile> => withDelay(saveConfig(file, content), 320),

  reload: (): Promise<IReloadResult> => withDelay(reloadServices(), 760),
};
