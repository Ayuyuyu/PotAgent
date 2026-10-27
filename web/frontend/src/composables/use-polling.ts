import { onUnmounted, ref, type Ref } from 'vue';

export interface IPollingOptions {
  /** 轮询间隔（毫秒） */
  interval?: number;
  /** 启动时立即执行一次 */
  immediate?: boolean;
  /** 页面切到后台时暂停，回到前台立即补一次 */
  pauseWhenHidden?: boolean;
}

export interface IUsePollingResult {
  isPaused: Ref<boolean>;
  isRunning: Ref<boolean>;
  interval: Ref<number>;
  lastRunAt: Ref<Date | null>;
  runNow: () => Promise<void>;
  start: () => void;
  stop: () => void;
  pause: () => void;
  resume: () => void;
  setInterval: (ms: number) => void;
}

/**
 * 通用轮询：负责定时器生命周期、重入保护、页面隐藏暂停。
 * 所有使用方都在 onUnmounted 时被自动清理，避免多页面切换后定时器泄漏。
 */
export function usePolling(
  task: () => Promise<void> | void,
  options: IPollingOptions = {},
): IUsePollingResult {
  const interval = ref(options.interval ?? 3000);
  const isPaused = ref(false);
  const isRunning = ref(false);
  const lastRunAt = ref<Date | null>(null);

  let timer: number | null = null;
  let hiddenStop = false;

  async function runNow(): Promise<void> {
    if (isRunning.value) {
      return;
    }

    isRunning.value = true;
    lastRunAt.value = new Date();

    await Promise.resolve(task()).finally(() => {
      isRunning.value = false;
    });
  }

  function stop(): void {
    if (timer !== null) {
      window.clearInterval(timer);
      timer = null;
    }
  }

  function start(): void {
    stop();
    timer = window.setInterval(() => {
      if (!isPaused.value) {
        void runNow();
      }
    }, interval.value);
  }

  function pause(): void {
    isPaused.value = true;
    stop();
  }

  function resume(): void {
    isPaused.value = false;
    start();
    void runNow();
  }

  function setIntervalMs(ms: number): void {
    interval.value = ms;

    if (timer !== null) {
      start();
    }
  }

  function onVisibilityChange(): void {
    if (!options.pauseWhenHidden) {
      return;
    }

    if (document.hidden) {
      hiddenStop = timer !== null;
      stop();
    } else if (hiddenStop) {
      hiddenStop = false;

      if (!isPaused.value) {
        start();
        void runNow();
      }
    }
  }

  if (options.pauseWhenHidden) {
    document.addEventListener('visibilitychange', onVisibilityChange);
  }

  onUnmounted(() => {
    stop();

    if (options.pauseWhenHidden) {
      document.removeEventListener('visibilitychange', onVisibilityChange);
    }
  });

  if (options.immediate !== false) {
    void runNow();
    start();
  }

  return {
    isPaused,
    isRunning,
    interval,
    lastRunAt,
    runNow,
    start,
    stop,
    pause,
    resume,
    setInterval: setIntervalMs,
  };
}
