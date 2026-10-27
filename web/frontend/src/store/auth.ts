import { defineStore } from 'pinia';
import { computed, ref } from 'vue';

import { adminApi } from '@/api/client';
import type { ISessionUser } from '@/api/types';

const SESSION_KEY = 'potagent.admin.session';

interface IStoredSession {
  username: string;
  expiresAt: number;
}

function readSession(): ISessionUser | null {
  const raw = sessionStorage.getItem(SESSION_KEY);

  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw) as IStoredSession;

    if (parsed.expiresAt < Date.now()) {
      sessionStorage.removeItem(SESSION_KEY);

      return null;
    }

    return { username: parsed.username, expiresIn: Math.floor((parsed.expiresAt - Date.now()) / 1000) };
  } catch (error) {
    console.error('读取登录态失败', error);
    sessionStorage.removeItem(SESSION_KEY);

    return null;
  }
}

export const useAuthStore = defineStore('auth', () => {
  const user = ref<ISessionUser | null>(readSession());
  const pending = ref(false);

  const isAuthenticated = computed(() => user.value !== null);

  function persist(session: ISessionUser): void {
    const stored: IStoredSession = {
      username: session.username,
      expiresAt: Date.now() + session.expiresIn * 1000,
    };

    sessionStorage.setItem(SESSION_KEY, JSON.stringify(stored));
  }

  async function signIn(username: string, password: string): Promise<void> {
    pending.value = true;

    const session = await adminApi.login(username, password);

    user.value = session;
    persist(session);
    pending.value = false;
  }

  function clearSession(): void {
    user.value = null;
    sessionStorage.removeItem(SESSION_KEY);
  }

  async function signOut(): Promise<void> {
    try {
      await adminApi.logout();
    } catch (error) {
      // 服务端会话已失效（例如主进程重启）时登出接口也可能失败，本地状态照样要清，
      // 否则界面会停在"本地以为已登录、每个接口都 401"的状态。
      console.warn('登出请求失败，已在本地注销', error);
    } finally {
      clearSession();
    }
  }

  /** 校验服务端会话是否仍然有效（用于页面首次进入时对齐真实状态） */
  async function validate(): Promise<boolean> {
    if (!user.value) {
      return false;
    }

    try {
      await adminApi.me();

      return true;
    } catch (error) {
      console.warn('会话已失效', error);
      clearSession();

      return false;
    }
  }

  return { user, pending, isAuthenticated, signIn, signOut, clearSession, validate };
});
