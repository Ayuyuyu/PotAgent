import { computed } from 'vue';
import { useRouter } from 'vue-router';

import { useAuthStore } from '@/store/auth';

export function useAuth() {
  const store = useAuthStore();
  const router = useRouter();

  const username = computed(() => store.user?.username ?? '');

  async function logout(): Promise<void> {
    await store.signOut();
    await router.push({ name: 'login' });
  }

  return { username, isAuthenticated: store.isAuthenticated, logout };
}
