import { createPinia } from 'pinia';
import { createApp } from 'vue';

import App from './App.vue';
import { setUnauthorizedHandler } from '@/api/client';
import router from './router';
import { useAuthStore } from './store/auth';
import { useThemeStore } from './store/theme';

// 样式顺序：变量 → 主题 → 基础 → Tailwind → 工具类，保证预置样式不被覆盖
import '@/styles/variables.css';
import '@/styles/themes.css';
import '@/styles/base.css';
import '@/styles/index.css';
import '@/styles/utilities.css';

const app = createApp(App);
const pinia = createPinia();

app.use(pinia);
app.use(router);

// 任意接口返回 401（会话过期 / 主进程重启丢了会话）时，清本地登录态并回登录页
setUnauthorizedHandler(() => {
  const auth = useAuthStore(pinia);

  auth.clearSession();

  const current = router.currentRoute.value;

  if (current.name !== 'login') {
    void router.replace({ name: 'login', query: { redirect: current.fullPath } });
  }
});

useThemeStore(pinia).init();

app.mount('#app');
