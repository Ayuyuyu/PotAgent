import { createRouter, createWebHistory } from 'vue-router';

import { useAuthStore } from '@/store/auth';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      component: () => import('@/layouts/BlankLayout.vue'),
      children: [
        {
          path: '',
          name: 'login',
          component: () => import('@/pages/login/index.vue'),
          meta: { title: '登录', public: true },
        },
      ],
    },
    {
      path: '/',
      component: () => import('@/layouts/DefaultLayout.vue'),
      redirect: '/overview',
      children: [
        {
          path: 'overview',
          name: 'overview',
          component: () => import('@/pages/overview/index.vue'),
          meta: { title: '概览' },
        },
        {
          path: 'logs',
          name: 'logs',
          component: () => import('@/pages/logs/index.vue'),
          meta: { title: '实时日志' },
        },
        {
          path: 'services',
          name: 'services',
          component: () => import('@/pages/services/index.vue'),
          meta: { title: '服务管理' },
        },
        {
          path: 'config',
          name: 'config',
          component: () => import('@/pages/config/index.vue'),
          meta: { title: '配置管理' },
        },
      ],
    },
    {
      path: '/:pathMatch(.*)*',
      redirect: '/overview',
    },
  ],
});

/** 本地 sessionStorage 可能残留着服务端已经失效的会话，首次进入时校准一次 */
let sessionChecked = false;

router.beforeEach(async (to) => {
  const auth = useAuthStore();

  if (to.meta.public) {
    return auth.isAuthenticated && to.name === 'login' ? { name: 'overview' } : true;
  }

  if (!auth.isAuthenticated) {
    return { name: 'login', query: { redirect: to.fullPath } };
  }

  if (!sessionChecked) {
    sessionChecked = true;

    if (!(await auth.validate())) {
      return { name: 'login', query: { redirect: to.fullPath } };
    }
  }

  return true;
});

router.afterEach((to) => {
  const title = typeof to.meta.title === 'string' ? to.meta.title : '';

  document.title = title ? `${title} · PotAgent 控制台` : 'PotAgent 控制台';
});

export default router;
