<script setup lang="ts">
import { computed } from 'vue';
import { RouterLink, useRoute } from 'vue-router';
import { FileCog, LayoutDashboard, ListTree, LogOut, Radio, ShieldCheck, SlidersHorizontal } from 'lucide-vue-next';

import ThemeSwitcher from './ThemeSwitcher.vue';
import { adminApi } from '@/api/client';
import { useAuth } from '@/composables/use-auth';

const route = useRoute();
const { username, logout } = useAuth();

const NAV_ITEMS = [
  { name: 'overview', label: '概览', icon: LayoutDashboard },
  { name: 'logs', label: '实时日志', icon: ListTree },
  { name: 'services', label: '服务管理', icon: SlidersHorizontal },
  { name: 'config', label: '配置管理', icon: FileCog },
];

const activeName = computed(() => (typeof route.name === 'string' ? route.name : ''));

const connectionLabel = computed(() => (adminApi.useMock ? '原型数据' : '实时连接'));
</script>

<template>
  <header
    class="topnav-elevation fixed inset-x-0 top-0 z-40 flex h-12 items-center gap-3 border-b border-line-strong bg-surface px-3"
  >
    <span
      class="pointer-events-none absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-primary via-primary to-accent"
      aria-hidden="true"
    />

    <div class="flex shrink-0 items-center gap-2">
      <span
        class="flex h-7 w-7 items-center justify-center rounded-card bg-primary text-white shadow-sm"
      >
        <ShieldCheck class="h-4 w-4" />
      </span>
      <div class="flex items-baseline gap-1.5">
        <span class="text-sm font-semibold tracking-tight text-ink">PotAgent</span>
        <span class="text-2xs font-medium uppercase tracking-widest text-subtle">Console</span>
      </div>
    </div>

    <span class="h-4 w-px bg-line" aria-hidden="true" />

    <nav class="flex min-w-0 flex-1 items-center gap-0.5 overflow-x-auto">
      <RouterLink
        v-for="item in NAV_ITEMS"
        :key="item.name"
        :to="{ name: item.name }"
        class="group relative flex h-12 shrink-0 items-center gap-1.5 px-2.5 text-sm transition-colors duration-150"
        :class="activeName === item.name ? 'text-primary-ink font-medium' : 'text-muted hover:text-ink'"
      >
        <component :is="item.icon" class="h-3.5 w-3.5" />
        {{ item.label }}
        <span
          class="absolute bottom-0 left-2 right-2 h-[2px] rounded-t-sm transition-all duration-200"
          :class="activeName === item.name ? 'bg-primary opacity-100' : 'opacity-0 group-hover:opacity-30'"
        />
      </RouterLink>
    </nav>

    <div class="flex shrink-0 items-center gap-2">
      <span
        class="hidden items-center gap-1 rounded-[3px] border px-1.5 py-0.5 text-2xs font-medium md:flex"
        :class="
          adminApi.useMock
            ? 'border-warning/30 bg-warning-soft text-warning'
            : 'border-success/30 bg-success-soft text-success'
        "
        :title="adminApi.useMock ? '当前使用 mock 数据，未连接 Go 管理端' : '已连接 Go 管理端'"
      >
        <Radio class="h-2.5 w-2.5" :class="adminApi.useMock ? '' : 'animate-pulse'" />
        {{ connectionLabel }}
      </span>

      <ThemeSwitcher />

      <span class="h-4 w-px bg-line" aria-hidden="true" />

      <span class="hidden text-xs text-muted sm:inline">{{ username }}</span>

      <button
        type="button"
        class="flex h-7 w-7 items-center justify-center rounded-card text-subtle transition-colors hover:bg-surface-hover hover:text-danger"
        title="退出登录"
        @click="logout"
      >
        <LogOut class="h-3.5 w-3.5" />
      </button>
    </div>
  </header>
</template>
