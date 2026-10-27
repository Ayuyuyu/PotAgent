<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { AlertCircle, KeyRound, Lock, ShieldCheck, User } from 'lucide-vue-next';

import AppButton from '@/components/common/AppButton.vue';
import AppInput from '@/components/common/AppInput.vue';
import { PROTOCOL_GROUPS } from '@/constants/protocol';
import { useAuthStore } from '@/store/auth';

const router = useRouter();
const route = useRoute();
const auth = useAuthStore();

const username = ref('admin');
const password = ref('potagent');
const errorMessage = ref('');

const canSubmit = computed(() => username.value.trim().length > 0 && password.value.length > 0);

// 直接列协议分类，与 constants/protocol.ts 保持同源，新增协议不会漏改这里
const capabilities = PROTOCOL_GROUPS;

const appVersion = import.meta.env.VITE_APP_VERSION;

async function submit(): Promise<void> {
  if (!canSubmit.value || auth.pending) {
    return;
  }

  errorMessage.value = '';

  await auth
    .signIn(username.value.trim(), password.value)
    .then(() => {
      const redirect = typeof route.query.redirect === 'string' ? route.query.redirect : '/overview';

      return router.replace(redirect);
    })
    .catch((reason: unknown) => {
      errorMessage.value = reason instanceof Error ? reason.message : '登录失败，请重试';
    });
}
</script>

<template>
  <div
    class="grid w-full max-w-[880px] overflow-hidden rounded-card border border-line bg-surface shadow-lift md:grid-cols-[1.05fr_1fr]"
  >
    <section class="relative hidden flex-col justify-between overflow-hidden bg-ink p-7 md:flex">
      <div class="absolute inset-0 opacity-[0.14] grid-backdrop" aria-hidden="true" />
      <div
        class="absolute -right-10 -top-10 h-44 w-44 rounded-full bg-primary/40 blur-3xl"
        aria-hidden="true"
      />

      <div class="relative">
        <div class="flex items-center gap-2">
          <span class="flex h-8 w-8 items-center justify-center rounded-card bg-primary text-white">
            <ShieldCheck class="h-4 w-4" />
          </span>
          <div>
            <p class="text-sm font-semibold tracking-tight text-white">PotAgent</p>
            <p class="text-2xs uppercase tracking-[0.18em] text-white/45">Honeypot Console</p>
          </div>
        </div>

        <h1 class="mt-7 text-[26px] font-semibold leading-snug text-white">
          蜜罐观测台
        </h1>
        <p class="mt-2 max-w-[300px] text-xs leading-relaxed text-white/60">
          轻量控制台
          实时收拢 event.log 中的探针行为，统一管理服务实例的启停与配置。
        </p>

        <ul class="mt-5 flex flex-col gap-1.5">
          <li
            v-for="item in capabilities"
            :key="item"
            class="flex items-center gap-2 text-xs text-white/70"
          >
            <span class="h-1 w-1 rounded-full bg-primary" aria-hidden="true" />
            {{ item }}
          </li>
        </ul>
      </div>

      <div class="relative mt-6 text-2xs text-white/40">
        <span>{{ appVersion }}</span>
      </div>
    </section>

    <section class="flex flex-col justify-center p-6 sm:p-8">
      <div class="mb-5">
        <h2 class="text-base font-semibold text-ink">登录控制台</h2>
        <p class="mt-1 text-xs text-muted">账号密码来自 pot.yaml 的 web 配置项</p>
      </div>

      <form class="flex flex-col gap-3" @submit.prevent="submit">
        <label class="flex flex-col gap-1">
          <span class="text-2xs font-medium uppercase tracking-wider text-muted">用户名</span>
          <AppInput
            v-model="username"
            :prefix-icon="User"
            placeholder="admin"
            autocomplete="username"
          />
        </label>

        <label class="flex flex-col gap-1">
          <span class="text-2xs font-medium uppercase tracking-wider text-muted">密码</span>
          <AppInput
            v-model="password"
            type="password"
            :prefix-icon="Lock"
            placeholder="请输入密码"
            autocomplete="current-password"
          />
        </label>

        <p
          v-if="errorMessage"
          class="flex items-start gap-1.5 rounded-card border border-danger/25 bg-danger-soft px-2 py-1.5 text-xs text-danger"
        >
          <AlertCircle class="mt-0.5 h-3.5 w-3.5 shrink-0" />
          {{ errorMessage }}
        </p>

        <AppButton
          variant="primary"
          type="submit"
          block
          :loading="auth.pending"
          :disabled="!canSubmit"
        >
          进入控制台
        </AppButton>
      </form>

      <div class="mt-5 rounded-card border border-line bg-surface-alt px-2.5 py-2">
        <p class="flex items-center gap-1.5 text-2xs font-medium text-muted">
          <KeyRound class="h-3 w-3 text-accent" />
          原型演示账号
        </p>
        <p class="mono-num mt-1 text-xs text-ink">admin / potagent</p>
      </div>
    </section>
  </div>
</template>
