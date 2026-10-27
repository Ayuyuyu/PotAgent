<script setup lang="ts">
import { RouterView } from 'vue-router';

import ToastHost from '@/components/common/ToastHost.vue';
</script>

<template>
  <RouterView v-slot="{ Component, route }">
    <Transition name="view" mode="out-in">
      <component :is="Component" :key="route.path" />
    </Transition>
  </RouterView>

  <ToastHost />
</template>

<style scoped>
.view-enter-active,
.view-leave-active {
  transition:
    opacity 160ms ease-out,
    transform 160ms cubic-bezier(0.22, 1, 0.36, 1);
}

.view-enter-from {
  opacity: 0;
  transform: translateY(6px);
}

.view-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}

@media (prefers-reduced-motion: reduce) {
  .view-enter-active,
  .view-leave-active {
    transition: none;
  }
}
</style>
