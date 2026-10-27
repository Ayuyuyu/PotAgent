<script setup lang="ts">
import { RouterView } from 'vue-router';
</script>

<template>
  <div class="relative min-h-screen overflow-hidden bg-canvas">
    <div class="absolute inset-0 grid-backdrop opacity-60" aria-hidden="true" />
    <div
      class="pointer-events-none absolute -left-24 top-1/4 h-72 w-72 rounded-full bg-primary/10 blur-3xl"
      aria-hidden="true"
    />
    <div
      class="pointer-events-none absolute -right-16 bottom-0 h-64 w-64 rounded-full bg-accent/10 blur-3xl"
      aria-hidden="true"
    />

    <div class="relative flex min-h-screen items-center justify-center px-4 py-8">
      <RouterView />
    </div>
  </div>
</template>
