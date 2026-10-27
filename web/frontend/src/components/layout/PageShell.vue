<script setup lang="ts">
const props = withDefaults(
  defineProps<{
    title: string;
    description?: string;
    /** 内容区是否加内边距 */
    padded?: boolean;
    /** 是否占满视口高度（日志页需要内部滚动而非页面滚动） */
    fill?: boolean;
  }>(),
  { description: '', padded: true, fill: false },
);
</script>

<template>
  <div
    class="flex flex-col"
    :class="props.fill ? 'h-[calc(100vh-48px)] overflow-hidden' : 'min-h-[calc(100vh-48px)]'"
  >
    <div
      class="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line bg-surface px-3 py-2"
    >
      <div class="min-w-0">
        <h1 class="text-xl font-semibold leading-tight tracking-tight text-ink">{{ title }}</h1>
        <p v-if="description" class="mt-0.5 text-xs text-muted">{{ description }}</p>
      </div>

      <div class="ml-auto flex flex-wrap items-center gap-2">
        <slot name="actions" />
      </div>
    </div>

    <div class="flex min-h-0 flex-1 flex-col" :class="padded ? 'gap-3 p-3' : ''">
      <slot />
    </div>
  </div>
</template>
