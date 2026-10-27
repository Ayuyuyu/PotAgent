<script setup lang="ts">
import { ref } from 'vue';
import { ChevronDown } from 'lucide-vue-next';

const props = withDefaults(
  defineProps<{
    title?: string;
    subtitle?: string;
    collapsible?: boolean;
    /** 卡片内容是否有内边距，表格类卡片用 none */
    padded?: boolean;
    dense?: boolean;
  }>(),
  { title: '', subtitle: '', collapsible: false, padded: true, dense: false },
);

const collapsed = ref(false);
</script>

<template>
  <section
    class="flex min-w-0 flex-col rounded-card border border-line bg-surface shadow-card transition-colors duration-150"
  >
    <header
      v-if="props.title"
      class="flex shrink-0 items-center gap-2 border-b border-line px-3"
      :class="props.dense ? 'h-8' : 'h-9'"
    >
      <button
        v-if="props.collapsible"
        type="button"
        class="flex h-5 w-5 items-center justify-center rounded-[3px] text-subtle transition-colors hover:bg-surface-hover hover:text-ink"
        :aria-expanded="!collapsed"
        :title="collapsed ? '展开' : '收起'"
        @click="collapsed = !collapsed"
      >
        <ChevronDown
          class="h-3.5 w-3.5 transition-transform duration-200"
          :class="collapsed ? '-rotate-90' : ''"
        />
      </button>

      <div class="flex min-w-0 flex-1 items-baseline gap-2">
        <h2 class="truncate text-sm font-semibold text-ink">{{ props.title }}</h2>
        <span v-if="props.subtitle" class="truncate text-2xs text-subtle">{{ props.subtitle }}</span>
      </div>

      <div class="flex shrink-0 items-center gap-1.5">
        <slot name="actions" />
      </div>
    </header>

    <div v-show="!collapsed" class="min-h-0 flex-1" :class="props.padded ? 'p-3' : ''">
      <slot />
    </div>

    <footer v-if="$slots.footer" class="border-t border-line px-3 py-1.5">
      <slot name="footer" />
    </footer>
  </section>
</template>
