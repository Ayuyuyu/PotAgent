import { fileURLToPath, URL } from 'node:url';

import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: true,
    // 容器/低 inotify 限额环境下改用轮询，避免 ENOSPC 导致 dev server 起不来
    watch: {
      usePolling: true,
      interval: 320,
    },
    proxy: {
      // 阶段 2 的 Go 管理端；原型阶段走 mock，不经过代理
      '/api': {
        target: 'http://127.0.0.1:58090',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 700,
  },
});
