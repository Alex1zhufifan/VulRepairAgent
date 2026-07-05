import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 使用简单的配置，暂时去掉 monaco-editor 插件
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true
      }
    }
  },
  // 优化依赖预构建
  optimizeDeps: {
    include: ['monaco-editor']
  }
})