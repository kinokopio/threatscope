import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      // 代理 API 请求到后端
      '/analyze': 'http://localhost:8000',
      '/tasks': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
      '/batch': 'http://localhost:8000',
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },
})
