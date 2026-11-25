import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// 生产部署：网关把 /admin/* 的请求剥前缀后服务本 SPA（rust-embed 嵌二进制），
// 因此资源路径必须带 /admin/ 前缀；路由 basename 同理（main.tsx）。
//
// dev 代理：浏览器同源请求 /api，由 Vite 转发到目标后端，
// 绕开 CORS 预检（后端白名单不必枚举 5173/5174/5175…）。
const target = process.env.VITE_PROXY_TARGET ?? 'https://api.lokahe.top:8443'

// https://vite.dev/config/
export default defineConfig({
  base: '/admin/',
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target, secure: false, changeOrigin: true },
    },
  },
})
