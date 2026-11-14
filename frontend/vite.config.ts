import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'
import { decodeInstallationBootstrap } from './src/control/bootstrap'

const entry = process.env.ICLOUDSPACE_UI_ENTRY || '/admin'
const target = process.env.ICLOUDSPACE_API_TARGET || 'http://127.0.0.1:8080'
const runtime = decodeInstallationBootstrap({ version: 1, ui_path: entry, control_path: entry + '/api/control/v1', public_mail_path: '/api/mail/v1' })

export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss(), { name: 'explicit-development-installation', apply: 'serve', transformIndexHtml: (_html, context) => /\/(viewer|docs)\.html$/.test(context.path) ? [] : [{ tag: 'script', attrs: { id: 'space-runtime', type: 'application/json' }, children: JSON.stringify(runtime).replace(/</g, '\\u003c'), injectTo: 'head-prepend' }] }],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: { proxy: { '/openapi.json': { target, changeOrigin: false }, [runtime.control_path]: { target, changeOrigin: false }, [runtime.public_mail_path]: { target, changeOrigin: false } } },
  build: { sourcemap: false, rollupOptions: { input: { workspace: fileURLToPath(new URL('./index.html', import.meta.url)), viewer: fileURLToPath(new URL('./viewer.html', import.meta.url)), docs: fileURLToPath(new URL('./docs.html', import.meta.url)) } } }
})
