import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Dev: Vite on :5173, /api proxied to the FastAPI server (start.ps1 runs it on :8013).
const api = process.env.SMARTOPS_API ?? 'http://localhost:8013';

export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': { target: api, changeOrigin: true } } },
});
