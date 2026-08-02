import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    // Proxying keeps the browser on one origin in development, so the
    // SameSite=Strict session cookie behaves exactly as it will in production
    // behind a reverse proxy. Talking to :4000 cross-origin instead would work
    // in dev and then break the first time cookies got stricter.
    proxy: {
      '/api': { target: 'http://127.0.0.1:4000', changeOrigin: false },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
