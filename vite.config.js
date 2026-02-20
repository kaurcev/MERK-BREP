import { defineConfig } from 'vite';

export default defineConfig({
  root: 'client',
  server: {
    open: true,
    fs: {
      allow: ['..']
    }
  }
});