// @ts-check
import { defineConfig } from 'astro/config';

import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';


// https://astro.build/config
export default defineConfig({
  output: 'server',
  integrations: [react(), tailwind()],
  vite: {
    server: {
      proxy: {
        '/health': process.env.API_PROXY_TARGET ?? 'http://127.0.0.1:8000',
        '/auth': process.env.API_PROXY_TARGET ?? 'http://127.0.0.1:8000',
        '/defense': process.env.API_PROXY_TARGET ?? 'http://127.0.0.1:8000',
        '/api': process.env.API_PROXY_TARGET ?? 'http://127.0.0.1:8000',
      },
    },
  },
});
