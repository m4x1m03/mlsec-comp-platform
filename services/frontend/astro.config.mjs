// @ts-check
import { defineConfig } from 'astro/config';

import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';

const apiTarget = process.env.API_INTERNAL_URL || 'http://127.0.0.1:8000';

// https://astro.build/config
export default defineConfig({
  output: 'server',
  integrations: [react(), tailwind()],
  vite: {
    server: {
      proxy: {
        '/health': apiTarget,
        '/auth':   apiTarget,
        '/api':    apiTarget,
      },
    },
  },
});