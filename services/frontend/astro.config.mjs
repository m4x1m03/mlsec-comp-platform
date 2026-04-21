// @ts-check
import { defineConfig } from 'astro/config';

import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';

const apiTarget = process.env.API_INTERNAL_URL || 'http://127.0.0.1:8000';

// https://astro.build/config
export default defineConfig({
  devToolbar: {
    enabled: false
  },
  output: 'server',
  integrations: [react(), tailwind()],
  vite: {
    server: {
      proxy: {
        '/health': apiTarget,
        '/auth':   apiTarget,
        '/api':    apiTarget,
        '/admin': {
          target: apiTarget,
          bypass(req) {
            // Let Vite handle the five admin page navigations directly.
            const adminPages = [
              '/admin',
              '/admin/users',
              '/admin/logs',
              '/admin/competition',
              '/admin/workers',
              '/admin/submissions',
            ];
            const url = (req.url ?? '').split('?')[0];
            const wantsHtml = (req.headers['accept'] ?? '').includes('text/html');
            if (adminPages.includes(url) && wantsHtml) {
              return url;
            }
          },
        },
      },
    },
  },
});