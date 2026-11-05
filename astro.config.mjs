import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://tinylabscom.github.io',
  base: '/mvm-packs',
  integrations: [
    starlight({
      title: 'Pack registry',
      sidebar: [
        { label: 'Packs', link: '/' },
        { label: 'Agents', items: [{ autogenerate: { directory: 'agent' } }] },
        { label: 'Runtimes', items: [{ autogenerate: { directory: 'runtime' } }] },
      ],
    }),
  ],
});
