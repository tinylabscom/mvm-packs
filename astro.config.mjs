import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://tinylabscom.github.io',
  base: '/mvm-packs',
  integrations: [
    starlight({
      title: 'Pack registry',
      customCss: ['./src/styles/registry.css'],
      sidebar: [
        { label: 'Packs', link: '/' },
        { label: 'Agents', items: [{ autogenerate: { directory: 'agent' } }] },
        { label: 'Runtimes', items: [{ autogenerate: { directory: 'runtime' } }] },
        { label: 'Publish a pack', link: '/publish/' },
      ],
    }),
  ],
});
