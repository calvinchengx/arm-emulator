// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { remarkMermaid } from './plugins/remark-mermaid.mjs';

// The site is published to GitHub Pages under /arm-emulator/docs/, so every
// generated link needs that base. The landing page in /site owns the root and
// the rendered docs sit beneath it. Docs content is generated from /docs by
// scripts/sync-docs.mjs before build — /docs stays the single source of truth.
export default defineConfig({
  site: 'https://calvinchengx.github.io',
  base: '/arm-emulator/docs/',
  markdown: { remarkPlugins: [remarkMermaid] },
  integrations: [
    starlight({
      title: 'ARM Emulator',
      description:
        'A local emulator of the Azure Resource Manager control plane — subscriptions, resource groups, role assignments and vault resources — driven by the real az CLI and management SDKs.',
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/calvinchengx/arm-emulator',
        },
      ],
      components: {
        // Hosts the parity version picker beside the header search.
        Search: './src/components/Search.astro',
        Head: './src/components/Head.astro',
        // A back-link to the landing page beside the site title. The component
        // explains why it cannot live in the header icon row or the sidebar.
        SiteTitle: './src/components/SiteTitle.astro',
      },
      sidebar: [
        {
          label: 'Getting started',
          items: [
            { slug: 'index' },
            { slug: '01-quickstart' },
            { slug: '02-installation' },
            { slug: '03-architecture' },
            { slug: '04-configuration' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { slug: '05-authorization' },
            { slug: '06-keyvault-provider' },
            { slug: '10-fabric-provider' },
            { slug: '07-family-feed' },
          ],
        },
        {
          label: 'Testing',
          items: [{ slug: '08-testing' }],
        },
        {
          label: 'Project',
          items: [
            { slug: 'parity', label: 'Parity' },
            { slug: 'parity-history' },
            { slug: 'parity-history/changelog' },
            { slug: '09-roadmap' },
          ],
        },
      ],
    }),
  ],
});
