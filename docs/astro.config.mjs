// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// When the site moves to docs.wattcloud.de, set `site` to that URL and drop
// `base`. Until then we publish under wattzupbyte.github.io/wattcloud.
export default defineConfig({
  site: 'https://wattzupbyte.github.io',
  base: '/wattcloud',
  integrations: [
    starlight({
      title: 'Wattcloud',
      description:
        'Operator handbook for self-hosting Wattcloud — a zero-knowledge, bring-your-own-storage cloud file manager.',
      favicon: '/favicon.svg',
      customCss: [
        './src/styles/design-system.css',
        './src/styles/docs-overrides.css',
        '@fontsource/inter/400.css',
        '@fontsource/inter/500.css',
        '@fontsource/inter/600.css',
        '@fontsource/inter/700.css',
      ],
      components: {
        SiteTitle: './src/components/SiteTitle.astro',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/wattzupbyte/wattcloud',
        },
      ],
      lastUpdated: true,
      pagination: true,
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
      sidebar: [
        { label: 'Quickstart', link: '/quickstart/' },
        {
          label: 'Install',
          items: [
            { label: 'One-command install', link: '/install/one-command-install/' },
            { label: 'Access control', link: '/install/access-control/' },
            { label: 'Upgrade & rollback', link: '/install/upgrades/' },
          ],
        },
        {
          label: 'Storage providers',
          items: [
            { label: 'WebDAV', link: '/providers/webdav/' },
            { label: 'SFTP', link: '/providers/sftp/' },
            { label: 'S3-compatible', link: '/providers/s3/' },
          ],
        },
      ],
    }),
  ],
});
