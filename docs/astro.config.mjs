// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Custom domain — see docs/public/CNAME. Pages serves from the custom
// domain at the root, so no `base` is needed. If the domain ever moves,
// update both this file and public/CNAME.
export default defineConfig({
  site: 'https://docs.wattcloud.de',
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
        {
          label: 'Operations',
          items: [
            { label: 'VPS hardening', link: '/operations/hardening/' },
            { label: 'Backups', link: '/operations/backups/' },
            { label: 'Troubleshooting', link: '/operations/troubleshooting/' },
            { label: 'Recovery', link: '/operations/recovery/' },
          ],
        },
        {
          label: 'Concepts',
          items: [
            { label: 'Security model', link: '/concepts/security-model/' },
            { label: 'Sharing', link: '/concepts/sharing/' },
            { label: 'Multi-device', link: '/concepts/multi-device/' },
            { label: 'Identity & passkeys', link: '/concepts/identity/' },
          ],
        },
        { label: 'FAQ', link: '/faq/' },
      ],
    }),
  ],
});
