import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { resolve } from 'path';
import { createHash } from 'crypto';
import { readFileSync } from 'fs';

/**
 * Vite plugin that computes the sha384 SRI hash of the compiled WASM binary at
 * build/dev-server start time and exposes it via the `virtual:wasm-sri` module.
 * The hash is recomputed on every build so it stays in sync with wasm-pack output.
 */
function wasmSriPlugin(): Plugin {
  const virtualId = 'virtual:wasm-sri';
  const resolvedId = '\0' + virtualId;
  return {
    name: 'wasm-sri',
    resolveId(id) {
      if (id === virtualId) return resolvedId;
    },
    load(id) {
      if (id === resolvedId) {
        const wasmPath = resolve(__dirname, 'src/pkg/secure_cloud_sdk_wasm_bg.wasm');
        const wasmBytes = readFileSync(wasmPath);
        const hash = createHash('sha384').update(wasmBytes).digest('base64');
        const integrity = `sha384-${hash}`;
        return `export const WASM_INTEGRITY = ${JSON.stringify(integrity)};`;
      }
    },
  };
}

/**
 * Vite plugin that adds SRI (Subresource Integrity) hashes to all generated JS and CSS bundles.
 * SECURITY: Prevents tampering with JavaScript and CSS files in transit or on CDN.
 */
function jsSriPlugin(): Plugin {
  return {
    name: 'js-sri',
    enforce: 'post',
    generateBundle(_, bundle) {
      for (const [fileName, file] of Object.entries(bundle)) {
        if (fileName.endsWith('.js') && file.type === 'chunk') {
          const content = typeof file.code === 'string' ? file.code : '';
          if (content) {
            const hash = createHash('sha384').update(content).digest('base64');
            (file as any).integrity = `sha384-${hash}`;
          }
        } else if (fileName.endsWith('.css') && file.type === 'asset') {
          const content = typeof file.source === 'string'
            ? file.source
            : file.source instanceof Uint8Array
              ? Buffer.from(file.source)
              : null;
          if (content) {
            const hash = createHash('sha384').update(content).digest('base64');
            (file as any).integrity = `sha384-${hash}`;
          }
        }
      }
    },
    transformIndexHtml(html, { bundle }) {
      if (!bundle) return html;

      const integrityMap = new Map<string, string>();
      for (const [fileName, file] of Object.entries(bundle)) {
        const integrity = (file as any).integrity;
        if (integrity) {
          integrityMap.set(fileName, integrity);
        }
      }

      // Add integrity + crossorigin to <script src="...js"> tags
      html = html.replace(
        /<script([^>]*)src=["']([^"']+\.js)["']([^>]*)>/gi,
        (match, before, src, after) => {
          const fileName = src.startsWith('/') ? src.slice(1) : src;
          const integrity = integrityMap.get(fileName);
          if (integrity) {
            const newBefore = before.includes('crossorigin') ? before : `${before} crossorigin`;
            return `<script${newBefore}src="${src}" integrity="${integrity}"${after}>`;
          }
          return match;
        }
      );

      // Add integrity + crossorigin to <link rel="stylesheet" href="...css"> tags
      html = html.replace(
        /<link([^>]*)href=["']([^"']+\.css)["']([^>]*)\/?>/gi,
        (match, before, href, after) => {
          const fileName = href.startsWith('/') ? href.slice(1) : href;
          const integrity = integrityMap.get(fileName);
          if (integrity) {
            const newBefore = before.includes('crossorigin') ? before : `${before} crossorigin`;
            return `<link${newBefore}href="${href}" integrity="${integrity}"${after}>`;
          }
          return match;
        }
      );

      return html;
    },
  };
}

// Build-time mode flag. VITE_MODE=byo for BYO build, default is managed.
const viteMode = process.env.VITE_MODE || 'managed';

export default defineConfig({
  plugins: [svelte(), wasmSriPlugin(), jsSriPlugin()],
  define: {
    // Tree-shaking flag: BYO-specific code is dead-code eliminated in managed builds.
    __BYO_MODE__: JSON.stringify(viteMode === 'byo'),
    // Test-mode flag: exposes MockProvider in ProviderPicker for E2E tests.
    // Set BYO_TEST_MODE=true when running the dev server for BYO E2E tests.
    __BYO_TEST_MODE__: JSON.stringify(process.env.BYO_TEST_MODE === 'true'),
  },
  resolve: {
    alias: {
      $lib: resolve(__dirname, 'src/lib'),
      '@wattcloud/wasm': resolve(__dirname, 'src/pkg/secure_cloud_sdk_wasm.js'),
      // BYO storage package — resolved from source for development builds.
      '@wattcloud/sdk': resolve(__dirname, '../byo/src/index.ts'),
    },
  },
  // SECURITY: Workers must be emitted as ES modules for code-splitting compatibility.
  // IIFE format is incompatible with code-splitting builds and causes CryptoBridge
  // to silently fall back to main-thread secureMemory, removing XSS isolation.
  worker: {
    format: 'es',
  },
  server: {
    port: 5173,
    strictPort: true,
    host: '0.0.0.0',
    allowedHosts: true,
    cors: {
      origin: '*',
    },
    // HMR disabled — WebSocket tunnelling through Traefik is unreliable.
    // File changes are detected via polling; refresh the browser manually.
    hmr: false,
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://localhost:3000',
        changeOrigin: true,
      },
    },
    headers: {
      'Cache-Control': 'no-store',
    },
    // File watching with polling enabled — monitors local changes and reloads
    watch: {
      usePolling: true,
      interval: 1000,
    },
  },
  optimizeDeps: {
    // Exclude WASM modules from Vite's dependency pre-bundling.
    exclude: ['@wattcloud/wasm', 'sql.js'],
    force: true,
  },
  build: {
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
    rollupOptions: viteMode === 'byo' ? {
      // Hard BYO-only entry: managed component graph never enters the bundle.
      // Only index.byo.html → main-byo.ts → ByoApp.svelte is reachable.
      input: resolve(__dirname, 'index.byo.html'),
    } : undefined,
  },
  test: {
    // Playwright E2E specs must run via `npm run test:e2e`, not under Vitest.
    exclude: ['**/node_modules/**', '**/dist/**', 'tests/e2e/**'],
  },
});