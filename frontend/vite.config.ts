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
        const wasmPath = resolve(__dirname, 'src/pkg/wattcloud_sdk_wasm_bg.wasm');
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

/**
 * Dev-server middleware: serve /dl/sw-download.js with an explicit
 * `text/javascript; charset=utf-8` Content-Type and `Service-Worker-Allowed: /dl/`.
 *
 * Without the charset, Firefox logs the "character encoding not declared"
 * warning every time the SW script is fetched. The Service-Worker-Allowed
 * header is strictly redundant here (scope `/dl/` is the default max scope
 * for a script served from `/dl/`), but making it explicit keeps dev and
 * prod aligned with the production relay config.
 *
 * We read the file ourselves rather than letting sirv/static middleware
 * handle it, because those would overwrite our Content-Type after we set it.
 */
function swHeadersPlugin(): Plugin {
  return {
    name: 'sw-headers',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url ?? '';
        if (url !== '/dl/sw-download.js' && !url.startsWith('/dl/sw-download.js?')) {
          return next();
        }
        try {
          const swPath = resolve(__dirname, 'public/dl/sw-download.js');
          const body = readFileSync(swPath);
          res.statusCode = 200;
          res.setHeader('Content-Type', 'text/javascript; charset=utf-8');
          res.setHeader('Service-Worker-Allowed', '/dl/');
          res.setHeader('Cache-Control', 'no-store');
          res.setHeader('X-Content-Type-Options', 'nosniff');
          res.end(body);
        } catch (e) {
          next(e as Error);
        }
      });
    },
  };
}

// Wattcloud is BYO-only — __BYO_MODE__ is always true. Kept as a compile-time
// flag so existing `if (__BYO_MODE__)` guards in copied code are a no-op
// rather than needing source edits.

export default defineConfig({
  plugins: [svelte(), wasmSriPlugin(), jsSriPlugin(), swHeadersPlugin()],
  define: {
    __BYO_MODE__: JSON.stringify(true),
    // Test-mode flag: exposes MockProvider in ProviderPicker for E2E tests.
    // Set BYO_TEST_MODE=true when running the dev server for BYO E2E tests.
    __BYO_TEST_MODE__: JSON.stringify(process.env.BYO_TEST_MODE === 'true'),
  },
  resolve: {
    alias: {
      $lib: resolve(__dirname, 'src/lib'),
      '@wattcloud/wasm': resolve(__dirname, 'src/pkg/wattcloud_sdk_wasm.js'),
      // BYO storage package — resolved from source for development builds.
      '@wattcloud/sdk': resolve(__dirname, 'src/lib/sdk/index.ts'),
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
    // Dev-only: forward relay endpoints (plus /health, /ready) to the locally
    // running byo-relay started by scripts/dev.sh. Same-origin fetches from
    // the SPA therefore reach the relay without CORS gymnastics. Override the
    // upstream with DEV_RELAY_URL when running the relay on a non-default port.
    proxy: {
      '/relay': {
        target: process.env.DEV_RELAY_URL || 'http://127.0.0.1:8443',
        changeOrigin: true,
        ws: true,
      },
      '/health': {
        target: process.env.DEV_RELAY_URL || 'http://127.0.0.1:8443',
        changeOrigin: true,
      },
      '/ready': {
        target: process.env.DEV_RELAY_URL || 'http://127.0.0.1:8443',
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
    // Exclude our own wasm-bindgen bundle from pre-bundling — it ships its own
    // ESM + .wasm glue and Vite's CJS→ESM wrapping breaks the __wbg_init flow.
    // sql.js is a UMD CJS bundle that leaves nothing on the ESM namespace
    // when evaluated as a module (no `typeof module`), so we *do* need Vite
    // to pre-bundle it — otherwise `import('sql.js').default` is undefined
    // and `initSqlJs(...)` throws "sql.default is not a function".
    exclude: ['@wattcloud/wasm'],
    force: true,
  },
  build: {
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
    // Single entry: index.html → src/main.ts → ByoApp.svelte. There is no
    // managed code path in this repo, so no conditional rollup input.
  },
  test: {
    // Playwright E2E specs must run via `npm run test:e2e`, not under Vitest.
    exclude: ['**/node_modules/**', '**/dist/**', 'tests/e2e/**'],
  },
});