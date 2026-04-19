import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'WattcloudSDK',
      formats: ['es'],
      fileName: () => 'index.js',
    },
    rollupOptions: {
      external: (id: string) => {
        // Don't bundle @wattcloud/wasm — it's loaded at runtime
        return id === '@wattcloud/wasm';
      },
    },
    sourcemap: true,
    minify: false, // Keep readable for security audit
  },
  resolve: {
    alias: {
      // SDK WASM package — resolves to the built pkg directory
      '@wattcloud/wasm': resolve(__dirname, '../sdk/sdk-wasm/pkg/secure_cloud_wasm.js'),
    },
  },
  worker: {
    format: 'es',
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['__tests__/**/*.test.ts'],
  },
});