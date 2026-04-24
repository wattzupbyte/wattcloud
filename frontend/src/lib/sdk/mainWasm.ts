/**
 * Main-thread WASM initialisation.
 *
 * The Web Worker has its own WASM instance initialised at worker boot
 * (`byo.worker.ts` → `initWasm`). The main thread imports the same
 * wasm-pack module but gets a SEPARATE instance that must be initialised
 * independently before any exports can be called — otherwise `wasm` is
 * undefined inside the pkg module and calling e.g.
 * `sftp_store_credential_password` throws:
 *
 *    can't access property "__wbindgen_malloc", wasm is undefined
 *
 * Currently used from the main thread by:
 *   - SFTP credential registry (`byoWorkerClient.ts`) — plaintext
 *     credentials stay in the main-thread WASM heap so they don't cross
 *     the postMessage boundary into the worker.
 *   - `SftpProvider.ts` — constructs `SftpSessionWasm` on the main thread
 *     because it needs the WebSocket pair.
 *
 * The init call is memoised — safe to call from many entry points.
 */

let initPromise: Promise<unknown> | null = null;

export async function ensureMainThreadWasm<T = unknown>(): Promise<T> {
  if (!initPromise) {
    initPromise = (async () => {
      const wasmModule = await import('@wattcloud/wasm') as unknown as {
        default?: (...args: unknown[]) => Promise<unknown>;
      };
      if (typeof wasmModule.default === 'function') {
        await wasmModule.default();
      }
      return wasmModule;
    })();
  }
  return initPromise as Promise<T>;
}
