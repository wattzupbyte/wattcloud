/**
 * Vite asset-URL imports (`import url from './foo.wasm?url'`). TypeScript
 * doesn't understand the `?url` query on its own — this declaration covers
 * the small number of ?url imports the frontend uses (currently only the
 * sql.js wasm binary).
 */
declare module '*.wasm?url' {
  const url: string;
  export default url;
}
