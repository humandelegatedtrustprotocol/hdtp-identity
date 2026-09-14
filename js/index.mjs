// The loader: the Node package under Node, the web package elsewhere. `load()` resolves to
// `{ call(name, args), version() }`, where `args` is an object and every answer is a parsed object
// — `{ error, why }` on failure, never an exception from the core itself.
export async function load() {
  const isNode = typeof process !== 'undefined' && !!process.versions?.node;
  if (isNode) {
    const { createRequire } = await import('node:module');
    const require = createRequire(import.meta.url);
    return wrap(require('./pkg-node/pact_identity_wasm.js'));
  }
  const mod = await import('./pkg-web/pact_identity_wasm.js');
  await mod.default(); // fetches pact_identity_wasm_bg.wasm beside the module
  return wrap(mod);
}

export function wrap(mod) {
  return {
    call: (name, args) => JSON.parse(mod.call(name, JSON.stringify(args ?? {}))),
    version: () => JSON.parse(mod.version()),
  };
}
