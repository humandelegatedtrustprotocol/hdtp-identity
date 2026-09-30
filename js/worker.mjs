// Cloudflare Workers: the *web* package initialised synchronously over a CompiledWasm module.
// wasm-bindgen's bundler target does not run on workerd (its module loader provides no named
// exports off a .wasm namespace), so a Worker imports this file — or copies its three lines —
// with this rule in wrangler.jsonc:
//   "rules": [{ "type": "CompiledWasm", "globs": ["**/*.wasm"], "fallthrough": true }]
// and vendors pkg-web/pact_identity_wasm.js and pact_identity_wasm_bg.wasm beside it, checking the
// bytes against manifest.json (js/verify.mjs), because Workers Builds has no Rust toolchain.
// Not verified under workerd from this repository; a host that runs it there tests it there.
import { initSync, call as rawCall, version as rawVersion } from './pkg-web/pact_identity_wasm.js';
import wasmModule from './pkg-web/pact_identity_wasm_bg.wasm';

initSync({ module: wasmModule });

export function call(name, args) {
  // As js/index.mjs: `args` left out is `{}`; anything else, `null` included, is the core's to judge.
  return JSON.parse(rawCall(name, JSON.stringify(args === undefined ? {} : args)));
}

export function version() {
  return JSON.parse(rawVersion());
}
