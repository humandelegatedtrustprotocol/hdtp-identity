// A fresh instance of the Wasm core, with its linear memory in view: test tooling for
// js/export-memory.test.mjs. The node package's glue keeps its instance to itself, so its source is
// evaluated here as a module of its own with one line added that hands the memory out. Each call to
// `fresh()` is a new instance, so a measurement starts from the core's own starting size.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const glue = fileURLToPath(new URL('./pkg-node/hdtp_identity_wasm.js', import.meta.url));

export function fresh() {
  const source = readFileSync(glue, 'utf8') + '\nexports.__memory = () => wasm.memory;\n';
  const module = { exports: {} };
  const require = createRequire(glue);
  new Function('exports', 'require', 'module', '__filename', '__dirname', source)(module.exports, require, module, glue, glue.replace(/\/[^/]*$/, ''));
  const mod = module.exports;
  return {
    call: (name, args) => JSON.parse(mod.call(name, JSON.stringify(args === undefined ? {} : args))),
    /** The instance's linear memory, in bytes. It only ever grows. */
    bytes: () => mod.__memory().buffer.byteLength,
  };
}
