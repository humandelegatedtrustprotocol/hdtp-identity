// Writes js/manifest.json: the crate version, the SHA-256 and size of every .wasm, and the builder
// that made them — so a host that vendors the bytes can verify them (js/verify.mjs), and anybody
// can make them again (js/reproduce.sh). Run by `sh js/reproduce.sh --pin`, and by nothing else:
// the pinned bytes are the canonical container's, never whatever this machine happened to build.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { INPUTS, inputsAtHead } from './inputs.mjs';

const [toolchainFile] = process.argv.slice(2);
if (!toolchainFile) {
  console.error('manifest: run `sh js/reproduce.sh --pin`; it says which builder made the bytes.');
  process.exit(2);
}
// Copied verbatim from the file both this and reproduce.sh read, so `verify.mjs` can hold a later
// tree's builder to the one the pin was made by.
const here = new URL('./', import.meta.url);
const builder = JSON.parse(readFileSync(new URL('builder.json', here), 'utf8'));
const cargo = readFileSync(new URL('../Cargo.toml', here), 'utf8');
const crate_version = /^version\s*=\s*"([^"]+)"/m.exec(cargo)?.[1] ?? 'unknown';
const toolchain = JSON.parse(readFileSync(toolchainFile, 'utf8'));

// EVERY file in each package, not one per package. A host does not run the `.wasm` on its own: a
// Worker imports `pact_identity_wasm.js`, 13 KB of wasm-bindgen glue that marshals every argument
// and every answer across the boundary — vault and PRF material included — and it was vendored
// beside the module and hashed by nothing. Editing one line of it to forward the argument string
// somewhere passed `verify.mjs`, the vendoring host's own check and `reproduce.sh`, because the
// `.wasm` was untouched. The packages are whole-directory copies of the container's
// output, so they were always canonical; only the record of them was partial.
const files = {};
for (const pkg of ['pkg-web', 'pkg-node']) {
  for (const entry of readdirSync(new URL(`${pkg}/`, here)).sort()) {
    const name = `${pkg}/${entry}`;
    const bytes = readFileSync(new URL(name, here));
    files[name] = { sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
  }
}
// What the bytes were built FROM. reproduce.sh builds `git archive HEAD` and refuses to pin while
// an input is uncommitted, so HEAD's inputs are exactly the source of these bytes; verify.mjs holds
// every later HEAD to this, which is how "the source moved and the pin did not" is learned in a
// second instead of from a container five minutes after a push.
const source = inputsAtHead();
if (!source) { console.error('manifest: no git checkout here, so the pin cannot name the commit it is of'); process.exit(2); }
const manifest = {
  crate_version, rustc: toolchain.rustc, wasm_pack: toolchain.wasm_pack,
  builder: { ...builder, how: 'sh js/reproduce.sh' },
  source: { inputs_sha256: source.sha256, files: source.files, paths: INPUTS, how: 'node js/inputs.mjs' },
  files,
};
writeFileSync(new URL('manifest.json', here), JSON.stringify(manifest, null, 2) + '\n');
for (const [name, f] of Object.entries(files)) console.log(`${name}: ${f.bytes} bytes, sha256 ${f.sha256}`);
