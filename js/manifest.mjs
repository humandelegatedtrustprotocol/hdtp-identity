// Writes js/manifest.json: the crate version, the SHA-256 and size of every .wasm, and the builder
// that made them — so a host that vendors the bytes can verify them (js/verify.mjs), and anybody
// can make them again (js/reproduce.sh). Run by `sh js/reproduce.sh --pin`, and by nothing else:
// the pinned bytes are the canonical container's, never whatever this machine happened to build.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const [toolchainFile, image, platform, wasmPackSha] = process.argv.slice(2);
if (!toolchainFile || !image || !platform || !wasmPackSha) {
  console.error('manifest: run `sh js/reproduce.sh --pin`; it says which builder made the bytes.');
  process.exit(2);
}
const here = new URL('./', import.meta.url);
const cargo = readFileSync(new URL('../Cargo.toml', here), 'utf8');
const crate_version = /^version\s*=\s*"([^"]+)"/m.exec(cargo)?.[1] ?? 'unknown';
const toolchain = JSON.parse(readFileSync(toolchainFile, 'utf8'));

const files = {};
for (const pkg of ['pkg-web', 'pkg-node']) {
  const name = `${pkg}/pact_identity_wasm_bg.wasm`;
  const bytes = readFileSync(new URL(name, here));
  files[name] = { sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
}
const manifest = {
  crate_version, rustc: toolchain.rustc, wasm_pack: toolchain.wasm_pack,
  builder: { image, platform, wasm_pack_sha256: wasmPackSha, how: 'sh js/reproduce.sh' },
  files,
};
writeFileSync(new URL('manifest.json', here), JSON.stringify(manifest, null, 2) + '\n');
for (const [name, f] of Object.entries(files)) console.log(`${name}: ${f.bytes} bytes, sha256 ${f.sha256}`);
