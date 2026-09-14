// Writes js/manifest.json after a build: the crate version, the toolchain, and the SHA-256 and size
// of every .wasm, so a host that vendors the bytes can verify them (js/verify.mjs).
import { createHash } from 'node:crypto';
import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';

const here = new URL('./', import.meta.url);
const cargo = readFileSync(new URL('../Cargo.toml', here), 'utf8');
const crate_version = /^version\s*=\s*"([^"]+)"/m.exec(cargo)?.[1] ?? 'unknown';
const tool = (cmd) => { try { return execSync(cmd, { encoding: 'utf8' }).trim(); } catch { return 'unknown'; } };

const files = {};
for (const pkg of ['pkg-web', 'pkg-node']) {
  const name = `${pkg}/pact_identity_wasm_bg.wasm`;
  const bytes = readFileSync(new URL(name, here));
  files[name] = { sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
}
const manifest = { crate_version, rustc: tool('rustc --version'), wasm_pack: tool('wasm-pack --version'), files };
writeFileSync(new URL('manifest.json', here), JSON.stringify(manifest, null, 2) + '\n');
for (const [name, f] of Object.entries(files)) console.log(`${name}: ${f.bytes} bytes, sha256 ${f.sha256}`);
