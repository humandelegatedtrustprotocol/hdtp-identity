// The release's manifest.json and SHA256SUMS, written into the directory of assets.
//
//   node scripts/release-manifest.mjs <dist-dir> <version> <commit> <protocol-commit>
//
// manifest.json is js/manifest.json of the tagged commit (the pin: crate_version, toolchain, builder,
// source inputs, and the sha256 and size of every file of both Wasm packages), with:
//   version          "X.Y.Z", no v
//   commit           the 40-hex commit both tags name
//   tags             ["vX.Y.Z", "go/vX.Y.Z"]
//   protocol_commit  the pact-protocol commit the release's gate ran against
//   assets           { "<basename>": { sha256, bytes } } for every other asset in the directory
// SHA256SUMS lists every asset but itself, manifest.json included, as `<hex>  <basename>`, sorted.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HEX40 = /^[0-9a-f]{40}$/;
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function write(dir, version, commit, protocolCommit, pin) {
  if (!HEX40.test(commit)) throw new Error(`commit ${commit} is not a 40-hex sha`);
  if (!HEX40.test(protocolCommit)) throw new Error(`protocol commit ${protocolCommit} is not a 40-hex sha`);
  const assets = {};
  for (const name of readdirSync(dir).sort()) {
    if (name === 'manifest.json' || name === 'SHA256SUMS') continue;
    if (!statSync(join(dir, name)).isFile()) throw new Error(`${name} in ${dir} is not a file`);
    const bytes = readFileSync(join(dir, name));
    assets[name] = { sha256: sha(bytes), bytes: bytes.length };
  }
  const manifest = { version, commit, tags: [`v${version}`, `go/v${version}`], protocol_commit: protocolCommit, ...pin, assets };
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  const sums = {};
  for (const name of [...Object.keys(assets), 'manifest.json'].sort()) sums[name] = sha(readFileSync(join(dir, name)));
  writeFileSync(join(dir, 'SHA256SUMS'), Object.entries(sums).map(([n, h]) => `${h}  ${n}\n`).join(''));
  return manifest;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [dir, version, commit, protocolCommit] = process.argv.slice(2);
  try {
    const pin = JSON.parse(readFileSync(fileURLToPath(new URL('../js/manifest.json', import.meta.url)), 'utf8'));
    const m = write(dir, version, commit, protocolCommit, pin);
    for (const [n, a] of Object.entries(m.assets)) console.log(`  ${n}  ${a.bytes} bytes  ${a.sha256}`);
  } catch (e) {
    console.error(`release-manifest: ${e.message}`);
    process.exit(1);
  }
}
