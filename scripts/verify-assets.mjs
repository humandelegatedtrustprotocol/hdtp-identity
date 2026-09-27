// The offline half of `make verify-release`: a directory of downloaded release assets, judged
// against SHA256SUMS, manifest.json, the tags' commits and the pin at the tag.
//
//   node scripts/verify-assets.mjs <assets-dir> <pin.json> <version> <vX.Y.Z commit> <go/vX.Y.Z commit>
import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

const [dir, pinFile, version, tagCommit, goTagCommit] = process.argv.slice(2);
const sha = (b) => createHash('sha256').update(b).digest('hex');
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const problems = [];
const names = readdirSync(dir).sort();
const m = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'));
const pin = JSON.parse(readFileSync(pinFile, 'utf8'));

// SHA256SUMS: every asset but itself, no more and no fewer, each hash right.
const sums = new Map();
for (const line of readFileSync(join(dir, 'SHA256SUMS'), 'utf8').trim().split('\n')) {
  const x = /^([0-9a-f]{64}) {2}(\S+)$/.exec(line);
  if (x) sums.set(x[2], x[1]); else problems.push(`SHA256SUMS: a line not of the form "<hex>  <name>": ${line}`);
}
const others = names.filter((n) => n !== 'SHA256SUMS');
if (!same([...sums.keys()].sort(), others)) problems.push(`SHA256SUMS lists ${[...sums.keys()].sort().join(', ')}; the release holds ${others.join(', ')}`);
for (const n of others) if (sums.has(n) && sums.get(n) !== sha(readFileSync(join(dir, n)))) problems.push(`${n}: its sha256 is not the one SHA256SUMS lists`);

// manifest.json's assets: every asset but itself and SHA256SUMS, each size and hash right.
const assetNames = names.filter((n) => n !== 'SHA256SUMS' && n !== 'manifest.json');
if (!same(Object.keys(m.assets ?? {}).sort(), assetNames)) problems.push(`manifest.json lists ${Object.keys(m.assets ?? {}).join(', ')}; the release holds ${assetNames.join(', ')}`);
for (const n of assetNames) {
  const b = readFileSync(join(dir, n));
  const a = m.assets?.[n];
  if (a && (a.sha256 !== sha(b) || a.bytes !== b.length)) problems.push(`${n}: ${b.length} bytes, sha256 ${sha(b)}; manifest.json says ${a.bytes}, ${a.sha256}`);
}

// What it claims to be: the version, the tags, the commit both tags name, the pin at that commit.
if (m.version !== version) problems.push(`manifest.json is for ${m.version}, not ${version}`);
if (!same(m.tags, [`v${version}`, `go/v${version}`])) problems.push(`manifest.json names the tags ${JSON.stringify(m.tags)}`);
if (m.commit !== tagCommit || m.commit !== goTagCommit) problems.push(`manifest.json names commit ${m.commit}; v${version} is ${tagCommit} and go/v${version} is ${goTagCommit}`);
if (!/^[0-9a-f]{40}$/.test(m.protocol_commit ?? '')) problems.push('manifest.json has no protocol_commit');
for (const k of Object.keys(pin)) if (!same(m[k], pin[k])) problems.push(`manifest.json's ${k} is not js/manifest.json's at v${version}`);

// The Wasm tarball: exactly the pinned pkg-web/ files, with the pinned bytes.
const tgz = `pact-identity-wasm-web-${version}.tgz`;
if (!names.includes(tgz)) problems.push(`the release has no ${tgz}`);
else {
  const out = mkdtempSync(join(tmpdir(), 'pact-verify-'));
  execFileSync('tar', ['-xzf', join(dir, tgz), '-C', out]);
  const want = Object.keys(pin.files).filter((k) => k.startsWith('pkg-web/')).sort();
  const top = readdirSync(out);
  if (!same(top, ['pkg-web'])) problems.push(`${tgz}'s top level is ${top.join(', ')}, not pkg-web/`);
  let got = [];
  try { got = readdirSync(join(out, 'pkg-web')).map((n) => `pkg-web/${n}`).sort(); } catch { /* reported above */ }
  if (!same(got, want)) problems.push(`${tgz} holds ${got.join(', ')}; the pin lists ${want.join(', ')}`);
  for (const k of want.filter((x) => got.includes(x))) {
    const b = readFileSync(join(out, k));
    if (sha(b) !== pin.files[k].sha256 || b.length !== pin.files[k].bytes) problems.push(`${tgz}: ${k} is not the pinned bytes`);
  }
}

if (problems.length) {
  console.error('verify-release:\n  ' + problems.join('\n  '));
  process.exit(1);
}
console.log(`verify-release: ${names.length} assets agree with SHA256SUMS, manifest.json, both tags and the pin at v${version}`);
