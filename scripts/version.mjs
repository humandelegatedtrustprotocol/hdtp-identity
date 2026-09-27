// The one version of pact-identity, and every place it is written. A release is one version for the
// Rust crates, the Go module and the Wasm package (tags vX.Y.Z and go/vX.Y.Z name the same commit);
// the copies below are held equal here, because two copies of one value drift the day they are
// written.
//
//   node scripts/version.mjs            print the version (every copy must agree)
//   node scripts/version.mjs --check    exit 1 unless every copy agrees
//   node scripts/version.mjs --set X.Y.Z   write X.Y.Z into every copy (make release does this)
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
export const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

// Each copy: the file, how to read the version from it, how to write one into it. Every reader must
// match exactly once; a copy that is not found is a failure, never a silent skip.
const LOCK_CRATES = ['pact', 'pact-identity', 'pact-identity-wasm'];
const lockRe = (name) => new RegExp(`(\\[\\[package\\]\\]\\nname = "${name}"\\nversion = ")([^"]+)(")`, 'g');
export const COPIES = [
  { file: 'Cargo.toml', re: () => /(\[workspace\.package\]\nversion = ")([^"]+)(")/g },
  ...LOCK_CRATES.map((name) => ({ file: 'Cargo.lock', label: `Cargo.lock (${name})`, re: () => lockRe(name) })),
  { file: 'js/package.json', re: () => /(\n {2}"version": ")([^"]+)(")/g },
  { file: 'go/api.go', re: () => /(\n\tModuleVersion = ")([^"]+)(")/g },
];

export function read(dir = root) {
  return COPIES.map((c) => {
    const text = readFileSync(dir + c.file, 'utf8');
    const hits = [...text.matchAll(c.re())];
    if (hits.length !== 1) throw new Error(`${c.label ?? c.file}: the version is written ${hits.length} times where it must be written once`);
    return { where: c.label ?? c.file, version: hits[0][2] };
  });
}

export function set(version, dir = root) {
  if (!SEMVER.test(version)) throw new Error(`${version} is not X.Y.Z`);
  for (const c of COPIES) {
    const text = readFileSync(dir + c.file, 'utf8');
    let n = 0;
    const out = text.replace(c.re(), (_, a, _v, b) => { n++; return a + version + b; });
    if (n !== 1) throw new Error(`${c.label ?? c.file}: found the version ${n} times`);
    writeFileSync(dir + c.file, out);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv[2] === '--set') { set(process.argv[3]); }
    const copies = read();
    const distinct = [...new Set(copies.map((c) => c.version))];
    if (distinct.length !== 1) {
      console.error('version: the copies disagree:');
      for (const c of copies) console.error(`  ${c.where.padEnd(32)} ${c.version}`);
      process.exit(1);
    }
    if (process.argv[2] === '--check') console.log(`version: ok (${distinct[0]} in all ${copies.length} places)`);
    else console.log(distinct[0]);
  } catch (e) {
    console.error(`version: ${e.message}`);
    process.exit(2);
  }
}
