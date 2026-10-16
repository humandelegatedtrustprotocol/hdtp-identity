// The one version of hdtp-identity, and every place it is written. A release is one version for the
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

// The workspace's crates, read from the workspace itself: every member of Cargo.toml's `members`,
// by the name its own Cargo.toml gives it. This was a list written here by hand, and when
// crates/hdtp-limits joined the workspace (2026-09-28) the list did not: `--check` said "ok" with that
// crate's lock entry never read, and `make release` then wrote the new version into three of the four
// crates and stopped at a lock file that no longer resolved.
export function workspaceCrates(dir = root) {
  const ws = readFileSync(dir + 'Cargo.toml', 'utf8');
  const m = /\[workspace\][^[]*?\nmembers = \[([^\]]*)\]/.exec(ws);
  if (!m) throw new Error('Cargo.toml: no [workspace] members list');
  const members = [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
  if (!members.length) throw new Error('Cargo.toml: the [workspace] members list is empty');
  return members.map((p) => {
    const name = /^\[package\]\nname = "([^"]+)"/m.exec(readFileSync(`${dir}${p}/Cargo.toml`, 'utf8'));
    if (!name) throw new Error(`${p}/Cargo.toml: no [package] name`);
    return name[1];
  });
}

// Each copy: the file, how to read the version from it, how to write one into it. Every reader must
// match exactly once; a copy that is not found is a failure, never a silent skip.
const lockRe = (name) => new RegExp(`(\\[\\[package\\]\\]\\nname = "${name}"\\nversion = ")([^"]+)(")`, 'g');
export const copies = (dir = root) => [
  { file: 'Cargo.toml', re: () => /(\[workspace\.package\]\nversion = ")([^"]+)(")/g },
  ...workspaceCrates(dir).map((name) => ({ file: 'Cargo.lock', label: `Cargo.lock (${name})`, re: () => lockRe(name) })),
  { file: 'js/package.json', re: () => /(\n {2}"version": ")([^"]+)(")/g },
  { file: 'go/api.go', re: () => /(\n\tModuleVersion = ")([^"]+)(")/g },
  // README.md's install snippets, which name the release a host copies them from: the version of the
  // tree they ship in, written by `make release` with the rest. They named 0.7.3 through 0.8.3 (#70).
  { file: 'README.md', label: 'README.md (go get)', re: () => /(\ngo get github\.com\/humandelegatedtrustprotocol\/hdtp-identity\/go@v)([^\s]+)(\n)/g },
  { file: 'README.md', label: 'README.md (Cargo tag)', re: () => /(\nhdtp-identity = \{ git = "https:\/\/github\.com\/humandelegatedtrustprotocol\/hdtp-identity", tag = "v)([^"]+)(")/g },
  { file: 'README.md', label: 'README.md (gh release download)', re: () => /(\ngh release download v)([^\s]+)( -R humandelegatedtrustprotocol\/hdtp-identity )/g },
  { file: 'README.md', label: 'README.md (the web package)', re: () => /(tar -xzf vendor\/hdtp-identity-wasm-web-)([^\s]+?)(\.tgz )/g },
];

export function read(dir = root) {
  return copies(dir).map((c) => {
    const text = readFileSync(dir + c.file, 'utf8');
    const hits = [...text.matchAll(c.re())];
    if (hits.length !== 1) throw new Error(`${c.label ?? c.file}: the version is written ${hits.length} times where it must be written once`);
    return { where: c.label ?? c.file, version: hits[0][2] };
  });
}

export function set(version, dir = root) {
  if (!SEMVER.test(version)) throw new Error(`${version} is not X.Y.Z`);
  for (const c of copies(dir)) {
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
