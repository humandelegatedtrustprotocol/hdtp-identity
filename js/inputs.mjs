// What the pinned Wasm is built FROM, as one identity: the git tree entries, at HEAD, of every
// path that can change a byte of the binary. The pin is of a commit — js/reproduce.sh builds
// `git archive HEAD`, never a working tree — so the question "is this pin current?" has an exact
// answer that costs a second, not a five-minute container build: does HEAD carry the same inputs
// the pin was built from?
//
//   node js/inputs.mjs            print the identity of the inputs at HEAD
//   node js/inputs.mjs --dirty    list inputs with uncommitted changes (exit 1 if any)
//
// The list is here and nowhere else: manifest.mjs records it, verify.mjs compares it, reproduce.sh
// refuses to pin while it is dirty. Paths are relative to pact-identity/. The CLI crate is not on
// it on purpose — it is not in the Wasm — but anything it does to the lock file is, through
// Cargo.lock. This is the early warning; the proof is still the container build
// (js/reproduce.sh, and the `reproduce` job that runs it on every push).
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const INPUTS = [
  'crates/pact-identity',
  'crates/pact-identity-wasm',
  'Cargo.toml',
  'Cargo.lock',
  'rust-toolchain.toml',
  '.cargo/config.toml',
  'js/build.sh',
];

const root = fileURLToPath(new URL('../', import.meta.url));
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

/** The identity of the inputs at HEAD, or null where there is no git checkout to ask. */
export function inputsAtHead() {
  let listing;
  try { listing = git('ls-tree', '-r', 'HEAD', '--', ...INPUTS); } catch { return null; }
  const files = listing.split('\n').filter(Boolean).length;
  if (!files) return null;
  return { sha256: createHash('sha256').update(listing).digest('hex'), files };
}

/** Inputs whose working copy or index differs from HEAD. */
export function dirtyInputs() {
  try { return git('status', '--porcelain', '--', ...INPUTS).split('\n').filter(Boolean); } catch { return []; }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === '--dirty') {
    const dirty = dirtyInputs();
    for (const line of dirty) console.log(line);
    process.exit(dirty.length ? 1 : 0);
  }
  const at = inputsAtHead();
  if (!at) { console.error('inputs: this is not a git checkout, so there is no commit to name'); process.exit(2); }
  console.log(`${at.sha256}  (${at.files} files at HEAD)`);
}
