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
  // The builder itself: the image digest, the platform and the wasm-pack release. Not on this list,
  // a bump of any of them left the pin looking current while the committed builder could no longer
  // produce those bytes.
  'js/builder.json',
];

const root = fileURLToPath(new URL('../', import.meta.url));
const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

/**
 * The identity of the inputs at HEAD, or null where there is no git checkout to ask.
 *
 * Every entry is also checked for matching SOMETHING. `git ls-tree` does not error on a pathspec
 * that matches nothing, so renaming `.cargo/config.toml` to `.cargo/config` — which cargo still
 * reads, and which still sets the wasm32 rustflags — would drop it from the listing, fail `verify`
 * once, and leave it permanently unwatched after the next re-pin. A typo in this list did the same.
 */
export function inputsAtHead() {
  let listing;
  try { listing = git('ls-tree', '-r', 'HEAD', '--', ...INPUTS); } catch { return null; }
  const files = listing.split('\n').filter(Boolean).length;
  if (!files) return null;
  const empty = INPUTS.filter((p) => {
    try { return git('ls-tree', '-r', 'HEAD', '--', p).trim() === ''; } catch { return true; }
  });
  if (empty.length) {
    throw new Error(`these build inputs match no tracked file at HEAD, so nothing is watching them: ${empty.join(', ')}`);
  }
  return { sha256: createHash('sha256').update(listing).digest('hex'), files };
}

/**
 * Inputs whose working copy or index differs from HEAD.
 *
 * A git failure is NOT an empty answer. This swallowed every error and returned `[]`, which
 * `reproduce.sh --pin` reads as "clean" — so a git version that refused an argument, or a `.git` in
 * a state `status` would not report on, let a pin be taken over uncommitted inputs: exactly the
 * ambush the pin-of-commit design exists to prevent.
 */
export function dirtyInputs() {
  return git('status', '--porcelain', '--', ...INPUTS).split('\n').filter(Boolean);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === '--dirty') {
    // 0 clean, 1 dirty, 2 could not tell — and `reproduce.sh` treats 2 as fatal when pinning.
    let dirty;
    try { dirty = dirtyInputs(); } catch (e) { console.error(`inputs: ${e.message}`); process.exit(2); }
    for (const line of dirty) console.log(line);
    process.exit(dirty.length ? 1 : 0);
  }
  const at = inputsAtHead();
  if (!at) { console.error('inputs: this is not a git checkout, so there is no commit to name'); process.exit(2); }
  console.log(`${at.sha256}  (${at.files} files at HEAD)`);
}
