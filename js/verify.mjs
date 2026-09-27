// Recomputes the SHA-256 of the built .wasm files and compares them with js/manifest.json.
//   node verify.mjs            — checks both packages in place
//   node verify.mjs <file> [entry]  — checks one copy against a named manifest entry (pkg-web's by default)
//   node verify.mjs --inputs   — only the fast question below (what the post-commit hook asks)
// Exit 1 on any mismatch, so a pipeline that vendors the bytes cannot ship a different core.
//
// **First, in every mode: is the pin OF this commit?** The manifest records the identity of the
// build inputs it was made from (js/inputs.mjs); if HEAD's inputs differ, the source moved after
// the pin and the bytes below describe an older commit, however well they hash. That answer takes
// a second and needs no build.
//
// **What a mismatch usually means: the source moved and the pin did not.** On 2026-09-19 the
// pinned core turned out to predate the 1.x removal by two days — it still contained the 1.x
// compat-card encoder the source had deleted — and nothing had noticed, because this check only
// ran where somebody had just rebuilt. So the first thing to ask is whether `crates/` changed
// since `manifest.json` did (`git log -1 -- crates js/manifest.json`); if it did, pin again with
// `sh js/reproduce.sh --pin` and commit the manifest; hosts take the bytes from a release.
//
// **The other ordinary cause is that the bytes were built HERE.** The pin is the build one
// container makes (js/reproduce.sh), because cargo lays the same code out differently on every
// host. `sh js/build.sh` on a developer's machine gives a core that behaves identically and
// hashes differently; checking js/pkg-* in place after one is expected to fail, and says so.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { inputsAtHead } from './inputs.mjs';

const here = new URL('./', import.meta.url);
const manifest = JSON.parse(readFileSync(new URL('manifest.json', here), 'utf8'));
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

let failures = 0;
// The BUILDER the pin was made by, against the builder this tree would use. Nothing compared these:
// `manifest.builder` was only ever printed, inside a failure message, so bumping the image digest left
// this saying "ok pin-of-commit" while the committed builder could no longer produce the pinned bytes.
const builder = JSON.parse(readFileSync(new URL('builder.json', here), 'utf8'));
for (const k of ['image', 'platform', 'wasm_pack', 'wasm_pack_sha256']) {
  const was = manifest.builder?.[k];
  if (was !== builder[k]) {
    failures++;
    console.log(`FAIL builder: js/builder.json's ${k} is ${builder[k] ?? '(absent)'}, and the pin was built with ${was ?? '(absent)'}`);
    console.log('     The committed builder can no longer make these bytes. sh js/reproduce.sh --pin');
  }
}

const head = inputsAtHead();
if (!head) {
  console.log('note pin-of-commit: not checked — this is not a git checkout, so there is no HEAD to compare with');
} else if (!manifest.source?.inputs_sha256) {
  failures++;
  console.log('FAIL pin-of-commit: js/manifest.json does not say what it was built from. Pin again: sh js/reproduce.sh --pin');
} else if (manifest.source.inputs_sha256 !== head.sha256) {
  failures++;
  console.log(`FAIL pin-of-commit: HEAD's build inputs (${head.sha256.slice(0, 16)}…) are not the ones the pin was built from (${manifest.source.inputs_sha256.slice(0, 16)}…).`);
  console.log('     A commit changed the Rust source, the lock file, the toolchain or js/build.sh after the pin.');
  console.log('     sh js/reproduce.sh --pin   then commit js/manifest.json.');
} else {
  console.log(`ok   pin-of-commit: HEAD's ${head.files} build inputs are the ones the pin was built from`);
}
if (process.argv[2] === '--inputs') process.exit(failures ? 1 : 0);
const check = (label, bytes, expected) => {
  const got = sha(bytes);
  const ok = got === expected.sha256 && bytes.length === expected.bytes;
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}: ${bytes.length} bytes, sha256 ${got}${ok ? '' : ` (manifest: ${expected.bytes} bytes, ${expected.sha256})`}`);
};

const file = process.argv[2];
if (file) {
  const entry = process.argv[3] && !process.argv[3].startsWith('--') ? process.argv[3] : 'pkg-web/pact_identity_wasm_bg.wasm';
  const expected = manifest.files[entry];
  if (!expected) {
    console.log(`FAIL ${file}: js/manifest.json has no entry named ${entry}`);
    process.exit(1);
  }
  check(file, readFileSync(file), expected);
} else {
  for (const [name, expected] of Object.entries(manifest.files)) check(name, readFileSync(new URL(name, here)), expected);
}
if (failures) {
  console.log('');
  console.log('  These bytes are not the pinned ones. The pin is what ONE container builds:');
  console.log(`    ${manifest.builder?.image ?? '(no builder recorded)'} on ${manifest.builder?.platform ?? '?'}`);
  console.log('  If they were built on this machine with `sh js/build.sh`, that is why: cargo lays the same');
  console.log('  code out differently per host. `sh js/reproduce.sh` rebuilds in the container and compares.');
  console.log('  If the container\'s bytes differ too, the source changed after the pin:');
  console.log('    git log -1 --format=%ad -- crates ; git log -1 --format=%ad -- js/manifest.json');
  console.log('  Then `sh js/reproduce.sh --pin`, and commit js/manifest.json.');
  console.log('  If crates/ is NOT newer, somebody shipped bytes nobody recorded — which is what this guards.');
}
process.exit(failures ? 1 : 0);
