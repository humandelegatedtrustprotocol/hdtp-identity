// Recomputes the SHA-256 of the built .wasm files and compares them with js/manifest.json.
//   node verify.mjs            — checks both packages in place
//   node verify.mjs <file>     — checks one vendored copy against the web package's entry
// Exit 1 on any mismatch, so a pipeline that vendors the bytes cannot ship a different core.
//
// **What a mismatch usually means: the source moved and the pin did not.** On 2026-09-19 the
// pinned core turned out to predate the 1.x removal by two days — it still contained the 1.x
// compat-card encoder the source had deleted — and nothing had noticed, because this check only
// ran where somebody had just rebuilt. So the first thing to ask is whether `crates/` changed
// since `manifest.json` did (`git log -1 -- crates js/manifest.json`); if it did, rebuild with
// `sh js/build.sh`, commit the manifest, and vendor the bytes wherever they are copied.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const here = new URL('./', import.meta.url);
const manifest = JSON.parse(readFileSync(new URL('manifest.json', here), 'utf8'));
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

let failures = 0;
const check = (label, bytes, expected) => {
  const got = sha(bytes);
  const ok = got === expected.sha256 && bytes.length === expected.bytes;
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}: ${bytes.length} bytes, sha256 ${got}${ok ? '' : ` (manifest: ${expected.bytes} bytes, ${expected.sha256})`}`);
};

const file = process.argv[2];
if (file) {
  check(file, readFileSync(file), manifest.files['pkg-web/pact_identity_wasm_bg.wasm']);
} else {
  for (const [name, expected] of Object.entries(manifest.files)) check(name, readFileSync(new URL(name, here)), expected);
}
if (failures) {
  console.log('');
  console.log('  The built bytes are not the pinned ones. Most often the source changed after the pin:');
  console.log('    git log -1 --format=%ad -- crates ; git log -1 --format=%ad -- js/manifest.json');
  console.log('  If crates/ is newer, run `sh js/build.sh`, commit js/manifest.json, and re-vendor.');
  console.log('  If it is not, somebody shipped bytes nobody recorded — which is what this guards.');
}
process.exit(failures ? 1 : 0);
