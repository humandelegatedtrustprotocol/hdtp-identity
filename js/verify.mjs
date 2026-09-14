// Recomputes the SHA-256 of the built .wasm files and compares them with js/manifest.json.
//   node verify.mjs            — checks both packages in place
//   node verify.mjs <file>     — checks one vendored copy against the web package's entry
// Exit 1 on any mismatch, so a pipeline that vendors the bytes cannot ship a different core.
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
process.exit(failures ? 1 : 0);
