// PACT 1.x is gone, and this is what holds it gone in this repository: no tracked file carries a
// NAME that 1.x had and 2.x does not — a card property, an info string, a mode, a tool — outside a
// file listed below WITH ITS REASON. Until the split of 2026-09-27 the node's guard scanned this
// tree through the umbrella; the node now scans its own, so this repository holds its own.
//
// The names are js/pact1x-markers.txt, which must be byte-identical to pact-protocol's copy
// (vectors/pact1x-markers.txt, the sibling gate.sh already reads): two copies of one list drift the
// day they are written, so the comparison is part of the check, not a note beside it.
//
//   node js/check-no-1x.mjs            # the check (gate.sh runs it)
//   node js/check-no-1x.mjs --selftest # proves the matcher finds a planted name (gate.sh runs it too)
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..');
const MARKERS = join(here, 'pact1x-markers.txt');
const PROTOCOL_COPY = join(repo, '../pact-protocol/vectors/pact1x-markers.txt');

const markerText = readFileSync(MARKERS);
const markers = markerText.toString('utf8')
  .split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).map((l) => new RegExp(l));
if (markers.length < 10) {
  console.error(`check-no-1x: read only ${markers.length} markers: the reader is broken, not the tree`);
  process.exit(1);
}

// Each entry is a file that MUST carry a 1.x name, because refusing that name is what it tests.
const allowed = new Map(Object.entries({
  'js/intrude.mjs': 'the intrusion battery: every 1.x input it sends — a stale info string, a retired card property appended in flight — must be refused or ignored',
  'crates/pact-identity/src/hpke.rs': 'asserts a 2.x ciphertext does not open under the 1.x info string',
}));
const built = /(^|\/)(dist|node_modules|target)\/|\.(png|jpg|jpeg|gif|ico|pdf|wasm|woff2?)$/;

export function namesIn(text) {
  const out = [];
  text.split('\n').forEach((line, i) => {
    for (const m of markers) {
      const hit = m.exec(line);
      if (hit) { out.push([i + 1, hit[0]]); break; }
    }
  });
  return out;
}

if (process.argv.includes('--selftest')) {
  const planted = namesIn('a clean line\nthe card carries X-PACT-' + 'KEY here\nsealed under PACT-SEAL-' + 'v1 by mistake\n');
  const clean = namesIn('PACT 1.x is not supported; a leaf is renewed, a root never rotates.\n');
  if (planted.length !== 2 || planted[0][0] !== 2 || clean.length !== 0) {
    console.error('check-no-1x --selftest: the matcher did not find two planted names, or found one in clean prose');
    process.exit(1);
  }
  console.log('check-no-1x --selftest: ok (2 planted names found, clean prose passes)');
  process.exit(0);
}

const problems = [];
if (!existsSync(PROTOCOL_COPY)) {
  problems.push(`../pact-protocol/vectors/pact1x-markers.txt is not on disk, so this copy cannot be held to it`);
} else if (!readFileSync(PROTOCOL_COPY).equals(markerText)) {
  problems.push('js/pact1x-markers.txt differs from ../pact-protocol/vectors/pact1x-markers.txt: the two must be the same bytes, and one has drifted');
}

const tracked = execFileSync('git', ['-C', repo, 'ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
const carries = new Set();
const found = [];
let scanned = 0;
for (const rel of tracked) {
  if (built.test(rel) || rel === 'js/pact1x-markers.txt') continue;
  let st;
  try { st = statSync(join(repo, rel)); } catch { continue; } // deleted since ls-files
  if (!st.isFile()) continue;
  const buf = readFileSync(join(repo, rel));
  if (buf.includes(0)) continue; // binary
  scanned++;
  for (const [line, name] of namesIn(buf.toString('utf8'))) {
    carries.add(rel);
    if (!allowed.has(rel)) found.push(`${rel}:${line}: ${name}`);
  }
}

// A guard that read nothing passes. This repository has well over a hundred tracked text files.
if (scanned < 100) problems.push(`scanned only ${scanned} files: the walk is broken, not the tree`);
if (found.length) {
  problems.push(`${found.length} line(s) carry a name PACT 1.x had and 2.x does not. Say it without the name, or list the file above with its reason.\n  ` + found.sort().join('\n  '));
}
for (const [rel, why] of allowed) {
  if (!carries.has(rel)) problems.push(`${rel} is allowed to carry a 1.x name (${why}) and carries none: the list is stale`);
}
if (problems.length) {
  console.error('check-no-1x:\n' + problems.join('\n'));
  process.exit(1);
}
console.log(`check-no-1x: ok (${scanned} files, ${markers.length} names, ${allowed.size} allowed with a reason, markers identical to pact-protocol's)`);
