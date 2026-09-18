// Every MUST in `pact-protocol/SPEC.md`, and the thing that holds it.
//
// The suites here are imagination-driven: someone thought of an attack and wrote it
// down. That finds what the author thought of. This finds what nobody did — it reads
// the normative sentences out of the specification itself and fails when one of them
// names nothing at all.
//
// Three failure modes, all of them silent before this existed:
//   MISSING   a MUST no entry covers — nobody has said who holds it
//   DRIFTED   the sentence changed since the entry was written, so the claim is stale
//   DANGLING  an entry names a test or scenario that does not exist, or an id the
//             specification no longer has
//
// An entry may say the MUST is not this library's to hold — a wallet's, a host's, a
// node's — but it must then say WHO and WHY, and the run prints the count. A silent
// allowlist is the thing this replaces.
import { readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const specPath = join(here, '../../pact-protocol/SPEC.md');

/** Every normative sentence in the document, keyed by the section it lives in. */
export function extract(markdown) {
  const lines = markdown.split('\n');
  const units = [];
  let fence = false, section = '(front matter)', buf = [];
  const flush = () => { if (buf.length) { units.push({ section, text: buf.join(' ') }); buf = []; } };
  for (const line of lines) {
    if (/^\s*```/.test(line)) { fence = !fence; flush(); continue; }
    if (fence) continue;
    const h = /^(#{2,4})\s+(.*)$/.exec(line);
    if (h) { flush(); section = h[2].trim(); continue; }
    if (!line.trim()) { flush(); continue; }
    if (/^\s*[-*|]/.test(line)) { flush(); units.push({ section, text: line.trim() }); continue; }
    buf.push(line.trim());
  }
  flush();

  const splitter = /(?<=[.!?:])\s+(?=[A-Z`*(§"“—\d])/;
  const NORM = /\bMUST NOT\b|\bMUST\b|\bREQUIRED\b/;
  const out = [];
  const seen = new Map();
  for (const u of units) {
    // One table row is one unit; splitting on cells keeps a row with two MUSTs as two.
    const pieces = u.text.startsWith('|') ? u.text.split('|').map((x) => x.trim()).filter(Boolean) : u.text.split(splitter);
    for (const p of pieces) {
      if (!NORM.test(p)) continue;
      const n = (seen.get(u.section) ?? 0) + 1;
      seen.set(u.section, n);
      const text = p.replace(/\s+/g, ' ').trim();
      out.push({
        id: `${u.section.split(/\s/)[0].replace(/^§/, '')}#${n}`,
        section: u.section,
        hash: createHash('sha256').update(text).digest('hex').slice(0, 12),
        text,
      });
    }
  }
  return out;
}

/** Names this repository can actually check: scenarios, Rust tests, Go tests. */
function knownNames() {
  const names = new Set();
  // The seed suite prints one line per scenario, which is the only exact list: a
  // third of the names are built in loops, and a regex over the source finds the
  // loop and not the scenarios. `js/intrude.mjs` reads the same output to compare
  // verdicts, so this is the established way to ask what scenarios exist.
  const seed = spawnSync(process.execPath, [join(here, '../../pact-protocol/vectors/intrude.mjs')], { encoding: 'utf8' });
  if (seed.status !== 0 && !seed.stdout) throw new Error('the seed intrusion suite did not run: ' + (seed.stderr || seed.error?.message));
  for (const line of seed.stdout.split('\n')) {
    const m = /^  (?:blocked|residual|REPRODUCES)\s+(.*?)(?:\s+→ .*)?$/.exec(line);
    if (m) names.add('scenario:' + m[1]);
  }
  const walk = (dir, out = []) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p, out);
      else out.push(p);
    }
    return out;
  };
  for (const f of walk(join(here, '../crates'))) {
    if (!f.endsWith('.rs')) continue;
    for (const m of readFileSync(f, 'utf8').matchAll(/fn\s+([a-z0-9_]+)\s*\(/g)) names.add('rust:' + m[1]);
  }
  for (const f of readdirSync(join(here, '../go'))) {
    if (!f.endsWith('_test.go')) continue;
    for (const m of readFileSync(join(here, '../go', f), 'utf8').matchAll(/func\s+(Test[A-Za-z0-9_]*)\s*\(/g)) names.add('go:' + m[1]);
  }
  return names;
}

const musts = extract(readFileSync(specPath, 'utf8'));
const manifest = JSON.parse(readFileSync(join(here, 'musts.json'), 'utf8'));
const names = knownNames();
const byId = new Map(musts.map((m) => [m.id, m]));

const problems = [];
let held = 0, elsewhere = 0;
for (const m of musts) {
  const e = manifest[m.id];
  if (!e) { problems.push(`MISSING  ${m.id}  ${m.text.slice(0, 96)}`); continue; }
  if (e.hash !== m.hash) { problems.push(`DRIFTED  ${m.id}  the sentence changed (${e.hash} → ${m.hash}); re-read it and update the entry`); continue; }
  const by = e.held_by ?? [];
  for (const n of by) if (!names.has(n)) problems.push(`DANGLING ${m.id}  names ${n}, which does not exist`);
  if (by.length) held++;
  else if (e.elsewhere && e.why) elsewhere++;
  else problems.push(`MISSING  ${m.id}  an entry with neither a test nor an "elsewhere" + "why"`);
}
for (const id of Object.keys(manifest)) {
  if (!byId.has(id)) problems.push(`DANGLING ${id}  the specification no longer has this MUST`);
}

console.log(`${musts.length} MUSTs in pact-protocol/SPEC.md`);
console.log(`  ${held} held by a test or scenario in this repository`);
console.log(`  ${elsewhere} held elsewhere by declaration (a wallet's, a host's, a node's), each with a reason:`);
for (const [id, e] of Object.entries(manifest)) {
  if (!e.held_by?.length && e.elsewhere) console.log(`      ${id.padEnd(9)} ${e.elsewhere.padEnd(8)} ${e.why}`);
}
if (problems.length) {
  console.log(`\n${problems.length} problem(s):`);
  for (const p of problems) console.log('  ' + p);
  process.exit(1);
}
console.log('\nevery MUST names something.');
