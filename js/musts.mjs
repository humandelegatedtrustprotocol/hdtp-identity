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
//
// An "elsewhere" entry names its holder in `elsewhere_names`, and those are checked
// too whenever the sibling repository is on disk. They were prose for exactly one
// revision, and in that revision two of eleven were wrong: 3.#1 named a
// `TestDisplayNameCollision` that has never existed, and 9.#2 credited
// `check-slug-rules.mjs`, which compares one reserved-name list with another
// and has nothing to do with holding a vacated address. A citation nothing
// checks is the defect this file was written to find, so it may not live in this
// file either. Where the sibling is not checked out, the count of unverified names is
// printed rather than assumed to be zero.
//
// What this proves and what it does not. A token is checked for EXISTENCE — that the Go
// test or the file is really there. It is not checked for RELEVANCE, which no mechanical
// check here can do: `check-slug-rules.mjs` exists, and existing was never the problem
// with citing it. So the 3.#1 shape (a name nobody can find) is now mechanical, and the
// 9.#2 shape (a real file that holds something else) still rests on a person having read
// the cited file. Half a guard, named as half.
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { seedIntrusions } from './seed.mjs';
import { recorder } from './results.mjs';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
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
  // loop and not the scenarios. js/seed.mjs runs it and reads that list, for this
  // file and for js/intrude.mjs alike.
  for (const s of seedIntrusions().scenarios) names.add('scenario:' + s.name);
  const walk = (dir, out = []) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p, out);
      else out.push(p);
    }
    return out;
  };
  // Only functions carrying a TEST attribute, which is what a `rust:` citation claims to name. This
  // collected EVERY `fn` under crates/, so `held_by: ["rust:parse"]` validated against the production
  // helper `x509::parse` — a citation that names something real and proves nothing, which is the one
  // outcome this file exists to prevent. The Go half was always narrowed to `func Test…`.
  for (const f of walk(join(here, '../crates'))) {
    if (!f.endsWith('.rs')) continue;
    const src = readFileSync(f, 'utf8');
    for (const m of src.matchAll(/#\[(?:tokio::)?test\][\s\S]{0,200}?\bfn\s+([a-z0-9_]+)\s*\(/g)) names.add('rust:' + m[1]);
  }
  for (const f of readdirSync(join(here, '../go'))) {
    if (!f.endsWith('_test.go')) continue;
    for (const m of readFileSync(join(here, '../go', f), 'utf8').matchAll(/func\s+(Test[A-Za-z0-9_]*)\s*\(/g)) names.add('go:' + m[1]);
  }
  return names;
}

const walkTree = (dir, out = []) => {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === '.git' || e.name === 'node_modules' || e.name === 'target' || e.name === 'dist') continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walkTree(p, out);
    else out.push(p);
  }
  return out;
};

/**
 * The only repository a citation's prefix may name, because it is the only one looked in. The node
 * is the other consumer of this library and its tests are cited here; a hosting platform keeps the
 * MUSTs it holds in its own table, beside its own code, and checks them there — this library does
 * not read a product's tree.
 */
const SIBLING_REPOS = ['gateway']; // invariant: constant

/**
 * The holders that live in a sibling repository, checked when that repository is on
 * disk. `gateway:Name` is a Go test function anywhere in pact-gateway.
 *
 * Returns the names it could confirm plus the roots it actually looked in, so a run
 * without the sibling reports what it could not check instead of passing quietly.
 */
function siblingNames() {
  const names = new Set();
  const looked = [];
  const gateway = join(here, '../../pact-gateway');
  if (existsSync(gateway)) {
    looked.push('gateway');
    for (const f of walkTree(gateway)) {
      if (!f.endsWith('_test.go')) continue;
      for (const m of readFileSync(f, 'utf8').matchAll(/func\s+(Test[A-Za-z0-9_]*)\s*\(/g)) names.add('gateway:' + m[1]);
    }
  }
  return { names, looked };
}

// `extract` is exported, so it has to be importable: everything below runs only when
// this file is the program. Without the guard an importer got the whole check, including
// its `process.exit(1)`, which made the export a decoration.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();

function main() {
const musts = extract(readFileSync(specPath, 'utf8'));
const manifest = JSON.parse(readFileSync(join(here, 'musts.json'), 'utf8'));
const names = knownNames();
const sibling = siblingNames();
const byId = new Map(musts.map((m) => [m.id, m]));

const problems = [];
let held = 0, elsewhere = 0, unverified = 0;
for (const m of musts) {
  const e = manifest[m.id];
  if (!e) { problems.push(`MISSING  ${m.id}  ${m.text.slice(0, 96)}`); continue; }
  if (e.hash !== m.hash) { problems.push(`DRIFTED  ${m.id}  the sentence changed (${e.hash} → ${m.hash}); re-read it and update the entry`); continue; }
  const by = e.held_by ?? [];
  for (const n of by) if (!names.has(n)) problems.push(`DANGLING ${m.id}  names ${n}, which does not exist`);
  // The sibling half. A name whose repository is absent is counted, not assumed:
  // this run proved less than a run with the siblings on disk, and says so.
  for (const n of e.elsewhere_names ?? []) {
    const repo = n.split(':')[0];
    // A prefix nobody can ever look in is a dangling citation, not an unverified one. `unverified` is
    // printed and never asserted on, so `gatway:TestFoo` — or a prefix for a repository that will
    // never be consulted — was excused for ever by the very mechanism built to stop citations nobody
    // checks. Only SIBLING_REPOS are ever looked in.
    if (!SIBLING_REPOS.includes(repo)) {
      problems.push(`DANGLING ${m.id}  names ${n}, whose prefix is not a repository this checks (${SIBLING_REPOS.join(', ')})`);
      continue;
    }
    if (!sibling.looked.includes(repo)) { unverified++; continue; }
    if (!sibling.names.has(n)) problems.push(`DANGLING ${m.id}  names ${n}, which does not exist in the ${repo} repository`);
  }
  if (by.length) held++;
  else if (e.elsewhere && e.why) elsewhere++;
  else problems.push(`MISSING  ${m.id}  an entry with neither a test nor an "elsewhere" + "why"`);
}
for (const id of Object.keys(manifest)) {
  if (!byId.has(id)) problems.push(`DANGLING ${id}  the specification no longer has this MUST`);
}

// One case per MUST: a problem naming its id fails it; a problem naming no MUST of the document
// (an entry for a sentence that is gone) is a case of its own.
const rec = recorder('musts');
const problemId = (p) => /^\S+\s+(\S+)/.exec(p)?.[1];
for (const m of musts) {
  const mine = problems.filter((p) => problemId(p) === m.id);
  const e = manifest[m.id];
  rec.add(m.id, mine.length ? 'FAIL' : 'PASS', { reason: mine.join('; ') || (e?.held_by?.length ? `held by ${e.held_by.join(', ')}` : `held elsewhere: ${e?.elsewhere}`) });
}
for (const p of problems.filter((x) => !byId.has(problemId(x)))) rec.add(problemId(p) ?? p, 'FAIL', { reason: p });
rec.write();

console.log(`${musts.length} MUSTs in pact-protocol/SPEC.md`);
console.log(`  ${held} held by a test or scenario in this repository`);
console.log(`  ${elsewhere} held elsewhere by declaration (a wallet's, a host's, a node's), each with a reason:`);
for (const [id, e] of Object.entries(manifest)) {
  if (!e.held_by?.length && e.elsewhere) console.log(`      ${id.padEnd(9)} ${e.elsewhere.padEnd(8)} ${e.why}`);
}
const crossRepo = Object.values(manifest).reduce((n, e) => n + (e.elsewhere_names?.length ?? 0), 0);
console.log(`  ${crossRepo - unverified} of ${crossRepo} cross-repo holders confirmed on disk` +
  (sibling.looked.length ? ` (looked in: ${sibling.looked.join(', ')})` : '') +
  (unverified ? ` — ${unverified} unverified, that repository is not checked out here` : ''));
if (problems.length) {
  console.log(`\n${problems.length} problem(s):`);
  for (const p of problems) console.log('  ' + p);
  process.exit(1);
}
console.log('\nevery MUST names something.');
}
