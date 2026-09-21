// The record of what is proven, generated from the things that prove it.
//
// Two lists that were only ever a number in a console line or a README: the normative
// sentences of `pact-protocol/SPEC.md` with what holds each one, and every cross-port
// parity case with the function it guards. A reviewer asking "which 45?" or "which 270?"
// had to run the suites and read scrollback.
//
// Generated, never written. Both halves come from their sources — `musts.json` plus the
// same extractor `musts.mjs` uses, and `parity.mjs --manifest`, which emits only after
// its comparison agreed — so a count here cannot drift from the count a run produces,
// and the document cannot claim a case that did not pass. `--check` regenerates and
// diffs, which is what CI runs; a hand edit fails it.
import { readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { extract } from './musts.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '../PROOFS.md');
const check = process.argv.includes('--check');

const musts = extract(readFileSync(join(here, '../../pact-protocol/SPEC.md'), 'utf8'));
const map = JSON.parse(readFileSync(join(here, 'musts.json'), 'utf8'));

// The parity manifest is produced by running the harness, not read from a committed file:
// a committed one could be stale, and the whole point is that the record describes a run.
//
// A failing parity run throws here (execFileSync does, on a non-zero exit), so nothing is written.
// The manifest is removed FIRST as well: this file outlives a run that dies between the two lines
// below, and a parity that exited 0 without writing one — it skips the manifest under `--only` —
// would otherwise hand this script the last run's numbers to record as today's.
const tmp = join(here, '.parity-manifest.json');
rmSync(tmp, { force: true });
execFileSync(process.execPath, [join(here, 'parity.mjs'), '--manifest', tmp], { stdio: 'pipe' });
const parity = JSON.parse(readFileSync(tmp, 'utf8'));
rmSync(tmp, { force: true });

const specVersion = (readFileSync(join(here, '../../pact-protocol/SPEC.md'), 'utf8')
  .match(/^\*\*Version\s+([^\s·]+)/m) || [, '(unknown)'])[1];

const holder = (id) => {
  const e = map[id];
  if (!e) return '— *nothing claims it*';
  const names = [...(e.held_by ?? []), ...(e.elsewhere_names ?? [])];
  if (names.length) return names.map((n) => `\`${n}\``).join(', ');
  return `*${e.elsewhere ?? 'elsewhere'}, by declaration*`;
};

const L = [];
L.push('# What is proven, and by what');
L.push('');
L.push('**Generated — do not edit.** `node js/record.mjs` rewrites this file; `node js/record.mjs --check`');
L.push('regenerates and fails on any difference, which is what CI runs. Both lists come from the things');
L.push('that prove them rather than from prose beside them: the MUSTs from `pact-protocol/SPEC.md` through');
L.push("the same extractor `js/musts.mjs` uses, with holders from `js/musts.json`; the parity cases from");
L.push('`js/parity.mjs --manifest`, which writes its manifest only after the comparison agreed — so no');
L.push('case can be listed here that did not pass.');
L.push('');
L.push(`Specification: **${specVersion}**. `
  + `**${musts.length}** normative sentences, **${parity.cases}** cross-port parity cases over `
  + `**${parity.functions}** guarded functions.`);
L.push('');
// The contract's own numbers, from the same run. A count of "answers validated" is two per case
// — one port each — and is the measure of the check the ports cannot pass by agreeing with each
// other, so it is worth recording as its own line rather than folded into the case count.
const c = parity.contract;
L.push(`Every answer of both ports is validated against \`${c.file}\` (**${c.methods}** functions, `
  + `spec ${c.spec}): **${c.answers_validated}** answers held to the shape it declares, `
  + `**${c.off_contract}** did not. Of **${c.declared_error_codes}** declared error codes, `
  + `**${c.declared_error_codes - c.codes_never_produced.length}** were produced by a case here; the `
  + `rest are declared for a caller's benefit and no argument in this suite reaches them.`);
L.push('');

// ── the MUSTs ─────────────────────────────────────────────────────────────────────────
const inRepo = musts.filter((m) => (map[m.id]?.held_by ?? []).length).length;
const declared = musts.length - inRepo;
L.push(`## The ${musts.length} normative sentences of the specification`);
L.push('');
L.push(`A sentence carrying MUST, MUST NOT or REQUIRED, one row each, in document order. **${inRepo}** are`);
L.push(`held by a test or an intrusion scenario in this repository; **${declared}** belong to a wallet, a host`);
L.push('or a node, and name the artefact that holds them there — checked against the sibling repository');
L.push('whenever it is on disk. A row with nothing in its last column would fail `js/musts.mjs`.');
L.push('');
let section = null;
for (const m of musts) {
  if (m.section !== section) {
    section = m.section;
    L.push('');
    L.push(`### ${section}`);
    L.push('');
    L.push('| # | The sentence | Held by |');
    L.push('|---|---|---|');
  }
  const text = m.text.replace(/\|/g, '\\|');
  L.push(`| \`${m.id}\` | ${text} | ${holder(m.id)} |`);
}
L.push('');

// ── the parity cases ──────────────────────────────────────────────────────────────────
L.push(`## The ${parity.cases} cross-port parity cases`);
L.push('');
L.push('Each case feeds one argument shape to both the Rust core (through its WebAssembly bindings) and');
L.push('the Go port and compares the whole answer — code, shape and `why` string. A function marked');
L.push('*whole on success* has at least one case whose successful answer is compared member by member,');
L.push('which is the only kind that notices a member going missing; a refusal compared whole proves both');
L.push('ports refuse alike. `js/parity.mjs` fails if any guarded function lacks either.');
L.push('');
L.push(`At the run that generated this file: **${parity.cases}** cases, **${parity.disagreements}** disagreements, `
  + `**${parity.compared_whole}** of **${parity.functions}** functions compared whole on success.`);
for (const f of parity.by_function) {
  L.push('');
  L.push(`### \`${f.fn}\` — ${f.cases.length} case${f.cases.length === 1 ? '' : 's'}`
    + (f.in_surface ? (f.compared_whole ? ' · whole on success' : '') : ' · not a dispatched function'));
  L.push('');
  for (const c of f.cases) L.push(`- ${c}`);
}
L.push('');

const body = L.join('\n');
if (check) {
  if (!existsSync(out)) {
    console.error('PROOFS.md does not exist; run `node js/record.mjs`');
    process.exit(1);
  }
  if (readFileSync(out, 'utf8') !== body) {
    console.error('PROOFS.md does not describe the current specification and suites.');
    console.error('Run `node js/record.mjs` and commit the result.');
    process.exit(1);
  }
  console.log(`PROOFS.md is current: ${musts.length} MUSTs, ${parity.cases} parity cases.`);
} else {
  writeFileSync(out, body);
  console.log(`wrote PROOFS.md — ${musts.length} MUSTs, ${parity.cases} parity cases over ${parity.functions} functions.`);
}
