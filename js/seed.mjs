// What the seed says, read in one place: its intrusion suite's scenarios and verdicts, and Appendix B's
// vector blocks.
//
// The seed's intrusion suite (hdtp-spec/vectors/intrude.mjs) prints one line per scenario, and that
// output is the only exact list of them: a third of the names are built in loops. Three files each ran
// it and each parsed the lines their own way (js/intrude.mjs, js/musts.mjs, js/live.mjs), and the gate
// ran it six times. It is run and parsed HERE, and within one gate run it runs once: with
// HDTP_RESULTS set (gate.sh sets it), the parse is kept in that directory under a key over every file
// the run reads — the suite, its library, the specification's pages — and the Node version, so a cached answer is the
// answer those exact bytes give.
//
//   node js/seed.mjs     prints the seed's own run and exits non-zero if it failed or anything reproduces
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { join } from 'node:path';

const protocol = fileURLToPath(new URL('../../hdtp-spec/', import.meta.url));
const suite = join(protocol, 'vectors/intrude.mjs');
const VERDICT = /^  (blocked|residual|REPRODUCES)\s+(.*?)(?:\s+→ .*)?$/;

/** The files whose bytes decide the seed suite's output. */
function inputsKey() {
  const lib = join(protocol, 'vectors/lib');
  const text = join(protocol, 'docs/specification');
  const pages = readdirSync(text).sort().flatMap((v) => readdirSync(join(text, v)).sort().map((p) => join(text, v, p)));
  const files = [suite, join(protocol, 'site/spec-source.mjs'), ...pages, ...readdirSync(lib).filter((f) => f.endsWith('.mjs')).sort().map((f) => join(lib, f))];
  const h = createHash('sha256').update(process.version);
  for (const f of files) h.update(f.slice(protocol.length)).update('\0').update(readFileSync(f)).update('\0');
  return h.digest('hex');
}

/** Parse the suite's output: every scenario line, and the count its summary line reports. */
export function parseIntrusions(stdout) {
  const scenarios = [];
  for (const line of stdout.split('\n')) {
    const m = VERDICT.exec(line);
    if (m) scenarios.push({ name: m[2], verdict: m[1] });
  }
  const total = Number(/^(\d+) scenarios:/m.exec(stdout)?.[1]);
  if (!scenarios.length || !Number.isInteger(total)) throw new Error('the seed intrusion suite printed no scenarios, or no summary line');
  if (total !== scenarios.length) throw new Error(`the seed intrusion suite reports ${total} scenarios and printed ${scenarios.length}`);
  return { scenarios, total };
}

/**
 * The seed's intrusion suite, run once: `{ status, stdout, scenarios: [{ name, verdict }], total }`.
 * Throws if it did not run or its output does not parse.
 */
export function seedIntrusions() {
  const key = inputsKey();
  const dir = process.env.HDTP_RESULTS;
  const cache = dir && join(dir, 'seed-intrude.json');
  if (cache && existsSync(cache)) {
    try {
      const kept = JSON.parse(readFileSync(cache, 'utf8'));
      if (kept.key === key) return kept;
    } catch { /* unreadable: run it again */ }
  }
  const run = spawnSync(process.execPath, [suite], { cwd: protocol, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (run.error || run.status === null) throw new Error(`the seed intrusion suite did not run: ${run.error?.message ?? run.signal}`);
  const answer = { key, status: run.status, stdout: run.stdout, ...parseIntrusions(run.stdout) };
  if (cache) writeFileSync(cache, JSON.stringify(answer));
  return answer;
}

/**
 * The JSON blocks of a specification's Appendix B: everything fenced as ```json between the heading
 * `## Appendix B` and the closing line `*End of HDTP`. Both markers must be there — a missing end
 * used to slice to one character short of the end of the file — every fence must close, and every
 * block must be JSON. js/appendix-b-reader.json is the list of cases this and the other three readers
 * (the CLI's, the core tests', the Go port's) are held to, refusals word for word.
 */
export function appendixB(spec) {
  const start = spec.indexOf('## Appendix B');
  if (start < 0) throw new Error('the document has no Appendix B');
  const end = spec.indexOf('*End of HDTP', start);
  if (end < 0) throw new Error('Appendix B has no end marker (*End of HDTP)');
  const b = spec.slice(start, end);
  const blocks = [];
  let at = 0;
  for (;;) {
    const i = b.indexOf('```json\n', at);
    if (i < 0) return blocks;
    const j = b.indexOf('\n```', i + 8);
    if (j < 0) throw new Error('an unterminated json fence in Appendix B');
    try {
      blocks.push(JSON.parse(b.slice(i + 8, j)));
    } catch {
      throw new Error(`Appendix B block ${blocks.length + 1} is not JSON`);
    }
    at = j + 4;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const s = seedIntrusions();
  process.stdout.write(s.stdout);
  const reproduce = s.scenarios.filter((x) => x.verdict === 'REPRODUCES').length;
  process.exit(s.status !== 0 || reproduce ? 1 : 0);
}
