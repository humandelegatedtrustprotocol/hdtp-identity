// The equivalence of `pact-limits` with the cloud's TypeScript, as a file every port replays.
//
// The cloud decides PACT §12's call budgets in `gateway/src/identity/limits.ts` (`RateLimiter.take`
// over `rate_buckets`) until its item M-C3 removes that file in favour of this crate
// (pact-gateway docs/release/two-layer-limits-2026-09-28.md). Before it goes, this generator runs the
// REAL TypeScript — the module itself, loaded by Node, over a `SqlStorage` made of `node:sqlite`, so
// REAL and INTEGER columns behave as SQLite has them — through seeded sequences of calls, and writes
// every decision and every row it wrote into js/cases/limits-vectors.json. The crate
// (crates/pact-limits/tests/vectors.rs), the Wasm and the Go port (js/limits.test.mjs) replay that
// file on every gate; the TypeScript is only needed to make or re-check it.
//
//   node --experimental-transform-types js/limits-vectors.mjs --cloud <pact-cloud checkout>          compare
//   node --experimental-transform-types js/limits-vectors.mjs --cloud <pact-cloud checkout> --write  write
//
// (The flag lets Node load limits.ts, whose constructor has a parameter property.)
//
// Each engine runs the sequence on its own state; nothing of the TypeScript's state is handed over,
// so the TypeScript's own sweep of idle rows runs, and every port must decide alike without it.
//
// Two call kinds are formed outside limits.ts, and are copied here: the guest's bucket
// (`guestBucket`, identity/surface.ts) and the integration's (`checkRate`, integrations/rails.ts).
// The lines they are copied from are checked verbatim in the checkout, so a change there fails this
// generator rather than the vectors quietly describing code that has moved.
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const OUT = fileURLToPath(new URL('./cases/limits-vectors.json', import.meta.url));

/** The lines of the cloud's code the generator reproduces outside limits.ts. */
const COPIED = {
  'gateway/src/identity/surface.ts': [
    'if (!root) return bucket.source(source)',
    'return bucket.guest(ip ? `${root}:${source}` : root)',
  ],
  'gateway/src/integrations/rails.ts': [
    'rate.take([bucket.perHour(`integration:${integrationId}:${contactFpr}`, limit)], now)',
    'perIntegrationPerHour: 60,',
  ],
};

/** mulberry32: small, seeded, and the same on every machine. */
function rng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return { next, below: (n) => Math.floor(next() * n), pick: (xs) => xs[Math.floor(next() * xs.length)] };
}

/**
 * The rule sets the sequences run under. The TypeScript's numbers are `BUDGETS` (a plain object the
 * module reads on every call, so a sequence can set it) and two it cannot: the capacity, a const
 * (12500), and the integration's hourly cap, rails.ts's argument (60 by default). The first set is the
 * TypeScript's own; the others are fractional on purpose. `guest_total_calls_per_hour` and
 * `pending_in_cap` are fixtures: the TypeScript has neither rule, so no vector exercises them.
 */
const RULE_SETS = [
  { contactPerSecond: 1, contactBurst: 10, guestPerHour: 10, guestSourcePerHour: 60, strangerOutPerHour: 20, integration: 60 },
  { contactPerSecond: 0.3, contactBurst: 7, guestPerHour: 7, guestSourcePerHour: 13, strangerOutPerHour: 11, integration: 17 },
  { contactPerSecond: 2.5, contactBurst: 3, guestPerHour: 1, guestSourcePerHour: 2, strangerOutPerHour: 3, integration: 1 },
  { contactPerSecond: 1 / 3, contactBurst: 1, guestPerHour: 3, guestSourcePerHour: 7, strangerOutPerHour: 6, integration: 7 },
];
const CAPACITY = 12_500;
const rulesDoc = (s) => ({
  contact_calls_per_second: s.contactPerSecond,
  contact_burst: s.contactBurst,
  identity_capacity_per_second: CAPACITY,
  guest_calls_per_hour: s.guestPerHour,
  guest_source_calls_per_hour: s.guestSourcePerHour,
  stranger_calls_out_per_hour: s.strangerOutPerHour,
  integration_calls_per_hour: s.integration,
  guest_total_calls_per_hour: 100,
  pending_in_cap: 100,
});

// Short names: a key is only ever concatenated, so its length changes no decision, and the file is
// a third the size with them.
const ROOTS = ['rA', 'rB', 'rC'];
const SOURCES = ['s1', 's2'];
const INTEGRATIONS = ['i1', 'i2'];
const CAPS = [0, 1, 3, 25, 500, 20_000];

/** One sequence's calls: kinds weighted towards the ones that share buckets, and gaps of every size. */
function sequence(seed, steps) {
  const r = rng(seed);
  let now = r.pick([0, 1_727_000_000_000, 1_790_000_000_123]);
  let cap = r.pick(CAPS);
  const out = [];
  for (let i = 0; i < steps; i++) {
    const g = r.next();
    if (g < 0.3) now += 0;
    else if (g < 0.65) now += r.below(200);
    else if (g < 0.8) now += 200 + r.below(5_000);
    else if (g < 0.87) now += 30_000 + r.below(600_000);
    else if (g < 0.93) now += 3_600_000 + r.below(7_200_000); // past the idle hour: the sweep runs
    else now = Math.max(0, now - 1 - r.below(3_000)); // a clock that went back
    if (r.next() < 0.08) cap = r.pick(CAPS); // the plan's cap moves under a stored aggregate
    const k = r.next();
    let charge;
    if (k < 0.3) charge = { kind: 'contact_in', root: r.pick(ROOTS), contact_cap: cap };
    else if (k < 0.5) charge = { kind: 'guest_in', root: r.pick([null, '', ...ROOTS]), source: r.pick(SOURCES), addressed: r.next() < 0.7 };
    else if (k < 0.75) charge = { kind: 'contact_out', root: r.pick(ROOTS), contact_cap: cap };
    else if (k < 0.87) charge = { kind: 'stranger_out' };
    else charge = { kind: 'integration', integration: r.pick(INTEGRATIONS), contact: r.pick(ROOTS) };
    out.push({ charge, now });
  }
  return out;
}

/** `SqlStorage` as a Durable Object has it, over node:sqlite: `exec(sql, ...params).toArray()`. */
function sqlStorage() {
  const db = new DatabaseSync(':memory:');
  return {
    db,
    exec(query, ...params) {
      const st = db.prepare(query);
      const rows = /^\s*SELECT/i.test(query) ? st.all(...params) : (st.run(...params), []);
      return { toArray: () => rows };
    },
  };
}

/** The TypeScript's buckets for a charge: limits.ts's `bucket`, and the two copied call sites. */
function tsBuckets(m, set, c) {
  switch (c.kind) {
    case 'contact_in': return [m.bucket.contact(c.root), m.bucket.identity(c.contact_cap)];
    case 'contact_out': return [m.bucket.outContact(c.root), m.bucket.outIdentity(c.contact_cap)];
    case 'stranger_out': return [m.bucket.outStranger()];
    case 'guest_in': {
      const { root, source } = c;
      const ip = c.addressed ? 'an address' : '';
      if (!root) return [m.bucket.source(source)];
      return [m.bucket.guest(ip ? `${root}:${source}` : root)];
    }
    case 'integration': return [m.bucket.perHour(`integration:${c.integration}:${c.contact}`, set.integration)];
    default: throw new Error(`no TypeScript for ${c.kind}`);
  }
}

async function generate(cloud) {
  const limitsPath = join(cloud, 'gateway/src/identity/limits.ts');
  const source = readFileSync(limitsPath);
  for (const [file, lines] of Object.entries(COPIED)) {
    const text = readFileSync(join(cloud, file), 'utf8');
    for (const line of lines) if (!text.includes(line)) throw new Error(`${file} no longer holds the line this generator copies: ${line}`);
  }
  const m = await import(pathToFileURL(limitsPath).href);
  if (m.IDENTITY_CAPACITY_PER_SECOND !== CAPACITY) throw new Error(`limits.ts's capacity is ${m.IDENTITY_CAPACITY_PER_SECOND}, not ${CAPACITY}`);
  const saved = { ...m.BUDGETS };
  const sequences = [];
  let seed = 1;
  for (const set of RULE_SETS) {
    for (let n = 0; n < 6; n++, seed++) {
      Object.assign(m.BUDGETS, set);
      const sql = sqlStorage();
      const limiter = new m.RateLimiter(sql);
      const steps = sequence(seed, 160).map(({ charge, now }) => {
        const buckets = tsBuckets(m, set, charge);
        const d = limiter.take(buckets, now);
        const writes = d.allowed
          ? buckets.map((b) => {
            const row = sql.db.prepare('SELECT tokens, updated_at FROM rate_buckets WHERE bucket = ?').get(b.key);
            return [b.key, row.tokens, row.updated_at];
          })
          : [];
        return [charge, now, d.allowed ? d.retryAfter : [d.retryAfter, d.refusedBy], writes];
      });
      sequences.push({ seed, rules: rulesDoc(set), steps });
    }
  }
  Object.assign(m.BUDGETS, saved);
  let commit = null;
  try { commit = execFileSync('git', ['-C', cloud, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(); } catch { /* not a checkout */ }
  return {
    about: 'PACT §12 call budgets: every decision and row of the cloud\'s RateLimiter.take over these sequences. Made by js/limits-vectors.mjs, whose header names every replay of it.',
    shape: 'a step is [charge, now, outcome, writes]: outcome 0 when let through, [retry_after, refused_by] when refused; writes [[bucket, tokens, updated_at], ...] in charge order, empty when refused',
    source: { repository: 'tech-sumit/pact-cloud', path: 'gateway/src/identity/limits.ts', commit, sha256: createHash('sha256').update(source).digest('hex') },
    fixtures: 'guest_total_calls_per_hour and pending_in_cap: the TypeScript has neither rule, so no step exercises them.',
    sequences,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const i = process.argv.indexOf('--cloud');
  if (i < 0 || !process.argv[i + 1]) {
    console.error('usage: node --experimental-transform-types js/limits-vectors.mjs --cloud <pact-cloud checkout> [--write]');
    process.exit(2);
  }
  const made = await generate(process.argv[i + 1]);
  const steps = made.sequences.reduce((n, s) => n + s.steps.length, 0);
  const refused = made.sequences.reduce((n, s) => n + s.steps.filter((x) => x[2] !== 0).length, 0);
  if (process.argv.includes('--write')) {
    writeFileSync(OUT, JSON.stringify(made) + '\n');
    console.log(`limits-vectors: wrote ${made.sequences.length} sequences, ${steps} steps (${refused} refused), from ${made.source.commit ?? 'no commit'}`);
  } else {
    const committed = JSON.parse(readFileSync(OUT, 'utf8'));
    // The provenance may differ (another commit of the same file); the decisions may not.
    const same = isDeepStrictEqual(committed.sequences, made.sequences);
    console.log(`limits-vectors: the TypeScript at ${made.source.commit ?? 'no commit'} (sha256 ${made.source.sha256.slice(0, 12)}) ${same ? 'decides' : 'does NOT decide'} as the committed ${steps} steps say`);
    process.exit(same ? 0 : 1);
  }
}
