// Both ports decide as js/cases/limits-vectors.json says, through the contract function a host
// calls: every step of it (a fixed record, made on 2026-09-28, of BatonDeck's RateLimiter.take over
// SQLite — batondeck 6c771f7, a commit of a private repository — a hash of batondeck's history before its rewrite of 2026-10-01; on its current main the file is `gateway/src/identity/limits.ts` from 449b273 to the parent of 2d6dc691, which removed it — which the cloud removed on
// 2026-09-29, batondeck ba68f9c; its `about` says how it was made), sent to `limits_decide` in the
// Wasm and in the Go adapter, each port carrying its own state from its own `writes`. Rows idle past the hour are dropped after every
// step, where the TypeScript swept at most once a minute: the decisions must not care.
// `node --test js/limits.test.mjs` (the Go adapter must be built: `make build` in go/).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { makePort } from './port.mjs';

const vectors = JSON.parse(readFileSync(new URL('./cases/limits-vectors.json', import.meta.url), 'utf8'));
const IDLE_MS = 3_600_000;

for (const kind of ['wasm', 'go']) {
  test(`${kind}: every step of the vectors decides and writes as the TypeScript did`, async () => {
    const port = await makePort(kind);
    assert.ok(port, `the ${kind} port is not built`);
    let steps = 0;
    let refused = 0;
    for (const { seed, rules, steps: seq } of vectors.sequences) {
      let state = {};
      seq.forEach(([charge, now, outcome, writes], i) => {
        const at = `seed ${seed} step ${i}`;
        const got = port.call('limits_decide', { rules, charge, now, state });
        assert.equal(got.error, undefined, `${at}: ${got.why}`);
        if (outcome === 0) {
          assert.deepEqual([got.allowed, got.retry_after, got.refused_by], [true, 0, null], at);
        } else {
          assert.deepEqual([got.allowed, got.retry_after, got.refused_by], [false, ...outcome], at);
          refused++;
        }
        // Every number compared as the same double: deepEqual is Object.is on numbers.
        assert.deepEqual(got.writes.map((w) => [w.bucket, w.tokens, w.updated_at]), writes, at);
        for (const w of got.writes) state[w.bucket] = { tokens: w.tokens, updated_at: w.updated_at };
        state = Object.fromEntries(Object.entries(state).filter(([, r]) => r.updated_at >= now - IDLE_MS));
        steps++;
      });
    }
    assert.ok(steps >= 1000 && refused >= 100, `the vectors hold ${steps} steps, ${refused} refused`);
  });
}
