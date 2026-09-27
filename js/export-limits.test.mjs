// The largest file the export's bounds allow is read in bounded time, through the Wasm core a host
// runs (a Worker or a Durable Object, under a 30 s CPU limit) and through the Go port.
//
// SPEC §9.2 bounds contacts.csv at 4 MiB and 5000 rows, and threads.csv at 16 MiB. 0.3.0's
// export_read scanned the rows it had read for every new thread id, which is quadratic: a 14.7 MB
// threads.csv (120k threads) ran for more than 9 CPU-minutes. This file holds the whole of the
// bound — 5000 contacts and a threads.csv just under 16 MiB — to an absolute ceiling, CEILING_MS, per
// port, as measured on the machine this is developed on (an arm64 Mac, under the load of parallel
// builds): see MEASURED below. The growth tests of both ports hold the shape
// (export_functions_grow_linearly_in_the_rows_of_a_file, TestExportFunctionsGrowLinearlyInTheRowsOfAFile).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { makePort } from './port.mjs';

// Measured 2026-09-27 on the whole-bound file below (5000 contacts, 163,962 threads, 16,777,013
// bytes), export_read, three runs: the Wasm core 1006, 1021 and 1024 ms; the Go port through its
// adapter (the 16 MiB carried over the pipe included) 1986, 817 and 852 ms. 0.3.0's Wasm core took
// 12.2 s on 16k threads and more than 9 CPU-minutes on 120k. The ceiling is some 5× the slowest
// run, so a busy machine passes and a scan per row (minutes) does not.
const MEASURED = { wasm: 1024, go: 1986 };
const CEILING_MS = 10_000;

const owner = 'sha256:' + 'O'.repeat(43);
const fp = (i) => 'sha256:' + createHash('sha256').update('c' + i).digest('base64url');

function largest(wasm) {
  const contacts = Array.from({ length: 5000 }, (_, i) => ({
    root: fp(i), endpoint: `https://c${i}.example/mcp`, name: '', display_name: '', status: 'active', was_active: true,
    permissions: [], their_permissions: [], leaf: null, root_cert: null, added: '2026-09-01T00:00:00Z',
  }));
  // A thread row is about 105 bytes; stop short of 16 MiB.
  const threads = [];
  for (let i = 0, bytes = 50; bytes < 16 * 1024 * 1024 - 256; i++) {
    const t = { id: `t${i}`, contact: fp(i % 5000), topic: '', created_at: '2026-09-01T00:00:00Z', last_at: '2026-09-01T00:00:00Z' };
    bytes += t.id.length + t.contact.length + 2 * t.created_at.length + 6;
    threads.push(t);
  }
  const w = wasm.call('export_write', { owner, owner_name: '', exported_at: '2026-09-27T00:00:00Z', tool: 't', contacts, threads });
  assert.ok(!w.error, w.why);
  const manifest = wasm.call('export_manifest', { partial: w.partial }).manifest;
  const directory = ['manifest.json', 'contacts.csv', 'threads.csv'].map((name) => ({ name, size: 1, encrypted: false, mode: 0 }));
  return { threads: threads.length, args: { directory, manifest, contacts_csv: w.contacts_csv, threads_csv: w.threads_csv, owner, now: '2026-09-27T00:00:00Z' } };
}

test('the largest file the bounds allow is read in bounded time, by both ports', async () => {
  const ports = { wasm: await makePort('wasm'), go: await makePort('go') };
  const { threads, args } = largest(ports.wasm);
  assert.ok(Buffer.byteLength(args.threads_csv) <= 16 * 1024 * 1024, 'the file must be within the bound it tests');
  assert.ok(Buffer.byteLength(args.threads_csv) > 15 * 1024 * 1024, `threads.csv is ${Buffer.byteLength(args.threads_csv)} bytes, not near the bound`);
  for (const [name, port] of Object.entries(ports)) {
    const t = performance.now();
    const r = port.call('export_read', args);
    const ms = performance.now() - t;
    assert.ok(!r.error, `${name}: ${r.why}`);
    assert.equal(r.threads.length, threads);
    console.log(`  ${name}: export_read of 5000 contacts and ${threads} threads (${Buffer.byteLength(args.threads_csv)} bytes) in ${ms.toFixed(0)} ms (measured ${MEASURED[name]}, ceiling ${CEILING_MS})`);
    assert.ok(ms < CEILING_MS, `${name}: ${ms.toFixed(0)} ms, over the ${CEILING_MS} ms ceiling for the largest legal file`);
  }
});
