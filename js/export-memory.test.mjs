// What the export's readers cost a host in memory, through the Wasm core a host runs. A Wasm
// instance's linear memory grows and never shrinks, and the cloud runs the core in a Durable Object
// of 128 MB: the peak of one call is what that call costs the instance for the rest of its life.
// Each case here is a fresh instance (js/wasm-memory.mjs), measured as the growth of its linear
// memory across the call, the argument text copied in and the answer copied out included.
//
// The bounds are ratios to the bytes a call is handed, never megabytes, so they cannot go stale
// with the file sizes, and each is checked at N and 4N rows so a cost that grows faster than the
// rows fails too.
//
//   export_read: at most 6 bytes of linear memory per byte of threads.csv. It must hold the member
//   twice — the argument text copied in, and the text its JSON decodes to — and write its answer,
//   the rows again with some 57 bytes of keys each: about 3.5×, 4.1–4.9× measured below (the rest is
//   a 40-byte digest per thread id and the allocator's pages). 0.3.1 took 15–16×.
//
//   export_read_end: at most 2.5 bytes per byte of its argument text (ids, msg_ids, reply_tos): it
//   holds the text and the strings it decodes to, borrowed and sorted, not copied. 1.7× measured;
//   0.3.1 took 5.2×.
//
// Two absolute figures are recorded as measured and held to a ceiling a Durable Object can carry:
// the largest threads.csv the bound allows (16 MiB), and a 64 MiB messages.jsonl read in batches of
// 500 lines, as a host streams it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fresh } from './wasm-memory.mjs';

// Measured 2026-09-27 (the linear memory's growth, this repository's pinned-profile Wasm core):
//   export_read, 200 contacts, UUID thread ids: 16k threads 10.9 MB (4.9× the CSV), 64k 43.1 MB
//   (4.8×), and the largest the bound allows, 120k threads and 16,680,037 bytes, 67.6 MB (4.1×).
//   0.3.1: 33.7 MB at 16k, 135.3 MB at 60k, some 260 MB at 120k.
//   export_read_end: 199 bytes an id (UUID ids, msg_ids and reply_tos). 0.3.1: 618.
//   A 64 MiB messages.jsonl, 160,430 lines, in batches of 500: 2.3 MB at the most.
// Measured 2026-10-10, with removed threads (SEP-0004): contacts' threads 4.85–4.92× as before; a file
//   whose every thread is removed with a root of its own 4.79–4.88× (16k, 64k), and the largest such
//   threads.csv, 118,972 threads and 16,775,123 bytes, 84.0 MB.
const PER_CSV_BYTE = 6;
const PER_END_ARG_BYTE = 2.5;
// Three quarters of a Durable Object's 128 MB: a call may not take more than that of an instance.
const LARGEST_CEILING = 96 * 1024 * 1024;
const BATCHES_CEILING = 16 * 1024 * 1024;

const owner = 'sha256:' + 'O'.repeat(42) + 'A';
const fp = (i) => 'sha256:' + createHash('sha256').update('c' + i).digest('base64url');
const uuid = (i) => createHash('sha256').update('u' + i).digest('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12}).*/, '$1-$2-$3-$4-$5');
const contacts = Array.from({ length: 200 }, (_, i) => ({
  root: fp(i), endpoint: `https://c${i}.example/mcp`, name: '', display_name: '', status: 'active', was_active: true,
  permissions: [], their_permissions: [], leaf: null, root_cert: null, added: '2026-09-01T00:00:00Z',
}));

/**
 * export_read's arguments for 200 contacts and `rows` threads with UUID ids, and the CSV's size; when
 * `removed`, each thread a removed thread with a root of its own (SPEC §9.2), the costliest legal
 * file per row for what the reader keeps of one.
 */
function readArgs(rows, removed = false) {
  const w0 = fresh();
  const threads = Array.from({ length: rows }, (_, i) => ({ id: uuid(i), contact: fp(removed ? 1000 + i : i % 200), topic: 'a topic', created_at: '2026-09-01T00:00:00Z', last_at: '2026-09-01T00:00:00Z' }));
  const w = w0.call('export_write', { owner, owner_name: '', exported_at: '2026-09-27T00:00:00Z', tool: 't', contacts, threads });
  assert.ok(!w.error, w.why);
  const manifest = w0.call('export_manifest', { partial: w.partial }).manifest;
  const directory = ['manifest.json', 'contacts.csv', 'threads.csv'].map((name) => ({ name, size: 1, encrypted: false, mode: 0 }));
  return { args: { directory, manifest, contacts_csv: w.contacts_csv, threads_csv: w.threads_csv, owner, now: '2026-09-27T00:00:00Z' }, csv: Buffer.byteLength(w.threads_csv) };
}

/** The growth of a fresh instance's linear memory across one call, and the answer. */
function grows(name, args) {
  const core = fresh();
  const before = core.bytes();
  const answer = core.call(name, args);
  assert.ok(!answer.error, `${name}: ${answer.why}`);
  return { bytes: core.bytes() - before, answer };
}

test('export_read holds at most 6 bytes per byte of threads.csv, at N and 4N rows, and when every thread is removed', () => {
  for (const [rows, removed] of [[16_000, false], [64_000, false], [16_000, true], [64_000, true]]) {
    const { args, csv } = readArgs(rows, removed);
    const { bytes, answer } = grows('export_read', args);
    assert.equal(answer.threads.length, rows);
    console.log(`  export_read, ${rows} threads, removed ${removed} (${csv} bytes): linear memory grew ${bytes} bytes, ${(bytes / csv).toFixed(2)}× the CSV`);
    assert.ok(bytes <= PER_CSV_BYTE * csv, `${rows} threads: ${(bytes / csv).toFixed(2)}× the CSV, over ${PER_CSV_BYTE}×`);
  }
});

test('export_read_end holds at most 2.5 bytes per byte of its lists, at N and 4N ids', () => {
  for (const rows of [16_000, 64_000]) {
    const ids = Array.from({ length: rows }, (_, i) => uuid(i));
    const msgIds = ids.map((x) => 'x' + x);
    const hash = 'a'.repeat(64);
    const manifest = JSON.stringify({ hdtp_export: 1, owner, owner_name: '', exported_at: '2026-09-27T00:00:00Z', tool: 't', counts: { contacts: 0, threads: 0, messages: rows, media: 0 }, files: { 'messages.jsonl': hash } });
    const args = { manifest, messages_sha256: hash, lines: rows, ids, msg_ids: msgIds, reply_tos: msgIds.slice(1), media_seen: [], media: [] };
    const listBytes = JSON.stringify([ids, msgIds, msgIds.slice(1)]).length;
    const { bytes } = grows('export_read_end', args);
    console.log(`  export_read_end, ${rows} ids (${listBytes} bytes of lists): linear memory grew ${bytes} bytes, ${(bytes / listBytes).toFixed(2)}× the lists`);
    assert.ok(bytes <= PER_END_ARG_BYTE * listBytes, `${rows} ids: ${(bytes / listBytes).toFixed(2)}× the lists, over ${PER_END_ARG_BYTE}×`);
  }
});

test('the largest threads.csv the bound allows fits a Durable Object', () => {
  // UUID ids make a row of 139 bytes; fill to just under 16 MiB.
  const rows = Math.floor((16 * 1024 * 1024 - 2048) / 139);
  const { args, csv } = readArgs(rows);
  assert.ok(csv <= 16 * 1024 * 1024 && csv > 15.9 * 1024 * 1024, `threads.csv is ${csv} bytes`);
  const { bytes } = grows('export_read', args);
  console.log(`  export_read of the largest threads.csv (${rows} threads, ${csv} bytes): linear memory grew ${(bytes / 1e6).toFixed(1)} MB`);
  assert.ok(bytes <= LARGEST_CEILING, `${(bytes / 1e6).toFixed(1)} MB, over the ${LARGEST_CEILING / 1024 / 1024} MiB ceiling`);
});

test('the largest threads.csv of removed threads, each with a root of its own, fits a Durable Object', () => {
  // A removed thread's row is 141 bytes (two empty names); fill to just under 16 MiB.
  const rows = Math.floor((16 * 1024 * 1024 - 2048) / 141);
  const { args, csv } = readArgs(rows, true);
  assert.ok(csv <= 16 * 1024 * 1024 && csv > 15.9 * 1024 * 1024, `threads.csv is ${csv} bytes`);
  const { bytes } = grows('export_read', args);
  console.log(`  export_read of the largest threads.csv of removed threads (${rows} threads, ${csv} bytes): linear memory grew ${(bytes / 1e6).toFixed(1)} MB`);
  assert.ok(bytes <= LARGEST_CEILING, `${(bytes / 1e6).toFixed(1)} MB, over the ${LARGEST_CEILING / 1024 / 1024} MiB ceiling`);
});

test('a 64 MiB messages.jsonl read in batches holds one batch, not the file', () => {
  const core = fresh();
  const before = core.bytes();
  const threads = Array.from({ length: 2000 }, (_, i) => uuid(i));
  const roots = contacts.map((c) => c.root);
  const body = 'x'.repeat(120);
  let bytes = 0, n = 0, peak = 0;
  while (bytes < 64 * 1024 * 1024) {
    const lines = [];
    for (let k = 0; k < 500 && bytes < 64 * 1024 * 1024; k++, n++) {
      const l = JSON.stringify({ id: uuid(1e6 + n), thread: threads[n % 2000], contact: roots[(n % 2000) % 200], msg_id: 'x' + n, direction: 'in', sender: 'human', time: '2026-09-01T00:00:00Z', body, reply_to: null, status: 'read', attachments: [] });
      lines.push(l);
      bytes += Buffer.byteLength(l) + 1;
    }
    const r = core.call('export_read_messages', { lines, threads, contacts: roots, media: [], first_line: n - lines.length + 1 });
    assert.ok(!r.error, r.why);
    peak = Math.max(peak, core.bytes() - before);
  }
  console.log(`  export_read_messages over ${bytes} bytes (${n} lines) in batches of 500: linear memory grew ${(peak / 1e6).toFixed(1)} MB at the most`);
  assert.ok(peak <= BATCHES_CEILING, `${(peak / 1e6).toFixed(1)} MB, over ${BATCHES_CEILING / 1024 / 1024} MiB`);
});
