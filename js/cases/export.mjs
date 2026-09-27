// §6.2 of the contract: the export. Three kinds of case:
//
// - the writers, compared whole: both ports must write the same BYTES for the same rows (every
//   formula prefix, quoting, a line break in a cell, a message line, a manifest), and each round
//   trip must read back what was written;
// - the corpus (go/exportcorpus, the files the Go port's ReadExportZip and the Rust CLI's reader are
//   tested on): every file whose refusal is the core's is read here as a host would read it, and the
//   call that must refuse it is a case holding the refusal cases.json names; the two controls are
//   read through export_read, export_read_messages and export_read_end, each compared whole;
// - the arguments and the merge.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { readZip } from '../zip.mjs';

const CORPUS = new URL('../../go/exportcorpus/', import.meta.url);
const sha = (b) => createHash('sha256').update(b).digest('hex');

export default function exportCases({ add, expect }, f) {
  const { wasm, rootFp, rootDer, leafDer, ENDPOINT, now } = f;
  const owner = 'sha256:' + 'O'.repeat(43);
  const other = (c) => 'sha256:' + c.repeat(43);

  // ── the writers ─────────────────────────────────────────────────────────────────────────────
  const row = (o) => ({
    root: rootFp, endpoint: ENDPOINT, name: 'Alina', display_name: '', status: 'active', was_active: true,
    permissions: ['message.text'], their_permissions: [], leaf: leafDer, root_cert: rootDer, added: '2026-09-02T09:00:00.500Z', ...o,
  });
  const prefixed = ['=1+1', '+1', '-1', '@SUM(A1)', "'Tis", '\tTab', '\rCR'];
  const contacts = [
    row({}),
    ...prefixed.map((p, i) => row({ root: other('BCDEFGH'[i]), endpoint: `https://p${i}.example/mcp`, name: p, display_name: `${p}, "quoted"\r\nand broken`, leaf: null, root_cert: null, permissions: ['message.text', 'integration.cal-x'] })),
  ];
  const threads = [
    { id: 't2', contact: rootFp, topic: '-a topic', created_at: '2026-09-10T10:00:00Z', last_at: '2026-09-11T10:00:00Z' },
    { id: 't1', contact: other('B'), topic: 'plain, "quoted"', created_at: '2026-09-10T10:00:00Z', last_at: '2026-09-10T10:00:00Z' },
  ];
  const file = sha('bytes');
  const media = [{ hash: file, size: 5 }];
  const writeArgs = { owner, owner_name: 'Olive', exported_at: now, tool: 'parity', contacts, threads, media };
  add('export_write: every formula prefix, quoting and line breaks, sorted rows', 'export_write', writeArgs);
  add('export_write: a book', 'export_write', { owner, owner_name: 'Olive', exported_at: now, tool: 'parity', contacts: [row({})] });
  const messages = [
    { id: 'm1', thread: 't2', contact: rootFp, msg_id: 'x-1', direction: 'in', sender: 'human', time: '2026-09-10T10:00:00.9Z', body: 'Hello\n"there" ', reply_to: null, status: 'delivered', attachments: [] },
    { id: 'm2', thread: 't2', contact: rootFp, msg_id: 'x-2', direction: 'out', sender: 'agent', time: '2026-09-11T10:00:00Z', body: '', reply_to: 'x-1', status: 'read', attachments: [{ file, filename: 'a.pdf', mime: 'application/pdf', size: 5 }] },
    { id: 'm3', thread: 't1', contact: other('B'), msg_id: 'x-3', direction: 'out', sender: 'human', time: '2026-09-11T10:00:00Z', body: 'https://files.example/a-link', reply_to: null, status: 'queued', attachments: [] },
  ];
  add('export_write_messages: a text, a file and a link', 'export_write_messages', { messages });
  const written = wasm.call('export_write', writeArgs);
  const lines = wasm.call('export_write_messages', { messages }).lines;
  const jsonl = lines.map((l) => l + '\n').join('');
  add('export_manifest: finished with the messages', 'export_manifest', { partial: written.partial, hashes: { 'messages.jsonl': sha(jsonl) }, messages: lines.length });
  add('export_manifest: a book', 'export_manifest', { partial: wasm.call('export_write', { owner, owner_name: '', exported_at: now, tool: 'parity', contacts: [] }).partial });

  // The round trip: what was written reads back, each step compared whole.
  const manifest = wasm.call('export_manifest', { partial: written.partial, hashes: { 'messages.jsonl': sha(jsonl) }, messages: lines.length }).manifest;
  const members = { 'manifest.json': manifest, 'contacts.csv': written.contacts_csv, 'threads.csv': written.threads_csv, 'messages.jsonl': jsonl };
  const directory = [
    ...Object.entries(members).map(([name, text]) => ({ name, size: Buffer.byteLength(text), encrypted: false, mode: 0o100644 })),
    { name: 'media/', size: 0, encrypted: false, mode: 0o040755 },
    { name: `media/${file}`, size: 5, encrypted: false, mode: 0o100644 },
  ];
  const readArgs = { directory, manifest, contacts_csv: written.contacts_csv, threads_csv: written.threads_csv, owner, now };
  add('export_read: what export_write wrote', 'export_read', readArgs);
  const read = wasm.call('export_read', readArgs);
  const names = { threads: read.threads.map((t) => t.id), contacts: read.contacts.map((c) => c.root), media: read.media.map((m) => m.hash) };
  add('export_read_messages: what export_write_messages wrote', 'export_read_messages', { lines, ...names });
  add('export_read_end: what was written', 'export_read_end', { manifest, messages_sha256: sha(jsonl), lines: lines.length, ids: ['m1', 'm2', 'm3'], msg_ids: ['x-1', 'x-2', 'x-3'], reply_tos: ['x-1'], media_seen: [file] });

  // ── the corpus ──────────────────────────────────────────────────────────────────────────────
  const index = JSON.parse(readFileSync(new URL('cases.json', CORPUS), 'utf8'));
  for (const c of index.cases) {
    if (c.stage === 'host') continue; // held by the two hosts' own tests, which read the container
    const entries = readZip(readFileSync(new URL(c.file, CORPUS)));
    const text = (name) => { const e = entries.find((x) => x.name === name); return e ? e.data().toString('utf8') : undefined; };
    const args = {
      directory: entries.map(({ name, size, encrypted, mode }) => ({ name, size, encrypted, mode })),
      owner: index.owner, now: index.now,
    };
    for (const [arg, name] of [['manifest', 'manifest.json'], ['contacts_csv', 'contacts.csv'], ['threads_csv', 'threads.csv']]) {
      const t = text(name);
      if (t !== undefined) args[arg] = t;
    }
    const label = `export corpus ${c.file}`;
    const want = c.accept ? null : { error: 'bad_request', why: c.refusal };
    const first = wasm.call('export_read', args);
    if (first.error || c.accept) {
      add(`${label}: export_read`, 'export_read', args);
      if (first.error) { expect(`${label}: export_read`, want); continue; }
    }
    const body = text('messages.jsonl') ?? '';
    const fileLines = body === '' ? [] : body.replace(/\n$/, '').split('\n');
    const msgArgs = { lines: fileLines, threads: first.threads.map((t) => t.id), contacts: first.contacts.map((r) => r.root), media: first.media.map((m) => m.hash) };
    const second = wasm.call('export_read_messages', msgArgs);
    if (second.error || c.accept) {
      add(`${label}: export_read_messages`, 'export_read_messages', msgArgs);
      if (second.error) { expect(`${label}: export_read_messages`, want); continue; }
    }
    const endArgs = {
      manifest: args.manifest, messages_sha256: text('messages.jsonl') === undefined ? null : sha(Buffer.from(body, 'utf8')), lines: fileLines.length,
      ids: second.messages.map((m) => m.id), msg_ids: second.messages.map((m) => m.msg_id),
      reply_tos: second.messages.map((m) => m.reply_to).filter((r) => r !== null), media_seen: second.media_seen,
    };
    add(`${label}: export_read_end`, 'export_read_end', endArgs);
    expect(`${label}: export_read_end`, want ?? { ok: true });
  }

  // JSON the two ports' decoders read differently: a lone surrogate escape is refused by serde and
  // was replaced with U+FFFD by Go's encoding/json. A manifest and a message are JSON inside a string,
  // so a file carries one to both; the ports must refuse it alike. A pair is one character, and reads.
  const manifestWith = (name) => `{"pact_export":2,"owner":"${owner}","owner_name":"${name}","exported_at":"2026-09-27T10:00:00Z","tool":"t","counts":{"contacts":0,"threads":0,"messages":0,"media":0},"files":{}}`;
  const end = (m) => ({ manifest: m, messages_sha256: null, lines: 0, ids: [], msg_ids: [], reply_tos: [], media_seen: [] });
  add('export_read_end: a manifest with a lone surrogate escape', 'export_read_end', end(manifestWith('\\ud800')));
  expect('export_read_end: a manifest with a lone surrogate escape', { error: 'bad_request', why: 'manifest.json: not a JSON object' });
  add('export_read_end: a manifest with a surrogate pair', 'export_read_end', end(manifestWith('\\ud83d\\ude00')));
  add('export_read_end: a manifest with a count of -0', 'export_read_end', end(manifestWith('x').replace('"messages":0', '"messages":-0')));
  const lineWith = (body) => `{"id":"1","thread":"t1","contact":"${other('B')}","msg_id":"m","direction":"in","sender":"human","time":"2026-09-27T10:00:00Z","body":"${body}","reply_to":null,"status":"read","attachments":[]}`;
  const lineNames = { threads: ['t1'], contacts: [other('B')], media: [] };
  add('export_read_messages: a line with a lone low surrogate escape', 'export_read_messages', { lines: [lineWith('a\\udc00b')], ...lineNames });
  expect('export_read_messages: a line with a lone low surrogate escape', { error: 'bad_request', why: 'messages.jsonl: line 1: not a JSON object' });
  add('export_read_messages: a line with a surrogate pair', 'export_read_messages', { lines: [lineWith('\\ud83d\\ude00 \\\\ud800')], ...lineNames });

  // ── the merge ───────────────────────────────────────────────────────────────────────────────
  const held = [row({}), row({ root: other('C'), endpoint: 'https://c.example/mcp', leaf: null, root_cert: null })];
  const rows = [
    row({ endpoint: 'https://moved.example/mcp' }), // held with a pin: kept, and the endpoint a conflict
    row({ root: other('C'), endpoint: 'https://c.example/mcp' }), // held without a leaf, and the row has one: written
    row({ root: other('D'), endpoint: 'https://d.example/mcp', leaf: null, root_cert: null }), // not held: written
  ];
  add('export_merge: a held pin is never replaced', 'export_merge', { held, rows });
  add('export_merge with rows whose root is no fingerprint', 'export_merge', { held, rows: [{ root: 'alina' }] });

  // ── the arguments and the writers' refusals ─────────────────────────────────────────────────
  add('export_read with nothing to work from', 'export_read', {});
  add('export_read with a directory entry that does not read', 'export_read', { directory: [{ name: 'manifest.json' }], owner, now });
  add('export_read_messages with nothing to work from', 'export_read_messages', {});
  add('export_read_messages from line 0', 'export_read_messages', { lines: [], threads: [], contacts: [], media: [], first_line: 0 });
  add('export_read_end with nothing to work from', 'export_read_end', {});
  add('export_write with nothing to work from', 'export_write', {});
  add('export_write: the owner as a contact', 'export_write', { ...writeArgs, contacts: [row({ root: owner })] });
  add('export_write: a permission §8 does not name', 'export_write', { ...writeArgs, contacts: [row({ permissions: ['everything'] })] });
  add('export_write: a private endpoint', 'export_write', { ...writeArgs, contacts: [row({ endpoint: 'https://10.0.0.1/mcp' })] });
  add('export_write: a thread whose contact is in no row', 'export_write', { ...writeArgs, threads: [{ ...threads[0], contact: other('Z') }] });
  add('export_write_messages: two attachments', 'export_write_messages', { messages: [{ ...messages[1], attachments: [messages[1].attachments[0], messages[1].attachments[0]] }] });
  add('export_write_messages: text beside a file', 'export_write_messages', { messages: [{ ...messages[1], body: 'a caption' }] });
  add('export_manifest with no partial', 'export_manifest', {});
  add('export_manifest: messages without their hash', 'export_manifest', { partial: written.partial, messages: 3 });
  add('export_manifest: a hash the host does not make', 'export_manifest', { partial: written.partial, hashes: { 'contacts.csv': file } });
  add('export_manifest: a partial that already counts messages', 'export_manifest', { partial: { ...written.partial, counts: { ...written.partial.counts, messages: 2 } } });
  expect('export_write_messages: two attachments', { error: 'bad_request', why: 'messages[0], member attachments: more than one attachment: a message carries at most one file' });
  expect('export_write_messages: text beside a file', { error: 'bad_request', why: 'messages[0], member body: not empty, and the message carries a file: a message with an attachment has no text' });
}
