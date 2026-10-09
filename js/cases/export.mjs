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
import readerCases from './export-reader.mjs';
import exportInstants from './export-instants.mjs';
import { ZONED } from './certificates.mjs';

const CORPUS = new URL('../../go/exportcorpus/', import.meta.url);
const sha = (b) => createHash('sha256').update(b).digest('hex');

export default function exportCases({ add, expect }, f) {
  const { wasm, rootFp, rootDer, leafDer, ENDPOINT, now } = f;
  const owner = 'sha256:' + 'O'.repeat(42) + 'A';
  const other = (c) => 'sha256:' + c.repeat(42) + 'A';

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
  // Removed threads (SPEC §9.2, SEP-0004): a former contact's conversation carries its names; the
  // longer header, a formula-led name guarded, a display name over 200 characters cut on a character,
  // an empty pair; and each refusal, in both ports' words.
  const removedThreads = [...threads,
    { id: 't3', contact: other('R'), topic: 'the handover', created_at: '2026-09-12T10:00:00Z', last_at: '2026-09-12T10:00:00Z', contact_name: '=former, "quoted"', contact_display_name: '\u00e9'.repeat(250) },
    { id: 't4', contact: other('R'), topic: '', created_at: '2026-09-13T10:00:00Z', last_at: '2026-09-13T10:00:00Z', contact_name: '=former, "quoted"', contact_display_name: '\u00e9'.repeat(250) },
    { id: 't5', contact: other('S'), topic: '', created_at: '2026-09-13T10:00:00Z', last_at: '2026-09-13T10:00:00Z' }];
  const withRemoved = (ts) => ({ ...writeArgs, threads: ts });
  add('export_write: removed threads, the longer header, names guarded and cut', 'export_write', withRemoved(removedThreads));
  add('export_write: names on a thread whose contact is a contact', 'export_write', withRemoved([...threads, { ...threads[0], id: 't9', contact_name: 'x' }]));
  add('export_write: a removed thread whose root is the owner', 'export_write', withRemoved([...threads, { ...removedThreads[2], contact: owner }]));
  add('export_write: a removed thread whose root is not a fingerprint', 'export_write', withRemoved([...threads, { ...removedThreads[2], contact: 'R' }]));
  add('export_write: two removed threads of one root with different names', 'export_write', withRemoved([...threads, removedThreads[2], { ...removedThreads[3], contact_name: 'other' }]));
  add('export_write: a removed thread whose own name is over 200 characters', 'export_write', withRemoved([...threads, { ...removedThreads[2], contact_name: 'n'.repeat(201) }]));
  add('export_write: a thread name that is not a string', 'export_write', withRemoved([...threads, { ...removedThreads[2], contact_name: 7 }]));
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
  // `export_read` declares `parse`, and nothing produced it until the coverage gate asked (TC-1).
  add('export_read at an instant that does not read', 'export_read', { ...readArgs, now: 'nope' });
  const read = wasm.call('export_read', readArgs);
  const names = { threads: read.threads.map((t) => t.id), contacts: read.contacts.map((c) => c.root), media: read.media.map((m) => m.hash) };
  add('export_read_messages: what export_write_messages wrote', 'export_read_messages', { lines, ...names });
  add('export_read_end: what was written', 'export_read_end', { manifest, messages_sha256: sha(jsonl), lines: lines.length, ids: ['m1', 'm2', 'm3'], msg_ids: ['x-1', 'x-2', 'x-3'], reply_tos: ['x-1'], media_seen: [file], media: [file] });

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
    // A message names a contact, or the contact of a removed thread.
    const roots = [...first.contacts.map((r) => r.root), ...first.threads.map((t) => t.contact)];
    const msgArgs = { lines: fileLines, threads: first.threads.map((t) => t.id), contacts: roots, media: first.media.map((m) => m.hash) };
    const second = wasm.call('export_read_messages', msgArgs);
    if (second.error || c.accept) {
      add(`${label}: export_read_messages`, 'export_read_messages', msgArgs);
      if (second.error) { expect(`${label}: export_read_messages`, want); continue; }
    }
    const endArgs = {
      manifest: args.manifest, messages_sha256: text('messages.jsonl') === undefined ? null : sha(Buffer.from(body, 'utf8')), lines: fileLines.length,
      ids: second.messages.map((m) => m.id), msg_ids: second.messages.map((m) => m.msg_id),
      reply_tos: second.messages.map((m) => m.reply_to).filter((r) => r !== null), media_seen: second.media_seen,
      media: first.media.map((m) => m.hash),
    };
    add(`${label}: export_read_end`, 'export_read_end', endArgs);
    expect(`${label}: export_read_end`, want ?? { ok: true });
  }

  // JSON the two ports' decoders read differently: a lone surrogate escape is refused by serde and
  // was replaced with U+FFFD by Go's encoding/json. A manifest and a message are JSON inside a string,
  // so a file carries one to both; the ports must refuse it alike. A pair is one character, and reads.
  const manifestWith = (name) => `{"hdtp_export":1,"owner":"${owner}","owner_name":"${name}","exported_at":"2026-09-27T10:00:00Z","tool":"t","counts":{"contacts":0,"threads":0,"messages":0,"media":0},"files":{}}`;
  const end = (m) => ({ manifest: m, messages_sha256: null, lines: 0, ids: [], msg_ids: [], reply_tos: [], media_seen: [], media: [] });
  add('export_read_end: a manifest with a lone surrogate escape', 'export_read_end', end(manifestWith('\\ud800')));
  expect('export_read_end: a manifest with a lone surrogate escape', { error: 'bad_request', why: 'manifest.json: not a JSON object' });
  add('export_read_end: a manifest with a surrogate pair', 'export_read_end', end(manifestWith('\\ud83d\\ude00')));
  add('export_read_end: a manifest with a count of -0', 'export_read_end', end(manifestWith('x').replace('"messages":0', '"messages":-0')));
  const lineWith = (body) => `{"id":"1","thread":"t1","contact":"${other('B')}","msg_id":"m","direction":"in","sender":"human","time":"2026-09-27T10:00:00Z","body":"${body}","reply_to":null,"status":"read","attachments":[]}`;
  const lineNames = { threads: ['t1'], contacts: [other('B')], media: [] };
  add('export_read_messages: a line with a lone low surrogate escape', 'export_read_messages', { lines: [lineWith('a\\udc00b')], ...lineNames });
  expect('export_read_messages: a line with a lone low surrogate escape', { error: 'bad_request', why: 'messages.jsonl: line 1: not a JSON object' });
  add('export_read_messages: a line with a surrogate pair', 'export_read_messages', { lines: [lineWith('\\ud83d\\ude00 \\\\ud800')], ...lineNames });
  // And what serde refuses and encoding/json read (R40, S3-2): a number infinite as a double, and
  // containers nested more than 127 deep. The Go port read the manifest and named a member; it is not
  // JSON to either port now. 127 deep reads, and is refused for what it holds.
  const nested = (n) => '['.repeat(n) + '1' + ']'.repeat(n);
  const notJSON = { error: 'bad_request', why: 'manifest.json: not a JSON object' };
  add('export_read_end: a manifest with a count past the largest double', 'export_read_end', end(manifestWith('x').replace('"messages":0', '"messages":1e400')));
  expect('export_read_end: a manifest with a count past the largest double', notJSON);
  add('export_read_end: a manifest nested 128 deep', 'export_read_end', end(manifestWith('x').replace('"tool":"t"', `"tool":${nested(127)}`)));
  expect('export_read_end: a manifest nested 128 deep', notJSON);
  add('export_read_end: a manifest nested 127 deep', 'export_read_end', end(manifestWith('x').replace('"tool":"t"', `"tool":${nested(126)}`)));
  const lineNotJSON = { error: 'bad_request', why: 'messages.jsonl: line 1: not a JSON object' };
  add('export_read_messages: a line with a number past the largest double', 'export_read_messages', { lines: [lineWith('x').replace('"attachments":[]', '"attachments":[1e400]')], ...lineNames });
  expect('export_read_messages: a line with a number past the largest double', lineNotJSON);
  add('export_read_messages: a line nested 128 deep', 'export_read_messages', { lines: [lineWith('x').replace('"attachments":[]', `"attachments":${nested(127)}`)], ...lineNames });
  expect('export_read_messages: a line nested 128 deep', lineNotJSON);

  // export_read_end reads its lists straight from the argument text (0.3.2): every shape a list can
  // take, answered as the parsed arguments were.
  const endWith = (over) => ({ manifest: manifestWith('x'), messages_sha256: null, lines: 0, ids: [], msg_ids: [], reply_tos: [], media_seen: [], media: [], ...over });
  for (const [what, over] of [
    ['ids holding null', { ids: [null] }],
    ['ids holding a number', { ids: ['a', 5] }],
    ['ids holding a list', { ids: [['a']] }],
    ['ids given as null', { ids: null }],
    ['ids given as a string', { ids: 'a' }],
    ['no ids at all', { ids: undefined }],
    ['ids that hold the word null and an escaped quote', { ids: ['null', 'a"null', 'b\\n'], lines: 0 }],
    ['msg_ids holding an object', { msg_ids: [{}] }],
    ['a manifest given as a number', { manifest: 5 }],
    ['lines given as text', { lines: '3' }],
    ['media holding a number', { media: [5] }],
    ['no media at all', { media: undefined }],
  ]) {
    const args = endWith(over);
    for (const k of Object.keys(args)) if (args[k] === undefined) delete args[k];
    add(`export_read_end with ${what}`, 'export_read_end', args);
  }

  // ── the merge ───────────────────────────────────────────────────────────────────────────────
  const held = [row({}), row({ root: other('C'), endpoint: 'https://c.example/mcp', leaf: null, root_cert: null })];
  const rows = [
    row({ endpoint: 'https://moved.example/mcp' }), // held with a pin: kept, and the endpoint a conflict
    row({ root: other('C'), endpoint: 'https://c.example/mcp' }), // held without a leaf, and the row has one: written
    row({ root: other('D'), endpoint: 'https://d.example/mcp', leaf: null, root_cert: null }), // not held: written
  ];
  add('export_merge: a held pin is never replaced', 'export_merge', { held, rows });
  add('export_merge with rows whose root is no fingerprint', 'export_merge', { held, rows: [{ root: 'alina' }] });
  // A row's status and added are what ContactRow says they are, in export_read's words: a held
  // `Blocked` was read as not blocked, so the import did not keep the person's block, and an added of
  // "" was carried into the rows the host writes (the review of 2026-09-30, found by parity's nested ""
  // cases). The controls are the case above and the one below.
  for (const [what, over, where, why] of [
    ['a held row whose status is "Blocked"', { held: [row({ status: 'Blocked' })] }, 'held[0]', 'status is not active, blocked or pending_out'],
    ['a row whose status is ""', { rows: [row({ status: '' })] }, 'rows[0]', 'status is not active, blocked or pending_out'],
    ['a held row whose added is ""', { held: [row({ added: '' })] }, 'held[0]', 'added is not an RFC 3339 instant'],
    ['a row whose added is a date', { rows: [row({ added: '2026-09-02' })] }, 'rows[0]', 'added is not an RFC 3339 instant'],
  ]) {
    add(`export_merge with ${what}`, 'export_merge', { held, rows, ...over });
    expect(`export_merge with ${what}`, { error: 'bad_request', why: `${where}: ${why}` });
  }
  // What the person decided about a held contact outlives an export that says otherwise (SPEC 9.2#16):
  // a blocked contact stays blocked and keeps its permissions even when the row is written for its
  // leaf, and each disagreement is a conflict. Permissions are a set: an order is no disagreement.
  const blocked = row({ root: other('E'), endpoint: 'https://e.example/mcp', status: 'blocked', permissions: ['message.media', 'message.text'], leaf: null, root_cert: null });
  add('export_merge: a held blocked contact keeps what the person decided', 'export_merge', {
    held: [blocked, row({ root: other('F'), endpoint: 'https://f.example/mcp', permissions: ['message.text', 'status.view'] })],
    rows: [
      row({ root: other('E'), endpoint: 'https://e.example/mcp', status: 'active', permissions: ['message.text'] }),
      row({ root: other('F'), endpoint: 'https://f.example/mcp', permissions: ['status.view', 'message.text'] }),
    ],
  });

  // ── what a contact controls (SPEC §9.2, 9.2#22–25): it never stops the owner's export, and what is
  //    written reads back ─────────────────────────────────────────────────────────────────────────
  const keyBody = f.hostPkcs8;
  const theirs = [
    { ...messages[0], id: 'k1', msg_id: 'k-1', reply_to: 'x-elsewhere' },
    { ...messages[0], id: 'k2', msg_id: 'k-2', body: keyBody },
    { ...messages[0], id: 'k3', msg_id: 'k-3', reply_to: 'k-2' },
    { ...messages[0], id: 'k4', msg_id: 'k-4', reply_to: 'k-1' },
  ];
  add('export_write_messages: a dangling reply, a key in a body, a reply to what was left out', 'export_write_messages', { messages: theirs });
  add('export_write_messages: in batches, the file names its msg_ids', 'export_write_messages', { messages: theirs.slice(0, 1), msg_ids: ['k-1', 'x-elsewhere'] });
  add('export_write_messages: msg_ids that are not strings', 'export_write_messages', { messages: theirs.slice(0, 1), msg_ids: [5] });
  const claimed = row({ root: other('B'), endpoint: 'https://b.example/mcp', display_name: 'é'.repeat(150) + 'x'.repeat(150), their_permissions: ['message.media', 'root.everything', 'message.media', 'integration.cal-x'], leaf: null, root_cert: null });
  const claimsArgs = { owner, owner_name: '', exported_at: now, tool: 'parity', contacts: [claimed], threads: [{ ...threads[1] }] };
  add('export_write: a 300-character display name and permissions §8 does not have', 'export_write', claimsArgs);
  // Read back: what was written is a file the reader takes whole.
  const cw = wasm.call('export_write', claimsArgs);
  const cl = wasm.call('export_write_messages', { messages: theirs.map((m) => ({ ...m, thread: 't1', contact: other('B') })) });
  const cjsonl = cl.lines.map((l) => l + '\n').join('');
  const cman = wasm.call('export_manifest', { partial: cw.partial, hashes: { 'messages.jsonl': sha(cjsonl) }, messages: cl.lines.length }).manifest;
  const cdir = [['manifest.json', cman], ['contacts.csv', cw.contacts_csv], ['threads.csv', cw.threads_csv], ['messages.jsonl', cjsonl]]
    .map(([name, text]) => ({ name, size: Buffer.byteLength(text), encrypted: false, mode: 0o100644 }));
  add('export_read: what a contact controls, as written, reads back', 'export_read', { directory: cdir, manifest: cman, contacts_csv: cw.contacts_csv, threads_csv: cw.threads_csv, owner, now });
  const cread = wasm.call('export_read', { directory: cdir, manifest: cman, contacts_csv: cw.contacts_csv, threads_csv: cw.threads_csv, owner, now });
  add('export_read_messages: what a contact controls, as written, reads back', 'export_read_messages', { lines: cl.lines, threads: cread.threads.map((t) => t.id), contacts: cread.contacts.map((c) => c.root), media: [] });
  const cback = wasm.call('export_read_messages', { lines: cl.lines, threads: cread.threads.map((t) => t.id), contacts: cread.contacts.map((c) => c.root), media: [] }).messages;
  add('export_read_end: what a contact controls, as written, reads back', 'export_read_end', {
    manifest: cman, messages_sha256: sha(cjsonl), lines: cl.lines.length, ids: cback.map((m) => m.id), msg_ids: cback.map((m) => m.msg_id),
    reply_tos: cback.map((m) => m.reply_to).filter((r) => r !== null), media_seen: [], media: [],
  });
  expect('export_read_end: what a contact controls, as written, reads back', { ok: true });

  // ── the wallet's book as rows ───────────────────────────────────────────────────────────────
  const kept = { root: rootFp, endpoint: ENDPOINT, name: 'Alina', leaf: leafDer, root_cert: rootDer, added: '2026-09-02T09:00:00Z' };
  add('book_rows: a contact with everything, one with the least', 'book_rows', { contacts: [kept, { root: other('B'), endpoint: 'https://b.example/mcp' }], exported_at: now });
  add('book_rows: an empty book', 'book_rows', { contacts: [], exported_at: now });
  add('book_rows: a contact with a member a book does not keep', 'book_rows', { contacts: [{ ...kept, preset: 'friend' }], exported_at: now });
  add('book_rows: a contact with no endpoint', 'book_rows', { contacts: [{ root: rootFp }], exported_at: now });
  add('book_rows: a name that is not a string', 'book_rows', { contacts: [{ ...kept, name: 5 }], exported_at: now });
  add('book_rows: a contact that is not an object', 'book_rows', { contacts: ['alina'], exported_at: now });
  add('book_rows with nothing to work from', 'book_rows', {});
  add('book_rows with an exported_at that does not read', 'book_rows', { contacts: [], exported_at: 'today' });
  // The rows are the ones export_write takes: a book through book_rows is a book that writes.
  const bookRows = wasm.call('book_rows', { contacts: [kept, { root: other('B'), endpoint: 'https://b.example/mcp' }], exported_at: now }).rows;
  add('export_write: the rows book_rows made', 'export_write', { owner, owner_name: 'Olive', exported_at: now, tool: 'parity', contacts: bookRows });
  expect('book_rows: a contact with a member a book does not keep', { error: 'bad_request', why: 'contacts[0]: "preset" is not a member of a wallet contact' });
  // A book's root and added reach the rows as the contract types them: a root that is no fingerprint
  // or an added that is no instant came back in a row off the contract (the review of 2026-09-30).
  for (const [what, over, why] of [
    ['a root that is no fingerprint', { root: 'alina' }, 'contacts[0]: root is not a fingerprint'],
    ['a root of ""', { root: '' }, 'contacts[0]: root is not a fingerprint'],
    ['an added of ""', { added: '' }, 'contacts[0]: added is not an RFC 3339 instant'],
    ['an added with an offset', { added: '2026-09-02T09:00:00+01:00' }, 'contacts[0]: added is not an RFC 3339 instant'],
  ]) {
    add(`book_rows: a contact with ${what}`, 'book_rows', { contacts: [{ ...kept, ...over }], exported_at: now });
    expect(`book_rows: a contact with ${what}`, { error: 'bad_request', why });
  }

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

  // Key material in the owner's and the host's own strings (SPEC 9.2#28): the writer refuses it,
  // naming the member, and so does the reader, in a manifest someone else wrote.
  add('export_write: a private key as the owner_name', 'export_write', { ...writeArgs, owner_name: f.hostPkcs8 });
  add('export_write: a private key as the tool', 'export_write', { ...writeArgs, tool: `-----BEGIN PRIVATE KEY-----\n${f.hostPkcs8}\n-----END PRIVATE KEY-----` });
  const keyManifest = (m) => JSON.stringify({ hdtp_export: 1, owner, owner_name: '', exported_at: '2026-09-27T10:00:00Z', tool: 't', counts: { contacts: 0, threads: 0, messages: 0, media: 0 }, files: {}, ...m });
  add('export_read_end: a manifest whose owner_name is a private key', 'export_read_end', end(keyManifest({ owner_name: f.hostPkcs8 })));
  add('export_read_end: a manifest whose tool is a private key', 'export_read_end', end(keyManifest({ tool: f.hostPkcs8 })));
  add('export_read_end: a manifest that lists a media member in files', 'export_read_end', end(keyManifest({ files: { [`media/${file}`]: file } })));
  for (const [id, why] of [
    ['export_write: a private key as the owner_name', 'owner_name holds a private key'],
    ['export_write: a private key as the tool', 'tool holds a private key'],
    ['export_read_end: a manifest whose owner_name is a private key', 'manifest.json: owner_name holds a private key'],
    ['export_read_end: a manifest whose tool is a private key', 'manifest.json: tool holds a private key'],
    ['export_read_end: a manifest that lists a media member in files', `manifest.json: files: "media/${file}" is not a member an export lists`],
  ]) expect(id, { error: 'bad_request', why });

  // `files` lists the text members only: an export of 5000 media files still has a
  // manifest under 64 KiB, and the reader counts them.
  const many = Array.from({ length: 5000 }, (_, i) => ({ hash: sha(`media ${i}`), size: 1 }));
  const manyWritten = wasm.call('export_write', { owner, owner_name: '', exported_at: now, tool: 'parity', contacts: [], media: many });
  add('export_write: 5000 media files', 'export_write', { owner, owner_name: '', exported_at: now, tool: 'parity', contacts: [], media: many });
  add('export_manifest: 5000 media files, the manifest under 64 KiB', 'export_manifest', { partial: manyWritten.partial });
  if (Buffer.byteLength(wasm.call('export_manifest', { partial: manyWritten.partial }).manifest) >= 64 * 1024) throw new Error('export_manifest: 5000 media files make a manifest of 64 KiB or more');

  // A contact row naming an IPv6 literal with a zone id (T1, C1, R09): a row whose endpoint is not the
  // normal form is refused by the writer, as every other one is.
  for (const endpoint of ZONED.slice(0, 2)) {
    add(`export_write of a row naming ${endpoint}`, 'export_write', { owner, owner_name: 'Olive', exported_at: now, tool: 'parity', contacts: [row({ endpoint })] });
    expect(`export_write of a row naming ${endpoint}`, { error: 'bad_request', why: 'contacts[0], column endpoint: not an https URL in normal form' });
  }
  // The reader's refusals, one per rule §9.2 names (SPEC 9.2#10, #13, #15): js/cases/export-reader.mjs.
  readerCases({ add, expect }, f);
  // One instant grammar in the export: js/cases/export-instants.mjs.
  exportInstants({ add, expect });

  // media_holds_private_key: SPEC §9.2's key material over a media file, from js/key-material.json, the
  // list both ports' own tests read (CW-07, R38). Each case is compared whole and held to the list's
  // answer; the lenient spellings (a spare bit, a length in a longer form) are the ones the cloud's copy
  // read as a key and the ports did not.
  const material = JSON.parse(readFileSync(new URL('../key-material.json', import.meta.url), 'utf8'));
  for (const c of material.cases) {
    const bytes = c.hex !== undefined ? Buffer.from(c.hex, 'hex') : Buffer.from(c.text, 'utf8');
    add(`media_holds_private_key: ${c.what}`, 'media_holds_private_key', { bytes: bytes.toString('base64url') });
    expect(`media_holds_private_key: ${c.what}`, { holds_private_key: c.holds });
  }
  add('media_holds_private_key of no bytes', 'media_holds_private_key', { bytes: '' });
  expect('media_holds_private_key of no bytes', { holds_private_key: false });
  // The argument is read strictly, as every argument's bytes are (CONTRACT §0): only the file's
  // contents are read leniently.
  add('media_holds_private_key of bytes that are not base64url', 'media_holds_private_key', { bytes: 'a b' });
  expect('media_holds_private_key of bytes that are not base64url', { error: 'parse', why: 'not base64url' });
}
