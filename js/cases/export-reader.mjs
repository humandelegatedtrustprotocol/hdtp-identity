// The export READER's refusals, one per rule of SPEC §9.2 the corpus did not reach (9.2#10, #13,
// #15), each built from the valid export of go/exportcorpus with ONE thing wrong and every hash the
// manifest holds made true again, so the rule under test is the first thing a reader meets. Called
// from js/cases/export.mjs, whose section this is. Sizes are cases here and not zips: a file over
// 4 or 16 MiB has no place in a committed corpus, and what the core is handed — a directory entry's
// stated size, a member's text — is exactly what these give it.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { readZip } from '../zip.mjs';

const CORPUS = new URL('../../go/exportcorpus/', import.meta.url);
const sha = (b) => createHash('sha256').update(b).digest('hex');
const MiB = 1024 * 1024;

export default function readerCases({ add, expect }) {
  const index = JSON.parse(readFileSync(new URL('cases.json', CORPUS), 'utf8'));
  const entries = readZip(readFileSync(new URL('valid-export.zip', CORPUS)));
  const text = Object.fromEntries(entries.filter((e) => !e.name.startsWith('media')).map((e) => [e.name, e.data().toString('utf8')]));
  const media = entries.find((e) => /^media\/[0-9a-f]{64}$/.test(e.name));
  const refused = (why) => ({ error: 'bad_request', why });

  /**
   * export_read's arguments for the valid export with `change` applied to a copy of its members:
   * `{ contacts, threads, manifest (an object), sizes (name → stated size) }`. Every hash the manifest
   * lists for a text member is recomputed from the text handed in, so no refusal comes from it.
   */
  const readArgs = (change = () => {}) => {
    const m = { contacts: text['contacts.csv'], threads: text['threads.csv'], manifest: JSON.parse(text['manifest.json']), sizes: {}, extra: null };
    change(m);
    m.manifest.files['contacts.csv'] = sha(m.contacts);
    m.manifest.files['threads.csv'] = sha(m.threads);
    const manifest = m.extra ?? JSON.stringify(m.manifest);
    const members = { 'manifest.json': manifest, 'contacts.csv': m.contacts, 'threads.csv': m.threads, 'messages.jsonl': text['messages.jsonl'] };
    const directory = entries.map(({ name, size, encrypted, mode }) => ({
      name, encrypted, mode,
      size: m.sizes[name] ?? (name in members ? Buffer.byteLength(members[name]) : size),
    }));
    return { directory, manifest, contacts_csv: m.contacts, threads_csv: m.threads, owner: index.owner, now: index.now };
  };
  // One cell of one contacts.csv row (2 is the first after the header) replaced by `cell`, as written.
  const withCell = (row, col, cell) => (m) => {
    const lines = m.contacts.split('\r\n');
    lines[row - 1] = cells(lines[row - 1]).map((c, k) => (k === col ? cell : c)).join(',');
    m.contacts = lines.join('\r\n');
  };

  // ── 9.2#10: sizes ────────────────────────────────────────────────────────────────────────────
  const sizeCases = [
    ['contacts.csv stated over 4 MiB', (m) => { m.sizes['contacts.csv'] = 4 * MiB + 1; }, `entry "contacts.csv": ${4 * MiB + 1} bytes, over the ${4 * MiB} an export allows`],
    ['contacts.csv over 4 MiB though its entry says less', (m) => { m.contacts += 'x'.repeat(4 * MiB + 1 - m.contacts.length); m.sizes['contacts.csv'] = 1024; }, `contacts.csv: over ${4 * MiB} bytes`],
    ['contacts.csv of 5001 rows', (m) => { m.contacts = m.contacts.split('\r\n')[0] + '\r\n' + 'x\r\n'.repeat(5001); }, 'contacts.csv: over 5000 rows'],
    ['threads.csv over 16 MiB though its entry says less', (m) => { m.threads += 'x'.repeat(16 * MiB + 1 - m.threads.length); m.sizes['threads.csv'] = 1024; }, `threads.csv: over ${16 * MiB} bytes`],
    ['a media file stated over 5 MiB', (m) => { m.sizes[media.name] = 5 * MiB + 1; }, `entry "${media.name}": ${5 * MiB + 1} bytes, over the ${5 * MiB} an export allows`],
  ];
  // ── 9.2#13 and #15: rows and the manifest ─────────────────────────────────────────────────────
  // Row 2 is Dana's (no certificates), row 4 Chen's (a leaf that does not pin, and a root), row 5 Bharat's.
  const chenLeaf = cells(text['contacts.csv'].split('\r\n')[3])[8];
  const bharatRoot = cells(text['contacts.csv'].split('\r\n')[4])[9];
  const rowCases = [
    ['a contact whose status is not one of the three', withCell(2, 4, 'friend'), 'contacts.csv: row 2, column status: not active, blocked or pending_out'],
    ['a contact whose endpoint is plain http', withCell(2, 1, 'http://dana.example/agent/mcp'), 'contacts.csv: row 2, column endpoint: not an https URL in normal form'],
    ['a contact whose endpoint is not in normal form', withCell(2, 1, 'https://DANA.example/agent/mcp'), 'contacts.csv: row 2, column endpoint: not an https URL in normal form'],
    ['a contact whose added is not an instant', withCell(2, 10, '2026-09-04 09:00'), 'contacts.csv: row 2, column added: not an RFC 3339 instant'],
    ['a contact granted a permission §8 does not name', withCell(2, 6, 'message.everything'), 'contacts.csv: row 2, column permissions: "message.everything" is not a permission of §8'],
    ['a contact whose name is over 200 characters', withCell(2, 2, 'N'.repeat(201)), 'contacts.csv: row 2, column name: over 200 characters'],
    ['a contact whose root_cert is a leaf', withCell(4, 9, chenLeaf), 'contacts.csv: row 4, column root_cert: not a root of §14.1\'s profile'],
    ['a contact whose root_cert is another identity\'s root', withCell(4, 9, bharatRoot), 'contacts.csv: row 4, column root_cert: not the certificate of this row\'s root'],
    ['a manifest with a member it does not hold', (m) => { m.manifest.note = 'hello'; }, 'manifest.json: "note" is not a member of a manifest'],
  ];
  for (const [what, change, why] of [...sizeCases, ...rowCases]) {
    add(`export_read: ${what}`, 'export_read', readArgs(change));
    expect(`export_read: ${what}`, refused(why));
  }

  // ── 9.2#13: messages ─────────────────────────────────────────────────────────────────────────
  const lines = text['messages.jsonl'].replace(/\n$/, '').split('\n');
  const names = {
    threads: ['t1', 't2'],
    contacts: text['contacts.csv'].split('\r\n').slice(1).filter(Boolean).map((l) => cells(l)[0]),
    media: [media.name.slice(6)],
  };
  const withMember = (k, v) => {
    const m = JSON.parse(lines[0]);
    if (v === undefined) delete m[k]; else m[k] = v;
    return [JSON.stringify(m), ...lines.slice(1)];
  };
  for (const [what, changed, why] of [
    ['a message whose direction is neither', withMember('direction', 'sideways'), 'messages.jsonl: line 1, member direction: not in or out'],
    ['a message whose sender is neither', withMember('sender', 'robot'), 'messages.jsonl: line 1, member sender: not agent or human'],
    ['a message whose status is not one of the four', withMember('status', 'lost'), 'messages.jsonl: line 1, member status: not delivered or queued or failed or read'],
    ['a message whose body is over 16 KiB', withMember('body', 'b'.repeat(16 * 1024 + 1)), `messages.jsonl: line 1, member body: over ${16 * 1024} bytes`],
    ['a message missing a member', withMember('sender', undefined), 'messages.jsonl: line 1: sender is missing'],
  ]) {
    add(`export_read_messages: ${what}`, 'export_read_messages', { lines: changed, ...names });
    expect(`export_read_messages: ${what}`, refused(why));
  }
  // The control: the valid export's own lines, with the same names, read.
  add('export_read_messages: the valid export\'s lines', 'export_read_messages', { lines, ...names });

  // ── 9.2#13: one instant grammar, on read (SPEC 2.2.2) ────────────────────────────────────────
  // `Z` and `T` upper-case, no offset, `.` alone before a fraction: in a contact's `added`, a thread's
  // `created_at`, the manifest's `exported_at` and a message's `time`. The valid export is the control.
  const threadCell = (row, col, cell) => (m) => {
    const tl = m.threads.split('\r\n');
    tl[row - 1] = cells(tl[row - 1]).map((c, k) => (k === col ? cell : c)).join(',');
    m.threads = tl.join('\r\n');
  };
  const csvCell = (v) => (v.includes(',') ? `"${v}"` : v);
  for (const [what, instant] of [
    ['a lower-case z', '2026-09-04T09:00:00z'],
    ['a lower-case t', '2026-09-04t09:00:00Z'],
    ['a comma before the fraction', '2026-09-04T09:00:00,5Z'],
    ['an offset', '2026-09-04T09:00:00+00:00'],
  ]) {
    for (const [where, change, why] of [
      ['a contact added', withCell(2, 10, csvCell(instant)), 'contacts.csv: row 2, column added: not an RFC 3339 instant'],
      ['a thread created', threadCell(2, 3, csvCell(instant)), 'threads.csv: row 2, column created_at: not an RFC 3339 instant'],
      ['a manifest exported', (m) => { m.manifest.exported_at = instant; }, 'manifest.json: exported_at is not an RFC 3339 instant'],
    ]) {
      add(`export_read: ${where} at an instant with ${what}`, 'export_read', readArgs(change));
      expect(`export_read: ${where} at an instant with ${what}`, refused(why));
    }
    add(`export_read_messages: a message time with ${what}`, 'export_read_messages', { lines: withMember('time', instant), ...names });
    expect(`export_read_messages: a message time with ${what}`, refused('messages.jsonl: line 1, member time: not an RFC 3339 instant'));
  }
  add('export_read: instants in the one grammar, a fraction included', 'export_read', readArgs(withCell(2, 10, '2026-09-04T09:00:00.25Z')));
}

/** One CSV record's cells as written, quotes kept: the rows here hold no line break inside a cell. */
function cells(line) {
  const out = [];
  let cur = '', quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') { quoted = !quoted; cur += c; } else if (c === ',' && !quoted) { out.push(cur); cur = ''; } else cur += c;
  }
  out.push(cur);
  return out;
}
