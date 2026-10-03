// Instants in the export, read in the one grammar both ports read everywhere:
// `YYYY-MM-DDTHH:MM:SS`, an optional `.` fraction, and `Z` — upper-case T and Z only, no offset, and
// no `,` before a fraction. A lower-case `z` and a `,` fraction were read by one port and refused by
// the other. Called from js/cases/export.mjs, whose section this is.
export default function exportInstants({ add, expect }) {
  const owner = 'sha256:' + 'O'.repeat(43);
  const peer = 'sha256:' + 'B'.repeat(43);
  const row = (added) => ({
    root: peer, endpoint: 'https://b.example/mcp', name: '', display_name: '', status: 'active', was_active: true,
    permissions: [], their_permissions: [], leaf: null, root_cert: null, added,
  });
  const message = (time) => ({
    id: 'm1', thread: 't1', contact: peer, msg_id: 'x1', direction: 'in', sender: 'human', time, body: 'hi', reply_to: null,
    status: 'read', attachments: [],
  });
  const write = (over) => ({ owner, owner_name: '', exported_at: '2026-09-27T10:00:00Z', tool: 'parity', contacts: [row('2026-09-01T00:00:00Z')], ...over });
  for (const [what, instant] of [['a lower-case z', '2026-09-27T10:00:00z'], ['a comma before the fraction', '2026-09-27T10:00:00,5Z']]) {
    add(`export_write: an exported_at with ${what}`, 'export_write', write({ exported_at: instant }));
    expect(`export_write: an exported_at with ${what}`, { error: 'parse', why: `not an RFC 3339 instant: ${instant}` });
    add(`export_write: a contact added with ${what}`, 'export_write', write({ contacts: [row(instant)] }));
    expect(`export_write: a contact added with ${what}`, { error: 'bad_request', why: 'contacts[0], column added: not an RFC 3339 instant' });
    add(`export_write_messages: a message time with ${what}`, 'export_write_messages', { messages: [message(instant)] });
    expect(`export_write_messages: a message time with ${what}`, { error: 'bad_request', why: 'messages[0], member time: not an RFC 3339 instant' });
  }
  // The control: the grammar's own shapes, a fraction included, write.
  add('export_write: instants in the one grammar, a fraction included', 'export_write', write({ exported_at: '2026-09-27T10:00:00.250Z', contacts: [row('2026-09-01T00:00:00.9Z')] }));
  expect('export_write: instants in the one grammar, a fraction included', { threads_csv: null });
}
