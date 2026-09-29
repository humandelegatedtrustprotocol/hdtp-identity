// §6.1 of the contract: the ledger — what signing a leaf for an endpoint would mean, as facts.
//
// One case per notice kind, the refusal that is the only thing `move` changes, an entry of another
// root that must not move the answer, the live leaf as the NEWEST entry (never the newest unexpired
// one), and every ledger that does not read. The last case is the control that must get through.
import { ZONED } from './certificates.mjs';

export default function ledger({ add, expect }, f) {
  const { now, ENDPOINT, rootFp } = f;
  const OTHER_ROOT = 'sha256:' + 'B'.repeat(43);
  const THERE = 'https://alina.host.example/alina/mcp';
  const day = 86_400_000;
  const at = (days) => new Date(Date.parse(now) + days * day).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const entry = (endpoint, nb, na, root = rootFp) => ({ root, endpoint, not_before: at(nb), not_after: at(na), issued_at: at(nb) });
  const ask = (ledger, over = {}) => {
    const args = { ledger, root: rootFp, endpoint: ENDPOINT, now, ...over };
    for (const k of Object.keys(args)) if (args[k] === undefined) delete args[k];
    return args;
  };
  const here = [entry(ENDPOINT, -10, 300)];
  const moved = [entry(ENDPOINT, -10, 300), entry(THERE, -1, 200)];
  const expired = [entry(ENDPOINT, -400, -1)];

  add('ledger_check: a renewal where the live leaf is', 'ledger_check', ask(here));
  add('ledger_check: a move, not chosen', 'ledger_check', ask(here, { endpoint: THERE }));
  add('ledger_check: a move, chosen', 'ledger_check', ask(here, { endpoint: THERE, move: true }));
  add('ledger_check: back to an endpoint issued to before, not chosen', 'ledger_check', ask(moved));
  add('ledger_check: back to an endpoint issued to before, chosen', 'ledger_check', ask(moved, { move: true }));
  add('ledger_check: an empty ledger', 'ledger_check', ask([]));
  // One grammar for every instant (SPEC 2.2.2): an entry's instant with an offset does not read, and
  // neither does a `now` with one. One port read both.
  add('ledger_check: an entry whose not_before has an offset', 'ledger_check', ask([{ ...here[0], not_before: here[0].not_before.replace(/Z$/, '+00:00') }]));
  expect('ledger_check: an entry whose not_before has an offset', { error: 'bad_request', why: "the record's ledger entry 0 does not read: not_before" });
  add('ledger_check: a now with an offset', 'ledger_check', ask(here, { now: now.replace(/Z$/, '+00:00') }));
  expect('ledger_check: a now with an offset', { error: 'parse', why: `not an RFC 3339 instant: ${now.replace(/Z$/, '+00:00')}` });
  add('ledger_check: a now with a lower-case z', 'ledger_check', ask(here, { now: now.replace(/Z$/, 'z') }));
  expect('ledger_check: a now with a lower-case z', { error: 'parse', why: `not an RFC 3339 instant: ${now.replace(/Z$/, 'z')}` });
  add('ledger_check: no ledger at all', 'ledger_check', ask(undefined));
  add('ledger_check: a ledger given as null', 'ledger_check', ask(null));
  add('ledger_check: after the live leaf expired, a new endpoint', 'ledger_check', ask(expired, { endpoint: THERE }));
  add('ledger_check: after the live leaf expired, the same endpoint', 'ledger_check', ask(expired));
  add('ledger_check: another root\'s live leaf is not this root\'s', 'ledger_check', ask([entry(THERE, -1, 300, OTHER_ROOT)]));
  // The newest leaf has expired and an older one has not: nothing is live (§14.3: the newer one
  // superseded the older the moment it was seen), and this is a renewal, not a second home.
  add('ledger_check: the newest leaf expired, an older one did not', 'ledger_check', ask([entry(ENDPOINT, -100, 200), entry(THERE, -50, -1)], { endpoint: THERE }));

  // Every ledger that does not read, whichever root its entry names: refused, never skipped.
  const good = entry(THERE, -1, 300, OTHER_ROOT);
  const unreadable = [
    ['an entry whose not_before does not read', [...here, { ...good, not_before: 'soon' }], 'the record\'s ledger entry 1 does not read: not_before'],
    ['an entry whose not_after does not read', [{ ...good, not_after: 'later' }], 'the record\'s ledger entry 0 does not read: not_after'],
    ['an entry with no endpoint', [{ ...good, endpoint: undefined }], 'the record\'s ledger entry 0 does not read: endpoint'],
    ['an entry carrying the leaf', [{ ...good, leaf: 'MIIB' }], 'the record\'s ledger entry 0 does not read: leaf'],
    ['an entry that is not an object', ['an entry'], 'the record\'s ledger entry 0 does not read'],
    ['a ledger that is not a list', { entries: [] }, 'the record\'s ledger is a list'],
  ];
  // An entry's root is a fingerprint (contract: LedgerEntry.root is a Fingerprint) and its endpoint is
  // not empty, whichever root it names. The ports answered these two ways: the Go port's typed pass
  // refused an empty member, and the core read it.
  for (const [what, bad, m] of [
    ['an entry whose root is empty', { ...good, root: '' }, 'root'],
    ['an entry whose root is no fingerprint', { ...good, root: 'alina' }, 'root'],
    ['an entry whose endpoint is empty', { ...good, endpoint: '' }, 'endpoint'],
  ]) {
    add(`ledger_check: ${what}`, 'ledger_check', ask([...here, bad]));
    expect(`ledger_check: ${what}`, { error: 'bad_request', why: `the record's ledger entry 1 does not read: ${m}` });
  }
  for (const [what, ledger, why] of unreadable) {
    add(`ledger_check: ${what}`, 'ledger_check', ask(ledger));
    expect(`ledger_check: ${what}`, { error: 'bad_request', why });
  }
  for (const [what, over] of [
    ['no root', { root: undefined }],
    ['an empty root', { root: '' }],
    ['no endpoint', { endpoint: undefined }],
    ['an endpoint not in normal form', { endpoint: 'http://agent.alina.example/mcp' }],
    ['no now', { now: undefined }],
    ['a now that does not read', { now: 'yesterday' }],
    ['a move that is not a boolean', { move: 'yes' }],
  ]) add(`ledger_check with ${what}`, 'ledger_check', ask(here, over));
  add('ledger_check with nothing to work from', 'ledger_check', {});

  // What SPEC §9 says, held here so two ports that broke it alike would still fail.
  expect('ledger_check: a move, not chosen', { refusal: `a leaf is live for ${ENDPOINT}: a second endpoint is a move, not a second home` });
  expect('ledger_check: a move, chosen', { refusal: null });
  expect('ledger_check: back to an endpoint issued to before, not chosen', { refusal: `a leaf is live for ${THERE}: a second endpoint is a move, not a second home` });
  expect('ledger_check: the newest leaf expired, an older one did not', { refusal: null, live: null });
  expect('ledger_check: another root\'s live leaf is not this root\'s', { refusal: null, previous_not_before: null });

  // The control that must get through: a ledger that reads, with an origin and another root's entry.
  add('ledger_check over a ledger that reads', 'ledger_check', ask([{ ...here[0], origin: 'https://app.example' }, good], { move: false }));
  expect('ledger_check over a ledger that reads', { refusal: null, known_endpoint: true, new_host: false });

  // An endpoint that is an IPv6 literal with a zone id is not the normal form (T1, C1, R09).
  for (const endpoint of ZONED.slice(0, 2)) {
    add(`ledger_check for ${endpoint}`, 'ledger_check', ask(here, { endpoint }));
    expect(`ledger_check for ${endpoint}`, { error: 'bad_request', why: 'endpoint is not an https URL in normal form' });
  }
}
