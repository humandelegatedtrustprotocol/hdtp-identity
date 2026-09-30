// The parity cases nobody writes by hand: generated from contract/contract.json for every function it
// declares, so that a function, or a member of one, cannot arrive without them.
//
// The hand-written cases stop where their author stopped. The audit of 2026-09-29 measured it: they
// tried the first member of a function and not the rest, 14 functions had no `{}` case at all, and
// the four cases that sent a member the contract does not declare each sent it beside a missing
// one, so none asked what a call that otherwise succeeds does with it. Behind those gaps were
// answers the two ports gave differently (report §2.6, fix 1). These are the shapes a caller gets
// wrong, taken from the contract's own description of each function's arguments:
//
//   {}           the empty object, compared whole;
//   hostile      js/cases/hostile.json, the object go/unit_test.go's TestCallNeverPanics and the core's
//                tests/boundary.rs sweep every function with, compared whole — so the sweep runs on
//                BOTH ports, where it ran on one and could not see a panic its own recover() had turned
//                into an answer. Each function is sent the hostile members it DECLARES, and a function
//                that declares none of them has no such case (`{}` is that case): the whole object
//                is refused for its first undeclared member before any is read (CONTRACT §0), so sent
//                whole it reached no function's body at all;
//   absent       each required member left out of a call that succeeds, held to CONTRACT §0's answer
//                for it: `{"error": "bad_request", "why": "<name> is required"}`;
//   null         the same member as the JSON literal null, which §0 says is absent: the same answer;
//   ""           each member that takes a string, as "" (§0: empty is not absent). An optional one is
//                compared between the ports; a REQUIRED one is also judged: it must refuse, unless
//                EMPTY_IS_A_VALUE below names it with the reason "" is a value there. Only optional
//                members were sent "", so no required string ever was, and export_read read another
//                identity's file for an owner of "" in one port and refused it in the other (the hunt
//                of 2026-09-30);
//   wrong type   each optional member of the wrong JSON type — a number for a string, a string for an
//                object, a list or a number, "yes" for a boolean — held to CONTRACT §0's answer for it:
//                bytes are `{"error": "parse", "why": "not base64url"}`, as bytes that will not decode
//                are, and any other member is `bad_request` in words that name it. An optional member
//                of the wrong type is a caller's mistake, never a member left out;
//   undeclared   one member the contract does not declare, on a call that succeeds;
//   read order   for each ordered pair (a, b) of members where a is required: a left out AND b of the
//                wrong type. The member named is the one the function reads first (CONTRACT §0: "both
//                ports read them in the same order"); a port that judges b's type at decode, before it
//                reads anything, names b where the other names a;
//   outside      each member that holds a key — a SubjectPublicKeyInfo, a PKCS #8 key, a certificate,
//                a request, or a list of one of them — holding one whose key is outside the profile
//                (`outside`, from js/cases/fixtures.mjs), in the first place of a list. CONTRACT §0: it
//                is refused where it is read, `unsupported`, `unsupported key type <OID>`. One port
//                read such a key as a key with no algorithm, so a certificate carrying one was parsed,
//                compared and taken on a card where the other refused it (R12, T2).
//
// "A call that succeeds" is one hand-written case per function, named in BASES below: its arguments
// are what each shape is made from, and its way of comparing (`how`) is kept, which is what already
// accounts for a value drawn fresh each run. The base is NAMED rather than found, so a hand-written
// case that is changed cannot quietly become a different base behind the same generated ids; js/parity.mjs
// fails the run when a base is missing or does not succeed on both ports.
import { readFileSync } from 'node:fs';

/** The hostile object, one copy: read here and by go/unit_test.go's TestCallNeverPanics. */
export const HOSTILE = JSON.parse(readFileSync(new URL('./hostile.json', import.meta.url), 'utf8'));

/** The contract's types that hold a key, which the `outside` shape fills. */
export const KEYED = ['Spki', 'Pkcs8', 'CertDer', 'Csr'];

/** Which of KEYED a member holds, and whether as a list: `{ type, list }`, or null. */
export function keyedOf(schema, root) {
  if (!schema || schema === true) return null;
  if (schema.$ref) {
    const name = /^#\/\$defs\/(.+)$/.exec(schema.$ref)[1];
    return KEYED.includes(name) ? { type: name, list: false } : keyedOf(root.$defs[name], root);
  }
  if (schema.type === 'array') {
    const item = keyedOf(schema.items, root);
    return item && !item.list ? { type: item.type, list: true } : null;
  }
  return null;
}

/**
 * Whether an answer refuses, in its function's own shape: a failure (`error` with `why` beside it, as
 * CONTRACT §0 writes every one; profile_error's `{error: null}` is an answer whose member happens to
 * be called that), `{ok: false}` (the checks that answer a verdict), a decision other than `ok`, or
 * follow_renewed's `{follow: false}`.
 */
export const refuses = (a) => !!a && ((typeof a.error === 'string' && typeof a.why === 'string') || a.ok === false || a.follow === false || (a.result?.code !== undefined && a.result.code !== 'ok'));

/**
 * The required string members where "" is a value, not a mistake, each with why — decided per member
 * on 2026-09-30, from what the function is for and what reads what it writes. Every other required
 * string member must refuse "". A name here that is no required string member fails the run.
 */
export const EMPTY_IS_A_VALUE = {
  'sign.data': 'the bytes to sign: none are a message like any other',
  'verify.data': 'the bytes to verify: none are a message like any other (the base signature is over others: valid false)',
  'verify.sig': 'no signature is one that does not verify: valid false',
  'build_root.cn': "a commonName is the name as given: §14.1 sets no length, and profile_error reads a root named \"\" as in the profile",
  'root_tbs.cn': 'as build_root',
  'build_leaf.cn': 'as build_root: profile_error reads a leaf named "" as in the profile',
  'build_leaf.root_cn': 'as build_root',
  'leaf_tbs.cn': 'as build_leaf',
  'leaf_tbs.root_cn': 'as build_root',
  'csr_new.cn': 'as build_leaf',
  'issue_from_csr.root_cn': 'as build_root',
  'issue_tbs_from_csr.root_cn': 'as build_root',
  'assemble_root.sig': "assembly writes the signature it is handed (the contract's note); whether it verifies is chain rule 3's question, asked where the certificate is read",
  'assemble_leaf.sig': 'as assemble_root',
  'profile_error.kind': 'declared, not enforced: anything but "root" is judged as a leaf (the contract\'s note)',
  'is_normal_https.url': 'the question is whether text is a normal https URL, and "" is not: normal false',
  'ip_is_private.ip': 'text that is no address is not private (the contract\'s note): private false',
  'csr_new.endpoint': 'a request carries the address it is given: SPEC §9 has the wallet refuse one not in normal form, and csr_check and issue_from_csr refuse it ("endpoint is not an https URL in normal form")',
  'card_encode.fn': "FN is the sender's own claim (SPEC §3): a card whose FN is empty reads, in the seed and both ports",
  'card_encode.cert': 'a certificate is refused where it is read (CONTRACT §0): card_decode refuses this card, "certificate does not parse: DER truncated"',
  'hpke_seal.info': 'bytes: none are a value',
  'hpke_seal.plaintext': 'bytes: none are a value',
  'export_write.owner_name': 'informative (SPEC §9.2): only key material is refused in it',
  'export_write.tool': 'as owner_name',
  'media_holds_private_key.bytes': 'no bytes hold no key: false',
};

/** The member no function declares, for the undeclared-member case. */
export const UNDECLARED = 'not_a_member';

/** Each function's base: the hand-written case, by id, whose arguments the generated cases vary. */
export const BASES = {
  generate_key: 'generate_key',
  key_from_seed: 'key_from_seed',
  prf_salt: 'prf_salt',
  derive_seed: 'derive_seed for pact/root/1',
  public_key: 'public_key',
  key_info: 'key_info',
  sign: 'sign',
  verify: 'verify a signature the other port made',
  build_root: 'build_root',
  root_tbs: 'root_tbs',
  assemble_root: 'assemble_root',
  build_leaf: 'build_leaf',
  leaf_tbs: 'leaf_tbs',
  assemble_leaf: 'assemble_leaf',
  parse_certificate: 'parse_certificate of a leaf',
  profile_error: 'profile_error of a leaf read as a leaf',
  validate_chain: 'validate_chain against the root and endpoint it really has',
  compare_leaves: 'compare_leaves with itself',
  is_normal_https: 'is_normal_https "https://agent.alina.example/mcp"',
  address_guard: 'address_guard on a contact naming us',
  ip_is_private: 'ip_is_private "10.0.0.1"',
  csr_new: 'csr_new',
  csr_check: 'csr_check',
  issue_from_csr: 'issue_from_csr',
  issue_tbs_from_csr: 'issue_tbs_from_csr',
  signing_request_check: 'signing_request_check: a renewal from a localhost node',
  card_encode: 'card_encode',
  card_decode: 'card_decode of a real card',
  refresh_check: 'refresh_check: the pinned leaf, unchanged',
  suite_for: 'suite_for an Ed25519 key',
  hpke_seal: 'hpke_seal',
  hpke_open: 'hpke_open of what hpke_seal made',
  seal_request: 'seal_request',
  seal_result: 'seal_result of a real result',
  open_result: 'open_result in the leaf form, from a held leaf: the answer that succeeds',
  follow_renewed: 'follow_renewed on the same leaf',
  decide: 'decide on an envelope from a pinned contact',
  decide_chain: 'decide_chain: the pinned leaf',
  vault_seal: 'vault_seal',
  vault_open: 'vault_open of what vault_seal made',
  wallet_issue: 'wallet_issue',
  ledger_check: 'ledger_check: a move, chosen',
  export_read: 'export_read: what export_write wrote',
  export_read_messages: 'export_read_messages: what export_write_messages wrote',
  export_read_end: 'export_read_end: what was written',
  export_write: 'export_write: every formula prefix, quoting and line breaks, sorted rows',
  export_write_messages: 'export_write_messages: in batches, the file names its msg_ids',
  export_manifest: 'export_manifest: finished with the messages',
  export_merge: 'export_merge: a held pin is never replaced',
  book_rows: 'book_rows: a contact with everything, one with the least',
  media_holds_private_key: 'media_holds_private_key: PKCS #8 of an Ed25519 key, in DER',
  limits_rules_check: 'limits_rules_check: a document that can be enforced',
  limits_decide: 'limits_decide: a contact in, fresh',
  limits_buckets: 'limits_buckets: a contact in',
};

/** The members of the hostile object a function declares: what reaches its body. */
export const hostileFor = (m) => Object.fromEntries(Object.entries(HOSTILE).filter(([k]) => k in (m.params.properties ?? {})));

const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);

/** The JSON types a schema admits: some of `string number integer boolean object array null`. */
export function admitted(schema, root) {
  const every = ['string', 'number', 'integer', 'boolean', 'object', 'array', 'null'];
  if (schema === true || schema === undefined) return new Set(every);
  if (schema === false) return new Set();
  if (schema.$ref) return admitted(root.$defs[/^#\/\$defs\/(.+)$/.exec(schema.$ref)[1]], root);
  if (schema.type) return new Set([schema.type].flat());
  if (schema.enum) return new Set(schema.enum.map(typeOf));
  if ('const' in schema) return new Set([typeOf(schema.const)]);
  const alternatives = schema.oneOf ?? schema.anyOf;
  if (alternatives) return new Set(alternatives.flatMap((s) => [...admitted(s, root)]));
  if (schema.allOf) return schema.allOf.map((s) => admitted(s, root)).reduce((a, b) => new Set([...a].filter((t) => b.has(t))));
  return new Set(every);
}

/**
 * A value of the wrong JSON type for a member, or `undefined` where the schema admits every type the
 * candidates have: a number where a string belongs, "yes" for a boolean, "7" for a number, a string
 * where an object or a list belongs, and `{}` where anything but an object does.
 */
export function wrongTypeFor(schema, root) {
  const t = admitted(schema, root);
  const numeric = t.has('number') || t.has('integer');
  if (t.has('string')) return numeric ? (t.has('object') ? undefined : {}) : 7;
  if (t.size === 1 && t.has('boolean')) return 'yes';
  return numeric ? '7' : 'x';
}

/** Whether a member is bytes: `B64url`, or a name the contract gives it (`Serial`, `Spki`, `Seed32`…). */
export function isBytes(schema, root) {
  if (!schema || schema === true || !schema.$ref) return false;
  const name = /^#\/\$defs\/(.+)$/.exec(schema.$ref)[1];
  return name === 'B64url' || isBytes(root.$defs[name], root);
}

/**
 * CONTRACT §0's answer to a member of the wrong type: bytes answer `parse`, `not base64url`, as bytes
 * that will not decode do; any other member answers `bad_request`, naming it — `<name> is required`,
 * or the particular words a function has for it (`first_line is a line number from 1`).
 */
export function wrongTypeAnswer(name, schema, root) {
  if (isBytes(schema, root)) return { error: 'parse', why: 'not base64url' };
  return { error: 'bad_request', why: new RegExp(`\\b${name}\\b`) };
}

const show = (v) => JSON.stringify(v);

/**
 * The bases, from the hand-written `cases`, each asked of both ports through `ask(case) -> [wasm, go]`;
 * `succeeded(answer)` says whether an answer is one that did not refuse. Answers `{ bases, problems }`.
 */
export function pickBases(contract, cases, ask, succeeded) {
  const bases = new Map();
  const problems = [];
  for (const [fn, m] of Object.entries(contract.methods)) {
    if (m.section === 'build') continue;
    const id = BASES[fn];
    if (!id) { problems.push(`${fn} has no base in js/cases/generated.mjs (BASES), so nothing is generated for it`); continue; }
    const c = cases.find((x) => x.id === id);
    if (!c) { problems.push(`js/cases/generated.mjs names ${show(id)} as ${fn}'s base, and no case has that id`); continue; }
    if (c.fn !== fn) { problems.push(`js/cases/generated.mjs names ${show(id)} as ${fn}'s base, and it calls ${c.fn}`); continue; }
    const [wasm, go] = ask(c);
    if (!succeeded(wasm) || !succeeded(go)) { problems.push(`${fn}'s base ${show(id)} does not succeed on both ports, so nothing can be generated from it`); continue; }
    bases.set(fn, c);
  }
  for (const fn of Object.keys(BASES)) if (!(fn in contract.methods)) problems.push(`js/cases/generated.mjs names a base for ${fn}, which the contract does not declare`);
  return { bases, problems };
}

/**
 * The generated cases, `[{ id, fn, args, how, kind, file }]`; `expected`, a Map from id to the answer
 * the contract fixes for it (its members, or a judge: a function of the whole answer, with a `label`);
 * and `problems`, what is wrong with this file's own lists. `bases` is `pickBases`'s; `outside` maps
 * each of KEYED to a value whose key is outside the profile, and without it that shape is not made.
 */
export function generate(contract, bases, outside) {
  const cases = [];
  const expected = new Map();
  const problems = [];
  const judge = (label, f) => Object.assign(f, { label });
  const refused = judge('a refusal', refuses);
  const answered = judge('an answer, not a refusal ("" is a value here: EMPTY_IS_A_VALUE)', (a) => !refuses(a));
  const root = contract.root ?? { $defs: contract.$defs };
  for (const key of Object.keys(EMPTY_IS_A_VALUE)) {
    const [fn, name] = key.split('.');
    const m = contract.methods[fn];
    if (!m?.params.required?.includes(name) || !admitted(m.params.properties[name], root).has('string')) problems.push(`js/cases/generated.mjs's EMPTY_IS_A_VALUE names ${key}, which is not a required member that takes a string`);
  }
  const add = (what, fn, args, how, kind, want) => {
    const id = `generated · ${fn} · ${what}`;
    cases.push({ id, fn, args, how, kind, file: 'generated' });
    if (want) expected.set(id, want);
  };
  for (const [fn, m] of Object.entries(contract.methods)) {
    if (m.section === 'build') continue; // `version` describes the port; its answer cannot agree
    add('{}', fn, {}, '*', 'the empty object');
    const hostile = hostileFor(m);
    if (Object.keys(hostile).length) add('the hostile object', fn, hostile, '*', 'the hostile object');
    const base = bases.get(fn);
    if (!base) continue; // pickBases has said why
    const members = Object.entries(m.params.properties ?? {});
    const required = m.params.required ?? [];
    const { how } = base;
    const without = (name) => Object.fromEntries(Object.entries(base.args).filter(([k]) => k !== name));
    for (const name of required) {
      const want = { error: 'bad_request', why: `${name} is required` };
      add(`${name} absent`, fn, without(name), how, 'a required member absent', want);
      add(`${name} null`, fn, { ...base.args, [name]: null }, how, 'a required member null', want);
      if (admitted(m.params.properties[name], root).has('string')) add(`${name} ""`, fn, { ...base.args, [name]: '' }, how, 'a required string empty', `${fn}.${name}` in EMPTY_IS_A_VALUE ? answered : refused);
    }
    for (const [name, schema] of members) {
      if (required.includes(name)) continue;
      if (admitted(schema, root).has('string')) add(`${name} ""`, fn, { ...base.args, [name]: '' }, how, 'an optional string empty');
      const wrong = wrongTypeFor(schema, root);
      if (wrong !== undefined) add(`${name} ${show(wrong)}`, fn, { ...base.args, [name]: wrong }, how, 'an optional member of the wrong type', wrongTypeAnswer(name, schema, root));
    }
    add('an undeclared member', fn, { ...base.args, [UNDECLARED]: 1 }, how, 'an undeclared member');
    for (const [name, schema] of outside ? members : []) {
      const keyed = keyedOf(schema, root);
      if (!keyed) continue;
      const was = base.args[name];
      const value = keyed.list ? [outside[keyed.type], ...(Array.isArray(was) ? was.slice(1) : [])] : outside[keyed.type];
      add(`${name} holding a key outside the profile`, fn, { ...base.args, [name]: value }, how, 'a key outside the profile');
    }
    for (const a of required) {
      for (const [b, schema] of members) {
        if (b === a) continue;
        const wrong = wrongTypeFor(schema, root);
        if (wrong !== undefined) add(`${a} absent, ${b} ${show(wrong)}`, fn, { ...without(a), [b]: wrong }, how, 'read order');
      }
    }
  }
  return { cases, expected, problems };
}
