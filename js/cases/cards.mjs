// §4 of the contract: cards — encode one, decode one.
import { b64url } from '../../../pact-protocol/vectors/lib/keys.mjs';
import { encodeCard, decodeCard } from '../../../pact-protocol/vectors/lib/card.mjs';
import { signDetached } from '../../../pact-protocol/vectors/lib/hpke.mjs';

export default function cards({ add, expect }, f) {
  const { now, leafDer, card, twinLeaf, shortAki } = f;
  const cardOf = (fn, der) => encodeCard({ fn, cert: Buffer.from(der, 'base64url') });
  add('card_encode', 'card_encode', { fn: 'Alina Rao', cert: leafDer, seal: 'required' });
  add('card_encode with a name outside ASCII', 'card_encode', { fn: 'é'.repeat(80), cert: leafDer, seal: 'required' });
  add('card_encode with a name that straddles the fold', 'card_encode', { fn: 'a'.repeat(70) + 'ü'.repeat(10), cert: leafDer });
  add('card_encode with an emoji name', 'card_encode', { fn: '👋'.repeat(40), cert: leafDer });
  add('card_encode with a seal nobody has', 'card_encode', { fn: 'A', cert: leafDer, seal: 'maybe' });
  add('card_encode of a certificate that is not one', 'card_encode', { fn: 'A', cert: b64url(new Uint8Array(4)) });
  // A certificate is bytes (CONTRACT §0): one that is not a string does not decode, which the contract
  // did not declare for this function until both ports were asked.
  add('card_encode with a certificate that is not a string', 'card_encode', { fn: 'A', cert: 7 });
  expect('card_encode with a certificate that is not a string', { error: 'parse', why: 'not base64url' });
  // `extra` is a list of strings or it is refused (T21): the core dropped an item that was not a
  // string — a number, or null — and wrote the card without it, where the Go port refused the call.
  for (const [what, extra] of [['a number', ['X-A:1', 7]], ['null', [null]]]) {
    add(`card_encode with an extra line that is ${what}`, 'card_encode', { fn: 'A', cert: leafDer, extra });
    expect(`card_encode with an extra line that is ${what}`, { error: 'bad_request', why: 'extra is required' });
  }
  add('card_decode of a real card', 'card_decode', { vcard: card, now });
  add('card_decode of an empty card', 'card_decode', { vcard: 'BEGIN:VCARD\r\nEND:VCARD\r\n', now });
  add('card_decode of nothing at all', 'card_decode', { vcard: '', now });
  add('card_decode of a 1.x card', 'card_decode', { vcard: 'BEGIN:VCARD\r\nVERSION:4.0\r\nX-PACT-VERSION:1\r\nEND:VCARD\r\n', now });
  add('card_decode of a card with two certificates', 'card_decode', { vcard: card.replace('END:VCARD', `X-PACT-CERT:${leafDer}\r\nEND:VCARD`), now });
  add('card_decode of a card whose certificate is not one', 'card_decode', { vcard: 'BEGIN:VCARD\r\nVERSION:4.0\r\nX-PACT-VERSION:2\r\nX-PACT-CERT:AAAA\r\nEND:VCARD\r\n', now });
  add('card_decode after the leaf expired', 'card_decode', { vcard: card, now: '2028-01-01T00:00:00Z' });
  // SPEC 2.1.1's high-S rule reaches a card: the leaf on it is Bharat's, whose ECDSA signature is the high twin.
  add('card_decode of a card carrying that leaf', 'card_decode', { vcard: cardOf('Bharat Mehta', twinLeaf), now });

  // Every member that is absent rather than empty.
  add('card_encode with nothing to work from', 'card_encode', {});
  add('card_decode with nothing to work from', 'card_decode', { now });
  // A member that is ABSENT is `<name> is required`, whatever its type.
  add('card_decode with no now', 'card_decode', { vcard: card });

  add('card_decode of a card whose leaf names its issuer in three bytes', 'card_decode', { vcard: cardOf('Alina Rao', shortAki), now });
  // A line break in any value is a property of the attacker's choosing.
  for (const [what, args] of [
    ['a name with CR LF', { fn: 'x\r\nX-PACT-SEAL:none', cert: leafDer, seal: 'required' }],
    ['a name with a bare LF', { fn: 'x\nX-PACT-SEAL:none', cert: leafDer }],
    ['a name with a NUL', { fn: 'x\u0000y', cert: leafDer }],
    ['a seal with CR LF', { fn: 'x', cert: leafDer, seal: 'required\r\nX-PACT-VERSION:3' }],
    ['an extra line with CR LF', { fn: 'x', cert: leafDer, extra: ['X-A:1\r\nX-PACT-SEAL:none'] }],
    ['a name with a comma and a semicolon', { fn: 'Rao, Alina; of Pune', cert: leafDer, seal: 'required' }],
  ]) add(`card_encode: ${what}`, 'card_encode', args);

  // What the seed's `decodeCard` makes of a card, as card_decode answers it: its refusal, or the
  // certificate, endpoint and root it read.
  const seedDecodes = (vcard) => {
    const c = decodeCard(vcard);
    return c.error ? { error: c.error, why: c.why } : { cert: b64url(c.cert), endpoint: c.endpoint, root: c.root };
  };
  // A card whose certificate carries a key outside the profile is refused at intake, the key named
  // (R12, T2): the Go port read such a certificate and took the card.
  for (const [kind, { oid }] of Object.entries(f.foreign)) {
    const vcard = encodeCard({ fn: 'Alina Rao', cert: Buffer.from(f.foreignLeaf(kind), 'base64url'), seal: 'required' });
    add(`card_decode of a card whose leaf holds a key outside the profile: ${kind}`, 'card_decode', { vcard, now });
    // Held to the seed's reading (seedDecodes), which took all four cards on pact-protocol main until
    // PR #10 (cluster G's seed half); there, and in both ports, the refusal names the key's OID.
    expect(`card_decode of a card whose leaf holds a key outside the profile: ${kind}`, seedDecodes(vcard));
  }

  // ── H: a card's certificate is bytes this port did not write, and an empty version is none ────────
  //
  // The core read X-PACT-CERT strictly, and the Go port and the seed's card.mjs as Buffer.from does,
  // skipping what they did not know: a stray character in the certificate was a card to two of them and
  // a refusal to the core, which the cloud runs (R24, T11, C7). An empty X-PACT-VERSION was `version not
  // implemented` to the core and `no X-PACT-VERSION` to the other two (C9). One reading now, in the
  // ports and the seed: the certificate as every argument's bytes are read (CONTRACT §0,
  // js/b64url-arguments.json), and an empty version as none. Hand-written, one line, so every value
  // reaches the reader as it is written here.
  const withCert = (value) => `BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Alina Rao\r\nX-PACT-VERSION:2\r\nX-PACT-CERT:${value}\r\nX-PACT-SEAL:required\r\nEND:VCARD\r\n`;
  const at8 = (c) => leafDer.slice(0, 8) + c + leafDer.slice(8);
  // A spare bit needs a certificate whose length is not a multiple of three: the first of these that
  // has one, with the lowest bit of its last character set.
  const A64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const spared = [leafDer, f.rootDer, twinLeaf, f.p256RootDer].find((d) => d.length % 4 !== 0);
  if (!spared) throw new Error('cards.mjs: no certificate fixture has spare bits to set');
  const withSpareBit = spared.slice(0, -1) + A64[A64.indexOf(spared.at(-1)) | 1];
  const notB64 = { error: 'bad_request', why: 'certificate does not parse: not base64url' };
  const read = { cert: leafDer, endpoint: f.ENDPOINT, root: f.rootFp };
  // Each is held to the seed's reading of the same card (seedDecodes): the Go port and the seed's
  // card.mjs read a stray character as nothing on pact-protocol main, which took the card, until PR #10
  // (cluster H's seed half). `want` is what that reading is, as both ports answer it.
  for (const [what, value, want] of [
    ['a stray character', at8('!'), notB64],
    ['a full stop', at8('.'), notB64],
    ['padding inside', at8('='), notB64],
    ['a no-break space', at8('\u00a0'), notB64],
    ['a vertical tab', at8('\u000b'), notB64],
    ['a tab', at8('\t'), notB64],
    ['nothing but !!!', '!!!', notB64],
    ['a spare bit set', withSpareBit, notB64],
    // The controls, which must read: the certificate as written, padded, and in the standard alphabet.
    ['nothing wrong with it', leafDer, read],
    ['padding at the end', leafDer + '='.repeat((4 - (leafDer.length % 4)) % 4), read],
    ['the standard alphabet', leafDer.replace(/-/g, '+').replace(/_/g, '/'), read],
    ['a space', at8(' '), notB64],
  ]) {
    const seed = seedDecodes(withCert(value));
    add(`card_decode of a card whose certificate has ${what}`, 'card_decode', { vcard: withCert(value), now });
    expect(`card_decode of a card whose certificate has ${what}`, JSON.stringify(seed) === JSON.stringify(want) ? want : seed);
  }
  add('card_decode of a card with an empty X-PACT-VERSION', 'card_decode', { vcard: card.replace('X-PACT-VERSION:2', 'X-PACT-VERSION:'), now });
  expect('card_decode of a card with an empty X-PACT-VERSION', { error: 'bad_request', why: 'no X-PACT-VERSION' });
  expect('card_decode of a 1.x card', { error: 'bad_request', why: 'version not implemented' });

  // ── refresh_check: a peer's answer to get_card, judged against the host's pin (CW-08) ──────────────
  //
  // Both hosts made this decision themselves, in different orders and words; the node verified the
  // card's signature with its own non-strict verifier. Every refusal in the order the contract's note
  // lists them, the two answers that succeed (the leaf unchanged, and renewed), and every fault of the
  // host's own arguments. The card and its signature are made by the seed; the chain is the cast's.
  const { rootDer, rootFp, ENDPOINT, hostKey, hostSpki, olderLeaf, alinaLeaf, p256Leaf, p256RootDer } = f;
  const sign = (text) => b64url(signDetached(hostKey.priv, Buffer.from(text, 'utf8')));
  const signedCard = (der) => { const c = cardOf('Alina Rao', der); return { card: c, card_sig: sign(c) }; };
  const pin = (leaf = leafDer) => ({ root: rootFp, endpoint: ENDPOINT, leaf });
  const refresh = (answer, o = {}) => ({ pin: pin(), answer, now, ...o });
  const good = { ...signedCard(leafDer), chain: [leafDer, rootDer] };
  add('refresh_check: the pinned leaf, unchanged', 'refresh_check', refresh(good));
  expect('refresh_check: the pinned leaf, unchanged', { ok: true, fn: 'Alina Rao', renewed: null, root_cert: rootDer });
  add('refresh_check: a newer leaf than the pinned one', 'refresh_check', refresh(good, { pin: pin(olderLeaf) }));
  expect('refresh_check: a newer leaf than the pinned one', { ok: true, renewed: { leaf: leafDer, spki: hostSpki } });
  const pinnedNewer = alinaLeaf({ notBefore: new Date('2026-09-10T00:00:00Z'), label: 'parity/refresh/newer' });
  const sameDay = alinaLeaf({ label: 'parity/refresh/same-day' });
  const moved = alinaLeaf({ endpoint: 'https://alina.moved.example/mcp', label: 'parity/refresh/moved' });
  const bharatLeaf = p256Leaf();
  for (const [what, args, why] of [
    ['an answer that is not an object', refresh('x'), 'the answer to get_card carries no signed card'],
    ['an answer with no card', refresh({ ...good, card: undefined }), 'the answer to get_card carries no signed card'],
    ['an answer whose card_sig is empty', refresh({ ...good, card_sig: '' }), 'the answer to get_card carries no signed card'],
    ['an answer with no chain', refresh({ ...good, chain: undefined }), 'the answer carries 0 certificate(s); get_card answers with the chain, leaf then root (§6.1)'],
    ['an answer whose chain is the leaf alone', refresh({ ...good, chain: [leafDer] }), 'the answer carries 1 certificate(s); get_card answers with the chain, leaf then root (§6.1)'],
    ['an answer whose chain holds a number', refresh({ ...good, chain: [leafDer, 5] }), 'the answer carries 2 certificate(s); get_card answers with the chain, leaf then root (§6.1)'],
    ['an answer whose chain member is not base64url', refresh({ ...good, chain: ['!!!', rootDer] }), 'a chain member is not base64url'],
    ['a card that does not decode', refresh({ ...good, card: 'BEGIN:VCARD\r\nEND:VCARD\r\n' }), 'the card does not decode: no X-PACT-VERSION'],
    ['a card of another root', refresh({ ...signedCard(bharatLeaf), chain: [bharatLeaf, p256RootDer] }), 'the card names another root, not the pinned one'],
    ['a chain to another root', refresh({ ...good, chain: [bharatLeaf, p256RootDer] }), 'the chain it answered with fails rule 2: root is not the one expected'],
    ['a chain at another endpoint', refresh({ ...signedCard(moved), chain: [moved, rootDer] }), 'the chain it answered with fails rule 5: endpoint differs from the one in question'],
    // A pin's endpoint is compared as it is, "" too: a typed Go ChainOpts reads "" as not given.
    ['a pin whose endpoint is empty', refresh(good, { pin: { ...pin(), endpoint: '' } }), 'the chain it answered with fails rule 5: endpoint differs from the one in question'],
    ['a leaf older than the pinned one', refresh(good, { pin: pin(pinnedNewer) }), 'the leaf it answered with is superseded by the pinned one (§14.3)'],
    ['a different leaf of the pinned one\'s date', refresh(good, { pin: pin(sameDay) }), 'two different leaves claim the same notBefore (§14.3)'],
    ['a card that carries another leaf than the chain', refresh({ ...signedCard(olderLeaf), chain: [leafDer, rootDer] }), 'the card\'s certificate is not the leaf the chain proved'],
    ['a card_sig that is not base64url', refresh({ ...good, card_sig: '!!!' }), 'the card signature is not base64url'],
    ['a card_sig over other text', refresh({ ...good, card_sig: sign('other text') }), 'the card signature does not verify under the proven leaf key'],
  ]) {
    add(`refresh_check: ${what}`, 'refresh_check', args);
    expect(`refresh_check: ${what}`, { ok: false, why });
  }
  for (const [what, args, want] of [
    ['no pin', { answer: good, now }, { error: 'bad_request', why: 'pin is required' }],
    ['a pin that is not an object', { pin: 'x', answer: good, now }, { error: 'bad_request', why: 'pin is required' }],
    ['a pin with no root', { pin: { endpoint: ENDPOINT, leaf: leafDer }, answer: good, now }, { error: 'bad_request', why: 'pin.root is required' }],
    ['a pin with no endpoint', { pin: { root: rootFp, leaf: leafDer }, answer: good, now }, { error: 'bad_request', why: 'pin.endpoint is required' }],
    ['a pin with no leaf', { pin: { root: rootFp, endpoint: ENDPOINT }, answer: good, now }, { error: 'bad_request', why: 'pin.leaf is required' }],
    ['a pinned leaf that is a number', { pin: pin(7), answer: good, now }, { error: 'parse', why: 'not base64url' }],
    ['a pinned leaf that is not a certificate', { pin: pin('AAAA'), answer: good, now }, { error: 'parse' }],
    // The pin's leaf is read before the answer, in its reader's class: a key outside the profile is
    // `unsupported`, whatever the peer sent.
    ['a pinned leaf holding a key outside the profile', { pin: pin(f.foreignLeaf('Ed25519 with a NULL')), answer: good, now }, { error: 'unsupported' }],
    // The pin's root is a Fingerprint (the contract's type for it): one that is not is the host's
    // fault, an error of the call read with the pin, before the answer. Both ports compared it with the
    // card's and answered `ok: false`, `the card names another root`, blaming the peer (a lead of the
    // port-parity verification, 2026-09-30).
    ['a pin whose root is not a fingerprint', { pin: { ...pin(), root: 'abc' }, answer: good, now }, { error: 'bad_request', why: 'pin.root is not a fingerprint' }],
    ['a pin whose root is empty', { pin: { ...pin(), root: '' }, answer: good, now }, { error: 'bad_request', why: 'pin.root is not a fingerprint' }],
    ['a pin whose root is a character short', { pin: { ...pin(), root: rootFp.slice(0, -1) }, answer: good, now }, { error: 'bad_request', why: 'pin.root is not a fingerprint' }],
    ['a pin whose root is not a fingerprint and no endpoint', { pin: { root: 'abc', leaf: leafDer }, answer: good, now }, { error: 'bad_request', why: 'pin.root is not a fingerprint' }],
    ['a pin whose root is not a fingerprint and no answer', { pin: { ...pin(), root: 'abc' }, now }, { error: 'bad_request', why: 'pin.root is not a fingerprint' }],
    ['no answer', { pin: pin(), now }, { error: 'bad_request', why: 'answer is required' }],
    ['no now', { pin: pin(), answer: good }, { error: 'bad_request', why: 'now is required' }],
  ]) {
    add(`refresh_check with ${what}`, 'refresh_check', args);
    expect(`refresh_check with ${what}`, want);
  }
}
