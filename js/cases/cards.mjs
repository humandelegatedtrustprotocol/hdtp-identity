// §4 of the contract: cards — encode one, decode one.
import { b64url } from '../../../pact-protocol/vectors/lib/keys.mjs';
import { encodeCard } from '../../../pact-protocol/vectors/lib/card.mjs';

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

  // A card whose certificate carries a key outside the profile is refused at intake, the key named
  // (R12, T2): the Go port read such a certificate and took the card.
  for (const [kind, { oid }] of Object.entries(f.foreign)) {
    const vcard = encodeCard({ fn: 'Alina Rao', cert: Buffer.from(f.foreignLeaf(kind), 'base64url'), seal: 'required' });
    add(`card_decode of a card whose leaf holds a key outside the profile: ${kind}`, 'card_decode', { vcard, now });
    expect(`card_decode of a card whose leaf holds a key outside the profile: ${kind}`, { error: 'bad_request', why: `certificate does not parse: unsupported key type ${oid}` });
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
    add(`card_decode of a card whose certificate has ${what}`, 'card_decode', { vcard: withCert(value), now });
    expect(`card_decode of a card whose certificate has ${what}`, want);
  }
  add('card_decode of a card with an empty X-PACT-VERSION', 'card_decode', { vcard: card.replace('X-PACT-VERSION:2', 'X-PACT-VERSION:'), now });
  expect('card_decode of a card with an empty X-PACT-VERSION', { error: 'bad_request', why: 'no X-PACT-VERSION' });
  expect('card_decode of a 1.x card', { error: 'bad_request', why: 'version not implemented' });
}
