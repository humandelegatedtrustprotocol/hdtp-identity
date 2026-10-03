// The cast every suite here shares: the people, their keys, their addresses and the clock the
// offline suites stand at. Built from labelled seeds by the SEED library (hdtp-spec/vectors/lib),
// never by the port a suite is testing — a fixture the port under test made can only ever agree
// with that port.
//
//   alina    an Ed25519 root and her host, at agent.alina.example (and a second and a new host)
//   bharat   a P-256 root and a P-256 host, at agent.bharat.example
//   mallory  an Ed25519 root and host of her own, who claims whatever she can
//   stranger(now)  a Mallory nobody has met: fresh random keys every call, for the LIVE battery,
//            whose control leaves her pending on the target (a fixed Mallory is a contact on the
//            second run)
//
// The labels are the ones parity.mjs has always used for Alina and for the P-256 key, so every answer
// its cases compare, and every byte PROOFS.md lists, is what it was before this module existed.
import { randomBytes } from 'node:crypto';
import { seed, ed25519FromSeed, p256FromSeed } from '../../hdtp-spec/vectors/lib/keys.mjs';
import { buildRoot, buildLeaf } from '../../hdtp-spec/vectors/lib/x509.mjs';

/** The instant the offline suites stand at, and the day their certificates begin and end. */
export const CLOCK = '2026-09-15T12:00:00Z';
export const BORN = new Date('2026-09-01T00:00:00Z');
export const DIES = new Date('2027-09-01T00:00:00Z');

export const H = 3_600_000, D = 86_400_000;

export const ENDPOINTS = {
  alina: 'https://agent.alina.example/mcp',
  alinaMoved: 'https://alina.host.example/alina/mcp',
  bharat: 'https://agent.bharat.example/mcp',
  mallory: 'https://mallory.example/mcp',
};

export const alina = {
  cn: 'Alina Rao',
  root: ed25519FromSeed(seed('parity/root')),
  host: ed25519FromSeed(seed('parity/host')),
  host2: ed25519FromSeed(seed('cast/alina/host/2')),
  hostNew: ed25519FromSeed(seed('cast/alina/host/new')),
  endpoint: ENDPOINTS.alina,
};

export const bharat = {
  cn: 'Bharat Mehta',
  root: p256FromSeed(seed('parity/p256')),
  host: p256FromSeed(seed('cast/bharat/host')),
  endpoint: ENDPOINTS.bharat,
};

export const mallory = {
  cn: 'Alina Rao', // the display name she borrows; her root is her own
  root: ed25519FromSeed(seed('cast/mallory/root')),
  host: ed25519FromSeed(seed('cast/mallory/host')),
  endpoint: ENDPOINTS.mallory,
};

/** A person's self-signed root certificate (DER), born on BORN unless told otherwise. */
export const rootOf = (person, o = {}) =>
  buildRoot({ cn: o.cn ?? person.cn, key: person.root, notBefore: o.notBefore ?? BORN, label: o.label ?? `cast/${person.cn}/root`, ...o.extra });

/** A leaf for `host` under a person's root (DER), BORN to DIES at the person's endpoint unless told otherwise. */
export const leafOf = (person, o = {}) =>
  buildLeaf({
    cn: person.cn, rootCn: person.cn, root: person.root, hostKey: o.host ?? person.host, endpoint: o.endpoint ?? person.endpoint,
    notBefore: o.notBefore ?? BORN, notAfter: o.notAfter ?? DIES, label: o.label ?? `cast/${person.cn}/leaf`, ...o.extra,
  });

/**
 * A Mallory nobody has met, for a live run at `now` (milliseconds): fresh random keys, a root born a
 * day ago and a leaf valid from an hour ago for a year.
 */
export function stranger(now) {
  const root = ed25519FromSeed(randomBytes(32)), host = ed25519FromSeed(randomBytes(32));
  const person = { cn: 'Mallory', root, host, endpoint: ENDPOINTS.mallory };
  return {
    ...person,
    ROOT: rootOf(person, { notBefore: new Date(now - D), label: 'live/root_m' }),
    LEAF: leafOf(person, { notBefore: new Date(now - H), notAfter: new Date(now + 365 * D), label: 'live/leaf_m' }),
  };
}
