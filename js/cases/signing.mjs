// §3.1 of the contract: signing requests — what a web wallet decides about a host's request before a
// person sees it. One request that must pass (the control, compared whole), and a refusal per rule.
import { b64url } from '../../../pact-protocol/vectors/lib/keys.mjs';

export default function signing({ add, expect }, f) {
  const { now, csr, rootCsr, rootFp, rootDer, rootSpki, leafDer, p256RootDer } = f;
  const at = (seconds) => new Date(Date.parse(now) + seconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const ORIGIN = 'http://localhost:8080';
  const good = {
    csr,
    purpose: 'renew',
    expect_root: rootFp,
    root_cert: rootDer,
    redirect: `${ORIGIN}/wallet/return`,
    state: b64url(new Uint8Array(32).fill(7)),
    recipient: 'Alina\'s node on her laptop',
    valid_days: '365',
    expires: at(300),
  };
  const ask = (over = {}, { origin = ORIGIN, time = now, roots } = {}) => {
    const request = { ...good, ...over };
    for (const k of Object.keys(request)) if (request[k] === undefined) delete request[k];
    return { request, origin, now: time, ...(roots ? { root_spkis: roots } : {}) };
  };
  const refused = (why) => ({ ok: false, why });

  // The controls: each must get through.
  add('signing_request_check: a renewal from a localhost node', 'signing_request_check', ask());
  expect('signing_request_check: a renewal from a localhost node', { ok: true, valid_days: 365, purpose: 'renew' });
  add('signing_request_check: a move from an https host, without root_cert', 'signing_request_check', ask({ purpose: 'move', root_cert: undefined, redirect: 'https://node.alina.example/wallet/return?x=1' }, { origin: 'https://node.alina.example' }));
  expect('signing_request_check: a move from an https host, without root_cert', { ok: true });
  for (const [what, redirect, origin] of [
    ['127.0.0.2 over http', 'http://127.0.0.2:9000/r', 'http://127.0.0.2:9000'],
    ['[::1] over http', 'http://[::1]:8080/r', 'http://[::1]:8080'],
    ['an https default port written out', 'https://node.alina.example:443/r', 'https://node.alina.example'],
    ['an http default port written out', 'http://localhost:80/r', 'http://localhost'],
    ['no path at all', 'http://localhost:8080', 'http://localhost:8080'],
  ]) {
    add(`signing_request_check: a redirect to ${what}`, 'signing_request_check', ask({ redirect }, { origin }));
    expect(`signing_request_check: a redirect to ${what}`, { ok: true });
  }
  add('signing_request_check: expiring exactly ten minutes ahead', 'signing_request_check', ask({ expires: at(600) }));
  expect('signing_request_check: expiring exactly ten minutes ahead', { ok: true });
  add('signing_request_check: 398 days, and a 200-character recipient', 'signing_request_check', ask({ valid_days: '398', recipient: 'é'.repeat(200) }));
  expect('signing_request_check: 398 days, and a 200-character recipient', { ok: true });

  // One refusal per rule, each with the words both ports must use.
  const rules = [
    ['a member a request does not carry', ask({ note: 'hello' }), 'a signing request does not carry note'],
    ['valid_days as a number', ask({ valid_days: 365 }), 'valid_days is a string, as a form carries it'],
    ['a csr over its bound', ask({ csr: 'A'.repeat(4097) }), 'csr is longer than 4096'],
    ['a redirect over its bound', ask({ redirect: `${ORIGIN}/${'r'.repeat(2048)}` }), 'redirect is longer than 2048'],
    ['a recipient of 201 characters', ask({ recipient: 'é'.repeat(201) }), 'recipient is longer than 200'],
    ['an empty recipient', ask({ recipient: '' }), 'recipient is required'],
    ['no origin', ask({}, { origin: '' }), 'the request has no origin: a wallet answers only the origin that asked'],
    ['an origin of null', ask({}, { origin: 'null' }), 'the request has no origin: a wallet answers only the origin that asked'],
    ['an origin that is not the redirect\'s', ask({}, { origin: 'http://localhost:8081' }), 'the redirect\'s origin is not the origin that asked'],
    ['an origin written with its default port', ask({ redirect: 'https://node.alina.example/r' }, { origin: 'https://node.alina.example:443' }), 'the redirect\'s origin is not the origin that asked'],
    ['a redirect over http to a public host', ask({ redirect: 'http://node.alina.example/r' }, { origin: 'http://node.alina.example' }), 'the redirect is not https, or http to a loopback host'],
    ['a redirect over http to a private address', ask({ redirect: 'http://192.168.1.10/r' }, { origin: 'http://192.168.1.10' }), 'the redirect is not https, or http to a loopback host'],
    ['a redirect over http to 127.1', ask({ redirect: 'http://127.1/r' }, { origin: 'http://127.1' }), 'the redirect is not https, or http to a loopback host'],
    ['a redirect over http to 127.000.0.1', ask({ redirect: 'http://127.000.0.1/r' }, { origin: 'http://127.000.0.1' }), 'the redirect is not https, or http to a loopback host'],
    ['a redirect over http to [::2]', ask({ redirect: 'http://[::2]/r' }, { origin: 'http://[::2]' }), 'the redirect is not https, or http to a loopback host'],
    ['a redirect over http to a name under localhost', ask({ redirect: 'http://evil.localhost/r' }, { origin: 'http://evil.localhost' }), 'the redirect is not https, or http to a loopback host'],
    ['a javascript: redirect', ask({ redirect: 'javascript:alert(1)' }), 'the redirect is not https, or http to a loopback host'],
    ['a relative redirect', ask({ redirect: '/wallet/return' }), 'the redirect is not https, or http to a loopback host'],
    ['a redirect with a fragment', ask({ redirect: `${ORIGIN}/r#chain=x` }), 'the redirect carries a fragment'],
    ['a redirect with userinfo', ask({ redirect: 'http://me@localhost:8080/r' }), 'the redirect carries userinfo'],
    ['a redirect with a space', ask({ redirect: `${ORIGIN}/a b` }), 'the redirect is not an absolute URL'],
    ['a redirect with a backslash', ask({ redirect: 'http://localhost:8080\\@evil.example/' }), 'the redirect is not an absolute URL'],
    ['a redirect whose host is upper case', ask({ redirect: 'http://LOCALHOST:8080/r' }, { origin: 'http://LOCALHOST:8080' }), 'the redirect\'s host is not in normal form'],
    ['a redirect with port 0', ask({ redirect: 'http://localhost:0/r' }, { origin: 'http://localhost:0' }), 'the redirect\'s port is not in normal form'],
    ['a redirect with a port with a leading zero', ask({ redirect: 'http://localhost:08080/r' }), 'the redirect\'s port is not in normal form'],
    ['a redirect with port 65536', ask({ redirect: 'http://localhost:65536/r' }), 'the redirect\'s port is not in normal form'],
    ['an expired request', ask({ expires: at(-1) }), 'the request has expired'],
    ['a request expiring now', ask({ expires: now }), 'the request has expired'],
    ['a request expiring more than ten minutes ahead', ask({ expires: at(601) }), 'the request expires more than ten minutes ahead'],
    ['an expiry with an offset', ask({ expires: '2026-09-15T14:05:00+02:00' }), 'expires is not an RFC 3339 instant'],
    ['an expiry that does not read', ask({ expires: 'soon' }), 'expires is not an RFC 3339 instant'],
    // One grammar for every instant (SPEC 2.2.2): upper-case T and Z, no offset, `.` alone before a fraction.
    ['an expiry with a lower-case z', ask({ expires: at(300).replace(/Z$/, 'z') }), 'expires is not an RFC 3339 instant'],
    ['an expiry with a comma before its fraction', ask({ expires: at(300).replace(/Z$/, ',5Z') }), 'expires is not an RFC 3339 instant'],
    ['an expiry with a lower-case t', ask({ expires: at(300).replace('T', 't') }), 'expires is not an RFC 3339 instant'],
    // The redirect's host in lower-case normal form (CONTRACT §3.1): no upper-case IPv6 hex, no empty label.
    ['a redirect to upper-case IPv6 hex', ask({ redirect: 'https://[2001:DB8::1]/r' }, { origin: 'https://[2001:DB8::1]' }), 'the redirect\'s host is not in normal form'],
    ['a redirect whose host has an empty label', ask({ redirect: 'https://node..alina.example/r' }, { origin: 'https://node..alina.example' }), 'the redirect\'s host is not in normal form'],
    ['a redirect whose host begins with a dot', ask({ redirect: 'https://.alina.example/r' }, { origin: 'https://.alina.example' }), 'the redirect\'s host is not in normal form'],
    ['a redirect whose host ends with a dot', ask({ redirect: 'https://alina.example./r' }, { origin: 'https://alina.example.' }), 'the redirect\'s host is not in normal form'],
    ['a signup', ask({ purpose: 'signup' }), 'purpose is renew or move'],
    ['valid_days of 0', ask({ valid_days: '0' }), 'valid_days is a whole number of days from 1 to 398'],
    ['valid_days of 399', ask({ valid_days: '399' }), 'valid_days is a whole number of days from 1 to 398'],
    ['valid_days with a leading zero', ask({ valid_days: '030' }), 'valid_days is a whole number of days from 1 to 398'],
    ['valid_days of -1', ask({ valid_days: '-1' }), 'valid_days is a whole number of days from 1 to 398'],
    ['a state of 31 bytes', ask({ state: b64url(new Uint8Array(31).fill(7)) }), 'state is 32 bytes, base64url'],
    ['a state outside base64url', ask({ state: '+'.repeat(43) }), 'state is 32 bytes, base64url'],
    ['an expect_root that is no fingerprint', ask({ expect_root: 'alina' }), 'expect_root is not a root fingerprint'],
    ['a root_cert outside base64url', ask({ root_cert: 'MII/' }), 'root_cert is not base64url'],
    ['a root_cert that is no certificate', ask({ root_cert: b64url(new Uint8Array([48, 3, 2, 1, 1])) }), 'root_cert is not a certificate'],
    ['a root_cert that is a leaf', ask({ root_cert: leafDer }), 'root_cert is not a root certificate'],
    ['another identity\'s root_cert', ask({ root_cert: p256RootDer }), 'root_cert is not the root expect_root names'],
    ['a csr outside base64url', ask({ csr: 'MII/' }), 'csr is not base64url'],
    ['a csr carrying the root\'s own key', ask({ csr: rootCsr }, { roots: [rootSpki] }), 'the request\'s key is a root'],
  ];
  for (const r of ['csr', 'purpose', 'expect_root', 'redirect', 'state', 'valid_days', 'expires']) rules.push([`no ${r}`, ask({ [r]: undefined }), `${r} is required`]);
  for (const [what, args, why] of rules) {
    add(`signing_request_check: ${what}`, 'signing_request_check', args);
    expect(`signing_request_check: ${what}`, refused(why));
  }
  // A csr that is base64url and not a request: csr_check's own refusal, whatever its words.
  add('signing_request_check: a csr that is not a request', 'signing_request_check', ask({ csr: b64url(new Uint8Array([48, 0])) }));
  // The arguments themselves.
  add('signing_request_check with no request', 'signing_request_check', { origin: ORIGIN, now });
  add('signing_request_check with a request that is a string', 'signing_request_check', { request: 'csr=…', origin: ORIGIN, now });
  add('signing_request_check with no origin', 'signing_request_check', { request: good, now });
  add('signing_request_check with no now', 'signing_request_check', { request: good, origin: ORIGIN });
  add('signing_request_check with root_spkis that do not read', 'signing_request_check', { ...ask(), root_spkis: ['!!!'] });
  add('signing_request_check with nothing to work from', 'signing_request_check', {});
}
