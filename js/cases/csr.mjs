// §3 of the contract: certificate signing requests — make one, check one, issue from one.
import { b64url } from '../../../pact-protocol/vectors/lib/keys.mjs';
import { read as derRead, children as derChildren, tlv as derTlv, seq as derSeq, set as derSet, bitstr as derBitstr, int as derInt } from '../../../pact-protocol/vectors/lib/der.mjs';
import { signDetached } from '../../../pact-protocol/vectors/lib/hpke.mjs';

export default function csr({ add, expect }, f) {
  const { now, ENDPOINT, hostKey, rootDer, rootPkcs8, rootSpki, hostPkcs8, rootKeyId, csr: request, rootCsr, x25519SpkiDer } = f;
  add('csr_new with no key', 'csr_new', { cn: 'A', endpoint: ENDPOINT });
  add('csr_new naming a local address', 'csr_new', { cn: 'A', host_pkcs8: hostPkcs8, endpoint: 'https://127.0.0.1:8443/mcp' });
  add('csr_new naming nothing', 'csr_new', { cn: 'A', host_pkcs8: hostPkcs8, endpoint: '' });
  add('csr_new with a dns_name that is not the host', 'csr_new', { cn: 'A', host_pkcs8: hostPkcs8, endpoint: ENDPOINT, dns_name: 'elsewhere.example' });
  add('csr_check of bytes that are not a request', 'csr_check', { der: b64url(new Uint8Array([1, 2, 3])) });
  add('csr_check of a certificate', 'csr_check', { der: rootDer });
  add('csr_check with no request', 'csr_check', {});
  add('the root-key refusal', 'csr_check', { der: rootCsr, root_spkis: [rootSpki] });
  add('the root-key refusal with a list that will not read', 'csr_check', { der: rootCsr, root_spkis: ['!!!'] });
  add('the root-key refusal with a list of numbers', 'csr_check', { der: rootCsr, root_spkis: [42] });
  add('the root-key refusal with a list of one empty string', 'csr_check', { der: rootCsr, root_spkis: [''] });
  add('the root-key refusal with no list', 'csr_check', { der: rootCsr });
  add('issue_from_csr with an explicit zero validity', 'issue_from_csr', { csr: request, root_cn: 'A', root_pkcs8: rootPkcs8, now, valid_days: 0 });
  add('issue_from_csr over 398 days', 'issue_from_csr', { csr: request, root_cn: 'A', root_pkcs8: rootPkcs8, now, valid_days: 400 });
  add('issue_from_csr with a negative validity', 'issue_from_csr', { csr: request, root_cn: 'A', root_pkcs8: rootPkcs8, now, valid_days: -1 });
  add('issue_from_csr of a request that is not one', 'issue_from_csr', { csr: b64url(new Uint8Array(8)), root_cn: 'A', root_pkcs8: rootPkcs8, now });
  // A request whose DER is one short SEQUENCE: csr_check's own `parse`, kept or not (TC-1, R27).
  const truncated = b64url(new Uint8Array([0x30, 0x03, 0x02, 0x01]));
  add('issue_from_csr of a request that is a truncated SEQUENCE', 'issue_from_csr', { csr: truncated, root_cn: 'A', root_pkcs8: rootPkcs8, now });
  add('issue_tbs_from_csr of a request that is a truncated SEQUENCE', 'issue_tbs_from_csr', { csr: truncated, root_cn: 'A', root_spki: rootSpki, now });
  add('issue_from_csr refusing the root\'s own key', 'issue_from_csr', { csr: rootCsr, root_cn: 'A', root_pkcs8: rootPkcs8, root_spkis: [rootSpki], now });
  add('issue_tbs_from_csr', 'issue_tbs_from_csr', { csr: request, root_cn: 'A', root_spki: rootSpki, now }, (a) => (a?.tbs ? { ...a, tbs: '<a tbs, whose serial is random>' } : a));
  add('issue_from_csr', 'issue_from_csr', { csr: request, root_cn: 'Alina Rao', root_pkcs8: rootPkcs8, now }, f.withoutSerial('der'));
  // A request made and checked with every member given: the calls the generated cases vary (BASES).
  add('csr_new', 'csr_new', { cn: 'Alina Rao', host_pkcs8: hostPkcs8, endpoint: ENDPOINT, dns_name: 'agent.alina.example' });
  add('csr_check', 'csr_check', { der: request, root_spkis: [rootSpki] });

  // §9's root-key refusal reaches a root given as its key id, which is the form a wallet holding
  // fingerprints has. One port matched only the SubjectPublicKeyInfo, so the other refusal never fired.
  add('the root-key refusal against a key id', 'csr_check', { der: rootCsr, root_spkis: [rootKeyId] });
  add('issue_from_csr refusing a root given as a key id', 'issue_from_csr', { csr: rootCsr, root_cn: 'A', root_pkcs8: rootPkcs8, root_spkis: [rootKeyId], now });

  // Every member that is absent rather than empty, and present as `null`.
  for (const fn of ['csr_new', 'csr_check']) add(`${fn} with nothing to work from`, fn, {});
  add('csr_check with der as null', 'csr_check', { der: null, presented: f.leafDer, now });
  add('csr_check with root_spkis as null', 'csr_check', { der: rootCsr, root_spkis: null });

  // B5 — a request a wallet is asked to SIGN. Laxer than the other port is the wrong direction.
  const [cri, sigAlg] = derChildren(derRead(Buffer.from(request, 'base64url')));
  const [version, subject, spki, attributes] = derChildren(cri);
  const signedBy = (key, info, alg = sigAlg.raw) => b64url(derSeq(info, alg, derBitstr(signDetached(key.priv, info))));
  const atv = derChildren(derChildren(derChildren(subject)[0])[0]);
  const threePartName = derSeq(derSet(derSeq(atv[0].raw, atv[1].raw, derTlv(0x05, Buffer.alloc(0)))));
  add('csr_check: a commonName attribute with a third element', 'csr_check', { der: signedBy(hostKey, derSeq(version.raw, threePartName, spki.raw, attributes.raw)) });
  add('csr_check: a CertificationRequestInfo that is a SET, not a SEQUENCE', 'csr_check', { der: signedBy(hostKey, derTlv(0x31, cri.content)) });
  add('csr_check: a signatureAlgorithm with a trailing NULL', 'csr_check', { der: signedBy(hostKey, cri.raw, derSeq(derChildren(sigAlg)[0].raw, derTlv(0x05, Buffer.alloc(0)))) });
  add('csr_check: a key outside the profile AND a malformed attribute set: which is said first', 'csr_check', { der: signedBy(hostKey, derSeq(version.raw, subject.raw, x25519SpkiDer, derTlv(0xa0, derInt(7)))) });

  add('issue_from_csr with no now', 'issue_from_csr', { csr: request, root_pkcs8: rootPkcs8, root_cn: 'Alina Rao' });

  // A request on another port, for the host's own dNSName and for someone else's. Port-built: the
  // seed builds no certificate signing request.
  const E8443 = 'https://agent.alina.example:8443/mcp';
  add('csr_check on another port, asking for the host\'s dNSName', 'csr_check', { der: f.wasm.call('csr_new', { cn: 'Alina Rao', host_pkcs8: hostPkcs8, endpoint: E8443, dns_name: 'agent.alina.example' }).der });
  add('csr_check on another port, asking for some other dNSName', 'csr_check', { der: f.wasm.call('csr_new', { cn: 'Alina Rao', host_pkcs8: hostPkcs8, endpoint: E8443, dns_name: 'agent.mallory.example' }).der });
  // A dns_name given as "" is refused where it is read (R26, F4); see certificates.mjs.
  add('csr_new with a dns_name that is empty', 'csr_new', { cn: 'Alina Rao', host_pkcs8: hostPkcs8, endpoint: ENDPOINT, dns_name: '' });
  expect('csr_new with a dns_name that is empty', { error: 'bad_request', why: 'dns_name is empty' });
}
