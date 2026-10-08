# Security policy

hdtp-identity is the identity core every HDTP host runs: the certificate profile and chain
validation, the sealed envelopes, the card codec, requests and issuance, the receiving rules, the
vault and the call budgets — as a Rust crate, as the pinned WebAssembly build of it, as the `hdtp`
command line, and as an independent Go port. If you find a weakness in any of them — a chain the
§14.1 profile should refuse and a port accepts, an envelope that opens, replays or verifies when it
must not, a receiving decision that differs between the ports or from the specification, a vault
that gives up key material, a budget a caller can exceed, a release asset that is not what its pin
says — report it privately.

**Do not open a public issue for security reports.**

Report it through GitHub's private vulnerability reporting
(<https://github.com/humandelegatedtrustprotocol/hdtp-identity/security/advisories/new>), or by
email to security@hdtp.io with subject `[hdtp-identity security]`. Say which port and version you
read against (a release tag, `hdtp --version`, the `version` function's answer) and include a
reproduction if you can; a case in the shape of those in `js/cases/*.mjs`, or a scenario in the
shape of hdtp-spec's `vectors/intrude.mjs`, is the most useful form, because `js/parity.mjs` and
`js/intrude.mjs` run them against both ports as they stand. You will get an acknowledgment within
72 hours and a status update at least every 14 days until resolution.

Please give us reasonable time to ship a fix before public disclosure. Credit is given in
`CHANGELOG.md` unless you prefer otherwise.

## Scope notes

- A weakness in the protocol itself — in what the specification requires — is hdtp-spec's
  (<https://github.com/humandelegatedtrustprotocol/hdtp-spec/blob/main/SECURITY.md>). The
  protocol's accepted trade-offs are stated there and in the specification, and are not
  vulnerabilities by themselves.
- Keys in Wasm memory are readable by any script in the same context, and the README says so: the
  core is never a root's long-term home, the vault is opened into it for one issuance and the
  material is zeroed when the call returns. A report that a same-context script can read what the
  core holds during a call restates that; a report that material outlives the call it was opened
  for does not.
- The Wasm that hosts run is the pinned build (`js/manifest.json`), made in one container named by
  digest. `node js/verify.mjs` checks a tree's bytes against the pin and `make verify-release`
  rebuilds a published release and compares it with what was published; a release asset that does
  not match is in scope.
- Reports about the hosts built on this library — HDTP Gateway, the self-hosted node, and BatonDeck,
  the hosted platform — go to the same address.
