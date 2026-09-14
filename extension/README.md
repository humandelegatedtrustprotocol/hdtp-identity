# PACT wallet — the browser extension

The person's root certificate lives here; hosts get their leaves from it. Manifest V3, plain ES
modules, no bundler, no framework. The cryptography is the identity core (`../crates/pact-identity`)
compiled to WebAssembly and vendored in `vendor/` (`vendor.sh` re-copies it from `../js/pkg-web`
and records the hash in `vendor/VENDORED.md`; it must equal `../js/manifest.json`).

## Parts

| File | Role |
|---|---|
| `background.js` | the service worker: loads the core once, holds the unlocked vault in memory only, auto-locks after 15 idle minutes (`chrome.alarms`), answers pages through the bridge and the window and popup over ports |
| `bridge.js` | content script, isolated world: relays a page's requests to the worker with the origin Chrome attaches (`sender.origin`), never one the page claims |
| `page.js` | content script, MAIN world: `window.pact` — `requestIdentity()`, `issueCertificate(csr, {notAfter?, move?})`, `listCertificates()`, `syncContacts(contacts)`, `ceremony(msg)` — every call a promise answered only after the person acts in the wallet's window |
| `window.html` / `window.js` | the wallet's own window, opened by the worker with `chrome.windows.create({type: 'popup'})`, never drawn by a page: unlock, create, pick an identity for an origin, the issuance screen (origin, endpoint, new-host and new-address flags, dates, Sign), contacts reconcile, ledger, backups |
| `popup.html` / `popup.js` | the toolbar popup: status, identities, open the window, lock |
| `hardware.js` | the FIDO2 PRF wrap: a credential's PRF output for a stored salt seals a second copy of the vault, so a security key or platform passkey replaces the passphrase on this device |
| `drive.js` | Google Drive app-data backups, an adapter that stays hidden until `config.js` carries an OAuth client id |
| `core.js`, `config.js`, `styles.css` | the core loader (`call(name, args)`), owner settings, the styles |

## The rules it enforces (SPEC §9), and the tests that prove them

`npm test` drives Chrome for Testing with the extension loaded (`--headless=new`; Puppeteer's
`enableExtensions`) and a page served from `127.0.0.1`:

1. `requestIdentity()` opens the window; the page is answered `{root_fingerprint, cn}` only after the person creates or picks an identity and clicks Allow. The vault file downloads on creation and opens with the passphrase. The one-time notice — a lost vault is a lost identity — is a required checkbox.
2. `issueCertificate(csr)` shows the origin, the endpoint, whether the host is new to this root and whether the address is, and the dates; nothing is signed before the click; a new address needs the passphrase again (an empty one is refused); the chain returned validates to the root at that endpoint. `listCertificates()` returns the ledger for the granted identity, never key material.
3. A second live leaf at another address is refused unless the request says `move`; with `move` the previous address's leaf is recorded as superseded in the ledger; a renewal for a known address needs the click alone.
4. The ceremony messages of the hosting design (`{pact: 'ceremony/1', op: 'signup' | 'renew' | 'move' | 'upgrade', csr, endpoint, display_name, new_host}`, posted to the page's own window or passed to `window.pact.ceremony`) are answered `{pact: 'ceremony/1', op: 'leaf', chain, root_fingerprint}` — from a second origin, a signup at a second address while a leaf is live elsewhere is refused (it is a move), and a move is issued.
5. `syncContacts` lists every difference and applies only what is ticked; a contact's `root_cert` (the root certificate the host's pin validated, base64url DER) is kept in the book beside its `leaf`, and the answer's `book` carries it back — the return-with-archive screen needs it to prove an archive's leaf.
6. Hardware wrap: with a CDP virtual authenticator (`hasPrf: true`) the credential is enrolled from the extension's own origin, the vault is re-sealed under the PRF output, a lock and a hardware unlock round-trip, and the passphrase still opens the vault.
7. Lock (the popup's button and the idle alarm) clears the unlocked state and every grant; the page's next call is refused.
8. The manifest loads with no error on `chrome://extensions`, permissions are exactly `storage` and `alarms`, no host permissions.

Chrome comes from `PUPPETEER_EXECUTABLE_PATH` or `~/.cache/puppeteer` (Chrome for Testing). Node 20+.

## How the ceremony converges on the extension

The portal probes `window.pact` (100 ms). When it is there, the portal posts the same ceremony
messages it would post to the provider's frame, to its own window; `page.js` answers them, and the
frame is never loaded. A person who brings a wallet never sees the provider's document.

## Where the root is, and when

Sealed in `chrome.storage.local` as a `pact-vault/1` document (Argon2id 64 MiB, t=3; AES-256-GCM;
the header as AAD). Unlocked, the plaintext lives in the service worker's memory only, until lock;
the root's private key exists as bytes outside that object only inside the core's `wallet_issue`
call. A hardware-wrapped copy, when enabled, is a second sealed document under the PRF-derived key;
it is re-sealed with every change when the PRF key is in memory and marked stale otherwise, and a
stale copy asks for the passphrase once. Nothing about the vault is ever handed to a page; a page
receives the fingerprint it was granted, the chain it asked for, the ledger of that one identity, or
the reconciled contact book.

## Load unpacked

`chrome://extensions` → Developer mode → Load unpacked → this directory. `npm run vendor` after
rebuilding the core.

## The owner's items

- **Google Drive**: a Google Cloud project with the Drive API on, an OAuth client id for a Chrome
  extension, put into `config.js`; then add `"identity"` to `permissions` and
  `"oauth2": {"client_id": "…", "scopes": ["https://www.googleapis.com/auth/drive.appdata"]}` to
  the manifest. Until then the Drive button is hidden.
- **Store listing**: the Chrome Web Store developer account, the listing text, the privacy
  disclosure (nothing leaves the device except to Drive when the person chooses it), the signing
  key and the update channel; review time is calendar.
- **Firefox**: MV3 there lacks `world: "MAIN"` content scripts in some versions; untested.

## Known limits

- The core reads the live leaf as **the newest one issued** (§14.3), and so does this extension; the
  `superseded_at` it records on a move is a convenience for what the window shows, not a rule any
  port depends on. A vault the CLI wrote — which records no `superseded_at` — therefore renews here
  exactly as it renews there.
- The wasm module is loaded unoptimised (623 KB; binaryen is not installed on the build machine).
