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
| `hardware.js` | what an authenticator can do for the wallet, in three kinds — see below; a security key or passkey replaces the passphrase on this device, and one kind holds the identity itself |
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

`test/cdp.mjs` settles, in the same browser, three things that were once argued from source
(`test/harness.mjs` is what the two suites share):

9. The service worker is evicted mid-decision — its CDP target is closed outright — and the open
   window says so rather than leaving Sign armed, while the page's call is refused `unavailable`
   instead of waiting for ever; the next attempt, on the restarted worker, goes through.
10. A request nobody answers ends at `CONFIG.REQUEST_TIMEOUT_MINUTES` (the worker's own
    `setTimeout` is clamped for the test, so the code is unchanged and only its clock is shorter),
    and a window removed before `chrome.windows.create` returns is answered `cancelled` by the
    guard after the await.
11. With `PACT_FAKE_PRF` unset, an authenticator without PRF is reported as a failure — nothing is
    enabled behind the person's back, and no half-wrapped copy of the vault is written. That is the
    state in which test 6 fails rather than falling back.
12. A passkey backup (`hasLargeBlob: true`) is written from one wallet and read back by a profile
    whose storage has been cleared: the restored identity's root fingerprint is the one that was
    backed up, and a leaf issued from the key it now holds validates to that root. Both screens say
    what the backup does not carry.
13. An authenticator without PRF is offered as a gate — and only after the panel has
    said what that costs. The offer is a second click; taking it stores the key in the profile,
    which is what the panel said it would do.

It also holds the portal to its claim: the certificate section reads `…/certificate` and
`…/addresses/pending` once per identity, not once per keystroke. The portal is built to a scratch
directory (never `pact-cloud/gateway/public`, which a local Worker serves) and served with stubbed
`/v1`. Against the bundle that predates the fix, ten keystrokes took each count from 2 to 14; with the fix
each stays at 1.
`PACT_PORTAL_DIST=<a built portal>` aims the same test at any copy, which is how that was shown.

Chrome comes from `PUPPETEER_EXECUTABLE_PATH` or `~/.cache/puppeteer` (Chrome for Testing). Node 20+.

## How the ceremony converges on the extension

The portal probes `window.pact` (100 ms). When it is there, the portal posts the same ceremony
messages it would post to the provider's frame, to its own window; `page.js` answers them, and the
frame is never loaded. A person who brings a wallet never sees the provider's document.

## What an authenticator can do here

WebAuthn signs `authenticatorData ‖ SHA-256(clientDataJSON)` and never bytes you hand it, so a
passkey cannot *be* the root: it cannot sign a certificate. (A root that never leaves hardware needs
a signer that takes arbitrary bytes — a PIV applet, which the CLI does through the core's
`root_tbs`/`assemble_root` seam.) What an authenticator can do is hold or gate a secret, and
which of the three you get depends on what it supports. The wallet tries them in this order, names
the one in force on the home screen, and never silently settles for the weakest.

These are two questions, not one, and the wallet keeps them apart.

**Unlocking this device.** Two mechanisms, tried in this order:

| Mode | What the authenticator does | The bargain |
|---|---|---|
| `prf` | derives a stable 32 bytes from a stored salt (CTAP2 hmac-secret) and that seals this device's copy of the vault | the authenticator is **one of two things** needed, the vault file being the other, so it fails closed if only one is taken |
| `gate` | answers an assertion, and nothing more — where 1Password and most password managers land | the key is kept in this profile: anyone with the profile can read it without the passkey, so what protects the vault at rest is the passphrase, as it was. Offered only after PRF fails, and only after a panel says this |

**Backing the identity up.** A largeBlob passkey — its own credential, because the passkey someone
keeps a backup in is rarely the security key they unlock with — holds the root private key, which is
the whole identity: the fingerprint contacts pin is of its public key (SPEC §2), so a certificate
rebuilt from that key is the same identity and every pin still matches. Two actions:

- **Keep a copy on a passkey**, beside the file and Drive kinds on the home screen.
- **Restore from a passkey**, on both screens a wallet can open on — "create an identity" for a
  fresh profile, "unlock" for one with a vault. It reads the blob, rebuilds the certificate when the
  blob could not carry one, asks for a passphrase, seals a vault, and hands over to the ordinary
  flow. The extension is the working wallet from then on; the passkey is a backup, not a key store.

The exposure, stated once because the owner chose it knowingly: a passkey holding those 32 bytes can
restore the identity anywhere, so whoever can use that credential can become that person. The key is
read once at setup rather than at every signature.

What a restored wallet does not have, said on both screens: the ledger and the contact book were not
in the backup. It will not know which certificates it issued — the next one takes a start date later
than any it later sees — and it will not know who the person knows; that comes from an archive or
from the contacts' own next messages. And syncing is not promised: *if* the passkey syncs, the copy
syncs with it. Chrome's own password manager does not sync large blobs today, and 1Password should
not be assumed without testing. A provider with PRF but no large blob has a better job here anyway —
keep the **vault file** itself in it, which needs nothing from this extension.

WebAuthn reports no blob capacity (CTAP's `maxSerializedLargeBlobArray` never reaches the page), so
the write is attempted with the certificates and repeated with the keys alone if the authenticator
refuses.

What `root-on-key` does **not** do yet: use what it stored. `unlockKey` reads the roots back — the
blob carries them and the test proves it — but unlocking still opens this device's sealed copy, and
a restore on a fresh profile from the authenticator alone is not built. The root is on the key; the
flow that rebuilds an identity from it is the next piece of work, not a claim to make today.

`root-on-key` writes the roots that exist when it is enrolled; an identity made afterwards is in
the vault and in this device's sealed copy, but not on the key until it is enrolled again, because
re-writing the blob would mean reaching for the authenticator at every `create`. The sealed copy is
the authoritative one either way.

`root-on-key` is what the owner asked for — the identity living on the key rather than only in a
file — and it changes nothing about backups: **an authenticator can be lost, and the vault file is
what survives that.** Enabling it hands the root from the worker to the wallet's own window for the
moment of the write; no page can reach that call, but it is the one moment a root is outside the
worker, and it is named here rather than left to be discovered.

A password manager (1Password and most others) lands in `gate`. The useful thing it can do for
this wallet is not the credential's secret but the **vault file** itself: keeping a copy of that
document is exactly what a password manager is good at, and it is the backup that survives
everything else.

## Where the root is, and when

Sealed in `chrome.storage.local` as a `pact-vault/1` document (Argon2id 64 MiB, t=3; AES-256-GCM;
the header as AAD). Unlocked, the plaintext lives in the service worker's memory only, until lock;
the root's private key exists as bytes outside that object only inside the core's `wallet_issue`
call. A hardware-wrapped copy, when enabled, is a second sealed document under whichever secret the mode
above gives; it is re-sealed with every change when that secret is in memory and marked stale
otherwise, and a stale copy asks for the passphrase once. Nothing about the vault is ever handed to a page; a page
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

## A warning about running these tests

The three hardware-mode tests (11–13) each launch their own Chrome, because a virtual authenticator
belongs to a whole browser and two of them in one browser make the tests pass or fail by which ran
first. That works — they pass together, in about a second and a half each — but the arrangement is
fragile in a way worth knowing before debugging it: **a second `puppeteer.launch` with an unpacked
extension in the same Node process sometimes yields a browser whose extension is loaded but inert**,
its wallet window never getting past the first screen. When that happens every test after it fails
on a timeout that says nothing about the wallet. Run them alone
(`node --test --test-name-pattern="largeBlob|gate:" test/cdp.mjs`) to tell a real failure from this
one, and kill stray `Chrome for Testing` processes first — the failure is much likelier on a loaded
machine.
