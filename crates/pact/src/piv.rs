//! A root that never leaves hardware.
//!
//! Every other arrangement in this design keeps the root as bytes somewhere a person can copy: in a
//! vault file, in a credential's large blob, in memory for the moment of an issuance. A PIV applet
//! is the one that does not. The key is generated on the card and cannot be read off it; the card
//! signs, and what comes back is a signature over a digest we handed in. So the root exists in
//! exactly one place, and "there is no export" is a property of the hardware rather than a promise
//! this code makes.
//!
//! **Why this is a native binary and not the browser.** PIV lives on the card's CCID (smartcard)
//! interface. WebHID carries HID devices and Chrome blocks FIDO HID from it outright; WebUSB cannot
//! claim an interface a kernel driver already owns, and on macOS, Linux and Windows the CCID driver
//! owns this one; `chrome.platformKeys` is ChromeOS enterprise-managed. PC/SC — a system service on
//! all three platforms — is the only door, and a native binary is the only thing that can open it.
//! So a card-held root is used from this command line, and from nowhere in a browser.
//!
//! **What the card is asked to do.** For ECC, PIV's GENERAL AUTHENTICATE takes the *digest* — for
//! P-256, the 32 bytes of a SHA-256 — and answers with a DER ECDSA signature (NIST SP 800-73-4
//! Part 2, §3.2.4). That is exactly the `signatureValue` an X.509 certificate needs, and exactly
//! what the core's external-signing seam wants: `root_tbs`/`leaf_tbs` hand out the bytes to be
//! signed, `assemble_root`/`assemble_leaf` put the certificate together from the signature.
// Without the `piv` feature there is no card to talk to, and the APDU layer below is unreachable
// rather than wrong: it stays compiled and tested, so a build that turns the feature off cannot
// quietly rot it.
#![cfg_attr(not(any(feature = "piv", test)), allow(dead_code))]
use crate::io::{fail, Fail, Res};
use pact_identity::keys::PublicKey;
use pact_identity::util::sha256;

/// Which PIV key slot. 9C is the default because it is the one that asks for the PIN on every
/// signature: a root should not sign quietly (SP 800-73-4 Part 1, §3.2 and Table 4b).
pub const DEFAULT_SLOT: &str = "9c";

/// The PIV application, as SELECT names it (NIST SP 800-73-4 Part 1, §2.2).
const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

/// The algorithm identifier GENERAL AUTHENTICATE takes in P1 for a P-256 key (SP 800-78-4, Table 6-2).
const ALG_ECC_P256: u8 = 0x11;

/// What a card, real or fake, can be asked. Every rule above this trait is the wallet's and the
/// core's; everything below it is APDUs.
pub trait CardSigner {
    /// Reader, serial, slot and algorithm — for `pact card-status` and for the line a person reads
    /// before a signature.
    fn describe(&self) -> CardInfo;
    /// The slot's public key, read from the certificate the slot holds.
    fn public_key(&self) -> Res<PublicKey>;
    /// A DER ECDSA signature over this digest, made on the card.
    fn sign_digest(&self, digest: &[u8; 32]) -> Res<Vec<u8>>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct CardInfo {
    pub reader: String,
    pub serial: Option<String>,
    pub slot: String,
    pub alg: String,
}

/// The digest an X.509 signature is over: the core signs P-256 certificates as ECDSA-with-SHA-256,
/// so the card is handed SHA-256 of the same TBS bytes and its answer verifies the same way.
pub fn digest_of(tbs: &[u8]) -> [u8; 32] {
    let h = sha256(tbs);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

/// A slot name as a person writes it, and the data object that holds its certificate
/// (SP 800-73-4 Part 1, Table 3; the retired slots are Table 3's 82–95).
pub fn slot_object(slot: &str) -> Res<(u8, [u8; 3])> {
    let s = slot.trim().trim_start_matches("0x").to_ascii_lowercase();
    let id = u8::from_str_radix(&s, 16).map_err(|_| Fail(format!("{slot}: a slot is two hex digits, like 9c")))?;
    let tail = match id {
        0x9A => 0x05,
        0x9C => 0x0A,
        0x9D => 0x0B,
        0x9E => 0x01,
        0x82..=0x95 => 0x0D + (id - 0x82),
        _ => {
            return fail(format!(
                "{slot}: not a PIV key slot. 9a (authentication), 9c (digital signature), 9d (key management), 9e (card authentication), or a retired slot 82 through 95"
            ))
        }
    };
    Ok((id, [0x5F, 0xC1, tail]))
}

/// The certificate inside a PIV certificate object: `53 L { 70 L cert, 71 01 xx, FE 00 }`
/// (SP 800-73-4 Part 1, Table 9). CertInfo 0x71 says whether the certificate is gzipped; this
/// refuses that rather than pretending, since no tool in this project writes one.
pub fn certificate_in_object(obj: &[u8]) -> Res<Vec<u8>> {
    let body = match tlv(obj, 0x53) {
        Some(b) => b,
        None => obj, // some cards answer with the bare template
    };
    let cert = tlv(body, 0x70).ok_or_else(|| Fail("the slot's data object holds no certificate (tag 70)".into()))?;
    if let Some(info) = tlv(body, 0x71) {
        if info.first().is_some_and(|b| b & 0x03 != 0) {
            return fail("the certificate in that slot is compressed; this reads only uncompressed ones");
        }
    }
    if cert.is_empty() {
        return fail("the slot holds an empty certificate");
    }
    Ok(cert.to_vec())
}

/// One BER-TLV value by tag, at the top level of `buf`. Tags here are one byte except the
/// two-byte `5F Cx` family, which never appears inside these templates.
fn tlv(buf: &[u8], want: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 1 < buf.len() {
        let tag = buf[i];
        let mut j = i + 1;
        let mut len = buf[j] as usize;
        j += 1;
        if len & 0x80 != 0 {
            let n = len & 0x7F;
            if n == 0 || n > 3 || j + n > buf.len() {
                return None;
            }
            len = 0;
            for _ in 0..n {
                len = (len << 8) | buf[j] as usize;
                j += 1;
            }
        }
        if j + len > buf.len() {
            return None;
        }
        if tag == want {
            return Some(&buf[j..j + len]);
        }
        i = j + len;
    }
    None
}

/// The signature inside a GENERAL AUTHENTICATE response: `7C L { 82 L sig }`.
pub fn signature_in_response(resp: &[u8]) -> Res<Vec<u8>> {
    let body = tlv(resp, 0x7C).ok_or_else(|| Fail("the card's answer is not an authentication template".into()))?;
    let sig = tlv(body, 0x82).ok_or_else(|| Fail("the card's answer carries no signature".into()))?;
    if sig.is_empty() {
        return fail("the card returned an empty signature");
    }
    Ok(sig.to_vec())
}

/// What a status word means, in the words of someone who has to do something about it
/// (SP 800-73-4 Part 1, Table 6, and ISO 7816-4).
pub fn status_meaning(sw: u16, slot: &str) -> String {
    match sw {
        0x9000 => "ok".into(),
        0x6982 => "the card wants the PIN first".into(),
        0x6983 => "the PIN is blocked: unblock it with the PUK (ykman piv access unblock-pin)".into(),
        sw if sw & 0xFFF0 == 0x63C0 => match sw & 0x000F {
            0 => "wrong PIN, and there are no tries left: the PIN is now blocked".into(),
            1 => "wrong PIN, one try left".into(),
            n => format!("wrong PIN, {n} tries left"),
        },
        0x6A82 => format!("slot {slot} holds no certificate: generate a key and a certificate there first (README)"),
        0x6A80 => "the card refused the parameters: the slot may hold a key of another algorithm (this signs with P-256)".into(),
        0x6A81 | 0x6D00 => "the card does not support that operation".into(),
        0x6700 => "the card refused the length of the command".into(),
        _ => format!("the card answered {sw:04X}"),
    }
}

/// A PIN as VERIFY takes one: 6 to 8 characters, padded to 8 bytes with 0xFF (SP 800-73-4 Part 2, §3.2.1).
pub fn pin_block(pin: &str) -> Res<[u8; 8]> {
    let bytes = pin.as_bytes();
    if bytes.len() < 6 || bytes.len() > 8 {
        return fail("a PIV PIN is 6 to 8 characters");
    }
    let mut out = [0xFFu8; 8];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

/// The PIN, from a file for a script or from the terminal for a person. The file is held to the
/// same rule the vault's passphrase file is: nobody else may read it.
pub fn pin() -> Res<String> {
    if let Ok(path) = std::env::var("PACT_PIN_FILE") {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).map_err(|e| Fail(format!("{path}: {e}")))?.permissions().mode();
            if mode & 0o077 != 0 {
                return fail(format!("{path}: readable by others (mode {:o}); make it 0600", mode & 0o777));
            }
        }
        let text = std::fs::read_to_string(&path).map_err(|e| Fail(format!("{path}: {e}")))?;
        let p = text.trim_end_matches(['\n', '\r']).to_string();
        if p.is_empty() {
            return fail(format!("{path}: empty"));
        }
        return Ok(p);
    }
    rpassword::prompt_password("PIV PIN: ").map_err(|e| Fail(format!("PIN: {e}")))
}

// ── the card itself ───────────────────────────────────────────────────────────────────────────

#[cfg(feature = "piv")]
mod real {
    use super::*;
    use std::cell::RefCell;

    pub struct PivCard {
        card: RefCell<pcsc::Card>,
        info: CardInfo,
        slot_id: u8,
        object: [u8; 3],
    }

    fn transmit(card: &pcsc::Card, apdu: &[u8]) -> Res<(Vec<u8>, u16)> {
        let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
        let out = card.transmit(apdu, &mut buf).map_err(|e| Fail(format!("the card did not answer: {e}")))?;
        if out.len() < 2 {
            return fail("the card's answer is too short to carry a status");
        }
        let sw = u16::from(out[out.len() - 2]) << 8 | u16::from(out[out.len() - 1]);
        Ok((out[..out.len() - 2].to_vec(), sw))
    }

    /// A command and its answer, following `61 xx` with GET RESPONSE until the card is done. PIV
    /// certificate objects are routinely larger than one short APDU can carry.
    fn send(card: &pcsc::Card, apdu: &[u8], what: &str, slot: &str) -> Res<Vec<u8>> {
        let (mut data, mut sw) = transmit(card, apdu)?;
        while sw >> 8 == 0x61 {
            let (more, next) = transmit(card, &[0x00, 0xC0, 0x00, 0x00, (sw & 0xFF) as u8])?;
            data.extend_from_slice(&more);
            sw = next;
        }
        if sw != 0x9000 {
            return fail(format!("{what}: {}", status_meaning(sw, slot)));
        }
        Ok(data)
    }

    impl PivCard {
        /// Opens the reader — the only one, or the first whose name contains `wanted` — and selects
        /// the PIV application on it.
        pub fn open(wanted: Option<&str>, slot: &str) -> Res<PivCard> {
            let (slot_id, object) = slot_object(slot)?;
            let ctx =
                pcsc::Context::establish(pcsc::Scope::User).map_err(|e| Fail(format!("no smartcard service on this machine: {e}")))?;
            let mut buf = [0u8; 4096];
            let readers: Vec<String> = ctx
                .list_readers(&mut buf)
                .map_err(|e| Fail(format!("cannot list readers: {e}")))?
                .map(|r| r.to_string_lossy().to_string())
                .collect();
            if readers.is_empty() {
                return fail("no smartcard reader: plug the card in, and check that the smartcard service is running");
            }
            let name = match wanted {
                Some(w) => readers
                    .iter()
                    .find(|r| r.to_lowercase().contains(&w.to_lowercase()))
                    .ok_or_else(|| Fail(format!("no reader matching {w:?}; this machine has: {}", readers.join(", "))))?
                    .clone(),
                None => {
                    if readers.len() > 1 {
                        return fail(format!("{} readers: say which with --reader — {}", readers.len(), readers.join(", ")));
                    }
                    readers[0].clone()
                }
            };
            let cname = std::ffi::CString::new(name.clone()).map_err(|e| Fail(format!("reader name: {e}")))?;
            let card = ctx
                .connect(&cname, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
                .map_err(|e| Fail(format!("cannot talk to the card in {name}: {e}")))?;

            let mut select = vec![0x00, 0xA4, 0x04, 0x00, PIV_AID.len() as u8];
            select.extend_from_slice(PIV_AID);
            select.push(0x00);
            send(&card, &select, "selecting the PIV application", slot)?;

            // The serial is a Yubico instruction, not a PIV one: nice to show, never required.
            let serial = transmit(&card, &[0x00, 0xF8, 0x00, 0x00])
                .ok()
                .filter(|(d, sw)| *sw == 0x9000 && d.len() == 4)
                .map(|(d, _)| u32::from_be_bytes([d[0], d[1], d[2], d[3]]).to_string());

            Ok(PivCard {
                card: RefCell::new(card),
                info: CardInfo { reader: name, serial, slot: slot.to_ascii_lowercase(), alg: "p256".into() },
                slot_id,
                object,
            })
        }

        fn verified(&self) -> Res<()> {
            let block = pin_block(&pin()?)?;
            let mut apdu = vec![0x00, 0x20, 0x00, 0x80, 0x08];
            apdu.extend_from_slice(&block);
            send(&self.card.borrow(), &apdu, "the PIN", &self.info.slot).map(|_| ())
        }
    }

    impl CardSigner for PivCard {
        fn describe(&self) -> CardInfo {
            self.info.clone()
        }

        fn public_key(&self) -> Res<PublicKey> {
            let mut apdu = vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03];
            apdu.extend_from_slice(&self.object);
            apdu.push(0x00);
            let obj = send(&self.card.borrow(), &apdu, "reading the slot", &self.info.slot)?;
            let cert = certificate_in_object(&obj)?;
            let parsed =
                pact_identity::x509::parse(&cert).map_err(|e| Fail(format!("the certificate in that slot does not parse: {}", e.why)))?;
            Ok(parsed.public_key)
        }

        fn sign_digest(&self, digest: &[u8; 32]) -> Res<Vec<u8>> {
            self.verified()?;
            // 7C L { 82 00 (give me the answer), 81 20 <digest> }
            let mut template = vec![0x82, 0x00, 0x81, 0x20];
            template.extend_from_slice(digest);
            let mut apdu = vec![0x00, 0x87, ALG_ECC_P256, self.slot_id, (template.len() + 2) as u8, 0x7C, template.len() as u8];
            apdu.extend_from_slice(&template);
            apdu.push(0x00);
            let resp = send(&self.card.borrow(), &apdu, "the signature", &self.info.slot)?;
            signature_in_response(&resp)
        }
    }
}

#[cfg(feature = "piv")]
pub use real::PivCard;

/// Opens a card, or says why this build cannot.
#[cfg(feature = "piv")]
pub fn open(reader: Option<&str>, slot: &str) -> Res<Box<dyn CardSigner>> {
    Ok(Box::new(PivCard::open(reader, slot)?))
}

#[cfg(not(feature = "piv"))]
pub fn open(_reader: Option<&str>, _slot: &str) -> Res<Box<dyn CardSigner>> {
    fail("this build has no smartcard support: build with the `piv` feature (it is on by default; a build that turned it off needs PC/SC headers to turn it back on)")
}

// ── a card for tests: the same trait, a key in memory ─────────────────────────────────────────

#[cfg(test)]
pub mod fake {
    use super::*;
    use pact_identity::keys::{Alg, PrivateKey};
    use std::cell::Cell;

    /// A card whose key is in this process. It answers exactly as the real one does — a DER ECDSA
    /// signature over a digest — so everything above the trait is exercised for real.
    ///
    /// It can also be hostile, because the two things a PIV slot holds are not made to agree by
    /// anything: `public_key` reads the slot's **certificate**, `sign_digest` uses the slot's
    /// **key**, and a card is free to hold a certificate for one key and sign with another, to
    /// answer with one key and then another, or to leave the reader between two calls. Each of
    /// those is a constructor here, because each of them must end in a refusal rather than in a
    /// certificate nobody can validate.
    pub struct FakeCard {
        /// The key that signs.
        pub key: Option<PrivateKey>,
        /// What `public_key` answers, call by call — the slot's certificate, in other words. Empty
        /// is the honest card: the signing key's own public key every time. A short list repeats
        /// its last entry.
        pub reports: Vec<PublicKey>,
        /// After this many calls of any kind the card is gone from the reader.
        pub gone_after: Option<u32>,
        /// Calls of either kind so far, so a hostile card can change its answer partway.
        pub calls: Cell<u32>,
        pub info: CardInfo,
        /// What the card refuses, if anything: the failure a test is about.
        pub refuses: Option<String>,
    }

    fn card(key: Option<PrivateKey>, serial: &str, alg: &str, refuses: Option<String>) -> FakeCard {
        FakeCard {
            key,
            reports: Vec::new(),
            gone_after: None,
            calls: Cell::new(0),
            info: CardInfo { reader: "Fake Reader".into(), serial: Some(serial.into()), slot: "9c".into(), alg: alg.into() },
            refuses,
        }
    }

    impl FakeCard {
        pub fn p256(serial: &str) -> FakeCard {
            card(Some(PrivateKey::generate(Alg::P256).expect("a P-256 key")), serial, "p256", None)
        }
        /// A slot holding a key this profile does not allow — an RSA one, as a card would say it.
        pub fn rsa() -> FakeCard {
            card(None, "1", "rsa2048", Some(status_meaning(0x6A80, "9c")))
        }
        pub fn empty_slot() -> FakeCard {
            card(None, "1", "p256", Some(status_meaning(0x6A82, "9c")))
        }
        /// The card that holds `honest`'s root, with a PIN attempt gone wrong: every check that
        /// reads the slot passes, and the signature is the thing refused — with the tries left,
        /// which is what a person needs next.
        pub fn wrong_pin_for(honest: &FakeCard) -> FakeCard {
            let mut c = FakeCard::reporting(honest, "1");
            c.refuses = Some(status_meaning(0x63C2, "9c"));
            c
        }

        /// A card that answers every question with `honest`'s key — its certificate, in other
        /// words — whatever its own key may be.
        fn reporting(honest: &FakeCard, serial: &str) -> FakeCard {
            let certificate_says = honest.key.as_ref().expect("an honest key").public();
            let mut c = FakeCard::p256(serial);
            c.reports = vec![certificate_says];
            c
        }

        /// A card holding `honest`'s certificate over a different key: it answers with the key the
        /// certificate names, every time, and signs with the other one. PIV does not prevent this
        /// — `ykman piv keys import` into a slot whose certificate was generated for an earlier key
        /// leaves a card exactly here — and no check that reads the certificate can tell. Only a
        /// signature verified under the pinned root can.
        pub fn signs_with_another_key(honest: &FakeCard, serial: &str) -> FakeCard {
            FakeCard::reporting(honest, serial)
        }

        /// The honest card for `answers` calls and another card after: pulled and replaced between
        /// the check and the signature, or the slot generated again in between. The check passes
        /// and the signature is a stranger's, which is the whole reason a signature is verified
        /// against the root a contact pinned rather than against whatever the card says now.
        pub fn swapped_after(honest: &FakeCard, answers: u32) -> FakeCard {
            let honest_pub = honest.key.as_ref().expect("an honest key").public();
            let mut c = FakeCard::p256(honest.info.serial.as_deref().unwrap_or("1"));
            let mut reports = vec![honest_pub; answers as usize];
            reports.push(c.key.as_ref().expect("a key").public());
            c.reports = reports;
            c
        }

        /// A card that answers `answers` times and is then gone from the reader — taken out
        /// between the check and the signature, which is the ordinary way this happens.
        pub fn vanishes_after(answers: u32) -> FakeCard {
            let mut c = FakeCard::p256("7777");
            c.gone_after = Some(answers);
            c
        }

        /// One call of either kind, and its 0-based number. A card that has left the reader says so
        /// here, because that is where a real one says it: the next APDU, whichever it was.
        fn tick(&self) -> Res<u32> {
            let n = self.calls.get();
            self.calls.set(n + 1);
            if self.gone_after.is_some_and(|g| n >= g) {
                return fail(format!("the card is no longer in {} (slot {}): nothing signed", self.info.reader, self.info.slot));
            }
            Ok(n)
        }
    }

    impl CardSigner for FakeCard {
        fn describe(&self) -> CardInfo {
            self.info.clone()
        }
        fn public_key(&self) -> Res<PublicKey> {
            let n = self.tick()?;
            if let Some(why) = &self.refuses {
                if self.key.is_none() {
                    return fail(format!("reading the slot: {why}"));
                }
            }
            if !self.reports.is_empty() {
                return Ok(self.reports[(n as usize).min(self.reports.len() - 1)].clone());
            }
            Ok(self.key.as_ref().expect("a key").public())
        }
        fn sign_digest(&self, digest: &[u8; 32]) -> Res<Vec<u8>> {
            self.tick()?;
            if let Some(why) = &self.refuses {
                return fail(format!("the signature: {why}"));
            }
            // The core signs a P-256 certificate as ECDSA-with-SHA-256 over the TBS; the card is
            // handed the digest, so here the same signature is made from it.
            let key = self.key.as_ref().expect("a key");
            let sk = p256::ecdsa::SigningKey::from(key.p256().map_err(|e| Fail(e.why))?);
            let sig: p256::ecdsa::Signature =
                signature::hazmat::PrehashSigner::sign_prehash(&sk, digest).map_err(|e| Fail(format!("the fake card: {e}")))?;
            Ok(sig.to_der().as_bytes().to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_by_name() {
        assert_eq!(slot_object("9c").unwrap().0, 0x9C);
        assert_eq!(slot_object("9C").unwrap().1, [0x5F, 0xC1, 0x0A]);
        assert_eq!(slot_object("9a").unwrap().1, [0x5F, 0xC1, 0x05]);
        assert_eq!(slot_object("9e").unwrap().1, [0x5F, 0xC1, 0x01]);
        assert_eq!(slot_object("82").unwrap().1, [0x5F, 0xC1, 0x0D]);
        assert_eq!(slot_object("95").unwrap().1, [0x5F, 0xC1, 0x20]);
        for bad in ["9b", "zz", "", "96"] {
            assert!(slot_object(bad).is_err(), "{bad} is not a key slot");
        }
    }

    #[test]
    fn reads_a_certificate_out_of_a_piv_object() {
        // 53 L { 70 L cert, 71 01 00, FE 00 }
        let cert = vec![0x30, 0x03, 0x02, 0x01, 0x07];
        let mut body = vec![0x70, cert.len() as u8];
        body.extend_from_slice(&cert);
        body.extend_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
        let mut obj = vec![0x53, body.len() as u8];
        obj.extend_from_slice(&body);
        assert_eq!(certificate_in_object(&obj).unwrap(), cert);

        // A gzipped certificate is refused rather than handed on as garbage.
        let mut z = vec![0x70, 0x02, 0x1F, 0x8B, 0x71, 0x01, 0x01];
        let mut zobj = vec![0x53, z.len() as u8];
        zobj.append(&mut z);
        assert!(certificate_in_object(&zobj).unwrap_err().0.contains("compressed"));
        assert!(certificate_in_object(&[0x53, 0x00]).unwrap_err().0.contains("no certificate"));
    }

    #[test]
    fn reads_a_signature_out_of_an_authentication_template() {
        let sig = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let mut body = vec![0x82, sig.len() as u8];
        body.extend_from_slice(&sig);
        let mut resp = vec![0x7C, body.len() as u8];
        resp.extend_from_slice(&body);
        assert_eq!(signature_in_response(&resp).unwrap(), sig);
        assert!(signature_in_response(&[0x30, 0x00]).unwrap_err().0.contains("not an authentication template"));
        assert!(signature_in_response(&[0x7C, 0x02, 0x82, 0x00]).unwrap_err().0.contains("empty"));
    }

    #[test]
    fn a_pin_is_padded_the_way_verify_wants_it() {
        assert_eq!(pin_block("123456").unwrap(), [b'1', b'2', b'3', b'4', b'5', b'6', 0xFF, 0xFF]);
        assert_eq!(pin_block("12345678").unwrap(), *b"12345678");
        assert!(pin_block("12345").is_err());
        assert!(pin_block("123456789").is_err());
    }

    #[test]
    fn status_words_say_what_to_do() {
        assert!(status_meaning(0x63C2, "9c").contains("2 tries left"));
        assert!(status_meaning(0x63C0, "9c").contains("blocked"));
        assert!(status_meaning(0x6982, "9c").contains("PIN"));
        assert!(status_meaning(0x6A82, "9c").contains("no certificate"));
        assert!(status_meaning(0x6A80, "9c").contains("P-256"));
    }
}
