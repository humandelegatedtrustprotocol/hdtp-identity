//! What `pact vectors check` runs: the vectors, from a document's Appendix B or a vector file,
//! proven natively against the Rust core.
use super::{at, cast, certificates, NOW};
use crate::io::{fail, read_input, Fail, Res};
use pact_identity::envelope::{self, Form, SealRequest};
use pact_identity::hpke::{self, suite_for, Suite};
use pact_identity::keys::{Alg, PrivateKey};
use pact_identity::time::parse_rfc3339;
use pact_identity::util::{from_b64u, from_hex, hex, seed};
use pact_identity::x509::{self, parse, validate_chain, ChainResult};
use serde_json::Value;
use std::collections::BTreeMap;

/// The JSON blocks of a document's Appendix B: everything fenced as ```json between the heading
/// `## Appendix B` and the closing line `*End of PACT`. Both markers must be there and every fence
/// must close — the rule js/seed.mjs `appendixB` reads by, held by the same cases in both test suites.
fn appendix_b(spec: &str) -> Res<Vec<Value>> {
    let start = spec.find("## Appendix B").ok_or_else(|| Fail("no Appendix B in the document".into()))?;
    let end =
        spec[start..].find("*End of PACT").map(|i| start + i).ok_or_else(|| Fail("Appendix B has no end marker (*End of PACT)".into()))?;
    let b = &spec[start..end];
    let mut out = Vec::new();
    let mut rest = b;
    while let Some(i) = rest.find("```json\n") {
        let after = &rest[i + 8..];
        let j = after.find("\n```").ok_or_else(|| Fail("an unterminated json fence in Appendix B".into()))?;
        out.push(serde_json::from_str(&after[..j]).map_err(|e| Fail(format!("Appendix B block: {e}")))?);
        rest = &after[j + 4..];
    }
    Ok(out)
}

struct Tally {
    checks: usize,
    failures: usize,
}

impl Tally {
    fn ok(&mut self, cond: bool, what: impl AsRef<str>) {
        self.checks += 1;
        if !cond {
            self.failures += 1;
            println!("  FAIL {}", what.as_ref());
        }
    }
}

pub fn check(spec: Option<&str>, file: Option<&str>) -> Res<i32> {
    let v2: Value = match (spec, file) {
        (Some(s), _) => {
            let text = String::from_utf8(read_input(s)?).map_err(|_| Fail("the document is not UTF-8".into()))?;
            let mut blocks = appendix_b(&text)?;
            if blocks.is_empty() {
                return fail("Appendix B has no vector blocks");
            }
            blocks.remove(0)
        }
        (None, Some(f)) => serde_json::from_slice(&read_input(f)?).map_err(|e| Fail(format!("{f}: {e}")))?,
        (None, None) => {
            let candidates = [std::env::var("PACT_SPEC").unwrap_or_default(), "pact-protocol/SPEC.md".into(), "SPEC.md".into()];
            match candidates.iter().find(|p| !p.is_empty() && std::path::Path::new(p).exists()) {
                Some(p) => return check(Some(p), None),
                None => return fail("give --spec SPEC.md or --file vectors.json"),
            }
        }
    };
    // EVERY section, or this proves nothing. Each loop below reads its section with
    // `unwrap_or_default()` and records a failure only for an item that is PRESENT, so deleting
    // `chain_cases` from Appendix B left the checker printing a smaller `N/N checks passed` and
    // exiting 0 — with SPEC 14.2's twelve cases no longer proven and nothing in the tree noticing.
    // `{}` passed too, as `0/0`. The names are asserted rather than counted, so the guard cannot
    // itself go stale as the suite grows.
    for section in ["certificates", "chain_cases", "newest_leaf_cases", "certificate_renewed_cases", "envelopes"] {
        if v2.get(section).is_none() {
            return fail(format!("the document has no `{section}`: a vector suite missing a section proves less than it says"));
        }
    }

    let mut t = Tally { checks: 0, failures: 0 };

    let der: BTreeMap<String, Vec<u8>> = v2["certificates"]
        .as_object()
        .map(|o| o.iter().filter_map(|(k, c)| from_hex(c["der_hex"].as_str()?).ok().map(|d| (k.clone(), d))).collect())
        .unwrap_or_default();
    let get = |n: &str| der.get(n).cloned().unwrap_or_default();

    println!("certificates rebuild from their seeds");
    let c = cast()?;
    let mine: BTreeMap<&str, Vec<u8>> = certificates(&c)?.into_iter().map(|(n, d, _)| (n, d)).collect();
    for (name, bytes) in &der {
        // A certificate the appendix marks `refused` exists to be refused (SPEC 14.1): it must not
        // come out of parse and the profile check clean. It is not one the generator rebuilds, and
        // it is not "in the profile as a leaf" — asserting either of those about it is the mistake
        // this branch is here to avoid.
        if v2["certificates"][name.as_str()]["refused"].as_bool() == Some(true) {
            let why = match parse(bytes) {
                Ok(cert) => x509::profile_error(&cert, "leaf"),
                Err(e) => Some(e.why),
            };
            t.ok(why.is_some(), format!("{name}: marked refused, and parse + profile let it through"));
            continue;
        }
        match parse(bytes) {
            Ok(cert) => {
                let kind = if name.starts_with("root") { "root" } else { "leaf" };
                t.ok(cert.kind() == kind, format!("{name}: in the profile as a {kind}"));
                t.ok(bytes.len() <= 4096, format!("{name}: under 4 KiB"));
                match mine.get(name.as_str()) {
                    Some(rebuilt) => {
                        let same_tbs = parse(rebuilt).map(|r| r.tbs == cert.tbs).unwrap_or(false);
                        let issuer = if name.ends_with("_b") { c.root_b.public() } else { c.root_a.public() };
                        let signed = x509::verify_cert(&cert, &issuer);
                        t.ok(
                            same_tbs && signed && (cert.public_key.alg() == Alg::P256 || rebuilt == bytes),
                            format!("{name}: rebuilt from the labelled seeds"),
                        );
                    }
                    None => t.ok(false, format!("{name}: not one the generator knows")),
                }
            }
            Err(e) => t.ok(false, format!("{name}: {}", e.why)),
        }
    }
    for (name, k) in v2["leaf_keys_pkcs8_hex"].as_object().cloned().unwrap_or_default() {
        let parsed = from_hex(k.as_str().unwrap_or("")).ok().and_then(|b| PrivateKey::from_pkcs8(&b).ok());
        let mine_spki = c.hosts.get(name.as_str()).map(|h| h.public().spki().to_vec());
        t.ok(
            parsed.as_ref().map(|p| p.public().spki().to_vec()) == mine_spki && mine_spki.is_some(),
            format!("{name}: leaf key is the seed's"),
        );
    }

    println!("chain cases (§14.2)");
    for case in v2["chain_cases"].as_array().cloned().unwrap_or_default() {
        let name = case["name"].as_str().unwrap_or("?");
        let chain: Vec<Vec<u8>> =
            case["chain"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).map(get).collect()).unwrap_or_default();
        let now = case["now"].as_str().and_then(|s| parse_rfc3339(s).ok()).unwrap_or(0);
        let r = validate_chain(&chain, now, case["expected_root"].as_str(), case["expected_endpoint"].as_str());
        let want = case["expect"].as_str().unwrap_or("");
        match &r {
            ChainResult::Ok(_) => t.ok(want == "accept", format!("{name}: expected {want}, got accept")),
            ChainResult::Refused { rule, reason } => t.ok(
                want == "refuse" && Some(*rule as u64) == case["rule"].as_u64(),
                format!("{name}: expected {want} rule {}, got rule {rule} ({reason})", case["rule"]),
            ),
        }
        println!(
            "  {name}: {}",
            match r {
                ChainResult::Ok(_) => "accepted".to_string(),
                ChainResult::Refused { rule, .. } => format!("refused by rule {rule}"),
            }
        );
    }

    println!("newest leaf (§14.3)");
    for case in v2["newest_leaf_cases"].as_array().cloned().unwrap_or_default() {
        let (p, q) = (case["pinned"].as_str().unwrap_or(""), case["presented"].as_str().unwrap_or(""));
        let got = x509::compare_leaves(&get(p), &get(q)).unwrap_or("error");
        t.ok(got == case["expect"].as_str().unwrap_or(""), format!("{p} vs {q}: expected {}, got {got}", case["expect"]));
        println!("  {p} then {q}: {got}");
    }

    println!("certificate_renewed (§14.4)");
    for case in v2["certificate_renewed_cases"].as_array().cloned().unwrap_or_default() {
        let name = case["name"].as_str().unwrap_or("?");
        let pinned = get(case["pinned_leaf"].as_str().unwrap_or(""));
        let root = parse(&pinned).ok().and_then(|c| c.aki.map(|a| pact_identity::keys::fingerprint_of_id(&a))).unwrap_or_default();
        let now = case["now"].as_str().and_then(|s| parse_rfc3339(s).ok()).unwrap_or(0);
        let r = envelope::follow_renewed(&case["answer"], &root, &pinned, case["dialed"].as_str().unwrap_or(""), now);
        let follow = r["follow"].as_bool().unwrap_or(false);
        t.ok(follow == (case["expect"] == "follow"), format!("{name}: expected {}, got {r}", case["expect"]));
        println!("  {name}: {}", if follow { "followed" } else { "discarded" });
    }

    println!("v2 envelopes (§13)");
    let now2 = v2["now"].as_str().and_then(|s| parse_rfc3339(s).ok()).unwrap_or(at(NOW));
    for e in v2["envelopes"].as_array().cloned().unwrap_or_default() {
        let name = e["name"].as_str().unwrap_or("?");
        let form = e["form"].as_str().unwrap_or("chain");
        let mut go = || -> Result<(), String> {
            let rn = e["recipient_chain"][0].as_str().ok_or("recipient_chain")?;
            let sn = e["sender_chain"][0].as_str().ok_or("sender_chain")?;
            let recipient_leaf = parse(&get(rn)).map_err(|e| e.why)?;
            let recipient = PrivateKey::from_pkcs8(&from_hex(v2["leaf_keys_pkcs8_hex"][rn].as_str().unwrap_or("")).map_err(|e| e.why)?)
                .map_err(|e| e.why)?;
            let aad = from_b64u(e["protected"].as_str().unwrap_or("")).map_err(|e| e.why)?;
            let enc = from_b64u(e["enc"].as_str().unwrap_or("")).map_err(|e| e.why)?;
            let ct = from_b64u(e["ct"].as_str().unwrap_or("")).map_err(|e| e.why)?;
            let sig = from_b64u(e["sig"].as_str().unwrap_or("")).map_err(|e| e.why)?;
            let header: Value = serde_json::from_slice(&aad).map_err(|e| e.to_string())?;
            let mut members: Vec<&str> = header.as_object().map(|o| o.keys().map(|k| k.as_str()).collect()).unwrap_or_default();
            members.sort_unstable();
            t.ok(members.join(",") == envelope::HEADER_MEMBERS, format!("{name}: header members"));
            let suite = suite_for(&recipient_leaf.public_key);
            t.ok(
                header["v"] == 2 && header["suite"] == e["suite"] && Suite::parse(e["suite"].as_str().unwrap_or("")) == Some(suite),
                format!("{name}: version and suite"),
            );
            t.ok(header["kid"] == recipient_leaf.public_key.fingerprint(), format!("{name}: kid is the recipient leaf key"));
            t.ok(recipient.public().spki() == &recipient_leaf.spki[..], format!("{name}: the recipient key is the leaf's"));
            let pt = hpke::open(suite, &recipient, &recipient_leaf.public_key, envelope::INFO_V2, &aad, &enc, &ct).map_err(|e| e.why)?;
            t.ok(hex(&pt) == e["plaintext_hex"].as_str().unwrap_or(""), format!("{name}: plaintext"));
            let body: Value = serde_json::from_slice(&pt).map_err(|e| e.to_string())?;
            let mut signed = aad.clone();
            signed.extend_from_slice(&enc);
            signed.extend_from_slice(&ct);
            let sender_leaf = parse(&get(sn)).map_err(|e| e.why)?;
            let mut bm: Vec<&str> = body.as_object().map(|o| o.keys().map(|k| k.as_str()).collect()).unwrap_or_default();
            bm.sort_unstable();
            if form == "leaf" {
                t.ok(bm.join(",") == "leaf,method,params", format!("{name}: small form carries leaf, method, params"));
                t.ok(body["leaf"] == sender_leaf.public_key.fingerprint(), format!("{name}: leaf names the sender's held leaf"));
                t.ok(sender_leaf.public_key.verify(&signed, &sig), format!("{name}: signature under the held leaf's key"));
                t.ok(ct.len() < 400, format!("{name}: small form stays small ({} bytes sealed)", ct.len()));
            } else {
                t.ok(bm.join(",") == "chain,method,params", format!("{name}: full form carries chain, method, params"));
                let chain: Vec<Vec<u8>> =
                    body["chain"].as_array().map(|a| a.iter().filter_map(|x| from_b64u(x.as_str()?).ok()).collect()).unwrap_or_default();
                match validate_chain(&chain, now2, None, None) {
                    ChainResult::Ok(ok) => {
                        t.ok(true, "");
                        t.ok(chain.first() == Some(&get(sn)), format!("{name}: chain inside is the sender's"));
                        t.ok(ok.leaf.public_key.verify(&signed, &sig), format!("{name}: signature under the chain's leaf key"));
                    }
                    ChainResult::Refused { rule, reason } => t.ok(false, format!("{name}: chain inside validates (rule {rule}: {reason})")),
                }
            }
            // Re-sealed from the same inputs and the vector's ephemeral seed: enc and ct reproduce.
            let sender = PrivateKey::from_pkcs8(&from_hex(v2["leaf_keys_pkcs8_hex"][sn].as_str().unwrap_or("")).map_err(|e| e.why)?)
                .map_err(|e| e.why)?;
            let chain: Vec<Vec<u8>> =
                e["sender_chain"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).map(get).collect()).unwrap_or_default();
            let wire = envelope::seal_request(SealRequest {
                recipient: &recipient_leaf.public_key,
                sender: &sender,
                form: Form::parse(form).map_err(|e| e.why)?,
                sender_chain: Some(&chain),
                method: body["method"].as_str().unwrap_or("tools/call").into(),
                params: body["params"].clone(),
                msg_id: header["msg_id"].as_str().unwrap_or("").into(),
                ts: header["ts"].as_i64().unwrap_or(0),
                exp: header["exp"].as_i64(),
                cty: None,
                ephemeral_seed: Some(seed(&format!("ephemeral/{name}"))),
            })
            .map_err(|e| e.why)?;
            t.ok(
                wire.protected == e["protected"] && wire.enc == e["enc"] && wire.ct == e["ct"],
                format!("{name}: re-sealed from the seed, enc and ct reproduce"),
            );
            Ok(())
        };
        match go() {
            Ok(()) => println!("  {name}: opened{}", if form == "leaf" { " (by reference)" } else { "" }),
            Err(err) => t.ok(false, format!("{name}: {err}")),
        }
    }

    println!("{}/{} checks passed", t.checks - t.failures, t.checks);
    Ok(if t.failures > 0 { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // The same cases js/seed.test.mjs holds `appendixB` to.
    #[test]
    fn appendix_b_is_read_between_its_two_markers_and_a_missing_marker_or_an_open_fence_is_refused() {
        let doc = |body: &str, end: &str| format!("# Spec\n\n## Appendix B\n\n{body}\n{end}");
        let blocks = appendix_b(&doc("```json\n{\"a\":1}\n```\n\n```json\n[2]\n```", "*End of PACT 2.1*\n")).unwrap();
        assert_eq!(blocks, vec![json!({ "a": 1 }), json!([2])]);
        assert!(appendix_b("# no appendix").is_err());
        assert!(appendix_b(&doc("```json\n{\"a\":1}\n```", "")).is_err_and(|e| e.0.contains("no end marker")));
        assert!(appendix_b(&doc("```json\n{\"a\":1}\n", "*End of PACT 2.1*\n")).is_err_and(|e| e.0.contains("unterminated")));
    }
}
