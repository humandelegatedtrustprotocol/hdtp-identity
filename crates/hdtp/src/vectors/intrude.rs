//! What `hdtp vectors intrude` runs: the black-box intrusion run, the live battery of
//! js/live-scenarios.json posted to a running endpoint and each answer judged.
use super::LIVE_SCENARIOS;
use crate::io::{core, fail, instant, now_or, Fail, Res};
use hdtp_identity::envelope::{self, Form, SealRequest};
use hdtp_identity::hpke::{self, suite_for};
use hdtp_identity::keys::{Alg, PrivateKey, PublicKey};
use hdtp_identity::util::{b64u, from_b64u};
use hdtp_identity::x509::{self, parse, LeafSpec};
use serde_json::{json, Value};

/// What a JSON-RPC answer says, reduced to the one word the scenarios judge by: a spec error code,
/// `sealed` for a result envelope, or `unknown:<shape>`.
/// The JSON-RPC body of an answer, whether it came as JSON or as an event stream's `data:` lines.
fn rpc_body(text: &str) -> std::result::Result<Value, String> {
    let payload = if text.trim_start().starts_with("event:") || text.trim_start().starts_with("data:") {
        text.lines().filter_map(|l| l.strip_prefix("data:")).map(|l| l.trim()).collect::<Vec<_>>().join("")
    } else {
        text.to_string()
    };
    serde_json::from_str::<Value>(&payload).map_err(|_| payload.chars().take(60).collect::<String>())
}

/// Every content item of a tool answer that is itself JSON.
fn tool_texts(v: &Value) -> Vec<Value> {
    v["result"]["content"]
        .as_array()
        .map(|a| a.iter().filter_map(|c| c["text"].as_str()).filter_map(|t| serde_json::from_str(t).ok()).collect())
        .unwrap_or_default()
}

/// What the CONTROL has to show. `answer_code` says `sealed` for anything SHAPED like an envelope —
/// four non-empty strings — which is the right price for twenty-seven scenarios where a false
/// "sealed" costs nothing. For the one call that must get THROUGH it is no evidence at all: a
/// receiver, or a carrier in front of it, answering `{"protected":"a","enc":"b","ct":"c","sig":"d"}`
/// scored the control as passed, and the driver was holding the key that would have said otherwise.
///
/// So the control OPENS what it is answered with, as any caller would (§13.2): sealed to Mallory's
/// leaf key, a result, for THIS call, inside the window, signed by a leaf that chains to the
/// target's root at the target's address — and carrying a result, not a sealed refusal.
pub fn control_opened(
    text: &str,
    my_key: &PrivateKey,
    msg_id: &str,
    now: i64,
    root: &str,
    endpoint: &str,
) -> std::result::Result<(), String> {
    let v = rpc_body(text).map_err(|s| format!("the answer is not JSON ({s})"))?;
    let Some(wire) = tool_texts(&v).into_iter().find_map(|inner| serde_json::from_value::<envelope::Wire>(inner).ok()) else {
        return Err("the answer carries no envelope".into());
    };
    let opened = envelope::open_result(envelope::OpenResultArgs {
        envelope: &wire,
        my_key,
        my_public: &my_key.public(),
        msg_id,
        now,
        pins: &[],
        expected_root: Some(root),
        expected_endpoint: Some(endpoint),
    })
    .map_err(|e| format!("{}: {}", e.code, e.why))?;
    match opened.get("error") {
        Some(e) => Err(format!("it opens, and what is inside is a refusal: {e}")),
        None => Ok(()),
    }
}

pub fn answer_code(text: &str) -> String {
    let v = match rpc_body(text) {
        Ok(v) => v,
        Err(start) => return format!("unknown:not-json({start})"),
    };
    if let Some(code) = v["error"]["data"]["code"].as_str() {
        return code.into();
    }
    if let Some(code) = v["error"]["code"].as_str() {
        return code.into();
    }
    for inner in tool_texts(&v) {
        // All FOUR members, each a non-empty string. This asked only whether `protected` and `ct`
        // existed, so `{"protected":"","ct":""}` scored the CONTROL as passed -- and the control is
        // the one scenario whose whole job is to prove a well-formed call gets through.
        let full = ["protected", "enc", "ct", "sig"].iter().all(|k| inner.get(*k).and_then(|v| v.as_str()).is_some_and(|v| !v.is_empty()));
        if full {
            return "sealed".into();
        }
        if let Some(code) = inner["code"].as_str() {
            return code.into();
        }
        if let Some(code) = inner["error"]["code"].as_str() {
            return code.into();
        }
    }
    if let Some(code) = v["result"]["code"].as_str() {
        return code.into();
    }
    if v["result"]["isError"].as_bool() == Some(true) {
        return "unknown:isError".into();
    }
    format!("unknown:{}", v.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>().join(",")).unwrap_or_default())
}

/// How the target is dialled. `--allow-insecure` means BOTH things a node on your own machine
/// needs: the address guard stands aside, and so does WebPKI.
///
/// It used to mean only the first. A node in direct mode serves TLS under its own chain — a root
/// no public authority signed — so the flag that promised "a node on your own machine" got past
/// the guard and stopped at `invalid peer certificate: UnknownIssuer`, having posted nothing. On
/// 2026-09-18 nobody noticed, because the rig this was aimed at sat behind Cloudflare, whose
/// certificates WebPKI does accept.
///
/// **With the card from a FILE, what the battery measures does not rest on the transport**: every
/// envelope is sealed to the key in that card, which no carrier can open or answer for. Without
/// `--card` the sentence is false, and that is why `--card` is now required alongside this flag:
/// the card was fetched over the very channel the flag stopped authenticating, so a carrier could
/// hand over its own card, hold the key all 28 envelopes were sealed to, answer `envelope_invalid`
/// 27 times and a stub once, and the tool printed `28 blocked, 0 reproduce` and exited 0. A
/// fabricated clean security report is worse than a crash.
fn tls(insecure: bool) -> ureq::tls::TlsConfig {
    ureq::tls::TlsConfig::builder().disable_verification(insecure).build()
}

/// An answer as posted: its body, the session id it gave, its HTTP status, and its `Retry-After`
/// header in seconds when it has one.
type Posted = (String, Option<String>, u16, Option<u64>);

fn post(endpoint: &str, body: &str, session: Option<&str>, insecure: bool) -> Res<Posted> {
    let mut req = ureq::post(endpoint).header("content-type", "application/json").header("accept", "application/json, text/event-stream");
    if let Some(id) = session {
        req = req.header("mcp-session-id", id);
    }
    let mut resp = req
        .config()
        .tls_config(tls(insecure))
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(20)))
        .build()
        .send(body)
        .map_err(|e| Fail(format!("{endpoint}: {e}")))?;
    let status = resp.status().as_u16();
    let given = resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    let wait = resp.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|s| s.trim().parse::<u64>().ok());
    let text = resp.body_mut().read_to_string().map_err(|e| Fail(format!("{endpoint}: {e}")))?;
    Ok((text, given, status, wait))
}

/// The MCP handshake, before any scenario.
///
/// Without it this whole battery measured nothing. A receiver that keeps sessions answers
/// `tools/call` with `method "tools/call" is invalid during session initialization` — a JSON-RPC
/// error whose code is the NUMBER 0, which `answer_code` reads as `unknown:jsonrpc,id,error`, and
/// which every scenario then reports as a REPRODUCTION. Eight scenarios said the reference node was
/// vulnerable to eight things it had never been asked about. A security instrument that answers
/// "vulnerable" when it never reached the code under test is worse than one that refuses to run.
///
/// A stateless receiver hands back no session id, and then this changes nothing: the scenarios post
/// exactly as they did before.
fn initialize(endpoint: &str, insecure: bool) -> Res<Option<String>> {
    let body = json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": { "name": "hdtp vectors intrude", "version": env!("CARGO_PKG_VERSION") },
    }});
    let (text, session, _, _) = post(endpoint, &body.to_string(), None, insecure)?;
    if session.is_none() && !text.contains("\"result\"") {
        return fail(format!(
            "{endpoint}: initialize was refused, so no scenario could be posted: {}",
            text.chars().take(200).collect::<String>()
        ));
    }
    if session.is_some() {
        // The notification the protocol requires before any call; a receiver that gates on it
        // answers everything else with the same session error the scenarios used to collect.
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        let _ = post(endpoint, &note.to_string(), session.as_deref(), insecure)?;
    }
    Ok(session)
}

/// One answer to a scenario: the code it is judged by, the body, and how long the target asked to
/// be left alone when it refused the attempt.
pub struct Answer {
    pub code: String,
    pub text: String,
    pub retry_after: Option<u64>,
}

fn sealed_call(endpoint: &str, wire: &Value, id: u32, session: Option<&str>, insecure: bool) -> Res<Answer> {
    let body = json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": "sealed_call", "arguments": wire } });
    let (text, _, status, header) = post(endpoint, &body.to_string(), session, insecure)?;
    let code = answer_code(&text);
    let retry_after = retry_after_of(&text).or(header);
    // A door that refuses before HDTP sees anything is `http_<n>`, as the JS driver has always
    // reported it. This dropped the status, so an HTTP 403 at the edge arrived as
    // `unknown:not-json(...)` -- classified UNREACHED correctly, but unable to say why, and the
    // `http_` arm of the verdict test below was dead code in this port.
    if code.starts_with("unknown:not-json") && status >= 400 {
        return Ok(Answer { code: format!("http_{status}"), text, retry_after });
    }
    Ok(Answer { code, text, retry_after })
}

// ── rate limits ──────────────────────────────────────────────────────────────────────────────────
// A target over a budget answers `rate_limited` (SPEC §5, with `retry_after` in seconds) or, at an
// edge, HTTP 429. Both refuse the ATTEMPT, before the target has judged the attack: scored as the
// target's verdict, a rate limit read as REPRODUCES for an attack and CONTROL REFUSED for the
// control, and neither is what happened. So a rate-limited post is paused and posted again, as the
// target asked, up to a bound; one still rate-limited is UNREACHED and fails the run, saying why. A
// rate-limited envelope was refused before it was opened (§5), so posting it again is not a replay.

/// How many times a rate-limited post is posted again.
pub const RATE_RETRIES: u32 = 3;
/// The longest one pause may be: a target asking for more is left UNREACHED at once.
pub const RATE_PAUSE_MAX: u64 = 60;
/// The pause when the target names none.
pub const RATE_PAUSE_DEFAULT: u64 = 10;

/// Whether a code is a refusal of the attempt for a budget: `rate_limited`, or HTTP 429 at an edge.
pub fn is_rate_limited(code: &str) -> bool {
    code == "rate_limited" || code == "http_429"
}

/// `retry_after`, in whole seconds, wherever an answer carries it beside its code.
pub fn retry_after_of(text: &str) -> Option<u64> {
    let v = rpc_body(text).ok()?;
    let mut places = vec![v["error"]["data"]["retry_after"].clone(), v["error"]["retry_after"].clone(), v["result"]["retry_after"].clone()];
    for inner in tool_texts(&v) {
        places.push(inner["retry_after"].clone());
        places.push(inner["error"]["retry_after"].clone());
    }
    places.iter().find_map(|p| p.as_u64())
}

/// Posts until the answer is not a rate limit, pausing as the target asks. `pause` sleeps (a test
/// passes one that only records). The last answer is returned whatever it is.
pub fn through_rate_limits(mut post: impl FnMut() -> Res<Answer>, mut pause: impl FnMut(u64)) -> Res<Answer> {
    let mut answer = post()?;
    for attempt in 1..=RATE_RETRIES {
        if !is_rate_limited(&answer.code) {
            break;
        }
        let wait = answer.retry_after.unwrap_or(RATE_PAUSE_DEFAULT);
        if wait > RATE_PAUSE_MAX {
            println!("  {:<10} rate-limited for {wait} s, over the {RATE_PAUSE_MAX} s this run waits", "");
            break;
        }
        println!("  {:<10} rate-limited: pausing {wait} s as asked, then posting again ({attempt} of {RATE_RETRIES})", "");
        pause(wait);
        answer = post()?;
    }
    Ok(answer)
}

/// The verdict on one scenario's answer. A rate limit, in either answer of a replayed pair, is
/// UNREACHED: the target refused the attempt, and said nothing about the attack.
pub fn verdict(got: &str, expect: &str, control: bool) -> &'static str {
    if got == expect {
        "blocked"
    } else if got.split(" then ").any(|c| c.starts_with("unknown") || c.starts_with("http_") || is_rate_limited(c)) {
        "UNREACHED"
    } else if control {
        // The control is the one scenario that must get THROUGH, so its failure is the opposite
        // of an intrusion: a receiver refusing everything -- exactly what the control exists to
        // catch -- was reported as `REPRODUCES`, i.e. "something got in", while what happened
        // was that the legitimate call was blocked.
        "CONTROL REFUSED"
    } else {
        "REPRODUCES"
    }
}

struct Scenario {
    id: String,
    name: String,
    expect: String,
    twice: bool,
    control: bool,
}

struct Battery {
    window: i64,
    margin: i64,
    scenarios: Vec<Scenario>,
}

fn battery() -> Res<Battery> {
    let v: Value = serde_json::from_str(LIVE_SCENARIOS).map_err(|e| Fail(format!("js/live-scenarios.json: {e}")))?;
    let whole = |k: &str| v[k].as_i64().ok_or_else(|| Fail(format!("js/live-scenarios.json: {k} must be whole seconds")));
    let (window, margin) = (whole("window_s")?, whole("margin_s")?);
    let mut scenarios = Vec::new();
    for s in v["scenarios"].as_array().ok_or_else(|| Fail("js/live-scenarios.json: no scenarios".into()))? {
        let text = |k: &str| {
            s[k].as_str().map(String::from).ok_or_else(|| Fail(format!("js/live-scenarios.json: every scenario has a string {k}: {s}")))
        };
        let scenario = Scenario {
            id: text("id")?,
            name: text("name")?,
            expect: text("expect")?,
            twice: s["twice"].as_bool() == Some(true),
            control: s["control"].as_bool() == Some(true),
        };
        if scenarios.iter().any(|t: &Scenario| t.id == scenario.id) {
            return fail(format!("js/live-scenarios.json: the id {} is used twice", scenario.id));
        }
        scenarios.push(scenario);
    }
    let controls = scenarios.iter().filter(|s| s.control).count();
    if controls != 1 {
        return fail(format!("js/live-scenarios.json: exactly one scenario must be the control; {controls} are"));
    }
    if !scenarios.last().is_some_and(|s| s.control) {
        return fail("js/live-scenarios.json: the control must be last, because after it the attacker is no stranger".to_string());
    }
    Ok(Battery { window, margin, scenarios })
}

/// Mallory: her own root, her own host, a leaf for an address of her own, and the certificates the
/// receiver must refuse. New every run: the control leaves her PENDING on the target, so a fixed
/// Mallory would arrive as a contact from the second run on.
struct Mallory {
    host: PrivateKey,
    root_der: Vec<u8>,
    leaf: Vec<u8>,
    expired: Vec<u8>,
    future: Vec<u8>,
    intermediate: Vec<u8>,
}

fn mallory(now: i64) -> Res<Mallory> {
    let root = PrivateKey::generate(Alg::Ed25519).map_err(|e| Fail(e.why))?;
    let host = PrivateKey::generate(Alg::Ed25519).map_err(|e| Fail(e.why))?;
    let serial = || x509::random_serial().map_err(|e| Fail(e.why));
    let root_der = x509::build_root("Alina Rao", &root, now - 3600, &serial()?).map_err(|e| Fail(e.why))?;
    let (issuer, host_pub) = (root.public(), host.public());
    let leaf = |host_key: &PublicKey, not_before: i64, not_after: i64, ca: bool| -> Res<Vec<u8>> {
        let spec = LeafSpec {
            cn: "Alina Rao",
            root_cn: "Alina Rao",
            issuer: &issuer,
            host_key,
            uris: vec!["https://mallory.example/mcp".into()],
            dns_name: None,
            not_before,
            not_after,
            serial: serial()?,
            ca,
            usage: if ca { Some(vec![5]) } else { None },
            aki: None,
        };
        x509::build_leaf(&spec, &root).map_err(|e| Fail(e.why))
    };
    Ok(Mallory {
        leaf: leaf(&host_pub, now - 3600, now + 365 * 86_400, false)?,
        expired: leaf(&host_pub, now - 400 * 86_400, now - 2 * 86_400, false)?,
        // Rule 4 checks the leaf's dates and only the leaf's: a leaf not valid yet is refused
        // exactly as an expired one is.
        future: leaf(&host_pub, now + 3600, now + 300 * 86_400, false)?,
        // A CA-signed intermediate in the root slot is WebPKI asking to be let in: accept it and any
        // public CA could mint an identity. Rule 2 wants the root self-signed, so there is no
        // hierarchy to climb and no authority above the person.
        intermediate: leaf(&issuer, now - 3600, now + 365 * 86_400, true)?,
        root_der,
        host,
    })
}

/// What builds the envelope for each id of the battery, sealed to the target's leaf key.
struct Aim<'a> {
    recipient: &'a PublicKey,
    m: &'a Mallory,
    now: i64,
    skew: i64,
    sealed: u32,
    forged: u32,
}

impl Aim<'_> {
    fn chain(&self) -> Vec<Vec<u8>> {
        vec![self.m.leaf.clone(), self.m.root_der.clone()]
    }

    fn message() -> Value {
        json!({ "name": "send_message", "arguments": { "msg_id": "m", "text": "hello" } })
    }

    fn seal(&mut self, form: Form, chain: &[Vec<u8>], params: Value) -> Res<Value> {
        self.sealed += 1;
        let wire = envelope::seal_request(SealRequest {
            recipient: self.recipient,
            sender: &self.m.host,
            form,
            sender_chain: Some(chain),
            method: "tools/call".into(),
            params,
            msg_id: format!("intrude-{}-{}", self.now, self.sealed),
            ts: self.now,
            exp: Some(self.now + 600),
            cty: None,
            ephemeral_seed: None,
        })
        .map_err(|e| Fail(e.why))?;
        serde_json::to_value(wire).map_err(|e| Fail(e.to_string()))
    }

    /// Everything an honest sealer will not build, hand-rolled — and SEALED UNDER what it forges.
    ///
    /// `seal_request` refuses a chain that is not exactly a leaf and a root, a version it does not
    /// speak, a header member it does not know: right for a sender, useless for an intruder. So this
    /// assembles the envelope from the same public parts `seal_body` uses — the canonical header as
    /// AAD, one HPKE seal to the recipient's leaf key, a signature over protected||enc||ct — with
    /// `patch` laid over the honest header BEFORE any of it is computed.
    ///
    /// Rewriting `protected` after sealing proves nothing: the AAD stops matching, and the envelope
    /// is refused for that alone whatever the header says. Three scenarios did exactly that until
    /// 2026-09-20 (an unknown `kid`, an unlisted member, the wrong suite) and so could not fail.
    fn forge(&mut self, chain: &[Vec<u8>], patch: Value, method: &str, params: Value) -> Res<Value> {
        self.forged += 1;
        let (ts, suite) = (self.now, suite_for(self.recipient));
        let mut header = json!({ "v": 1, "suite": suite.id(), "kid": self.recipient.fingerprint(),
            "msg_id": format!("intrude-{ts}-forge{}", self.forged), "ts": ts, "exp": ts + 600, "cty": "application/hdtp-call+json" });
        if let (Some(h), Some(p)) = (header.as_object_mut(), patch.as_object()) {
            for (k, v) in p {
                h.insert(k.clone(), v.clone());
            }
        }
        let aad = hdtp_identity::canonical::canonical(&header).into_bytes();
        let chain_b64: Vec<Value> = chain.iter().map(|c| json!(b64u(c))).collect();
        let body = json!({ "method": method, "params": params, "chain": chain_b64 });
        let plaintext = serde_json::to_vec(&body).map_err(|e| Fail(e.to_string()))?;
        let (enc, ct) = hpke::seal(suite, self.recipient, envelope::INFO, &aad, &plaintext, None).map_err(|e| Fail(e.why))?;
        let mut signed = aad.clone();
        signed.extend_from_slice(&enc);
        signed.extend_from_slice(&ct);
        let sig = self.m.host.sign(&signed);
        Ok(json!({ "protected": b64u(&aad), "enc": b64u(&enc), "ct": b64u(&ct), "sig": b64u(&sig) }))
    }

    fn forged_call(&mut self, chain: &[Vec<u8>], patch: Value) -> Res<Value> {
        self.forge(chain, patch, "tools/call", Self::message())
    }

    /// The envelope for one id of the battery; `None` for an id this driver has no builder for,
    /// which `intrude` refuses and the tests below hold against the file.
    fn wire(&mut self, id: &str) -> Res<Option<Value>> {
        let (ts, skew, chain) = (self.now, self.skew, self.chain());
        let (leaf, root) = (self.m.leaf.clone(), self.m.root_der.clone());
        Ok(Some(match id {
            "small-form-stranger" | "small-form-replayed" => self.seal(Form::Leaf, &chain, Self::message())?,
            "full-form-contact-tool" => self.seal(Form::Chain, &chain, Self::message())?,
            "tampered-signature" => {
                let mut tampered = self.seal(Form::Chain, &chain, Self::message())?;
                tampered["sig"] = json!(b64u(&[0u8; 64]));
                tampered
            }
            // Headers no honest sealer writes.
            "unknown-kid" => self.forged_call(&chain, json!({ "kid": self.m.host.public().fingerprint() }))?,
            "unlisted-header-member" => self.forged_call(&chain, json!({ "from": self.m.host.public().fingerprint() }))?,
            "wrong-suite" => {
                let other = if suite_for(self.recipient).id() == "HDTP-SEAL-X25519" { "HDTP-SEAL-P256" } else { "HDTP-SEAL-X25519" };
                self.forged_call(&chain, json!({ "suite": other }))?
            }
            // §14.2 takes exactly two certificates, in one order, the second self-signed. Every
            // shape below is a path a general X.509 verifier would happily walk.
            "chain-of-one" => self.forged_call(std::slice::from_ref(&leaf), json!({}))?,
            "chain-empty" => self.forged_call(&[], json!({}))?,
            "chain-of-three" => self.forged_call(&[leaf, root.clone(), root], json!({}))?,
            "chain-reversed" => self.forged_call(&[root, leaf], json!({}))?,
            "root-as-leaf" => self.forged_call(&[root.clone(), root], json!({}))?,
            "leaf-as-root" => self.forged_call(&[leaf.clone(), leaf], json!({}))?,
            "intermediate-as-root" => self.forged_call(&[leaf, self.m.intermediate.clone()], json!({}))?,
            // Time, WELL outside the edges the receiver holds.
            "leaf-not-yet-valid" => self.seal(Form::Chain, &[self.m.future.clone(), root], Self::message())?,
            "leaf-expired" => self.seal(Form::Chain, &[self.m.expired.clone(), root], Self::message())?,
            "hour-old" => self.forged_call(&chain, json!({ "ts": ts - 3600, "exp": ts - 3000 }))?,
            // §13.3's window is 300 seconds either way, and the EXACT boundary — 300 in, 301 out — is
            // the offline suite's, where there is no transit and one clock. Over a network an
            // envelope sealed 301 seconds ahead and posted two seconds later is 299 ahead and inside
            // the window, and a receiver that accepts it is right: the file's margin is the honest
            // "well outside the window is refused".
            "past-window" => self.forged_call(&chain, json!({ "ts": ts - skew, "exp": ts + 300 }))?,
            "future-window" => self.forged_call(&chain, json!({ "ts": ts + skew, "exp": ts + 900 }))?,
            // §13.3 caps a lifetime at thirty days, because `exp` is how long a receiver must remember.
            "year-lifetime" => self.forged_call(&chain, json!({ "exp": ts + 365 * 86_400 }))?,
            // A version other than 1, and one that does not exist yet.
            "unknown-v2" => self.forged_call(&chain, json!({ "v": 2 }))?,
            "future-v3" => self.forged_call(&chain, json!({ "v": 3 }))?,
            // A `ts` of "1757000000" is not the same bytes as one of 1757000000 (§13.1).
            "string-times" => self.forged_call(&chain, json!({ "ts": ts.to_string(), "exp": (ts + 600).to_string() }))?,
            // Idempotency keyed on an empty string protects nothing (§13.1).
            "empty-msg-id" => self.forged_call(&chain, json!({ "msg_id": "" }))?,
            // `cty` is what binds direction: a result envelope is never dispatched (§13.2).
            "result-as-request" => self.forged_call(&chain, json!({ "cty": "application/hdtp-result+json" }))?,
            "stranger-tools-list" => self.forge(&chain, json!({}), "tools/list", json!({}))?,
            // `sig` covers protected||enc||ct with nothing between them, so a byte moved across the
            // enc/ct boundary leaves the signed bytes identical: what refuses it is `enc` being the
            // suite's own length (§13.1).
            "enc-byte-slid" => {
                let mut slid = self.seal(Form::Chain, &chain, Self::message())?;
                let mut enc = from_b64u(slid["enc"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
                let mut ct = from_b64u(slid["ct"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
                if let Some(last) = enc.pop() {
                    ct.insert(0, last);
                }
                slid["enc"] = json!(b64u(&enc));
                slid["ct"] = json!(b64u(&ct));
                slid
            }
            // THE CONTROL: the one well-formed call from a stranger that must get through the same
            // door — sealed, by the target, to her key.
            "control" => {
                let card = hdtp_identity::card::encode("Mallory", &self.m.leaf, Some("required"), &[]).map_err(|e| Fail(e.why))?;
                self.seal(Form::Chain, &chain, json!({ "name": "request_contact", "arguments": { "card": card, "note": "hi" } }))?
            }
            _ => return Ok(None),
        }))
    }
}

pub fn intrude(against: &str, card_file: Option<&str>, allow_insecure: bool, now: Option<&str>) -> Res<i32> {
    let now = now_or(now)?;
    let battery = battery()?;
    let endpoint = against.trim_end_matches('/').to_string();
    // This command dials what it is given and posts sealed envelopes there. The same guard a
    // receiver applies to a card's endpoint (§3, §14.2) applies to the target, so `--against` can
    // never be talked into reaching a loopback or a metadata address; a node on your own machine
    // is the one case worth an explicit flag.
    // One guard, and its words are the answer. The core's `address_guard` applies the normal form
    // of §14.1 as its own first rule, so asking `is_normal_https` first only took the refusal away
    // from the guard that owns it — and gave two different sentences for one rule, which is how a
    // guard and its message drift apart.
    // The card must come from DISK when verification is off, or the run's verdict is the carrier's.
    // See `tls` above: this is the whole of the flag's safety argument.
    if allow_insecure && card_file.is_none() {
        return fail(format!(
            "{endpoint}: --allow-insecure turns off certificate verification, so the card must come from a file: pass --card <file>. \
             Fetched over an unverified channel the card is whatever answered, every envelope is sealed to ITS key, and a clean \
             `{n} blocked` would say nothing about the target.",
            n = battery.scenarios.len()
        ));
    }
    if !allow_insecure {
        let guard = core("address_guard", json!({ "endpoint": &endpoint, "guest": false }))?;
        if guard["ok"].as_bool() != Some(true) {
            return fail(format!(
                "{endpoint}: {} (pass --allow-insecure for a node on your own machine)",
                guard["why"].as_str().unwrap_or("the address guard refuses this endpoint")
            ));
        }
    }
    // The card comes from a file when one is given, and from `<endpoint>/card.vcf` otherwise.
    // That URL is NOT something a target must serve: SPEC §9 puts the card on the invite landing
    // page, and the reference node serves exactly three public routes — `/a/{slug}/mcp`,
    // `/i/{token}` and `/mcp`. Aimed at one with no `--card`, this command used to stop at a 404
    // with nothing to say about what to do instead, which is how the battery came to be something
    // only the hosted platform could be measured with.
    let card_text = match card_file {
        Some(path) => std::fs::read_to_string(path).map_err(|e| Fail(format!("{path}: {e}")))?,
        None => ureq::get(format!("{endpoint}/card.vcf"))
            .config()
            .tls_config(tls(allow_insecure))
            .build()
            .call()
            .and_then(|mut r| r.body_mut().read_to_string())
            .map_err(|e| Fail(format!("{endpoint}/card.vcf: {e} — a host need not serve a card at a URL of its own (SPEC §9 puts it on the invite landing page); save the target's card and pass --card <file>")))?,
    };
    let card = match core("card_decode", json!({ "vcard": card_text, "now": instant(now) })) {
        Ok(c) => c,
        Err(e) => {
            println!("the target's card is not a 2.0 card ({}): nothing to aim at", e.0);
            return Ok(2);
        }
    };
    let recipient_leaf = from_b64u(card["cert"].as_str().unwrap_or("")).map_err(|e| Fail(e.why))?;
    let recipient = parse(&recipient_leaf).map_err(|e| Fail(e.why))?;
    println!(
        "target      {} root {} leaf {}",
        card["endpoint"].as_str().unwrap_or(""),
        card["root"].as_str().unwrap_or(""),
        recipient.public_key.fingerprint()
    );
    let m = mallory(now)?;
    let mut aim = Aim { recipient: &recipient.public_key, m: &m, now, skew: battery.window + battery.margin, sealed: 0, forged: 0 };

    // The handshake first: a receiver that keeps MCP sessions refuses every `tools/call` before it,
    // and the refusal looks nothing like a security answer.
    let session = initialize(&endpoint, allow_insecure)?;
    match session.as_deref() {
        Some(id) => println!("session     {id}"),
        None => println!("session     none (the receiver is stateless)"),
    }

    // An answer that is no HDTP answer at all — a transport error, a body that is not JSON — means
    // the scenario never reached the layer it tests. That is a failure of the RUN, and calling it
    // an intrusion that reproduces is how the JS driver once reported 27 of 27 against the
    // reference node, every one an `http_400` from a missing handshake.
    let mut results: Vec<(String, String, &'static str)> = Vec::new();
    let mut posted = 0u32;
    println!("scenarios (judged by the answer's code only)");
    for s in &battery.scenarios {
        let Some(wire) = aim.wire(&s.id)? else {
            return fail(format!("js/live-scenarios.json names {}, and this driver has no builder for it", s.id));
        };
        let mut post_once = || {
            through_rate_limits(
                || {
                    posted += 1;
                    sealed_call(&endpoint, &wire, posted, session.as_deref(), allow_insecure)
                },
                |s| std::thread::sleep(std::time::Duration::from_secs(s)),
            )
        };
        let Answer { code: first, text: raw, .. } = post_once()?;
        // Replayed: the same envelope posted again must be answered the same way.
        let got = if s.twice {
            let second = post_once()?.code;
            if second == first {
                first
            } else {
                format!("{first} then {second}")
            }
        } else {
            first
        };
        let mut verdict = verdict(&got, &s.expect, s.control);
        println!("  {verdict:<10} {}: {got}", s.name);
        // …and an answer that LOOKS sealed is opened, with the key this driver has been holding all
        // along. Only a verdict of `blocked` (the expected `sealed`) is worth opening: a refusal and
        // an unreached run have said what they are already.
        if s.control && verdict == "blocked" {
            let control_id = from_b64u(wire["protected"].as_str().unwrap_or(""))
                .ok()
                .and_then(|h| serde_json::from_slice::<Value>(&h).ok())
                .and_then(|h| h["msg_id"].as_str().map(String::from))
                .unwrap_or_default();
            let (root, at) = (card["root"].as_str().unwrap_or(""), card["endpoint"].as_str().unwrap_or(""));
            if let Err(why) = control_opened(&raw, &m.host, &control_id, now, root, at) {
                println!("  {:<10} …and what it was answered with does not open: {why}", "");
                verdict = "CONTROL UNOPENED";
            }
        }
        results.push((s.name.clone(), got, verdict));
    }

    let reproduce = results.iter().filter(|(_, _, v)| *v == "REPRODUCES").count();
    let unreached = results.iter().filter(|(_, _, v)| *v == "UNREACHED").count();
    let control = results.iter().filter(|(_, _, v)| *v == "CONTROL REFUSED").count();
    let unopened = results.iter().filter(|(_, _, v)| *v == "CONTROL UNOPENED").count();
    let limited = results.iter().filter(|(_, got, v)| *v == "UNREACHED" && got.split(" then ").any(is_rate_limited)).count();
    println!(
        "{} scenarios: {} blocked, {} reproduce, {} never reached a HDTP answer{}{}{}",
        results.len(),
        results.len() - reproduce - unreached - control - unopened,
        reproduce,
        unreached,
        if limited > 0 {
            format!(
                " ({limited} of them rate-limited: the target refused the attempt before judging the attack, so nothing is known of it; wait out its budget and run again)"
            )
        } else {
            String::new()
        },
        if control > 0 { ", and the CONTROL was refused: this receiver refuses a legitimate call too" } else { "" },
        if unopened > 0 {
            ", and the CONTROL's answer looked sealed and did not open: nothing here shows a call can get through"
        } else {
            ""
        }
    );
    Ok(if reproduce + unreached + control + unopened > 0 { 1 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The battery is data (js/live-scenarios.json, which js/live.mjs reads too): this driver has to
    // build every id in it, and the file has to put its one control last.
    #[test]
    fn the_battery_file_parses_and_its_one_control_is_last() {
        let b = battery().unwrap();
        assert!(b.scenarios.len() > 1, "a battery of one scenario is its control alone");
        assert_eq!(b.scenarios.iter().filter(|s| s.control).count(), 1);
        assert!(b.scenarios.last().is_some_and(|s| s.control && s.expect == "sealed"));
        assert!(b.window > 0 && b.margin > 0);
    }

    #[test]
    fn every_scenario_in_the_battery_file_is_one_this_driver_builds() {
        let b = battery().unwrap();
        let target = PrivateKey::generate(Alg::Ed25519).unwrap().public();
        let now = 1_789_000_000;
        let m = mallory(now).unwrap();
        let mut aim = Aim { recipient: &target, m: &m, now, skew: b.window + b.margin, sealed: 0, forged: 0 };
        for s in &b.scenarios {
            let wire = aim.wire(&s.id).unwrap().unwrap_or_else(|| panic!("no builder for {} ({})", s.id, s.name));
            for member in ["protected", "enc", "ct", "sig"] {
                assert!(wire[member].as_str().is_some_and(|v| !v.is_empty()), "{}: {member} is missing", s.id);
            }
        }
        assert!(aim.wire("a-scenario-nobody-wrote").unwrap().is_none());
    }

    /// A rate limit refuses the attempt, not the attack: never REPRODUCES, never CONTROL REFUSED.
    #[test]
    fn a_rate_limit_is_unreached_for_an_attack_and_for_the_control() {
        for got in ["rate_limited", "http_429", "envelope_invalid then rate_limited", "rate_limited then envelope_invalid"] {
            assert_eq!(verdict(got, "envelope_invalid", false), "UNREACHED", "{got}, an attack");
            assert_eq!(verdict(got, "sealed", true), "UNREACHED", "{got}, the control");
        }
        // The controls of the table: the target's own verdicts are judged as before.
        assert_eq!(verdict("envelope_invalid", "envelope_invalid", false), "blocked");
        assert_eq!(verdict("chain_required", "envelope_invalid", false), "REPRODUCES");
        assert_eq!(verdict("envelope_invalid", "sealed", true), "CONTROL REFUSED");
        assert_eq!(verdict("http_400", "sealed", true), "UNREACHED");
        // Where an answer says how long to wait.
        let tool =
            |inner: &str| json!({ "jsonrpc": "2.0", "id": 1, "result": { "content": [{ "type": "text", "text": inner }] } }).to_string();
        assert_eq!(retry_after_of(&tool(r#"{"code":"rate_limited","retry_after":7}"#)), Some(7));
        assert_eq!(
            retry_after_of(
                r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x","data":{"code":"rate_limited","retry_after":9}}}"#
            ),
            Some(9)
        );
        assert_eq!(retry_after_of(&tool(r#"{"code":"rate_limited"}"#)), None);
    }

    /// A rate-limited post is posted again after the pause the target asked for, up to the bound; a
    /// target asking for longer than the bound is not waited for; one that stays rate-limited is
    /// answered as it last answered, which the verdict makes UNREACHED.
    #[test]
    fn a_rate_limited_post_is_paused_and_posted_again_up_to_a_bound() {
        let answer = |code: &str, wait: Option<u64>| Answer { code: code.into(), text: String::new(), retry_after: wait };
        let run = |script: Vec<Answer>| {
            let mut script = script.into_iter();
            let (mut posts, mut pauses) = (0, Vec::new());
            let got = through_rate_limits(
                || {
                    posts += 1;
                    Ok(script.next().expect("posted more often than the script answers"))
                },
                |s| pauses.push(s),
            )
            .unwrap()
            .code;
            (got, posts, pauses)
        };
        // Through after two pauses, each as long as asked, or the default when nothing was named.
        assert_eq!(
            run(vec![answer("rate_limited", Some(3)), answer("http_429", None), answer("envelope_invalid", None)]),
            ("envelope_invalid".into(), 3, vec![3, RATE_PAUSE_DEFAULT])
        );
        // Never through: the bound, and the last answer.
        let always = (0..=RATE_RETRIES).map(|_| answer("rate_limited", Some(1))).collect();
        assert_eq!(run(always), ("rate_limited".into(), RATE_RETRIES as usize + 1, vec![1; RATE_RETRIES as usize]));
        // Asked to wait longer than a run waits: not waited for.
        assert_eq!(run(vec![answer("rate_limited", Some(RATE_PAUSE_MAX + 1))]), ("rate_limited".into(), 1, vec![]));
        // The control of the loop: an answer that is no rate limit is posted once.
        assert_eq!(run(vec![answer("sealed", None)]), ("sealed".into(), 1, vec![]));
    }

    #[test]
    fn answers_reduce_to_one_word() {
        assert_eq!(
            answer_code(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x","data":{"code":"envelope_invalid"}}}"#),
            "envelope_invalid"
        );
        assert_eq!(
            answer_code(r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"code\":\"chain_required\"}"}]}}"#),
            "chain_required"
        );
        assert_eq!(
            answer_code(
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"protected\":\"a\",\"enc\":\"b\",\"ct\":\"c\",\"sig\":\"d\"}"}]}}"#
            ),
            "sealed"
        );
        assert_eq!(answer_code("event: message\ndata: {\"result\":{\"code\":\"certificate_renewed\"}}\n\n"), "certificate_renewed");
        assert!(answer_code("<html>").starts_with("unknown:"));
    }

    // The control is the one scenario that must get THROUGH, and it was judged by the look of its
    // answer. The first case below is the very stub `answers_reduce_to_one_word` calls "sealed".
    #[test]
    fn the_control_is_passed_by_an_envelope_that_opens_and_by_nothing_that_only_looks_like_one() {
        const NOW: i64 = 1_789_000_000;
        const AT: &str = "https://target.example/mcp";
        let wrap = |inner: &Value| {
            json!({ "jsonrpc": "2.0", "id": 1, "result": { "content": [{ "type": "text", "text": inner.to_string() }] } }).to_string()
        };

        // The target, and Mallory's host key: the control's call is sealed to the target, and its
        // answer is sealed back to her.
        let (root_t, host_t, host_m) = (
            PrivateKey::generate(Alg::Ed25519).unwrap(),
            PrivateKey::generate(Alg::Ed25519).unwrap(),
            PrivateKey::generate(Alg::Ed25519).unwrap(),
        );
        let root_t_der = x509::build_root("Target", &root_t, NOW - 3600, &x509::serial_of("control/root")).unwrap();
        let (issuer, host_pub) = (root_t.public(), host_t.public());
        let leaf_t = x509::build_leaf(
            &LeafSpec {
                cn: "Target",
                root_cn: "Target",
                issuer: &issuer,
                host_key: &host_pub,
                uris: vec![AT.into()],
                dns_name: None,
                not_before: NOW - 3600,
                not_after: NOW + 86_400,
                serial: x509::serial_of("control/leaf"),
                ca: false,
                usage: None,
                aki: None,
            },
            &root_t,
        )
        .unwrap();
        let root_fp = issuer.fingerprint();
        let answer = |msg_id: &str, result: Option<Value>, error: Option<Value>, to: &PrivateKey| {
            let wire = envelope::seal_result(envelope::SealResult {
                recipient: &to.public(),
                sender: &host_t,
                form: Form::Chain,
                sender_chain: Some(&[leaf_t.clone(), root_t_der.clone()]),
                result,
                error,
                msg_id: msg_id.into(),
                ts: NOW,
                exp: Some(NOW + 600),
                ephemeral_seed: None,
            })
            .unwrap();
            wrap(&serde_json::to_value(wire).unwrap())
        };

        // What passed before: four non-empty strings.
        let stub = wrap(&json!({ "protected": "a", "enc": "b", "ct": "c", "sig": "d" }));
        assert_eq!(answer_code(&stub), "sealed", "the cheap reading still calls this sealed, which is why the control cannot use it");
        assert!(control_opened(&stub, &host_m, "c1", NOW, &root_fp, AT).is_err());

        // What must pass: a result, for this call, sealed to her, from the target.
        let good = answer("c1", Some(json!({ "status": "pending" })), None, &host_m);
        control_opened(&good, &host_m, "c1", NOW, &root_fp, AT).expect("a real sealed result opens");

        // And each way a REAL envelope can still be the wrong one.
        let refuses = |text: &str, id: &str, root: &str, at: &str, what: &str| {
            assert!(control_opened(text, &host_m, id, NOW, root, at).is_err(), "{what} was accepted as the control's answer");
        };
        refuses(&good, "another-call", &root_fp, AT, "an answer to a different call");
        refuses(&good, "c1", &host_m.public().fingerprint(), AT, "an answer from somebody who is not the target's root");
        refuses(&good, "c1", &root_fp, "https://elsewhere.example/mcp", "an answer from a leaf for another address");
        refuses(
            &answer("c1", Some(json!({ "status": "pending" })), None, &host_t),
            "c1",
            &root_fp,
            AT,
            "an answer sealed to somebody else",
        );
        refuses(&answer("c1", None, Some(json!({ "code": "rate_limited" })), &host_m), "c1", &root_fp, AT, "a sealed REFUSAL");
    }
}
