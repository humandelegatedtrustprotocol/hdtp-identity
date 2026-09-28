//! The cloud's TypeScript and this crate decide alike: every step of js/cases/limits-vectors.json,
//! which js/limits-vectors.mjs made by running the cloud's `RateLimiter.take` over SQLite, replayed
//! here on the crate's own state, bit for bit.
//!
//! The replay deletes every idle row after every step, where the TypeScript swept at most once a
//! minute: the two stores hold different rows, and the decisions must not care.
use pact_limits::{decide, Charge, Decision, MemoryStore, Rules, StateStore};
use serde_json::Value;

fn charge(c: &Value) -> Charge {
    let s = |k: &str| c[k].as_str().expect(k).to_string();
    let n = |k: &str| c[k].as_f64().expect(k);
    match c["kind"].as_str().expect("kind") {
        "contact_in" => Charge::ContactIn { root: s("root"), contact_cap: n("contact_cap") },
        "contact_out" => Charge::ContactOut { root: s("root"), contact_cap: n("contact_cap") },
        "guest_in" => Charge::GuestIn {
            root: c["root"].as_str().map(str::to_string),
            source: s("source"),
            addressed: c["addressed"].as_bool().expect("addressed"),
        },
        "stranger_out" => Charge::StrangerOut,
        "integration" => Charge::Integration { integration: s("integration"), contact: s("contact") },
        other => panic!("the vectors hold a charge the TypeScript has no rule for: {other}"),
    }
}

#[test]
fn every_step_decides_and_writes_as_the_typescript_did() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../js/cases/limits-vectors.json");
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).expect(path)).expect("the vectors read");
    let (mut steps, mut refused) = (0, 0);
    for seq in file["sequences"].as_array().expect("sequences") {
        let seed = &seq["seed"];
        let rules = Rules::from_members(|m| seq["rules"][m].as_f64().expect(m));
        rules.check().expect("the vectors' rules pass the check");
        let mut store = MemoryStore::default();
        for (i, step) in seq["steps"].as_array().expect("steps").iter().enumerate() {
            let at = format!("seed {seed} step {i}");
            let c = charge(&step[0]);
            let now = step[1].as_i64().expect("now");
            let got = decide(&rules, &c, now, &mut store);
            let want = match &step[2] {
                Value::Number(n) if n.as_i64() == Some(0) => Decision::Allow,
                o => Decision::Refuse {
                    retry_after: Some(o[0].as_u64().expect("retry_after")),
                    which: o[1].as_str().expect("refused_by").into(),
                },
            };
            assert_eq!(got, want, "{at}: {c:?} at {now}");
            if got == Decision::Allow {
                let keys: Vec<String> = c.buckets(&rules).into_iter().map(|b| b.key).collect();
                let writes = step[3].as_array().expect("writes");
                assert_eq!(writes.len(), keys.len(), "{at}: one row per bucket");
                for (key, w) in keys.iter().zip(writes) {
                    assert_eq!(key, w[0].as_str().expect("bucket"), "{at}");
                    let row = store.get(key).expect("written");
                    let tokens = w[1].as_f64().expect("tokens");
                    assert_eq!(
                        row.tokens.to_bits(),
                        tokens.to_bits(),
                        "{at}: {key} holds {} where the TypeScript wrote {tokens}",
                        row.tokens
                    );
                    assert_eq!(row.updated_at, w[2].as_i64().expect("updated_at"), "{at}: {key}");
                }
            } else {
                refused += 1;
            }
            store.sweep(now);
            steps += 1;
        }
    }
    // A floor, not a count: the file can grow, and must not shrink to nothing.
    assert!(steps >= 1_000 && refused >= 100, "the vectors hold {steps} steps, {refused} refused");
}
