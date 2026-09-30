//! The constants the two ports each write down, held to the one copy contract/contract.json carries:
//! its `Windows` and `LimitsIdle`. go/constants_test.go holds the Go port's to the same file. (The
//! vault's bounds and default are private to vault.rs and held there; the canonical number table in
//! canonical.rs; the export's bounds in tests/limits.rs.)
use pact_identity::envelope::{CLAIM_WINDOW_S, MAX_LIFETIME_S, SKEW_S, TOMBSTONE_S};
use pact_identity::signing::MAX_AHEAD_SECONDS;
use pact_identity::x509::MAX_LEAF_DAYS;
use serde_json::{json, Value};

fn defs() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contract/contract.json");
    let contract: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    contract["$defs"].clone()
}

#[test]
fn the_contracts_windows_are_the_cores_constants() {
    let core = json!({
        "skew_s": SKEW_S, "max_lifetime_s": MAX_LIFETIME_S, "tombstone_s": TOMBSTONE_S, "claim_window_s": CLAIM_WINDOW_S,
        "max_leaf_days": MAX_LEAF_DAYS, "signing_max_ahead_s": MAX_AHEAD_SECONDS,
    });
    assert_eq!(defs()["Windows"]["const"], core, "contract/contract.json's Windows and the core's constants");
}

#[test]
fn the_contracts_idle_window_is_the_limits_crates() {
    assert_eq!(defs()["LimitsIdle"]["const"], json!(pact_limits::IDLE_MS), "contract/contract.json's LimitsIdle and pact-limits' IDLE_MS");
}
