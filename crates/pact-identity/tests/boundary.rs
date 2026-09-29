//! Every function contract/contract.json declares, asked with nothing, an empty object, a list and
//! the hostile object js/cases/hostile.json holds: each answers one JSON object, and none of them
//! `internal`. `call` turns a panic into `{"error":"internal"}` off wasm32 (a `catch_unwind` in
//! api.rs), so an answer that parses proves nothing about panics; `internal` is what one looks like
//! here, and no input known reaches it. go/unit_test.go's TestCallNeverPanics is the Go port's twin,
//! over the same object, and js/parity.mjs sends both ports every one of these through the Wasm.
use serde_json::Value;

fn read(path: &str) -> String {
    std::fs::read_to_string(format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn every_function_answers_hostile_arguments_and_none_with_internal() {
    let contract: Value = serde_json::from_str(&read("contract/contract.json")).unwrap();
    let hostile = read("js/cases/hostile.json");
    let names: Vec<&String> = contract["methods"].as_object().unwrap().keys().collect();
    assert!(names.len() > 40, "the contract declares {} functions", names.len());
    for name in names {
        for args in ["", "{}", "[]", hostile.trim()] {
            let out = pact_identity::call(name, args);
            let v: Value = serde_json::from_str(&out).unwrap_or_else(|_| panic!("{name}({args}): not JSON: {out}"));
            assert!(v.is_object(), "{name}({args}): not an object: {out}");
            assert_ne!(v["error"], "internal", "{name}({args}): a panic, caught: {out}");
        }
    }
}
