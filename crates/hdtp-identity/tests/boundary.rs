//! Every function contract/contract.json declares, asked with nothing, an empty object, a list and
//! the members of the hostile object js/cases/hostile.json holds that it declares (sent whole, the
//! object is refused for its first undeclared member before any member is read, CONTRACT §0, and
//! reaches no function's body): each answers one JSON object, none of them `internal`, and none of
//! them the undeclared-member refusal. `call` turns a panic into `{"error":"internal"}` off wasm32 (a `catch_unwind` in
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
    let hostile: Value = serde_json::from_str(&read("js/cases/hostile.json")).unwrap();
    let methods = contract["methods"].as_object().unwrap();
    assert!(methods.len() > 40, "the contract declares {} functions", methods.len());
    let mut reached = 0;
    for (name, m) in methods {
        let declared = m["params"]["properties"].as_object().cloned().unwrap_or_default();
        let mine: serde_json::Map<String, Value> =
            hostile.as_object().unwrap().iter().filter(|(k, _)| declared.contains_key(*k)).map(|(k, v)| (k.clone(), v.clone())).collect();
        let mut sweep = vec![String::new(), "{}".into(), "[]".into()];
        if !mine.is_empty() {
            sweep.push(Value::Object(mine).to_string());
            reached += 1;
        }
        for args in &sweep {
            let out = hdtp_identity::call(name, args);
            let v: Value = serde_json::from_str(&out).unwrap_or_else(|_| panic!("{name}({args}): not JSON: {out}"));
            assert!(v.is_object(), "{name}({args}): not an object: {out}");
            assert_ne!(v["error"], "internal", "{name}({args}): a panic, caught: {out}");
            let why = v["why"].as_str().unwrap_or("");
            assert!(!why.contains("takes no member"), "{name}({args}): refused before its body, so the sweep reached nothing: {out}");
        }
    }
    assert!(reached >= 10, "the hostile object reaches {reached} functions' bodies");
}
