//! The wasm-bindgen boundary: one export, bytes in and JSON out. `call(name, args)` takes the
//! CONTRACT's function name and its arguments as a JSON string and returns the answer as one.
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn call(name: &str, args: &str) -> String {
    pact_identity::call(name, args)
}

/// The crate version and the spec generation it implements.
#[wasm_bindgen]
pub fn version() -> String {
    pact_identity::call("version", "{}")
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn calls_through_the_boundary() {
        let out = super::call("generate_key", r#"{"alg":"ed25519"}"#);
        assert!(out.contains("\"fingerprint\":\"sha256:"), "{out}");
        assert!(super::call("nope", "{}").contains("no function named nope"));
    }
}
