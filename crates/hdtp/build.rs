//! Embeds go/exportcorpus, the files cases.json names and cases.json itself, so `hdtp vectors
//! corpus` can re-issue the corpus for any owner from the binary alone. The list is read from
//! cases.json, never written here a second time.
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../go/exportcorpus");
    let index = dir.join("cases.json");
    println!("cargo:rerun-if-changed={}", index.display());
    let text = std::fs::read_to_string(&index).expect("go/exportcorpus/cases.json");
    let mut files = Vec::new();
    for part in text.split("\"file\": \"").skip(1) {
        let name = &part[..part.find('"').expect("a file name ends with a quote")];
        assert!(name.ends_with(".zip") && !name.contains('/'), "cases.json names {name}");
        println!("cargo:rerun-if-changed={}", dir.join(name).display());
        files.push(format!("    ({name:?}, include_bytes!({:?})),", dir.join(name).display().to_string()));
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("corpus.rs");
    let body = format!(
        "/// cases.json, as committed.\npub const CASES: &str = include_str!({:?});\n/// Every file cases.json names, in its order.\npub const FILES: &[(&str, &[u8])] = &[\n{}\n];\n",
        index.display().to_string(),
        files.join("\n")
    );
    std::fs::write(out, body).unwrap();
}
