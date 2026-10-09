//! The export's bounds are written three times: contract/contract.json's `ExportLimits`, the core's
//! constants, and the Go port's (held to the contract by go/export_limits_test.go). This holds the
//! first two to each other, so the contract a host reads is the core it runs.
use hdtp_identity::export::{
    ATTACHMENTS_MAX, BODY_MAX, CONTACTS_MAX, CONTACTS_ROWS_MAX, LINE_MAX, MANIFEST_MAX, MEDIA_MAX, NAME_MAX, THREADS_MAX,
};
use serde_json::{json, Value};

#[test]
fn the_contracts_export_limits_are_the_cores_constants() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../contract/contract.json");
    let contract: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let declared = &contract["$defs"]["ExportLimits"]["const"];
    let core = json!({
        "manifest": MANIFEST_MAX, "contacts_csv": CONTACTS_MAX, "contacts_rows": CONTACTS_ROWS_MAX, "threads_csv": THREADS_MAX,
        "messages_line": LINE_MAX, "media_file": MEDIA_MAX, "body": BODY_MAX, "name_characters": NAME_MAX, "attachments": ATTACHMENTS_MAX,
    });
    assert_eq!(declared, &core, "contract/contract.json's ExportLimits and the core's constants");
}
