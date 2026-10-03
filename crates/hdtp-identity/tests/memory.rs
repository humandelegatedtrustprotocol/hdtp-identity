//! What the export's readers hold at their peak, per row of the file they read. A host runs the core
//! in a Wasm instance whose linear memory only ever grows — a Durable Object of 128 MB, in the
//! cloud — so the peak of one call IS what that call costs the host for the rest of its life.
//!
//! The allocator below counts the bytes live and the most ever live, and each call is measured as
//! the peak above what was live before it, less the argument text the caller hands in (a host holds
//! that anyway, and so does the Wasm glue that copies it in). The Wasm build uses the same code over
//! dlmalloc; js/export-memory.test.mjs measures its linear memory itself.
//!
//! The bounds are ratios to what the call is handed, checked at N and 4N rows, so they cannot go
//! stale with file sizes and a cost growing faster than the rows fails:
//!
//!   export_read, at most 4 bytes per byte of threads.csv: the member once more (the text its
//!   argument's JSON decodes to), the answer (the rows again with some 57 bytes of keys each), and a
//!   40-byte digest per thread id — about 3×; 2.9–3.0× measured on 2026-09-27. 0.3.1 held 15–16×.
//!
//!   export_read_end, at most 2 bytes per byte of its lists: the ids as strings borrowed from the
//!   argument text wherever JSON did not escape them, sorted, never copied — 1.15× measured. 0.3.1
//!   held 4.7×.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size(), Relaxed) + l.size();
            PEAK.fetch_max(now, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            if new > l.size() {
                let now = LIVE.fetch_add(new - l.size(), Relaxed) + (new - l.size());
                PEAK.fetch_max(now, Relaxed);
            } else {
                LIVE.fetch_sub(l.size() - new, Relaxed);
            }
        }
        q
    }
}

#[global_allocator]
static A: Counting = Counting;

/// One test at a time, held for the whole test: the counters are the process's, and the harness runs
/// tests on threads of their own, whose allocations would otherwise land in another's measurement.
static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn alone() -> std::sync::MutexGuard<'static, ()> {
    ONE.lock().unwrap_or_else(|e| e.into_inner())
}

/// The bytes one call holds at its peak beyond what was live before it, its answer included.
fn peak_of(name: &str, args: &str) -> (usize, String) {
    let before = LIVE.load(Relaxed);
    PEAK.store(before, Relaxed);
    let answer = hdtp_identity::call(name, args);
    (PEAK.load(Relaxed) - before, answer)
}

fn fp(i: usize) -> String {
    format!("sha256:{}", hdtp_identity::util::b64u(&hdtp_identity::util::sha256(format!("c{i}").as_bytes())))
}

/// A UUID-shaped thread id, as hosts mint them.
fn uuid(i: usize) -> String {
    let h = hdtp_identity::util::hex(&hdtp_identity::util::sha256(format!("u{i}").as_bytes()));
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

struct File {
    args: String,
    csv_bytes: usize,
}

/// The export_read arguments of a file of 200 contacts and `rows` threads.
fn a_file(rows: usize) -> File {
    use serde_json::json;
    let owner = format!("sha256:{}", "O".repeat(43));
    let contacts: Vec<_> = (0..200)
        .map(|i| {
            json!({ "root": fp(i), "endpoint": format!("https://c{i}.example/mcp"), "name": "", "display_name": "", "status": "active",
                "was_active": true, "permissions": [], "their_permissions": [], "added": "2026-09-01T00:00:00Z" })
        })
        .collect();
    let threads: Vec<_> = (0..rows)
        .map(|i| json!({ "id": uuid(i), "contact": fp(i % 200), "topic": "a topic", "created_at": "2026-09-01T00:00:00Z", "last_at": "2026-09-01T00:00:00Z" }))
        .collect();
    let w: serde_json::Value = serde_json::from_str(&hdtp_identity::call(
        "export_write",
        &json!({ "owner": owner, "owner_name": "", "exported_at": "2026-09-27T00:00:00Z", "tool": "t", "contacts": contacts, "threads": threads }).to_string(),
    ))
    .unwrap();
    let manifest: serde_json::Value =
        serde_json::from_str(&hdtp_identity::call("export_manifest", &json!({ "partial": w["partial"] }).to_string())).unwrap();
    let directory: Vec<_> = ["manifest.json", "contacts.csv", "threads.csv"]
        .iter()
        .map(|n| json!({ "name": n, "size": 1, "encrypted": false, "mode": 0 }))
        .collect();
    let csv_bytes = w["threads_csv"].as_str().unwrap().len();
    let args = json!({ "directory": directory, "manifest": manifest["manifest"], "contacts_csv": w["contacts_csv"], "threads_csv": w["threads_csv"], "owner": owner, "now": "2026-09-27T00:00:00Z" }).to_string();
    File { args, csv_bytes }
}

#[test]
fn export_read_holds_a_bounded_amount_per_row() {
    let _alone = alone();
    for rows in [16_000, 64_000] {
        let f = a_file(rows);
        let (peak, answer) = peak_of("export_read", &f.args);
        assert!(!answer.contains("\"error\""), "{}", &answer[..answer.len().min(200)]);
        eprintln!(
            "export_read, {rows} threads ({} bytes of threads.csv): peak {peak} bytes, {} per row, {:.1}x the CSV",
            f.csv_bytes,
            peak / rows,
            peak as f64 / f.csv_bytes as f64
        );
        assert!(peak <= 4 * f.csv_bytes, "{rows} threads: {:.2}x the CSV, over 4x", peak as f64 / f.csv_bytes as f64);
    }
}

#[test]
fn export_read_end_holds_a_bounded_amount_per_id() {
    let _alone = alone();
    use serde_json::json;
    for rows in [16_000, 64_000] {
        let ids: Vec<String> = (0..rows).map(uuid).collect();
        let msg_ids: Vec<String> = ids.iter().map(|i| format!("x{i}")).collect();
        let hash = "a".repeat(64);
        let owner = format!("sha256:{}", "O".repeat(43));
        let manifest = json!({ "hdtp_export": 1, "owner": owner, "owner_name": "", "exported_at": "2026-09-27T00:00:00Z", "tool": "t",
        "counts": { "contacts": 0, "threads": 0, "messages": rows, "media": 0 }, "files": { "messages.jsonl": hash } })
        .to_string();
        let args = json!({ "manifest": manifest, "messages_sha256": hash, "lines": rows, "ids": ids, "msg_ids": msg_ids, "reply_tos": msg_ids[1..], "media_seen": [], "media": [] }).to_string();
        let lists = json!([ids, msg_ids, msg_ids[1..]]).to_string().len();
        let (peak, answer) = peak_of("export_read_end", &args);
        assert!(!answer.contains("\"error\""), "{answer}");
        eprintln!(
            "export_read_end, {rows} ids ({lists} bytes of lists): peak {peak} bytes, {} per id, {:.2}x the lists",
            peak / rows,
            peak as f64 / lists as f64
        );
        assert!(peak <= 2 * lists, "{rows} ids: {:.2}x the lists, over 2x", peak as f64 / lists as f64);
    }
}
