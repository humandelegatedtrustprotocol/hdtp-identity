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
//!   With removed threads (SEP-0004), 2026-10-10: 2.9× for contacts' threads; 3.3–3.4× for a file
//!   whose every thread is removed with a root of its own (each also keeps a 36-byte record and some 44
//!   bytes of names in the answer), the largest such threads.csv peaking at 56.1 MB beside its 17.0 MB
//!   of argument text (6.1× and 104.8 MB before a removed thread's names were left out of the record);
//!   3.4× for 64,000 of them holding the 65,536 control characters `CONTROL_MAX` lets through. At the
//!   largest legal threads.csv: every topic 1000 line feeds or tabs, which the answer writes as two
//!   bytes each, 2.98× (3.16× before the answer's room counted them); every thread removed under one
//!   root with names of 200 characters, 2.41× (40.5 MB). A member denser with U+0001, which a JSON
//!   answer writes as six bytes, is refused before it is parsed, at a peak of 2.0–2.4× its CSV (15.8×
//!   before, building an answer six times it).
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

/// The export_read arguments of a file of 200 contacts and `rows` threads, or, when `removed`, the same
/// rows each a removed thread with a root of its own (SPEC §9.2): what the reader keeps of a removed
/// thread, on every row.
fn a_file_of(rows: usize, removed: bool) -> File {
    if removed {
        a_file_with(rows, |i, t| t["contact"] = serde_json::json!(fp(1000 + i)))
    } else {
        a_file_with(rows, |_, _| {})
    }
}

/// `a_file_of`'s contacts and `rows` threads, each handed to `edit` before export_write writes it.
fn a_file_with(rows: usize, edit: impl Fn(usize, &mut serde_json::Value)) -> File {
    use serde_json::json;
    let owner = format!("sha256:{}A", "O".repeat(42));
    let contacts: Vec<_> = (0..200)
        .map(|i| {
            json!({ "root": fp(i), "endpoint": format!("https://c{i}.example/mcp"), "name": "", "display_name": "", "status": "active",
                "was_active": true, "permissions": [], "their_permissions": [], "added": "2026-09-01T00:00:00Z" })
        })
        .collect();
    let threads: Vec<_> = (0..rows)
        .map(|i| {
            let mut t = json!({ "id": uuid(i), "contact": fp(i % 200), "topic": "a topic", "created_at": "2026-09-01T00:00:00Z", "last_at": "2026-09-01T00:00:00Z" });
            edit(i, &mut t);
            t
        })
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
    for (rows, removed) in [(16_000, false), (64_000, false), (16_000, true), (64_000, true)] {
        let f = a_file_of(rows, removed);
        let (peak, answer) = peak_of("export_read", &f.args);
        assert!(!answer.contains("\"error\""), "{}", &answer[..answer.len().min(200)]);
        eprintln!(
            "export_read, {rows} threads, removed {removed} ({} bytes of threads.csv): peak {peak} bytes, {} per row, {:.1}x the CSV",
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
        let owner = format!("sha256:{}A", "O".repeat(42));
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

/// The largest threads.csv the format allows, every thread removed with a root of its own: the peak
/// one call holds in the Durable Object's instance, recorded as measured, and held to the same bound.
#[test]
fn export_read_of_the_largest_file_of_removed_threads() {
    let _alone = alone();
    let rows = (16 * 1024 * 1024 - 2048) / 141;
    let f = a_file_of(rows, true);
    assert!(f.csv_bytes <= 16 * 1024 * 1024 && f.csv_bytes > 16 * 1024 * 1024 - 64 * 1024, "threads.csv is {} bytes", f.csv_bytes);
    let (peak, answer) = peak_of("export_read", &f.args);
    assert!(!answer.contains("\"error\""), "{}", &answer[..answer.len().min(200)]);
    eprintln!(
        "export_read of the largest threads.csv of removed threads ({rows} threads, {} bytes; argument text {} bytes): peak {:.1} MB, {:.2}x",
        f.csv_bytes,
        f.args.len(),
        peak as f64 / 1e6,
        peak as f64 / f.csv_bytes as f64
    );
    assert!(peak <= 4 * f.csv_bytes, "{:.2}x the CSV, over 4x", peak as f64 / f.csv_bytes as f64);
}

/// `a_file_with` at the most rows whose threads.csv fits the 16 MiB SPEC §9.2 allows, within 64 KiB of
/// it: a row's size is measured on 1000 of them.
fn the_largest(edit: impl Fn(usize, &mut serde_json::Value) + Copy) -> (File, usize) {
    let (one, more) = (a_file_with(1, edit).csv_bytes, a_file_with(1001, edit).csv_bytes);
    let per = (more - one) / 1000;
    let rows = (16 * 1024 * 1024 - 4096 - (one - per)) / per;
    let f = a_file_with(rows, edit);
    assert!(f.csv_bytes <= 16 * 1024 * 1024 && f.csv_bytes > 16 * 1024 * 1024 - 64 * 1024, "threads.csv is {} bytes", f.csv_bytes);
    (f, rows)
}

/// The largest legal threads.csv that each costs the reader most per byte, as this library's writer
/// writes it, each within the same 4x: every topic a run of line feeds (or tabs), which the answer
/// writes as two bytes each, and every thread removed under ONE root with two names of 200 characters,
/// which the reader compares rather than keeps.
#[test]
fn export_read_of_the_costliest_largest_files() {
    let _alone = alone();
    let lf = |_: usize, t: &mut serde_json::Value| t["topic"] = serde_json::json!("\n".repeat(1000));
    let tab = |_: usize, t: &mut serde_json::Value| t["topic"] = serde_json::json!(format!("a{}", "\t".repeat(1000)));
    let one_root = |_: usize, t: &mut serde_json::Value| {
        t["contact"] = serde_json::json!(fp(1000));
        t["contact_name"] = serde_json::json!("n".repeat(200));
        t["contact_display_name"] = serde_json::json!("d".repeat(200));
    };
    for (what, (f, rows)) in [
        ("every topic 1000 line feeds", the_largest(lf)),
        ("every topic 1000 tabs", the_largest(tab)),
        ("every thread removed under one root, names of 200 characters", the_largest(one_root)),
    ] {
        let (peak, answer) = peak_of("export_read", &f.args);
        assert!(!answer.contains("\"error\""), "{}", &answer[..answer.len().min(200)]);
        eprintln!(
            "export_read of the largest threads.csv, {what} ({rows} threads, {} bytes; argument text {} bytes): peak {:.1} MB, {:.2}x",
            f.csv_bytes,
            f.args.len(),
            peak as f64 / 1e6,
            peak as f64 / f.csv_bytes as f64
        );
        assert!(peak <= 4 * f.csv_bytes, "{what}: {:.2}x the CSV, over 4x", peak as f64 / f.csv_bytes as f64);
    }
}

/// `a_file_of`'s file of removed threads with every topic and both names of every thread `per`
/// characters U+0001 (each six bytes as JSON: `\u0001`), the manifest re-hashed: what a writer no longer writes,
/// and a reader is handed all the same.
fn a_control_file(rows: usize, per: usize) -> File {
    a_control_file_on(rows, per, rows)
}

/// `a_control_file` with only the first `on` rows so written.
fn a_control_file_on(rows: usize, per: usize, on: usize) -> File {
    let f = a_file_of(rows, true);
    let mut a: serde_json::Value = serde_json::from_str(&f.args).unwrap();
    let c = "\u{1}".repeat(per);
    let csv =
        a["threads_csv"].as_str().unwrap().replacen(",a topic,", &format!(",{c},"), on).replacen(",,\r\n", &format!(",{c},{c}\r\n"), on);
    let mut m: serde_json::Value = serde_json::from_str(a["manifest"].as_str().unwrap()).unwrap();
    m["files"]["threads.csv"] = serde_json::json!(hdtp_identity::util::hex(&hdtp_identity::util::sha256(csv.as_bytes())));
    let csv_bytes = csv.len();
    a["threads_csv"] = serde_json::json!(csv);
    a["manifest"] = serde_json::json!(hdtp_identity::canonical::canonical(&m));
    File { args: a.to_string(), csv_bytes }
}

/// A member dense with U+0001, which a JSON answer writes as six bytes each, is refused before it is
/// parsed, at N and 4N rows and at the largest the format allows, holding less than its argument; one
/// at the ceiling is read within the bound. Before the ceiling, a threads.csv of removed threads named
/// and titled with U+0001 peaked at 15.8× its size, building an answer six times it.
#[test]
fn control_characters_are_bounded_where_they_enter() {
    let _alone = alone();
    for rows in [4_000, 16_000, (16 * 1024 * 1024 - 2048) / 741] {
        let f = a_control_file(rows, 200);
        let (peak, answer) = peak_of("export_read", &f.args);
        assert!(answer.contains("characters below U+0020"), "{}", &answer[..answer.len().min(200)]);
        eprintln!(
            "export_read refusing {rows} threads dense with U+0001 ({} bytes of threads.csv, {} of argument): peak {:.1} MB, {:.2}x the CSV",
            f.csv_bytes,
            f.args.len(),
            peak as f64 / 1e6,
            peak as f64 / f.csv_bytes as f64
        );
        assert!(peak <= 4 * f.csv_bytes, "{rows} rows: {:.2}x the CSV, over 4x", peak as f64 / f.csv_bytes as f64);
    }
    // At the ceiling: 64,000 threads, a topic and two names of one U+0001 each on as many of them as
    // the ceiling takes.
    let (rows, on) = (64_000, hdtp_identity::export::CONTROL_MAX / 3);
    let mut f = a_control_file_on(rows, 1, on);
    // And the one more that makes it exactly the ceiling.
    let extra = hdtp_identity::export::CONTROL_MAX - 3 * on;
    let mut a: serde_json::Value = serde_json::from_str(&f.args).unwrap();
    let csv = a["threads_csv"].as_str().unwrap().replacen(",a topic,", &format!(",{},", "\u{1}".repeat(extra)), 1);
    let mut m: serde_json::Value = serde_json::from_str(a["manifest"].as_str().unwrap()).unwrap();
    m["files"]["threads.csv"] = serde_json::json!(hdtp_identity::util::hex(&hdtp_identity::util::sha256(csv.as_bytes())));
    f.csv_bytes = csv.len();
    a["threads_csv"] = serde_json::json!(csv);
    a["manifest"] = serde_json::json!(hdtp_identity::canonical::canonical(&m));
    f.args = a.to_string();
    let (peak, answer) = peak_of("export_read", &f.args);
    assert!(!answer.contains("\"error\""), "{}", &answer[..answer.len().min(200)]);
    eprintln!(
        "export_read of {rows} threads holding {} control characters ({} bytes): {:.2}x",
        hdtp_identity::export::CONTROL_MAX,
        f.csv_bytes,
        peak as f64 / f.csv_bytes as f64
    );
    assert!(peak <= 4 * f.csv_bytes, "at the ceiling: {:.2}x the CSV, over 4x", peak as f64 / f.csv_bytes as f64);
}
