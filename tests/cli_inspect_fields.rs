//! `heap inspect` field values: the seek-based reader, and its degradation.
//!
//! The feature exists so that reading one object's fields does not require
//! re-scanning the dump — the OQL `toString(s)` path does, which costs ~50
//! minutes on a 44 GB dump and stalls the whole server. These tests pin the
//! user-facing contract: correct values, and a *loud* refusal (never a silent
//! empty object) when the offsets needed to seek are absent.

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_hprof-analyzer");

fn fixture() -> Option<PathBuf> {
    let p =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dump_4_philosophers.hprof");
    match std::fs::metadata(&p) {
        Ok(m) if m.len() >= 1024 => Some(p),
        _ => None,
    }
}

/// Copy the fixture into a scratch dir so the test owns (and may mutate) its
/// cache without racing the gitignored cache the rest of the suite shares.
fn staged_copy(tag: &str) -> Option<(PathBuf, PathBuf)> {
    let src = fixture()?;
    let dir = std::env::temp_dir().join(format!("hprof_inspect_{}_{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let dump = dir.join("dump.hprof");
    std::fs::copy(&src, &dump).ok()?;
    Some((dir, dump))
}

/// The single `cache/<hash>` directory `CacheDir::for_dump` created for `dump`.
fn cache_dir(dump: &Path) -> Option<PathBuf> {
    let base = PathBuf::from(format!("{}.hprof-cache", dump.display()));
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&base)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    entries.pop()
}

fn inspect_json(dump: &Path, idx: u64) -> serde_json::Value {
    let out = Command::new(BIN)
        .args(["heap", "inspect"])
        .arg(dump)
        .args(["--index", &idx.to_string(), "--json"])
        .output()
        .expect("spawn heap inspect");
    assert!(
        out.status.success(),
        "heap inspect failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("inspect --json output must be JSON")
}

/// Field values are decoded from the dump and match the object's real contents.
///
/// Object 100 of this fixture is a `java.util.HashMap$Node`: `hash` is a
/// primitive, `key`/`value` are references to Strings, `next` is a null
/// reference — one of each shape the reader has to render.
#[test]
fn inspect_decodes_field_values() {
    let Some((_dir, dump)) = staged_copy("fields") else {
        return;
    };
    // Builds the cache *and* the object-offset table.
    let load = Command::new(BIN)
        .args(["heap", "load"])
        .arg(&dump)
        .output()
        .unwrap();
    assert!(load.status.success(), "heap load failed");
    assert!(
        cache_dir(&dump)
            .map(|d| d.join("offsets.bin").exists())
            .unwrap_or(false),
        "heap load must write offsets.bin"
    );

    let obj = inspect_json(&dump, 100);
    assert_eq!(obj["class"], "java.util.HashMap$Node");
    assert_eq!(obj["address"], "0x80100c40");
    let f = &obj["fields"];
    assert_eq!(f["hash"], 119777, "primitive int field");
    assert_eq!(f["next"], serde_json::Value::Null, "null reference");
    // A reference is its address plus a dense index, never a nested expansion.
    assert_eq!(f["key"]["@ref"], "0xffe45968");
    assert_eq!(f["key"]["@index"], 226452);
    assert_eq!(f["key"]["@class"], "java.lang.String");
    assert_eq!(f["value"]["@ref"], "0xffe69fb8");
}

/// Negative control: with no offset table the reader must say so — not print an
/// empty object, which would read as "this object has no fields".
#[test]
fn inspect_without_offsets_degrades_loudly() {
    let Some((_dir, dump)) = staged_copy("noff") else {
        return;
    };
    let load = Command::new(BIN)
        .args(["heap", "load"])
        .arg(&dump)
        .output()
        .unwrap();
    assert!(load.status.success(), "heap load failed");
    let cd = cache_dir(&dump).expect("cache dir");
    std::fs::remove_file(cd.join("offsets.bin")).expect("remove offsets.bin");

    let obj = inspect_json(&dump, 100);
    // The rest of the report still works...
    assert_eq!(obj["class"], "java.util.HashMap$Node");
    assert!(obj["shallow_bytes"].is_number());
    // ...and the missing piece is reported, not silently empty.
    assert_eq!(obj["fields"], serde_json::Value::Null);
    let note = obj["fields_note"].as_str().unwrap_or("");
    assert!(
        note.contains("no object-offset table"),
        "expected an explanatory note, got {note:?}"
    );
}

/// A `String`-valued field carries the decoded text, not just a `byte[]` the
/// caller would have to chase: `key` here points at a `java.lang.String`.
#[test]
fn inspect_inlines_string_field_text() {
    let Some((_dir, dump)) = staged_copy("strfld") else {
        return;
    };
    let load = Command::new(BIN)
        .args(["heap", "load"])
        .arg(&dump)
        .output()
        .unwrap();
    assert!(load.status.success(), "heap load failed");

    let obj = inspect_json(&dump, 100);
    let key = &obj["fields"]["key"];
    assert_eq!(key["@class"], "java.lang.String");
    assert_eq!(
        key["@text"], "ymt",
        "string-valued field must carry its text"
    );
}

/// Inspecting a `String` itself shows the text, not only its `value` byte[].
#[test]
fn inspect_string_object_shows_text() {
    let Some((_dir, dump)) = staged_copy("strobj") else {
        return;
    };
    let load = Command::new(BIN)
        .args(["heap", "load"])
        .arg(&dump)
        .output()
        .unwrap();
    assert!(load.status.success(), "heap load failed");

    let s = inspect_json(&dump, 226452);
    assert_eq!(s["class"], "java.lang.String");
    assert_eq!(s["fields"]["@text"], "ymt");
    // The raw fields are still there alongside the decoded text.
    assert_eq!(s["fields"]["hash"], 119776);
    assert_eq!(s["fields"]["coder"], 0);
}

/// Arrays are decoded now: elements (capped), element type, and the true count.
///
/// Object 72895 is a `byte[]`; the point is that a reference chain no longer
/// dead-ends here — `String.value` → `byte[]` used to be unreadable.
#[test]
fn inspect_decodes_array_elements() {
    let Some((_dir, dump)) = staged_copy("arr") else {
        return;
    };
    let load = Command::new(BIN)
        .args(["heap", "load"])
        .arg(&dump)
        .output()
        .unwrap();
    assert!(load.status.success(), "heap load failed");

    let arr = inspect_json(&dump, 72895);
    assert_eq!(arr["class"], "byte[]");
    let f = &arr["fields"];
    assert_eq!(f["@kind"], "primitive array");
    assert_eq!(f["@element_type"], "byte");
    assert!(
        f["@element_count"].is_number(),
        "must report the true count"
    );
    assert!(f["elements"].is_array(), "elements must be a list");
}

/// A class object has no HPROF record; it must say that rather than read garbage
/// or print an empty object.
#[test]
fn inspect_class_object_reports_no_record() {
    let Some((_dir, dump)) = staged_copy("cls") else {
        return;
    };
    let load = Command::new(BIN)
        .args(["heap", "load"])
        .arg(&dump)
        .output()
        .unwrap();
    assert!(load.status.success(), "heap load failed");

    // Object 233903 is a `java.lang.Class` (kind 3).
    let cls = inspect_json(&dump, 233903);
    assert_eq!(cls["class"], "java.lang.Class");
    assert_eq!(cls["fields"], serde_json::Value::Null);
    assert!(
        cls["fields_note"]
            .as_str()
            .unwrap_or("")
            .contains("class object"),
        "class object must report why it has no fields, got {:?}",
        cls["fields_note"]
    );
}
