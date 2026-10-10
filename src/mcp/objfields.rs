//! Field-value rendering for the MCP `inspect_object` tool.
//!
//! This is the MCP face of the same seek-based reader the CLI's `heap inspect`
//! uses: with a dense object index and the cache's `offsets.bin`, one object's
//! field values are a `seek` plus a few dozen bytes of reads — no rescan of the
//! dump. `src/objread.rs` is the reader; this module turns its output into the
//! JSON shape an MCP caller sees.
//!
//! Why the rendering is duplicated rather than shared with `main.rs`: the CLI
//! renders through `print!`-oriented helpers that live in the binary, and the
//! binary is not a dependency of the library. The *semantics* below are kept
//! deliberately identical to `heap inspect`'s — same notes, same caps, same
//! `{"@ref","@index","@class","@text"}` reference shape — so an MCP caller and
//! a CLI caller see the same object.
//!
//! Degradation is loud, never silent: when the values cannot be read, the
//! caller gets `fields: null` plus a `fields_note` saying why. An empty object
//! would read as "this object has no fields", which is a different (and false)
//! statement.

use std::path::Path;

use crate::cache::CachedSession;
use crate::objread;
use crate::types::HprofType;

/// Why no field values could be produced, when the cache has no offset table.
/// Same wording as the CLI's note, so both faces explain the same gap.
pub const NO_OFFSETS_NOTE: &str = "this cache has no object-offset table (it predates offset \
     capture). Re-analyze the dump to read field values.";
/// The offsets index the *decompressed* stream, so they are file offsets only
/// for an uncompressed dump. Say so rather than silently rescanning.
pub const COMPRESSED_NOTE: &str = "the dump is compressed (gzip/zip), so record offsets are not \
     directly seekable; uncompress it and re-analyze to read fields.";
const CLASS_OBJECT_NOTE: &str = "this object is a class object; it has no HPROF record to decode";
const NO_RECORD_NOTE: &str = "no HPROF record offset recorded for this object";

/// Render object `idx`'s field values, or explain why they cannot be read.
///
/// Returns `(fields, note)`. Exactly one of the two is `Some`:
///   * `(Some(json), None)` — the object was decoded (its address is inside the
///     JSON as `@address`);
///   * `(None, Some(note))` — it could not be, and `note` says why.
pub fn render_fields(
    sess: &CachedSession,
    class_idx: &[u32],
    idx: usize,
) -> (Option<serde_json::Value>, Option<String>) {
    match try_render_fields(sess, class_idx, idx) {
        Ok(v) => (Some(v), None),
        Err(note) => (None, Some(note)),
    }
}

fn try_render_fields(
    sess: &CachedSession,
    class_idx: &[u32],
    idx: usize,
) -> Result<serde_json::Value, String> {
    let kind = sess.pass1.kind.get(idx).copied().unwrap_or(0);

    // 1. The object-offset table. Present on any cache this version wrote.
    let offsets = match sess.cache.read_hprof_offsets() {
        Ok(Some(o)) => o,
        Ok(None) => return Err(NO_OFFSETS_NOTE.into()),
        Err(e) => return Err(format!("could not read the object-offset table: {e}")),
    };

    // 2. Class objects have no HPROF record (pass 1 records offset 0 for them).
    if kind == 3 {
        return Err(CLASS_OBJECT_NOTE.into());
    }
    let offset = offsets.get(idx).copied().unwrap_or(0);
    if offset == 0 {
        return Err(NO_RECORD_NOTE.into());
    }

    // 3. Offsets index the decompressed stream; that is a file offset only for
    //    an uncompressed dump. Refuse rather than silently rescan a gzip stream.
    let path: &Path = &sess.dump_path;
    match objread::is_seekable(path) {
        Ok(true) => {}
        Ok(false) => return Err(COMPRESSED_NOTE.into()),
        Err(e) => {
            return Err(format!(
                "could not open the dump at {}: {e}",
                path.display()
            ));
        }
    }

    if kind == 0 {
        render_instance(sess, class_idx, offset, &offsets)
    } else {
        render_array(sess, class_idx, offset, &offsets)
    }
}

/// Render a plain instance's fields.
///
/// A field whose value is a reference to a `java.lang.String` also carries the
/// decoded text: without it the most interesting field of most objects (the
/// string it holds) reads as an opaque `byte[]` the caller has to chase.
fn render_instance(
    sess: &CachedSession,
    class_idx: &[u32],
    offset: u64,
    offsets: &[u64],
) -> Result<serde_json::Value, String> {
    let (addr, _class_addr, fields) = match objread::read_instance_at(
        &sess.dump_path,
        offset,
        &sess.pass1.class_map,
        &sess.pass1.strings,
        sess.pass1.id_size as usize,
    ) {
        Ok(Some(t)) => t,
        Ok(None) => return Err("no INSTANCE_DUMP record at the recorded offset".into()),
        Err(e) => return Err(format!("could not decode this object: {e}")),
    };

    // A subclass field may shadow an inherited one of the same simple name;
    // qualify those with their declaring class so none is lost.
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for f in &fields {
        *counts.entry(f.name.as_str()).or_insert(0) += 1;
    }
    let mut map = serde_json::Map::new();
    map.insert("@address".into(), serde_json::json!(format!("0x{addr:x}")));
    for f in &fields {
        let key = if counts[f.name.as_str()] > 1 {
            format!("{}.{}", f.owner.replace('/', "."), f.name)
        } else {
            f.name.clone()
        };
        let v = match &f.value {
            objread::FieldValue::Prim(v) => v.clone(),
            objread::FieldValue::Null => serde_json::Value::Null,
            objread::FieldValue::Ref(a) => ref_json(*a, sess, class_idx, offsets),
        };
        map.insert(key, v);
    }
    // Inspecting a String itself should show the string, not just its `value`.
    if let Some((text, full_len, truncated)) = string_text(sess, offsets, addr) {
        map.insert("@text".into(), serde_json::json!(text));
        if truncated {
            map.insert("@text_length".into(), serde_json::json!(full_len));
        }
    }
    Ok(serde_json::Value::Object(map))
}

/// Render an array's elements, capped at `objread::MAX_ARRAY_ELEMENTS`.
fn render_array(
    sess: &CachedSession,
    class_idx: &[u32],
    offset: u64,
    offsets: &[u64],
) -> Result<serde_json::Value, String> {
    let arr = match objread::read_array_at(
        &sess.dump_path,
        offset,
        sess.pass1.id_size as usize,
        0,
        objread::MAX_ARRAY_ELEMENTS,
    ) {
        Ok(Some(a)) => a,
        Ok(None) => return Err("no array record at the recorded offset".into()),
        Err(e) => return Err(format!("could not decode this array: {e}")),
    };
    let mut o = serde_json::Map::new();
    o.insert(
        "@address".into(),
        serde_json::json!(format!("0x{:x}", arr.addr)),
    );
    o.insert(
        "@kind".into(),
        serde_json::json!(if arr.elem_ty.is_some() {
            "primitive array"
        } else {
            "object array"
        }),
    );
    o.insert("@element_count".into(), serde_json::json!(arr.count));
    match arr.elem_ty {
        Some(ty) => {
            o.insert("@element_type".into(), serde_json::json!(type_name(ty)));
        }
        None => {
            if let Some(n) = class_name_at(sess, arr.elem_class_addr) {
                o.insert(
                    "@element_class".into(),
                    serde_json::json!(n.replace('/', ".")),
                );
            }
        }
    }
    o.insert(
        "elements".into(),
        serde_json::Value::Array(
            arr.values
                .iter()
                .map(|v| match v {
                    objread::FieldValue::Prim(v) => v.clone(),
                    objread::FieldValue::Null => serde_json::Value::Null,
                    objread::FieldValue::Ref(a) => ref_json(*a, sess, class_idx, offsets),
                })
                .collect(),
        ),
    );
    if arr.truncated() {
        o.insert("@truncated".into(), serde_json::json!(true));
    }
    Ok(serde_json::Value::Object(o))
}

/// The slash-form name of the class object at `class_addr` (the form
/// `pass1::strings` holds; callers dot it for display).
fn class_name_at(sess: &CachedSession, class_addr: u64) -> Option<String> {
    let ci = sess.pass1.class_map.get(&class_addr)?;
    sess.pass1.strings.get(&ci.name_id).cloned()
}

/// Render an object reference as `{"@ref","@index","@class"}` — the target's
/// address plus its dense index (so it can be fed back to `inspect_object`) —
/// never a recursive expansion. Adds `@text` when the target is a
/// `java.lang.String`, so a string-valued field reads as text.
fn ref_json(
    addr: u64,
    sess: &CachedSession,
    class_idx: &[u32],
    offsets: &[u64],
) -> serde_json::Value {
    let mut o = serde_json::Map::new();
    o.insert("@ref".into(), serde_json::json!(format!("0x{addr:x}")));
    if let Some(i) = sess.index_of_addr(addr) {
        o.insert("@index".into(), serde_json::json!(i));
        if let Some(&ci) = class_idx.get(i) {
            if let Some(n) = sess.class_names.get(ci as usize) {
                o.insert("@class".into(), serde_json::json!(n));
            }
        }
    }
    if let Some((text, full_len, truncated)) = string_text(sess, offsets, addr) {
        o.insert("@text".into(), serde_json::json!(text));
        if truncated {
            o.insert("@text_length".into(), serde_json::json!(full_len));
        }
    }
    serde_json::Value::Object(o)
}

/// Decode the `java.lang.String` at `addr` into `(text, full_len, truncated)`.
///
/// `None` for anything that is not a String, or whose bytes cannot be reached —
/// a String we cannot read must not fail the whole `inspect_object`.
///
/// Covers both layouts: Java 9+ compact strings (`byte[] value` + `byte coder`,
/// 0 = LATIN1, 1 = UTF-16) and pre-9 (`char[] value` + `int offset` + `int count`).
fn string_text(sess: &CachedSession, offsets: &[u64], addr: u64) -> Option<(String, u64, bool)> {
    let path: &Path = &sess.dump_path;
    let id_size = sess.pass1.id_size as usize;
    let idx = sess.index_of_addr(addr)?;
    // Only a plain instance can be a String. Anything else — an array, a class
    // object — is an expected miss, so it must not fall through to the
    // error-swallowing read below and be mistaken for a read failure.
    if sess.pass1.kind.get(idx).copied().unwrap_or(0) != 0 {
        return None;
    }
    let offset = *offsets.get(idx)?;
    if offset == 0 {
        return None;
    }
    let (_, class_addr, fields) = objread::read_instance_at(
        path,
        offset,
        &sess.pass1.class_map,
        &sess.pass1.strings,
        id_size,
    )
    .ok()??;
    if class_name_at(sess, class_addr).as_deref() != Some("java/lang/String") {
        return None;
    }
    let (mut value_addr, mut coder, mut joffset, mut jcount) = (None, 0i64, None, None);
    for f in &fields {
        match (f.name.as_str(), &f.value) {
            ("value", objread::FieldValue::Ref(a)) => value_addr = Some(*a),
            ("coder", objread::FieldValue::Prim(v)) => coder = v.as_i64().unwrap_or(0),
            ("offset", objread::FieldValue::Prim(v)) => joffset = v.as_i64(),
            ("count", objread::FieldValue::Prim(v)) => jcount = v.as_i64(),
            _ => {}
        }
    }
    let vi = sess.index_of_addr(value_addr?)?;
    let voff = *offsets.get(vi)?;
    if voff == 0 {
        return None;
    }
    // Pre-9 a String may share a `char[]` and own a window of it, so start the
    // read at that window rather than at element 0: a String whose text begins
    // past the cap must still decode, not come back empty.
    let skip = joffset.unwrap_or(0).max(0) as u64;
    let arr =
        objread::read_array_at(path, voff, id_size, skip, objread::MAX_STRING_CHARS).ok()??;
    let ty = arr.elem_ty?;
    let text = match ty {
        HprofType::Byte => objread::text_from_bytes(&arr.values, coder),
        // A shared `char[]` may extend past this String's own window.
        HprofType::Char => {
            let n = jcount
                .map(|c| c.max(0) as usize)
                .unwrap_or(arr.values.len())
                .min(arr.values.len());
            objread::text_from_chars(&arr.values[..n])
        }
        _ => return None,
    };
    let full_chars = full_char_len(ty, coder, arr.count, jcount);
    let truncated = full_chars > text.chars().count() as u64;
    let text: String = text.chars().take(objread::MAX_STRING_CHARS).collect();
    Some((text, full_chars, truncated))
}

/// How many characters the String's *full* text holds.
///
/// Java 9+ stores exactly the String's characters in `value`, so that array's
/// element count is the character count — halved for UTF-16, which packs two
/// bytes per character. A pre-9 `char[]` may be shared between Strings, so the
/// String's own `count` is authoritative when present.
fn full_char_len(ty: HprofType, coder: i64, arr_count: u64, jcount: Option<i64>) -> u64 {
    match ty {
        HprofType::Byte if coder == 1 => arr_count / 2,
        HprofType::Byte => arr_count,
        HprofType::Char => jcount.map(|c| c.max(0) as u64).unwrap_or(arr_count),
        _ => arr_count,
    }
}

fn type_name(ty: HprofType) -> &'static str {
    match ty {
        HprofType::Object => "object",
        HprofType::Boolean => "boolean",
        HprofType::Char => "char",
        HprofType::Float => "float",
        HprofType::Double => "double",
        HprofType::Byte => "byte",
        HprofType::Short => "short",
        HprofType::Int => "int",
        HprofType::Long => "long",
    }
}
