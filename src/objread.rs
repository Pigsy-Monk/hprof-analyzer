//! Read one object's field values straight out of the HPROF dump, by byte
//! offset — no rescan.
//!
//! The analysis pipeline records, per dense object index, the byte offset of
//! that object's record in the (decompressed) HPROF stream
//! (`Pass1::hprof_offsets`, persisted as the cache's `offsets.bin`). With that
//! offset and a *seekable* dump, decoding one object's fields costs a single
//! `seek` plus a few dozen bytes of reads, regardless of how large the dump is.
//!
//! That is the whole point: the OQL `toString(s)` path answers the same question
//! by re-scanning the dump (~50 minutes on 44 GB) and it serializes behind the
//! server's single query slot, so one such query stalls every other client.
//! Reading by offset has neither cost.
//!
//! Scope: `INSTANCE_DUMP` records only (what a plain Java object — e.g.
//! `FareSearchRequest` — is). Arrays and class objects report their kind and
//! are left to the array/class paths.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::pass1::ClassInfo;
use crate::types::HprofType;

/// HPROF heap-dump sub-record tag for a plain object instance.
const INSTANCE_DUMP: u8 = 0x21;

/// One decoded field of an instance.
pub struct InstanceField {
    /// Slash-form name of the class that declares this field. Needed to
    /// disambiguate a subclass field that shadows an inherited one of the same
    /// simple name (e.g. a Scala `PhantomReference.name` over `Thread.name`).
    pub owner: String,
    pub name: String,
    pub ty: HprofType,
    pub value: FieldValue,
}

/// A field's decoded value. Object references are kept as raw addresses —
/// deliberately NOT followed, so the output stays a single object's contents
/// rather than an unbounded tree.
pub enum FieldValue {
    /// Primitive rendered for JSON (numbers, booleans, single-char strings).
    Prim(serde_json::Value),
    /// A non-null object reference: the target's address.
    Ref(u64),
    /// A null object reference.
    Null,
}

/// Whether `path` can be read at an arbitrary byte offset cheaply.
///
/// `Pass1::hprof_offsets` are positions in the *decompressed* stream. For a
/// plain (uncompressed) `.hprof` those are also file offsets, so a `seek` is
/// enough. For gzip / zip / tar.gz inputs they are not, and reaching one would
/// mean decompressing everything before it — exactly the rescan this module
/// exists to avoid — so callers must refuse rather than silently do that.
pub fn is_seekable(path: &Path) -> io::Result<bool> {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    if lower.ends_with(".gz") || lower.ends_with(".tgz") || lower.ends_with(".zip") {
        return Ok(false);
    }
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    let gzip = n >= 2 && magic[..2] == [0x1f, 0x8b];
    let zip = n >= 2 && magic[..2] == [0x50, 0x4b];
    Ok(!gzip && !zip)
}

/// Read the `INSTANCE_DUMP` record at `offset` and decode its fields.
///
/// Returns `(object_addr, class_addr, fields)`; `Ok(None)` when `offset` is `0`,
/// which is the sentinel the pipeline writes for class objects (they have no
/// raw HPROF record — see `pass1::scan_heap_segment`).
pub fn read_instance_at(
    path: &Path,
    offset: u64,
    class_map: &HashMap<u64, ClassInfo>,
    strings: &HashMap<u64, String>,
    id_size: usize,
) -> io::Result<Option<(u64, u64, Vec<InstanceField>)>> {
    if offset == 0 {
        return Ok(None);
    }
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut head = [0u8; 1];
    f.read_exact(&mut head)?;
    if head[0] != INSTANCE_DUMP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "expected INSTANCE_DUMP (0x{INSTANCE_DUMP:02x}) at offset {offset}, \
                 found 0x{:02x} — offsets.bin is stale or the dump changed",
                head[0]
            ),
        ));
    }
    let mut buf = vec![0u8; id_size + 4 + id_size + 4];
    f.read_exact(&mut buf)?;
    let obj_addr = be_u64(&buf[0..id_size]);
    let class_addr = be_u64(&buf[id_size + 4..id_size + 4 + id_size]);
    let data_len = be_u64(&buf[id_size + 4 + id_size..]) as usize;
    if data_len > (1 << 30) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("implausible INSTANCE_DUMP data_len {data_len} at offset {offset}"),
        ));
    }
    let mut blob = vec![0u8; data_len];
    f.read_exact(&mut blob)?;

    let fields = decode_fields(class_addr, &blob, class_map, strings, id_size);
    Ok(Some((obj_addr, class_addr, fields)))
}

/// Walk the class's super-chain (child → parent, the order HPROF lays instance
/// field values down in) and decode each field out of `blob`.
///
/// The layout matches `pass2::sizing::field_offset`, which the query engine's
/// `SELECT s.field` uses — the two must agree, so this walks the chain the same
/// way (accumulating widths child-first) rather than re-deriving the rule.
fn decode_fields(
    class_addr: u64,
    blob: &[u8],
    class_map: &HashMap<u64, ClassInfo>,
    strings: &HashMap<u64, String>,
    id_size: usize,
) -> Vec<InstanceField> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut cur = class_addr;
    // Guard against a malformed cycle in super_id rather than looping forever.
    let mut hops = 0usize;
    while let Some(ci) = class_map.get(&cur) {
        hops += 1;
        if hops > 10_000 {
            break;
        }
        let owner = strings
            .get(&ci.name_id)
            .cloned()
            .unwrap_or_else(|| format!("<class@0x{cur:x}>"));
        for &(fname_id, ty) in &ci.fields {
            let size = if ty == HprofType::Object {
                id_size
            } else {
                ty.byte_size()
            };
            let name = strings
                .get(&fname_id)
                .cloned()
                .unwrap_or_else(|| format!("<field@{fname_id:x}>"));
            // A truncated blob (shouldn't happen, but a corrupt dump must not
            // panic) yields nulls for the tail fields.
            let value = match blob.get(off..off + size) {
                Some(bytes) => decode_value(ty, bytes, id_size),
                None => FieldValue::Null,
            };
            out.push(InstanceField {
                owner: owner.clone(),
                name,
                ty,
                value,
            });
            off += size;
        }
        if ci.super_id == 0 {
            break;
        }
        cur = ci.super_id;
    }
    out
}

fn decode_value(ty: HprofType, bytes: &[u8], id_size: usize) -> FieldValue {
    match ty {
        HprofType::Object => {
            let addr = be_u64(&bytes[..id_size.min(bytes.len())]);
            if addr == 0 {
                FieldValue::Null
            } else {
                FieldValue::Ref(addr)
            }
        }
        HprofType::Boolean => FieldValue::Prim(serde_json::Value::Bool(bytes[0] != 0)),
        HprofType::Byte => FieldValue::Prim(serde_json::json!(bytes[0] as i8)),
        HprofType::Char => {
            let c = be_u64(bytes) as u32;
            FieldValue::Prim(serde_json::Value::String(
                char::from_u32(c).map(String::from).unwrap_or_default(),
            ))
        }
        HprofType::Short => FieldValue::Prim(serde_json::json!(be_u64(bytes) as u16 as i16)),
        HprofType::Int => FieldValue::Prim(serde_json::json!(be_u64(bytes) as u32 as i32)),
        HprofType::Long => FieldValue::Prim(serde_json::json!(be_u64(bytes) as i64)),
        HprofType::Float => {
            let x = f32::from_bits(be_u64(bytes) as u32) as f64;
            FieldValue::Prim(f64_json(x))
        }
        HprofType::Double => {
            let x = f64::from_bits(be_u64(bytes));
            FieldValue::Prim(f64_json(x))
        }
    }
}

/// `serde_json` has no representation for NaN / ±Inf; render those as strings
/// rather than dropping the field or emitting invalid JSON.
fn f64_json(x: f64) -> serde_json::Value {
    match serde_json::Number::from_f64(x) {
        Some(n) => serde_json::Value::Number(n),
        None => serde_json::Value::String(x.to_string()),
    }
}

/// Big-endian unsigned read of up to 8 bytes (HPROF is a big-endian format).
fn be_u64(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in bytes.iter().take(8) {
        v = (v << 8) | b as u64;
    }
    v
}
