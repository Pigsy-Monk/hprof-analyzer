//! Regression test for `ClassImpl.instanceSize` in the emitted MAT `.index`.
//!
//! `mat::compute_instance_sizes` mirrors MAT's
//! `HprofParserHandlerImpl.calculateInstanceSize`: it walks the superclass chain
//! and sizes every object-reference field with `MatClassMeta::ref_size`. That
//! field starts out as the HPROF `id_size` (8) and must be corrected to the
//! reference width pass 2 actually detected (4 on a compressed-oops dump)
//! **before** `compute_instance_sizes` runs — it also uses `ref_size` as the
//! intermediate alignment modulus.
//!
//! When the correction happened *after* that call, every non-array
//! `ClassImpl.instanceSize` came out inflated (`java.lang.String` 32 instead of
//! 24), contradicting the `a2s`/`o2ret` tables — both built from the native
//! 4-byte shallow — and producing the "shallow 152 > retained 96" nonsense seen
//! in MAT's Class Histogram on real compressed-oops dumps.
//!
//! The test runs the real binary over a committed compressed-oops fixture with
//! `--mat`, decodes the emitted `.index` (a Java object-serialization stream)
//! and checks `instanceSize` against MAT's own `heapSizePerInstance` values.
//! Those are the same numbers the native report prints as the per-instance
//! shallow size, so they are checkable without MAT installed.
//!
//! The expected values are frozen with the fixture dump and never drift.
//!
//! Two further tests in this file use the same decoder:
//!
//! * `index_folds_alias_rows_into_one_class_impl` checks
//!   `ClassImpl.instanceCount`: histogram rows that resolve to the same class
//!   object (a canonical row plus per-loader "alias" rows) must fold into ONE
//!   `ClassImpl` with their counts summed, otherwise MAT's histogram loses a
//!   whole class's worth of instances.
//! * `unreachable_class_objects_use_the_class_objects_own_shallow` checks the
//!   `UnreachableObjectsHistogram` `SnapshotInfo` property record by record
//!   against MAT's own master `.index` for the `dump_7_gauss-mix` fixture.

use std::path::Path;
use std::process::Command;

const FIXTURE: &str = "tests/fixtures/dump_1_mnemonics.hprof";
const PREFIX: &str = "dump_1_mnemonics";

/// `(class name as MAT records it, MAT's heapSizePerInstance)`.
///
/// The first six carry object references, so they are only right when
/// `ref_size` is the detected 4 — these are the ones that regress.
/// `java.lang.Object` and `java.lang.Long` have no reference fields and are the
/// same either way; they pin that the fix does not *over*-correct.
const EXPECTED: &[(&str, i32)] = &[
    ("java.lang.String", 24),
    ("java.lang.Integer", 16),
    ("java.util.ArrayList", 24),
    ("java.util.HashSet", 16),
    ("java.lang.Thread", 104),
    ("java.util.HashMap$Node", 32),
    ("java.lang.Object", 16),
    ("java.lang.Long", 24),
];

#[test]
fn index_instance_size_uses_the_detected_reference_width() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    // Committed dumps may be unhydrated LFS pointers on a bare checkout.
    match std::fs::metadata(&fixture) {
        Ok(m) if m.len() >= 1024 => {}
        _ => {
            eprintln!(
                "skip index_instance_size_uses_the_detected_reference_width: \
                       fixture absent or an LFS pointer at {}",
                fixture.display()
            );
            return;
        }
    }

    let out = std::env::temp_dir().join("hprof_mat_index_instsize");
    let Some(bytes) = emit_index(&out) else {
        return;
    };
    let mut r = Reader::new(&bytes);
    r.run();
    assert_eq!(
        r.p,
        bytes.len(),
        "decoder stopped early: the .index stream is not shaped as expected"
    );

    let mut failures = Vec::new();
    for (class, want) in EXPECTED {
        match r.class_impls.iter().find(|(n, _)| n == class) {
            Some((_, got)) if got == want => {}
            Some((_, got)) => {
                failures.push(format!("{class}: instanceSize={got}, expected {want}"));
            }
            None => failures.push(format!("{class}: no ClassImpl in the .index")),
        }
    }
    assert!(
        failures.is_empty(),
        "ClassImpl.instanceSize disagrees with MAT's heapSizePerInstance — \
         `meta.ref_size` must be set to `g.ref_size` BEFORE compute_instance_sizes:\n  {}",
        failures.join("\n  ")
    );
}

/// Run the real pipeline over the fixture with `--mat` and return the emitted
/// `PREFIX.index` bytes, or `None` when the fixture is absent (unhydrated LFS
/// pointer on a bare checkout).
fn emit_index(out: &Path) -> Option<Vec<u8>> {
    emit_index_for(FIXTURE, PREFIX, out)
}

/// As `emit_index`, for an arbitrary fixture (relative to the crate root) whose
/// emitted master index is named `<prefix>.index`.
fn emit_index_for(fixture_rel: &str, prefix: &str, out: &Path) -> Option<Vec<u8>> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join(fixture_rel);
    match std::fs::metadata(&fixture) {
        Ok(m) if m.len() >= 1024 => {}
        _ => {
            eprintln!(
                "skip: fixture absent or an LFS pointer at {}",
                fixture.display()
            );
            return None;
        }
    }

    let _ = std::fs::remove_dir_all(out);
    std::fs::create_dir_all(out).expect("create out dir");

    let bin = env!("CARGO_BIN_EXE_hprof-analyzer");
    let status = Command::new(bin)
        // Relative path from the crate root keeps `SnapshotInfo.path` stable.
        .arg(fixture_rel)
        .arg(out.join("report.md"))
        .arg("--mat")
        .arg(out)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("spawn hprof-analyzer");
    assert!(status.success(), "hprof-analyzer exited with {status:?}");

    let idx = out.join(format!("{prefix}.index"));
    Some(std::fs::read(&idx).unwrap_or_else(|e| panic!("read emitted {}: {e}", idx.display())))
}

/// `java.lang.Class`'s `ClassImpl` must count BOTH the class objects (the
/// canonical `JLC_KEY` histogram row) and the heap's real `java.lang.Class`
/// instances (the per-address alias row). Both rows resolve to the same class
/// object, so `emit_dot_index` has to fold them into ONE `ClassImpl` with the
/// counts summed; emitting one entry per row put two values under one mat-id
/// and let the later row overwrite the earlier one, so MAT's histogram
/// reported only the real instances (9 on this fixture) and summed exactly
/// `numberOfClasses` short.
///
/// The dump-independent invariant behind it: every object in the index is
/// counted under exactly one class, so the `instanceCount` of every emitted
/// `ClassImpl` must sum to `SnapshotInfo.numberOfObjects`.
#[test]
fn index_folds_alias_rows_into_one_class_impl() {
    let out = std::env::temp_dir().join("hprof_mat_index_alias_fold");
    let Some(bytes) = emit_index(&out) else {
        return;
    };
    let mut r = Reader::new(&bytes);
    r.run();

    let jlc: Vec<i32> = r
        .class_counts
        .iter()
        .filter(|(n, _)| n == "java.lang.Class")
        .map(|(_, c)| *c)
        .collect();
    assert_eq!(
        jlc.len(),
        1,
        "the class cache must hold exactly one ClassImpl per class object, \
         but {} ClassImpls are named java.lang.Class",
        jlc.len()
    );

    let (n_objects, n_classes) = r
        .snapshot_info
        .expect("SnapshotInfo missing from the emitted .index");
    assert_eq!(
        r.class_counts.len() as i32,
        n_classes,
        "the class cache must hold one ClassImpl per distinct class object"
    );
    assert!(
        jlc[0] >= n_classes,
        "java.lang.Class counts {} instances, but the dump has {n_classes} class \
         objects — the canonical JLC_KEY row was overwritten by its alias row",
        jlc[0]
    );
    let sum: i64 = r.class_counts.iter().map(|(_, c)| *c as i64).sum();
    assert_eq!(
        sum,
        n_objects as i64,
        "the ClassImpl instance counts must sum to numberOfObjects — {} objects, \
         {} counted: {} lost to an alias-row collision",
        n_objects,
        sum,
        n_objects as i64 - sum
    );
}

/// `UnreachableObjectsHistogram`: an unreachable *class object* contributes the
/// shallow size of the class object ITSELF — MAT's `ClassImpl.getUsedHeapSize`,
/// i.e. its static-field bytes — and MAT records it under the class object's own
/// class, `java.lang.Class`.
///
/// This used to accumulate the used heap size of the class each class object
/// *represents* (its retained instances' shallow sum), which is 0 for a class
/// with no retained instances — so every unreachable class object contributed
/// nothing and our `java.lang.Class` record read `452 / 0` where MAT has
/// `452 / 552`.
///
/// Oracle: MAT's own master `.index` for this fixture, committed alongside the
/// dump as `tests/fixtures/dump_7_gauss-mix.index`. Every histogram record —
/// class name, class-object address, unreachable count, summed shallow size —
/// must match MAT's, so the check is not limited to the one record the bug hit.
#[test]
fn unreachable_class_objects_use_the_class_objects_own_shallow() {
    const F: &str = "tests/fixtures/dump_7_gauss-mix.hprof";
    const P: &str = "dump_7_gauss-mix";
    const ORACLE: &str = "tests/fixtures/dump_7_gauss-mix.index";

    let out = std::env::temp_dir().join("hprof_mat_index_unreach_hist");
    let Some(bytes) = emit_index_for(F, P, &out) else {
        return;
    };
    let mut ours = Reader::new(&bytes);
    ours.run();

    // MAT's own master index for the same dump — the ground truth.
    let oracle_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(ORACLE);
    let oracle_bytes = std::fs::read(&oracle_path)
        .unwrap_or_else(|e| panic!("read oracle {}: {e}", oracle_path.display()));
    let mut mat = Reader::new(&oracle_bytes);
    mat.run();

    assert!(
        !mat.uoh_records.is_empty(),
        "the oracle {} carries no UnreachableObjectsHistogram records",
        oracle_path.display()
    );

    let mut ours_sorted = ours.uoh_records.clone();
    let mut mat_sorted = mat.uoh_records.clone();
    ours_sorted.sort();
    mat_sorted.sort();
    // Report only the differing records: a whole-list dump buries the one entry
    // a regression touched.
    let missing: Vec<_> = mat_sorted
        .iter()
        .filter(|r| !ours_sorted.contains(r))
        .collect();
    let extra: Vec<_> = ours_sorted
        .iter()
        .filter(|r| !mat_sorted.contains(r))
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "the emitted UnreachableObjectsHistogram must match MAT's own .index \
         record for record — (class name, class-object address, unreachable \
         count, summed shallow size).\n  MAT has, we lack: {missing:?}\n  we \
         emit, MAT lacks: {extra:?}"
    );

    // Name the one record the class-object rule governs, so a future regression
    // fails with a pointed message rather than a whole-list dump.
    let jlc = mat_sorted
        .iter()
        .find(|(n, _, _, _)| n == "java.lang.Class")
        .expect("MAT's histogram has a java.lang.Class record");
    let ours_jlc = ours_sorted
        .iter()
        .find(|(n, _, _, _)| n == "java.lang.Class")
        .expect("our histogram has a java.lang.Class record");
    assert_eq!(
        ours_jlc, jlc,
        "the java.lang.Class record must carry the unreachable class objects' \
         OWN shallow sizes (MAT: {} / {}), not the used heap size of the classes \
         they represent",
        jlc.2, jlc.3
    );
}

// ---------------------------------------------------------------------------
// Minimal Java object-serialization reader
//
// Only what these tests need: walk the stream correctly and collect the
// `ClassImpl` fields and the `UnreachableObjectsHistogram$Record` records.
// Written against the same grammar as `src/mat/serial.rs`'s writer.
// ---------------------------------------------------------------------------

const TC_NULL: u8 = 0x70;
const TC_REFERENCE: u8 = 0x71;
const TC_CLASSDESC: u8 = 0x72;
const TC_OBJECT: u8 = 0x73;
const TC_STRING: u8 = 0x74;
const TC_ARRAY: u8 = 0x75;
const TC_CLASS: u8 = 0x76;
const TC_BLOCKDATA: u8 = 0x77;
const TC_ENDBLOCKDATA: u8 = 0x78;
const TC_RESET: u8 = 0x79;
const TC_BLOCKDATALONG: u8 = 0x7A;
const TC_LONGSTRING: u8 = 0x7C;
const TC_PROXYCLASSDESC: u8 = 0x7D;
const TC_ENUM: u8 = 0x7E;
const BASE_HANDLE: u32 = 0x7E_0000;
const SC_WRITE_METHOD: u8 = 0x01;

#[derive(Clone)]
enum Handle {
    Desc(usize),
    Str(String),
    Other,
}

struct Desc {
    name: String,
    flags: u8,
    fields: Vec<(u8, String)>,
    superdesc: Option<usize>,
}

enum Val {
    Int(i32),
    Long(i64),
    Str(String),
    Other,
}

struct Reader<'a> {
    d: &'a [u8],
    p: usize,
    handles: Vec<Handle>,
    descs: Vec<Desc>,
    /// `(class name, instanceSize)` for every ClassImpl in the stream.
    class_impls: Vec<(String, i32)>,
    /// `(class name, instanceCount)` for every ClassImpl in the stream.
    class_counts: Vec<(String, i32)>,
    /// `(className, classAddress, objectCount, shallowHeapSize)` for every
    /// `UnreachableObjectsHistogram$Record` in the stream.
    uoh_records: Vec<(String, u64, i32, i64)>,
    /// `SnapshotInfo.numberOfObjects` / `numberOfClasses`, when seen.
    snapshot_info: Option<(i32, i32)>,
}

impl<'a> Reader<'a> {
    fn new(d: &'a [u8]) -> Self {
        Reader {
            d,
            p: 0,
            handles: Vec::new(),
            descs: Vec::new(),
            class_impls: Vec::new(),
            class_counts: Vec::new(),
            uoh_records: Vec::new(),
            snapshot_info: None,
        }
    }

    fn u8(&mut self) -> u8 {
        let v = self.d[self.p];
        self.p += 1;
        v
    }

    fn u16(&mut self) -> u16 {
        let v = u16::from_be_bytes(self.d[self.p..self.p + 2].try_into().unwrap());
        self.p += 2;
        v
    }

    fn u32(&mut self) -> u32 {
        let v = u32::from_be_bytes(self.d[self.p..self.p + 4].try_into().unwrap());
        self.p += 4;
        v
    }

    fn i32(&mut self) -> i32 {
        let v = i32::from_be_bytes(self.d[self.p..self.p + 4].try_into().unwrap());
        self.p += 4;
        v
    }

    fn i64(&mut self) -> i64 {
        let v = i64::from_be_bytes(self.d[self.p..self.p + 8].try_into().unwrap());
        self.p += 8;
        v
    }

    fn utf(&mut self) -> String {
        let n = self.u16() as usize;
        let s = String::from_utf8_lossy(&self.d[self.p..self.p + n]).into_owned();
        self.p += n;
        s
    }

    fn long_utf(&mut self) -> String {
        let n = self.i64() as usize;
        let s = String::from_utf8_lossy(&self.d[self.p..self.p + n]).into_owned();
        self.p += n;
        s
    }

    fn push_handle(&mut self, h: Handle) {
        self.handles.push(h);
    }

    fn handle(&self, h: u32) -> Handle {
        self.handles
            .get((h - BASE_HANDLE) as usize)
            .cloned()
            .unwrap_or(Handle::Other)
    }

    fn run(&mut self) {
        assert_eq!(self.u16(), 0xACED, "bad serialization magic");
        assert_eq!(self.u16(), 5, "bad serialization version");
        while self.p < self.d.len() {
            self.read_object();
        }
    }

    /// Consume one `classDesc` and return its index in `self.descs`.
    fn read_class_desc(&mut self) -> Option<usize> {
        match self.u8() {
            TC_NULL => None,
            TC_REFERENCE => {
                let h = self.u32();
                match self.handle(h) {
                    Handle::Desc(i) => Some(i),
                    _ => panic!("classDesc reference to a non-desc handle {h:#x}"),
                }
            }
            TC_CLASSDESC => {
                let name = self.utf();
                let _uid = self.i64();
                let idx = self.descs.len();
                self.descs.push(Desc {
                    name,
                    flags: 0,
                    fields: Vec::new(),
                    superdesc: None,
                });
                self.push_handle(Handle::Desc(idx));
                let flags = self.u8();
                self.descs[idx].flags = flags;
                let n = self.u16() as usize;
                let mut fields = Vec::with_capacity(n);
                for _ in 0..n {
                    let ty = self.u8();
                    let fname = self.utf();
                    if ty == b'L' || ty == b'[' {
                        self.read_object(); // the field's type name
                    }
                    fields.push((ty, fname));
                }
                self.descs[idx].fields = fields;
                // classAnnotation: contents, then TC_ENDBLOCKDATA
                while self.d[self.p] != TC_ENDBLOCKDATA {
                    self.read_object();
                }
                self.p += 1;
                let sup = self.read_class_desc();
                self.descs[idx].superdesc = sup;
                Some(idx)
            }
            other => panic!("expected classDesc, got {other:#x} at {}", self.p - 1),
        }
    }

    fn read_value(&mut self, ty: u8) -> Val {
        let n = match ty {
            b'B' | b'Z' => 1,
            b'C' | b'S' => 2,
            b'F' | b'I' => 4,
            b'D' | b'J' => 8,
            _ => return self.read_object(),
        };
        let raw = &self.d[self.p..self.p + n];
        self.p += n;
        if ty == b'I' {
            return Val::Int(i32::from_be_bytes(raw.try_into().unwrap()));
        }
        if ty == b'J' {
            return Val::Long(i64::from_be_bytes(raw.try_into().unwrap()));
        }
        Val::Other
    }

    /// Read the field values of an object whose most-derived class is `desc`.
    fn read_classdata(&mut self, desc: Option<usize>) {
        let Some(d) = desc else { return };
        let mut chain = Vec::new();
        let mut cur = Some(d);
        while let Some(i) = cur {
            chain.push(i);
            cur = self.descs[i].superdesc;
        }
        let mut vals: Vec<(String, Val)> = Vec::new();
        for ci in chain.into_iter().rev() {
            let fields = self.descs[ci].fields.clone();
            let flags = self.descs[ci].flags;
            for (ty, fname) in fields {
                let v = self.read_value(ty);
                vals.push((fname, v));
            }
            // SC_WRITE_METHOD appends custom data after the declared fields.
            if flags & SC_WRITE_METHOD != 0 {
                while self.d[self.p] != TC_ENDBLOCKDATA {
                    self.read_object();
                }
                self.p += 1;
            }
        }
        // `vals` holds (field name, value) pairs for this object's whole class
        // chain; pick out whatever this test cares about.
        let is_class_impl = self.descs[d].name.ends_with("ClassImpl");
        let is_snapshot_info = self.descs[d].name.ends_with("SnapshotInfo");
        let is_uoh_record = self.descs[d]
            .name
            .ends_with("UnreachableObjectsHistogram$Record");
        let mut name: Option<String> = None;
        let mut size: Option<i32> = None;
        let mut count: Option<i32> = None;
        let mut objects: Option<i32> = None;
        let mut classes: Option<i32> = None;
        let mut uoh_name: Option<String> = None;
        let mut uoh_addr: Option<u64> = None;
        let mut uoh_count: Option<i32> = None;
        let mut uoh_shallow: Option<i64> = None;
        for (fname, v) in &vals {
            match (fname.as_str(), v) {
                ("name", Val::Str(s)) => name = Some(s.clone()),
                ("instanceSize", Val::Int(i)) => size = Some(*i),
                ("instanceCount", Val::Int(i)) => count = Some(*i),
                ("numberOfObjects", Val::Int(i)) => objects = Some(*i),
                ("numberOfClasses", Val::Int(i)) => classes = Some(*i),
                ("className", Val::Str(s)) => uoh_name = Some(s.clone()),
                ("classAddress", Val::Long(l)) => uoh_addr = Some(*l as u64),
                ("objectCount", Val::Int(i)) => uoh_count = Some(*i),
                ("shallowHeapSize", Val::Long(l)) => uoh_shallow = Some(*l),
                _ => {}
            }
        }
        if is_class_impl {
            if let (Some(n), Some(s)) = (name.clone(), size) {
                self.class_impls.push((n, s));
            }
            if let (Some(n), Some(c)) = (name, count) {
                self.class_counts.push((n, c));
            }
        }
        if is_uoh_record {
            if let (Some(n), Some(a), Some(c), Some(s)) =
                (uoh_name, uoh_addr, uoh_count, uoh_shallow)
            {
                self.uoh_records.push((n, a, c, s));
            }
        }
        if is_snapshot_info {
            if let (Some(o), Some(c)) = (objects, classes) {
                self.snapshot_info = Some((o, c));
            }
        }
    }

    fn read_object(&mut self) -> Val {
        match self.u8() {
            TC_NULL => Val::Other,
            TC_REFERENCE => {
                let h = self.u32();
                match self.handle(h) {
                    Handle::Str(s) => Val::Str(s),
                    _ => Val::Other,
                }
            }
            TC_STRING => {
                let s = self.utf();
                self.push_handle(Handle::Str(s.clone()));
                Val::Str(s)
            }
            TC_LONGSTRING => {
                let s = self.long_utf();
                self.push_handle(Handle::Str(s.clone()));
                Val::Str(s)
            }
            TC_CLASSDESC => {
                self.p -= 1;
                let _ = self.read_class_desc();
                Val::Other
            }
            TC_OBJECT => {
                let desc = self.read_class_desc();
                self.push_handle(Handle::Other);
                self.read_classdata(desc);
                Val::Other
            }
            TC_CLASS => {
                let _ = self.read_class_desc();
                self.push_handle(Handle::Other);
                Val::Other
            }
            TC_ARRAY => {
                let desc = self.read_class_desc();
                self.push_handle(Handle::Other);
                let size = self.i32();
                let elem = desc
                    .and_then(|i| self.descs[i].name.as_bytes().get(1).copied())
                    .unwrap_or(b'L');
                let n = match elem {
                    b'B' | b'Z' => 1,
                    b'C' | b'S' => 2,
                    b'F' | b'I' => 4,
                    b'D' | b'J' => 8,
                    _ => 0,
                };
                if n > 0 {
                    self.p += n * size as usize;
                } else {
                    for _ in 0..size {
                        self.read_object();
                    }
                }
                Val::Other
            }
            TC_ENUM => {
                let _ = self.read_class_desc();
                self.push_handle(Handle::Other);
                self.read_object(); // the constant's name
                Val::Other
            }
            TC_PROXYCLASSDESC => {
                self.push_handle(Handle::Other);
                let n = self.i32();
                for _ in 0..n {
                    let _ = self.utf();
                }
                while self.d[self.p] != TC_ENDBLOCKDATA {
                    self.read_object();
                }
                self.p += 1;
                let _ = self.read_class_desc();
                Val::Other
            }
            TC_BLOCKDATA => {
                let n = self.u8() as usize;
                self.p += n;
                Val::Other
            }
            TC_BLOCKDATALONG => {
                let n = self.i32() as usize;
                self.p += n;
                Val::Other
            }
            TC_RESET => {
                self.handles.clear();
                Val::Other
            }
            other => panic!("unexpected type code {other:#x} at {}", self.p - 1),
        }
    }
}
