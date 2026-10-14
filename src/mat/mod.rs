mod codec;
mod int_index;
mod int_index_1n;
pub mod serial;

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::cvec::CompressedU32;
use crate::pass2::ThreadStack;
use int_index::{IntIndexStreamer, LongIndexStreamer};

/// RAII timing probe for the MAT emission path, gated on `HPROF_TIMING`.
///
/// Prints exactly one stderr line when it drops:
/// `[mat] <name> <elapsed>s @<wall-epoch-seconds>`
///
/// The trailing wall-clock epoch is deliberate: it lets a reader reconstruct the
/// *compute* time between two emits as
/// `wall(next) - wall(this) - elapsed(next)` — so the "assemble the structure"
/// cost is measurable without instrumenting the caller in `src/main.rs`.
///
/// When `HPROF_TIMING` is unset the only cost is one `std::env::var_os` per
/// emit (a handful per run); nothing is printed, and every emitted byte — and
/// stdout — is unaffected, so parity is untouched. stderr only.
struct MatTimer<'a> {
    name: &'a str,
    start: Option<std::time::Instant>,
}

impl<'a> MatTimer<'a> {
    #[inline]
    fn new(name: &'a str) -> Self {
        let start = if std::env::var_os("HPROF_TIMING").is_some() {
            Some(std::time::Instant::now())
        } else {
            None
        };
        Self { name, start }
    }
}

impl Drop for MatTimer<'_> {
    fn drop(&mut self) {
        if let Some(t) = self.start {
            let wall = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            eprintln!(
                "[mat] {} {:.3}s @{:.3}",
                self.name,
                t.elapsed().as_secs_f64(),
                wall
            );
        }
    }
}

/// Per-class metadata captured from Pass1 before it is consumed by Pass2::build.
/// This carries everything needed to emit the `ClassImpl` objects in the master
/// `.index` Java serialization stream.
pub struct MatClassMeta {
    /// class-object address → (super_class_addr, loader_addr, instance_size)
    pub class_info: HashMap<u64, (u64, u64, u32)>,
    /// GC-root object addresses (direct, non-thread-local), in encounter order
    pub gc_root_addrs: Vec<u64>,
    /// HPROF base timestamp in milliseconds since Unix epoch (from header)
    pub timestamp_ms: u64,
    /// HPROF total file size in bytes
    pub file_size: u64,
    /// HPROF format string (e.g. "JAVA PROFILE 1.0.2")
    pub format: String,
    /// HPROF object-id byte width (8 for modern dumps).
    pub id_size: u8,
    /// Object-reference byte width detected by pass 2 (`ref_size < id_size`
    /// means compressed oops). Set after the graph is built.
    pub ref_size: u8,
    /// Absolute path of the heap dump, written into SnapshotInfo.path/prefix.
    pub dump_path: String,
    /// class-object address → MAT id (reachable class objects only). Filled in
    /// after the id map is built; lets ClassImpl emit a real `address` and
    /// resolve `superClassId`/`classLoaderId` (both are MAT ids, not addresses).
    pub class_addr_to_mat: HashMap<u64, i32>,
    /// class-object MAT id → its address (reverse of the above).
    pub class_mat_to_addr: HashMap<i32, u64>,
    /// class-loader object address → MAT id.
    pub loader_addr_to_mat: HashMap<u64, i32>,
    /// class-object address → its declared instance fields, as
    /// `(name, HPROF typecode)` in HPROF dump order.
    ///
    /// MAT's `FieldDescriptor.type` is `IObject.Type`, whose constants are
    /// numerically identical to the HPROF basic typecodes (OBJECT=2,
    /// BOOLEAN=4 … LONG=11), so the HPROF typecode can be written straight
    /// through.
    pub class_fields: HashMap<u64, Vec<(String, u8)>>,
    /// class-object address → its declared static (constant-pool) fields, as
    /// `(name, HPROF typecode, raw big-endian value bits)`. MAT's
    /// `ClassImpl.staticFields`; several MAT reports read these (System
    /// Properties reads `java.lang.System.props`).
    pub class_statics: HashMap<u64, Vec<(String, u8, u64)>>,
    /// class-object address → the JVM-internal class name (e.g.
    /// `java/lang/String`, `[Ljava/lang/String;`). Needed to reproduce MAT's
    /// `calculateInstanceSize`, which walks the superclass chain by address.
    pub class_name_by_addr: HashMap<u64, String>,
    /// class-object address → its direct subclasses' addresses. MAT's
    /// `ClassImpl.subClasses` is a real field that `getSubclasses()` /
    /// `getAllSubclasses()` read (the "include subclasses" class lookups, the
    /// Thread Overview and the reference-statistics reports all depend on it).
    pub subclasses_by_addr: HashMap<u64, Vec<u64>>,
    /// GC-root object addresses (direct, non-thread-local), in encounter order.
    /// Parallel to `gc_root_types`.
    pub gc_root_types: Vec<u8>,
    /// Thread-local roots (JAVA_FRAME / JNI_LOCAL / NATIVE_STACK / THREAD_BLOCK)
    /// with the referrer MAT would have used at read time.
    pub thread_local_roots: Vec<crate::pass1::ThreadLocalRoot>,
}

/// One thread's thread-local roots: `(local object mat-id, its root records)`.
pub type RootLocals = (i32, Vec<RootRecord>);

/// One resolved GC-root record, in MAT id space.
#[derive(Clone)]
pub struct RootRecord {
    pub object_id: i32,
    pub object_address: u64,
    pub context_id: i32,
    pub context_address: u64,
    /// MAT `GCRootInfo.Type` constant.
    pub ty: i32,
}

/// Per-class aggregates for MAT's `UnreachableObjectsHistogram` property.
///
/// MAT builds it in `GarbageCleaner.createHistogramOfUnreachableObjects`: one
/// record per class that has unreachable objects, carrying the class name, the
/// class object's address, the unreachable instance count and their summed
/// size. The per-object size is the array size when non-zero (`a2size`), else —
/// for a *class object* — the used heap size of the class it represents, else
/// the class's `heapSizePerInstance` (our `shallow`). Only the class-object case
/// needs data the caller does not have, so those are passed as the row of the
/// class each one represents.
#[derive(Default)]
pub struct MatUnreachableHist {
    /// row -> number of unreachable objects of that class.
    pub count: Vec<i32>,
    /// row -> summed size of that class's unreachable objects, excluding class
    /// objects (whose size is the represented class's used heap size instead).
    pub shallow: Vec<i64>,
    /// For every unreachable *class object*: the row of the class it represents.
    pub classobj_rows: Vec<i32>,
}

/// Everything the master `.index` needs for its roots / rootsPerThread /
/// loaderLabels maps, already translated into MAT id space by the caller
/// (which is the only place the address table is still live).
#[derive(Default)]
pub struct MatRoots {
    /// key = root object mat-id → its root records. Sorted by key.
    pub roots: Vec<(i32, Vec<RootRecord>)>,
    /// key = thread object mat-id → (local object mat-id → its root records).
    pub per_thread: Vec<(i32, Vec<RootLocals>)>,
    /// key = class-loader mat-id → MAT's display label.
    pub loader_labels: Vec<(i32, String)>,
}

impl MatClassMeta {
    /// Extract the fields we need from Pass1 before it is moved into Pass2::build.
    pub fn from_pass1(p1: &crate::pass1::Pass1, dump_path: &str) -> Self {
        let _mt = MatTimer::new("MatClassMeta::from_pass1");
        let class_info = p1
            .class_map
            .iter()
            .map(|(&addr, ci)| (addr, (ci.super_id, ci.loader_id, ci.instance_size)))
            .collect();
        // Instance field names per class, for MAT's ClassImpl.fields
        // (FieldDescriptor[]). ~40k classes x ~10 fields on a large dump.
        let class_fields: HashMap<u64, Vec<(String, u8)>> = p1
            .class_map
            .iter()
            .map(|(&addr, ci)| {
                let v: Vec<(String, u8)> = ci
                    .fields
                    .iter()
                    .map(|&(name_id, ty)| {
                        (
                            p1.strings.get(&name_id).cloned().unwrap_or_default(),
                            ty.code(),
                        )
                    })
                    .collect();
                (addr, v)
            })
            .collect();
        // Static (constant-pool) fields, same shape as `class_fields`.
        let class_statics: HashMap<u64, Vec<(String, u8, u64)>> = p1
            .class_map
            .iter()
            .map(|(&addr, ci)| {
                let v: Vec<(String, u8, u64)> = ci
                    .statics
                    .iter()
                    .map(|&(name_id, ty, val)| {
                        (
                            p1.strings.get(&name_id).cloned().unwrap_or_default(),
                            ty,
                            val,
                        )
                    })
                    .collect();
                (addr, v)
            })
            .collect();
        let class_name_by_addr: HashMap<u64, String> = p1
            .class_map
            .iter()
            .map(|(&addr, ci)| {
                (
                    addr,
                    p1.strings.get(&ci.name_id).cloned().unwrap_or_default(),
                )
            })
            .collect();
        // Direct subclasses, keyed by the superclass's address (MAT's
        // `HprofParserHandlerImpl` calls `superclass.addSubClass(clazz)`).
        let mut subclasses_by_addr: HashMap<u64, Vec<u64>> = HashMap::new();
        for (&addr, ci) in p1.class_map.iter() {
            if ci.super_id != 0 {
                subclasses_by_addr
                    .entry(ci.super_id)
                    .or_default()
                    .push(addr);
            }
        }
        for v in subclasses_by_addr.values_mut() {
            v.sort_unstable();
        }
        MatClassMeta {
            class_info,
            gc_root_addrs: p1.gc_root_addrs.clone(),
            gc_root_types: p1.gc_root_types.clone(),
            thread_local_roots: p1.thread_local_pairs.clone(),
            timestamp_ms: p1.header_timestamp_ms,
            file_size: p1.file_size,
            format: p1.format.clone(),
            id_size: p1.id_size,
            ref_size: p1.id_size,
            dump_path: dump_path.to_string(),
            class_addr_to_mat: HashMap::new(),
            class_mat_to_addr: HashMap::new(),
            loader_addr_to_mat: HashMap::new(),
            class_fields,
            class_statics,
            class_name_by_addr,
            subclasses_by_addr,
        }
    }
}

/// Map an HPROF heap-dump GC-root sub-tag to MAT's `GCRootInfo.Type` constant.
///
/// MAT's `Pass1Parser` reads the sub-tag and calls `handler.addGCRoot(id,
/// referrer, <Type>)` with the type fixed per tag; the values are MAT's, not
/// HPROF's, numbering (see `org.eclipse.mat.snapshot.model.GCRootInfo.Type`).
pub fn mat_root_type(hprof_tag: u8) -> i32 {
    use crate::types::heap;
    match hprof_tag {
        heap::ROOT_JNI_GLOBAL => 8,                             // NATIVE_STATIC
        heap::ROOT_JNI_LOCAL => 4,                              // NATIVE_LOCAL
        heap::ROOT_JAVA_FRAME => 64,                            // JAVA_LOCAL
        heap::ROOT_NATIVE_STACK => 128,                         // NATIVE_STACK
        heap::ROOT_STICKY_CLASS | heap::ROOT_SYSTEM_CLASS => 2, // SYSTEM_CLASS
        heap::ROOT_THREAD_BLOCK => 16,                          // THREAD_BLOCK
        heap::ROOT_MONITOR_USED => 32,                          // BUSY_MONITOR
        heap::ROOT_THREAD_OBJ => 256,                           // THREAD_OBJ
        // ROOT_UNKNOWN and the Android/JDK extras MAT 1.17 has no case for.
        _ => 1, // UNKNOWN
    }
}

/// MAT's `HprofParserHandlerImpl.calculateAlignment`: the GCD of the gaps
/// between consecutive (address-sorted) object addresses, clamped to
/// `[8, 256]`. The GCD can only shrink, so MAT bails out as soon as it reaches
/// the 8-byte minimum.
pub fn compute_object_align<I: Iterator<Item = u64>>(addrs: I) -> i32 {
    let mut prev: u64 = 0;
    let mut align: u64 = 0;
    for next in addrs {
        if next == 0 {
            continue;
        }
        let diff = next.wrapping_sub(prev);
        prev = next;
        if next == diff {
            // prev was 0: this is the first real address, nothing to compare.
            continue;
        }
        if align == 0 {
            align = diff;
        } else {
            let (mut mx, mut mn) = (align.max(diff), align.min(diff));
            let mut d = mx % mn;
            while d != 0 {
                mx = mn;
                mn = d;
                d = mx % mn;
            }
            align = mn;
            if align <= 8 {
                break;
            }
        }
    }
    (align.min(256) as i32).max(8)
}

/// Reproduce MAT's `ClassImpl.heapSizePerInstance`, i.e.
/// `HprofParserHandlerImpl.calculateInstanceSize`.
///
/// MAT ignores the HPROF `instance_size` field except for the `<method>` fake
/// class: it recomputes the size from the declared fields, walking the
/// superclass chain and 8-byte-aligning the result. Getting this wrong is
/// visible in every MAT report that shows "Heap Size per Instance".
pub fn compute_instance_sizes(meta: &MatClassMeta, object_align: i32) -> HashMap<u64, i32> {
    let ref_size = meta.ref_size as i32;
    let pointer_size = meta.id_size as i32;
    let mut out: HashMap<u64, i32> = HashMap::with_capacity(meta.class_info.len());
    let align_up = |v: i32, m: i32| -> i32 {
        if m <= 0 {
            return v;
        }
        let r = v % m;
        if r == 0 { v } else { v + (m - r) }
    };
    // Declared-field byte total, MAT's `sizeOf` summed over the class's own
    // `getFieldDescriptors()`.
    let own_bytes = |addr: u64| -> i32 {
        meta.class_fields
            .get(&addr)
            .map(|fs| {
                fs.iter()
                    .map(|&(_, ty)| {
                        if ty == 2 {
                            ref_size
                        } else {
                            crate::types::HprofType::from_code(ty)
                                .map(|t| t.byte_size() as i32)
                                .unwrap_or(0)
                        }
                    })
                    .sum()
            })
            .unwrap_or(0)
    };
    fn recursive(
        addr: u64,
        meta: &MatClassMeta,
        own_bytes: &dyn Fn(u64) -> i32,
        pointer_size: i32,
        ref_size: i32,
        align_up: &dyn Fn(i32, i32) -> i32,
        depth: u32,
    ) -> i32 {
        let super_addr = meta.class_info.get(&addr).map(|c| c.0).unwrap_or(0);
        if super_addr == 0 || depth > 64 {
            return pointer_size + ref_size;
        }
        align_up(
            own_bytes(addr)
                + recursive(
                    super_addr,
                    meta,
                    own_bytes,
                    pointer_size,
                    ref_size,
                    align_up,
                    depth + 1,
                ),
            ref_size,
        )
    }
    for &addr in meta.class_info.keys() {
        let is_array = meta
            .class_name_by_addr
            .get(&addr)
            .is_some_and(|n| n.starts_with('['));
        let size = if is_array {
            ref_size
        } else {
            let super_addr = meta.class_info.get(&addr).map(|c| c.0).unwrap_or(0);
            let is_method = super_addr != 0
                && meta
                    .class_name_by_addr
                    .get(&super_addr)
                    .is_some_and(|n| n == "<method>");
            if is_method {
                meta.class_info.get(&addr).map(|c| c.2 as i32).unwrap_or(0)
            } else {
                align_up(
                    recursive(addr, meta, &own_bytes, pointer_size, ref_size, &align_up, 0),
                    object_align,
                )
            }
        };
        out.insert(addr, size);
    }
    out
}

/// Maps our internal dense-id space (all objects, encounter order) to MAT's
/// id space (reachable-only, address-sorted, id-0 = synthetic system-classloader
/// at address 0x0).
///
/// `old_to_mat[old_id]` = mat-id (1..=reachable_count), or -1 for unreachable
/// objects and sentinel values. MAT id 0 is the synthetic root (address 0x0),
/// never present in `old_to_mat`.
///
/// **Addresses are deliberately not stored here.** A dense `mat-id -> address`
/// table costs ~4 GB on a 366M-object heap and is freed as soon as the index is
/// emitted. Consumers that need an address must capture it from the dense
/// address table while that is still resident — see the `.threads` side table
/// built in `main.rs` (`mat_thread_addrs`).
pub struct MatIdMap {
    /// old dense-id -> mat-id (1-based for real objects, -1 for unreachable)
    old_to_mat: Vec<i32>,
    /// reachable old-ids in address-ascending order (mat-id = index+1)
    sorted: Vec<u32>,
}

impl MatIdMap {
    /// Build the MAT id-space mapping.
    ///
    /// - `n`: `g.n` — total object count in our dense-id space
    /// - `idom`: dominator array of length n+1; `idom[i] == u32::MAX` marks
    ///   unreachable objects
    /// - `addr_at`: closure returning the object address for a given dense-id;
    ///   must be callable while the id_map is still live (before compress)
    pub fn build(n: usize, idom: &[u32], addr_at: impl Fn(usize) -> u64) -> Self {
        let _mt = MatTimer::new("MatIdMap::build");
        let mut sorted: Vec<u32> = (0..n as u32)
            .filter(|&i| idom[i as usize] != u32::MAX)
            .collect();
        sorted.sort_by_key(|&i| addr_at(i as usize));

        let mut old_to_mat = vec![-1i32; n];
        for (mat_pos, &old_id) in sorted.iter().enumerate() {
            // mat-id 0 = synthetic root; real objects start at 1
            old_to_mat[old_id as usize] = (mat_pos + 1) as i32;
        }

        Self { old_to_mat, sorted }
    }

    /// Translate an old dense-id to a mat-id. Returns -1 for unreachable
    /// objects or out-of-range values.
    #[inline]
    pub fn translate(&self, old: i32) -> i32 {
        if old < 0 || old as usize >= self.old_to_mat.len() {
            return -1;
        }
        self.old_to_mat[old as usize]
    }

    /// Total number of MAT objects (includes synthetic id-0 = reachable+1).
    pub fn mat_count(&self) -> usize {
        self.sorted.len() + 1
    }

    /// Reachable old-ids in address-ascending (= mat-id ascending) order.
    /// `sorted()[i]` has mat-id `i + 1`.
    pub fn sorted(&self) -> &[u32] {
        &self.sorted
    }
}

#[allow(dead_code)]
pub struct MatEmitter {
    dir: PathBuf,
    prefix: String,
    /// Parser ID written into the `.index` header so MAT recognises the cache.
    /// Detected from the installed MAT at construction time; falls back to the
    /// known default `org.eclipse.mat.hprof.hprof`.
    parser_id: String,
}

/// Detect the Eclipse MAT installation and return its hprof parser ID.
///
/// The parser ID is `{Bundle-SymbolicName}.{extension-id}` as read from
/// `org.eclipse.mat.hprof_*.jar` inside the MAT plugins directory.  MAT
/// embeds this string in the `.index` header and rejects caches with a
/// mismatched ID, re-parsing from scratch.
///
/// If `mat_bin` is given (path to the `MemoryAnalyzer` executable), the
/// plugins directory is derived from it: `<bin>/../Eclipse/plugins` (the macOS
/// bundle layout where `bin` lives in `MacOS/`). That candidate is tried first.
///
/// Returns `None` when no MAT installation is found or the jar cannot be
/// read; the caller falls back to the hard-coded default.
pub fn detect_mat_parser_id(mat_bin: Option<&Path>) -> Option<String> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    // If an explicit MAT binary was given, derive the plugins dir from it.
    // macOS bundle: .../Contents/MacOS/MemoryAnalyzer → .../Contents/Eclipse/plugins
    if let Some(bin) = mat_bin {
        if let Some(macos_dir) = bin.parent() {
            candidates.push(macos_dir.join("../Eclipse/plugins"));
        }
    }
    // Candidate plugins directories on macOS and Linux.
    {
        candidates.push(
            // macOS standard location
            std::path::PathBuf::from("/Applications/MemoryAnalyzer.app/Contents/Eclipse/plugins"),
        );
        if let Some(home) = std::env::var_os("HOME") {
            candidates.push(
                std::path::Path::new(&home)
                    .join("Applications/MemoryAnalyzer.app/Contents/Eclipse/plugins"),
            );
            // Linux: ~/mat/plugins (common after unpacking the tar.gz)
            candidates.push(std::path::Path::new(&home).join("mat/plugins"));
        }
        // Linux system-wide paths
        candidates.push(std::path::PathBuf::from("/opt/mat/plugins"));
        candidates.push(std::path::PathBuf::from("/usr/local/mat/plugins"));
    }

    for plugins_dir in &candidates {
        if let Some(id) = probe_mat_plugins_dir(plugins_dir) {
            return Some(id);
        }
    }
    None
}

/// Scan one plugins directory for an `org.eclipse.mat.hprof_*.jar` and
/// extract `{Bundle-SymbolicName}.{parser-extension-id}` from it.
fn probe_mat_plugins_dir(plugins_dir: &std::path::Path) -> Option<String> {
    let entries = std::fs::read_dir(plugins_dir).ok()?;
    // Collect all matching jars; pick the one with the highest version.
    let mut best: Option<(String, std::path::PathBuf)> = None;
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("org.eclipse.mat.hprof_") && name.ends_with(".jar") {
            let ver = name
                .strip_prefix("org.eclipse.mat.hprof_")
                .and_then(|s| s.strip_suffix(".jar"))
                .unwrap_or("")
                .to_string();
            if best.as_ref().map(|(v, _)| &ver > v).unwrap_or(true) {
                best = Some((ver, entry.path()));
            }
        }
    }
    let (_, jar_path) = best?;
    extract_parser_id_from_jar(&jar_path)
}

/// Open the hprof jar and read `Bundle-SymbolicName` from `META-INF/MANIFEST.MF`
/// and the parser extension `id` from `plugin.xml`, then combine them.
fn extract_parser_id_from_jar(jar: &std::path::Path) -> Option<String> {
    let file = std::fs::File::open(jar).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;

    // Read Bundle-SymbolicName from MANIFEST.MF
    let bundle = {
        let mut mf = archive.by_name("META-INF/MANIFEST.MF").ok()?;
        let mut s = String::new();
        std::io::Read::read_to_string(&mut mf, &mut s).ok()?;
        s.lines()
            .find_map(|l| l.strip_prefix("Bundle-SymbolicName:"))?
            .split(';') // strip ;singleton:=true etc.
            .next()?
            .trim()
            .to_string()
    };

    // Read parser extension id from plugin.xml: the <extension> with
    // point="org.eclipse.mat.parser.parser" carries id="<ext-id>".
    let ext_id = {
        let mut px = archive.by_name("plugin.xml").ok()?;
        let mut s = String::new();
        std::io::Read::read_to_string(&mut px, &mut s).ok()?;
        // Find `point="org.eclipse.mat.parser.parser"` then look backwards
        // for the nearest `id="..."` attribute.
        let parser_point = "org.eclipse.mat.parser.parser";
        let pos = s.find(parser_point)?;
        // Search backwards from pos for id="
        let before = &s[..pos];
        let id_pos = before.rfind("id=\"")?;
        let after_quote = &before[id_pos + 4..];
        after_quote.split('"').next()?.to_string()
    };

    Some(format!("{bundle}.{ext_id}"))
}

#[allow(dead_code)]
impl MatEmitter {
    pub fn new(dir: &Path, prefix: &str, mat_bin: Option<&Path>) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let parser_id = detect_mat_parser_id(mat_bin)
            .unwrap_or_else(|| "org.eclipse.mat.hprof.hprof".to_string());
        Ok(Self {
            dir: dir.to_path_buf(),
            prefix: prefix.to_string(),
            parser_id,
        })
    }

    /// Return the detected (or default) MAT parser ID that will be written
    /// into the `.index` header.
    pub fn parser_id(&self) -> &str {
        &self.parser_id
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{}.{}.index", self.prefix, name))
    }

    /// Emit the MAT `o2c` index: for each object id, the dense object id of its
    /// `java.lang.Class` object. `class_idx_c` is the compressed per-object
    /// class-histogram row (as produced in pass 2); `inv` maps a histogram row
    /// to the dense id of the class-object for that row (see
    /// [`build_row_to_classobj_id`]).
    pub fn emit_o2c(&self, class_idx_c: &CompressedU32, inv: &[i32]) -> io::Result<()> {
        let _mt = MatTimer::new("o2c");
        let w = BufWriter::new(File::create(self.path("o2c"))?);
        let mut s = IntIndexStreamer::new(w);
        let mut err: Option<io::Error> = None;
        class_idx_c.for_each_u32(|row| {
            if err.is_some() {
                return;
            }
            if let Err(e) = s.push(inv[row as usize]) {
                err = Some(e);
            }
        })?;
        if let Some(e) = err {
            return Err(e);
        }
        let w = s.finish()?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Emit the MAT `idx` index: object id -> object address (a LongIndex).
    /// Values are the raw addresses in dense-id order. Must be called BEFORE the
    /// id-map is compressed (the caller supplies an `addr_at(i)` accessor).
    pub fn emit_idx<F: FnMut(usize) -> u64>(&self, n: usize, mut addr_at: F) -> io::Result<()> {
        let _mt = MatTimer::new("idx");
        let w = BufWriter::new(File::create(self.path("idx"))?);
        let mut s = LongIndexStreamer::new(w);
        for i in 0..n {
            s.push(addr_at(i) as i64)?;
        }
        let w = s.finish()?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Emit the MAT `a2s` index: object id -> shallow heap size (an IntIndex of
    /// MAT-compressed sizes). `shallow_c` is the compressed per-object shallow
    /// size in bytes; each is passed through [`size_compress`] (identity for
    /// sizes <= i32::MAX, which is the common case).
    pub fn emit_a2s(&self, shallow_c: &CompressedU32) -> io::Result<()> {
        let _mt = MatTimer::new("a2s");
        let w = BufWriter::new(File::create(self.path("a2s"))?);
        let mut s = IntIndexStreamer::new(w);
        let mut err: Option<io::Error> = None;
        shallow_c.for_each_u32(|sz| {
            if err.is_some() {
                return;
            }
            if let Err(e) = s.push(size_compress(sz as i64)) {
                err = Some(e);
            }
        })?;
        if let Some(e) = err {
            return Err(e);
        }
        let w = s.finish()?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Emit the MAT `domIn` index: object id -> immediate-dominator object id (an
    /// IntIndex over the dominator-tree `idom` array).
    pub fn emit_dom_in(&self, idom: &[i32]) -> io::Result<()> {
        let _mt = MatTimer::new("domIn");
        let w = BufWriter::new(File::create(self.path("domIn"))?);
        let mut s = IntIndexStreamer::new(w);
        for &d in idom {
            s.push(d)?;
        }
        let w = s.finish()?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Emit a named IntIndex from a pre-built `&[i32]` slice (used for remapped
    /// o2c and a2s where values are assembled in MAT id order by the caller).
    pub fn emit_int_index(&self, name: &str, vals: &[i32]) -> io::Result<()> {
        let _mt = MatTimer::new(name);
        let w = BufWriter::new(File::create(self.path(name))?);
        let mut s = IntIndexStreamer::new(w);
        for &v in vals {
            s.push(v)?;
        }
        let w = s.finish()?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Emit a named LongIndex from a pre-built `&[i64]` slice (used for remapped
    /// idx and o2ret where values are assembled in MAT id order by the caller).
    pub fn emit_long_index(&self, name: &str, vals: &[i64]) -> io::Result<()> {
        let _mt = MatTimer::new(name);
        let w = BufWriter::new(File::create(self.path(name))?);
        let mut s = LongIndexStreamer::new(w);
        for &v in vals {
            s.push(v)?;
        }
        let w = s.finish()?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Streaming variant: emit a LongIndex from an iterator, avoiding a full
    /// `Vec<i64>` materialisation.
    pub fn emit_long_index_iter<I>(&self, name: &str, iter: I) -> io::Result<()>
    where
        I: IntoIterator<Item = i64>,
    {
        let _mt = MatTimer::new(name);
        let w = BufWriter::new(File::create(self.path(name))?);
        let mut s = LongIndexStreamer::new(w);
        for v in iter {
            s.push(v)?;
        }
        let w = s.finish()?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Emit the MAT `o2ret` index: object id -> retained heap size in bytes (a
    /// LongIndex).
    pub fn emit_o2ret(&self, retained: &[i64]) -> io::Result<()> {
        let _mt = MatTimer::new("o2ret");
        let w = BufWriter::new(File::create(self.path("o2ret"))?);
        let mut s = LongIndexStreamer::new(w);
        for &r in retained {
            s.push(r)?;
        }
        let w = s.finish()?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Emit the MAT `outbound` IntArray1N (SORTED writer). `entries[i]` must be
    /// the fully-assembled per-object int slice: the object's class-object dense
    /// id followed by its sorted-unique forward targets (see the module docs on
    /// `int_index_1n` for the layout). The caller owns the assembly so the
    /// large `Vec<Vec<i32>>` can be built streaming and dropped promptly.
    pub fn emit_outbound(&self, entries: &[Vec<i32>]) -> io::Result<()> {
        let _mt = MatTimer::new("outbound");
        let w = BufWriter::new(File::create(self.path("outbound"))?);
        let w = int_index_1n::write_sorted(w, entries)?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Streaming variant: emit `outbound` from an iterator of entry slices,
    /// avoiding both a full `Vec<Vec<i32>>` and an in-memory body buffer.
    pub fn emit_outbound_iter<I, S>(&self, entries: I) -> io::Result<()>
    where
        I: Iterator<Item = S>,
        S: AsRef<[i32]>,
    {
        let _mt = MatTimer::new("outbound");
        let w = BufWriter::new(File::create(self.path("outbound"))?);
        let w = int_index_1n::write_sorted_iter_streaming(w, entries)?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Callback-driven emit for `outbound`. Avoids per-entry `Vec<i32>`
    /// allocations. `n_entries` includes the synthetic root at index 0.
    /// `f(i, push)` is called once per entry; caller pushes pre-sorted i32 ids.
    pub fn emit_outbound_cb<F>(&self, n_entries: usize, f: F) -> io::Result<()>
    where
        F: FnMut(&mut dyn FnMut(i32) -> io::Result<()>) -> io::Result<()>,
    {
        let _mt = MatTimer::new("outbound");
        let w = BufWriter::new(File::create(self.path("outbound"))?);
        let w = int_index_1n::write_sorted_cb(w, n_entries, f)?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Emit the MAT `inbound` IntArray1N (SORTED writer). `entries[i]` is the
    /// per-object referrer list; empty lists are written as unset holes (MAT
    /// never `set`s them). MAT's inbound has NO pseudo class-object element
    /// (unlike outbound) — the entry is purely the referrer ids in MAT's
    /// pre-order sort order.
    pub fn emit_inbound(&self, entries: &[Vec<i32>]) -> io::Result<()> {
        let _mt = MatTimer::new("inbound");
        let w = BufWriter::new(File::create(self.path("inbound"))?);
        let w = int_index_1n::write_sorted(w, entries)?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Streaming variant: emit `inbound` from an iterator of entry slices,
    /// streaming body pages directly to disk to avoid an in-memory body buffer.
    pub fn emit_inbound_iter<I, S>(&self, entries: I) -> io::Result<()>
    where
        I: Iterator<Item = S>,
        S: AsRef<[i32]>,
    {
        let _mt = MatTimer::new("inbound");
        let w = BufWriter::new(File::create(self.path("inbound"))?);
        let w = int_index_1n::write_sorted_iter_streaming(w, entries)?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Emit the MAT `domOut` IntArray1N (UNSORTED writer). `entries` has length
    /// `n + 1`: `entries[0]` is the superroot's children (objects dominated by
    /// the virtual root, i.e. the GC roots / top-level dominators) and
    /// `entries[k + 1]` is object `k`'s dominator children.
    pub fn emit_dom_out(&self, entries: &[Vec<i32>]) -> io::Result<()> {
        let _mt = MatTimer::new("domOut");
        let w = BufWriter::new(File::create(self.path("domOut"))?);
        let w = int_index_1n::write_unsorted(w, entries)?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Streaming variant: emit `domOut` from an iterator of entry slices.
    pub fn emit_dom_out_iter<I, S>(&self, entries: I) -> io::Result<()>
    where
        I: Iterator<Item = S>,
        S: AsRef<[i32]>,
    {
        let _mt = MatTimer::new("domOut");
        let w = BufWriter::new(File::create(self.path("domOut"))?);
        let w = int_index_1n::write_unsorted_iter_streaming(w, entries)?;
        w.into_inner().map_err(|e| e.into_error())?;
        Ok(())
    }

    /// Emit the MAT `i2sv2.index` retained-size cache. Each entry is a class
    /// mat-id (i32) followed by the negated per-class retained size (i64). MAT
    /// stores retained sizes as negative (a lazy/minimum-estimate marker).
    /// `class_retained`: iterator of `(class_mat_id, per_class_retained_bytes)`.
    pub fn emit_i2sv2<I>(&self, class_retained: I) -> io::Result<()>
    where
        I: Iterator<Item = (i32, i64)>,
    {
        let _mt = MatTimer::new("i2sv2");
        let path = self.dir.join(format!("{}.i2sv2.index", self.prefix));
        let mut f = BufWriter::new(File::create(&path)?);
        for (cid, ret) in class_retained {
            f.write_all(&cid.to_be_bytes())?;
            f.write_all(&(-ret).to_be_bytes())?;
        }
        f.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        Ok(())
    }

    /// Emit the MAT `.threads` plain-text file, byte-for-byte the shape
    /// `Pass1Parser.dumpThreads` produces. Each thread is written as:
    /// ```text
    /// Thread 0x<addr>
    ///   at class.method(sig) (source:line)<CR><LF>
    ///   ...
    /// <blank>
    ///   locals:
    ///     objectId=0x<addr>, line=<frame_number>
    ///     ...
    /// <blank>
    /// ```
    /// The frame lines end with CRLF (MAT builds them with `StackTrace.toString`,
    /// which hard-codes `\r\n`) while every other line ends with a bare LF. The
    /// `  locals:` header is written for EVERY thread, even one with no locals —
    /// the reader (`ThreadStackHelper.loadThreadsData`) probes the line after the
    /// frames for `locals`, and when the section is missing it consumes the next
    /// thread's header as that probe, silently dropping the thread.
    ///
    /// `thread_stacks`: resolved thread stacks from `g.thread_stacks`. A thread
    /// whose object could not be resolved (`u32::MAX`) is skipped, mirroring
    /// MAT's `if (tid == null) continue;`. A thread with an empty stack is still
    /// written as a header-only block, again as MAT does.
    /// `thread_addrs`: dense-id → object address for the thread objects and
    ///   frame locals this file names. `MatIdMap` deliberately does not store
    ///   addresses (they cost ~4 GB on a large heap), so the caller captures
    ///   this small side table while the dense address table is still resident.
    /// `local_frame_samples`: per-thread `(frame_number, old_dense_idx)` pairs,
    ///   complete (not a sample) — MAT lists every local of every thread.
    pub fn emit_threads(
        &self,
        thread_stacks: &[ThreadStack],
        thread_addrs: &HashMap<u32, u64>,
        local_frame_samples: &HashMap<u32, Vec<(u32, u32)>>,
    ) -> io::Result<()> {
        let _mt = MatTimer::new("threads");
        let path = self.dir.join(format!("{}.threads", self.prefix));
        let mut f = BufWriter::new(File::create(&path)?);
        for ts in thread_stacks {
            // Thread header: the *address* of the thread object, which is what
            // MAT writes (`Pass1Parser.dumpThreads`: `"0x" + hex(tid)`) and what
            // the reader's `mapAddressToId` resolves. A thread whose object we
            // could not resolve has no address to write, so it is skipped
            // outright — mirroring MAT's `if (tid == null) continue;`. Writing a
            // 0x0 placeholder here would make the reader drop the thread anyway
            // (and was the bug: every line read `Thread 0x0`).
            let Some(&thread_addr) = thread_addrs.get(&ts.thread_obj_idx) else {
                continue;
            };
            writeln!(f, "Thread 0x{:x}", thread_addr)?;
            // Frames. MAT writes `out.println(stack)` where `StackTrace.toString`
            // appends `\r\n` after each frame, so frame lines carry CRLF.
            for frame in &ts.mat_frames {
                writeln!(f, "{frame}\r")?;
            }
            // The blank line `out.println(stack)` leaves after the last frame.
            writeln!(f)?;
            // Locals header — unconditional, exactly as MAT writes it.
            writeln!(f, "  locals:")?;
            if let Some(locals) = local_frame_samples.get(&ts.thread_serial) {
                for &(frame_num, old_idx) in locals {
                    let local_addr = thread_addrs.get(&old_idx).copied().unwrap_or(0);
                    // MAT writes the raw `JavaLocal.lineNumber`, which is the
                    // *frame index* inside the stack trace, not a source line:
                    // its reader (`ThreadStackHelper.buildFrames`) groups locals
                    // by this value and looks them up per frame index `i`. The
                    // `u32::MAX` sentinel (JNI local / native stack / thread
                    // block, which carry no frame) becomes -1, exactly what MAT
                    // writes when `hasLineInfo` is false — and the reader skips
                    // any negative value. Adding 1 here (as this used to) moved
                    // every local one frame down.
                    let line: i64 = if frame_num == u32::MAX {
                        -1
                    } else {
                        i64::from(frame_num)
                    };
                    writeln!(f, "    objectId=0x{:x}, line={}", local_addr, line)?;
                }
            }
            // The blank line `out.println()` leaves after each thread block.
            writeln!(f)?;
        }
        f.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        Ok(())
    }

    /// Emit the MAT master `.index` Java Object Serialization stream.
    ///
    /// Writes the same sequence SnapshotImpl.writeToFile/readFromFile uses:
    /// stream header → XSnapshotInfo → classcache(HashMapIntObject<ClassImpl>)
    /// → roots(HashMapIntObject<XGCRootInfo[]>) → rootsPerThread → loaderLabels
    /// → BitField(arrayObjects).
    ///
    /// `meta`: metadata captured from Pass1 before it was consumed.
    /// `class_names`: `g.class_names` (histogram-row name strings).
    /// `class_loader_id`: `g.class_loader_id` (histogram-row → loader object addr, 0=boot).
    /// `class_obj_class_idx`: `g.class_obj_class_idx` (class-obj old dense id → histogram row).
    /// `inv`: per-row inverse map (histogram row → old class-obj dense id), from build_row_to_classobj_id.
    /// `mm`: MAT id map (for translating addresses and old dense ids to mat-ids).
    /// `array_obj_bits`: `g.array_obj_1based` — bitmask threshold (see Graph docs).
    #[allow(clippy::type_complexity)]
    pub fn emit_dot_index(
        &self,
        meta: &MatClassMeta,
        class_names: &[String],
        class_loader_id: &[u64],
        _class_obj_class_idx: &HashMap<u32, u32>,
        inv: &[i32],
        mm: &MatIdMap,
        _num_objects: usize,
        shallow: &[u32],
        class_idx: &[u32],
        roots: &MatRoots,
        instance_sizes: &HashMap<u64, i32>,
        root_instance_size: i32,
        root_class_mat: i32,
        // MAT id of each class object -> (0-based start of that class object's
        // entry in the `inbound` body, number of instances written there). See
        // `ClassImpl.cacheEntry` below.
        class_inb: &HashMap<i32, (i32, i32)>,
        // Per-class aggregates of the objects MAT drops as unreachable; becomes
        // the `UnreachableObjectsHistogram` SnapshotInfo property.
        unreach: &MatUnreachableHist,
        // row -> class-object address, for the class objects MAT drops
        // altogether (absent from the class cache, yet named by the
        // unreachable-objects histogram).
        unreach_class_addr: &HashMap<u32, u64>,
    ) -> io::Result<()> {
        use serial::*;

        let _mt = MatTimer::new("index");
        let num_rows = class_names.len();

        // --- build per-class aggregate data (instance count + shallow-heap sum) ---
        // MAT's `ClassImpl.instanceCount`/`totalSize` are accumulated by
        // `addInstance` over the objects that survive `GarbageCleaner` — i.e. the
        // ones that get an id in the index, which is exactly `mm.sorted()`.
        // Counting our whole dense space here (which also holds unreachable
        // objects MAT drops) inflated every MAT histogram and every
        // "Number of Objects" column.
        let mut instance_count: Vec<i32> = vec![0i32; num_rows];
        let mut used_heap: Vec<i64> = vec![0i64; num_rows];
        for &old in mm.sorted() {
            let row = class_idx[old as usize] as usize;
            if row < num_rows {
                instance_count[row] = instance_count[row].saturating_add(1);
                used_heap[row] = used_heap[row].saturating_add(shallow[old as usize] as i64);
            }
        }

        // --- invert class_obj_class_idx: old_classobj_id → histogram row (addr keyed) ---
        // Class-object addresses reach us through `meta.class_addr_to_mat` /
        // `meta.class_mat_to_addr`, resolved by the caller while the dense
        // address table was still resident (MatIdMap stores no addresses).

        let mut ser = Ser::new();

        // --- MAT block-data header: two separate TC_BLOCKDATA records, each
        // holding one UTF string (u16-length-prefixed), read by two successive
        // ObjectInputStream.readUTF() calls in SnapshotImpl.readFromFile:
        //   readUTF() → "MAT_01"     (version check)
        //   readUTF() → parser-id    (parser lookup)
        // Both strings are encoded as Java DataOutputStream.writeUTF: u16 len + bytes.
        // The parser-id is detected from the installed MAT at MatEmitter::new;
        // mismatched IDs cause MAT to reject the cache and re-parse from scratch.
        {
            // Both strings live in ONE TC_BLOCKDATA record: MAT writes them with
            // two consecutive `ObjectOutputStream.writeUTF` calls, and writeUTF
            // appends to the stream's block-data buffer, which is drained as a
            // single record when the next `writeObject` follows. Two separate
            // records are still readable by MAT's `readUTF` (it refills from the
            // next block), but they are not what MAT emits — they shift every
            // later byte by 2 and break byte-parity with MAT's own `.index`.
            let mut blk = Vec::with_capacity(2 + 6 + 2 + self.parser_id.len());
            blk.extend_from_slice(&(6u16).to_be_bytes());
            blk.extend_from_slice(b"MAT_01");
            blk.extend_from_slice(&(self.parser_id.len() as u16).to_be_bytes());
            blk.extend_from_slice(self.parser_id.as_bytes());
            ser.block_data(&blk);
        }

        // --- 1. XSnapshotInfo ---
        // XSnapshotInfo extends SnapshotInfo (uid=4) which extends nothing.
        // XSnapshotInfo declares no fields of its own.
        // We write: XSnapshotInfo → SnapshotInfo → null
        //
        // SnapshotInfo's declared field list must match MAT's exactly. MAT 1.17
        // declares 11 (6 primitives + 5 objects) — see
        // org.eclipse.mat.snapshot.SnapshotInfo. A stream that omits them leaves
        // the corresponding MAT fields at their Java defaults (0 / null), which
        // silently zeroes "number of objects", "used heap size" etc. in every
        // MAT report, so the whole list is emitted here.
        let snapshot_fields = || {
            vec![
                f_int("identifierSize"),
                f_int("numberOfClassLoaders"),
                f_int("numberOfClasses"),
                f_int("numberOfGCRoots"),
                f_int("numberOfObjects"),
                f_long("usedHeapSize"),
                f_obj("creationDate", "Ljava/util/Date;"),
                f_obj("jvmInfo", "Ljava/lang/String;"),
                f_obj("path", "Ljava/lang/String;"),
                f_obj("prefix", "Ljava/lang/String;"),
                f_obj("properties", "Ljava/util/Map;"),
            ]
        };
        let snapshot_chain = vec![
            ClassDesc {
                name: "org.eclipse.mat.parser.model.XSnapshotInfo".into(),
                uid: uid::X_SNAPSHOT_INFO,
                flags: SC_SERIALIZABLE,
                fields: vec![],
            },
            ClassDesc {
                name: "org.eclipse.mat.snapshot.SnapshotInfo".into(),
                uid: uid::SNAPSHOT_INFO,
                flags: SC_SERIALIZABLE,
                fields: snapshot_fields(),
            },
        ];

        // --- SnapshotInfo counters (MAT recomputes none of these on reopen) ---
        // `numberOfObjects` must count the synthetic id-0 root too: MAT sizes its
        // object-marking arrays from this value and then indexes them with real
        // object ids (0..N), so writing N instead of N+1 makes
        // `ObjectMarkerOld.markSingleThreaded` throw
        // `ArrayIndexOutOfBoundsException: Index N out of bounds for length N`
        // and silently drop every `getRetainedSet`-based result from the report.
        let n_objects = mm.mat_count() as i32;
        // MAT counts distinct *class objects*, not class-histogram rows: several
        // rows (a canonical one plus per-loader "alias" rows) can map to the same
        // class object, and MAT's own index reports 853 for this dump where a
        // row count gives 854.
        let n_classes = {
            let mut seen = std::collections::HashSet::new();
            for row in 0..num_rows {
                let old_cobj = inv[row];
                if old_cobj >= 0 {
                    let m = mm.translate(old_cobj);
                    if m > 0 {
                        seen.insert(m);
                    }
                }
            }
            seen.len() as i32
        };
        let n_loaders = roots.loader_labels.len() as i32;
        // MAT counts distinct root *objects* — and, crucially, only those it can
        // resolve to an object in the heap (`HprofParserHandlerImpl.map2ids`
        // drops root records whose address has no identifier). The caller
        // already applied that filter, so the count is the emitted map size.
        let n_roots = roots.roots.len() as i32;
        // usedHeapSize = sum of shallow sizes over reachable objects, plus MAT's
        // synthetic object 0 (the system class loader), which MAT treats as an
        // instance of java.lang.ClassLoader and therefore counts at that class's
        // heapSizePerInstance.
        let used_heap_size: i64 = mm
            .sorted()
            .iter()
            .map(|&old| shallow[old as usize] as i64)
            .sum::<i64>()
            + root_instance_size as i64;
        let id_size = meta.id_size as i32;
        // Captured by value so the `properties` closure below stays 'static.
        let has_oops_property = meta.id_size == 8;
        let compressed_oops = meta.ref_size < meta.id_size;
        let dump_path = meta.dump_path.clone();
        let prefix = {
            // MAT's prefix is the dump path with the final extension removed,
            // plus a '.':  /tmp/x.hprof -> /tmp/x.
            let p = std::path::Path::new(&dump_path);
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("dump");
            match p.parent().and_then(|d| d.to_str()) {
                Some(d) if !d.is_empty() => format!("{d}/{stem}."),
                _ => format!("{stem}."),
            }
        };
        // `hprof.version` is NOT the HPROF header string. MAT's
        // HprofHeapObjectReader.open() does
        //   Version.valueOf(snapshotInfo.getProperty("hprof.version"))
        // against org.eclipse.mat.hprof.describer.Version, whose constants are
        // the enum NAMES JDK12BETA3 / JDK12BETA4 / JDK6 — their describe strings
        // are "JAVA PROFILE 1.0" / "1.0.1" / "1.0.2". Writing the header string
        // throws IllegalArgumentException and aborts the snapshot open.
        let hprof_version = match meta.format.as_str() {
            "JAVA PROFILE 1.0" => "JDK12BETA3",
            "JAVA PROFILE 1.0.1" => "JDK12BETA4",
            _ => "JDK6", // "JAVA PROFILE 1.0.2" and anything newer
        };
        let file_size = meta.file_size;
        let ts_ms = meta.timestamp_ms as i64;
        // --- MAT's `UnreachableObjectsHistogram` property records ---
        // MAT stores one record per *class object* that has unreachable
        // instances, keyed by the class id, so several histogram rows that
        // resolve to the same class object (canonical + per-loader aliases)
        // merge into one record. MAT's list order is its
        // `HashMap<Integer,Record>` iteration order, which for a table larger
        // than the highest class id is ascending class id — i.e. ascending
        // class-object address.
        let unreach_records: Vec<(String, u64, i32, i64)> = {
            let jlc_row = class_names
                .iter()
                .position(|n| mat_class_name(n) == "java.lang.Class");
            // A class object contributes the *used heap size of the class it
            // represents* (MAT's `ClassImpl.getUsedHeapSize`), not its own
            // shallow size — which is why golden's `java.lang.Class` record
            // shows a size of 0 for classes with no instances.
            let classobj_shallow: i64 = unreach
                .classobj_rows
                .iter()
                .map(|&r| used_heap.get(r as usize).copied().unwrap_or(0))
                .sum();
            let mut by_addr: HashMap<u64, (String, i32, i64)> = HashMap::new();
            for row in 0..num_rows {
                let count = unreach.count.get(row).copied().unwrap_or(0);
                if count == 0 {
                    continue;
                }
                // MAT drops some class objects entirely (their class never
                // reaches the class cache) yet still records them here, so the
                // address falls back to the map the caller built from the
                // address table before it was freed.
                let addr = match inv[row] {
                    o if o >= 0 => {
                        let mat_id = mm.translate(o);
                        if mat_id > 0 {
                            meta.class_mat_to_addr.get(&mat_id).copied()
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
                .or_else(|| unreach_class_addr.get(&(row as u32)).copied());
                let addr = match addr {
                    Some(a) => a,
                    None => continue,
                };
                let mut shallow = unreach.shallow.get(row).copied().unwrap_or(0);
                if Some(row) == jlc_row {
                    shallow += classobj_shallow;
                }
                let e = by_addr
                    .entry(addr)
                    .or_insert_with(|| (mat_class_name(&class_names[row]), 0, 0));
                e.1 += count;
                e.2 += shallow;
            }
            let mut v: Vec<(u64, (String, i32, i64))> = by_addr.into_iter().collect();
            v.sort_by_key(|&(addr, _)| addr);
            v.into_iter()
                .map(|(addr, (name, count, shallow))| (name, addr, count, shallow))
                .collect()
        };
        let snapshot_layers = vec![
            // XSnapshotInfo layer (subclass)
            LayerData {
                fields: vec![],
                values: vec![],
            },
            // SnapshotInfo layer (superclass)
            LayerData {
                fields: snapshot_fields(),
                values: vec![
                    ("identifierSize".into(), FieldVal::Int(id_size)),
                    ("numberOfClassLoaders".into(), FieldVal::Int(n_loaders)),
                    ("numberOfClasses".into(), FieldVal::Int(n_classes)),
                    ("numberOfGCRoots".into(), FieldVal::Int(n_roots)),
                    ("numberOfObjects".into(), FieldVal::Int(n_objects)),
                    ("usedHeapSize".into(), FieldVal::Long(used_heap_size)),
                    (
                        "creationDate".into(),
                        FieldVal::ObjRef(Box::new(move |s: &mut Ser| {
                            s.write_date(ts_ms);
                        })),
                    ),
                    (
                        "jvmInfo".into(),
                        FieldVal::ObjRef(Box::new(|s: &mut Ser| s.null())),
                    ),
                    (
                        "path".into(),
                        FieldVal::ObjRef(Box::new(move |s: &mut Ser| {
                            s.string(&dump_path);
                        })),
                    ),
                    (
                        "prefix".into(),
                        FieldVal::ObjRef(Box::new(move |s: &mut Ser| {
                            s.string(&prefix);
                        })),
                    ),
                    (
                        "properties".into(),
                        FieldVal::ObjRef(Box::new(move |s: &mut Ser| {
                            // Properties map: the keys MAT's own index carries.
                            // MAT sets `$heapFormat` from the parser id's format
                            // string (lower-case "hprof"), and only sets
                            // `$useCompressedOops` for a 64-bit dump (the
                            // `pointerSize == 8` guard in beforePass2).
                            let mut entries: Vec<(
                                i32,
                                Box<dyn FnOnce(&mut Ser)>,
                                Box<dyn FnOnce(&mut Ser)>,
                            )> = vec![(
                                Ser::java_string_hashcode("$heapFormat"),
                                Box::new(|s: &mut Ser| {
                                    s.string("$heapFormat");
                                }),
                                Box::new(|s: &mut Ser| {
                                    s.string("hprof");
                                }),
                            )];
                            // MAT only records this for a 64-bit dump.
                            if has_oops_property {
                                let e: (i32, Box<dyn FnOnce(&mut Ser)>, Box<dyn FnOnce(&mut Ser)>) = (
                                    Ser::java_string_hashcode("$useCompressedOops"),
                                    Box::new(|s: &mut Ser| {
                                        s.string("$useCompressedOops");
                                    }),
                                    Box::new(move |s: &mut Ser| {
                                        s.write_boolean(compressed_oops);
                                    }),
                                );
                                entries.push(e);
                            }
                            let e: (i32, Box<dyn FnOnce(&mut Ser)>, Box<dyn FnOnce(&mut Ser)>) = (
                                Ser::java_string_hashcode("hprof.version"),
                                Box::new(|s: &mut Ser| {
                                    s.string("hprof.version");
                                }),
                                Box::new(move |s: &mut Ser| {
                                    s.string(hprof_version);
                                }),
                            );
                            entries.push(e);
                            let e: (i32, Box<dyn FnOnce(&mut Ser)>, Box<dyn FnOnce(&mut Ser)>) = (
                                Ser::java_string_hashcode("hprof.length"),
                                Box::new(|s: &mut Ser| {
                                    s.string("hprof.length");
                                }),
                                Box::new(move |s: &mut Ser| {
                                    s.write_long(file_size as i64);
                                }),
                            );
                            entries.push(e);
                            // MAT's `UnreachableObjectsHistogram`, stored as a
                            // SnapshotInfo property under the class's own name.
                            // MAT's Class Histogram / "Unreachable Objects"
                            // reports read it back via
                            // `ISnapshot.getSnapshotAddons`.
                            let e: (i32, Box<dyn FnOnce(&mut Ser)>, Box<dyn FnOnce(&mut Ser)>) = (
                                Ser::java_string_hashcode(
                                    "org.eclipse.mat.snapshot.UnreachableObjectsHistogram",
                                ),
                                Box::new(|s: &mut Ser| {
                                    s.string(
                                        "org.eclipse.mat.snapshot.UnreachableObjectsHistogram",
                                    );
                                }),
                                Box::new(move |s: &mut Ser| {
                                    s.write_unreachable_objects_histogram(unreach_records);
                                }),
                            );
                            entries.push(e);
                            s.write_hashmap(16, 12, entries);
                        })),
                    ),
                ],
            },
        ];
        ser.write_object(&snapshot_chain, snapshot_layers);

        // --- 2. classcache: HashMapIntObject<ClassImpl> ---
        // Key = class mat-id (int), value = ClassImpl object.
        // Build the MatIntMap with initial capacity = num_rows (MAT uses HMIO(classMap.size())).
        let num_classes = num_rows;
        let mut hm = MatIntMap::new(num_classes as i32);
        // Build ordered list of (mat_id, row) pairs for insertion.
        // MAT inserts classes in pass1 order (class address → class-serial → insertion order).
        // We use mat-id ascending order as a deterministic approximation.
        let mut class_entries: Vec<(i32, usize)> = (0..num_rows)
            .filter_map(|row| {
                let old_cobj = inv[row];
                if old_cobj < 0 {
                    return None;
                }
                let mat_id = mm.translate(old_cobj);
                if mat_id <= 0 {
                    return None;
                }
                Some((mat_id, row))
            })
            .collect();
        class_entries.sort_by_key(|&(mid, _)| mid);
        // The ClassImpl of java.lang.Class: every class's `classInstance`.
        let jlc_key: Option<String> = meta
            .class_name_by_addr
            .iter()
            .find(|(_, n)| *n == "java.lang.Class" || *n == "java/lang/Class")
            .and_then(|(&a, _)| meta.class_addr_to_mat.get(&a).copied())
            .filter(|&m| m > 0)
            .map(|m| {
                let a = meta.class_mat_to_addr.get(&m).copied().unwrap_or(0);
                format!("class_0x{:x}", a)
            });
        // MAT materialises its synthetic object 0 as a `ClassLoaderImpl` whose
        // class is `java.lang.ClassLoader`, so that class's instance count is
        // one higher than the heap's real loaders and its totalSize carries
        // object 0's heapSizePerInstance (MAT's own index shows the extra
        // instance, and the snapshot's usedHeapSize — the sum of every class's
        // totalSize — only adds up with it included).
        if root_class_mat > 0 {
            if let Some(&(_, row)) = class_entries.iter().find(|&&(m, _)| m == root_class_mat) {
                instance_count[row] = instance_count[row].saturating_add(1);
                used_heap[row] = used_heap[row].saturating_add(root_instance_size as i64);
            }
        }
        // Insert into HMIO in that order (insertion order determines slot positions after rehash).
        for (i, &(mat_id, _row)) in class_entries.iter().enumerate() {
            hm.put(mat_id, i);
        }
        // Emit the class cache children-first: every ClassImpl's `subClasses`
        // list is then a set of plain back-references to already-written
        // ClassImpls (MAT stores the *same* ClassImpl instances, and
        // GarbageCleaner later hangs its `cacheEntry` — and therefore
        // `getObjectIds()` — off exactly those instances, so duplicates would
        // break every "include subclasses" query). MAT's reader re-inserts each
        // entry with `putQuick`, so the stream order does not change the map.
        let val_of: std::collections::HashMap<i32, usize> = class_entries
            .iter()
            .enumerate()
            .map(|(i, &(m, _))| (m, i))
            .collect();
        // Only reference subclasses we actually emit: a class object can be
        // reachable without its row resolving to it, and referencing one of
        // those would leave a dangling forward reference in the stream.
        let mut subs_by_mat: std::collections::HashMap<i32, Vec<(i32, u64)>> =
            std::collections::HashMap::new();
        for &(mat_id, _) in class_entries.iter() {
            if let Some(&addr) = meta.class_mat_to_addr.get(&mat_id) {
                if let Some(kids) = meta.subclasses_by_addr.get(&addr) {
                    let v: Vec<(i32, u64)> = kids
                        .iter()
                        .filter_map(|&kaddr| {
                            let km = *meta.class_addr_to_mat.get(&kaddr)?;
                            if val_of.contains_key(&km) {
                                Some((km, kaddr))
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !v.is_empty() {
                        subs_by_mat.insert(mat_id, v);
                    }
                }
            }
        }
        // The `java.lang.Class` class object is every class's `classInstance`
        // (MAT's `ClassImpl.getClazz()` resolves through it, and the class
        // grouping in Top Consumers / the Class Histogram depends on it), so it
        // must be on the wire before any class that references it. It has no
        // subclasses of its own, so hoisting it does not break the
        // children-first invariant below.
        let jlc_mat: Option<i32> = meta
            .class_name_by_addr
            .iter()
            .find(|(_, n)| *n == "java.lang.Class" || *n == "java/lang/Class")
            .and_then(|(&a, _)| meta.class_addr_to_mat.get(&a).copied())
            .filter(|m| val_of.contains_key(m));
        // Iterative post-order (children first) over the subclass forest.
        let mut emit_order: Vec<usize> = Vec::with_capacity(class_entries.len());
        {
            let mut state: std::collections::HashMap<i32, usize> = std::collections::HashMap::new();
            if let Some(jm) = jlc_mat {
                // Hoisted to the front AND marked visited, so the post-order
                // walk below (which would otherwise reach it through its
                // superclass) does not emit it a second time.
                emit_order.push(val_of[&jm]);
                state.insert(jm, usize::MAX);
            }
            let empty: Vec<(i32, u64)> = Vec::new();
            for &(root, _) in class_entries.iter() {
                if state.contains_key(&root) {
                    continue;
                }
                let mut stack: Vec<i32> = vec![root];
                state.insert(root, 0);
                while let Some(&m) = stack.last() {
                    let idx = state[&m];
                    let kids = subs_by_mat.get(&m).unwrap_or(&empty);
                    if idx < kids.len() {
                        state.insert(m, idx + 1);
                        let k = kids[idx].0;
                        if let std::collections::hash_map::Entry::Vacant(e) = state.entry(k) {
                            e.insert(0);
                            stack.push(k);
                        }
                    } else {
                        stack.pop();
                        emit_order.push(val_of[&m]);
                    }
                }
            }
        }

        // Build ClassImpl chain descriptor (shared, written once via handle table).
        let class_impl_chain = vec![
            ClassDesc {
                name: "org.eclipse.mat.parser.model.ClassImpl".into(),
                uid: uid::CLASS_IMPL,
                flags: SC_SERIALIZABLE,
                fields: vec![
                    f_long("classLoaderAddress"),
                    f_int("classLoaderId"),
                    f_int("instanceCount"),
                    f_int("instanceSize"),
                    f_bool("isArrayType"),
                    f_long("superClassAddress"),
                    f_int("superClassId"),
                    f_long("totalSize"),
                    f_int("usedHeapSize"),
                    f_obj("cacheEntry", "Ljava/lang/Object;"),
                    f_arr(
                        "fields",
                        "[Lorg.eclipse.mat.snapshot.model.FieldDescriptor;",
                    ),
                    f_obj("name", "Ljava/lang/String;"),
                    f_arr("staticFields", "[Lorg.eclipse.mat.snapshot.model.Field;"),
                    f_obj("subClasses", "Ljava/util/Collection;"),
                ],
            },
            ClassDesc {
                name: "org.eclipse.mat.parser.model.AbstractObjectImpl".into(),
                uid: uid::ABSTRACT_OBJECT_IMPL,
                flags: SC_SERIALIZABLE,
                fields: vec![
                    f_long("address"),
                    f_int("objectId"),
                    f_obj("classInstance", "Lorg.eclipse.mat.parser.model.ClassImpl;"),
                ],
            },
        ];

        ser.write_hashmap_int_object_custom(
            "org.eclipse.mat.collect.HashMapIntObject",
            &hm,
            &emit_order,
            |s, val_idx| {
                let (mat_id, row) = class_entries[val_idx];
                // Real class-object address (resolved in main.rs while the
                // address array was still resident).
                let addr = meta.class_mat_to_addr.get(&mat_id).copied().unwrap_or(0);
                let name = &class_names[row];
                let loader_addr = class_loader_id[row];
                // MAT records the bootstrap loader as address 0 / id 0 (id 0 is
                // its synthetic address-0 loader), so an unresolved loader falls
                // back to 0 rather than -1.
                let loader_mid = if loader_addr == 0 {
                    0
                } else {
                    meta.loader_addr_to_mat
                        .get(&loader_addr)
                        .copied()
                        .unwrap_or(0)
                };
                let (super_addr, _loader_addr_ci, inst_size) =
                    meta.class_info.get(&addr).copied().unwrap_or((0, 0, 0));
                let _ = inst_size;
                // superClassId is a MAT id, resolved from the super's address.
                // java.lang.Object has no superclass, and MAT records that as id
                // 0 (the id of address 0x0, the synthetic system class loader)
                // rather than -1 — its own index has `superClassId=0` for
                // java.lang.Object. Keep the (address, id) pair consistent: if
                // the super's class object is not in the cache, emit
                // "no superclass" rather than a dangling id — ClassImpl
                // .getSuperClass() keys off the address.
                let super_mat_id = meta
                    .class_addr_to_mat
                    .get(&super_addr)
                    .copied()
                    .unwrap_or(0);
                let super_addr = if super_mat_id <= 0 { 0 } else { super_addr };
                // MAT recomputes the per-instance heap size from the declared
                // fields (see compute_instance_sizes); the HPROF instance_size
                // field is only used for the `<method>` pseudo-class.
                let inst_size = instance_sizes.get(&addr).copied().unwrap_or(0);
                let is_array = name.starts_with('[');
                // MAT stores the source form of the name, not the HPROF
                // descriptor form.
                let mat_name = mat_class_name(name);
                let inst_count_val = instance_count[row];
                let used_heap_val = used_heap[row];
                // ClassImpl.totalSize = sum of the shallow sizes of the class's
                // instances (MAT: ClassImpl.addInstance adds each instance size).
                let total_size = used_heap_val;
                // ClassImpl.usedHeapSize is the shallow size of the CLASS OBJECT
                // itself, not of its instances (MAT's own index records e.g. 40
                // for a class with 12493 instances at 72 bytes each).
                let class_obj_shallow = {
                    let old_cobj = inv[row];
                    if old_cobj >= 0 {
                        shallow[old_cobj as usize] as i64
                    } else {
                        0
                    }
                };

                let key_str = format!("class_0x{:x}", addr);
                let name_clone = mat_name;
                // The ObjRef closure must be 'static, so copy the pair out.
                let ce_pair = class_inb.get(&mat_id).copied();
                s.write_object_keyed(
                    &class_impl_chain,
                    // `layers` must be ordered subclass-first, parallel to `chain`:
                    // `write_object_keyed` reverses it so the values land superclass-first
                    // on the wire, which is the order the JVM (and therefore MAT) reads.
                    // Passing the superclass layer first — as this used to — made every
                    // ClassImpl value stream subclass-first, so MAT's reader consumed the
                    // first ClassImpl primitive as AbstractObjectImpl.address and then hit
                    // a non-type-code byte: "invalid type code: 00".
                    vec![
                        // ClassImpl layer (subclass)
                        LayerData {
                            fields: vec![
                                f_long("classLoaderAddress"),
                                f_int("classLoaderId"),
                                f_int("instanceCount"),
                                f_int("instanceSize"),
                                f_bool("isArrayType"),
                                f_long("superClassAddress"),
                                f_int("superClassId"),
                                f_long("totalSize"),
                                f_int("usedHeapSize"),
                                f_obj("cacheEntry", "Ljava/lang/Object;"),
                                f_arr(
                                    "fields",
                                    "[Lorg.eclipse.mat.snapshot.model.FieldDescriptor;",
                                ),
                                f_obj("name", "Ljava/lang/String;"),
                                f_arr("staticFields", "[Lorg.eclipse.mat.snapshot.model.Field;"),
                                f_obj("subClasses", "Ljava/util/Collection;"),
                            ],
                            values: vec![
                                (
                                    "classLoaderAddress".into(),
                                    FieldVal::Long(loader_addr as i64),
                                ),
                                ("classLoaderId".into(), FieldVal::Int(loader_mid)),
                                ("instanceCount".into(), FieldVal::Int(inst_count_val)),
                                ("instanceSize".into(), FieldVal::Int(inst_size)),
                                ("isArrayType".into(), FieldVal::Bool(is_array)),
                                (
                                    "superClassAddress".into(),
                                    FieldVal::Long(super_addr as i64),
                                ),
                                ("superClassId".into(), FieldVal::Int(super_mat_id)),
                                ("totalSize".into(), FieldVal::Long(total_size)),
                                (
                                    "usedHeapSize".into(),
                                    FieldVal::Int(class_obj_shallow.min(i32::MAX as i64) as i32),
                                ),
                                (
                                    "cacheEntry".into(),
                                    FieldVal::ObjRef(Box::new(move |s: &mut Ser| {
                                        // MAT's ClassImpl.getObjectIds() is
                                        // `snapshot.getIndexManager().c2objects()
                                        // .getObjectsOf(this.cacheEntry)`, and
                                        // `IndexManager.c2objects()` returns the
                                        // **inbound** index (javap of MAT 1.17:
                                        // `c2objects()` -> `getfield inbound`).
                                        // `InboundReader.getObjectsOf(int[])` is
                                        // `body.getNext(off, cnt)` — the slice
                                        // `body[off .. off+cnt)` of the inbound
                                        // body. So cacheEntry must be an
                                        // int[]{offset, count} whose slice is the
                                        // class's instance list. `offset` is the
                                        // 0-based body index where this class
                                        // object's inbound entry starts (that
                                        // entry is written instances-first, see
                                        // the inbound emitter in main.rs) and
                                        // `count` is its instance count.
                                        //
                                        // A null here is NOT harmless: it makes
                                        // getObjectsOf return int[0] for every
                                        // class, which collapses Top Consumers,
                                        // the Finalizer view, the system class
                                        // loader page and the Thread Overview
                                        // table (every one of them asks a class
                                        // for its instances). Classes with no
                                        // instances keep MAT's own null.
                                        match ce_pair {
                                            Some((off, cnt)) => s.write_int_array(&[off, cnt]),
                                            None => s.null(),
                                        }
                                    })),
                                ),
                                // `fields`, `staticFields` and `subClasses` must be
                                // non-null: MAT's ClassImpl.setSnapshot() iterates
                                // `staticFields` while restoring the snapshot (NPE
                                // otherwise), and the field / subclass views
                                // dereference the other two. Empty arrays/lists mean
                                // "no declared fields / no static fields / no known
                                // subclasses".
                                (
                                    "fields".into(),
                                    FieldVal::ObjRef({
                                        let cf = meta
                                            .class_fields
                                            .get(&addr)
                                            .cloned()
                                            .unwrap_or_default();
                                        Box::new(move |s: &mut Ser| {
                                            write_field_descriptors(s, &cf);
                                        })
                                    }),
                                ),
                                (
                                    "name".into(),
                                    FieldVal::ObjRef(Box::new(move |s: &mut Ser| {
                                        s.string(&name_clone)
                                    })),
                                ),
                                (
                                    "staticFields".into(),
                                    FieldVal::ObjRef({
                                        let sf = meta
                                            .class_statics
                                            .get(&addr)
                                            .cloned()
                                            .unwrap_or_default();
                                        Box::new(move |s: &mut Ser| {
                                            write_static_fields(s, &sf);
                                        })
                                    }),
                                ),
                                (
                                    "subClasses".into(),
                                    FieldVal::ObjRef({
                                        // Direct subclasses, as back-references
                                        // to the ClassImpls written earlier
                                        // (children-first order above).
                                        //
                                        // MAT leaves this field `null` for a
                                        // class with no subclasses and only
                                        // materialises a list when there is at
                                        // least one — an empty list is not the
                                        // same object on the wire (it costs a
                                        // full `ArrayList` record per class,
                                        // ~44 KB on a 2 285-class dump) and is
                                        // not what MAT's own `.index` carries.
                                        let kids: Vec<u64> = subs_by_mat
                                            .get(&mat_id)
                                            .map(|v| v.iter().map(|&(_, a)| a).collect())
                                            .unwrap_or_default();
                                        Box::new(move |s: &mut Ser| {
                                            if kids.is_empty() {
                                                s.null();
                                                return;
                                            }
                                            let elems: Vec<Box<dyn FnOnce(&mut Ser)>> = kids
                                                .iter()
                                                .map(|&kaddr| {
                                                    let k = format!("class_0x{:x}", kaddr);
                                                    Box::new(move |s: &mut Ser| {
                                                        s.ref_object(&k);
                                                    })
                                                        as Box<dyn FnOnce(&mut Ser)>
                                                })
                                                .collect();
                                            s.write_array_list(kids.len() as i32, elems);
                                        })
                                    }),
                                ),
                            ],
                        },
                        // AbstractObjectImpl layer (superclass). Its values are emitted
                        // before ClassImpl's on the wire because `write_object_keyed`
                        // reverses the layer order.
                        LayerData {
                            fields: vec![
                                f_long("address"),
                                f_int("objectId"),
                                f_obj("classInstance", "Lorg.eclipse.mat.parser.model.ClassImpl;"),
                            ],
                            values: vec![
                                ("address".into(), FieldVal::Long(addr as i64)),
                                ("objectId".into(), FieldVal::Int(mat_id)),
                                (
                                    "classInstance".into(),
                                    FieldVal::ObjRef({
                                        // A class object's class is java.lang.Class
                                        // (MAT's own index resolves every
                                        // ClassImpl.getClazz() to that ClassImpl).
                                        // Falls back to a self-reference only if
                                        // java.lang.Class is absent from the cache.
                                        let k = key_str.clone();
                                        let jlc = jlc_key.clone();
                                        Box::new(move |s: &mut Ser| match jlc {
                                            Some(ref j)
                                                if s.object_handle(j).is_some() && *j != k =>
                                            {
                                                s.ref_object(j);
                                            }
                                            _ => s.ref_object(&k),
                                        })
                                    }),
                                ),
                            ],
                        },
                    ],
                    Some(&key_str),
                );
            },
        );

        // --- 3. roots: HashMapIntObject<XGCRootInfo[]> ---
        // Key = object mat-id, value = the object's XGCRootInfo[] (an object can
        // be a root for more than one reason). `roots.roots` was already
        // filtered to objects MAT can resolve, and translated into MAT id space
        // by the caller (the only place the address table is still live).
        let mut roots_hm = MatIntMap::new(roots.roots.len() as i32);
        for (i, &(key, _)) in roots.roots.iter().enumerate() {
            roots_hm.put(key, i);
        }
        ser.write_hashmap_int_object(
            "org.eclipse.mat.collect.HashMapIntObject",
            &roots_hm,
            |s, val_idx| {
                let recs = &roots.roots[val_idx].1;
                let mut it = recs.iter();
                s.write_object_array(
                    "[Lorg.eclipse.mat.parser.model.XGCRootInfo;",
                    uid::X_GC_ROOT_INFO_ARRAY,
                    recs.len() as i32,
                    move |s: &mut Ser| {
                        for r in it.by_ref() {
                            s.write_xgcroot_info(
                                r.object_id,
                                r.object_address,
                                r.context_id,
                                r.context_address,
                                r.ty,
                            );
                        }
                    },
                );
            },
        );

        // --- 4. rootsPerThread: HashMapIntObject<HashMapIntObject<XGCRootInfo[]>> ---
        // MAT routes a thread-local root (JAVA_FRAME / JNI_LOCAL / NATIVE_STACK /
        // THREAD_BLOCK whose thread serial was already known) into
        // `threadAddressToLocals` instead of `gcRoots`.
        let mut roots_pt_hm = MatIntMap::new(roots.per_thread.len() as i32);
        for (i, &(key, _)) in roots.per_thread.iter().enumerate() {
            roots_pt_hm.put(key, i);
        }
        ser.write_hashmap_int_object(
            "org.eclipse.mat.collect.HashMapIntObject",
            &roots_pt_hm,
            |s, val_idx| {
                let locals = &roots.per_thread[val_idx].1;
                let mut inner = MatIntMap::new(locals.len() as i32);
                for (j, &(key, _)) in locals.iter().enumerate() {
                    inner.put(key, j);
                }
                s.write_hashmap_int_object(
                    "org.eclipse.mat.collect.HashMapIntObject",
                    &inner,
                    |s, j| {
                        let recs = &locals[j].1;
                        let mut it = recs.iter();
                        s.write_object_array(
                            "[Lorg.eclipse.mat.parser.model.XGCRootInfo;",
                            uid::X_GC_ROOT_INFO_ARRAY,
                            recs.len() as i32,
                            move |s: &mut Ser| {
                                for r in it.by_ref() {
                                    s.write_xgcroot_info(
                                        r.object_id,
                                        r.object_address,
                                        r.context_id,
                                        r.context_address,
                                        r.ty,
                                    );
                                }
                            },
                        );
                    },
                );
            },
        );

        // --- 5. loaderLabels: HashMapIntObject<String> ---
        let mut loader_hm = MatIntMap::new(roots.loader_labels.len() as i32);
        for (i, &(key, _)) in roots.loader_labels.iter().enumerate() {
            loader_hm.put(key, i);
        }
        ser.write_hashmap_int_object(
            "org.eclipse.mat.collect.HashMapIntObject",
            &loader_hm,
            |s, val_idx| {
                s.string(&roots.loader_labels[val_idx].1);
            },
        );

        // --- 6. BitField arrayObjects: n+1 bits (mat-id 0..=n), bit set for array objects ---
        // An object is an array if its class name starts with '['.
        let mat_n = mm.mat_count(); // includes synthetic id 0
        let num_words = mat_n.div_ceil(32);
        let mut words: Vec<i32> = vec![0i32; num_words];
        for &old_id in mm.sorted() {
            let mat_id = mm.translate(old_id as i32);
            if mat_id > 0 {
                let row = class_idx[old_id as usize] as usize;
                let is_array = row < class_names.len() && class_names[row].starts_with('[');
                if is_array {
                    let bit_pos = mat_id as usize;
                    words[bit_pos / 32] |= 1i32.wrapping_shl((bit_pos % 32) as u32);
                }
            }
        }
        ser.u8(TC_OBJECT);
        {
            // MAT's BitField (org.eclipse.mat.collect.BitField, uid 1) declares
            // exactly ONE field: `private int[] bits`. There is no `size` field —
            // the bit count is implied by the array length. Writing a `size`/`words`
            // pair leaves MAT's `bits` field null, and every later
            // BitField.get(id) NPEs.
            let bf_cd = ClassDesc {
                name: "org.eclipse.mat.collect.BitField".into(),
                uid: uid::BIT_FIELD,
                flags: SC_SERIALIZABLE,
                fields: vec![f_arr("bits", "[I")],
            };
            ser.write_class_desc_chain(&[bf_cd]);
        }
        let _bf_handle = ser.assign_handle_pub();
        // words: TC_ARRAY of int
        ser.write_int_array(&words);

        // Write stream to file.
        let path = self.dir.join(format!("{}.index", self.prefix));
        let mut f = BufWriter::new(File::create(&path)?);
        f.write_all(&ser.buf)?;
        f.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        Ok(())
    }
}

/// Convert an HPROF class name to the form MAT's `ClassImpl.getName()` uses.
///
/// HPROF stores JVM-internal names (`java/lang/String`, `[Ljava/lang/String;`);
/// MAT normalises them to the source form (`java.lang.String`,
/// `java.lang.String[]`, `int[][]`). MAT's class lookup by name
/// (`getClassesByName`, OQL `FROM java.lang.String`) keys off this form, so a
/// raw HPROF name makes those lookups miss.
pub fn mat_class_name(name: &str) -> String {
    let dims = name.chars().take_while(|&c| c == '[').count();
    if dims == 0 {
        return name.replace('/', ".");
    }
    let base = &name[dims..];
    let comp = match base {
        "I" => "int",
        "J" => "long",
        "S" => "short",
        "B" => "byte",
        "C" => "char",
        "F" => "float",
        "D" => "double",
        "Z" => "boolean",
        s if s.starts_with('L') && s.ends_with(';') && s.len() > 2 => &s[1..s.len() - 1],
        _ => return name.replace('/', "."),
    };
    format!("{}{}", comp.replace('/', "."), "[]".repeat(dims))
}

/// Write a MAT `FieldDescriptor[]` (TC_ARRAY of
/// `org.eclipse.mat.snapshot.model.FieldDescriptor`, uid 2, fields
/// `type:int` + `name:String`).
///
/// `fields` is `(name, HPROF typecode)`; the typecode is numerically identical
/// to MAT's `IObject.Type`, so it goes through unchanged.
fn write_field_descriptors(s: &mut serial::Ser, fields: &[(String, u8)]) {
    use serial::{FieldVal, LayerData, Ser, f_int, f_obj};
    let chain = vec![serial::ClassDesc {
        name: "org.eclipse.mat.snapshot.model.FieldDescriptor".into(),
        uid: 2,
        flags: serial::SC_SERIALIZABLE,
        fields: vec![f_int("type"), f_obj("name", "Ljava/lang/String;")],
    }];
    let mut it = fields.iter();
    s.write_object_array(
        "[Lorg.eclipse.mat.snapshot.model.FieldDescriptor;",
        serial::uid::FIELD_DESCRIPTOR_ARRAY,
        fields.len() as i32,
        move |s: &mut Ser| {
            for (name, ty) in it.by_ref() {
                let n = name.clone();
                s.write_object(
                    &chain,
                    vec![LayerData {
                        fields: vec![f_int("type"), f_obj("name", "Ljava/lang/String;")],
                        values: vec![
                            ("type".into(), FieldVal::Int(*ty as i32)),
                            (
                                "name".into(),
                                FieldVal::ObjRef(Box::new(move |s: &mut Ser| {
                                    s.string(&n);
                                })),
                            ),
                        ],
                    }],
                );
            }
        },
    );
}

/// Write a MAT `Field[]` for a class's static (constant-pool) fields.
///
/// `fields` is `(name, HPROF typecode, raw big-endian value bits)`. MAT's
/// `AbstractParser.readValue` boxes the value by type — an object field becomes
/// an `ObjectReference` (or `null` when the address is 0), a primitive becomes
/// the corresponding `java.lang` wrapper — and several MAT reports read these
/// (the System Properties view reads `java.lang.System.props`).
fn write_static_fields(s: &mut serial::Ser, fields: &[(String, u8, u64)]) {
    use serial::{Ser, uid};
    let mut it = fields.iter();
    s.write_object_array(
        "[Lorg.eclipse.mat.snapshot.model.Field;",
        uid::FIELD_ARRAY,
        fields.len() as i32,
        move |s: &mut Ser| {
            for (name, ty, val) in it.by_ref() {
                let (ty, val) = (*ty, *val);
                s.write_field(name, ty as i32, move |s: &mut Ser| {
                    if ty == 2 {
                        if val == 0 {
                            s.null();
                        } else {
                            s.write_object_reference(val);
                        }
                    } else {
                        s.write_boxed_primitive(ty, val);
                    }
                });
            }
        },
    );
}

/// MAT `SizeIndexCollectorUncompressed.compress`
#[allow(dead_code)]
pub fn size_compress(y: i64) -> i32 {
    if y < 0 {
        -1
    } else if y <= i32::MAX as i64 {
        y as i32
    } else if y <= 0x4_0000_0000 {
        ((y / 8) as i32).wrapping_add(0x7000_0000)
    } else {
        0xf000_0000u32 as i32
    }
}

/// Build the per-class inverse table: histogram row -> dense id of that row's
/// class-object. `coc` maps `class-object dense id -> histogram row` (MAT's
/// `class_obj_class_idx`, sparse — only class objects appear). We invert it so
/// that `inv[class_idx[obj]]` yields the class-object id for `o2c`.
///
/// When multiple class-objects share the same row (e.g. primitive-array or
/// java/lang/Class duplicates across different address spaces), we prefer the
/// reachable one (mm.translate >= 0) to avoid emitting o2c=0 for all instances
/// of that class. Among reachable entries, lowest dense-id wins (deterministic).
///
/// Rows with no class object keep the sentinel `-1`.
#[allow(dead_code)]
pub fn build_row_to_classobj_id(
    coc: &HashMap<u32, u32>,
    num_classes: usize,
    mm: &MatIdMap,
) -> Vec<i32> {
    let mut inv = vec![-1i32; num_classes];
    // First pass: fill with any entry (last-wins over HashMap iteration)
    for (&classobj_id, &row) in coc {
        let slot = &mut inv[row as usize];
        if *slot < 0 {
            // No entry yet: take it unconditionally.
            *slot = classobj_id as i32;
        } else {
            // Prefer reachable over unreachable; among equal reachability, lower id wins.
            let cur_reachable = mm.translate(*slot) >= 0;
            let new_reachable = mm.translate(classobj_id as i32) >= 0;
            if (!cur_reachable && new_reachable)
                || (cur_reachable == new_reachable && (classobj_id as i32) < *slot)
            {
                *slot = classobj_id as i32;
            }
        }
    }
    inv
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn emitter_creates_dir_and_is_noop_without_calls() {
        let tmp = std::env::temp_dir().join("mat_emit_test_0");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        drop(e);
        assert!(tmp.exists());
    }

    #[test]
    fn inverse_class_table_maps_row_to_classobj_id() {
        // class-object dense id 100 has histogram row 2; id 200 has row 5.
        let mut coc = HashMap::new();
        coc.insert(100u32, 2u32);
        coc.insert(200u32, 5u32);
        // All objects reachable (idom[i] != u32::MAX), addresses 0,1,...
        let idom: Vec<u32> = vec![0u32; 201];
        let mm = MatIdMap::build(201, &idom, |i| i as u64);
        let inv = build_row_to_classobj_id(&coc, 6, &mm);
        assert_eq!(inv[2], 100);
        assert_eq!(inv[5], 200);
        // untouched rows keep the -1 sentinel
        assert_eq!(inv[0], -1);
        assert_eq!(inv[1], -1);
        assert_eq!(inv[3], -1);
        assert_eq!(inv[4], -1);
    }

    #[test]
    fn inverse_class_table_prefers_reachable_entry() {
        // Two class-objects map to the same row: id 50 (unreachable) and id 51 (reachable).
        // build_row_to_classobj_id should keep id 51.
        let mut coc = HashMap::new();
        coc.insert(50u32, 3u32);
        coc.insert(51u32, 3u32);
        // Mark id 50 unreachable (idom[50] = u32::MAX), id 51 reachable.
        let mut idom = vec![0u32; 60];
        idom[50] = u32::MAX;
        let mm = MatIdMap::build(60, &idom, |i| i as u64);
        let inv = build_row_to_classobj_id(&coc, 6, &mm);
        assert_eq!(
            inv[3], 51,
            "should prefer reachable id 51 over unreachable id 50"
        );
    }

    /// `emit_o2c` composes an identity `inv` (row == value) so we can drive it
    /// from an arbitrary class_idx stream and confirm the resulting file decodes
    /// back to the input values through the standard IntIndex reader path.
    #[test]
    fn emit_o2c_roundtrips_through_streamer() {
        use crate::cvec::Codec;
        let class_idx: Vec<u32> = vec![3, 0, 3, 1, 2, 2, 0];
        let inv: Vec<i32> = (0..8).collect(); // identity
        let c = CompressedU32::compress(&class_idx, Codec::None).unwrap();

        let tmp = std::env::temp_dir().join("mat_emit_o2c_test");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_o2c(&c, &inv).unwrap();

        let bytes = std::fs::read(e.path("o2c")).unwrap();
        let vals = decode_int_index(&bytes);
        let expected: Vec<i32> = class_idx.iter().map(|&r| inv[r as usize]).collect();
        assert_eq!(vals, expected);
    }

    /// Definition of done: re-emit the real MAT `o2c` values and assert the file
    /// is byte-identical. Uses an identity `inv` fed by the decoded values, so
    /// this validates the emit_o2c -> IntIndexStreamer path against ground truth.
    #[test]
    fn matches_real_o2c() {
        use crate::cvec::Codec;
        let path = "/tmp/matidx/dump_.o2c.index";
        let Ok(real) = std::fs::read(path) else {
            eprintln!("skip matches_real_o2c: fixture absent at {path}");
            return;
        };
        let vals = decode_int_index(&real);
        // Feed the values as the class-idx stream with an identity inv.
        let class_idx: Vec<u32> = vals.iter().map(|&v| v as u32).collect();
        let max = *class_idx.iter().max().unwrap() as usize;
        let inv: Vec<i32> = (0..=max as i32).collect();
        let c = CompressedU32::compress(&class_idx, Codec::None).unwrap();

        let tmp = std::env::temp_dir().join("mat_emit_o2c_real");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_o2c(&c, &inv).unwrap();
        let ours = std::fs::read(e.path("o2c")).unwrap();

        if ours != real {
            let at = ours
                .iter()
                .zip(&real)
                .position(|(a, b)| a != b)
                .unwrap_or(ours.len().min(real.len()));
            panic!(
                "matches_real_o2c byte mismatch: ours.len={} real.len={} first diff at {}",
                ours.len(),
                real.len(),
                at
            );
        }
    }

    /// Decode a plain MAT IntIndex file into its i32 values.
    fn decode_int_index(buf: &[u8]) -> Vec<i32> {
        use codec::decode_int;
        let n = buf.len();
        let size = i32::from_be_bytes(buf[n - 4..n].try_into().unwrap()) as i64;
        let page_size = i32::from_be_bytes(buf[n - 8..n - 4].try_into().unwrap()) as usize;
        let pages = (size as usize).div_ceil(page_size);
        let entries = pages + 1;
        let footer_start = n - 8 - entries * 8;
        let mut ps = Vec::with_capacity(entries);
        for i in 0..entries {
            let off = footer_start + i * 8;
            ps.push(i64::from_be_bytes(buf[off..off + 8].try_into().unwrap()) as usize);
        }
        let mut out = Vec::with_capacity(size as usize);
        for i in 0..pages {
            let cnt = std::cmp::min(page_size, size as usize - i * page_size);
            out.extend_from_slice(&decode_int(&buf[ps[i]..ps[i + 1]], cnt));
        }
        out
    }

    /// Decode a plain MAT LongIndex file into its i64 values.
    fn decode_long_index(buf: &[u8]) -> Vec<i64> {
        use codec::decode_long;
        let n = buf.len();
        let size = i32::from_be_bytes(buf[n - 4..n].try_into().unwrap()) as i64;
        let page_size = i32::from_be_bytes(buf[n - 8..n - 4].try_into().unwrap()) as usize;
        let pages = (size as usize).div_ceil(page_size);
        let entries = pages + 1;
        let footer_start = n - 8 - entries * 8;
        let mut ps = Vec::with_capacity(entries);
        for i in 0..entries {
            let off = footer_start + i * 8;
            ps.push(i64::from_be_bytes(buf[off..off + 8].try_into().unwrap()) as usize);
        }
        let mut out = Vec::with_capacity(size as usize);
        for i in 0..pages {
            let cnt = std::cmp::min(page_size, size as usize - i * page_size);
            out.extend_from_slice(&decode_long(&buf[ps[i]..ps[i + 1]], cnt));
        }
        out
    }

    #[test]
    fn size_compress_boundaries() {
        assert_eq!(size_compress(-1), -1);
        assert_eq!(size_compress(-999), -1);
        assert_eq!(size_compress(0), 0);
        assert_eq!(size_compress(48), 48);
        assert_eq!(size_compress(i32::MAX as i64), i32::MAX);
        // just above i32::MAX uses the /8 + 0x70000000 encoding
        let y = i32::MAX as i64 + 1;
        assert_eq!(size_compress(y), ((y / 8) as i32).wrapping_add(0x7000_0000));
        // the documented upper cap
        assert_eq!(size_compress(0x4_0000_0001), 0xf000_0000u32 as i32);
    }

    #[test]
    fn matches_real_idx_long() {
        let path = "/tmp/matidx/dump_.idx.index";
        let Ok(real) = std::fs::read(path) else {
            eprintln!("skip matches_real_idx_long: fixture absent at {path}");
            return;
        };
        let vals = decode_long_index(&real);
        let addrs: Vec<u64> = vals.iter().map(|&v| v as u64).collect();
        let tmp = std::env::temp_dir().join("mat_emit_idx_real");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_idx(addrs.len(), |i| addrs[i]).unwrap();
        let ours = std::fs::read(e.path("idx")).unwrap();
        assert_files_eq("idx", &ours, &real);
    }

    #[test]
    fn matches_real_a2s() {
        use crate::cvec::Codec;
        let path = "/tmp/matidx/dump_.a2s.index";
        let Ok(real) = std::fs::read(path) else {
            eprintln!("skip matches_real_a2s: fixture absent at {path}");
            return;
        };
        // Real a2s already stores compressed sizes; for our fixture every value
        // is <= i32::MAX so compress() is identity and we can round-trip them
        // directly as the "shallow" input.
        let vals = decode_int_index(&real);
        assert!(
            vals.iter().all(|&v| v >= 0),
            "fixture a2s within identity range"
        );
        let shallow: Vec<u32> = vals.iter().map(|&v| v as u32).collect();
        let c = CompressedU32::compress(&shallow, Codec::None).unwrap();
        let tmp = std::env::temp_dir().join("mat_emit_a2s_real");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_a2s(&c).unwrap();
        let ours = std::fs::read(e.path("a2s")).unwrap();
        assert_files_eq("a2s", &ours, &real);
    }

    #[test]
    fn matches_real_dom_in() {
        let path = "/tmp/matidx/dump_.domIn.index";
        let Ok(real) = std::fs::read(path) else {
            eprintln!("skip matches_real_dom_in: fixture absent at {path}");
            return;
        };
        let idom = decode_int_index(&real);
        let tmp = std::env::temp_dir().join("mat_emit_domin_real");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_dom_in(&idom).unwrap();
        let ours = std::fs::read(e.path("domIn")).unwrap();
        assert_files_eq("domIn", &ours, &real);
    }

    #[test]
    fn matches_real_o2ret() {
        let path = "/tmp/matidx/dump_.o2ret.index";
        let Ok(real) = std::fs::read(path) else {
            eprintln!("skip matches_real_o2ret: fixture absent at {path}");
            return;
        };
        let retained = decode_long_index(&real);
        let tmp = std::env::temp_dir().join("mat_emit_o2ret_real");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_o2ret(&retained).unwrap();
        let ours = std::fs::read(e.path("o2ret")).unwrap();
        assert_files_eq("o2ret", &ours, &real);
    }

    fn assert_files_eq(name: &str, ours: &[u8], real: &[u8]) {
        if ours != real {
            let at = ours
                .iter()
                .zip(real)
                .position(|(a, b)| a != b)
                .unwrap_or(ours.len().min(real.len()));
            panic!(
                "{name} byte mismatch: ours.len={} real.len={} first diff at {}",
                ours.len(),
                real.len(),
                at
            );
        }
    }

    // ── MatIdMap unit tests ──────────────────────────────────────────────────

    #[test]
    fn mat_id_map_address_sorted_reachable_only() {
        // 5 objects: addresses out of order, object 2 is unreachable (idom==MAX)
        // dense ids:   0      1      2          3      4
        let addrs = [0x300u64, 0x100, 0x500, 0x200, 0x400];
        // idom: 0→vroot(5), 1→0, 2→UNREACHABLE, 3→0, 4→0, vroot→vroot
        let mut idom = vec![5u32, 0, u32::MAX, 0, 0, 5];
        idom[5] = 5; // virtual root self-loop

        let map = MatIdMap::build(5, &idom, |i| addrs[i]);

        // mat-id 0 = synthetic; reachable sorted by addr: 1(0x100) 3(0x200) 0(0x300) 4(0x400)
        assert_eq!(map.mat_count(), 5); // 4 reachable + synthetic id-0
        assert_eq!(map.sorted(), &[1u32, 3, 0, 4]);

        // old-id 1 → mat-id 1 (smallest addr among reachable)
        assert_eq!(map.translate(1), 1);
        assert_eq!(map.translate(3), 2);
        assert_eq!(map.translate(0), 3);
        assert_eq!(map.translate(4), 4);
        // unreachable object 2 → -1
        assert_eq!(map.translate(2), -1);
        // out-of-range → -1
        assert_eq!(map.translate(-1), -1);
        assert_eq!(map.translate(99), -1);
    }

    #[test]
    fn mat_id_map_all_reachable() {
        // 3 objects, all reachable, already address-sorted
        let addrs = [0x10u64, 0x20, 0x30];
        let idom = vec![3u32, 3, 3, 3]; // all dominated by vroot (index 3)
        let map = MatIdMap::build(3, &idom, |i| addrs[i]);
        assert_eq!(map.mat_count(), 4);
        assert_eq!(map.translate(0), 1);
        assert_eq!(map.translate(1), 2);
        assert_eq!(map.translate(2), 3);
    }

    #[test]
    fn mat_id_map_empty_graph() {
        // n=0: no objects at all; mat_count = 1 (synthetic root only)
        let idom: Vec<u32> = vec![];
        let map = MatIdMap::build(0, &idom, |_| 0);
        assert_eq!(map.mat_count(), 1);
        assert_eq!(map.sorted(), &[] as &[u32]);
        assert_eq!(map.translate(0), -1);
    }

    #[test]
    fn mat_id_map_all_unreachable() {
        // 3 objects, all unreachable (idom==MAX)
        let idom = vec![u32::MAX; 3];
        let map = MatIdMap::build(3, &idom, |i| i as u64);
        assert_eq!(map.mat_count(), 1); // only synthetic root
        assert_eq!(map.sorted(), &[] as &[u32]);
        assert_eq!(map.translate(0), -1);
        assert_eq!(map.translate(1), -1);
    }

    #[test]
    fn size_compress_at_exact_boundary() {
        // 0x4_0000_0000 is the last value to use the /8 encoding
        let boundary = 0x4_0000_0000i64;
        let expected = ((boundary / 8) as i32).wrapping_add(0x7000_0000);
        assert_eq!(size_compress(boundary), expected);
        // one over → cap
        assert_eq!(size_compress(boundary + 1), 0xf000_0000u32 as i32);
        // one under i32::MAX boundary → identity
        assert_eq!(size_compress(i32::MAX as i64), i32::MAX);
        // one over i32::MAX → /8 encoding
        let just_over = i32::MAX as i64 + 1;
        assert_eq!(
            size_compress(just_over),
            ((just_over / 8) as i32).wrapping_add(0x7000_0000)
        );
    }

    // ── emit_i2sv2 ──────────────────────────────────────────────────────────

    #[test]
    fn emit_i2sv2_empty_produces_empty_file() {
        let tmp = std::env::temp_dir().join("mat_i2sv2_empty");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_i2sv2(std::iter::empty()).unwrap();
        let path = tmp.join("dump_.i2sv2.index");
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.is_empty(), "empty iterator should produce empty file");
    }

    #[test]
    fn emit_i2sv2_encoding() {
        // Three entries: (class_mat_id, retained) → file = (i32_be, i64_neg_be) x 3
        let entries = [(1i32, 100i64), (7i32, 200i64), (-1i32, 0i64)];
        let tmp = std::env::temp_dir().join("mat_i2sv2_encoding");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_i2sv2(entries.iter().copied()).unwrap();
        let bytes = std::fs::read(tmp.join("dump_.i2sv2.index")).unwrap();
        assert_eq!(bytes.len(), 3 * 12, "each entry is 4 + 8 bytes");
        // First entry: class_mat_id=1, retained=100 → stored as -100
        assert_eq!(&bytes[0..4], &1i32.to_be_bytes());
        assert_eq!(&bytes[4..12], &(-100i64).to_be_bytes());
        // Second entry
        assert_eq!(&bytes[12..16], &7i32.to_be_bytes());
        assert_eq!(&bytes[16..24], &(-200i64).to_be_bytes());
        // Third (retained=0 → stored as 0, negated)
        assert_eq!(&bytes[24..28], &(-1i32).to_be_bytes());
        assert_eq!(&bytes[28..36], &0i64.to_be_bytes());
    }

    #[test]
    fn emit_i2sv2_roundtrip_size() {
        // File size must always be a multiple of 12.
        let entries: Vec<(i32, i64)> = (0..50).map(|i| (i, i as i64 * 1000)).collect();
        let tmp = std::env::temp_dir().join("mat_i2sv2_roundtrip");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_i2sv2(entries.iter().copied()).unwrap();
        let bytes = std::fs::read(tmp.join("dump_.i2sv2.index")).unwrap();
        assert_eq!(bytes.len() % 12, 0);
        assert_eq!(bytes.len() / 12, 50);
    }

    // ── emit_threads ────────────────────────────────────────────────────────

    fn make_thread_stack(
        serial: u32,
        thread_obj_idx: u32,
        frames: &[&str],
    ) -> crate::pass2::ThreadStack {
        crate::pass2::ThreadStack {
            thread_serial: serial,
            thread_obj_idx,
            frames: frames.iter().map(|s| s.to_string()).collect(),
            mat_frames: frames.iter().map(|s| format!("  at {s}")).collect(),
        }
    }

    /// Build the small `dense-id → address` side table `emit_threads` takes
    /// (the caller captures it from the dense address table while that is live).
    fn addr_map(pairs: &[(u32, u64)]) -> HashMap<u32, u64> {
        pairs.iter().copied().collect()
    }

    #[test]
    fn emit_threads_empty_produces_empty_file() {
        // No thread stacks at all → file should be empty (0 bytes, no content).
        let tmp = std::env::temp_dir().join("mat_threads_empty");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_threads(&[], &HashMap::new(), &HashMap::new())
            .unwrap();
        let bytes = std::fs::read(tmp.join("dump_.threads")).unwrap();
        assert!(bytes.is_empty(), "no threads → empty file");
    }

    #[test]
    fn emit_threads_writes_header_only_block_for_empty_stack() {
        // A thread with an empty stack is still a thread MAT writes: it gets a
        // header, no frames, and an (empty) locals section. Dropping it lost the
        // thread from MAT entirely.
        let ts = make_thread_stack(1, 0, &[]); // no frames
        let tmp = std::env::temp_dir().join("mat_threads_skip_noframe");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_threads(&[ts], &addr_map(&[(0, 0x10)]), &HashMap::new())
            .unwrap();
        let content = std::fs::read_to_string(tmp.join("dump_.threads")).unwrap();
        assert_eq!(
            content, "Thread 0x10\n\n  locals:\n\n",
            "empty-stack thread must be written as a header-only block"
        );
    }

    #[test]
    fn emit_threads_always_writes_locals_header() {
        // The `  locals:` header is unconditional. The MAT reader probes the
        // line after the frames for `locals`; when it is missing, the reader
        // consumes the NEXT thread's header as the probe and drops that thread.
        let stacks = vec![
            make_thread_stack(1, 0, &["a.A.run(A.java:1)"]),
            make_thread_stack(2, 1, &["b.B.run(B.java:2)"]),
        ];
        let tmp = std::env::temp_dir().join("mat_threads_locals_header");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        // No locals for either thread.
        e.emit_threads(&stacks, &addr_map(&[(0, 0x10), (1, 0x20)]), &HashMap::new())
            .unwrap();
        let content = std::fs::read_to_string(tmp.join("dump_.threads")).unwrap();
        let headers = content.lines().filter(|l| l.starts_with("Thread ")).count();
        let locals = content.lines().filter(|l| l.trim() == "locals:").count();
        assert_eq!(headers, 2, "{content}");
        assert_eq!(
            locals, headers,
            "every thread block needs a locals header:\n{content}"
        );
        // Frame lines end with CRLF, exactly as MAT writes them.
        assert!(
            content.contains("  at a.A.run(A.java:1)\r\n"),
            "{content:?}"
        );
    }

    #[test]
    fn emit_threads_single_thread_address_and_frames() {
        // Thread obj_idx=0 → its *real* address 0x10, not the old 0x0 placeholder.
        let ts = make_thread_stack(
            1,
            0,
            &[
                "com.example.Foo.bar(Foo.java:42)",
                "com.example.Main.main(Main.java:10)",
            ],
        );
        let tmp = std::env::temp_dir().join("mat_threads_single");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_threads(&[ts], &addr_map(&[(0, 0x10)]), &HashMap::new())
            .unwrap();
        let content = std::fs::read_to_string(tmp.join("dump_.threads")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines[0], "Thread 0x10");
        assert_eq!(lines[1], "  at com.example.Foo.bar(Foo.java:42)");
        assert_eq!(lines[2], "  at com.example.Main.main(Main.java:10)");
        // trailing blank line
        assert!(content.ends_with('\n'));
    }

    #[test]
    fn emit_threads_skips_thread_with_unresolved_object() {
        // A thread whose object never resolved (our `u32::MAX` sentinel — the
        // analogue of MAT's `tid == null`) has no address to write, so the whole
        // block is skipped. MAT's `dumpThreads` does the same `continue`, and a
        // `0x0` placeholder would be unmappable for its reader anyway.
        let ts = make_thread_stack(5, u32::MAX, &["java.lang.Thread.run(Thread.java:1)"]);
        let tmp = std::env::temp_dir().join("mat_threads_unresolved");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_threads(&[ts], &HashMap::new(), &HashMap::new())
            .unwrap();
        let content = std::fs::read_to_string(tmp.join("dump_.threads")).unwrap();
        assert!(
            content.is_empty(),
            "unresolved thread object → block skipped, got: {content:?}"
        );
    }

    #[test]
    fn emit_threads_writes_real_addresses_never_zero() {
        // Regression for the `Thread 0x0` bug: `emit_threads` used to write a zero
        // address for every thread *and* every local, because `MatIdMap` no longer
        // stores addresses. MAT's `ThreadStackHelper` then failed
        // `mapAddressToId(0x0)` on every line, leaving `threadId2stack` empty so
        // `getThreadStack` returned null for every thread. This asserts the
        // addresses are real and resolvable — not merely that the file exists.
        let addrs = addr_map(&[
            (0, 0x7e41c01c5608),
            (1, 0x7e41c01c5700),
            (2, 0x7e41c01c5800),
        ]);
        let stacks = vec![
            make_thread_stack(1, 0, &["a.A.run(A.java:1)"]),
            make_thread_stack(2, 1, &["b.B.run(B.java:2)"]),
        ];
        let mut locals: HashMap<u32, Vec<(u32, u32)>> = HashMap::new();
        locals.insert(1, vec![(0u32, 2u32)]);
        let tmp = std::env::temp_dir().join("mat_threads_real_addrs");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_threads(&stacks, &addrs, &locals).unwrap();
        let content = std::fs::read_to_string(tmp.join("dump_.threads")).unwrap();

        assert!(
            !content.contains("Thread 0x0"),
            "no thread may be written with a zero address:\n{content}"
        );
        // Every "Thread 0x<hex>" line must name an address present in the index.
        let known: std::collections::HashSet<String> =
            addrs.values().map(|a| format!("Thread 0x{a:x}")).collect();
        let mut seen = 0usize;
        for line in content.lines().filter(|l| l.starts_with("Thread ")) {
            assert!(
                known.contains(line),
                "thread address {line:?} maps to no object in the index"
            );
            seen += 1;
        }
        assert_eq!(seen, 2, "expected both threads to be written:\n{content}");
        // Same for the locals section.
        assert!(
            !content.contains("objectId=0x0,"),
            "no local may be written with a zero address:\n{content}"
        );
        assert!(
            content.contains("objectId=0x7e41c01c5800, line=0"),
            "local should carry its real address and its frame index:\n{content}"
        );
    }

    #[test]
    fn emit_threads_with_locals() {
        // Thread with locals section: frame_num and local object addresses.
        let addrs = addr_map(&[(0, 0x100), (1, 0x200), (2, 0x300)]);
        let ts = make_thread_stack(1, 0, &["frame1(A.java:1)"]);
        let mut locals: HashMap<u32, Vec<(u32, u32)>> = HashMap::new();
        // serial=1, frame_num=0 → line 0 (0-based frame index);
        // frame_num=MAX (no frame) → line -1, as MAT writes it.
        locals.insert(1, vec![(0u32, 2u32), (u32::MAX, 1u32)]);
        let tmp = std::env::temp_dir().join("mat_threads_locals");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_threads(&[ts], &addrs, &locals).unwrap();
        let content = std::fs::read_to_string(tmp.join("dump_.threads")).unwrap();
        assert!(content.contains("locals:"), "should have locals section");
        assert!(
            content.contains("objectId=0x300, line=0"),
            "frame_num=0 → line 0 (frame index), real address:\n{content}"
        );
        assert!(
            content.contains("objectId=0x200, line=-1"),
            "frame_num=MAX (no frame) → line -1, real address:\n{content}"
        );
    }

    #[test]
    fn emit_threads_multiple_threads_separated_by_blank_lines() {
        let addrs = addr_map(&[(0, 0x10), (1, 0x20), (2, 0x30)]);
        let stacks = vec![
            make_thread_stack(1, 0, &["a.A.run(A.java:1)"]),
            make_thread_stack(2, 1, &["b.B.run(B.java:2)"]),
        ];
        let tmp = std::env::temp_dir().join("mat_threads_multi");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_threads(&stacks, &addrs, &HashMap::new()).unwrap();
        let content = std::fs::read_to_string(tmp.join("dump_.threads")).unwrap();
        // Each thread gets its own real address, not the old shared 0x0.
        assert!(content.contains("Thread 0x10\n"), "{content}");
        assert!(content.contains("Thread 0x20\n"), "{content}");
        let thread_count = content.lines().filter(|l| l.starts_with("Thread ")).count();
        assert_eq!(thread_count, 2, "expected 2 threads, got:\n{content}");
        // Each thread block ends with a blank line → content has at least 2 blank lines
        let blank_lines = content.lines().filter(|l| l.is_empty()).count();
        assert!(
            blank_lines >= 2,
            "expected blank lines between threads, got {blank_lines}"
        );
    }

    // ---- emit_outbound / emit_inbound / emit_dom_out roundtrip tests ----

    fn read_sorted_1n(path: &std::path::Path) -> Vec<Vec<i32>> {
        let bytes = std::fs::read(path).unwrap();
        let n = bytes.len();
        let divider = i64::from_be_bytes(bytes[n - 8..n].try_into().unwrap()) as usize;

        fn parse_footer(region: &[u8]) -> (usize, i32, i64, Vec<i64>) {
            let n = region.len();
            let size = i32::from_be_bytes(region[n - 4..n].try_into().unwrap());
            let page_size = i32::from_be_bytes(region[n - 8..n - 4].try_into().unwrap());
            let pages = (size as usize).div_ceil(page_size as usize);
            let entries = pages + 1;
            let footer_start = n - 8 - entries * 8;
            let mut starts = Vec::with_capacity(entries);
            for i in 0..entries {
                let off = footer_start + i * 8;
                starts.push(i64::from_be_bytes(region[off..off + 8].try_into().unwrap()));
            }
            (pages, page_size, size as i64, starts)
        }

        fn decode_region(
            file: &[u8],
            _region: &[u8],
            pages: usize,
            psize: i32,
            size: i64,
            starts: &[i64],
        ) -> Vec<i32> {
            use crate::mat::codec::decode_int;
            let mut out = Vec::with_capacity(size as usize);
            for i in 0..pages {
                let s = starts[i] as usize;
                let e = starts[i + 1] as usize;
                let n = (psize as usize).min(size as usize - i * psize as usize);
                out.extend_from_slice(&decode_int(&file[s..e], n));
            }
            out
        }

        fn sorted_get(hdr: &[i32], body: &[i32], idx: usize) -> Vec<i32> {
            let p0 = hdr[idx] as i64;
            if p0 == 0 {
                return vec![];
            }
            let body_end = (body.len() + 1) as i64;
            let mut p1 = if idx + 1 < hdr.len() {
                hdr[idx + 1] as i64
            } else {
                body_end
            };
            let mut j = idx + 2;
            while p1 < p0 && j < hdr.len() {
                p1 = hdr[j] as i64;
                j += 1;
            }
            if p1 < p0 {
                p1 = body_end;
            }
            let s = (p0 - 1) as usize;
            body[s..s + (p1 - p0) as usize].to_vec()
        }

        let body_region = &bytes[0..divider];
        let (bp, bps, bs, bst) = parse_footer(body_region);
        let body_vals = decode_region(&bytes, body_region, bp, bps, bs, &bst);

        let hdr_region = &bytes[divider..n - 8];
        let (hp, hps, hs, hst) = parse_footer(hdr_region);
        let hst_local: Vec<i64> = hst.iter().map(|&s| s - divider as i64).collect();
        let hdr_vals = decode_region(hdr_region, hdr_region, hp, hps, hs, &hst_local);

        (0..hdr_vals.len())
            .map(|i| sorted_get(&hdr_vals, &body_vals, i))
            .collect()
    }

    fn read_unsorted_1n(path: &std::path::Path) -> Vec<Vec<i32>> {
        let bytes = std::fs::read(path).unwrap();
        let n = bytes.len();
        let divider = i64::from_be_bytes(bytes[n - 8..n].try_into().unwrap()) as usize;

        fn parse_footer(region: &[u8]) -> (usize, i32, i64, Vec<i64>) {
            let n = region.len();
            let size = i32::from_be_bytes(region[n - 4..n].try_into().unwrap());
            let page_size = i32::from_be_bytes(region[n - 8..n - 4].try_into().unwrap());
            let pages = (size as usize).div_ceil(page_size as usize);
            let entries = pages + 1;
            let footer_start = n - 8 - entries * 8;
            let mut starts = Vec::with_capacity(entries);
            for i in 0..entries {
                let off = footer_start + i * 8;
                starts.push(i64::from_be_bytes(region[off..off + 8].try_into().unwrap()));
            }
            (pages, page_size, size as i64, starts)
        }

        fn decode_region(
            file: &[u8],
            pages: usize,
            psize: i32,
            size: i64,
            starts: &[i64],
        ) -> Vec<i32> {
            use crate::mat::codec::decode_int;
            let mut out = Vec::with_capacity(size as usize);
            for i in 0..pages {
                let s = starts[i] as usize;
                let e = starts[i + 1] as usize;
                let n = (psize as usize).min(size as usize - i * psize as usize);
                out.extend_from_slice(&decode_int(&file[s..e], n));
            }
            out
        }

        let body_region = &bytes[0..divider];
        let (bp, bps, bs, bst) = parse_footer(body_region);
        let body_vals = decode_region(&bytes, bp, bps, bs, &bst);

        let hdr_region = &bytes[divider..n - 8];
        let (hp, hps, hs, hst) = parse_footer(hdr_region);
        let hst_local: Vec<i64> = hst.iter().map(|&s| s - divider as i64).collect();
        let hdr_vals = decode_region(hdr_region, hp, hps, hs, &hst_local);

        let mut out = Vec::with_capacity(hdr_vals.len());
        for &pos in &hdr_vals {
            let p = pos as usize;
            let len = body_vals[p] as usize;
            out.push(body_vals[p + 1..p + 1 + len].to_vec());
        }
        out
    }

    #[test]
    fn emit_outbound_roundtrip() {
        let entries: Vec<Vec<i32>> = vec![
            vec![5, 3, 1], // object 0: class-ref + 2 refs
            vec![],        // object 1: no outbound refs (hole)
            vec![7, 2],    // object 2: class-ref + 1 ref
            vec![9],       // object 3: class-ref only
        ];
        let tmp = std::env::temp_dir().join("mat_emit_outbound_rt");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_outbound(&entries).unwrap();
        let path = tmp.join("dump_.outbound.index");
        let recon = read_sorted_1n(&path);
        assert_eq!(recon, entries, "outbound sorted roundtrip");
    }

    #[test]
    fn emit_inbound_roundtrip() {
        let entries: Vec<Vec<i32>> = vec![
            vec![],     // object 0: no inbound (hole)
            vec![0, 2], // object 1: referenced by 0 and 2
            vec![0],    // object 2: referenced by 0
            vec![],     // object 3: hole
        ];
        let tmp = std::env::temp_dir().join("mat_emit_inbound_rt");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_inbound(&entries).unwrap();
        let path = tmp.join("dump_.inbound.index");
        let recon = read_sorted_1n(&path);
        assert_eq!(recon, entries, "inbound sorted roundtrip");
    }

    #[test]
    fn emit_dom_out_roundtrip() {
        // domOut is UNSORTED: entries[0] = superroot children, entries[k+1] = children of k.
        let entries: Vec<Vec<i32>> = vec![
            vec![1, 2], // superroot children: objects 1 and 2
            vec![3],    // object 0 dominated by: 3
            vec![],     // object 1: no dominated children
            vec![],     // object 2: no dominated children
            vec![],     // object 3: no dominated children
        ];
        let tmp = std::env::temp_dir().join("mat_emit_domout_rt");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_dom_out(&entries).unwrap();
        let path = tmp.join("dump_.domOut.index");
        let recon = read_unsorted_1n(&path);
        assert_eq!(recon, entries, "domOut unsorted roundtrip");
    }

    #[test]
    fn emit_outbound_all_empty_roundtrip() {
        let entries: Vec<Vec<i32>> = vec![vec![], vec![], vec![]];
        let tmp = std::env::temp_dir().join("mat_emit_outbound_empty");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_outbound(&entries).unwrap();
        let recon = read_sorted_1n(&tmp.join("dump_.outbound.index"));
        assert_eq!(recon, entries);
    }

    #[test]
    fn emit_inbound_all_empty_roundtrip() {
        let entries: Vec<Vec<i32>> = vec![vec![], vec![], vec![]];
        let tmp = std::env::temp_dir().join("mat_emit_inbound_empty");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_inbound(&entries).unwrap();
        let recon = read_sorted_1n(&tmp.join("dump_.inbound.index"));
        assert_eq!(recon, entries);
    }

    #[test]
    fn emit_dom_out_all_empty_roundtrip() {
        let entries: Vec<Vec<i32>> = vec![vec![], vec![], vec![]];
        let tmp = std::env::temp_dir().join("mat_emit_domout_empty");
        let _ = std::fs::remove_dir_all(&tmp);
        let e = MatEmitter::new(&tmp, "dump_", None).unwrap();
        e.emit_dom_out(&entries).unwrap();
        let recon = read_unsorted_1n(&tmp.join("dump_.domOut.index"));
        assert_eq!(recon, entries);
    }
}
