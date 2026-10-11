//! The pass-1-derived tables `Pass2::build` needs but that require no heap scan.
//!
//! `Pass2::build`'s 2a/2b scans cost ~43 minutes on a 44 GB dump, and they exist
//! to produce the forward CSR. The MAT index emitters, however, need a second
//! set of per-object facts that come out of pass1's object directory alone: the
//! MAT shallow sizes, the class-histogram tables, the GC-root set, the thread
//! stacks and the synthetic thread-local edges.
//!
//! Those derivations live here so that `Pass2::build` and the `mat caches`
//! from-cache path (`src/main.rs`) share exactly one implementation — a second
//! copy would drift and silently break MAT parity. The code below is a pure
//! move out of `Pass2::build`: same statements, same order, same results.

use std::collections::HashMap;

use super::*;
use crate::pass1::Pass1;
use crate::types::HprofType;

/// Everything derived from pass1 *before* the heap scan: the reference width,
/// the per-object MAT shallow sizes, and the class-histogram tables.
pub struct ClassTables {
    /// Object-reference width in bytes (4 with compressed OOPs, else `id_size`).
    pub ref_size: usize,
    /// Per-object MAT shallow size, 1:1 with object indices 0..n.
    pub shallow: Vec<u32>,
    /// Per-object class-histogram row index, 1:1 with objects.
    pub class_idx: Vec<u32>,
    /// Histogram row names, indexed by the values in `class_idx`.
    pub class_names: Vec<String>,
    /// Class-loader object address per histogram row.
    pub class_loader_id: Vec<u64>,
    /// Class-object address -> histogram row, for instances and object arrays.
    pub class_addr_to_hist: HashMap<u64, u32>,
    /// Histogram row of `java/lang/Class` (the JLC_KEY row).
    pub jlc_idx: u32,
    /// Class-object index -> histogram row of the class it represents.
    pub class_obj_class_idx: HashMap<u32, u32>,
}

/// Everything derived from pass1 that needs the class tables but still no heap
/// scan: GC roots, thread stacks, and the synthetic thread-local edges.
pub struct GraphExtras {
    /// Class-loader object address -> class NAME of that loader object.
    pub loader_labels: HashMap<u64, String>,
    /// Object indices that are GC roots, sorted ascending.
    pub gc_root_indices: Vec<u32>,
    /// Per-root HPROF sub-tag, aligned 1:1 with `gc_root_indices`.
    pub gc_root_types: Vec<u8>,
    /// Number of GC roots added synthetically (system class roots, etc.).
    pub synthetic_root_count: usize,
    /// MAT-formula shallow size of `java/lang/ClassLoader`, when present.
    pub system_classloader_shallow: Option<u32>,
    /// Resolved thread stack traces (one per STACK_TRACE with frames).
    pub thread_stacks: Vec<ThreadStack>,
    /// Per-thread count of thread-local roots that resolved to a live object.
    pub thread_local_counts: HashMap<u32, u64>,
    /// Bounded per-thread sample of thread-local root object indices.
    pub thread_local_samples: HashMap<u32, Vec<u32>>,
    /// Per-thread (frame_number, local object index) pairs.
    pub thread_local_frame_samples: HashMap<u32, Vec<(u32, u32)>>,
    /// Thread objects that are one of their own locals (`thread → itself`).
    /// Deliberately kept OUT of `synthetic_edges`: the forward CSR — and so the
    /// dominator tree — must stay byte-for-byte what it was before MAT emitted
    /// these out of band.
    pub synthetic_self_edges: Vec<u32>,
    /// Resolved thread-local edges (source index, target index), deduped.
    pub synthetic_edges: Vec<(u32, u32)>,
}

/// The class-histogram key for a primitive-array row.
const PRIM_KEY_BASE: u64 = 0xFFFF_0000_0000_0000;
/// The class-histogram key for the single `java/lang/Class` row.
const JLC_KEY: u64 = 0xFFFF_FFFF_FFFF_FFFF;

impl Pass2 {
    /// Derive the reference width, the per-object MAT shallow sizes and the
    /// class-histogram tables from pass1's object directory.
    ///
    /// Must run *before* the 2a scan: the scan consumes `class_idx` (compressed)
    /// and `class_addr_to_hist`.
    pub fn class_tables(p1: &Pass1) -> ClassTables {
        let n = p1.id_map.len();
        let id_size = p1.id_size;
        let ptr_size = id_size as usize;

        // ── Phase 0: detect ref_size ─────────────────────────────────────
        // Reuse the object-array (addr, count) data already collected in pass1
        // instead of re-scanning the whole file. Array addresses are the id_map
        // entries whose kind == 1 (object array).
        let ref_size = if id_size == 8 {
            let mut array_addr_counts: Vec<(u64, u64)> = Vec::new();
            for i in 0..n {
                if p1.kind[i] == 1 {
                    array_addr_counts.push((p1.id_map.addr_at(i), p1.elem_count[i] as u64));
                }
            }
            detect_ref_size(id_size, &array_addr_counts)
        } else {
            id_size
        } as usize;

        // ── Phase 0b: compute shallow sizes with MAT formula ─────────────
        // Uses per-object kind (0=instance,1=obj_array,2=prim_array,3=class_obj)
        // and raw element counts collected in pass1 — authoritative, no heuristics.
        let mut size_cache: HashMap<u64, usize> = HashMap::new();

        // Set of class-object addresses (used later for edge/class-obj resolution).
        let class_addrs: std::collections::HashSet<u64> = p1.class_map.keys().cloned().collect();

        let mut shallow: Vec<u32> = Vec::with_capacity(n);
        for i in 0..n {
            let cid = p1.class_ids[i];
            let sz = match p1.kind[i] {
                3 => {
                    // Class object: shallow from static fields only, attributed to java.lang.Class.
                    let addr = p1.class_addr_table.get(cid as usize).copied().unwrap_or(0);
                    match p1.class_map.get(&addr) {
                        Some(ci) => class_obj_shallow(ci, ptr_size, ref_size),
                        None => align_up(ptr_size + ref_size, 8) as u32,
                    }
                }
                1 => {
                    // Object array: cid is the array class index (elem count from pass1).
                    obj_array_shallow(p1.elem_count[i] as u64, ptr_size, ref_size)
                }
                2 => {
                    // Primitive array: cid is the raw element type code.
                    let elem_size = HprofType::from_code(cid as u8)
                        .map(|t| t.byte_size())
                        .unwrap_or(1);
                    prim_array_shallow(p1.elem_count[i] as u64, elem_size, ptr_size, ref_size)
                }
                _ => {
                    // Instance: MAT calculateSizeRecursive over the super chain.
                    let addr = p1.class_addr_table.get(cid as usize).copied().unwrap_or(0);
                    if p1.class_map.contains_key(&addr) {
                        instance_shallow_size(
                            addr,
                            &p1.class_map,
                            ptr_size,
                            ref_size,
                            &mut size_cache,
                        )
                    } else {
                        align_up(ptr_size + ref_size, 8) as u32
                    }
                }
            };
            shallow.push(sz);
        }

        // ── Phase 0c: Build class names ──────────────────────────────────
        // MAT keys the class histogram by CLASS-OBJECT identity, not by name: a
        // class loaded by two different loaders yields two histogram rows even
        // though the names are identical. We therefore intern by a u64 key:
        //   - instances / object arrays: the class-object address (loader-distinct)
        //   - primitive arrays: PRIM_KEY_BASE | type_code (boot-loaded, single row)
        //   - class objects (java.lang.Class): the JLC_KEY sentinel (single row)
        let mut class_key_to_idx: HashMap<u64, u32> = HashMap::new();
        let mut class_names: Vec<String> = Vec::new();
        let mut class_loader_id: Vec<u64> = Vec::new();

        let mut get_or_insert_class =
            |key: u64, name: &dyn Fn() -> String, loader: &dyn Fn() -> u64| -> u32 {
                if let Some(&idx) = class_key_to_idx.get(&key) {
                    return idx;
                }
                let idx = class_names.len() as u32;
                class_key_to_idx.insert(key, idx);
                class_names.push(name());
                class_loader_id.push(loader());
                idx
            };

        // Build class_idx array
        let mut class_idx: Vec<u32> = vec![0u32; n];
        // class_addr_to_hist: class object address → histogram idx, for instances
        // (and object arrays). Used to build field_plans_dense after the closure drops.
        let mut class_addr_to_hist: HashMap<u64, u32> = HashMap::new();

        // First pass: populate class_idx for all objects (kind-driven, no heuristics)
        for i in 0..n {
            let cid = p1.class_ids[i];

            match p1.kind[i] {
                3 => {
                    // Class object → single java/lang/Class row (MAT parity). Boot-loaded.
                    class_idx[i] =
                        get_or_insert_class(JLC_KEY, &|| "java/lang/Class".to_string(), &|| 0);
                }
                2 => {
                    // Primitive array: cid is the raw element type code. Boot-loaded.
                    let tc = cid as u8;
                    class_idx[i] = get_or_insert_class(
                        PRIM_KEY_BASE | tc as u64,
                        &|| prim_array_class_name(tc).to_string(),
                        &|| 0,
                    );
                }
                1 => {
                    // Object array: cid indexes the array-class address (loader-distinct).
                    let addr = p1.class_addr_table.get(cid as usize).copied().unwrap_or(0);
                    class_idx[i] = get_or_insert_class(
                        addr,
                        &|| {
                            p1.class_map
                                .get(&addr)
                                .and_then(|ci| p1.strings.get(&ci.name_id).cloned())
                                .unwrap_or_else(|| "[Ljava/lang/Object;".to_string())
                        },
                        &|| p1.class_map.get(&addr).map(|ci| ci.loader_id).unwrap_or(0),
                    );
                    class_addr_to_hist.entry(addr).or_insert(class_idx[i]);
                }
                _ => {
                    // Instance: cid indexes the class-object address (loader-distinct).
                    let addr = p1.class_addr_table.get(cid as usize).copied().unwrap_or(0);
                    class_idx[i] = get_or_insert_class(
                        addr,
                        &|| {
                            p1.class_map
                                .get(&addr)
                                .and_then(|ci| p1.strings.get(&ci.name_id).cloned())
                                .unwrap_or_else(|| format!("unknown@{addr:#x}"))
                        },
                        &|| p1.class_map.get(&addr).map(|ci| ci.loader_id).unwrap_or(0),
                    );
                    class_addr_to_hist.entry(addr).or_insert(class_idx[i]);
                }
            }
        }

        // Class objects already map to the java/lang/Class row (JLC_KEY) from Phase 0c.
        let jlc_idx = get_or_insert_class(JLC_KEY, &|| "java/lang/Class".to_string(), &|| 0);

        // ── Build class_obj_class_idx ─────────────────────────────────────
        // For each class object, record the histogram row of the class it
        // represents. Under identity keying, that row is keyed by the class
        // object's own address (the same key instances of that class use).
        let mut class_obj_class_idx: HashMap<u32, u32> = HashMap::new();
        for i in 0..n {
            let addr = p1.id_map.addr_at(i);
            if class_addrs.contains(&addr) {
                let ci = p1.class_map.get(&addr);
                // Determine the histogram row this class-object represents.
                // Must use the SAME key that instances of the class use:
                //   - Primitive array class-objects ([I, [B, ...): PRIM_KEY_BASE|tc
                //   - java/lang/Class class-object: JLC_KEY
                //   - All other class-objects: addr-based key (same as instances)
                let name = ci.and_then(|c| p1.strings.get(&c.name_id));
                let idx = if let Some(n) = name {
                    if let Some(tc) = prim_array_type_code(n) {
                        // Class-object for a primitive array: register under PRIM_KEY
                        get_or_insert_class(
                            PRIM_KEY_BASE | tc as u64,
                            &|| prim_array_class_name(tc).to_string(),
                            &|| 0,
                        )
                    } else if n == "java/lang/Class" {
                        // Class-object for java.lang.Class: register under JLC_KEY
                        get_or_insert_class(JLC_KEY, &|| "java/lang/Class".to_string(), &|| 0)
                    } else {
                        get_or_insert_class(addr, &|| n.to_string(), &|| {
                            ci.map(|c| c.loader_id).unwrap_or(0)
                        })
                    }
                } else {
                    get_or_insert_class(addr, &|| format!("unknown@{addr:#x}"), &|| {
                        ci.map(|c| c.loader_id).unwrap_or(0)
                    })
                };
                class_obj_class_idx.insert(i as u32, idx);
            }
        }

        // Ensure no zero shallow sizes for instances/arrays (fall back to minimum).
        // Class objects (kind==3) are exempt: MAT reports 0 shallow for a class
        // whose static-field bytes sum to 0 (e.g. array classes like `[I`), so we
        // must not bump those to the object minimum.
        let min_obj = align_up(ptr_size + ref_size, 8) as u32;
        for (i, s) in shallow.iter_mut().enumerate() {
            if *s == 0 && p1.kind[i] != 3 {
                *s = min_obj;
            }
        }

        ClassTables {
            ref_size,
            shallow,
            class_idx,
            class_names,
            class_loader_id,
            class_addr_to_hist,
            jlc_idx,
            class_obj_class_idx,
        }
    }

    /// Derive the GC-root set, thread stacks, loader labels and the synthetic
    /// thread-local edges from pass1.
    ///
    /// Needs pass1's `kind` / `class_ids` / `class_map` / `strings` /
    /// `class_addr_table` / `stack_*` / `thread_local_pairs`, so it must run
    /// before `Pass2::build` frees those.
    pub fn graph_extras(
        p1: &Pass1,
        class_loader_id: &[u64],
        ref_size: usize,
        opts: &crate::AnalyzeOptions,
    ) -> GraphExtras {
        let n = p1.id_map.len();
        let ptr_size = p1.id_size as usize;

        // ── Phase 2: Build GC root indices ───────────────────────────────
        let mut gc_root_set: std::collections::HashSet<u32> = std::collections::HashSet::new();
        // Per-index representative root type (minimum sub-tag when an index has
        // several root records), carried into Graph for B1 grouping + why-alive.
        let mut root_type_of: std::collections::HashMap<u32, u8> = std::collections::HashMap::new();
        let note_type = |m: &mut std::collections::HashMap<u32, u8>, idx: u32, ty: u8| {
            m.entry(idx).and_modify(|e| *e = (*e).min(ty)).or_insert(ty);
        };
        for (&addr, &ty) in p1.gc_root_addrs.iter().zip(p1.gc_root_types.iter()) {
            if let Some(idx) = p1.id_map.index_of(addr) {
                gc_root_set.insert(idx as u32);
                note_type(&mut root_type_of, idx as u32, ty);
            }
        }
        // Add implicit roots: non-array boot-loader classes (loader_id==0) if no sticky roots
        if !p1.has_sticky_class_roots {
            for (&caddr, ci) in &p1.class_map {
                if ci.loader_id == 0 {
                    // Check it's not an array class (name doesn't start with '[')
                    let is_array = p1
                        .strings
                        .get(&ci.name_id)
                        .map(|n| n.starts_with('['))
                        .unwrap_or(false);
                    if !is_array {
                        if let Some(idx) = p1.id_map.index_of(caddr) {
                            gc_root_set.insert(idx as u32);
                            note_type(
                                &mut root_type_of,
                                idx as u32,
                                crate::types::heap::ROOT_SYSTEM_CLASS,
                            );
                        }
                    }
                }
            }
        }
        // ── addSystemClassRootsIfMissing: boot-loader non-array classes not yet roots ─
        let mut synthetic_root_count = 0usize;
        // MAT materializes a synthetic <system class loader> object at 0x0 of
        // class java/lang/ClassLoader (no HPROF record). Capture that class's
        // instance shallow size so the report layer can inject the object.
        let mut system_classloader_shallow: Option<u32> = None;
        let mut size_cache: HashMap<u64, usize> = HashMap::new();
        for (&caddr, ci) in &p1.class_map {
            if ci.loader_id != 0 {
                continue;
            }
            let name = p1.strings.get(&ci.name_id);
            if name.map(|n| n == "java/lang/ClassLoader").unwrap_or(false) {
                system_classloader_shallow = Some(instance_shallow_size(
                    caddr,
                    &p1.class_map,
                    ptr_size,
                    ref_size,
                    &mut size_cache,
                ));
            }
            let is_array = name.map(|n| n.starts_with('[')).unwrap_or(false);
            let is_prim_array = name
                .map(|n| is_primitive_array_class_name(n))
                .unwrap_or(false);
            if !should_add_system_class_root(is_array, is_prim_array, p1.has_sticky_class_roots) {
                continue;
            }
            if let Some(idx) = p1.id_map.index_of(caddr) {
                if !gc_root_set.contains(&(idx as u32)) {
                    gc_root_set.insert(idx as u32);
                    note_type(
                        &mut root_type_of,
                        idx as u32,
                        crate::types::heap::ROOT_SYSTEM_CLASS,
                    );
                    synthetic_root_count += 1;
                }
            }
        }

        // Resolve STACK_TRACE/STACK_FRAME into pre-rendered thread stacks while
        // pass1's string/class tables are still alive (they are freed just
        // below). Only traces that carry frames are kept. Small — one entry per
        // thread trace, off the per-object RSS budget.
        let thread_stacks = build_thread_stacks(p1);

        // Resolve each distinct non-boot class-loader OBJECT address to the
        // class NAME of that loader object (e.g.
        // "jdk/internal/loader/ClassLoaders$AppClassLoader"), so the report
        // layer can label loaders instead of showing a raw address.
        let mut loader_labels: std::collections::HashMap<u64, String> =
            std::collections::HashMap::new();
        for &loader_addr in class_loader_id {
            if loader_addr == 0 {
                continue; // boot loader handled in report layer
            }
            if loader_labels.contains_key(&loader_addr) {
                continue;
            }
            // Resolve: loader_addr -> object index -> its class-obj addr -> name.
            if let Some(idx) = p1.id_map.index_of(loader_addr) {
                // Only plain instances (kind 0) are real loader objects.
                if p1.kind[idx] == 0 {
                    let cid = p1.class_ids[idx];
                    let class_addr = p1.class_addr_table.get(cid as usize).copied().unwrap_or(0);
                    if let Some(name) = p1
                        .class_map
                        .get(&class_addr)
                        .and_then(|ci| p1.strings.get(&ci.name_id))
                    {
                        loader_labels.insert(loader_addr, name.clone());
                    }
                }
            }
        }

        // ── Resolve thread→local synthetic edges ─────────────────────────
        let mut synthetic_edges: Vec<(u32, u32)> = Vec::new();
        // Self-referencing thread-local pairs: a thread object that appears as
        // one of its own stack-frame locals. MAT materialises these as a
        // `thread → itself` edge. Our graph deliberately omits self-loops (the
        // retained/dominator computation is verified against MAT and must not
        // gain edges), so they are collected here as *dense source ids only* and
        // re-injected by the MAT index emitters (see `main.rs`). Keeping them out
        // of `synthetic_edges` means the forward CSR — and therefore the
        // dominator tree — is byte-for-byte what it was before.
        let mut synthetic_self_edges: Vec<u32> = Vec::new();
        // Per-thread count of local roots that resolve to a live object. Sized
        // by #threads only (bounded), so it stays off the per-object RSS budget.
        let mut thread_local_counts: std::collections::HashMap<u32, u64> =
            std::collections::HashMap::new();
        // Bounded per-thread sample of local object indices. Only populated when
        // the opt-in `--thread-locals` flag is set; empty otherwise (zero cost on
        // the default path).
        let mut thread_local_samples: std::collections::HashMap<u32, Vec<u32>> =
            std::collections::HashMap::new();
        // Gated frame→local map: per-thread (frame_number, local_idx) pairs, used
        // to build MAT's per-frame significant-locals interleave. Only populated
        // when `--thread-locals` is set; `u32::MAX` frame_number = no frame (JNI
        // local / native stack / thread block). Bounded per thread by the same
        // per-thread cap. Zero cost on the default path.
        let mut thread_local_frame_samples: std::collections::HashMap<u32, Vec<(u32, u32)>> =
            std::collections::HashMap::new();
        for tlr in &p1.thread_local_pairs {
            let (thread_serial, frame_number, local_addr) =
                (tlr.thread_serial, tlr.frame_number, tlr.local_addr);
            let thread_obj_addr = match p1.thread_serial_to_obj_id.get(&thread_serial) {
                Some(&a) => a,
                None => continue,
            };
            let thread_idx = match p1.id_map.index_of(thread_obj_addr) {
                Some(i) => i as u32,
                None => continue,
            };
            let local_idx = match p1.id_map.index_of(local_addr) {
                Some(i) => i as u32,
                None => continue,
            };
            if thread_idx == local_idx {
                // Thread is one of its own locals: MAT records a self-edge.
                synthetic_self_edges.push(thread_idx);
            } else {
                synthetic_edges.push((thread_idx, local_idx));
                *thread_local_counts.entry(thread_serial).or_insert(0) += 1;
                let sample = thread_local_samples.entry(thread_serial).or_default();
                if sample.len() < opts.thread_locals_per_thread {
                    sample.push(local_idx);
                }
                if opts.thread_locals_per_thread > 0 {
                    let fs = thread_local_frame_samples.entry(thread_serial).or_default();
                    if fs.len() < opts.thread_locals_per_thread {
                        fs.push((frame_number, local_idx));
                    }
                }
            }
        }
        // Dedup synthetic edges (same thread may reference same local multiple times)
        synthetic_edges.sort_unstable();
        synthetic_edges.dedup();
        synthetic_self_edges.sort_unstable();
        synthetic_self_edges.dedup();

        let mut gc_root_indices: Vec<u32> = gc_root_set.into_iter().collect();
        gc_root_indices.sort_unstable();
        // Per-root type aligned 1:1 with the sorted indices. Every index in the
        // set came from a note_type call, so the lookup always hits; fall back
        // to ROOT_UNKNOWN defensively.
        let gc_root_types: Vec<u8> = gc_root_indices
            .iter()
            .map(|idx| {
                root_type_of
                    .get(idx)
                    .copied()
                    .unwrap_or(crate::types::heap::ROOT_UNKNOWN)
            })
            .collect();
        let _ = n;

        GraphExtras {
            loader_labels,
            gc_root_indices,
            gc_root_types,
            synthetic_root_count,
            system_classloader_shallow,
            thread_stacks,
            thread_local_counts,
            thread_local_samples,
            thread_local_frame_samples,
            synthetic_self_edges,
            synthetic_edges,
        }
    }
}
