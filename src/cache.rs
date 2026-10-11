//! Disk cache for analysis results — avoids re-running the 5–15 min pipeline.
//!
//! # Layout
//!
//! `<dump_path>.hprof-cache/<hash>/`
//! - `report.json.zst`   — full Report JSON, zstd-3
//! - `pass1.bin.zst`     — Pass1Snapshot (bincode), zstd-3
//! - `arrays.bin`        — 6 dense arrays in indexed format (seekable)
//! - `graph.bin`         — forward/inbound edges (delta-encoded + zstd-3), Graph mode only
//!
//! `hash` = hex(first-64-bytes-of-dump ++ file-size-le8 ++ mtime-ns-le8).
//! Cache busts automatically on any change to the dump file.
//!
//! # File format
//!
//! Both `arrays.bin` and `graph.bin` share a seekable indexed format:
//! ```text
//! [4B magic: b"HPCA"] [2B version: u16 LE = 1] [1B n_arrays]
//! [index: n × { name[16B], offset: u64 LE, len: u64 LE }]
//! [data: concatenated independent zstd frames, one per array]
//! ```
//!
//! One entry — `graph.bin`'s `fwd_tgt`, the forward edge-target array — is
//! itself a *chunked* container inside its frame, so it can be read a block at
//! a time instead of whole. See [`ChunkedTgt`] and
//! [`IndexedWriter::add_chunked_delta_u32`].

use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use crate::{chunkvec::ChunkU32, pass1::Pass1Snapshot, report::Report};

// ── File format constants ─────────────────────────────────────────────────────

const MAGIC: &[u8; 4] = b"HPCA";
const VERSION: u16 = 1;
const ENTRY_SIZE: usize = 16 + 8 + 8; // name[16] + offset:u64 + len:u64

// ── Chunked edge-target container ─────────────────────────────────────────────

/// Magic of the chunked `fwd_tgt` container, written inside the `fwd_tgt`
/// entry's frame. Its first four bytes being `HTGT` instead of a zstd frame
/// magic (`28 B5 2F FD`) is what lets a reader tell the new format from the old
/// single-frame one without a version bump.
const TGT_MAGIC: &[u8; 4] = b"HTGT";

/// Values per chunk in the `fwd_tgt` container — 1,000,000 u32 = 4 MB raw.
///
/// Measured on the 44 GB dump's 2.33-billion-edge array: 2326 chunks, +0.45%
/// on-disk versus the single frame, and 2.9–9.2 ms (mean 6.7 ms) to decompress
/// one chunk. Smaller chunks shrink the random-access read but multiply the
/// per-chunk zstd frame overhead; larger ones inflate the read. This is the
/// value the C probe (`.tmp-chunkprobe.c`) measured.
pub const TGT_CHUNK_VALUES: usize = 1_000_000;

/// Header of the chunked container, in bytes: magic + total:u64 + n_chunks:u64.
const TGT_HEADER_BYTES: usize = 4 + 8 + 8;

/// One chunk's table row: base:u64 + comp_len:u64.
const TGT_TABLE_ENTRY: usize = 8 + 8;

// ── CacheMode ────────────────────────────────────────────────────────────────

/// Which layers to write/check in the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// report.json.zst + pass1.bin.zst + arrays.bin (default)
    Full,
    /// Full + graph.bin (forward/inbound CSR; 210–680 MB after delta+zstd-3)
    Graph,
}

// ── Raw data handed to CacheDir for writing ──────────────────────────────────

/// Raw arrays from pass2, slices only (no allocation).
pub struct ArraysForCache<'a> {
    pub shallow: &'a [u32],
    pub class_idx: &'a [u32],
    pub idom: &'a [u32],
    pub retained: &'a [u64],
    pub dc_off: &'a [u32],
    pub dc_tgt: &'a [u32],
    pub n_objects: usize,
}

/// The forward half of the graph cache (opt-in with --with-graph).
///
/// `graph.bin` is assembled in two phases because its halves exist at different
/// points in the pipeline: the forward CSR must be streamed out *before*
/// `build_from_fwd` consumes it (that is what lets it borrow the chunked store
/// instead of flattening it), while the inbound CSR is only produced by that
/// call. See `CacheDir::graph_writer`.
pub struct GraphForCache<'a> {
    pub fwd_off: &'a [u32],
    /// Forward edge targets. Held as the chunked store rather than a flat
    /// `Vec<u32>`: on the 44 GB dump this array has 2.3 billion entries, so
    /// flattening it costs ~9.3 GB — and flattening it here (while the chunked
    /// original is still live) was the bulk of the ~50 GiB `--with-graph` peak.
    /// The writer streams it straight into the compressor instead.
    pub fwd_tgt: &'a ChunkU32,
    /// Only when --ref-paths was used.
    pub fwd_field_idx: Option<&'a [u16]>,
}

// ── CachedSession ─────────────────────────────────────────────────────────────

/// Everything loaded from a valid cache.
pub struct CachedSession {
    pub dump_path: PathBuf,
    pub report: Report,
    pub pass1: Pass1Snapshot,
    pub cache: CacheDir,
    pub mode: CacheMode,
    /// Dense pass2 class name table: index = class_idx value → class name string.
    pub class_names: Vec<String>,
}

impl CachedSession {
    /// Dense object index (0-based) for an object address, or `None` when the
    /// address is not a heap object (or is null). Searches the cached id-map
    /// pages in place — no `IdMap` rebuild and no multi-GB page clone.
    pub fn index_of_addr(&self, addr: u64) -> Option<usize> {
        crate::id_map::IdMap::index_of_in_pages(&self.pass1.id_map_pages, addr)
    }
}

// ── CacheDir ──────────────────────────────────────────────────────────────────

pub struct CacheDir {
    pub path: PathBuf,
}

impl CacheDir {
    /// Compute (or create) the cache directory for the given dump file.
    pub fn for_dump(dump: &Path) -> io::Result<Self> {
        let hash = dump_hash(dump)?;
        let mut dir = dump.to_path_buf();
        // Append ".hprof-cache/<hash>" alongside the dump.
        let name = dir
            .file_name()
            .map(|n| format!("{}.hprof-cache", n.to_string_lossy()))
            .unwrap_or_else(|| "dump.hprof-cache".to_string());
        dir.pop();
        dir.push(name);
        dir.push(&hash);
        fs::create_dir_all(&dir)?;
        Ok(Self { path: dir })
    }

    /// True if the cache is valid for `mode` (checks magic of required files).
    pub fn is_valid(&self, mode: CacheMode) -> bool {
        let arrays_ok = check_magic(&self.path.join("arrays.bin"));
        let pass1_ok = self.path.join("pass1.bin.zst").exists();
        let report_ok = self.path.join("report.json.zst").exists();
        let base_ok = report_ok && pass1_ok && arrays_ok;
        if mode == CacheMode::Graph {
            base_ok && check_magic(&self.path.join("graph.bin"))
        } else {
            base_ok
        }
    }

    // ── Report layer ──────────────────────────────────────────────────────────

    pub fn write_report(&self, r: &Report) -> io::Result<()> {
        let json = serde_json::to_vec(r).map_err(io::Error::other)?;
        write_zstd(&self.path.join("report.json.zst"), &json)
    }

    pub fn read_report(&self) -> io::Result<Option<Report>> {
        let path = self.path.join("report.json.zst");
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_zstd(&path)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(io::Error::other)
    }

    /// Write the dense pass2 class name table (index = class_idx value → name).
    pub fn write_class_names(&self, names: &[String]) -> io::Result<()> {
        let json = serde_json::to_vec(names).map_err(io::Error::other)?;
        write_zstd(&self.path.join("class_names.json.zst"), &json)
    }

    /// Read the class name table written by `write_class_names`.
    pub fn read_class_names(&self) -> io::Result<Option<Vec<String>>> {
        let path = self.path.join("class_names.json.zst");
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_zstd(&path)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(io::Error::other)
    }

    // ── Pass1 layer ───────────────────────────────────────────────────────────

    pub fn write_pass1(&self, p: &Pass1Snapshot) -> io::Result<()> {
        let bin = bincode::serde::encode_to_vec(p, bincode::config::standard())
            .map_err(io::Error::other)?;
        write_zstd(&self.path.join("pass1.bin.zst"), &bin)
    }

    pub fn read_pass1(&self) -> io::Result<Option<Pass1Snapshot>> {
        let path = self.path.join("pass1.bin.zst");
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_zstd(&path)?;
        let (snap, _) = bincode::serde::decode_from_slice::<Pass1Snapshot, _>(
            &bytes,
            bincode::config::standard(),
        )
        .map_err(io::Error::other)?;
        Ok(Some(snap))
    }

    // ── Array layer ───────────────────────────────────────────────────────────

    pub fn write_arrays(&self, a: &ArraysForCache) -> io::Result<()> {
        let names = [
            "shallow",
            "class_idx",
            "idom",
            "retained",
            "dc_off",
            "dc_tgt",
        ];
        let frames: Vec<Vec<u8>> = vec![
            zstd_compress_u32(a.shallow)?,
            zstd_compress_u32(a.class_idx)?,
            zstd_compress_u32(a.idom)?,
            zstd_compress_u64(a.retained)?,
            zstd_compress_u32(a.dc_off)?,
            zstd_compress_u32(a.dc_tgt)?,
        ];
        write_indexed_file(&self.path.join("arrays.bin"), &names, &frames)
    }

    // ── Graph layer ───────────────────────────────────────────────────────────

    /// Start a `graph.bin` write. See [`CacheDir::add_forward_to_graph`] and
    /// [`CacheDir::add_inbound_to_graph`] for what to add, and in which order.
    pub fn graph_writer(&self, has_fwd_field_idx: bool) -> io::Result<IndexedWriter> {
        // fwd_off + fwd_tgt (+ fwd_field_idx) + inb_block_off + inb_data
        let n_arrays = 2 + usize::from(has_fwd_field_idx) + 2;
        IndexedWriter::create(&self.path.join("graph.bin"), n_arrays)
    }

    /// Add the forward half: `fwd_off`, `fwd_tgt` (+ `fwd_field_idx`).
    ///
    /// Must run *before* `build_from_fwd` consumes the CSR, which is what lets
    /// `fwd_tgt` stream out of the chunked store without being flattened.
    ///
    /// `fwd_tgt` goes out in the chunked container
    /// ([`IndexedWriter::add_chunked_delta_u32`]) rather than as one delta frame
    /// so a warm session can read a row's edges without decoding the whole
    /// 2.3-billion-entry array — see [`ChunkedTgt`].
    pub fn add_forward_to_graph(w: &mut IndexedWriter, g: &GraphForCache) -> io::Result<()> {
        w.add_u32("fwd_off", g.fwd_off.iter().copied())?;
        // `fwd_off` is the CSR offset table, so its last entry is the edge count.
        let total_edges = g.fwd_off.last().copied().unwrap_or(0) as usize;
        w.add_chunked_delta_u32(
            "fwd_tgt",
            total_edges,
            g.fwd_tgt
                .iter_live_chunks()
                .flatten()
                .copied()
                .take(total_edges),
        )?;
        if let Some(fi) = g.fwd_field_idx {
            w.add_delta_u16("fwd_field_idx", fi.iter().copied())?;
        }
        Ok(())
    }

    /// Add the inbound half: `inb_block_off` + `inb_data`, straight from
    /// `InboundBuilder::build_from_fwd`'s return value.
    ///
    /// These used to be written as empty arrays ("inbound CSR omitted for now"),
    /// which is why the one reader that wanted an inbound CSR
    /// (`read_inbound_csr`) always came back empty. They are stored in the
    /// engine's own block format rather than as a flat CSR: that is what
    /// `compute_dominators` and the query engine's edge hook consume, so a
    /// cache-backed session can use them without a second conversion.
    pub fn add_inbound_to_graph(
        w: &mut IndexedWriter,
        inb_block_off: &[u64],
        inb_data: &[u8],
    ) -> io::Result<()> {
        w.add_u64("inb_block_off", inb_block_off.iter().copied())?;
        w.add_bytes("inb_data", inb_data)
    }

    /// Read the inbound CSR written by [`CacheDir::add_inbound_to_graph`].
    ///
    /// Returns `(inb_block_off, inb_data)` or `None` when the cache predates
    /// the inbound half (or has no graph at all).
    pub fn read_inbound_blocks(&self) -> io::Result<Option<(Vec<u64>, Vec<u8>)>> {
        let path = self.path.join("graph.bin");
        let off = read_u64_array(&path, "inb_block_off")?;
        let data = read_raw_array(&path, "inb_data")?;
        Ok(match (off, data) {
            (Some(o), Some(d)) if !o.is_empty() => Some((o, d)),
            _ => None,
        })
    }

    // ── Object-offset layer ───────────────────────────────────────────────────

    /// Write the per-object HPROF record offsets (`Pass1::hprof_offsets`, in
    /// dense-object-index order) to `offsets.bin`.
    ///
    /// These are what let `heap inspect` read one object's field values with a
    /// single seek into the dump instead of a full rescan — the rescan is what
    /// makes `toString(s)` cost ~50 minutes and stall the whole server.
    ///
    /// Stored as `i64` deltas (the offsets are close to monotonic in dense-id
    /// order) streamed straight through zstd, so the 8-bytes-per-object array
    /// never has to exist twice.
    ///
    /// This lives in its own file rather than as a 7th `arrays.bin` entry on
    /// purpose: `write_arrays` runs at the very end of the pipeline, and
    /// carrying the raw `Vec<u64>` (~4.9 GB on a 44 GB dump) that far would
    /// raise the whole run's peak RSS. Here it is written and dropped right
    /// after pass 1.
    pub fn write_hprof_offsets(&self, offs: &[u64]) -> io::Result<()> {
        let frame = encode_delta_u64_zstd(offs)?;
        write_indexed_file(&self.path.join("offsets.bin"), &["offsets"], &[frame])
    }

    /// Read `offsets.bin`. `None` when the cache predates offset capture (or the
    /// dump was analyzed before this feature existed) — callers must degrade
    /// gracefully rather than treat it as an empty array.
    pub fn read_hprof_offsets(&self) -> io::Result<Option<Vec<u64>>> {
        read_delta_u64_array(&self.path.join("offsets.bin"), "offsets")
    }

    /// True when `offsets.bin` is present. Used to distinguish "no offsets
    /// captured" from "offsets captured but empty" without decompressing.
    pub fn has_hprof_offsets(&self) -> bool {
        self.path.join("offsets.bin").exists()
    }

    /// Rebuild an OQL query session straight from this cache.
    ///
    /// The analysis pipeline hands the OQL engine an `OqlCacheHandover`
    /// assembled from `Pass1` plus the graph it just built (see
    /// `keep_oql_cache`). Every one of that handover's fields is either in
    /// `pass1.bin.zst` — `id_map` via `IdMapPages`, the rest verbatim — or
    /// derivable from it, and `arrays.bin` carries `shallow` / `class_idx`, so
    /// the same session can be reconstructed from disk. That is what lets a
    /// server come up warm in seconds instead of re-running a pipeline that
    /// costs ~50 minutes and ~20 GiB on a 44 GB dump.
    ///
    /// Scope matches the pipeline's handover exactly: `reachable_only: false`
    /// with `dfn: None`, i.e. bit-for-bit the cache the first query builds today.
    ///
    /// Lives here rather than in the library's free functions because both
    /// `main.rs` and `lib.rs` declare a module tree and compile this file into
    /// each; keeping the assembly in one file keeps the types on both sides
    /// identical. Returns `Ok(None)` when the cache is absent or undecodable.
    pub fn read_query_cache(
        &self,
        source: crate::source::HprofSource,
    ) -> io::Result<Option<crate::query::run::ReplCache>> {
        if !self.is_valid(CacheMode::Full) {
            return Ok(None);
        }
        // A cache can pass `is_valid` (magic bytes and file presence only) and
        // still fail to decode — bincode is not self-describing — so every read
        // here is best-effort: anything missing or undecodable means "no warm
        // start", never a hard error.
        let Some(snap) = self.read_pass1().ok().flatten() else {
            return Ok(None);
        };
        let (Some(shallow), Some(class_idx)) = (
            self.read_shallow().ok().flatten(),
            self.read_class_idx().ok().flatten(),
        ) else {
            return Ok(None);
        };
        if shallow.len() != class_idx.len() {
            return Ok(None);
        }
        let class_names = self.read_class_names().ok().flatten().unwrap_or_default();

        let handover = crate::query::run::OqlCacheHandover {
            class_map: snap.class_map,
            strings: snap.strings,
            id_map: crate::id_map::IdMap::from_pages(snap.id_map_pages),
            kind: snap.kind,
            class_addr_table: snap.class_addr_table,
            class_ids: snap.class_ids,
            id_size: snap.id_size,
        };
        let n = shallow.len();
        // Edges, so a warm session can answer `@inbounds` / `@outbounds` /
        // `path()` without re-reading the dump. Best-effort: a `heap load`
        // (CacheMode::Full) has no `graph.bin` at all, and a truncated or
        // foreign one must degrade to "no edges" rather than panic.
        //
        // Only TWO things are taken resident: `fwd_off` (the row pointers —
        // 2.26 GiB on the 44 GB dump) and, for an old-format `graph.bin`, the
        // whole `fwd_tgt`. A chunked `fwd_tgt` is NOT read here: the session
        // holds a [`ChunkedTgt`] that seeks to the chunks a query actually
        // needs. That is the difference between a server that needs 16.33 GiB
        // for its edges and one that needs 2.26 GiB — the former OOMs a 32 GB
        // box, the latter does not.
        //
        // The inbound block CSR is deliberately NOT loaded: nothing in the
        // query path consumes it (`compute_dominators` runs only in the
        // pipeline, on the live blocks), so carrying it cost 5.41 GiB of
        // resident memory for nothing. `mat caches` still reads it straight off
        // disk via `read_inbound_blocks`.
        let mut edges = crate::query::run::ReplCacheEdges::default();
        if let Some(fwd_off) = self.read_forward_offsets().ok().flatten() {
            // Validate before accepting: a truncated or mismatched pair would
            // make the consumer index out of bounds (`fwd_off[s + 1]`,
            // `fwd_tgt.get(..)`). This is a best-effort read, so a bad pair means
            // "no edges", never a panic.
            let total = fwd_off.last().copied().unwrap_or(0) as usize;
            if fwd_off.len() == n + 1 {
                let store = match ChunkedTgt::open(&self.path) {
                    // Chunked (current) format: hold the file, not the array.
                    Ok(Some(t)) if t.total() == total => {
                        Some(crate::query::run::FwdTgtStore::OnDisk(Box::new(t)))
                    }
                    // Old single-frame format: fall back to reading it whole.
                    // `read_forward_targets` handles both, so this is also the
                    // path a partially-chunked or reverted cache takes.
                    _ => match self.read_forward_targets(total) {
                        Ok(Some(tgt)) if tgt.len() == total => Some(
                            crate::query::run::FwdTgtStore::Resident(ChunkU32::from_vec(tgt)),
                        ),
                        _ => None,
                    },
                };
                if let Some(store) = store {
                    edges.fwd_tgt = store;
                    edges.fwd_off = fwd_off;
                }
            }
        }
        Ok(Some(handover.into_cache(
            source,
            n,
            shallow,
            class_idx,
            class_names,
            edges,
        )))
    }

    // ── Seek-based reads ──────────────────────────────────────────────────────

    pub fn read_shallow(&self) -> io::Result<Option<Vec<u32>>> {
        read_u32_array(&self.path.join("arrays.bin"), "shallow")
    }

    pub fn read_class_idx(&self) -> io::Result<Option<Vec<u32>>> {
        read_u32_array(&self.path.join("arrays.bin"), "class_idx")
    }

    pub fn read_idom(&self) -> io::Result<Option<Vec<u32>>> {
        read_u32_array(&self.path.join("arrays.bin"), "idom")
    }

    pub fn read_retained(&self) -> io::Result<Option<Vec<u64>>> {
        read_u64_array(&self.path.join("arrays.bin"), "retained")
    }

    /// Returns `(dc_off, dc_tgt)` or `None` if not cached.
    pub fn read_dominator_children(&self) -> io::Result<Option<(Vec<u32>, Vec<u32>)>> {
        let off = read_u32_array(&self.path.join("arrays.bin"), "dc_off")?;
        let tgt = read_u32_array(&self.path.join("arrays.bin"), "dc_tgt")?;
        Ok(match (off, tgt) {
            (Some(o), Some(t)) => Some((o, t)),
            _ => None,
        })
    }

    /// Read `fwd_off` (the forward CSR's offset table) on its own.
    pub fn read_forward_offsets(&self) -> io::Result<Option<Vec<u32>>> {
        read_u32_array(&self.path.join("graph.bin"), "fwd_off")
    }

    /// Returns `(fwd_off, fwd_tgt)` or `None` if the graph is not cached.
    ///
    /// Materialises the whole target array (9.3 GB of `u32` on the 44 GB dump),
    /// so it is only for callers that genuinely want all of it. A warm session
    /// uses [`CacheDir::read_forward_offsets`] plus [`ChunkedTgt`] instead and
    /// never holds the array. Works with both on-disk formats — see
    /// [`CacheDir::read_forward_targets`].
    pub fn read_forward_edges(&self) -> io::Result<Option<(Vec<u32>, Vec<u32>)>> {
        let Some(off) = self.read_forward_offsets()? else {
            return Ok(None);
        };
        let total = off.last().copied().unwrap_or(0) as usize;
        Ok(match self.read_forward_targets(total)? {
            Some(t) if t.len() == total => Some((off, t)),
            _ => None,
        })
    }

    /// Stream the whole `fwd_tgt` from `graph.bin` into a flat `Vec<u32>`.
    ///
    /// [`CacheDir::read_forward_edges`] materialised that array three times over
    /// — the compressed frame, the `Vec<i32>` deltas, then the `Vec<u32>`
    /// targets — which on the 44 GB dump (2.3 billion edges) is ~27 GB of
    /// transients for one array. This walks the zstd frame through a 64 KiB
    /// buffer and undeltas straight into the output, so the only large
    /// allocation is the result itself.
    ///
    /// Handles BOTH on-disk formats by sniffing the entry's first four bytes:
    /// the chunked container (`HTGT`) is decoded chunk by chunk, and an older
    /// single-frame cache takes the streaming path. Callers that want random
    /// access should use [`ChunkedTgt`] instead — this exists for the whole-array
    /// consumers (`mat caches`) and for the old-format fallback in
    /// [`CacheDir::read_query_cache`].
    ///
    /// Returns `Ok(None)` when `graph.bin` has no `fwd_tgt` or the payload does
    /// not hold exactly `total_edges` values (a stale or foreign cache).
    pub fn read_forward_targets(&self, total_edges: usize) -> io::Result<Option<Vec<u32>>> {
        let path = self.path.join("graph.bin");
        let Some((mut f, len)) = seek_to_entry(&path, "fwd_tgt")? else {
            return Ok(None);
        };
        let entry_off = f.stream_position()?;
        let mut head = [0u8; 4];
        if f.read_exact(&mut head).is_err() {
            return Ok(None);
        }
        if &head == TGT_MAGIC {
            // Chunked container: reuse the random-access reader and pull every
            // chunk. `ChunkedTgt::open` re-reads the header, which is 20 bytes.
            let Some(t) = ChunkedTgt::open(&self.path)? else {
                return Ok(None);
            };
            if t.total() != total_edges {
                return Ok(None);
            }
            let mut out = Vec::with_capacity(total_edges);
            t.copy_range(0, total_edges, &mut out)?;
            if out.len() != total_edges {
                return Ok(None);
            }
            return Ok(Some(out));
        }
        // Old format: one delta frame for the whole array. Rewind over the four
        // bytes we sniffed so the decoder sees the frame from its first byte.
        f.seek(SeekFrom::Start(entry_off))?;
        let mut dec = zstd::stream::read::Decoder::new(f.take(len as u64))?;
        let mut buf = vec![0u8; STAGE_BYTES];
        // The entry is an i32 delta stream (see `IndexedWriter::add_delta_u32`);
        // a 4-byte value can straddle a read boundary, so carry the partial one.
        let mut carry = [0u8; 4];
        let mut have = 0usize;
        let mut acc: i64 = 0;
        let mut out: Vec<u32> = Vec::with_capacity(total_edges);
        loop {
            let n = dec.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let mut i = 0usize;
            while i < n {
                let take = (4 - have).min(n - i);
                carry[have..have + take].copy_from_slice(&buf[i..i + take]);
                have += take;
                i += take;
                if have == 4 {
                    acc = acc.wrapping_add(i32::from_le_bytes(carry) as i64);
                    out.push(acc as u32);
                    have = 0;
                }
            }
        }
        if have != 0 || out.len() != total_edges {
            return Ok(None);
        }
        Ok(Some(out))
    }

    /// Returns `(inb_off, inb_tgt)` or `None` if graph not cached.
    pub fn read_inbound_csr(&self) -> io::Result<Option<(Vec<u32>, Vec<u32>)>> {
        let off = read_u32_array(&self.path.join("graph.bin"), "inb_off")?;
        let tgt = read_delta_u32_array(&self.path.join("graph.bin"), "inb_tgt")?;
        Ok(match (off, tgt) {
            (Some(o), Some(t)) => Some((o, t)),
            _ => None,
        })
    }

    // ── Cache management ──────────────────────────────────────────────────────

    /// Delete all files in the cache directory.
    pub fn clear(&self) -> io::Result<()> {
        if self.path.exists() {
            fs::remove_dir_all(&self.path)?;
            fs::create_dir_all(&self.path)?;
        }
        Ok(())
    }

    /// Total bytes used by all files in the cache directory.
    pub fn size_bytes(&self) -> u64 {
        dir_size(&self.path)
    }
}

// ── Indexed file format ───────────────────────────────────────────────────────

/// Write the HPCA indexed format: magic + version + index + zstd frames.
fn write_indexed_file(path: &Path, names: &[&str], frames: &[Vec<u8>]) -> io::Result<()> {
    assert_eq!(names.len(), frames.len());
    let n = names.len();
    let index_bytes = n * ENTRY_SIZE;
    let header_bytes = 4 + 2 + 1 + index_bytes; // magic + version + n_arrays + index
    let mut offset = header_bytes as u64;
    let mut entries: Vec<(u64, u64)> = Vec::with_capacity(n);
    for frame in frames {
        let len = frame.len() as u64;
        entries.push((offset, len));
        offset += len;
    }

    let mut f = File::create(path)?;
    f.write_all(MAGIC)?;
    f.write_all(&VERSION.to_le_bytes())?;
    f.write_all(&[n as u8])?;
    for (i, &name) in names.iter().enumerate() {
        let mut name_bytes = [0u8; 16];
        let nb = name.as_bytes();
        name_bytes[..nb.len().min(16)].copy_from_slice(&nb[..nb.len().min(16)]);
        f.write_all(&name_bytes)?;
        f.write_all(&entries[i].0.to_le_bytes())?;
        f.write_all(&entries[i].1.to_le_bytes())?;
    }
    for frame in frames {
        f.write_all(frame)?;
    }
    f.flush()
}

// ── Streaming indexed writer ─────────────────────────────────────────────────

/// Staging buffer for the streaming writers: bytes are handed to zstd in 64 KiB
/// blocks, so neither the uncompressed array nor the compressed frame is ever
/// fully resident.
const STAGE_BYTES: usize = 1 << 16;

/// Write an HPCA indexed file without materialising whole arrays.
///
/// `write_indexed_file` needs every compressed frame in memory up front, which
/// forces each array through a full-size temporary — and delta-encoding one
/// naively adds two more (the `Vec<i32>` deltas, then their LE bytes). For the
/// 44 GB dump's forward targets (2.3 billion edges) that is ~28 GB of
/// transients for one array, which is what pushed `heap load --with-graph` to
/// ~50 GiB.
///
/// This writer compresses each array straight into the file through a single
/// 64 KiB staging buffer and patches the index at `finish()`, so the resident
/// cost is constant regardless of array length. It also lets the caller add
/// arrays at different points in the pipeline — needed because the forward CSR
/// must be written before `build_from_fwd` consumes it, while the inbound CSR
/// only exists afterwards.
///
/// The file is assembled under `<path>.tmp` and renamed on `finish()`, so a run
/// that dies mid-write cannot leave a truncated file that `check_magic` would
/// accept as a valid cache.
pub struct IndexedWriter {
    tmp: PathBuf,
    final_path: PathBuf,
    f: File,
    entries: Vec<([u8; 16], u64, u64)>,
    n_arrays: usize,
    offset: u64,
}

impl IndexedWriter {
    /// Start a file that will hold exactly `n_arrays` arrays. The count is
    /// needed up front because the index sits ahead of the data.
    pub fn create(path: &Path, n_arrays: usize) -> io::Result<Self> {
        let mut tmp_os = path.as_os_str().to_owned();
        tmp_os.push(".tmp");
        let tmp = PathBuf::from(tmp_os);
        let mut f = File::create(&tmp)?;
        f.write_all(MAGIC)?;
        f.write_all(&VERSION.to_le_bytes())?;
        f.write_all(&[n_arrays as u8])?;
        // Placeholder index, patched by `finish`.
        f.write_all(&vec![0u8; n_arrays * ENTRY_SIZE])?;
        Ok(Self {
            tmp,
            final_path: path.to_path_buf(),
            f,
            entries: Vec::with_capacity(n_arrays),
            n_arrays,
            offset: (4 + 2 + 1 + n_arrays * ENTRY_SIZE) as u64,
        })
    }

    /// Compress whatever `emit` writes, straight into the file.
    fn add_frame(
        &mut self,
        name: &str,
        emit: impl FnOnce(&mut zstd::stream::write::Encoder<'_, &mut File>) -> io::Result<()>,
    ) -> io::Result<()> {
        let start = self.offset;
        let mut enc = zstd::stream::write::Encoder::new(&mut self.f, 3)?;
        emit(&mut enc)?;
        let _ = enc.finish()?;
        self.record_raw(name, start)
    }

    /// Record an entry whose bytes were written to the file directly, from
    /// `start` up to the current position. Used by
    /// [`add_chunked_delta_u32`](Self::add_chunked_delta_u32), which emits one
    /// independent zstd frame per chunk and so cannot go through `add_frame`'s
    /// single encoder.
    fn record_raw(&mut self, name: &str, start: u64) -> io::Result<()> {
        let end = self.f.stream_position()?;
        let mut name_bytes = [0u8; 16];
        let nb = name.as_bytes();
        let take = nb.len().min(16);
        name_bytes[..take].copy_from_slice(&nb[..take]);
        self.entries.push((name_bytes, start, end - start));
        self.offset = end;
        Ok(())
    }

    /// Little-endian u32s, no delta.
    pub fn add_u32<I: IntoIterator<Item = u32>>(&mut self, name: &str, it: I) -> io::Result<()> {
        self.add_frame(name, |enc| {
            let mut buf: Vec<u8> = Vec::with_capacity(STAGE_BYTES);
            for v in it {
                buf.extend_from_slice(&v.to_le_bytes());
                if buf.len() >= STAGE_BYTES {
                    enc.write_all(&buf)?;
                    buf.clear();
                }
            }
            if !buf.is_empty() {
                enc.write_all(&buf)?;
            }
            Ok(())
        })
    }

    /// Deltas of the u32 stream, written as `(v - prev) as i32` little-endian.
    /// `read_delta_u32_array` accumulates them the same way, so this is the
    /// format the old whole-array delta compressor produced.
    pub fn add_delta_u32<I: IntoIterator<Item = u32>>(
        &mut self,
        name: &str,
        it: I,
    ) -> io::Result<()> {
        self.add_frame(name, |enc| {
            let mut buf: Vec<u8> = Vec::with_capacity(STAGE_BYTES);
            let mut prev = 0i64;
            for v in it {
                let d = (v as i64 - prev) as i32;
                prev = v as i64;
                buf.extend_from_slice(&d.to_le_bytes());
                if buf.len() >= STAGE_BYTES {
                    enc.write_all(&buf)?;
                    buf.clear();
                }
            }
            if !buf.is_empty() {
                enc.write_all(&buf)?;
            }
            Ok(())
        })
    }

    /// Deltas of the u32 stream, written as **independent per-chunk zstd
    /// frames** in the chunked container [`ChunkedTgt`] reads.
    ///
    /// `total` must be the exact number of values `it` yields. It goes into the
    /// header, and because it is known up front the header — including
    /// `n_chunks` — can be written before any data, which is what lets the
    /// per-chunk table live at the *end* of the entry and avoid a back-patch.
    ///
    /// Each chunk restarts the delta chain at `base` = the value immediately
    /// preceding that chunk (0 for the first), so decoding the chunks in order
    /// reproduces exactly the sequence [`add_delta_u32`](Self::add_delta_u32)
    /// would have written — while any single chunk decodes on its own.
    ///
    /// Resident cost is one 4 MB raw buffer plus one compressed frame at a
    /// time, regardless of `total`; on the 44 GB dump this is what lets a warm
    /// session read one object's edges without materialising 9.3 GB of `u32`.
    pub fn add_chunked_delta_u32<I: IntoIterator<Item = u32>>(
        &mut self,
        name: &str,
        total: usize,
        it: I,
    ) -> io::Result<()> {
        let n_chunks = total.div_ceil(TGT_CHUNK_VALUES);
        let start = self.offset;
        let mut it = it.into_iter();
        // 16 bytes per chunk: ~37 KiB for the 44 GB dump's 2326 chunks.
        let mut table: Vec<(u64, u64)> = Vec::with_capacity(n_chunks);

        self.f.write_all(TGT_MAGIC)?;
        self.f.write_all(&(total as u64).to_le_bytes())?;
        self.f.write_all(&(n_chunks as u64).to_le_bytes())?;

        let mut prev: i64 = 0;
        let mut written = 0usize;
        for _ in 0..n_chunks {
            let take = TGT_CHUNK_VALUES.min(total - written);
            let base = prev as u64;
            let mut raw: Vec<u8> = Vec::with_capacity(take * 4);
            for _ in 0..take {
                let Some(v) = it.next() else {
                    return Err(io::Error::other(format!(
                        "chunked {name}: iterator yielded fewer than the declared {total} values"
                    )));
                };
                // Wrapping: a u32 difference can exceed i32's range, and the
                // reader accumulates with `wrapping_add` to match (the same
                // two's-complement round trip `add_delta_u32` relies on).
                raw.extend_from_slice(&((v as i64).wrapping_sub(prev) as i32).to_le_bytes());
                prev = v as i64;
            }
            let comp = zstd::encode_all(raw.as_slice(), 3)?;
            table.push((base, comp.len() as u64));
            self.f.write_all(&comp)?;
            written += take;
        }
        for (base, len) in &table {
            self.f.write_all(&base.to_le_bytes())?;
            self.f.write_all(&len.to_le_bytes())?;
        }
        self.record_raw(name, start)
    }

    /// i16 deltas of u16s, little-endian.
    pub fn add_delta_u16<I: IntoIterator<Item = u16>>(
        &mut self,
        name: &str,
        it: I,
    ) -> io::Result<()> {
        self.add_frame(name, |enc| {
            let mut buf: Vec<u8> = Vec::with_capacity(STAGE_BYTES);
            let mut prev = 0i32;
            for v in it {
                let d = (v as i32 - prev) as i16;
                prev = v as i32;
                buf.extend_from_slice(&d.to_le_bytes());
                if buf.len() >= STAGE_BYTES {
                    enc.write_all(&buf)?;
                    buf.clear();
                }
            }
            if !buf.is_empty() {
                enc.write_all(&buf)?;
            }
            Ok(())
        })
    }

    /// Little-endian u64s, no delta.
    pub fn add_u64<I: IntoIterator<Item = u64>>(&mut self, name: &str, it: I) -> io::Result<()> {
        self.add_frame(name, |enc| {
            let mut buf: Vec<u8> = Vec::with_capacity(STAGE_BYTES);
            for v in it {
                buf.extend_from_slice(&v.to_le_bytes());
                if buf.len() >= STAGE_BYTES {
                    enc.write_all(&buf)?;
                    buf.clear();
                }
            }
            if !buf.is_empty() {
                enc.write_all(&buf)?;
            }
            Ok(())
        })
    }

    /// Raw bytes, no transform — for opaque payloads like `inb_data`.
    pub fn add_bytes(&mut self, name: &str, data: &[u8]) -> io::Result<()> {
        self.add_frame(name, |enc| enc.write_all(data))
    }

    /// Patch the index and move the finished file into place.
    pub fn finish(mut self) -> io::Result<()> {
        if self.entries.len() != self.n_arrays {
            return Err(io::Error::other(format!(
                "indexed writer: expected {} arrays, got {}",
                self.n_arrays,
                self.entries.len()
            )));
        }
        self.f.seek(SeekFrom::Start(7))?;
        for (name, off, len) in &self.entries {
            self.f.write_all(name)?;
            self.f.write_all(&off.to_le_bytes())?;
            self.f.write_all(&len.to_le_bytes())?;
        }
        self.f.flush()?;
        let tmp = std::mem::take(&mut self.tmp);
        let dest = std::mem::take(&mut self.final_path);
        drop(self.f);
        fs::rename(tmp, dest)
    }
}

// ── Random-access reader for the chunked fwd_tgt ──────────────────────────────

/// The most recently decoded chunk, retained across reads.
#[derive(Default)]
struct ChunkState {
    idx: Option<usize>,
    vals: Vec<u32>,
}

/// Random-access reader for the chunked `fwd_tgt` container written by
/// [`IndexedWriter::add_chunked_delta_u32`].
///
/// Holds the `graph.bin` path and the per-chunk table — base, absolute frame
/// offset and compressed length, 24 bytes per chunk, so ~56 KiB for the 44 GB
/// dump's 2326 chunks — and decompresses a chunk only when a query asks for a
/// value inside it. The array itself (9.3 GB of `u32` there) is never resident.
///
/// The one-chunk cache is what makes the query path's access pattern cheap:
/// `run_oql::build_retained_edges` walks rows in increasing `fwd_off` order, so
/// a whole-heap scan decodes each chunk exactly once (~6.7 ms measured) and a
/// single-object lookup decodes one or two. A class-level query still pays for
/// every chunk — that is the inherent cost of answering `@inbounds`/`@outbounds`
/// over a scattered match set from a forward CSR, and it is reported as such.
///
/// Interior mutability is a `Mutex` rather than a `RefCell` because a
/// `ReplCache` lives behind a `Mutex` in the server and so must be `Send`.
pub struct ChunkedTgt {
    path: PathBuf,
    total: usize,
    /// `(base, absolute file offset of the chunk's frame, compressed length)`.
    table: Vec<(u64, u64, u64)>,
    state: Mutex<ChunkState>,
}

impl ChunkedTgt {
    /// Open the chunked `fwd_tgt` inside `graph.bin` in `cache_dir`.
    ///
    /// `Ok(None)` means "not in the chunked format": an older cache, or no
    /// `graph.bin` / `fwd_tgt` at all. Callers fall back to
    /// [`CacheDir::read_forward_targets`], which handles the old single-frame
    /// layout. A malformed *chunked* table is an `Err`, not a `None`, so a
    /// corrupt container cannot be silently reinterpreted as the old format.
    pub fn open(cache_dir: &Path) -> io::Result<Option<Self>> {
        let path = cache_dir.join("graph.bin");
        let Some((mut f, len)) = seek_to_entry(&path, "fwd_tgt")? else {
            return Ok(None);
        };
        let entry_off = f.stream_position()?;
        let mut head = [0u8; TGT_HEADER_BYTES];
        if f.read_exact(&mut head).is_err() || &head[0..4] != TGT_MAGIC {
            return Ok(None);
        }
        let total = u64::from_le_bytes(head[4..12].try_into().expect("8 bytes")) as usize;
        let n_chunks = u64::from_le_bytes(head[12..20].try_into().expect("8 bytes")) as usize;
        if n_chunks != total.div_ceil(TGT_CHUNK_VALUES) {
            return Err(io::Error::other(format!(
                "chunked fwd_tgt: header says {n_chunks} chunks for {total} values"
            )));
        }
        let table_bytes = n_chunks * TGT_TABLE_ENTRY;
        if (len as u64) < (TGT_HEADER_BYTES + table_bytes) as u64 {
            return Err(io::Error::other(
                "chunked fwd_tgt: entry too short to hold its chunk table",
            ));
        }
        // The table sits at the END of the entry, so its position follows from
        // the index's length — that is what let the writer avoid a back-patch.
        f.seek(SeekFrom::Start(entry_off + len as u64 - table_bytes as u64))?;
        let mut raw = vec![0u8; table_bytes];
        f.read_exact(&mut raw)?;
        let mut table = Vec::with_capacity(n_chunks);
        let mut off = entry_off + TGT_HEADER_BYTES as u64;
        for c in 0..n_chunks {
            let b = &raw[c * TGT_TABLE_ENTRY..(c + 1) * TGT_TABLE_ENTRY];
            let base = u64::from_le_bytes(b[0..8].try_into().expect("8 bytes"));
            let clen = u64::from_le_bytes(b[8..16].try_into().expect("8 bytes"));
            if clen == 0 || off + clen > entry_off + len as u64 {
                return Err(io::Error::other(
                    "chunked fwd_tgt: chunk frame outside the entry",
                ));
            }
            table.push((base, off, clen));
            off += clen;
        }
        // The frames must end exactly where the table begins. A gap or overlap
        // means the container is inconsistent with its own index entry.
        if off != entry_off + len as u64 - table_bytes as u64 {
            return Err(io::Error::other(
                "chunked fwd_tgt: chunk frames do not tile the entry",
            ));
        }
        Ok(Some(Self {
            path,
            total,
            table,
            state: Mutex::new(ChunkState::default()),
        }))
    }

    /// Number of values the container holds (`fwd_off`'s last entry).
    pub fn total(&self) -> usize {
        self.total
    }

    /// Number of chunks (the container's random-access granularity).
    pub fn n_chunks(&self) -> usize {
        self.table.len()
    }

    /// Copy `[start, end)` of the array into `out` (cleared first), decoding
    /// only the chunks the range touches.
    pub fn copy_range(&self, start: usize, end: usize, out: &mut Vec<u32>) -> io::Result<()> {
        out.clear();
        let end = end.min(self.total);
        if start >= end {
            return Ok(());
        }
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut i = start;
        while i < end {
            let c = i / TGT_CHUNK_VALUES;
            if g.idx != Some(c) {
                g.vals = self.load_chunk(c)?;
                g.idx = Some(c);
            }
            let o = i % TGT_CHUNK_VALUES;
            let avail = g.vals.len().saturating_sub(o);
            if avail == 0 {
                return Err(io::Error::other(format!(
                    "chunked fwd_tgt: chunk {c} is short of index {i}"
                )));
            }
            let take = (TGT_CHUNK_VALUES - o).min(end - i).min(avail);
            out.extend_from_slice(&g.vals[o..o + take]);
            i += take;
        }
        Ok(())
    }

    /// Decompress one chunk and undo its delta chain, starting from the chunk's
    /// stored base. The accumulator wraps, matching the writer's `as i32`
    /// truncation of a difference that may not fit in `i32`.
    fn load_chunk(&self, c: usize) -> io::Result<Vec<u32>> {
        let (base, off, clen) = self.table[c];
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(off))?;
        let mut buf = vec![0u8; clen as usize];
        f.read_exact(&mut buf)?;
        let raw = zstd::decode_all(buf.as_slice())?;
        let mut vals: Vec<u32> = Vec::with_capacity(raw.len() / 4);
        let mut acc = base as i64;
        for ch in raw.chunks_exact(4) {
            acc = acc.wrapping_add(i32::from_le_bytes([ch[0], ch[1], ch[2], ch[3]]) as i64);
            vals.push(acc as u32);
        }
        Ok(vals)
    }
}

/// Check that a file starts with the HPCA magic bytes.
fn check_magic(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf).is_ok() && &buf == MAGIC
}

/// Read the array index header from an indexed file.
#[allow(clippy::type_complexity)]
fn read_index(path: &Path) -> io::Result<Option<(File, Vec<([u8; 16], u64, u64)>)>> {
    if !path.exists() {
        return Ok(None);
    }
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Ok(None);
    }
    let mut ver = [0u8; 2];
    f.read_exact(&mut ver)?;
    if u16::from_le_bytes(ver) != VERSION {
        return Ok(None);
    }
    let mut n_buf = [0u8; 1];
    f.read_exact(&mut n_buf)?;
    let n = n_buf[0] as usize;
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let mut name = [0u8; 16];
        let mut off = [0u8; 8];
        let mut len = [0u8; 8];
        f.read_exact(&mut name)?;
        f.read_exact(&mut off)?;
        f.read_exact(&mut len)?;
        entries.push((name, u64::from_le_bytes(off), u64::from_le_bytes(len)));
    }
    Ok(Some((f, entries)))
}

/// Find an entry by name and seek to it, returning (file, compressed_len).
fn seek_to_entry(path: &Path, entry_name: &str) -> io::Result<Option<(File, usize)>> {
    let Some((mut f, entries)) = read_index(path)? else {
        return Ok(None);
    };
    let name_bytes = entry_name.as_bytes();
    for (name, offset, len) in entries {
        if name[..name_bytes.len().min(16)] == name_bytes[..name_bytes.len().min(16)]
            && (name_bytes.len() >= 16 || name[name_bytes.len()] == 0)
        {
            f.seek(SeekFrom::Start(offset))?;
            return Ok(Some((f, len as usize)));
        }
    }
    Ok(None)
}

// ── Array read helpers ────────────────────────────────────────────────────────

fn read_u32_array(path: &Path, name: &str) -> io::Result<Option<Vec<u32>>> {
    let Some((f, len)) = seek_to_entry(path, name)? else {
        return Ok(None);
    };
    let raw = decompress_zstd_frame(f, len)?;
    Ok(Some(le_bytes_to_u32(&raw)))
}

fn read_u64_array(path: &Path, name: &str) -> io::Result<Option<Vec<u64>>> {
    let Some((f, len)) = seek_to_entry(path, name)? else {
        return Ok(None);
    };
    let raw = decompress_zstd_frame(f, len)?;
    Ok(Some(le_bytes_to_u64(&raw)))
}

fn read_delta_u32_array(path: &Path, name: &str) -> io::Result<Option<Vec<u32>>> {
    let Some((f, len)) = seek_to_entry(path, name)? else {
        return Ok(None);
    };
    let raw = decompress_zstd_frame(f, len)?;
    let deltas = le_bytes_to_i32(&raw);
    Ok(Some(undelta_zigzag_i32(&deltas)))
}

/// Read an `i64`-delta stream (see [`encode_delta_u64_zstd`]) back to `u64`s.
fn read_delta_u64_array(path: &Path, name: &str) -> io::Result<Option<Vec<u64>>> {
    let Some((f, len)) = seek_to_entry(path, name)? else {
        return Ok(None);
    };
    let raw = decompress_zstd_frame(f, len)?;
    let mut out = Vec::with_capacity(raw.len() / 8);
    let mut acc = 0i64;
    for c in raw.chunks_exact(8) {
        let d = i64::from_le_bytes(c.try_into().expect("chunks_exact(8)"));
        // Wrapping: the encoder wrote `v - prev` as i64, so any offset < 2^63
        // round-trips regardless of monotonicity.
        acc = acc.wrapping_add(d);
        out.push(acc as u64);
    }
    Ok(Some(out))
}

/// Delta-encode a `u64` stream as little-endian `i64` deltas and zstd it,
/// streaming through the compressor so the raw 8-bytes-per-element array is
/// never materialized a second time. The counterpart is
/// [`read_delta_u64_array`]. Object record offsets are near-monotonic in
/// dense-id order, so the deltas are small and compress hard.
fn encode_delta_u64_zstd(data: &[u64]) -> io::Result<Vec<u8>> {
    let mut enc = zstd::Encoder::new(Vec::new(), 3)?;
    let mut buf: Vec<u8> = Vec::with_capacity(STAGE_BYTES);
    let mut prev = 0i64;
    for &v in data {
        let d = (v as i64).wrapping_sub(prev);
        prev = v as i64;
        buf.extend_from_slice(&d.to_le_bytes());
        if buf.len() >= STAGE_BYTES {
            enc.write_all(&buf)?;
            buf.clear();
        }
    }
    if !buf.is_empty() {
        enc.write_all(&buf)?;
    }
    enc.finish()
}

/// Read an entry as opaque bytes, with no byte-order interpretation — the
/// counterpart of `IndexedWriter::add_bytes`.
fn read_raw_array(path: &Path, name: &str) -> io::Result<Option<Vec<u8>>> {
    let Some((f, len)) = seek_to_entry(path, name)? else {
        return Ok(None);
    };
    Ok(Some(decompress_zstd_frame(f, len)?))
}

// ── Compression helpers ───────────────────────────────────────────────────────

fn write_zstd(path: &Path, data: &[u8]) -> io::Result<()> {
    let enc = zstd::encode_all(data, 3)?;
    fs::write(path, enc)
}

fn read_zstd(path: &Path) -> io::Result<Vec<u8>> {
    let compressed = fs::read(path)?;
    zstd::decode_all(compressed.as_slice())
}

fn zstd_compress_u32(data: &[u32]) -> io::Result<Vec<u8>> {
    let raw = u32_to_le_bytes(data);
    zstd::encode_all(raw.as_slice(), 3)
}

fn zstd_compress_u64(data: &[u64]) -> io::Result<Vec<u8>> {
    let raw = u64_to_le_bytes(data);
    zstd::encode_all(raw.as_slice(), 3)
}

fn undelta_zigzag_i32(deltas: &[i32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(deltas.len());
    let mut acc = 0i64;
    for &d in deltas {
        acc += d as i64;
        out.push(acc as u32);
    }
    out
}

fn decompress_zstd_frame(mut f: File, compressed_len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; compressed_len];
    f.read_exact(&mut buf)?;
    zstd::decode_all(buf.as_slice())
}

// ── Byte-reinterpretation helpers ─────────────────────────────────────────────

fn u32_to_le_bytes(data: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 4);
    for &v in data {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

fn u64_to_le_bytes(data: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 8);
    for &v in data {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

fn le_bytes_to_u32(data: &[u8]) -> Vec<u32> {
    data.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn le_bytes_to_u64(data: &[u8]) -> Vec<u64> {
    data.chunks_exact(8)
        .map(|c| u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
        .collect()
}

fn le_bytes_to_i32(data: &[u8]) -> Vec<i32> {
    data.chunks_exact(4)
        .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

// ── Hash / filesystem helpers ──────────────────────────────────────────────────

/// Hash a dump file for cache-busting: hex(first-64-bytes ++ file-size-le8 ++ mtime-ns-le8).
fn dump_hash(path: &Path) -> io::Result<String> {
    let meta = fs::metadata(path)?;
    let file_size = meta.len();
    let mtime_ns = meta
        .modified()
        .ok()
        .and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_nanos() as u64)
        })
        .unwrap_or(0);

    let mut f = File::open(path)?;
    let mut header = [0u8; 64];
    let n = f.read(&mut header)?;
    let header = &header[..n];

    // Simple but collision-resistant hash: FNV-1a over all input bytes.
    let mut h: u64 = 14695981039346656037u64;
    for &b in header {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    for &b in &file_size.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    for &b in &mtime_ns.to_le_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    Ok(format!("{h:016x}"))
}

fn dir_size(path: &Path) -> u64 {
    let Ok(rd) = fs::read_dir(path) else {
        return 0;
    };
    rd.filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("hprof-cache-tests");
        let _ = fs::create_dir_all(&dir);
        dir.join(name)
    }

    /// Every array kind the graph writer uses must survive a write/read round
    /// trip. `add_bytes`/`read_raw_array` in particular exist only for the
    /// inbound payload, which is opaque vbyte data.
    #[test]
    fn indexed_writer_round_trips_every_array_kind() {
        let path = tmp_path("roundtrip.bin");
        let mut w = IndexedWriter::create(&path, 5).unwrap();
        w.add_u32("fwd_off", [0u32, 2, 5]).unwrap();
        w.add_delta_u32("fwd_tgt", [1u32, 4, 4, 9, 2]).unwrap();
        w.add_delta_u16("fwd_field_idx", [3u16, 3, 0]).unwrap();
        w.add_u64("inb_block_off", [0u64, 7]).unwrap();
        w.add_bytes("inb_data", &[1, 2, 3, 4, 5, 6, 7]).unwrap();
        w.finish().unwrap();

        assert_eq!(
            read_u32_array(&path, "fwd_off").unwrap().unwrap(),
            [0, 2, 5]
        );
        assert_eq!(
            read_delta_u32_array(&path, "fwd_tgt").unwrap().unwrap(),
            [1, 4, 4, 9, 2]
        );
        assert_eq!(
            read_u64_array(&path, "inb_block_off").unwrap().unwrap(),
            [0, 7]
        );
        assert_eq!(
            read_raw_array(&path, "inb_data").unwrap().unwrap(),
            [1, 2, 3, 4, 5, 6, 7]
        );
    }

    /// The index sits ahead of the data, so the array count has to be declared
    /// up front. A mismatch must fail loudly rather than leave a file whose
    /// index points into the wrong frame — `graph.bin` is two-phase (forward
    /// before `build_from_fwd`, inbound after), so the count is easy to get
    /// wrong, and it was.
    #[test]
    fn indexed_writer_rejects_a_missing_array() {
        let path = tmp_path("short.bin");
        let mut w = IndexedWriter::create(&path, 4).unwrap();
        w.add_u32("a", [1u32]).unwrap();
        w.add_u32("b", [2u32]).unwrap();
        w.add_u32("c", [3u32]).unwrap();
        let err = w.finish().unwrap_err().to_string();
        assert!(err.contains("expected 4 arrays, got 3"), "{err}");
    }
}
