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

use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use crate::{chunkvec::ChunkU32, pass1::Pass1Snapshot, report::Report};

// ── File format constants ─────────────────────────────────────────────────────

const MAGIC: &[u8; 4] = b"HPCA";
const VERSION: u16 = 1;
const ENTRY_SIZE: usize = 16 + 8 + 8; // name[16] + offset:u64 + len:u64

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
    pub fn add_forward_to_graph(w: &mut IndexedWriter, g: &GraphForCache) -> io::Result<()> {
        w.add_u32("fwd_off", g.fwd_off.iter().copied())?;
        // `fwd_off` is the CSR offset table, so its last entry is the edge count.
        let total_edges = g.fwd_off.last().copied().unwrap_or(0) as usize;
        w.add_delta_u32(
            "fwd_tgt",
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
        Ok(Some(handover.into_cache(
            source,
            n,
            shallow,
            class_idx,
            class_names,
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

    /// Returns `(fwd_off, fwd_tgt)` or `None` if graph not cached.
    pub fn read_forward_edges(&self) -> io::Result<Option<(Vec<u32>, Vec<u32>)>> {
        let off = read_u32_array(&self.path.join("graph.bin"), "fwd_off")?;
        let tgt = read_delta_u32_array(&self.path.join("graph.bin"), "fwd_tgt")?;
        Ok(match (off, tgt) {
            (Some(o), Some(t)) => Some((o, t)),
            _ => None,
        })
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
