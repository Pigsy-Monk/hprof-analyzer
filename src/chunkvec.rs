//! Chunked u32 store for large fill-then-consume arrays.
//!
//! `inb_flat` in the inbound CSR build is filled by random-access scatter, then
//! consumed strictly left-to-right in Phase-4. A single flat `Vec<u32>` must
//! stay fully live until the last node is encoded, so it coexists with the
//! fully-built `inb_data` at the global RSS peak. Splitting the backing store
//! into fixed power-of-two chunks lets Phase-4 free each chunk the moment its
//! read cursor passes it, so remaining(inb_flat)+built(inb_data) peaks far below
//! their sum.
//!
//! Indexing uses shift/mask (CHUNK_LOG) so the scatter-fill hot path stays cheap.

const CHUNK_LOG: usize = 26; // 2^26 u32 = 64M slots = 256 MB per chunk
const CHUNK_LEN: usize = 1 << CHUNK_LOG;
const CHUNK_MASK: usize = CHUNK_LEN - 1;

/// Fill-then-consume u32 array split into fixed 256 MB chunks so each chunk can
/// be freed the instant its read cursor passes it (see module docs for the RSS
/// rationale). Empty inner `Vec`s mark already-freed chunks.
#[derive(Default)]
pub struct ChunkU32 {
    chunks: Vec<Vec<u32>>,
}

impl ChunkU32 {
    /// Returns true if no slots are allocated (len == 0).
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Build a ChunkU32 from a flat Vec. Used by tests, and by the disk cache
    /// when it rehydrates the forward CSR read back from `graph.bin`.
    pub fn from_vec(v: Vec<u32>) -> Self {
        let mut c = Self::zeroed(v.len());
        for (i, &x) in v.iter().enumerate() {
            c.set(i, x);
        }
        c
    }

    /// Allocate `len` u32 slots, zero-initialized, across power-of-two chunks.
    pub fn zeroed(len: usize) -> Self {
        let nchunks = len.div_ceil(CHUNK_LEN);
        let mut chunks = Vec::with_capacity(nchunks);
        let mut remaining = len;
        for _ in 0..nchunks {
            let this = remaining.min(CHUNK_LEN);
            chunks.push(vec![0u32; this]);
            remaining -= this;
        }
        ChunkU32 { chunks }
    }

    /// Store `val` at `idx` (shift/mask chunk lookup; hot scatter-fill path).
    #[inline(always)]
    pub fn set(&mut self, idx: usize, val: u32) {
        let c = idx >> CHUNK_LOG;
        let o = idx & CHUNK_MASK;
        self.chunks[c][o] = val;
    }

    /// Get the value at `idx`.
    #[inline(always)]
    pub fn get(&self, idx: usize) -> u32 {
        let c = idx >> CHUNK_LOG;
        let o = idx & CHUNK_MASK;
        self.chunks[c][o]
    }

    /// Free every chunk whose slots are entirely below `boundary` (exclusive).
    /// Idempotent: already-freed chunks stay empty. Call as the Phase-4 read
    /// cursor advances so consumed backing memory is returned promptly.
    /// Uses MADV_FREE (after drop) to hint the OS to reclaim pages.
    pub fn free_below(&mut self, boundary: usize) {
        let last_chunk = boundary >> CHUNK_LOG; // chunks strictly before this are fully consumed
        for c in 0..last_chunk {
            if !self.chunks[c].is_empty() {
                #[cfg(target_os = "linux")]
                let (ptr, len) = {
                    let chunk = &self.chunks[c];
                    (
                        chunk.as_ptr() as *mut libc::c_void,
                        chunk.len() * std::mem::size_of::<u32>(),
                    )
                };
                self.chunks[c] = Vec::new();
                // MADV_FREE after drop: pages are now in glibc's free-list;
                // the hint tells the kernel it can reclaim them under pressure
                // without corrupting glibc's bookkeeping (unlike MADV_DONTNEED
                // which zero-fills immediately and can corrupt free-list metadata).
                #[cfg(target_os = "linux")]
                unsafe {
                    libc::madvise(ptr, len, 8 /* MADV_FREE */);
                }
            }
        }
    }

    /// Copy the slots [start, end) into `out` (cleared first). The range may
    /// straddle a chunk boundary; both source chunks must still be live.
    pub fn copy_range(&self, start: usize, end: usize, out: &mut Vec<u32>) {
        out.clear();
        let mut i = start;
        while i < end {
            let c = i >> CHUNK_LOG;
            let o = i & CHUNK_MASK;
            let chunk = &self.chunks[c];
            let take = (CHUNK_LEN - o).min(end - i);
            out.extend_from_slice(&chunk[o..o + take]);
            i += take;
        }
    }

    /// Return a direct slice for `[start, end)` when the range lies entirely
    /// within a single chunk. Returns `None` when the range straddles a boundary
    /// (caller must fall back to `get` or `copy_range`). Zero-cost for the
    /// common case where a node's adjacency list fits inside one 256 MB chunk.
    #[inline(always)]
    pub fn range_slice(&self, start: usize, end: usize) -> Option<&[u32]> {
        if start >= end {
            return Some(&[]);
        }
        let c0 = start >> CHUNK_LOG;
        let c1 = (end - 1) >> CHUNK_LOG;
        if c0 == c1 {
            let o0 = start & CHUNK_MASK;
            let o1 = end & CHUNK_MASK;
            // end is exclusive; if end falls exactly on a chunk boundary, o1==0
            // which means the slice ends at the chunk's last element.
            let end_off = if o1 == 0 { CHUNK_LEN } else { o1 };
            Some(&self.chunks[c0][o0..end_off])
        } else {
            None
        }
    }

    /// Iterate the live chunks in index order, yielding each as a slice.
    ///
    /// Lets a consumer stream the whole array (e.g. into a compressor) without
    /// flattening it into one `Vec<u32>` first — the flatten is what made
    /// `heap load --with-graph` peak at ~50 GiB on a 44 GB dump. Already-freed
    /// chunks (see `free_below`) are skipped, so a partially-consumed array
    /// yields only what is still resident; callers that need a fixed count
    /// should `.take(n)` with `n` known independently (e.g. the CSR's
    /// `fwd_offsets.last()`).
    // Only the lib's `cache` module streams through this; the binary declares
    // its own copy of this module tree, where it is unused.
    #[allow(dead_code)]
    pub fn iter_live_chunks(&self) -> impl Iterator<Item = &[u32]> {
        self.chunks.iter().filter(|c| !c.is_empty()).map(|c| &c[..])
    }
}

/// Read-only view over a forward-target array, for the readers that do not care
/// how it is stored.
///
/// The two representations exist for different reasons: the pipeline builds a
/// [`ChunkU32`] because it scatter-fills the array and then frees chunks as the
/// read cursor passes them, while the from-cache path (`mat caches` with
/// `HPROF_MAT_USE_CACHE=1`) already holds a flat `Vec<u32>` decoded off
/// `graph.bin` — and that flat array is needed verbatim by the outbound emit
/// later, so it cannot be dropped in favour of a chunked copy.
///
/// Building the chunked copy anyway cost a full second array: 9.3 GB of
/// duplicate on the 44 GB dump, held across the `rpo_dfs` /
/// `unreachable_retained` window, which is where the from-cache path's ~52 GiB
/// peak came from. Both readers only ever call [`get`](Self::get) and
/// [`range_slice`](Self::range_slice), so this enum lets each path hand them
/// whichever form it already has.
#[derive(Clone, Copy)]
// The lib and the bin each compile their own copy of this module tree; the lib
// only ever builds `Chunked` (the from-cache path lives in the binary), so
// `Flat` would otherwise warn as unconstructed there.
#[allow(dead_code)]
pub enum TgtView<'a> {
    /// A contiguous `Vec<u32>`/slice (from-cache path).
    Flat(&'a [u32]),
    /// A chunked store (pipeline path).
    Chunked(&'a ChunkU32),
}

impl TgtView<'_> {
    /// Value at `idx`. Panics on out-of-range, like indexing a slice.
    #[inline(always)]
    pub fn get(&self, idx: usize) -> u32 {
        match self {
            TgtView::Flat(s) => s[idx],
            TgtView::Chunked(c) => c.get(idx),
        }
    }

    /// Contiguous slice for `[start, end)` when one exists, else `None` (caller
    /// falls back to per-element [`get`](Self::get)). A flat slice always
    /// satisfies the request; a chunked store only when the range stays inside
    /// one chunk.
    #[inline(always)]
    pub fn range_slice(&self, start: usize, end: usize) -> Option<&[u32]> {
        match self {
            TgtView::Flat(s) => s.get(start..end),
            TgtView::Chunked(c) => c.range_slice(start, end),
        }
    }
}
