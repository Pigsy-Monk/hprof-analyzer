# Speeding up Eclipse MAT with hprof-analyzer

Eclipse MAT parses a **34 GB** heap dump in ~4 seconds and writes 12 cache files
alongside the `.hprof`. On the next open it reads from cache and loads in ~0.9 s.
The catch: MAT's own parser peaks at **~55 GB RSS** while writing those caches
on the same **34 GB** dump.

hprof-analyzer generates the same cache files in a single pipeline pass,
peaking at **~19 GB RSS** on that **34 GB** dump — less than half of MAT's peak.
Once the cache files are present, MAT opens instantly at the same low memory
cost regardless of who generated them.

The two measurements below are on **different dumps**, so the numbers are not
directly comparable row-to-row; each row names its dump.

| | 34 GB dump | 44.3 GB dump |
|---|---|---|
| `mat caches` wall time | — | **1 h 15 m 12 s** |
| cache files written | 12 | **11 files, 42.81 GiB** |
| hprof-analyzer peak RSS | **19.2 GB** | **25.53 GiB** |
| MAT's own parse peak RSS | **~55 GB** | not measured |

The 44.3 GB run writes 11 files rather than 12 because `i2sv2` is no longer
emitted (see [Known differences](#known-differences-from-mats-own-output));
MAT rebuilds that cache itself on first use.

## Workflow

```
# Step 1: generate the cache (fast, low RSS) — files written alongside dump.hprof
hprof-analyzer mat caches dump.hprof

# Step 2: open in MAT as usual — it detects the cache and skips its parser
# File → Open Heap Dump → pick dump.hprof in the same dir
```

MAT detects the cache automatically: if all index files are present and newer
than the `.hprof`, it prints "Reopening parsed heap dump file" and skips the
parse entirely.

If you also want hprof-analyzer's own report, you can generate both in one pass
(single hprof read, shared pipeline) with the `--mat` flag:

```
hprof-analyzer dump.hprof report.html --mat /path/to/dump-dir/
```

This is cheaper than running `analyze` then `mat caches` separately (two full
hprof parses vs one).

## Generated files

| File | Format | Content |
|------|--------|---------|
| `<dump>.idx.index` | LongIndex | Object address → MAT object id (sorted address table) |
| `<dump>.o2hprof.index` | LongIndex | MAT object id → byte offset of the object's record in the `.hprof` |
| `<dump>.o2c.index` | IntIndex | MAT object id → MAT class id |
| `<dump>.domIn.index` | IntIndex | MAT object id → immediate dominator MAT id |
| `<dump>.a2s.index` | LongIndex | MAT object id → shallow size |
| `<dump>.o2ret.index` | LongIndex | MAT object id → retained size |
| `<dump>.outbound.index` | IntArray1N sorted | Per-object outbound reference list |
| `<dump>.inbound.index` | IntArray1N sorted | Per-object inbound reference list |
| `<dump>.domOut.index` | IntArray1N unsorted | Per-object dominator-tree children |
| `<dump>.threads` | Text | Thread stacks and local variables |
| `<dump>.index` | Java serialization | Master snapshot metadata (class cache, GC roots, loader labels) |

`<dump>.i2sv2.index` (MAT's per-class retained-size cache) is deliberately
**not** written: MAT's Class Histogram reads the cached value whenever the
entry is present, and ours disagreed with MAT's, so MAT now recomputes it
itself. That is why a run writes 11 files, not 12.

MAT expects files named `<hprof-basename>.<suffix>` in the same directory as
the `.hprof`. The optional `<dir>` argument to `mat caches` lets you write cache
files to a different location; if omitted, they are written alongside the `.hprof`.

## Known differences from MAT's own output

These are intentional divergences that MAT accepts at load time without error:

- **`.index`**: The embedded hprof path string differs (our absolute path vs MAT's path). MAT re-resolves the path at open time; harmless.
- **`outbound.index`**: Our synthetic GC-root model differs slightly — the virtual superroot edges are arranged differently. Some root-path queries may return slightly different paths.
- **`a2s.index` / `o2ret.index`**: MAT adds a synthetic shallow size for GC-root stubs; we do not. Affects a handful of objects.
- **`i2sv2.index`**: no longer written (see above) — MAT recomputes the per-class retained-size cache itself.
- **`threads`**: Content-equivalent but not byte-identical (different serialization ordering).

`idx`, `o2c`, `domIn`, `o2hprof`, `inbound`, `domOut`: byte-identical to MAT's output.

## CLI reference

```
# Standalone cache generation (writes index files alongside the .hprof)
hprof-analyzer mat caches <hprof> [dir] [--mat-binary <path>] [--trace-rss]

# Combined analysis + cache generation (single hprof parse)
hprof-analyzer <hprof> [output] --mat <dir> [--mat-binary <path>]
```

`--mat-binary` points to the `MemoryAnalyzer` executable. When given,
hprof-analyzer derives the MAT plugins directory from it and embeds the correct
parser ID string in `.index`. Without it, hprof-analyzer auto-detects from
common install locations; if detection fails it falls back to a fixed default
that works with MAT 1.13.x.

## Why the RSS is so much lower

MAT's writers materialise full `int[N]` / `long[N]` arrays in Java heap — for
a 34 GB dump that means allocating several arrays of 500M–1.65B elements at
once inside the JVM. hprof-analyzer instead:

- **Interleaves each emit** with the pipeline stage where its source data is
  already live, rather than deferring everything to the end
- **Streams per page** (1M ints at a time), never holding the full value array
- Applies several targeted tricks in the hardest window (outbound emit, where
  `fwd_tgt` 8.87 GB + `fwd_off` 2.3 GB + `class_obj_ids` 2 GB are all live):
  - **In-place MAT-id translation** inside `fwd_tgt` — no per-object scratch Vec
  - **Chunked `fwd_tgt`** — the 2.3-billion-entry forward-target array is kept
    in 256 MB power-of-two chunks (`ChunkU32`) and never flattened into one
    `Vec<u32>`; the outbound emitter streams it straight into the compressor
  - **Deferred `class_obj_ids` restore** — kept compressed across the scatter phase
  - **Streaming decompression** for `CompressedU32::restore` — 64 KiB read buffer,
    no intermediate 2 GB byte Vec
  - **Delta-encoded zstd header spool** — the IntArray1N sorted format requires
    the 2 GB header to be written *after* the body; we stream it through a zstd
    encoder with delta encoding (deltas are small integers ~3–5, compress to
    ~25 MB) instead of holding a raw `Vec<i32>`
  - **`malloc_trim`** after scatter to return freed id_map pages to the OS before
    restoring `class_obj_ids`

The measured peak on the **34 GB** production dump is **19.2 GB** vs MAT's
~55 GB; the same pipeline peaks at **25.53 GiB** on the **44.3 GB** dump.

## Reusing the graph cache (the fast path)

`mat caches` can skip the whole pipeline when a graph cache already sits next to
the dump (written by `heap load --with-graph`). Opt in:

```
HPROF_MAT_USE_CACHE=1 hprof-analyzer mat caches dump.hprof outdir
```

- **Output is byte-identical** to the pipeline's: all 11 `.index` files match
  (verified 2026-10-12 on a 44 GB dump; also cross-checked against a second
  machine — the only differing file is the master `.index`, which embeds the
  dump's path and so legitimately differs).
- **24m18s / 29.37 GiB peak** vs the pipeline's **1h15m12s / 25.53 GiB**.

**But the accounting only works if the cache already exists:**

| scenario | total | vs pipeline |
|---|---|---|
| cache already there | **24m18s** | saves ~51 min |
| cache must be built for this | 46m46s (build) + 24m18s = **71m04s** | saves ~4 min |

So quote the fast path as 24m18s **only** when the cache is already paid for —
otherwise it is barely worth it.

Two caveats:
- `--report` is **degraded** on this path (no Waste Summary, no per-thread
  section, ~18–25% smaller) — those sections are by-products of pass 2's
  ~43-minute scan. Full report or fast path: pick one.
- The cache must be current; a cache missing inbound/idom/dominator-children
  makes the tool log and fall back to the pipeline (a wasted run). The log line
  `mat caches: reusing the graph cache…` is the tell.

## `o2hprof` implementation detail

MAT needs the byte offset in the `.hprof` for every object to support direct
record access. We track this in pass1: a `bytes_consumed` counter on
`HprofReader` is sampled at the start of each object record (`INSTANCE_DUMP`,
`OBJ_ARRAY_DUMP`, `PRIM_ARRAY_DUMP`, `CLASS_DUMP`). After pass1's address-sort
permutation, `p1.hprof_offsets[dense_id]` is the file offset for that object.
For gzipped dumps, offsets are positions in the decompressed stream — same
convention as MAT.
