# Changelog

All notable changes to hprof-analyzer are documented here.

## [Unreleased]

### Added

- **`server` starts from the disk cache.** A `server` previously held its
  analysis in memory only, so every restart re-ran the whole pipeline — on a
  44 GB dump that is ~50 minutes and ~20 GiB, which is most of the reason not
  to run one. It now rebuilds the query session from the cache files already
  on disk (`pass1.bin.zst` + `arrays.bin` + `class_names.json.zst`) before
  spawning the pipeline, and logs `warm start from disk cache`. On the 44 GB
  fare dump that brings a restart down to **42.7 seconds**. Anything missing
  or undecodable falls through to the pipeline, so this is purely an
  optimisation.

- **`server` diagnostics: `--trace-rss` and `--progress`.** The analyze path
  had per-stage RSS tracing and progress output; `server` accepted neither
  (setting `HPROF_TRACE_RSS` in the environment worked, but nothing
  documented it). Both flags now exist on `server`, with the CLI's `auto`
  rule, and the server's stage boundaries emit progress phases.

- **`server` refuses to re-read the dump by default; `--allow-rescan` opts in.**
  Both of the server's query escape hatches re-read the dump *while the resident
  analysis stays in memory*, so the peaks are roughly additive: a single query
  needing dominators took a `ready` server from 14.6 GiB to 31.3 GiB on a 32 GiB
  box and got it OOM-killed silently. The old `--no-rescan` flag was opt-in, so
  the safe behavior had to be remembered — and on a 32 GB box the unsafe default
  cost a live server. The default is now to refuse such a query up front with
  `{"kind":"rescan_refused"}`, naming the capability it wanted. Start the server
  with `--allow-rescan` (replacing the old `--no-rescan`, which is gone) to
  restore the escalated re-run on a box with memory to spare. Queries the
  resident cache can answer — counts, histograms, plain class projections,
  `@retainedHeapSize`, and edges from a `--with-graph` cache — are unaffected.

- **Queries answer `@inbounds` / `@outbounds` / `path()` from the cache.** A
  server warmed from `graph.bin` no longer re-reads the dump for edge
  queries. The session built from disk now carries the forward CSR and the
  inbound block CSR, so the ~50-minute, ~20 GiB rescan that existed only
  because a cache-assembled session carried no edges at all is gone. A
  truncated cache degrades to "no edges" rather than panicking, and a `heap
  load` without `--with-graph` simply has none.

- **`mat caches --report <path>`.** `mat caches` deliberately skipped the
  HTML report (`skip_report: true`, output to `/dev/null`) to avoid paying
  for `build_model` + `render` + `alloc_sites`. `--report` opts back in,
  with the output format inferred from the extension. Without the flag
  nothing changes.

- **Checkpoint tooling for the inbound-CSR and dominator stages.** Debugging
  the rescan-path edge loss meant re-running a ~40-minute pipeline per
  hypothesis; `HPROF_CKPT_SAVE=<dir>` plus the `dev dom-ckpt` /
  `dev ckpt-diff` / `dev ckpt-cmp` / `dev ckpt-rebuild-inbound` subcommands
  make that seconds-level.

### Changed

- **`heap load --with-graph` peak cut by ~48%.** On the 44 GB fare dump the
  peak dropped from ≥50.79 GiB to **26.43 GiB** (a plain `heap load` sits
  near 20 GiB). The graph-cache write path no longer flattens the 2.3-billion
  -edge forward CSR into a `Vec<u32>`, builds full-size delta buffers, or
  clones the offset table: `graph.bin` is now streamed straight to the file
  through a single 64 KiB staging buffer, and the forward half is written
  *before* `build_from_fwd` consumes the CSR, which is what lets it borrow
  the chunked store instead of copying it. Output is byte-identical to the
  old file. `graph.bin` is assembled under `.tmp` and renamed, so a run that
  dies mid-write cannot leave a truncated file that `check_magic` would
  accept.

- **`graph.bin`'s inbound half is real.** It was written as empty arrays
  while the file claimed otherwise. The inbound CSR is now written in the
  same `(inb_block_off, inb_data)` block form `compute_dominators` consumes.

- **Cache snapshots carry `kind` / `class_ids`.** Groundwork for the warm
  start: `Pass1Snapshot` now holds every field `OqlCacheHandover` needs, so
  the session can be rebuilt from the cache alone. Because `bincode` is not
  self-describing, a cache written by an older build now fails to decode and
  is re-analyzed with a warning (rather than a hard error), since `is_valid`
  only checks magic bytes and file presence and cannot see a schema change.

- **`server` hands the OQL cache over with the report.** The server's first
  OQL query used to re-run Pass1+Pass2 to build its `ReplCache` — 1903 s on a
  37.9 GB dump. Two causes: a `prewarm()` that ran a full Pass1+Pass2
  *concurrently* with the analysis (roughly doubling peak memory, and what
  OOM'd a 32 GiB box in server mode while the same binary finished the same
  dump in CLI mode — removing it takes the analysis peak from 31.29 GiB to
  17.03 GiB), and the analysis discarding the tables the query path reads.
  `AnalyzeOptions::keep_oql_cache` (set only by the server) now keeps them.

- **`mat caches` emits the report content MAT expects, not just an openable
  index.** `ClassImpl` carries a real `address`, MAT-id `superClassId` /
  `classLoaderId`, and real `fields` / `staticFields`; `SnapshotInfo`
  declares its full field set; `$useCompressedOops` is derived rather than
  hard-coded false; `roots` / `rootsPerThread` / `loaderLabels` and per-class
  static fields are populated. MAT recomputes none of these on reopen, so
  whatever is omitted stays omitted.

### Fixed

- **Report instance counts now name their scope.** One report showed
  `FareRecordContainer` as 2,174,154, 5,593,970 and 7,905,792 in three places
  and read like a bug. All three were correct and measuring different things:
  the Class Histogram's column is the class's **total instance count**, the
  Dominator Analysis "Biggest Classes by Retained Heap" column counts only
  **top-level dominators**, and a leak suspect's "Accumulated objects by
  class" counts only instances **inside that suspect's dominated subtree**.
  The columns are now `Instances (heap)`, `Top Dominators` and `In Subtree`,
  each table carries a one-line scope note, and the Glossary gains an
  "Instance counts — three scopes" entry.

- **The Threads section prints the complete stack.** It used to print only the
  frames that held a sampled local variable whenever `--thread-locals` data
  existed, which collapsed a 30-frame Tomcat dispatch to the single frame that
  happened to hold an object — hiding the call chain that explained the
  retention. Every recorded frame is now listed; frames that do hold a local
  are marked `✦` and annotated in place.

- **Top Components warns when its numbers cannot be added up.** A component's
  `Retained` is a sum of per-class retained heaps, which overlap, so the column
  total can exceed the entire heap — on a real dump one
  `ParallelWebappClassLoader` read 118.49 GB against a 24.86 GiB heap. When the
  column total exceeds the reachable heap the section now says so in a
  prominent warning, flags the offending rows, and states that `% Heap` is a
  share of that overlapping sum rather than of the heap.

- **One unit spelling: `KiB`/`MiB`/`GiB`/`TiB`/`PiB`.** `format_bytes` emitted
  `KB`/`MB`/`GB` for 1024-based quantities, so the same report read as
  "24.86 GB" in one place and "22.42 GiB" in another — a reader could reach
  opposite conclusions from one sentence. Every size in the Markdown report,
  the `--md-graphs` report and `compare reports` now carries the binary-unit
  suffix, and the size-basis caption matches.

- **Off-heap memory is reported twice, and labelled.** The single
  `DirectByteBuffer` figure was a per-instance sum of `capacity`, which counts
  memory shared between a buffer and its `duplicate()` / `slice()` views once
  per view: on a real dump it read 9.14 GB against 268 MB of actual direct
  memory. The decoder now also computes the size of the union of every
  buffer's `[address, address + capacity)` range — each allocation counted once
  — as `direct_byte_buffer_distinct_capacity_sum`, alongside the instance
  count. Both figures appear in the Heap Summary and Leak Indicators, and the
  OOM-triage off-heap rule fires on the de-duplicated one.

- **System properties are rendered at all.** They never were on JDK 9+: the
  overview's intro promised a System Properties table that never appeared,
  because `java.util.Properties` overrides every accessor to use its own
  `ConcurrentHashMap map` field, leaving the inherited `Hashtable.table` null
  forever, so the resolver found nothing. The props walk now follows
  `Properties.map` when `Hashtable.table` is empty, and decodes
  `ConcurrentHashMap$Node` as well as `Hashtable$Entry`. The table also carries
  a caption stating that the dump does **not** contain the JVM command line —
  HPROF records no `-Xmx` or GC flags — and a dump with no properties now says
  so instead of omitting the section.

- **`FROM INSTANCEOF <class>` no longer drops array types.** `FROM INSTANCEOF
  java.lang.Object` answered differently on the two query paths: the CLI
  (scan) reported `byte[]` and `java.lang.Object[]`, the server reported
  neither — everything else agreed, which is what made it easy to miss. Both
  paths now deliver arrays; on the server, the resident path drives array
  visits too, gated on the same `wants_arrays` predicate the scan uses. A
  query that can observe an array's element count (`@length`,
  `length()`/`size()`) is kept on the scan path, since the resident cache
  does not carry element counts.

- **`--reachable-only` now actually prunes.** Two separate defects. The CLI
  passed `reachable_only: true` as an argument while handing down
  `AnalyzeOptions::default()` (whose `reachable_only` is `false`), so the
  per-row source-index sidecar was never armed and `heap query` pruned
  nothing — it reported 762 `java.lang.Thread` objects on the 44 GB fare dump
  where MAT reports 753. Separately, the flag was a no-op for every query
  that escalates to the full pipeline (`@retainedHeapSize`, dominators,
  `@inbounds`, `toString`, RefPath), because carry-mode executors never build
  rows and so never arm the sidecar; those now prune their seeds before the
  late stage runs. **Known limitation:** scan-phase aggregates such as
  `COUNT(*)` still cannot be pruned.

- **MAT index: `ClassImpl.cacheEntry` was written as null.** MAT's
  `ClassImpl.getObjectIds()` slices the *inbound* index by that entry, so
  every view that asks a class for its instances came back empty or
  truncated: Top Consumers / Retained Set page numbering, the Finalizer page,
  the system class loader page, and the Thread Overview table. `inbound` now
  writes a class object's entry in MAT's own layout (instances ascending,
  then remaining referrers ascending), and `inbound.index` is byte-identical
  to MAT's. Thread Overview goes 19 → 21 rows, `372.html` 1489 → 5600 B.

- **MAT index: `domOut` was unsorted.** MAT sorts *every* dominator-tree
  entry by total size descending, not just the superroot's; ours were in
  ascending mat-id order, and the synthetic id 0 was forced to the end.
  `domOut.index` is now byte-identical to MAT's golden file. (This is what
  had collapsed MAT's Top Consumers to "No objects bigger than 1%".)

- **MAT index: the `UnreachableObjectsHistogram` property was missing; the
  `i2sv2` we wrote was wrong.** MAT stores the objects it discards as
  unreachable in a `SnapshotInfo` property; we wrote only the four plain
  properties, so the "Unreachable Objects" view had nothing to show. It now
  carries the same records, in the same order, with the same counts and sizes
  as MAT's own index. Conversely `i2sv2` (`RetainedSizeCache`) is no longer
  emitted: MAT's Class Histogram `Retained Heap` column reads the cached
  value whenever the entry is present, and ours (a plain sum of instance
  retained sizes) disagreed with MAT for 408 of 2036 classes, showing the
  column too large and mis-ordered. MAT recomputes the cache itself when the
  file is absent, so MAT now owns those values and the page is row-for-row
  identical to MAT's.

- **MAT index: `ClassImpl` field order and the embedded version.** The
  `ClassImpl` call site passed its key layers superclass-first where the
  serializer expects subclass-first, so MAT read `classLoaderAddress` /
  `classLoaderId` where it expected `AbstractObjectImpl`'s address and
  objectId and then hit `StreamCorruptedException: invalid type code: 00`
  (it re-parsed the dump). `fields` / `staticFields` / `subClasses` written
  as `TC_NULL` also made MAT NPE while restoring the snapshot.

- **`server`: the retained fast path was unreachable.** `used_fast_path`
  required `needs.retained` (via `needs_only_retained`) *and*
  `cache_eligible` (which requires `!needs.retained`), so the branch was dead
  code and every `@retainedHeapSize` query re-ran Pass1+Pass2 from the dump,
  on top of the resident analysis. On the fixture,
  `SUM(@retainedHeapSize)` went 3033 ms → 122 ms and `SELECT
  @retainedHeapSize` 2949 ms → 108 ms.

- **pass2: the inbound-CSR rescan path dropped edges.** When the dump is
  large enough to take the re-read path rather than transposing the forward
  CSR, `InboundBuilder` was handed empty `class_addr_to_hist` /
  `field_plans_dense` (so every instance-field edge was silently skipped) and
  an object array's element-class id was read and discarded. On a 41.3 GiB
  dump this lost 39% of the inbound edges and put 16.9% of nodes in the wrong
  place.

- **dominator: fail loudly when the LT invariant is violated.**
  `semi[w] <= preorder(parent[w])` is a theorem, so a violation proves the
  predecessor lists and the DFS tree disagree about where edges are attached
  — and therefore that any dominator tree built from them is wrong. That is
  exactly the silent failure the recovery ladder cannot catch (it fires only
  on an out-of-bounds decode), and it was producing a plausible, wrong tree
  with exit 0 and no warning. Now checked in the production path (one
  O(count) integer scan, no allocation) and reported as an error.

## [0.3.1] — 2026-10-02

### Added

- **Browser UI: `?file=<url>` query parameter.** Opening the browser UI with
  `?file=<url>` auto-loads without user interaction. A URL ending in `.hprof`,
  `.gz`, or `.zip` is fetched and loaded via WASM; any other URL is treated as
  a server base URL and auto-connected. Enables plugin-launched workflows such
  as `hprof-analyzer server dump.hprof` opening
  `https://parttimenerd.github.io/hprof-analyzer/?file=http://127.0.0.1:7070`.

### Changed

- **`hprof-redact` moved to its own workspace crate (`crates/hprof-redact`,
  `publish = false`).** The binary no longer appears in `cargo install
  hprof-analyzer`; it is built and distributed exclusively by CI.

- **MCP: `get_summary` tool removed.** It was redundant with the `load_dump`
  response, which now embeds a ready-to-run OQL query for the top leak suspect.
  Agents should call `get_report({section:"triage"})` or `get_report({section:"leaks"})`
  instead.

- **MCP: `get_report({section:"top-classes"})` default limit reduced from 20 to 10.**
  Each top-classes row carries holder breakdown data, making 20 rows
  disproportionately large. Pass `limit` explicitly for more rows.

- **MCP: dominator tree width capped at 20 children per node in leaks section.**
  Previously a single node with thousands of children could produce multi-MB
  responses. Truncated nodes carry `{"_truncated":true,"_omitted":<n>}`.

- **MCP: `get_report` section routing clarified.** Tool description now
  explicitly separates "simple question" sections (`top-classes`, `top-objects`,
  `overview`, `threads`) from "leak investigation" sections (`triage`, `leaks`,
  `retainers`, `dominators`), reducing unnecessary `triage` calls for histogram
  lookups.

## [0.3.0] — 2026-09-09

### Added

- **Lean redaction mode (new default for `hprof-redact`).** `RedactMode::Lean`
  is a single-pass redactor that zeroes all primitive array element data
  (`byte[]`, `char[]`, `int[]`, `long[]`, etc.) while copying `INSTANCE_DUMP`
  and `CLASS_DUMP` bodies verbatim. No class-field map is built; no HashMap is
  allocated. Use when throughput matters and leaking scalar fields (e.g.
  `String.hash`) is acceptable.

- **Complete redaction mode (opt-in via `--complete`).** `RedactMode::Complete`
  is the original two-pass mode, renamed and made opt-in. It zeroes all
  primitive values everywhere: array elements, scalar instance fields, and
  CLASS_DUMP static values. Use when the strongest privacy guarantee is needed.

- **`redact-bin` Cargo feature.** Minimal dependency set for the standalone
  `hprof-redact` binary (`dep:zip` + `dep:tar` only). Excludes clap, tokio,
  reedline, rmcp, scraper, ureq, self-replace, crossterm, anyhow, and bincode.
  Keeps the binary under 1 MB on all platforms.

- **`hprof-redact` binary now defaults to lean mode.** Pass `--complete` for
  full two-pass redaction. Progress output is suppressed when writing to stdout
  (piping-friendly).

- **MCP `redact` tool: optional `complete` parameter.** `complete: false`
  (default) uses lean mode; `complete: true` uses complete mode. The result
  message describes what was zeroed vs. preserved.

- **WASM: `redact_with_progress(data, name, mode, cb)`.** The `mode` parameter
  accepts `"lean"` or `"complete"`. Previous callers without the parameter must
  be updated.

- **Browser: Redact modal.** The Redact button opens a dialog to choose lean
  vs. complete mode before downloading the redacted dump.

- **ZIP streaming in `open_zip` / `open_zip_bytes`.** ZIP input now streams
  the decompressed HPROF content on-the-fly instead of buffering the entire
  decompressed file in memory (same `Box::leak + transmute` pattern as the
  existing tar path).

### Fixed

- **`copy_bytes` heap allocation eliminated.** The inner copy loop previously
  allocated a `vec![0u8; 65536]` per call. Now delegates to `copy_exact` which
  uses a stack `[u8; 4096]` buffer.

## [0.2.2] — 2026-09-04

### Added

- **`redact` subcommand and `hprof-redact` standalone binary.** Zeroes all
  primitive field values and array element data (char[], byte[], int fields,
  etc.) while preserving the complete object graph (class/field names, object
  IDs, reference links). Output is readable by hprof-analyzer, Eclipse MAT,
  and jhat. Accepts `.hprof`, `.hprof.gz`, `.hprof.zip`, `.tgz` input; output
  format is inferred from extension.

- **Redaction marker record (tag `0xDE`).** Redacted dumps carry a
  `REDACTED\x01` top-level record so hprof-analyzer can detect them and show
  a "Redacted dump" info banner in reports. Old tools skip the record cleanly.

- **`redacted_input: true` in JSON reports.** When a redacted dump is loaded,
  the report JSON includes `redacted_input: true` (mirrors `truncated_input`).
  Duplicate-string and collections analyses are skipped (they return
  meaningless all-zero results on zeroed data).

- **In-memory ZIP support for `HprofSource::Bytes`.** WASM and test code can
  now pass `.hprof.zip` bytes directly; the ZIP is decompressed in-memory
  without a temporary file.

### Fixed

- **Redactor handles `HEAP_DUMP_INFO` sub-records (tag `0xFE`).** The
  sub-record was previously unhandled, causing the heap-segment loop to
  desynchronize and corrupt or truncate output for dumps containing multiple
  heap segments with info records (Android, some HotSpot dumps).

- **Unknown sub-tag drains remaining segment bytes.** Previously an unknown
  sub-tag caused a silent early exit from the segment loop, leaving the
  outer stream desynchronized. Now remaining bytes in the segment are consumed
  before breaking, so subsequent top-level records parse correctly.

- **Conservative zeroing for unknown-class instances.** Instance blobs whose
  class is not in the field-type map (e.g. class was in a skipped segment) are
  now zeroed entirely rather than copied verbatim, preventing data leakage.

- **Redactor no longer over-reads instance blobs.** Added a `written >=
  data_len` guard that stops field processing if accumulated field sizes
  exceed the reported blob size; tail bytes are zeroed rather than copied.

## [0.2.1] — 2026-09-03

### Added

- **Setup & Usage modal in the browser UI.** Clicking "Setup & Usage" in the
  footer opens a modal with install instructions (Homebrew, Cargo, prebuilt
  binary), CLI quick reference, and MCP setup for Claude Code, Cline, and
  Claude Desktop. All code blocks are syntax-highlighted (shell and JSON).

- **Collapsible install panel on the browser landing page.** "— or install it
  locally (and with coding agents) —" expands to show CLI install tabs and AI
  integration cards inline, without leaving the page.

- **OQL syntax highlighting in the browser shell.** Both the sidebar query
  preview (HTML spans) and the xterm.js terminal input (ANSI codes) now
  highlight keywords, strings, numbers, identifiers, and `--` comments.

- **Shell and JSON syntax highlighting in setup guide code blocks.** Shell
  commands are tokenised into command/subcommand/flag/string/path/comment
  classes; JSON config blocks highlight keys, string values, keywords, and
  numbers. Both follow the page's light/dark theme.

- **Sample dump cards always visible on the landing page.** Sample dumps
  (mnemonics, scala-doku, philosophers, gauss-mix) are shown at all times;
  cards are grayed out when the server does not serve the files (e.g. local
  `file://` open) and become clickable once probed as available.

- **`mat caches` in CLI usage guides.** The setup modal, install panel,
  and README quick reference now include `hprof-analyzer mat caches dump.hprof`
  as a key command.

### Fixed

- **MCP: OQL alias `AS RETAINED` conflicted with reserved keyword.** All
  generated queries (examples, `get_summary`) now use `AS ret` / `AS ret_bytes`
  instead of `AS retained` / `AS RETAINED`.

- **MCP: `browse_dominators` / `query` responses had a trailing `/* HINT */`
  comment** that broke `json.loads()` for every model calling the tool. The
  hint is now in a `_hint` JSON field.

- **MCP: `get_report` now exposes all 17 report sections** with documentation
  updated to match actual JSON field names.

- **MCP: named queries use `@objectId AS idx`** instead of `@objectAddress`,
  so results plug directly into `browse_dominators` / `inspect_object` without
  address conversion.

- **CLI: `heap cache-list` now accepts a `.hprof` file path** (previously
  failed when passed a file rather than a directory).

- **MCP: leak detection fixed for small/medium heaps.** `load_dump` now embeds
  the top-5 suspect list in its response; `NEXT STEPS` now point to
  `get_report({section:"leaks"})` as the first action rather than the OQL
  `leak-suspects` view, which has a >10 MB threshold and returns 0 rows on
  small/medium heaps.

### Changed

- **OQL footguns documented:** glob patterns do not match inner classes
  (`ZipFile*` misses `ZipFile$Source` — use exact name or `INSTANCEOF`);
  `retained` / `RETAINED` column alias conflicts with `AS RETAINED SET`;
  `@objectId` is 0-based while `obj_index_1based` from `get_report` is 1-based.

- **MCP `get_report` description** updated: calls it "BEST TOOL for finding the
  leak / why OOM", explains single vs. group suspect JSON structures, and
  clarifies that the `leak-suspects` OQL view has a >10 MB threshold.

- **README "Browser mode" section removed.** Content was stale and duplicated
  the "Try it in the browser" section above it.

## [0.2.0] — 2026-08-10

### Added

- **MCP server.** Exposes heap analysis via the Model Context
  Protocol so Claude Code, Cline, Claude Desktop, and any other MCP-compatible
  AI assistant can load and analyze heap dumps interactively. Tools: `get_session_info`,
  `get_oql_docs`, `load_dump`, `get_summary`, `get_histogram`, `get_report`, `query`,
  `browse_dominators`, `inspect_object`. The server is stateful — `load_dump` must be
  called first, after which all other tools use the same session. Optionally pre-load
  a dump with `hprof-analyzer mcp --dump heap.hprof`.

- **`heap` subcommand group.** Every MCP tool is also a CLI command for scripting
  and LLM-driven workflows:
  ```
  hprof-analyzer heap summary <dump>
  hprof-analyzer heap histogram <dump> [--limit N] [--json]
  hprof-analyzer heap report <dump> [--section leaks|top|threads|overview|all] [--json]
  hprof-analyzer heap query <dump> --oql "..." [--json]
  hprof-analyzer heap browse <dump> [--index N] [--depth D] [--width W] [--json]
  hprof-analyzer heap inspect <dump> --index N [--json]
  hprof-analyzer heap docs [--topic syntax|attributes|examples|workflow|all]
  hprof-analyzer heap load <dump> [--with-graph]
  hprof-analyzer heap cache-list [<dump>]
  hprof-analyzer heap cache-clear <dump>
  ```
  Output is human-readable text by default; `--json` for machine-parseable output.

- **Disk cache.** The first analysis of a dump writes a cache to
  `<dump>.hprof-cache/<hash>/` (5–15 min, 70–400 MB). Every subsequent call for
  the same dump loads in ~1 s. Cache is content-addressed (first 64 bytes + file
  size + mtime) and busts automatically on dump changes. Add `--with-graph` on the
  first load to cache the reference graph for OQL `@inbounds`/`@outbounds` traversal
  (adds 200–600 MB).

- **Homebrew tap.** Install via:
  ```sh
  brew tap parttimenerd/hprof-analyzer
  brew trust parttimenerd/hprof-analyzer
  brew install hprof-analyzer
  ```
  A rolling nightly formula tracks every push to `main`; a stable versioned formula
  is published on each tagged release.

- **Holder breakdown in HTML report.** The Biggest Classes section now shows
  a collapsible "Held by (immediate dominators)" widget. For each top class,
  it lists the immediate-dominator classes (with instance count and retained
  size) and their own immediate dominators (level 2), making it easy to
  answer "which classes are keeping all these HashMaps alive?" without
  leaving the Top Consumers section. Computed via two O(n) passes over all
  objects after the class ranking is built; capped at 10 holders per class
  and 10 level-2 entries per holder.

- **`holder_chain` on biggest objects.** `ObjRow` now carries up to 2
  immediate-dominator class names toward the GC root, available in the JSON
  model for tooling that consumes the report programmatically.

- **Truncation resilience.** Truncated dumps, corrupt gzip streams, and
  malformed heap records all produce a partial report with a `truncated_input`
  warning rather than a crash or error exit. Corrupt length fields are capped
  before allocation to prevent OOM. Validated with a proptest fuzzing suite
  (8 suites × 500 cases) and a 10 000-iteration prefix-fuzz campaign.

- **`.tar.gz` / `.tgz` input support.** Heap dumps packaged as gzip-compressed
  tar archives are accepted everywhere a plain `.hprof` or `.hprof.gz` is —
  CLI, `diff`, `server`, `query`, and `mat` subcommands. Streamed on-the-fly;
  no decompression to disk required.

- **Android ART and IBM J9 support.** All HPROF sub-tags from Android ART
  (`ROOT_INTERNED_STRING`, `ROOT_DEBUGGER`, `ROOT_VM_INTERNAL`, `ROOT_JNI_MONITOR`,
  `PRIM_ARRAY_NODATA_DUMP`) and IBM J9 (`ROOT_SYSTEM_CLASS`) are now parsed
  correctly. Previously these produced `unknown heap sub tag` errors and aborted.

- **Interactive Object Graph Explorer.** Force-directed graph view for leak
  suspects and dominator tree nodes, powered by d3-force. Includes Inspector
  integration, neighbor dimming, and edge labels.

- **Heap Inspector panel.** Click-through from any object to see its fields,
  inbound references, retained size, and per-field value scan (top instances by
  retained size).

- **ThreadLocal Analysis section** in Markdown reports, plus Collection Waste
  Budget section with TOC.

- **`--field-stats` flag** for per-class reference-field null/non-null/retained
  breakdown.

- **WASM memory optimizations.** Compressed `shallow`/`retained`/`fwd_targets`
  arrays and a `run_fast_analysis_with_progress()` path that skips the retained
  pass — enables large dumps to load in-browser without OOM.

### Changed

- Holder breakdown is omitted from the plain Markdown renderer (it is
  present in the JSON model and HTML report only).

### Fixed

- `inspect_object` no longer panics when called with `with_graph=true` if
  the inbound CSR was not cached (the graph cache stores forward edges only;
  a bounds-check now guards the inbound lookup).

- All scan loops in pass 1, pass 2, and the field-decode layer now treat
  `InvalidData` (corrupt sub-tag, segment overrun, oversized array) identically
  to `UnexpectedEof` — stop scanning and emit a partial report instead of
  propagating a hard error.
- Saturating arithmetic throughout shallow-size helpers, collection-waste
  calculations, and array byte-length computations prevents integer overflow on
  file-derived values.
- Numerous HTML report display fixes: number formatting, percentage rendering,
  exact-byte tooltips, table overflow, column truncation.
