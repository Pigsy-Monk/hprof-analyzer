//! CLI entry point and two-pass orchestration for the HPROF heap-dump analyzer.
//!
//! The default (no-subcommand) form sniffs the positional input: a `.hprof`,
//! `.hprof.gz`, `.tar.gz`, or `.tgz` dump (or HPROF magic) runs the analyze
//! pipeline, anything else is re-rendered as a saved Report JSON. Named
//! subcommands: `compare mat` (MAT export vs our
//! JSON) / `compare reports` (cross-dump growth), `completions` (shell completion
//! scripts), and `dev` (diagnostics).
//!
//! The analyze pipeline runs: pass1 (scan) -> pass2 (build graph) -> compress
//! cold arrays -> rpo DFS -> inbound CSR -> dominators -> retained -> build_model
//! -> render. Allocation/free/compress ordering here is load-bearing for the
//! peak-RSS budget on multi-GB dumps; see the inline notes before changing it.

mod bitset;
// Compiled into both module trees. The binary only *reads* the cache (warm
// start in `serve.rs`); the write-side API is exercised by the library's
// `analyze_with_cache`, so it is dead code here. The attribute is scoped to
// this declaration, so it does not mask anything in the library's copy.
#[allow(dead_code)]
mod cache;
mod chunkvec;
mod collection_config;
mod cvec;
mod diff;
mod diff_reports;
mod dominator;
mod html;
mod id_map;
mod mat;
mod md;
#[cfg(test)]
mod md_test;
mod named_queries;
mod opts;
mod pass1;
mod pass2;
mod progress;
mod query;
mod reader;
mod report;
mod retained;
mod rpo_dfs;
mod run_oql;
mod serve;
mod source;
mod sweep;
mod trace;
mod types;
mod unreachable_retained;
mod update;
mod vbyte;

use std::io::IsTerminal;
use std::{io, process, time::Instant};

use opts::{AnalyzeOptions, DEFAULT_QUERY_PATH_DEPTH, DetailLevel, OutputFormat};
use pass1::Pass1;
use run_oql::{NoClassIndex, RetainedEdgeStructs, query_uses_edges, run_oql_escalated};

/// clap `value_parser` for `--query-path-depth`: reject `0` (and non-numeric
/// input) with an actionable message. `usize`'s parser already rejects negative
/// and non-numeric values; we add the `> 0` guard on top.
fn parse_query_path_depth(s: &str) -> Result<usize, String> {
    let n: usize = s
        .parse()
        .map_err(|_| format!("`{s}` is not a valid non-negative integer for --query-path-depth"))?;
    if n == 0 {
        return Err(
            "--query-path-depth must be > 0 (bounded path walks need at least one hop)".into(),
        );
    }
    Ok(n)
}

use clap::{CommandFactory, Parser, Subcommand, ValueEnum, ValueHint};
use clap_complete::Shell;

/// Analyze a heap dump or re-render a saved report. The input is sniffed:
/// a `.hprof`, `.hprof.gz`, `.tar.gz`, or `.tgz` dump (or any file starting
/// with the HPROF magic) runs the full analysis pipeline; anything else is
/// treated as a saved Report JSON and re-rendered.
#[derive(Parser)]
#[command(
    name = "hprof-analyzer",
    version,
    about = "Analyze Java HPROF heap dumps (Eclipse MAT parity)",
    long_about = "A fast, low-memory analyzer for Java HPROF heap dumps.\n\n\
        Give it a heap dump and it parses the dump in a few streaming passes and \
        emits static reports that replicate three Eclipse MAT views: System \
        Overview, Leak Suspects, and Top Consumers, plus a Threads overview and \
        some extended collection views. Give it a saved Report JSON instead and \
        it re-renders that report without re-parsing the dump. Reports render as \
        plain Markdown, Markdown with ASCII graphs, self-contained HTML, or \
        machine-readable JSON.",
    after_help = "EXAMPLES:\n  \
        hprof-analyzer heap.hprof                         # Markdown to stdout\n  \
        hprof-analyzer heap.hprof report.html             # HTML (format from .html)\n  \
        hprof-analyzer heap.hprof report.json             # JSON (format from .json)\n  \
        hprof-analyzer heap.hprof -f md-graphs            # Markdown + ASCII graphs\n  \
        hprof-analyzer report.json report.html            # re-render saved JSON to HTML\n  \
        hprof-analyzer query heap.hprof --query 'SELECT COUNT(*) FROM java.lang.String'  # ad-hoc OQL\n  \
        hprof-analyzer query heap.hprof --repl            # interactive OQL shell\n  \
        hprof-analyzer heap.hprof out.html --query-file q.oql       # queries folded into a report\n  \
        hprof-analyzer compare reports r1.json r2.json [r3.json …]  # cross-dump growth diff\n  \
        hprof-analyzer completions zsh > _hprof-analyzer  # shell completions\n\n\
        OQL grammar, the -- @viz chart directive, and the --query= equals-form\n  \
        gotcha are documented in docs/OQL.md.\n\n\
        Install zsh completions:\n  \
        hprof-analyzer completions zsh > \"${fpath[1]}/_hprof-analyzer\"",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// A `.hprof`, `.hprof.gz`, `.hprof.tar.gz`, `.tar.gz`, or `.tgz` heap dump
    /// to analyze, or a saved Report JSON (or `.json.gz`, or `-` for stdin) to
    /// re-render. Required when no subcommand is given.
    #[arg(value_hint = ValueHint::FilePath)]
    input: Option<String>,

    /// Output path; writes to stdout when omitted. A `.gz` suffix writes
    /// gzip-compressed. When `--format` is not given, the format is inferred
    /// from this path's extension (.html/.htm, .json[.gz], .md).
    #[arg(value_hint = ValueHint::AnyPath)]
    output: Option<String>,

    /// Report output format. Overrides the extension-inferred format;
    /// defaults to Markdown when neither is given.
    #[arg(short, long, value_enum)]
    format: Option<FormatArg>,

    /// Output-size detail preset. `default` reproduces the historical caps;
    /// `minimal` shrinks and `max` expands every per-analysis output cap
    /// (leak-suspect children, dominator subtree, alloc sites, thread
    /// locals, top consumers). Ignored when re-rendering a saved report.
    #[arg(long, value_enum, default_value_t = DetailLevel::Default)]
    detail: DetailLevel,

    /// Log per-phase timing (and RSS on Linux) to stderr.
    #[arg(short, long)]
    verbose: bool,

    /// Print resident-set size (RSS) at each labeled pipeline stage to stderr,
    /// as `[trace-rss] <stage> RSS=N MB (peak N MB)`. Linux reads VmHWM for the
    /// peak; use it to pinpoint which stage drives the memory high-water mark.
    /// Analyze-only.
    #[arg(long)]
    trace_rss: bool,

    /// Show a live progress line on stderr. `auto` (default) enables it only
    /// when stderr is a terminal and --verbose is not set.
    #[arg(long, value_enum, default_value_t = ProgressWhen::Auto)]
    progress: ProgressWhen,

    /// Compute approximate duplicate-object analysis: finds content-identical
    /// `java.lang.String` values and content-identical primitive arrays
    /// (byte[], int[], etc.), then reports wasted bytes and top offenders.
    /// Hashes content to 64 bits — never retains the raw data, so RSS stays
    /// bounded. Adds a few extra heap-file scans; off by default. Analyze-only.
    #[arg(long)]
    find_duplicates: bool,

    /// Compute container attribution by holder Class#field (opt-in; adds
    /// ~300MB peak RSS). Analyze-only.
    #[arg(long)]
    collections: bool,

    /// Path to a TOML file defining custom collection handlers.
    /// Auto-discovers .hprof-analyzer.toml (CWD) or $HOME/.config/hprof-analyzer/collections.toml.
    #[arg(long, value_name = "PATH")]
    collection_config: Option<std::path::PathBuf>,

    /// Run an OQL query against the heap and include results in the report.
    /// May be repeated. Example: --query "SELECT * FROM java.lang.String".
    /// To embed a `-- @viz` chart directive, use the attached equals form so
    /// the leading `--` is not read as a flag: --query="-- @viz histogram
    /// <newline> SELECT ...". See docs/OQL.md for the full grammar.
    #[arg(long = "query", value_name = "OQL")]
    query: Vec<String>,

    /// Read one OQL query per non-empty line from a file (lines starting with
    /// `#` are comments; a `-- @viz` line attaches to the next query).
    #[arg(long = "query-file", value_name = "PATH", value_hint = ValueHint::FilePath)]
    query_file: Option<String>,

    /// Max hops for OQL `path(a, b)` bounded walks (must be > 0).
    #[arg(long = "query-path-depth", value_name = "N", default_value_t = DEFAULT_QUERY_PATH_DEPTH, value_parser = parse_query_path_depth)]
    query_path_depth: usize,

    /// Restrict OQL results to GC-reachable objects (Eclipse MAT parity). Off by
    /// default for analyze so the report stays byte-identical; opt in to prune
    /// unreachable objects from `--query` results.
    #[arg(long)]
    reachable_only: bool,

    /// Store field-name labels on forward edges so that leak-suspect
    /// "path to GC roots" steps show `ParentClass.fieldName → ChildClass`.
    /// Gated (off by default): adds ~2 bytes per reference edge in the heap
    /// (~100–500 MB extra RSS for large dumps). Analyze-only.
    #[arg(long)]
    ref_paths: bool,

    /// Collect per-class reference-field statistics: for the top-50 most
    /// common classes by instance count, report total non-null ref counts and
    /// sum of retained sizes for their pointees. Adds one O(n) pass.
    #[arg(long)]
    field_stats: bool,

    /// How many histogram rows (sorted by retained desc) get an expandable
    /// GC-root path in the report. Default 20; use 0 to disable. Overrides
    /// the value set by --detail. Analyze-only.
    #[arg(long, value_name = "N")]
    hist_root_path_top: Option<usize>,

    /// Enable all heavy opt-in analyses: equivalent to passing
    /// --obj-graph --collections --find-duplicates together.
    /// Adds ~330 MB peak RSS on large dumps (--obj-graph ~30 MB,
    /// --collections ~300 MB). --ref-paths is excluded because it can add
    /// 100–500 MB on top; pass it separately when field-name labels are needed.
    /// Analyze-only.
    #[arg(long)]
    full_analysis: bool,

    /// Capture the outbound-reference graph and dominator subtree for the top
    /// retained objects. Enables the interactive Object Graph Explorer (outbound
    /// refs, inbound refs, GC-root path, dominator drill-down) in the HTML report.
    /// Adds ~1–3 MB to the report; ~30 MB peak RSS freed after analysis.
    /// Implied by --full-analysis. Analyze-only.
    ///
    /// Optional value controls the edge capture tier:
    ///   --obj-graph          → small  (100 edges/obj, ~1–3 MB delta)
    ///   --obj-graph=medium   → medium (150 edges/obj, ~2–5 MB delta)
    ///   --obj-graph=large    → large  (300 edges/obj, ~5–15 MB delta)
    #[arg(long, num_args = 0..=1, default_missing_value = "small", value_name = "TIER")]
    obj_graph: Option<String>,

    /// Collection-detail size preset for --collections / --full-analysis.
    /// Controls how many holder-edges, container records, node-KV entries, and
    /// element-type samples are captured. Larger sizes give richer collection
    /// breakdowns at the cost of higher peak RSS.
    ///
    ///   --size small   → lowest RSS (1M edges, 10k collections tracked)
    ///   --size default → balanced (2.5M edges, 50k collections) [default]
    ///   --size large   → 2× balanced caps (5M edges, 100k collections)
    ///   --size max     → original uncapped limits (10M edges, 200k collections)
    ///
    /// Only affects --collections / --full-analysis; ignored for basic analysis.
    #[arg(long, default_value = "default", value_name = "SIZE")]
    size: String,

    /// Embed the React app bundle as plain readable JS in the HTML report
    /// (no deflate/base64). The report is ~750 KB larger but the JS is visible
    /// and editable in browser DevTools — useful for iterating on the UI.
    /// Implies --format html. Analyze-only.
    #[arg(long)]
    dev: bool,

    /// Read the React app bundle from PATH instead of the compile-time embedded
    /// bytes. Use together with --dev to iterate on JS/CSS without rebuilding
    /// the binary: run `node esbuild.config.mjs` in web/, then re-run this
    /// command with --dev --bundle-path web/dist/bundle.js.
    /// Implies --dev.
    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    bundle_path: Option<std::path::PathBuf>,

    /// Emit Eclipse MAT-compatible binary index files into DIR while running
    /// the normal analysis (the report output is unaffected). The files are
    /// named `<dump>.<kind>.index` using the input basename as the prefix.
    /// Analyze-only; adds some transient RSS to re-materialize compressed arrays.
    #[arg(long, value_name = "DIR", value_hint = ValueHint::DirPath)]
    mat: Option<std::path::PathBuf>,

    /// Path to the MemoryAnalyzer executable (used with --mat to auto-detect
    /// the MAT plugins directory and resolve the correct parser ID).
    #[arg(long, value_hint = ValueHint::FilePath)]
    mat_binary: Option<std::path::PathBuf>,
}

/// Named subcommands. The default (no subcommand) analyzes or re-renders the
/// positional input; see `Cli`.
#[derive(Subcommand)]
enum Cmd {
    /// Show available versions and optionally replace the running binary.
    ///
    /// With no argument: shows the current version, latest nightly build, and
    /// latest stable release without changing anything.
    ///
    /// With a channel argument: downloads that release and replaces this binary.
    ///   hprof-analyzer update nightly   # replace with latest nightly
    ///   hprof-analyzer update latest    # replace with latest stable release
    Update {
        /// Channel to update from. Omit to just show version info.
        #[arg(value_enum)]
        channel: Option<update::Channel>,
    },
    /// Compare reports (MAT export vs ours, or two of ours across time)
    Compare {
        #[command(subcommand)]
        cmd: CompareCmd,
    },
    /// Generate a shell completion script (write it to your completions dir)
    Completions {
        /// Target shell.
        shell: Shell,
    },
    /// Developer / diagnostic commands
    Dev {
        #[command(subcommand)]
        cmd: DevCmd,
    },
    /// Start a loopback HTTP server exposing OQL and report-section endpoints.
    Server {
        /// Path to the .hprof dump (.hprof, .hprof.gz, .tar.gz, .tgz).
        #[arg(value_hint = ValueHint::FilePath)]
        input: String,
        /// Port to bind (default 7070; loopback only).
        #[arg(long, value_name = "N")]
        port: Option<u16>,
        /// Never re-read the dump to answer a query: refuse it instead.
        ///
        /// Both of the server's escape hatches re-read the dump *while the
        /// analysis stays resident*, so peak memory is roughly additive. On a
        /// 32 GiB box a single query needing dominators, GC roots, edges or a
        /// reference walk was enough to push a `ready` server from 14.6 GiB to
        /// 31.3 GiB and get it OOM-killed — silently, minutes later. With this
        /// flag such a query returns `{"kind":"rescan_refused"}` naming the
        /// capability it wanted, instead of killing the server.
        ///
        /// Queries that the resident cache can answer — counts, histograms,
        /// `@retainedHeapSize`, and `@inbounds`/`@outbounds`/`path()` when the
        /// cache was written with `--with-graph` — are unaffected.
        #[arg(long)]
        no_rescan: bool,
        /// Print resident-set size (RSS) at each labeled pipeline stage to
        /// stderr while the analysis runs — the same `[trace-rss] <stage>
        /// RSS=N MB (peak N MB)` lines the CLI prints with `--trace-rss`.
        /// Equivalent to setting `HPROF_TRACE_RSS` in the environment.
        #[arg(long)]
        trace_rss: bool,
        /// Show a live progress line on stderr while the analysis runs.
        /// `auto` (default) enables it only when stderr is a terminal and
        /// `--trace-rss` is not set (that already prints per-stage lines).
        #[arg(long, value_enum, default_value_t = ProgressWhen::Auto)]
        progress: ProgressWhen,
    },
    /// Run one or more OQL queries against a heap dump and print the results.
    /// Fast query-only path (no full report): retained-size, dominator, and
    /// reference-graph attributes (@retainedHeapSize, dominators(x), @inbounds,
    /// path(a,b), ...) need the full report instead. See docs/OQL.md.
    Query {
        /// Path to the .hprof dump (.hprof, .hprof.gz, .hprof.zip, .tar.gz, .tgz).
        #[arg(value_hint = ValueHint::FilePath)]
        input: String,
        /// OQL query text (may be repeated). For a `-- @viz` directive use the
        /// attached equals form: --query="-- @viz histogram\nSELECT ...".
        #[arg(long = "query", value_name = "OQL")]
        query: Vec<String>,
        /// Read queries from a file, one per line (`#` comments allowed; a
        /// `-- @viz` line attaches to the next query).
        #[arg(long = "query-file", value_name = "PATH", value_hint = ValueHint::FilePath)]
        query_file: Option<String>,
        /// Max hops for OQL `path(a, b)` bounded walks (must be > 0).
        #[arg(long = "query-path-depth", value_name = "N", default_value_t = DEFAULT_QUERY_PATH_DEPTH, value_parser = parse_query_path_depth)]
        query_path_depth: usize,
        /// Start an interactive OQL REPL reading queries from stdin.
        #[arg(long)]
        repl: bool,
        /// Run a loopback HTTP server so tools can POST OQL and get JSON back.
        /// See the startup banner for usage; GET /help returns the language ref.
        #[arg(long, conflicts_with = "repl")]
        server: bool,
        /// Port for --server (default 7070; binds 127.0.0.1 only).
        #[arg(long, value_name = "N")]
        port: Option<u16>,
        /// Restrict OQL results to GC-reachable objects (Eclipse MAT parity).
        /// This is the default for the `query` subcommand; pass `--all` to
        /// include unreachable objects (raw heap scan).
        #[arg(long, conflicts_with = "all")]
        reachable_only: bool,
        /// Include unreachable objects in OQL results (raw heap scan), opting
        /// out of the reachable-only default.
        #[arg(long)]
        all: bool,
        /// Run a named query by name (see `query --list-named` for available names).
        #[arg(long = "run", value_name = "NAME")]
        run: Option<String>,
        /// List all named queries and exit.
        #[arg(long = "list-named")]
        list_named: bool,
        /// Output format for query results.
        /// `text` (default) prints aligned ASCII tables; `json` emits a JSON
        /// array of QueryResult objects suitable for scripting.
        #[arg(short, long, value_enum, default_value_t = QueryFormatArg::Text)]
        format: QueryFormatArg,
        /// When to show the live progress line on stderr.
        #[arg(long, value_enum, default_value_t = ProgressWhen::Auto)]
        progress: ProgressWhen,
    },
    /// Eclipse MAT cache generation
    Mat {
        #[command(subcommand)]
        cmd: MatCmd,
    },
    /// Heap dump analysis with transparent disk caching.
    ///
    /// On the first run against a dump, the full pipeline (5–15 min) executes
    /// and results are written to a cache directory alongside the dump.
    /// All subsequent runs load from cache in ~1 s.
    Heap {
        #[command(subcommand)]
        cmd: HeapCmd,
    },
    /// Start an MCP server that exposes heap-analysis tools via stdin/stdout.
    ///
    /// Designed for Claude Desktop and other MCP clients. Configure with:
    ///   claude mcp add hprof -- hprof-analyzer mcp
    Mcp {
        /// Pre-load this dump on startup (faster for single-dump sessions).
        #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
        dump: Option<String>,
    },
    /// Redact a heap dump: zero primitive array elements while preserving the
    /// object graph (IDs, class names, reference fields, instance scalar fields).
    ///
    /// Default (lean) mode is a single-pass stream: only PRIM_ARRAY_DUMP element
    /// bytes are zeroed — this covers byte[], char[], short[], int[], long[],
    /// float[], double[], and boolean[] arrays. Instance scalar fields (int, long,
    /// etc. on objects) are left untouched. Add --complete for a two-pass run that
    /// also zeros those.
    ///
    /// The output is a valid HPROF file that MAT, jhat, and hprof-analyzer can
    /// open. A custom marker record (tag 0xDE) is prepended so hprof-analyzer
    /// displays a "Redacted dump" banner and skips analyses that would be
    /// meaningless on zeroed data.
    ///
    /// Output format is inferred from the extension:
    ///   .hprof         raw binary
    ///   .hprof.gz      gzip-compressed
    ///   .hprof.zip     zip archive (single entry "dump.hprof")
    Redact {
        /// Input dump (.hprof, .hprof.gz, .hprof.zip, .tar.gz, .tgz).
        #[arg(value_hint = ValueHint::FilePath)]
        input: String,
        /// Output path (.hprof, .hprof.gz, or .hprof.zip).
        #[arg(value_hint = ValueHint::FilePath)]
        output: String,
        /// Complete (two-pass) mode: also zeros primitive scalar fields on instances
        /// and static fields on classes. Slower but leaves no primitive values anywhere.
        /// Default is lean mode (single-pass, zeros only primitive array elements).
        #[arg(long)]
        complete: bool,
    },
    /// Scan a heap dump for secrets: API keys, tokens, passwords, and other
    /// credentials left in JVM memory. Patterns sourced from betterleaks
    /// (https://github.com/betterleaks/betterleaks, MIT License).
    ///
    /// Default output is human-readable grouped by category.
    /// Use --format tsv for machine-readable: CATEGORY\tCLASS.FIELD,...\tVALUE
    ///
    /// Values are masked by default; use --verbatim to print them in plain text.
    DetectSecrets {
        /// Path to the heap dump (.hprof, .hprof.gz, .hprof.zip, .tar.gz, .tgz).
        #[arg(value_hint = ValueHint::FilePath)]
        input: String,
        /// When to show the live progress line on stderr.
        #[arg(long, value_enum, default_value_t = ProgressWhen::Auto)]
        progress: ProgressWhen,
        /// Print secret values verbatim instead of masking them.
        #[arg(long)]
        verbatim: bool,
        /// Output format: human-readable (default) or tab-separated values.
        #[arg(long, value_enum, default_value_t = SecretsFormat::Human)]
        format: SecretsFormat,
    },
}

/// `mat` subcommands.
#[derive(Subcommand)]
enum MatCmd {
    /// Generate Eclipse MAT-compatible binary index files for a heap dump.
    ///
    /// Runs the full analysis pipeline on HPROF and writes the MAT cache files
    /// into DIR (default: same directory as the dump). The files are named
    /// `<dump>.<kind>.index` matching MAT's own naming convention. After this
    /// completes, Eclipse MAT can open the dump instantly without re-parsing.
    Caches {
        /// The `.hprof`, `.hprof.gz`, `.tar.gz`, or `.tgz` heap dump to analyze.
        #[arg(value_hint = ValueHint::FilePath)]
        input: String,
        /// Directory to write the MAT index files into. Defaults to the
        /// directory containing the heap dump.
        #[arg(value_hint = ValueHint::DirPath)]
        dir: Option<String>,
        /// Path to the MemoryAnalyzer executable. Used to auto-detect the
        /// MAT plugins directory and resolve the correct parser ID for the
        /// `.index` header. When omitted, common installation paths are tried.
        #[arg(long, value_hint = ValueHint::FilePath)]
        mat_binary: Option<String>,
        /// Also write the analysis report here (`.md` / `.html` / `.json`,
        /// inferred from the extension). Omit to get only the MAT index —
        /// which is the old behaviour, and skips `build_model` + `render` +
        /// `alloc_sites` entirely.
        #[arg(long, value_hint = ValueHint::FilePath)]
        report: Option<String>,
    },
}

/// `heap` subcommands — heap dump analysis with transparent disk caching.
#[derive(Subcommand)]
enum HeapCmd {
    /// Print a text summary: top suspects + top classes by retained size.
    Summary {
        /// Path to the .hprof dump.
        #[arg(value_hint = ValueHint::FilePath)]
        dump: String,
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Print a section of the full analysis report.
    Report {
        /// Path to the .hprof dump.
        #[arg(value_hint = ValueHint::FilePath)]
        dump: String,
        /// Section to print: leaks, top, threads, overview, triage, waste, indicators,
        /// retainers, arrays, collections, references, dominators, components, alloc_sites,
        /// thread_locals, framework, field_stats, or all (default).
        #[arg(long, value_name = "SECTION")]
        section: Option<String>,
        /// Emit JSON instead of Markdown.
        #[arg(long)]
        json: bool,
    },
    /// Print a class histogram sorted by retained size.
    Histogram {
        /// Path to the .hprof dump.
        #[arg(value_hint = ValueHint::FilePath)]
        dump: String,
        /// Number of classes to print (default 50).
        #[arg(long, value_name = "N", default_value_t = 50)]
        limit: usize,
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Run an OQL query against a heap dump.
    Query {
        /// Path to the .hprof dump.
        #[arg(value_hint = ValueHint::FilePath)]
        dump: String,
        /// OQL query text.
        #[arg(long = "oql", value_name = "OQL")]
        oql: String,
        /// Emit JSON instead of an ASCII table.
        #[arg(long)]
        json: bool,
    },
    /// Browse the dominator tree.
    Browse {
        /// Path to the .hprof dump.
        #[arg(value_hint = ValueHint::FilePath)]
        dump: String,
        /// Object index (0-based @objectId from query results, or 'index' from browse output). Omit to start at GC root.
        #[arg(long = "index", value_name = "N")]
        index: Option<u64>,
        /// Levels of children to expand (default 3).
        #[arg(long, value_name = "N", default_value_t = 3)]
        depth: u8,
        /// Max children per node (default 10).
        #[arg(long, value_name = "N", default_value_t = 10)]
        width: usize,
        /// Emit JSON instead of a tree view.
        #[arg(long)]
        json: bool,
    },
    /// Inspect a single object, by dense index or by heap address.
    Inspect {
        /// Path to the .hprof dump.
        #[arg(value_hint = ValueHint::FilePath)]
        dump: String,
        /// Dense object index (0-based): from @objectId in query results or 'index' in browse output. NOT from obj_index_1based in get_report.
        #[arg(long = "index", value_name = "N")]
        index: Option<u64>,
        /// Heap address of the object, e.g. `0x56614a4e0` (`0x` optional).
        ///
        /// For when an address is all you have — from MAT, a log line, or
        /// another tool. The cache resolves it to the dense index, so the
        /// result is identical to passing `--index` for the same object.
        #[arg(long = "address", value_name = "ADDR")]
        address: Option<String>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
        /// Also show what the object's references point at, up to this many
        /// levels deep (default 0 — references stay as addresses).
        ///
        /// One level is usually what you want: a field holding a `City` then
        /// shows the `City`'s own fields instead of just its address. Expansion
        /// is bounded (200 extra objects), so a single inspect cannot walk the
        /// heap; `@fields` is simply absent past that point.
        #[arg(long, value_name = "N", default_value_t = 0)]
        depth: u32,
        /// Build the object-offset table (`offsets.bin`) first if this cache
        /// lacks it. Costs one pass-1 scan of the dump (~pass1's memory, which
        /// on a multi-GB dump means a multi-GB RSS spike) — only needed for
        /// caches created before offset capture existed.
        #[arg(long)]
        build_offsets: bool,
    },
    /// Print OQL documentation.
    Docs {
        /// Topic: syntax, attributes, examples, workflow, or all (default).
        #[arg(long, value_name = "TOPIC")]
        topic: Option<String>,
    },
    /// List the 20 built-in named query views (ready-to-run OQL, no dump needed).
    Views {
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Pre-populate the disk cache without printing any output.
    Load {
        /// Path to the .hprof dump.
        #[arg(value_hint = ValueHint::FilePath)]
        dump: String,
        /// Also build the reference graph: without it a cache-backed session
        /// cannot answer @inbounds/@outbounds/path(), and the server falls back
        /// to re-reading the dump (or refusing under --no-rescan).
        #[arg(long)]
        with_graph: bool,
    },
    /// Show cache entries and sizes for a dump (or all dumps in a directory).
    CacheList {
        /// Path to the .hprof dump, or a directory to scan.
        #[arg(value_hint = ValueHint::AnyPath)]
        path: Option<String>,
    },
    /// Delete cached results for a dump (forces re-analysis on next run).
    CacheClear {
        /// Path to the .hprof dump.
        #[arg(value_hint = ValueHint::FilePath)]
        dump: String,
    },
}

/// `compare` subcommands: MAT-parity check, or cross-dump growth.
#[derive(Subcommand)]
enum CompareCmd {
    /// Compare a MAT export against our canonical JSON (exit 2 on FAIL)
    Mat {
        /// Path to the Eclipse MAT report (HTML/zip).
        #[arg(value_hint = ValueHint::FilePath)]
        mat: String,
        /// Path to our canonical Report JSON.
        #[arg(value_hint = ValueHint::FilePath)]
        ours: String,
        /// Diff output format (Markdown or JSON); defaults to Markdown.
        #[arg(short, long, value_enum)]
        format: Option<FormatArg>,
    },
    /// Cross-dump growth: compare 2+ canonical Report JSONs as a time series
    /// (first = baseline, last = current)
    Reports {
        /// Report JSON paths in time order (first = baseline). Two or more are
        /// required; use "-" for stdin (at most one).
        #[arg(value_hint = ValueHint::FilePath, num_args = 2..)]
        reports: Vec<String>,
        /// Diff output format (Markdown, JSON, or HTML); defaults to Markdown.
        #[arg(short, long, value_enum)]
        format: Option<FormatArg>,
        /// Write output to this path instead of stdout. Gzip-compressed when the
        /// path ends in `.gz`.
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: Option<String>,
    },
}

/// Developer / diagnostic subcommands.
#[derive(Subcommand)]
enum DevCmd {
    /// Print the JSON Schema of the report model
    EmitSchema,
    /// Re-run ONLY the dominator stage from a checkpoint directory written by
    /// `HPROF_CKPT_SAVE=<dir>`, so the stage can be iterated in seconds rather
    /// than re-running the whole pipeline. Set `HPROF_DBG_GRAPH=1` for the
    /// dominator diagnostics.
    DomCkpt {
        #[arg(value_hint = ValueHint::DirPath)]
        dir: String,
    },
    /// Rebuild the inbound CSR inside a checkpoint from its SAVED forward CSR
    /// (the transpose path — the same edges `build_from_fwd` produces), so the
    /// dominator can be re-run without re-reading the dump. The previous
    /// `inb_data.bin` is kept as `inb_data.orig.bin`.
    CkptRebuildInbound {
        #[arg(value_hint = ValueHint::DirPath)]
        dir: String,
    },
    /// Cross-check the stages of an `HPROF_CKPT_SAVE` directory against each
    /// other: 2a degree counts vs the forward CSR's true in-degrees, the
    /// prefix-summed cursors vs those counts, and the encoded inbound lists vs
    /// both. Localises which stage of the inbound-CSR construction diverges.
    CkptDiff {
        #[arg(value_hint = ValueHint::DirPath)]
        dir: String,
    },
    /// Compare the encoded inbound CSRs of two `HPROF_CKPT_SAVE` directories
    /// node by node. With one dump analysed through both inbound paths (the
    /// fwd-transpose path and the forced rescan path), the difference set is
    /// exactly what the rescan path loses.
    CkptCmp {
        #[arg(value_hint = ValueHint::DirPath)]
        a: String,
        #[arg(value_hint = ValueHint::DirPath)]
        b: String,
    },
    /// Aggregate per-dump *.diff.json files into a gate report (exit 2 on gate-fail)
    SweepAggregate {
        #[arg(value_hint = ValueHint::DirPath)]
        dir: String,
    },
    /// Dump pass-1 parse stats as JSON
    DumpPass1 {
        #[arg(value_hint = ValueHint::FilePath)]
        input: String,
    },
}

/// CLI mirror of `OutputFormat` (kept separate so clap owns the value-enum).
#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum FormatArg {
    /// Human-readable Markdown.
    Md,
    /// Markdown with embedded graph/chart blocks.
    MdGraphs,
    /// Canonical Report JSON.
    Json,
    /// Standalone HTML.
    Html,
}

/// Output format for the `query` subcommand.
#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum QueryFormatArg {
    /// Aligned ASCII tables (default).
    Text,
    /// JSON array of QueryResult objects.
    Json,
}

/// Output-size preset. `Default` reproduces the historical cap values so
/// MAT/golden parity is unchanged; `Minimal`/`Max` scale the caps down/up.
/// Implement clap's `ValueEnum` manually (the type is defined in `opts.rs`
/// without clap as a dependency, so the derive is not available there).
impl ValueEnum for DetailLevel {
    fn value_variants<'a>() -> &'a [Self] {
        &[DetailLevel::Minimal, DetailLevel::Default, DetailLevel::Max]
    }
    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            DetailLevel::Minimal => clap::builder::PossibleValue::new("minimal"),
            DetailLevel::Default => clap::builder::PossibleValue::new("default"),
            DetailLevel::Max => clap::builder::PossibleValue::new("max"),
        })
    }
}

/// When to show the live progress line on stderr.
#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum ProgressWhen {
    /// Enable only when stderr is a terminal and no verbose/trace flag is set.
    Auto,
    /// Always emit progress lines to stderr.
    Always,
    /// Never emit progress lines.
    Never,
}

#[derive(clap::ValueEnum, Clone, Default)]
enum SecretsFormat {
    /// Grouped, human-readable output with category headers and location hints.
    #[default]
    Human,
    /// Tab-separated: CATEGORY\tLOCATIONS\tVALUE — one finding per line.
    Tsv,
}

impl From<FormatArg> for OutputFormat {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Md => OutputFormat::Md,
            FormatArg::MdGraphs => OutputFormat::MdGraphs,
            FormatArg::Json => OutputFormat::Json,
            FormatArg::Html => OutputFormat::Html,
        }
    }
}

/// Choose the output format: an explicit `--format` always wins; otherwise
/// infer from the output path's extension; otherwise fall back to Markdown
/// (the stdout default). `md-graphs` is never inferred — it shares the `.md`
/// extension with plain Markdown, so it stays opt-in via `-f md-graphs`.
fn resolve_format(explicit: Option<FormatArg>, out: Option<&str>) -> OutputFormat {
    if let Some(f) = explicit {
        return f.into();
    }
    if let Some(path) = out {
        let lower = path.to_ascii_lowercase();
        if lower.ends_with(".html") || lower.ends_with(".htm") {
            return OutputFormat::Html;
        }
        if lower.ends_with(".json") || lower.ends_with(".json.gz") {
            return OutputFormat::Json;
        }
        // .md / .markdown (and anything else) → plain Markdown.
    }
    OutputFormat::Md
}

/// Write report text to `path`, or to stdout when `path` is `None`. A `.gz`
/// suffix is written gzip-compressed (matching how `render` reads it back).
fn write_output(path: Option<&str>, text: &str) -> io::Result<()> {
    match path {
        Some(p) if p.ends_with(".gz") => {
            use std::io::Write;
            let f = std::fs::File::create(p).map_err(|e| io::Error::new(e.kind(), e))?;
            let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::best());
            enc.write_all(text.as_bytes())?;
            enc.finish()?;
            Ok(())
        }
        Some("-") | None => {
            print!("{text}");
            Ok(())
        }
        Some(p) => std::fs::write(p, text).map_err(|e| io::Error::new(e.kind(), e)),
    }
}

/// Print a one-line `error:` message to stderr and exit with status 1.
fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}

fn run_redact(input: &str, output: &str, complete: bool) -> io::Result<()> {
    use hprof_analyzer::redact::RedactMode;
    use hprof_analyzer::source::HprofSource;
    use std::fs::File;

    let source = HprofSource::from(input);
    let lower = output.to_ascii_lowercase();
    let mode = if complete {
        RedactMode::Complete
    } else {
        RedactMode::Lean
    };

    let progress = |_phase: &str, _fraction: f64| {};

    if lower.ends_with(".hprof.gz") {
        let file = File::create(output)?;
        let gz = flate2::write::GzEncoder::new(file, flate2::Compression::best());
        hprof_analyzer::redact::redact(&source, gz, mode, progress)
    } else if lower.ends_with(".hprof.zip") {
        let file = File::create(output)?;
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("dump.hprof", opts)
            .map_err(io::Error::other)?;
        hprof_analyzer::redact::redact(&source, &mut zip, mode, progress)?;
        zip.finish().map_err(io::Error::other)?;
        Ok(())
    } else {
        let file = File::create(output)?;
        hprof_analyzer::redact::redact(&source, file, mode, progress)
    }
}

fn run_detect_secrets(input: &str, progress: ProgressWhen, verbatim: bool, format: SecretsFormat) {
    use hprof_analyzer::query::run::ReplCache;
    use hprof_analyzer::secrets::SecretPatterns;
    use hprof_analyzer::source::HprofSource;

    let show_progress = match progress {
        ProgressWhen::Always => true,
        ProgressWhen::Never => false,
        ProgressWhen::Auto => std::io::stderr().is_terminal(),
    };

    let source = HprofSource::from(input);
    let cache = ReplCache::build_with_progress(&source, true, &mut |stage, _frac| {
        if show_progress {
            eprint!("\r\x1b[K[hprof] {stage}...");
        }
    });
    if show_progress {
        eprint!("\r\x1b[K");
    }
    let cache = match cache {
        Ok(c) => c,
        Err(e) => fail(format!("failed to load {input}: {e}")),
    };

    let string_values = match cache.build_string_values() {
        Ok(sv) => sv,
        Err(e) => fail(format!("failed to extract string values: {e}")),
    };

    let string_idxs: std::collections::HashSet<u32> = string_values.keys().copied().collect();
    if show_progress {
        eprint!("\r\x1b[K[hprof] scanning referrers...");
    }
    let attribution = match cache.build_string_referrers(&string_idxs, &string_values) {
        Ok(a) => a,
        Err(e) => fail(format!("failed to scan referrers: {e}")),
    };
    if show_progress {
        eprint!("\r\x1b[K");
    }

    let findings = SecretPatterns::new().scan(&string_values, &attribution);

    if findings.is_empty() {
        eprintln!("No secrets found.");
        return;
    }

    // Group by category preserving first-seen order.
    let mut categories: Vec<&str> = Vec::new();
    let mut by_category: std::collections::HashMap<
        &str,
        Vec<&hprof_analyzer::secrets::SecretFinding>,
    > = std::collections::HashMap::new();
    for f in &findings {
        let cat = f.category.as_str();
        by_category
            .entry(cat)
            .or_insert_with(|| {
                categories.push(cat);
                Vec::new()
            })
            .push(f);
    }

    match format {
        SecretsFormat::Tsv => {
            for f in &findings {
                let display_value = if verbatim {
                    f.value.clone()
                } else {
                    mask_secret(&f.value)
                };
                let locs = if f.locations.is_empty() {
                    "-".to_owned()
                } else {
                    f.locations
                        .iter()
                        .map(|(c, field)| format!("{c}.{field}"))
                        .collect::<Vec<_>>()
                        .join(",")
                };
                println!("{}\t{}\t{}", f.category, locs, display_value);
            }
        }
        SecretsFormat::Human => {
            let n_cats = categories.len();
            eprintln!(
                "Found {} secret(s) in {} categor{}:",
                findings.len(),
                n_cats,
                if n_cats == 1 { "y" } else { "ies" }
            );
            for cat in &categories {
                let items = &by_category[cat];
                eprintln!();
                eprintln!(
                    "  {cat} ({} value{})",
                    items.len(),
                    if items.len() == 1 { "" } else { "s" }
                );
                for f in items.iter() {
                    let display_value = if verbatim {
                        f.value.clone()
                    } else {
                        mask_secret(&f.value)
                    };
                    if f.locations.is_empty() {
                        println!("    {display_value}");
                    } else {
                        let locs = f
                            .locations
                            .iter()
                            .map(|(c, field)| format!("{c}.{field}"))
                            .collect::<Vec<_>>()
                            .join(", ");
                        println!("    {display_value}  [{locs}]");
                    }
                }
            }
            eprintln!();
        }
    }
}

fn mask_secret(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let n = chars.len();
    if n <= 8 {
        return "*".repeat(n);
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[n - 4..].iter().collect();
    format!("{head}****{tail}")
}

/// Parse args and dispatch to the selected subcommand.
fn main() {
    // Restore default SIGPIPE handling so `… | head` (or any reader that closes
    // early) terminates us via the signal like a normal Unix filter, instead of
    // Rust's default SIG_IGN turning the closed pipe into an EPIPE that panics
    // on the next stdout write. Unix only; a no-op elsewhere.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();
    match cli.cmd {
        None => run_default(cli),
        Some(Cmd::Update { channel }) => {
            if let Err(e) = update::run(channel) {
                fail(e);
            }
        }
        Some(Cmd::Compare { cmd }) => match cmd {
            CompareCmd::Mat { mat, ours, format } => {
                // Name a missing input up front — `run_diff` opens both files but
                // surfaces only a bare OS error, so pre-check for a clear message.
                for p in [&mat, &ours] {
                    if p != "-" && !std::path::Path::new(p).exists() {
                        fail(format!("cannot open '{p}': no such file or directory"));
                    }
                }
                let json_out = resolve_format(format, None) == OutputFormat::Json;
                match diff::run_diff(&mat, &ours, json_out) {
                    Ok(true) => {}
                    Ok(false) => process::exit(2),
                    Err(e) => fail(e),
                }
            }
            CompareCmd::Reports {
                reports,
                format,
                output,
            } => {
                // Name a missing input up front for a clear error, mirroring the
                // MAT arm. Skip "-" (stdin) — it has no filesystem path.
                for p in &reports {
                    if p != "-" && !std::path::Path::new(p).exists() {
                        fail(format!("cannot open '{p}': no such file or directory"));
                    }
                }
                match diff_reports::run(&reports, resolve_format(format, None)) {
                    Ok(text) => {
                        if let Some(path) = output {
                            let bytes = text.into_bytes();
                            if path.ends_with(".gz") {
                                use std::io::Write;
                                match std::fs::File::create(&path) {
                                    Ok(f) => {
                                        let mut gz = flate2::write::GzEncoder::new(
                                            f,
                                            flate2::Compression::default(),
                                        );
                                        if let Err(e) = gz
                                            .write_all(&bytes)
                                            .and_then(|_| gz.finish().map(|_| ()))
                                        {
                                            fail(format!("gzip write error: {e}"));
                                        }
                                    }
                                    Err(e) => fail(format!("cannot create '{path}': {e}")),
                                }
                            } else if let Err(e) = std::fs::write(&path, &bytes) {
                                fail(format!("cannot write '{path}': {e}"));
                            }
                        } else {
                            print!("{text}");
                        }
                    }
                    Err(e) => fail(e),
                }
            }
        },
        Some(Cmd::Completions { shell }) => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "hprof-analyzer", &mut io::stdout());
        }
        Some(Cmd::Dev { cmd }) => match cmd {
            DevCmd::EmitSchema => {
                let schema = schemars::schema_for!(report::Report);
                match serde_json::to_string_pretty(&schema) {
                    Ok(js) => println!("{js}"),
                    Err(e) => fail(e),
                }
            }
            DevCmd::DomCkpt { dir } => {
                if let Err(e) = run_dom_ckpt(&dir) {
                    fail(e);
                }
            }
            DevCmd::CkptDiff { dir } => {
                if let Err(e) = run_ckpt_diff(&dir) {
                    fail(e);
                }
            }
            DevCmd::CkptRebuildInbound { dir } => {
                if let Err(e) = run_ckpt_rebuild(&dir) {
                    fail(e);
                }
            }
            DevCmd::CkptCmp { a, b } => {
                if let Err(e) = run_ckpt_cmp(&a, &b) {
                    fail(e);
                }
            }
            DevCmd::SweepAggregate { dir } => match sweep::run_aggregate(&dir) {
                Ok(true) => {}
                Ok(false) => process::exit(2),
                Err(e) => fail(e),
            },
            DevCmd::DumpPass1 { input } => {
                if let Err(e) = dump_pass1_json(&input) {
                    fail(e);
                }
            }
        },
        Some(Cmd::Server {
            input,
            port,
            no_rescan,
            trace_rss,
            progress,
        }) => {
            if !input_is_hprof(&input) {
                fail(format!(
                    "'{input}' is not an HPROF dump; the `server` subcommand needs a .hprof[.gz/.zip/.tar.gz] file"
                ));
            }
            // The analysis runs on a background thread inside `serve`, but both
            // of these are process-global switches, so setting them here covers
            // it. `auto` mirrors the CLI: on only when stderr is a terminal, and
            // off when --trace-rss already prints per-stage lines.
            let show_progress = match progress {
                ProgressWhen::Always => true,
                ProgressWhen::Never => false,
                ProgressWhen::Auto => !trace_rss && std::io::stderr().is_terminal(),
            };
            progress::set_enabled(show_progress);
            trace::set_enabled(trace_rss);
            let opts = AnalyzeOptions {
                reachable_only: true,
                // Hand the OQL cache over with the report so the first query
                // after `ready` is served from it instead of re-running
                // Pass1+Pass2 (~30 min on a 30 GB+ dump).
                keep_oql_cache: true,
                ..DetailLevel::Default.options()
            };
            if let Err(e) =
                serve::run_server(&input, port.unwrap_or(serve::DEFAULT_PORT), opts, no_rescan)
            {
                fail(analyze_error_hint(&input, &e));
            }
        }
        Some(Cmd::Query {
            input,
            query,
            query_file,
            query_path_depth,
            repl,
            server,
            port,
            reachable_only: _,
            all,
            run,
            list_named,
            format,
            progress,
        }) => {
            if !input_is_hprof(&input) {
                fail(format!(
                    "'{input}' is not an HPROF dump; the `query` subcommand needs a .hprof[.gz/.zip/.tar.gz] file"
                ));
            }
            // --server and --repl take their queries from HTTP/stdin, so any
            // --query/--query-file is dropped. Warn rather than silently ignore.
            if (server || repl) && (!query.is_empty() || query_file.is_some()) {
                let mode = if server { "--server" } else { "--repl" };
                eprintln!(
                    "warning: {mode} takes queries interactively; --query/--query-file are ignored"
                );
            }
            if server {
                // Loopback HTTP server: POST OQL, get JSON back. Reads no stdin;
                // --query/--query-file are ignored.
                if let Err(e) = crate::query::server::run_server(
                    &input,
                    query_path_depth,
                    port.unwrap_or(serve::DEFAULT_PORT),
                ) {
                    fail(analyze_error_hint(&input, &e));
                }
            } else if repl {
                // Interactive mode reads queries from stdin; --query/--query-file
                // are ignored.
                if let Err(e) = crate::query::repl::run_repl(&input, query_path_depth) {
                    fail(analyze_error_hint(&input, &e));
                }
            } else {
                if list_named {
                    for nq in crate::named_queries::NAMED_QUERIES {
                        println!("{:40}  [{}]  {}", nq.name, nq.group, nq.display);
                    }
                    return;
                }
                let mut queries_vec = query;
                if let Some(ref name) = run {
                    let nq = crate::named_queries::NAMED_QUERIES
                        .iter()
                        .find(|q| q.name == name);
                    match nq {
                        None => {
                            let prefix_end = name
                                .char_indices()
                                .nth(3)
                                .map(|(i, _)| i)
                                .unwrap_or(name.len());
                            let prefix = &name[..prefix_end];
                            let candidates: Vec<&str> = crate::named_queries::NAMED_QUERIES
                                .iter()
                                .filter(|q| q.name.starts_with(prefix))
                                .map(|q| q.name)
                                .collect();
                            eprintln!("error: unknown named query {:?}", name);
                            if !candidates.is_empty() {
                                eprintln!("  did you mean: {}", candidates.join(", "));
                            }
                            std::process::exit(1);
                        }
                        Some(nq) => {
                            queries_vec.push(nq.oql.to_string());
                        }
                    }
                }
                let opts = AnalyzeOptions {
                    queries: queries_vec,
                    query_file,
                    query_path_depth,
                    // Query subcommand defaults to reachable-only (MAT parity);
                    // --all opts back into a raw-heap scan. --reachable-only is
                    // redundant-but-allowed since the default is already true.
                    reachable_only: !all,
                    ..DetailLevel::Default.options()
                };
                // Reuse the analyze pipeline, printing only the query results as text.
                let show_progress = match progress {
                    ProgressWhen::Always => true,
                    ProgressWhen::Never => false,
                    ProgressWhen::Auto => std::io::stderr().is_terminal(),
                };
                progress::set_enabled(show_progress);
                let json_out = format == QueryFormatArg::Json;
                if let Err(e) = run_queries(&input, opts, json_out) {
                    fail(analyze_error_hint(&input, &e));
                }
            }
        }
        Some(Cmd::Mat { cmd }) => match cmd {
            MatCmd::Caches {
                input,
                dir,
                mat_binary,
                report,
            } => {
                if !input_is_hprof(&input) {
                    fail(format!(
                        "'{input}' does not look like a .hprof[.gz/.zip/.tar.gz] file"
                    ));
                }
                progress::set_enabled(std::io::stderr().is_terminal());
                let mat_dir = dir.as_deref().unwrap_or_else(|| {
                    std::path::Path::new(&input)
                        .parent()
                        .and_then(|p| p.to_str())
                        .unwrap_or(".")
                });
                let base = std::path::Path::new(&input)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("dump");
                let prefix = base
                    .strip_suffix(".hprof.tar.gz")
                    .or_else(|| base.strip_suffix(".hprof.gz"))
                    .or_else(|| base.strip_suffix(".tar.gz"))
                    .or_else(|| base.strip_suffix(".tgz"))
                    .or_else(|| base.strip_suffix(".hprof"))
                    .unwrap_or(base);
                let mat_bin_path = mat_binary.as_deref().map(std::path::Path::new);
                let mat_emitter =
                    match mat::MatEmitter::new(std::path::Path::new(mat_dir), prefix, mat_bin_path)
                    {
                        Ok(e) => e,
                        Err(e) => fail(format!("cannot create MAT index dir '{mat_dir}': {e}")),
                    };
                // With `--report <path>`: write the report there, and let the
                // pipeline build it. Without it: skip `build_model` + `render`
                // + `alloc_sites` and send the (never-built) output to
                // /dev/null — i.e. the original `mat caches` behaviour.
                let (out_path, skip_report) = match report.as_deref() {
                    Some(p) => (p, false),
                    None => ("/dev/null", true),
                };
                if let Err(e) = run(
                    &input,
                    Some(out_path),
                    resolve_format(None, Some(out_path)),
                    false,
                    cvec::Codec::Deflate1,
                    AnalyzeOptions {
                        skip_report,
                        ..DetailLevel::Default.options()
                    },
                    Some(mat_emitter),
                ) {
                    fail(e);
                }
            }
        },
        Some(Cmd::Heap { cmd }) => {
            if let Err(e) = run_heap_cmd(cmd) {
                fail(e);
            }
        }
        Some(Cmd::Mcp { dump }) => {
            let preload = dump.map(std::path::PathBuf::from);
            if let Err(e) = hprof_analyzer::mcp::run_mcp_server(preload) {
                fail(e);
            }
        }
        Some(Cmd::Redact {
            input,
            output,
            complete,
        }) => {
            if let Err(e) = run_redact(&input, &output, complete) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        Some(Cmd::DetectSecrets {
            input,
            progress,
            verbatim,
            format,
        }) => {
            run_detect_secrets(&input, progress, verbatim, format);
        }
    }
}

/// Handler for all `heap` subcommands. Loads from cache (or runs the pipeline
/// on first call), then dispatches to the appropriate output function.
fn run_heap_cmd(cmd: HeapCmd) -> anyhow::Result<()> {
    use hprof_analyzer::{analyze_with_cache, cache::CacheMode, mcp::oql_docs};
    let lib_opts = hprof_analyzer::AnalyzeOptions::default();

    // Helper: load a session with progress on stderr.
    let load =
        |dump: &str, mode: CacheMode| -> anyhow::Result<hprof_analyzer::cache::CachedSession> {
            let path = std::path::Path::new(dump);
            if !path.exists() {
                anyhow::bail!("dump file not found: {dump}");
            }
            let show_progress = std::io::stderr().is_terminal();
            let result = analyze_with_cache(path, &lib_opts, mode, |stage| {
                if show_progress {
                    eprint!("\r\x1b[K[hprof] {stage}...");
                }
            })?;
            if show_progress {
                eprint!("\r\x1b[K");
            }
            Ok(result)
        };

    match cmd {
        HeapCmd::Summary { dump, json } => {
            let sess = load(&dump, CacheMode::Full)?;
            let r = &sess.report;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "suspects": &r.leaks.suspects.iter().take(5).map(|s| serde_json::json!({
                            "name": s.pretty_class,
                            "retained_bytes": s.retained,
                        })).collect::<Vec<_>>(),
                        "top_classes": &r.top.biggest_classes.iter().take(5).map(|c| serde_json::json!({
                            "class": c.pretty_class,
                            "instances": c.instances,
                            "retained_bytes": c.retained,
                        })).collect::<Vec<_>>(),
                    }))?
                );
            } else {
                println!("## Top Leak Suspects\n");
                for (i, s) in r.leaks.suspects.iter().take(5).enumerate() {
                    println!(
                        "{}. {} — {} MB retained",
                        i + 1,
                        s.pretty_class,
                        s.retained / 1_000_000
                    );
                }
                println!("\n## Top Classes by Retained Size\n");
                for (i, c) in r.top.biggest_classes.iter().take(5).enumerate() {
                    println!(
                        "{}. {} — {} instances, {} MB retained",
                        i + 1,
                        c.pretty_class,
                        c.instances,
                        c.retained / 1_000_000
                    );
                }
            }
        }
        HeapCmd::Report {
            dump,
            section,
            json,
        } => {
            let sess = load(&dump, CacheMode::Full)?;
            let r = &sess.report;
            if json {
                let val = match section.as_deref().unwrap_or("all") {
                    "leaks" => serde_json::to_value(&r.leaks)?,
                    "top" => serde_json::to_value(&r.top)?,
                    "threads" => serde_json::to_value(&r.threads)?,
                    "overview" => serde_json::to_value(&r.overview)?,
                    "triage" => serde_json::to_value(&r.triage)?,
                    "waste" => serde_json::to_value(&r.waste_summary)?,
                    "indicators" => serde_json::to_value(&r.leak_indicators)?,
                    "retainers" => serde_json::to_value(&r.top_retainers)?,
                    "arrays" => serde_json::to_value(&r.arrays_by_size)?,
                    "collections" => serde_json::to_value(&r.collections)?,
                    "references" => serde_json::to_value(&r.references)?,
                    "dominators" => serde_json::to_value(&r.dominator_analysis)?,
                    "components" => serde_json::to_value(&r.top_components)?,
                    "alloc_sites" => serde_json::to_value(&r.alloc_sites)?,
                    "thread_locals" => serde_json::to_value(&r.thread_local_analysis)?,
                    "framework" => serde_json::to_value(&r.framework_analysis)?,
                    "field_stats" => serde_json::to_value(&r.field_stats)?,
                    _ => serde_json::to_value(r)?,
                };
                println!("{}", serde_json::to_string_pretty(&val)?);
            } else {
                let sec = section.as_deref().unwrap_or("all");
                println!("{}", hprof_analyzer::render_report_section(r, sec));
            }
        }
        HeapCmd::Histogram { dump, limit, json } => {
            let sess = load(&dump, CacheMode::Full)?;
            let rows: Vec<_> = sess
                .report
                .top
                .biggest_classes
                .iter()
                .take(limit)
                .map(|c| {
                    serde_json::json!({
                        "class": c.pretty_class,
                        "instances": c.instances,
                        "retained_bytes": c.retained,
                    })
                })
                .collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                println!(
                    "{:<60} {:>12} {:>16}",
                    "Class", "Instances", "Retained (MB)"
                );
                println!("{}", "-".repeat(92));
                for c in sess.report.top.biggest_classes.iter().take(limit) {
                    println!(
                        "{:<60} {:>12} {:>16.1}",
                        c.pretty_class,
                        c.instances,
                        c.retained as f64 / 1_000_000.0
                    );
                }
            }
        }
        HeapCmd::Query { dump, oql, json } => {
            let dump_str = dump.as_str();
            // Resolve view name or raw OQL
            let resolved_oql = named_queries::NAMED_QUERIES
                .iter()
                .find(|nq| nq.name.eq_ignore_ascii_case(oql.trim()))
                .map(|nq| nq.oql.to_string())
                .unwrap_or_else(|| oql.clone());
            let results = hprof_analyzer::run_oql_query(dump_str, &resolved_oql, true, &lib_opts)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            for r in results {
                if json {
                    let cols: Vec<&str> = r.columns.iter().map(|c| c.name.as_str()).collect();
                    let rows: Vec<Vec<serde_json::Value>> = r
                        .rows
                        .iter()
                        .map(|row| row.iter().map(qval_to_json).collect())
                        .collect();
                    let out = serde_json::json!({
                        "columns": cols,
                        "rows": rows,
                        "row_count": r.row_count,
                        "truncated": r.truncated,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    // Simple aligned table
                    let widths: Vec<usize> =
                        r.columns.iter().map(|c| c.name.len().max(12)).collect();
                    let header: Vec<&str> = r.columns.iter().map(|c| c.name.as_str()).collect();
                    println!(
                        "{}",
                        header
                            .iter()
                            .zip(widths.iter())
                            .map(|(h, w)| format!("{h:>w$}"))
                            .collect::<Vec<_>>()
                            .join("  ")
                    );
                    println!(
                        "{}",
                        widths
                            .iter()
                            .map(|w| "-".repeat(*w))
                            .collect::<Vec<_>>()
                            .join("  ")
                    );
                    for row in &r.rows {
                        let cells: Vec<String> = row
                            .iter()
                            .zip(widths.iter())
                            .map(|(v, w)| {
                                let s = match v {
                                    hprof_analyzer::query::model::QueryValue::Null => {
                                        "null".to_string()
                                    }
                                    hprof_analyzer::query::model::QueryValue::Bool(b) => {
                                        b.to_string()
                                    }
                                    hprof_analyzer::query::model::QueryValue::Int(n) => {
                                        n.to_string()
                                    }
                                    hprof_analyzer::query::model::QueryValue::Float(f) => {
                                        format!("{f:.3}")
                                    }
                                    hprof_analyzer::query::model::QueryValue::Str(s) => s.clone(),
                                    hprof_analyzer::query::model::QueryValue::ObjRef {
                                        index,
                                        class,
                                        ..
                                    } => format!("{class}@{index}"),
                                };
                                format!("{s:>w$}")
                            })
                            .collect();
                        println!("{}", cells.join("  "));
                    }
                    if r.truncated {
                        println!("(truncated — {} rows total)", r.row_count);
                    }
                }
            }
        }
        HeapCmd::Browse {
            dump,
            index,
            depth,
            width,
            json,
        } => {
            let sess = load(&dump, CacheMode::Full)?;
            let (dc_off, dc_tgt) = sess
                .cache
                .read_dominator_children()?
                .ok_or_else(|| anyhow::anyhow!("arrays.bin missing from cache"))?;
            let retained = sess
                .cache
                .read_retained()?
                .ok_or_else(|| anyhow::anyhow!("retained missing from cache"))?;
            let shallow = sess
                .cache
                .read_shallow()?
                .ok_or_else(|| anyhow::anyhow!("shallow missing from cache"))?;
            let class_idx = sess
                .cache
                .read_class_idx()?
                .ok_or_else(|| anyhow::anyhow!("class_idx missing from cache"))?;
            let n = shallow.len();
            let start = index.unwrap_or(n as u64);
            let class_by_idx: std::collections::HashMap<u32, String> = sess
                .class_names
                .iter()
                .enumerate()
                .map(|(i, n)| (i as u32, n.clone()))
                .collect();
            let tree = hprof_analyzer::mcp::browse_tree(
                start,
                depth.min(8),
                width.min(50),
                n,
                &dc_off,
                &dc_tgt,
                &retained,
                &shallow,
                &class_idx,
                &class_by_idx,
            );
            if json {
                println!("{}", serde_json::to_string_pretty(&tree)?);
            } else {
                print_dom_tree(&tree, 0);
            }
        }
        HeapCmd::Inspect {
            dump,
            index,
            address,
            json,
            depth,
            build_offsets,
        } => {
            let sess = load(&dump, CacheMode::Full)?;
            let shallow = sess
                .cache
                .read_shallow()?
                .ok_or_else(|| anyhow::anyhow!("shallow missing"))?;
            let retained = sess
                .cache
                .read_retained()?
                .ok_or_else(|| anyhow::anyhow!("retained missing"))?;
            let class_idx = sess
                .cache
                .read_class_idx()?
                .ok_or_else(|| anyhow::anyhow!("class_idx missing"))?;
            let idx = match (index, address.as_deref()) {
                (Some(i), None) => i as usize,
                (None, Some(a)) => {
                    let addr = parse_object_address(a)?;
                    sess.index_of_addr(addr).ok_or_else(|| {
                        anyhow::anyhow!(
                            "no heap object at address {a} — is this the dump the address came from?"
                        )
                    })?
                }
                (Some(_), Some(_)) => {
                    anyhow::bail!("give either --index or --address, not both")
                }
                (None, None) => {
                    anyhow::bail!("give --index N (dense index) or --address 0x… (heap address)")
                }
            };
            if idx >= shallow.len() {
                anyhow::bail!("object_index {idx} out of range (0..{})", shallow.len());
            }
            let cidx = class_idx[idx] as usize;
            let class_name = sess
                .class_names
                .get(cidx)
                .map(|s| s.as_str())
                .unwrap_or("<unknown>");

            // ── Field values ─────────────────────────────────────────────────
            // Read straight out of the dump at this object's recorded record
            // offset. One seek, a few dozen bytes — NOT a rescan (which is what
            // makes OQL `toString(s)` cost ~50 minutes and stall the server).
            let (fields, address, note) =
                inspect_fields(&dump, &sess, &class_idx, idx, build_offsets, depth)?;

            if json {
                let mut obj = serde_json::json!({
                    "object_index": idx,
                    "class": class_name,
                    "shallow_bytes": shallow[idx],
                    "retained_bytes": retained[idx],
                });
                if let Some(a) = &address {
                    obj["address"] = serde_json::Value::String(a.clone());
                }
                match fields {
                    Some(f) => obj["fields"] = f,
                    None => {
                        obj["fields"] = serde_json::Value::Null;
                        obj["fields_note"] = serde_json::Value::String(
                            note.unwrap_or_else(|| "field values unavailable".into()),
                        );
                    }
                }
                println!("{}", serde_json::to_string_pretty(&obj)?);
            } else {
                println!("Object #{idx}");
                if let Some(a) = &address {
                    println!("  Address:  {a}");
                }
                println!("  Class:    {class_name}");
                println!("  Shallow:  {} bytes", shallow[idx]);
                println!(
                    "  Retained: {} bytes ({:.1} MB)",
                    retained[idx],
                    retained[idx] as f64 / 1_000_000.0
                );
                match fields {
                    Some(f) => {
                        println!("  Fields:");
                        for (k, v) in f.as_object().into_iter().flatten() {
                            println!("    {k} = {}", render_field(v));
                        }
                    }
                    None => println!("  Fields:   (unavailable) {}", note.unwrap_or_default()),
                }
            }
        }
        HeapCmd::Docs { topic } => {
            println!("{}", oql_docs::get_oql_docs(topic.as_deref()));
        }
        HeapCmd::Views { json } => {
            if json {
                let rows: Vec<serde_json::Value> = named_queries::NAMED_QUERIES
                    .iter()
                    .map(|nq| {
                        serde_json::json!({
                            "name": nq.name,
                            "display": nq.display,
                            "group": nq.group,
                            "needs_retained": nq.needs_retained,
                            "oql": nq.oql,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows).unwrap());
            } else {
                let mut current_group = "";
                for nq in named_queries::NAMED_QUERIES {
                    if nq.group != current_group {
                        if !current_group.is_empty() {
                            println!();
                        }
                        println!("── {} ────────────────────────", nq.group);
                        current_group = nq.group;
                    }
                    let marker = if nq.needs_retained {
                        " [needs retained]"
                    } else {
                        ""
                    };
                    println!("  {}{}", nq.display, marker);
                    println!("    hprof-analyzer heap query <dump> --oql \"{}\"", nq.oql);
                }
            }
        }
        HeapCmd::Load { dump, with_graph } => {
            let mode = if with_graph {
                CacheMode::Graph
            } else {
                CacheMode::Full
            };
            load(&dump, mode)?;
            println!("Cache populated for: {dump}");
        }
        HeapCmd::CacheList { path } => {
            let search_path = path.as_deref().unwrap_or(".");
            let p = std::path::Path::new(search_path);
            if p.is_file() {
                // Specific dump file — show its cache
                let cache = hprof_analyzer::cache::CacheDir::for_dump(p)?;
                let cache_path = &cache.path;
                if cache_path.exists() {
                    let size = dir_size_recursive(cache_path);
                    println!(
                        "{}: {:.1} MB",
                        cache_path.display(),
                        size as f64 / 1_000_000.0
                    );
                } else {
                    println!("No cache for: {search_path}");
                }
            } else {
                list_caches(search_path);
            }
        }
        HeapCmd::CacheClear { dump } => {
            let cache = hprof_analyzer::cache::CacheDir::for_dump(std::path::Path::new(&dump))?;
            cache.clear()?;
            println!("Cache cleared for: {dump}");
        }
    }
    Ok(())
}

fn list_caches(path: &str) {
    let p = std::path::Path::new(path);
    let rd = match std::fs::read_dir(p) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Cannot read directory {path}: {e}");
            return;
        }
    };
    let mut found = false;
    for entry in rd.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".hprof-cache") {
            found = true;
            let cache_path = entry.path();
            let size = dir_size_recursive(&cache_path);
            println!(
                "{}: {:.1} MB",
                cache_path.display(),
                size as f64 / 1_000_000.0
            );
        }
    }
    if !found {
        println!("No cache directories found in {path}");
    }
}

fn dir_size_recursive(path: &std::path::Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(path) else {
        return 0;
    };
    rd.flatten()
        .map(|e| {
            let m = e.metadata().ok();
            match m {
                Some(m) if m.is_dir() => dir_size_recursive(&e.path()),
                Some(m) => m.len(),
                None => 0,
            }
        })
        .sum()
}

fn qval_to_json(v: &hprof_analyzer::query::model::QueryValue) -> serde_json::Value {
    use hprof_analyzer::query::model::QueryValue;
    match v {
        QueryValue::Null => serde_json::Value::Null,
        QueryValue::Bool(b) => serde_json::Value::Bool(*b),
        QueryValue::Int(n) => serde_json::json!(n),
        QueryValue::Float(f) => serde_json::json!(f),
        QueryValue::Str(s) => serde_json::Value::String(s.clone()),
        QueryValue::ObjRef { index, class, .. } => {
            serde_json::Value::String(format!("{class}@{index}"))
        }
    }
}

fn print_dom_tree(node: &serde_json::Value, indent: usize) {
    let pad = "  ".repeat(indent);
    let class = node["class"].as_str().unwrap_or("?");
    let retained = node["retained_bytes"].as_u64().unwrap_or(0);
    let index = node["index"].as_u64().unwrap_or(0);
    println!(
        "{pad}{class} (#{index}) — {:.1} MB retained",
        retained as f64 / 1_000_000.0
    );
    if let Some(children) = node["children"].as_array() {
        for child in children {
            print_dom_tree(child, indent + 1);
        }
    }
}

/// The default (no-subcommand) command: sniff the input and either run the
/// full analyze pipeline (HPROF) or re-render a saved Report JSON.
fn run_default(cli: Cli) {
    let Some(input) = cli.input else {
        // No subcommand and no input: this is a usage error, so write help to
        // stderr (not stdout) and exit 2, matching clap's own missing-arg path.
        let mut cmd = Cli::command();
        let _ = cmd.write_help(&mut io::stderr());
        eprintln!();
        process::exit(2);
    };

    if input_is_hprof(&input) {
        let show_progress = match cli.progress {
            ProgressWhen::Always => true,
            ProgressWhen::Never => false,
            ProgressWhen::Auto => !cli.verbose && std::io::stderr().is_terminal(),
        };
        progress::set_enabled(show_progress);
        trace::set_enabled(cli.trace_rss);
        let fmt = if cli.dev || cli.bundle_path.is_some() {
            // --dev implies HTML unless an explicit format or .html extension already means HTML.
            let base = resolve_format(cli.format, cli.output.as_deref());
            if base != OutputFormat::Html {
                OutputFormat::Html
            } else {
                base
            }
        } else {
            resolve_format(cli.format, cli.output.as_deref())
        };
        let opts = cli.detail.options();
        let mut opts = AnalyzeOptions {
            find_duplicates: cli.find_duplicates || cli.full_analysis,
            collections: cli.collections || cli.full_analysis,
            collection_config: cli.collection_config.clone(),
            coll_descs: crate::collection_config::load_collection_descs(
                cli.collection_config.as_deref(),
            ),
            queries: cli.query.clone(),
            query_file: cli.query_file.clone(),
            query_path_depth: cli.query_path_depth,
            // Analyze defaults to raw (all); --reachable-only opts into pruning.
            reachable_only: cli.reachable_only,
            ref_paths: cli.ref_paths,
            field_stats: cli.field_stats,
            obj_graph: cli.obj_graph.is_some() || cli.full_analysis,
            dev_report: cli.dev || cli.bundle_path.is_some(),
            bundle_path: cli.bundle_path.clone(),
            ..opts
        };
        if let Some(n) = cli.hist_root_path_top {
            opts.hist_root_path_top = n;
        }
        opts.report_size = match cli
            .obj_graph
            .as_deref()
            .map(|s| s.to_ascii_lowercase())
            .as_deref()
        {
            Some("medium") => crate::opts::ReportSize::Default,
            Some("large") => crate::opts::ReportSize::Large,
            None | Some("small") => crate::opts::ReportSize::Small,
            Some(other) => {
                eprintln!(
                    "error: unknown --obj-graph tier '{other}' (expected: small, medium, large)"
                );
                std::process::exit(2);
            }
        };
        // --size overrides the collection-detail caps (independent of --obj-graph tier).
        opts.report_size = match cli.size.to_ascii_lowercase().as_str() {
            "small" => crate::opts::ReportSize::Small,
            "default" => crate::opts::ReportSize::Default,
            "large" => crate::opts::ReportSize::Large,
            "max" => crate::opts::ReportSize::Max,
            other => {
                eprintln!(
                    "error: unknown --size tier '{other}' (expected: small, default, large, max)"
                );
                std::process::exit(2);
            }
        };
        // Build the MAT index emitter when --mat DIR is set. The prefix is the
        // input basename with a trailing `.hprof[.gz/.tar.gz]` stripped, matching how
        // MAT names its cache files (`dump_.hprof` -> `dump_.<kind>.index`).
        let mat = match cli.mat.as_deref() {
            Some(dir) => {
                let base = std::path::Path::new(&input)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("dump");
                let prefix = base
                    .strip_suffix(".hprof.tar.gz")
                    .or_else(|| base.strip_suffix(".hprof.gz"))
                    .or_else(|| base.strip_suffix(".tar.gz"))
                    .or_else(|| base.strip_suffix(".tgz"))
                    .or_else(|| base.strip_suffix(".hprof"))
                    .unwrap_or(base);
                match mat::MatEmitter::new(dir, prefix, cli.mat_binary.as_deref()) {
                    Ok(e) => Some(e),
                    Err(e) => fail(format!(
                        "cannot create MAT index dir '{}': {e}",
                        dir.display()
                    )),
                }
            }
            None => None,
        };
        if let Err(e) = run(
            &input,
            cli.output.as_deref(),
            fmt,
            cli.verbose,
            cvec::Codec::Deflate1,
            opts,
            mat,
        ) {
            fail(analyze_error_hint(&input, &e));
        }
    } else {
        // Re-render path. Analyze-only flags have no effect here — refuse them
        // with a hint rather than silently ignoring them.
        if cli.collections {
            fail(
                "--collections has no effect when re-rendering a saved report; \
                  re-run on the .hprof dump to include it",
            );
        }
        if cli.collection_config.is_some() {
            fail(
                "--collection-config has no effect when re-rendering a saved report; \
                  re-run on the .hprof dump to use it",
            );
        }
        if cli.find_duplicates {
            fail(
                "--find-duplicates has no effect when re-rendering a saved report; \
                  re-run on the .hprof dump to include it",
            );
        }
        if cli.mat.is_some() {
            fail(
                "--mat has no effect when re-rendering a saved report; \
                  re-run on the .hprof dump to emit MAT index files",
            );
        }
        if cli.detail != DetailLevel::Default {
            fail(
                "--detail has no effect when re-rendering a saved report; \
                  re-run on the .hprof dump to change output caps",
            );
        }
        // --verbose / --trace-rss / --progress are analyze-pipeline diagnostics;
        // they are harmless no-ops on the fast re-render path, so we accept them
        // silently rather than refuse them (unlike the data-affecting flags above).
        let fmt = resolve_format(cli.format, cli.output.as_deref());
        match render_report(&input, fmt) {
            Ok(text) => {
                if let Err(e) = write_output(cli.output.as_deref(), &text) {
                    let target = cli.output.as_deref().unwrap_or("<stdout>");
                    fail(format!("cannot write '{target}': {e}"));
                }
            }
            Err(e) => fail(render_error_hint(&input, &e)),
        }
    }
}

/// Like `analyze_to_report`, but also returns the per-object retained-size array
/// so callers (e.g. the HTTP server) can reuse it for OQL queries without a
/// full re-scan of the dump.
pub(crate) fn analyze_to_report_with_retained(
    source: &crate::source::HprofSource,
    opts: &AnalyzeOptions,
) -> std::io::Result<(crate::report::Report, Vec<u64>)> {
    let (report, retained, _oql_cache) = analyze_to_report_inner(source, opts)?;
    Ok((report, retained))
}

/// Like `analyze_to_report_with_retained`, but also hands back the warm OQL
/// `ReplCache` when `opts.keep_oql_cache` is set — so the server's **first**
/// query is served from it instead of re-running Pass1+Pass2 (~30 min on a
/// 30 GB+ dump). See `AnalyzeOptions::keep_oql_cache`.
pub(crate) fn analyze_to_report_with_retained_and_cache(
    source: &crate::source::HprofSource,
    opts: &AnalyzeOptions,
) -> std::io::Result<(
    crate::report::Report,
    Vec<u64>,
    Option<crate::query::run::ReplCache>,
)> {
    analyze_to_report_inner(source, opts)
}

fn analyze_to_report_inner(
    source: &crate::source::HprofSource,
    opts: &AnalyzeOptions,
) -> std::io::Result<(
    crate::report::Report,
    Vec<u64>,
    Option<crate::query::run::ReplCache>,
)> {
    // Wall-clock timing of the post-pass2 "dark phase" (obj-graph capture,
    // dominators, retained, build_model) to localize the runtime sink. The pass2
    // t_phase! markers reset to 0 at Pass2::build start, so "2b scan done" is
    // pass2-relative, not wall — these markers close that gap. Gated on
    // HPROF_TIMING like the pass2 markers; zero cost otherwise.
    let _t_pipe = std::time::Instant::now();
    macro_rules! t_pipe {
        ($label:expr) => {
            if std::env::var_os("HPROF_TIMING").is_some() {
                eprintln!(
                    "[timing] {}: {:.3}s",
                    $label,
                    _t_pipe.elapsed().as_secs_f64()
                );
            }
        };
    }
    progress::phase("scanning dump (pass 1)");
    let p1 = pass1::Pass1::run(source, false)?;
    let truncated_input = p1.truncated_input;
    let redacted = p1.redacted;

    if p1.class_ids.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "dump has {} objects, exceeding the {} (u32::MAX) limit of the \
                 analyzer's index scheme; cannot analyze",
                p1.class_ids.len(),
                u32::MAX
            ),
        ));
    }

    let compress = cvec::Codec::Deflate1;

    // Server path: keep copies of the five Pass1 tables the OQL cache reads
    // (`class_map`, `strings`, `id_map`, `kind`, `class_addr_table`) plus
    // `class_ids`, because `Pass2::build` takes `p1` by value and frees them
    // before the rpo peak. Cloning just these — rather than retaining all of
    // `p1` — bounds the extra peak to those tables. Off unless the server asked.
    let oql_handover = if opts.keep_oql_cache {
        Some(crate::query::run::OqlCacheHandover {
            class_map: p1.class_map.clone(),
            strings: p1.strings.clone(),
            id_map: p1.id_map.clone(),
            kind: p1.kind.clone(),
            class_addr_table: p1.class_addr_table.clone(),
            class_ids: p1.class_ids.clone(),
            id_size: p1.id_size,
        })
    } else {
        None
    };

    let mut no_in_sets = std::collections::HashMap::new();
    let mut no_exists_bools = std::collections::HashMap::new();
    progress::phase("building object graph (pass 2)");
    let (
        mut g,
        mut inbound,
        shallow_c,
        class_idx_c,
        alloc_serial_c,
        _query_state,
        _refwalk_csr,
        _string_values,
        _string_values_truncated,
    ) = pass2::Pass2::build(
        source,
        p1,
        compress,
        opts,
        &[],
        &mut no_in_sets,
        &mut no_exists_bools,
    )?;
    t_pipe!("pass2 done");

    inbound.compress_id_map(compress)?;

    progress::phase("ordering objects (reverse post-order)");
    let rpo = rpo_dfs::rpo_dfs(
        g.n,
        &g.gc_root_indices,
        &g.fwd_offsets,
        crate::chunkvec::TgtView::Chunked(&g.fwd_targets),
    );
    t_pipe!("rpo done");

    progress::phase("retained size (unreachable forest)");
    {
        g.unreachable_retained = unreachable_retained::compute_unreachable_retained(
            g.n,
            &rpo.dfn,
            &g.fwd_offsets,
            crate::chunkvec::TgtView::Chunked(&g.fwd_targets),
            &shallow_c,
            &class_idx_c,
            g.class_names.len(),
            &g.class_obj_class_idx,
            &g.class_names,
        )?;
    }
    t_pipe!("unreachable_retained done");
    let mut rpo = rpo;
    let parent_pre_count = rpo.parent_pre.len();
    let parent_pre_c = if compress != cvec::Codec::None {
        #[cfg(feature = "native")]
        let parent_pre_codec = cvec::Codec::Zstd1;
        #[cfg(not(feature = "native"))]
        let parent_pre_codec = cvec::Codec::Deflate1;
        let c = cvec::CompressedU32::compress(&rpo.parent_pre, parent_pre_codec)?;
        crate::trace::drop_vec(std::mem::take(&mut rpo.parent_pre));
        Some(c)
    } else {
        None
    };

    // Capture type-reference graph (class-pair counts) inline, then per-object
    // edges for the top-500K objects by shallow size (feeds click-through view).
    // g.class_idx is compressed into class_idx_c at this point; restore it
    // transiently for the scan (matching the run() path).
    if opts.obj_graph {
        g.class_idx = class_idx_c.restore()?;
        let (pairs, pair_fields, obj_graph) = crate::pass2::capture_type_ref_and_obj_graph(
            &g,
            &g.class_idx.clone(),
            500_000,
            opts.report_size.edge_cap(),
        );
        crate::trace::drop_vec(std::mem::take(&mut g.class_idx));
        g.type_ref_pairs = Some(pairs);
        g.type_ref_pair_fields = Some(pair_fields);
        g.obj_graph_edges = Some(obj_graph);
        crate::trace::probe("main: after capture_type_ref_and_obj_graph");
    }

    // When --field-stats is requested, save the fwd CSR before inbound consumes it.
    // It is restored into g after retained computation so build_field_stats can use it.
    let field_stats_fwd: Option<(Vec<u32>, crate::chunkvec::ChunkU32)> = if opts.field_stats {
        let total_edges = g.fwd_offsets.last().copied().unwrap_or(0) as usize;
        let fwd_off_copy = g.fwd_offsets.clone();
        let mut fwd_tgt_copy = crate::chunkvec::ChunkU32::zeroed(total_edges);
        for i in 0..total_edges {
            fwd_tgt_copy.set(i, g.fwd_targets.get(i));
        }
        Some((fwd_off_copy, fwd_tgt_copy))
    } else {
        None
    };

    // build_from_fwd needs dfn alive; it is cleared afterward (matching run()).
    // Large dumps: drop fwd_targets first and rescan HPROF to avoid the
    // inb_flat+fwd_targets peak (saves ~7-10 GB on 30G+ dumps).
    progress::phase("building inbound references");
    let (inb_block_off, inb_data) = if inbound.total_inb > 1_000_000_000 {
        drop(std::mem::take(&mut g.fwd_targets));
        drop(std::mem::take(&mut g.fwd_offsets));
        inbound.build_mat_scan(&rpo.dfn, |_src, _fwd| Ok(()))?
    } else {
        inbound.build_from_fwd(
            std::mem::take(&mut g.fwd_offsets),
            std::mem::take(&mut g.fwd_targets),
            &rpo.dfn,
        )?
    };

    // Rebuild vertex while dfn is still live; then free dfn.
    let count = parent_pre_count;
    rpo.vertex = rpo_dfs::rebuild_vertex(&rpo.dfn, count);
    rpo.dfn = Vec::new();

    if let Some(c) = parent_pre_c {
        rpo.parent_pre = c.restore()?;
    }

    progress::phase("computing dominators");
    g.idom =
        dominator::compute_dominators(g.n, rpo, &g.gc_root_indices, &inb_block_off, &inb_data)?;
    drop(inb_block_off);
    drop(inb_data);

    let (dc_off, dc_tgt) = retained::build_dom_children_csr(g.n, &g.idom);

    if compress != cvec::Codec::None {
        g.shallow = shallow_c.restore()?;
        g.class_idx = class_idx_c.restore()?;
    }
    drop(shallow_c);
    drop(class_idx_c);

    let class_count = g.class_names.len();
    let (retained, has_same, depth_counts) = retained::compute_retained(
        g.n,
        &g.shallow,
        &g.class_idx,
        class_count,
        &g.class_obj_class_idx,
        g.jlc_idx,
        &dc_off,
        &dc_tgt,
    );
    g.retained = retained;
    g.has_same_class_ancestor = has_same;

    // Compute field_stats now (while the saved fwd clone is live and retained is populated),
    // then immediately free the clone to avoid carrying it through build_model's allocations.
    let precomputed_field_stats: Option<crate::report::FieldStats> =
        if let Some((fwd_off, fwd_tgt)) = field_stats_fwd {
            g.fwd_offsets = fwd_off;
            g.fwd_targets = fwd_tgt;
            let fs = crate::report::build_field_stats(&g);
            g.fwd_offsets = Vec::new();
            g.fwd_targets = crate::chunkvec::ChunkU32::default();
            Some(fs)
        } else {
            None
        };

    let alloc_sites = if let Some(c) = alloc_serial_c {
        let mut agg = report::AllocAgg::new(&g, opts.alloc_sites_top);
        c.for_each_u32(|serial| agg.push(serial))?;
        let a = agg.finish();
        g.alloc_frames_by_serial = None;
        Some(a)
    } else {
        let a = report::build_alloc_sites(&g, opts.alloc_sites_top);
        g.alloc_stack_serial = Vec::new();
        g.alloc_frames_by_serial = None;
        Some(a)
    };

    progress::phase("building report");
    let mut report = report::build_model(
        &mut g,
        dc_off,
        dc_tgt,
        opts.leak_children_cap,
        &depth_counts,
        opts,
        alloc_sites,
        precomputed_field_stats,
        redacted,
    );
    // dc_off and dc_tgt were moved into build_model and freed early inside it.
    report.truncated_input = truncated_input;

    // Extract the per-object retained-size array before g is dropped.
    // The caller (analyze_to_report_with_retained) stores this for OQL reuse.
    let retained = std::mem::take(&mut g.retained);

    // Server path: assemble the warm OQL cache from the handover plus the arrays
    // the pipeline already restored into `g`. `g` is dead after this point, so
    // the two big arrays move rather than copy.
    //
    // No edges: by here the forward CSR has been consumed by `build_from_fwd`
    // (or dropped on the rescan path) and the inbound blocks it produced were
    // released right after `compute_dominators`. Both releases are what keeps
    // this path's peak down, so re-acquiring them here would cost the memory the
    // warm cache exists to save. A cache-backed session gets its edges from
    // `graph.bin` instead — see `CacheDir::read_query_cache`.
    let oql_cache = oql_handover.map(|h| {
        h.into_cache(
            source.clone(),
            g.n,
            std::mem::take(&mut g.shallow),
            std::mem::take(&mut g.class_idx),
            g.class_names
                .iter()
                .map(|n| crate::report::format::pretty_class_name(n))
                .collect(),
            crate::query::run::ReplCacheEdges::default(),
        )
    });

    Ok((report, retained, oql_cache))
}

/// Decide whether `input` should run the analyze pipeline. True when the path
/// has a `.hprof` / `.hprof.gz` extension OR the file begins with the HPROF
/// magic (`JAVA PROFILE`). `-` (stdin) is never HPROF: a non-seekable pipe of a
/// dump was never supported, and the render path handles `-`.
fn input_is_hprof(input: &str) -> bool {
    if input == "-" {
        return false;
    }
    let lower = input.to_ascii_lowercase();
    if lower.ends_with(".hprof")
        || lower.ends_with(".hprof.gz")
        || lower.ends_with(".hprof.zip")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tgz")
    {
        return true;
    }
    looks_like_hprof(input)
}

/// Turn an `analyze` pipeline error into an actionable message. A missing input
/// file is the most common mistake, so name the path explicitly — but only when
/// the error is a bare `NotFound` from opening the input. Output-write failures
/// already carry a `cannot write '…'` message (see `run`), so leave those alone.
/// A file routed here on its `.hprof` extension but lacking the HPROF magic is
/// almost certainly a saved report JSON misnamed as a dump — say so.
fn analyze_error_hint(input: &str, e: &io::Error) -> String {
    let msg = e.to_string();
    if e.kind() == io::ErrorKind::NotFound && !msg.starts_with("cannot ") {
        return format!("cannot open '{input}': no such file or directory");
    }
    // A genuine dump (HPROF magic present) that hits EOF mid-record is almost
    // always a truncated or partially-copied file. Replace the raw internal
    // reader message with a user-actionable one.
    if e.kind() == io::ErrorKind::UnexpectedEof && looks_like_hprof(input) {
        return format!(
            "'{input}' appears truncated or corrupt — hit end of file mid-record; \
             re-copy the .hprof dump and retry"
        );
    }
    // A file with a .hprof extension that lacks the HPROF magic is almost certainly
    // a saved report JSON misnamed as a dump. Suppress the raw IO error string and
    // give a clean actionable message instead.
    if input != "-" && std::fs::metadata(input).is_ok() && !looks_like_hprof(input) {
        return format!(
            "'{input}' does not start with the HPROF magic; \
             if it is a saved report JSON, rename it without the .hprof \
             extension to re-render it"
        );
    }
    msg
}

/// Turn a `render` error into an actionable message. The most common mistake is
/// feeding the re-render path a *rendered* report (HTML/Markdown) instead of the
/// canonical `.json` it was rendered from; serde then fails with a bare
/// "invalid report JSON" that gives no clue what the file actually is. Sniff the
/// first non-whitespace bytes and name the likely format so the fix is obvious.
fn render_error_hint(input: &str, e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::NotFound {
        return format!("cannot open '{input}': no such file or directory");
    }
    let msg = e.to_string();
    if msg.starts_with("invalid report JSON") && input != "-" {
        match sniff_report_kind(input) {
            Some("html") => {
                return format!(
                    "{msg}\n(hint: '{input}' looks like a rendered HTML report; \
                     re-render from the saved report JSON (.json/.json.gz), not \
                     the .html)"
                );
            }
            Some("markdown") => {
                return format!(
                    "{msg}\n(hint: '{input}' looks like a rendered Markdown report; \
                     re-render from the saved report JSON (.json/.json.gz))"
                );
            }
            _ => {
                return format!(
                    "{msg}\n(hint: expected a saved report JSON (.json/.json.gz); \
                     analyze a .hprof dump to produce one)"
                );
            }
        }
    }
    msg
}

/// Peek at the first non-whitespace bytes of `path` (transparently gunzipping a
/// gzip-magic prefix) to guess whether a non-JSON re-render input is a rendered
/// HTML report (`<`), a Markdown report (`#`/`|`), or unknown. Best-effort: any
/// read error yields `None`, and the caller falls back to a generic hint.
fn sniff_report_kind(path: &str) -> Option<&'static str> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut head = [0u8; 512];
    let n = f.read(&mut head).ok()?;
    let head = &head[..n];
    // Transparently sniff through a gzip prefix so `.md.gz` / `.html.gz` are
    // classified too (matches how render_report gunzips its input).
    let decoded;
    let bytes: &[u8] = if head.starts_with(&[0x1f, 0x8b]) {
        let mut d = flate2::read::GzDecoder::new(head);
        let mut buf = Vec::new();
        // A short read is fine; we only need the leading bytes.
        let _ = d.read_to_end(&mut buf);
        if buf.is_empty() {
            return None;
        }
        decoded = buf;
        &decoded
    } else {
        head
    };
    let s = String::from_utf8_lossy(bytes);
    let t = s.trim_start();
    let lower = t.to_ascii_lowercase();
    if t.starts_with('<') || lower.contains("<!doctype") || lower.contains("<html") {
        return Some("html");
    }
    if t.starts_with('#') || t.starts_with('|') {
        return Some("markdown");
    }
    None
}

/// True when the file at `path` begins with the HPROF magic (`JAVA PROFILE`).
fn looks_like_hprof(path: &str) -> bool {
    use std::io::Read;
    if path == "-" {
        return false;
    }
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 12];
    matches!(f.read_exact(&mut head), Ok(())) && head.starts_with(b"JAVA PROFILE")
}

/// Returns true when a file could plausibly be a truncated (or tiny) HPROF dump,
/// .hprof.gz, or .hprof.tar.gz — i.e. `UnexpectedEof` is a truncation symptom
/// rather than a format error.  Excludes files whose first bytes clearly
/// identify them as a different format (e.g. JSON `{`).
fn could_be_truncated_hprof(path: &str) -> bool {
    use std::io::Read;
    if path == "-" {
        return false;
    }
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 4];
    let n = f.read(&mut head).unwrap_or(0);
    if n == 0 {
        // Zero-byte file — could be an empty truncated dump.
        return true;
    }
    let h = &head[..n];
    // Clearly non-HPROF formats: JSON, HTML, XML, plain text
    if matches!(h[0], b'{' | b'[' | b'<' | b'"') {
        return false;
    }
    // gzip magic or HPROF "JAVA" prefix → plausibly truncated
    true
}

/// Read current process RSS from /proc/self/status (Linux only).
/// Returns 0 on any error or non-Linux platform.
fn rss_mb() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    let kb: u64 = rest
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    return kb as f64 / 1024.0;
                }
            }
        }
    }
    0.0
}

// ── Dominator checkpoint helpers (HPROF_CKPT_SAVE / dev dom-ckpt) ──────────

fn write_u32s(p: &std::path::Path, v: &[u32]) -> std::io::Result<()> {
    let mut b = Vec::with_capacity(v.len() * 4);
    for &x in v {
        b.extend_from_slice(&x.to_le_bytes());
    }
    std::fs::write(p, b)
}

fn write_u8s(p: &std::path::Path, v: &[u8]) -> std::io::Result<()> {
    std::fs::write(p, v)
}

fn write_u64s(p: &std::path::Path, v: &[u64]) -> std::io::Result<()> {
    let mut b = Vec::with_capacity(v.len() * 8);
    for &x in v {
        b.extend_from_slice(&x.to_le_bytes());
    }
    std::fs::write(p, b)
}

fn read_u32s(p: &std::path::Path) -> std::io::Result<Vec<u32>> {
    let b = std::fs::read(p)?;
    Ok(b.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

fn read_u64s(p: &std::path::Path) -> std::io::Result<Vec<u64>> {
    let b = std::fs::read(p)?;
    Ok(b.chunks_exact(8)
        .map(|c| u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]))
        .collect())
}

/// Re-run only the dominator stage from a checkpoint written by `HPROF_CKPT_SAVE`.
fn run_dom_ckpt(dir: &str) -> std::io::Result<()> {
    let d = std::path::Path::new(dir);
    let n: usize = std::fs::read_to_string(d.join("meta.txt"))?
        .trim()
        .parse()
        .map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("meta.txt: {e}"))
        })?;
    let t = std::time::Instant::now();
    let parent_pre = read_u32s(&d.join("parent_pre.bin"))?;
    let dfn = read_u32s(&d.join("dfn.bin"))?;
    let vertex = read_u32s(&d.join("vertex.bin"))?;
    let roots = read_u32s(&d.join("roots.bin"))?;
    let inb_block_off = read_u64s(&d.join("inb_block_off.bin"))?;
    let inb_data = std::fs::read(d.join("inb_data.bin"))?;
    eprintln!(
        "[ckpt] loaded n={} count={} roots={} inb_block_off={} inb_data={}B in {:.1}s",
        n,
        parent_pre.len(),
        roots.len(),
        inb_block_off.len(),
        inb_data.len(),
        t.elapsed().as_secs_f64()
    );
    let rpo = crate::rpo_dfs::RpoResult {
        parent_pre,
        dfn,
        vertex,
    };
    let t = std::time::Instant::now();
    let idom = crate::dominator::compute_dominators(n, rpo, &roots, &inb_block_off, &inb_data)?;
    let vroot = n as u32;
    let nv = idom.iter().filter(|&&x| x == vroot).count();
    eprintln!(
        "[ckpt] dominator done in {:.1}s  idom_len={} idom==vroot={} ({:.2}%)",
        t.elapsed().as_secs_f64(),
        idom.len(),
        nv,
        nv as f64 * 100.0 / n as f64
    );
    Ok(())
}

/// Decode one vbyte value at `pos`; returns (value, next_pos).
fn decode_vbyte(buf: &[u8], mut pos: usize) -> Option<(u32, usize)> {
    let mut v: u32 = 0;
    let mut shift = 0;
    loop {
        let b = *buf.get(pos)?;
        pos += 1;
        v |= ((b & 0x7f) as u32) << shift;
        if b & 0x80 == 0 {
            return Some((v, pos));
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }
}

/// Cross-check the stages of an `HPROF_CKPT_SAVE` directory. Each check
/// localises a different stage of the inbound-CSR construction:
///   (A) 2a degree counts      vs the forward CSR's true in-degrees
///   (B) prefix-summed cursors vs the 2a degree counts
///   (C) encoded inbound lists vs the 2a degree counts (+ kind of empty nodes)
fn run_ckpt_diff(dir: &str) -> std::io::Result<()> {
    let d = std::path::Path::new(dir);
    let n: usize = std::fs::read_to_string(d.join("meta.txt"))?
        .trim()
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;
    let t = std::time::Instant::now();
    let in_degree = read_u32s(&d.join("d_in_degree.bin"))?;
    let in_cursors = read_u32s(&d.join("d_in_cursors.bin"))?;
    let fwd_tgt = read_u32s(&d.join("d_fwd_targets.bin"))?;
    let kind = std::fs::read(d.join("d_kind.bin"))?;
    let vertex = read_u32s(&d.join("vertex.bin"))?;
    let inb_data = std::fs::read(d.join("inb_data.bin"))?;
    eprintln!(
        "[diff] loaded n={} total_edges={} count={} inb_data={}B in {:.1}s",
        n,
        fwd_tgt.len(),
        vertex.len(),
        inb_data.len(),
        t.elapsed().as_secs_f64()
    );

    // (A) true in-degree from the forward CSR (the ground truth edge set)
    let mut t0 = std::time::Instant::now();
    let mut true_indeg = vec![0u32; n + 1];
    for &tg in &fwd_tgt {
        let i = tg as usize;
        if i < true_indeg.len() {
            true_indeg[i] = true_indeg[i].wrapping_add(1);
        }
    }
    let mut a_bad = 0u64;
    let mut a_true = 0u64;
    let mut a_2a = 0u64;
    for i in 0..n {
        let tv = true_indeg[i] as u64;
        let dv = *in_degree.get(i).unwrap_or(&0) as u64;
        a_true += tv;
        a_2a += dv;
        if tv != dv {
            a_bad += 1;
        }
    }
    eprintln!(
        "[diff] (A) 2a counts vs fwd truth: mismatched_nodes={} ({:.4}%)  truth_sum={} 2a_sum={} in {:.1}s",
        a_bad,
        a_bad as f64 * 100.0 / n as f64,
        a_true,
        a_2a,
        t0.elapsed().as_secs_f64()
    );
    drop(true_indeg);

    // (B) The cursors ARE the prefix sum of the POST-synthetic-edge counts, so
    // their consecutive differences recover those counts. Comparing them with
    // the pre-synthetic 2a counts isolates exactly the synthetic edges.
    t0 = std::time::Instant::now();
    let mut b_bad = 0u64;
    let mut b_extra = 0u64;
    for i in 0..n.saturating_sub(1) {
        let c0 = *in_cursors.get(i).unwrap_or(&0) as u64;
        let c1 = *in_cursors.get(i + 1).unwrap_or(&0) as u64;
        let post = c1.saturating_sub(c0);
        let pre = *in_degree.get(i).unwrap_or(&0) as u64;
        if post != pre {
            b_bad += 1;
            b_extra += post.saturating_sub(pre);
        }
    }
    eprintln!(
        "[diff] (B) cursor-diff vs 2a counts: differing_nodes={} ({:.4}%)  extra_edges={}  (expect = synthetic thread->local edges) in {:.1}s",
        b_bad,
        b_bad as f64 * 100.0 / n as f64,
        b_extra,
        t0.elapsed().as_secs_f64()
    );

    // (C) Only REACHABLE nodes carry a meaningful list — the dominator runs on
    // the reachable subgraph, and the encoder leaves unreachable nodes empty.
    // The expected count is therefore the number of in-edges whose SOURCE is
    // reachable, not the raw 2a in-degree.
    t0 = std::time::Instant::now();
    let fwd_off = read_u32s(&d.join("d_fwd_offsets.bin"))?;
    let mut reach = vec![false; n + 1];
    for &node in &vertex {
        let v = node as usize;
        if v < n {
            reach[v] = true;
        }
    }
    let mut reach_indeg = vec![0u32; n + 1];
    for src in 0..n {
        if !reach[src] {
            continue;
        }
        let lo = *fwd_off.get(src).unwrap_or(&0) as usize;
        let hi = *fwd_off.get(src + 1).unwrap_or(&0) as usize;
        if let Some(sl) = fwd_tgt.get(lo..hi) {
            for &tg in sl {
                let tv = tg as usize;
                if tv < reach_indeg.len() {
                    reach_indeg[tv] = reach_indeg[tv].wrapping_add(1);
                }
            }
        }
    }
    let count = vertex.len();
    eprintln!(
        "[diff] (C) reachable={} ; reachable-restricted in-degrees in {:.1}s",
        count,
        t0.elapsed().as_secs_f64()
    );

    t0 = std::time::Instant::now();
    let mut pos = 0usize;
    let mut c_bad = 0u64;
    let mut c_total = 0u64;
    let mut c_empty_reach = 0u64;
    let mut first_bad: u64 = u64::MAX;
    let mut empty_kind = [0u64; 4];
    let mut decoded_nodes = 0u64;
    for i in 0..n {
        let (cnt, np) = match decode_vbyte(&inb_data, pos) {
            Some(x) => x,
            None => break,
        };
        pos = np;
        decoded_nodes += 1;
        c_total += cnt as u64;
        if reach[i] {
            if cnt as u64 != reach_indeg[i] as u64 {
                c_bad += 1;
                if (i as u64) < first_bad {
                    first_bad = i as u64;
                }
            }
            if cnt == 0 {
                c_empty_reach += 1;
                let k = *kind.get(i).unwrap_or(&0) as usize;
                if k < 4 {
                    empty_kind[k] += 1;
                }
            }
        }
        for _ in 0..cnt {
            match decode_vbyte(&inb_data, pos) {
                Some((_, np)) => pos = np,
                None => break,
            }
        }
    }
    eprintln!(
        "[diff] (C) encoded count vs reachable-restricted truth: mismatched_reachable={} ({:.4}% of {} reachable)  first_bad_node={}  decoded={} encoded_total={} in {:.1}s",
        c_bad,
        c_bad as f64 * 100.0 / count.max(1) as f64,
        count,
        if first_bad == u64::MAX { 0 } else { first_bad },
        decoded_nodes,
        c_total,
        t0.elapsed().as_secs_f64()
    );
    eprintln!(
        "[diff] (C) EMPTY lists among reachable={} ({:.4}%)  by-kind[0=inst 1=objarr 2=primarr 3=class]={:?}",
        c_empty_reach,
        c_empty_reach as f64 * 100.0 / count.max(1) as f64,
        empty_kind
    );

    // (C2) The encoder translates to pre-order, then SORTS and DEDUPS each
    // node's predecessor list, so the correct expectation is the number of
    // DISTINCT reachable sources pointing at the node — not its raw in-degree.
    // Reproduce that with a counting-sort transpose plus per-slice dedup.
    t0 = std::time::Instant::now();
    let mut exp_off: Vec<u32> = vec![0u32; n + 2];
    let mut acc = 0u64;
    for i in 0..n {
        exp_off[i] = acc as u32;
        acc += reach_indeg[i] as u64;
    }
    exp_off[n] = acc as u32;
    let total = acc as usize;
    let mut exp_src: Vec<u32> = vec![0u32; total];
    let mut cur: Vec<u32> = exp_off.clone();
    for src in 0..n {
        if !reach[src] {
            continue;
        }
        let lo = *fwd_off.get(src).unwrap_or(&0) as usize;
        let hi = *fwd_off.get(src + 1).unwrap_or(&0) as usize;
        if let Some(sl) = fwd_tgt.get(lo..hi) {
            for &tg in sl {
                let tv = tg as usize;
                if tv < n {
                    let p = cur[tv] as usize;
                    if p < exp_src.len() {
                        exp_src[p] = src as u32;
                        cur[tv] += 1;
                    }
                }
            }
        }
    }
    let mut dedup = vec![0u32; n + 1];
    for i in 0..n {
        let a = exp_off[i] as usize;
        let b = cur[i] as usize;
        if b > a {
            let s = &mut exp_src[a..b];
            s.sort_unstable();
            let mut c = 0u32;
            let mut last: Option<u32> = None;
            for &x in s.iter() {
                if Some(x) != last {
                    c += 1;
                    last = Some(x);
                }
            }
            dedup[i] = c;
        }
    }
    eprintln!(
        "[diff] (C2) deduped-distinct-source expectation built in {:.1}s ({} entries)",
        t0.elapsed().as_secs_f64(),
        total
    );
    let mut pos2 = 0usize;
    let mut c2_bad = 0u64;
    let mut c2_first_bad: u64 = u64::MAX;
    let mut c2_sum_enc = 0u64;
    let mut c2_sum_exp = 0u64;
    for i in 0..n {
        let (cnt, np) = match decode_vbyte(&inb_data, pos2) {
            Some(x) => x,
            None => break,
        };
        pos2 = np;
        if reach[i] {
            c2_sum_enc += cnt as u64;
            c2_sum_exp += dedup[i] as u64;
            if cnt != dedup[i] {
                c2_bad += 1;
                if (i as u64) < c2_first_bad {
                    c2_first_bad = i as u64;
                }
            }
        }
        for _ in 0..cnt {
            match decode_vbyte(&inb_data, pos2) {
                Some((_, np)) => pos2 = np,
                None => break,
            }
        }
    }
    eprintln!(
        "[diff] (C2) encoded vs deduped-distinct expectation: mismatched_reachable={} ({:.4}%)  first_bad_node={}  encoded_sum={} expected_sum={}  [residual = excluded weak/finalizer edges]",
        c2_bad,
        c2_bad as f64 * 100.0 / count.max(1) as f64,
        if c2_first_bad == u64::MAX {
            0
        } else {
            c2_first_bad
        },
        c2_sum_enc,
        c2_sum_exp
    );

    Ok(())
}

/// Compare two checkpoints' encoded inbound CSRs node by node. Run the same
/// dump through both inbound paths (default = fwd transpose, and
/// `HPROF_FORCE_RESCAN_INBOUND=1` = rescan) and the difference set is exactly
/// what the rescan path loses.
fn run_ckpt_cmp(a: &str, b: &str) -> std::io::Result<()> {
    let (da, db) = (std::path::Path::new(a), std::path::Path::new(b));
    let n: usize = std::fs::read_to_string(da.join("meta.txt"))?
        .trim()
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;
    let inb_a = std::fs::read(da.join("inb_data.bin"))?;
    let inb_b = std::fs::read(db.join("inb_data.bin"))?;
    let vertex = read_u32s(&da.join("vertex.bin"))?;
    let kind = std::fs::read(da.join("d_kind.bin"))?;
    let mut reach = vec![false; n + 1];
    for &v in &vertex {
        let i = v as usize;
        if i < n {
            reach[i] = true;
        }
    }
    let mut pa = 0usize;
    let mut pb = 0usize;
    let mut diff_nodes = 0u64;
    let mut first_diff: u64 = u64::MAX;
    let mut last_diff: u64 = 0;
    let mut sum_a = 0u64;
    let mut sum_b = 0u64;
    let mut miss_kind = [0u64; 4];
    let mut prev_kinds = [0u64; 4];
    let mut samples = 0u32;
    let mut ea: Vec<u32> = Vec::new();
    let mut eb: Vec<u32> = Vec::new();
    for i in 0..n {
        let (ca, npa) = decode_vbyte(&inb_a, pa).unwrap_or((0, pa));
        pa = npa;
        let (cb, npb) = decode_vbyte(&inb_b, pb).unwrap_or((0, pb));
        pb = npb;
        ea.clear();
        let mut prev = 0u32;
        for _ in 0..ca {
            let (d, np) = decode_vbyte(&inb_a, pa).unwrap_or((0, pa));
            pa = np;
            prev = prev.wrapping_add(d);
            ea.push(prev);
        }
        eb.clear();
        prev = 0;
        for _ in 0..cb {
            let (d, np) = decode_vbyte(&inb_b, pb).unwrap_or((0, pb));
            pb = np;
            prev = prev.wrapping_add(d);
            eb.push(prev);
        }
        sum_a += ca as u64;
        sum_b += cb as u64;
        if reach[i] && ca != cb {
            diff_nodes += 1;
            if (i as u64) < first_diff {
                first_diff = i as u64;
            }
            last_diff = i as u64;
            // Kind census over every edge of the differing nodes, on both sides.
            for &p in &ea {
                let src = *vertex.get(p as usize).unwrap_or(&0) as usize;
                let k = *kind.get(src).unwrap_or(&0) as usize;
                prev_kinds[k.min(3)] += 1;
            }
            for &p in &ea {
                if !eb.contains(&p) {
                    let src = *vertex.get(p as usize).unwrap_or(&0) as usize;
                    let k = *kind.get(src).unwrap_or(&0) as usize;
                    if k < 4 {
                        miss_kind[k] += 1;
                    }
                }
            }
            if samples < 5 {
                println!(
                    "[cmp] node {} kind={} A_count={} B_count={} A_pre={:?} B_pre={:?}",
                    i,
                    *kind.get(i).unwrap_or(&0),
                    ca,
                    cb,
                    ea,
                    eb
                );
                samples += 1;
            }
        }
    }
    eprintln!(
        "[cmp] nodes_with_diff={} ({:.4}% of {} reached)  first_diff_node={} last_diff_node={}",
        diff_nodes,
        diff_nodes as f64 * 100.0 / vertex.len().max(1) as f64,
        vertex.len(),
        if first_diff == u64::MAX {
            0
        } else {
            first_diff
        },
        last_diff
    );
    eprintln!(
        "[cmp] encoded edges: A(transpose)={}  B(rescan)={}  missing={}",
        sum_a,
        sum_b,
        sum_a.saturating_sub(sum_b)
    );
    eprintln!(
        "[cmp] sources of ALL present edges (kind) = {:?}",
        prev_kinds
    );
    eprintln!(
        "[cmp] sources of MISSING edges  (kind) = {:?}   [0=inst 1=objarr 2=primarr 3=class]",
        miss_kind
    );
    Ok(())
}

/// Rebuild the inbound CSR of a checkpoint from its SAVED forward CSR — the
/// transpose path, i.e. exactly what `build_from_fwd` produces — so the
/// dominator can be re-run on the real dump without re-reading it. The previous
/// `inb_data.bin` is preserved as `inb_data.orig.bin`.
fn run_ckpt_rebuild(dir: &str) -> std::io::Result<()> {
    let d = std::path::Path::new(dir);
    let n: usize = std::fs::read_to_string(d.join("meta.txt"))?
        .trim()
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;
    let t = std::time::Instant::now();
    let fwd_off = read_u32s(&d.join("d_fwd_offsets.bin"))?;
    let fwd_tgt = read_u32s(&d.join("d_fwd_targets.bin"))?;
    let mut cursors = read_u32s(&d.join("d_in_cursors.bin"))?;
    let vertex = read_u32s(&d.join("vertex.bin"))?;
    let n_nodes = fwd_off.len().saturating_sub(1);
    let total_inb = *fwd_off.get(n_nodes).unwrap_or(&0) as u64;
    eprintln!(
        "[rebuild] loaded in {:.1}s: n={} nodes={} total_inb={}",
        t.elapsed().as_secs_f64(),
        n,
        n_nodes,
        total_inb
    );

    // dfn = inverse(vertex)
    let mut dfn = vec![u32::MAX; n + 1];
    for (pre, &node) in vertex.iter().enumerate() {
        if (node as usize) < n {
            dfn[node as usize] = pre as u32;
        }
    }

    let mut inb_flat = crate::chunkvec::ChunkU32::zeroed(total_inb as usize);
    let t = std::time::Instant::now();
    for src in 0..n_nodes {
        let lo = *fwd_off.get(src).unwrap_or(&0) as usize;
        let hi = *fwd_off.get(src + 1).unwrap_or(&0) as usize;
        if let Some(sl) = fwd_tgt.get(lo..hi) {
            for &dst in sl {
                let dv = dst as usize;
                if dv < cursors.len() {
                    inb_flat.set(cursors[dv] as usize, src as u32);
                    cursors[dv] += 1;
                }
            }
        }
    }
    eprintln!(
        "[rebuild] transpose done in {:.1}s",
        t.elapsed().as_secs_f64()
    );
    drop(fwd_tgt);
    drop(fwd_off);

    let t = std::time::Instant::now();
    let (block_off, data) =
        crate::pass2::InboundBuilder::encode_phase4(n, total_inb, cursors, inb_flat, &dfn)?;
    eprintln!(
        "[rebuild] encode done in {:.1}s: {} block offsets, {} bytes",
        t.elapsed().as_secs_f64(),
        block_off.len(),
        data.len()
    );

    let orig = d.join("inb_data.bin");
    if orig.exists() {
        let _ = std::fs::rename(&orig, d.join("inb_data.orig.bin"));
    }
    std::fs::write(&orig, &data)?;
    write_u64s(&d.join("inb_block_off.bin"), &block_off)?;
    eprintln!(
        "[rebuild] wrote {} (previous kept as inb_data.orig.bin)",
        orig.display()
    );
    Ok(())
}

/// Log a phase name, elapsed seconds, and (Linux) RSS when `verbose`.
fn log(verbose: bool, phase: &str, elapsed: f64) {
    if verbose {
        let rss = rss_mb();
        if rss > 0.0 {
            eprintln!("{phase}: {elapsed:.2}s  RSS={rss:.0} MB");
        } else {
            eprintln!("{phase}: {elapsed:.2}s");
        }
    }
}

/// Re-render a previously saved canonical Report JSON to the given format.
/// The input may be gzip-compressed (`.json.gz`): decompression is transparent,
/// detected by the gzip magic bytes so it works for files and stdin alike.
fn render_report(path: &str, format: OutputFormat) -> io::Result<String> {
    use std::io::Read;
    let raw = if path == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        std::fs::read(path)?
    };
    // gzip magic (0x1f 0x8b): decompress transparently, matching how the
    // analyzer already reads `.hprof.gz` dumps.
    let json = if raw.starts_with(&[0x1f, 0x8b]) {
        let mut d = flate2::read::GzDecoder::new(&raw[..]);
        let mut s = String::new();
        d.read_to_string(&mut s)?;
        s
    } else {
        String::from_utf8(raw).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("input not UTF-8: {e}"))
        })?
    };
    let report: report::Report = serde_json::from_str(&json).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid report JSON: {e}"),
        )
    })?;
    if report.schema_version > report::SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "report schema_version {} is newer than supported version {}; refusing to render",
                report.schema_version,
                report::SCHEMA_VERSION
            ),
        ));
    }
    Ok(match format {
        OutputFormat::Md => report::render_markdown(&report),
        OutputFormat::MdGraphs => report::render_markdown_graphs(&report),
        OutputFormat::Json => serde_json::to_string_pretty(&report).map_err(io::Error::other)?,
        OutputFormat::Html => html::render_html(&report),
    })
}

/// A collected query: its OQL text (with any `-- @viz` directive already
/// stripped), the parsed [`VizSpec`] if one was declared, an optional warning
/// when the directive was malformed (surfaced later as a result note), and an
/// optional display name (config `[[query]]` entries may name themselves).
struct CollectedQuery {
    text: String,
    viz: Option<query::viz::VizSpec>,
    warning: Option<String>,
    name: Option<String>,
}

/// Collect the OQL queries for a run: inline `--query` flags first, then each
/// non-empty, non-comment (`#`) line of `--query-file`, then any `[[query]]`
/// entries from the config file. A leading `-- @viz` line in a query file
/// attaches to the FOLLOWING query line (queries in files are one-per-line, so
/// the directive is its own physical line). Inline `--query` args and config
/// `oql` strings may embed the directive on their own `\n`-separated line. The
/// directive is stripped from the text before parsing; a malformed one is
/// recorded as a warning and the query still runs as a plain table.
/// A missing or unreadable query file is a hard error naming the path.
fn collect_query_texts(opts: &AnalyzeOptions) -> io::Result<Vec<CollectedQuery>> {
    let mut collected: Vec<CollectedQuery> = opts
        .queries
        .iter()
        .map(|q| {
            let (text, viz, warning) = query::viz::split_directive(q);
            CollectedQuery {
                text,
                viz,
                warning,
                name: None,
            }
        })
        .collect();
    if let Some(ref qf) = opts.query_file {
        let body = std::fs::read_to_string(qf).map_err(|e| {
            io::Error::new(e.kind(), format!("cannot read --query-file '{qf}': {e}"))
        })?;
        // A pending `-- @viz` directive line waits for the next query line.
        let mut pending_directive: Option<String> = None;
        let mut line_num = 0usize;
        for line in body.lines() {
            line_num += 1;
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            // A `-- @viz ...` line prefixes the next query; hold it.
            if is_viz_directive_line(t) {
                pending_directive = Some(t.to_string());
                continue;
            }
            let full = match pending_directive.take() {
                Some(dir) => format!("{dir}\n{t}"),
                None => t.to_string(),
            };
            let (text, viz, warning) = query::viz::split_directive(&full);
            // Validate parse eagerly so we can attach the line number.
            if let Err(e) = query::parse::parse(&text) {
                let semi_hint = if e.0.contains(';') || text.contains(';') {
                    " (each line is one query; semicolons are not supported — put each query on its own line)"
                } else {
                    ""
                };
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "--query-file '{qf}': parse error on line {line_num}: {}{semi_hint}",
                        e.0
                    ),
                ));
            }
            collected.push(CollectedQuery {
                text,
                viz,
                warning,
                name: None,
            });
        }
    }
    // Config `[[query]]` entries run after CLI-supplied queries, keeping their
    // declared names for display.
    for cq in crate::collection_config::load_config_queries(opts.collection_config.as_deref()) {
        let (text, viz, warning) = query::viz::split_directive(&cq.oql);
        collected.push(CollectedQuery {
            text,
            viz,
            warning,
            name: cq.name,
        });
    }
    Ok(collected)
}

/// True if a trimmed line is a `-- @viz ...` directive (case-insensitive on the
/// `@viz` keyword). Mirrors the recognizer in `query::viz::split_directive` so a
/// directive on its own query-file line is attached to the following query
/// rather than being fed to the OQL parser as a stray comment.
fn is_viz_directive_line(t: &str) -> bool {
    t.strip_prefix("--")
        .map(str::trim_start)
        .and_then(|r| r.split_whitespace().next())
        .is_some_and(|w| w.eq_ignore_ascii_case("@viz"))
}

/// Parse and plan each OQL text, failing fast with an actionable message that
/// names the offending query text and includes the parser/planner detail.
fn parse_plan_queries(
    query_texts: &[String],
    depth_cap: usize,
) -> io::Result<Vec<(query::ast::Query, query::plan::QueryPlan)>> {
    let mut parsed_queries: Vec<(query::ast::Query, query::plan::QueryPlan)> =
        Vec::with_capacity(query_texts.len());
    for text in query_texts {
        let q = query::parse::parse_or_report(text).map_err(|report| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("OQL parse error in `{text}`:\n{report}"),
            )
        })?;
        let plan = query::plan::plan_query(&q, depth_cap).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("OQL plan error in `{text}`: {}", e.0),
            )
        })?;
        let plan = query::optimize::optimize(plan, &q, &query::optimize::SchemaStats::default());
        parsed_queries.push((q, plan));
    }
    Ok(parsed_queries)
}

/// Fill in each result's display metadata: the OQL text from the source query
/// (the executor leaves `oql` blank) and a default `q{N}` name when unnamed.
/// Relies on `query_results` already being restored to the caller's input
/// order (pass2 sorts it), so the positional zip against `query_texts` and the
/// 1-based `q{N}` labels line up with the queries the user supplied.
///
/// An unnamed block derives a descriptive default from its FROM target (e.g.
/// `java.lang.String`, `INSTANCEOF java.lang.Thread`, `object 0x10`) via
/// [`query::viz::default_view_name`]; subquery/UNION sources have no single
/// class, so those fall back to the positional `q{N}` label. Derived (and
/// already-set) names are de-duplicated so two identical FROM targets render as
/// `java.lang.String` and `java.lang.String (2)`. Explicit config-/directive
/// names still win: they are applied later in [`attach_viz`].
fn finalize_query_labels(
    results: &mut [query::model::QueryResult],
    query_texts: &[String],
    queries: &[(query::ast::Query, query::plan::QueryPlan)],
) {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    for (i, (r, text)) in results.iter_mut().zip(query_texts.iter()).enumerate() {
        if r.oql.is_empty() {
            r.oql = text.clone();
        }
        if r.name.is_empty() {
            let base = queries
                .get(i)
                .map(|(q, _)| q)
                .and_then(query::viz::default_view_name)
                .unwrap_or_else(|| format!("q{}", i + 1));
            let mut name = base.clone();
            let mut n = 2;
            while seen.contains(&name) {
                name = format!("{base} ({n})");
                n += 1;
            }
            r.name = name.clone();
            seen.insert(name);
        } else {
            // An already-set name still participates in de-dup.
            seen.insert(r.name.clone());
        }
    }
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            curr[j] = if a[i - 1] == b[j - 1] {
                prev[j - 1]
            } else {
                1 + prev[j - 1].min(prev[j]).min(curr[j - 1])
            };
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// True when a FROM target is a *plain* class name — a bare dotted identifier,
/// not `INSTANCEOF`, not a double-quoted regex, not a `pkg.*` glob, and not an
/// array (`[]`) target. Only for such a FROM does "zero rows" unambiguously
/// mean "no such class" (a glob/regex/instanceof can legitimately match nothing
/// without any single named class being absent).
#[allow(dead_code)]
fn is_plain_class_from(q: &query::ast::Query) -> Option<&str> {
    let spec = q.from.class_spec()?;
    if spec.instanceof || spec.is_regex {
        return None;
    }
    let name = spec.class_name.as_str();
    if name.contains('*') || name.ends_with("[]") || name.is_empty() {
        return None;
    }
    Some(name)
}

/// Same as `is_plain_class_from` but also matches `FROM INSTANCEOF <class>`,
/// so absent-class annotation works for INSTANCEOF queries too.
fn is_named_class_from(q: &query::ast::Query) -> Option<&str> {
    let spec = q.from.class_spec()?;
    if spec.is_regex {
        return None;
    }
    let name = spec.class_name.as_str();
    if name.contains('*') || name.ends_with("[]") || name.is_empty() {
        return None;
    }
    Some(name)
}

/// Annotate each zero-row result whose query selects `FROM <plain class name>`
/// with a note when that class is absent from the dump, so a typo'd or wrong
/// class name is not silently reported as an empty-but-valid result. The dump's
/// class-name set is resolved lazily (one cheap pass1) and ONLY when at least
/// one result is a zero-row plain-class candidate, so the common (non-empty or
/// non-plain) case pays nothing. Skips UNION-collapsed runs, where result and
/// query indices no longer align one-to-one.
fn annotate_missing_classes(
    input: &str,
    results: &mut [query::model::QueryResult],
    queries: &[(query::ast::Query, query::plan::QueryPlan)],
) {
    // Index alignment (results[i] <-> queries[i]) only holds without UNION
    // collapse, which is exactly when the counts match.
    if results.len() != queries.len() {
        return;
    }
    let has_candidate = results.iter().zip(queries.iter()).any(|(r, (q, _))| {
        r.error.is_none() && r.row_count == 0 && is_named_class_from(q).is_some()
    });
    if !has_candidate {
        return;
    }
    // Resolve the dump's dotted class-name set once (slash-form normalized to
    // dots, matching how FROM names are written and how LiveResolver maps them).
    let Ok(p1) = Pass1::run(&crate::source::HprofSource::from(input), false) else {
        return;
    };
    let names: std::collections::HashSet<String> = p1
        .class_map
        .values()
        .filter_map(|ci| p1.strings.get(&ci.name_id).map(|s| s.replace('/', ".")))
        .collect();
    for (r, (q, _)) in results.iter_mut().zip(queries.iter()) {
        if r.error.is_some() || r.row_count != 0 {
            continue;
        }
        if let Some(name) = is_named_class_from(q) {
            if !names.contains(name) {
                let simple = name.rsplit('.').next().unwrap_or(name);
                let lower = name.to_ascii_lowercase();
                let simple_lower = simple.to_ascii_lowercase();
                // Match by: simple name equality (case-insensitive), or
                // the query name is a substring of a real name, or vice-versa,
                // or the real simple name starts with the query simple name prefix (≥4 chars),
                // or edit distance ≤ 2 on the simple name (catches typos like Stirng→String).
                // Exclude JVM array descriptors (names starting with '[') from suggestions.
                let prefix_len = simple_lower.len().min(6);
                let dist_threshold = if simple_lower.len() <= 4 { 1 } else { 2 };
                let mut candidates: Vec<&str> = names
                    .iter()
                    .filter(|n| {
                        if n.starts_with('[') {
                            return false;
                        }
                        let nl = n.to_ascii_lowercase();
                        let sn = n
                            .rsplit('.')
                            .next()
                            .unwrap_or(n.as_str())
                            .to_ascii_lowercase();
                        sn == simple_lower
                            || nl.contains(&lower)
                            || (prefix_len >= 4 && sn.starts_with(&simple_lower[..prefix_len]))
                            || edit_distance(&sn, &simple_lower) <= dist_threshold
                    })
                    .map(|n| n.as_str())
                    .collect();
                candidates.sort_unstable();
                candidates.dedup();
                candidates.truncate(4);
                let hint = if candidates.is_empty() {
                    format!(
                        "no class named `{name}` in this dump \
                         (check the fully-qualified name, or use a `pkg.*` glob)"
                    )
                } else {
                    format!(
                        "no class named `{name}` in this dump — did you mean: {}?",
                        candidates.join(", ")
                    )
                };
                append_note(r, &hint);
            }
        }
    }
}

/// Attach each collected query's [`VizSpec`] to its result, and fold any
/// directive warning into the result `note`. A well-formed directive whose
/// columns cannot be resolved against the actual result (unknown/non-numeric
/// column, too few columns) is downgraded to a plain table with an explanatory
/// note — charts never hard-fail a query. Results and `collected` are in the
/// same order (executor output is restored to input order before this runs).
fn attach_viz(results: &mut [query::model::QueryResult], collected: &[CollectedQuery]) {
    for (r, c) in results.iter_mut().zip(collected.iter()) {
        // A config-supplied name overrides the positional `q{N}` label.
        if let Some(name) = &c.name {
            if !name.is_empty() {
                r.name = name.clone();
            }
        }
        // A `-- @viz name="..."` directive overrides the label too (inline with
        // the query text, so it wins over the positional/config name).
        if let Some(spec) = &c.viz {
            if let Some(name) = &spec.name {
                if !name.is_empty() {
                    r.name = name.clone();
                }
            }
        }
        // A malformed directive recorded at collection time becomes a note.
        if let Some(w) = &c.warning {
            append_note(r, w);
        }
        // An errored query keeps no chart; the error already explains it.
        if r.error.is_some() {
            continue;
        }
        let Some(spec) = &c.viz else { continue };
        match query::viz::resolve_columns(spec, &r.columns, &r.rows) {
            Ok(_) => r.viz = Some(spec.clone()),
            Err(reason) => append_note(r, &reason),
        }
    }
}

/// Append `msg` to a result's `note`, preserving any existing note.
fn append_note(r: &mut query::model::QueryResult, msg: &str) {
    match &mut r.note {
        Some(existing) => {
            existing.push_str("; ");
            existing.push_str(msg);
        }
        None => r.note = Some(msg.to_string()),
    }
}

/// Format a single query cell for plain-text table output.
fn fmt_query_value(v: &query::model::QueryValue) -> String {
    use query::model::QueryValue::*;
    match v {
        Null => "null".to_string(),
        Bool(b) => b.to_string(),
        Int(i) => i.to_string(),
        Float(f) => f.to_string(),
        Str(s) => s.clone(),
        ObjRef { index, class, addr } => {
            if let Some(a) = addr {
                format!("{class}@0x{a:x}")
            } else {
                format!("{class}@{index}")
            }
        }
    }
}

/// The `query` subcommand: run pass1+pass2 with the parsed queries and print
/// each result as a simple aligned text table (`json_out = false`) or as a
/// JSON array of QueryResult objects (`json_out = true`). Never writes a file.
fn run_queries(input: &str, opts: AnalyzeOptions, json_out: bool) -> io::Result<()> {
    let collected = collect_query_texts(&opts)?;
    if collected.is_empty() {
        // No `--query`, no `--query-file`, and no config `[[query]]` entries: the
        // run would parse the dump and print nothing (exit 0), which reads as a
        // silent success. Fail with an actionable message naming every OQL source.
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no query given. Supply OQL with `--query \"SELECT ...\"` (repeatable), \
             `--query-file <PATH>` (one per line), a `[[query]]` entry in \
             `.hprof-analyzer.toml`, `--repl` (interactive shell), or `--server` \
             (HTTP endpoint). See `hprof-analyzer query --help`.",
        ));
    }
    let query_texts: Vec<String> = collected.iter().map(|c| c.text.clone()).collect();
    let parsed = parse_plan_queries(&query_texts, opts.query_path_depth)?;
    let (flat, union_groups) = query::run::expand_union_queries(&parsed);

    // Subqueries need a two-phase (inner-then-outer) scan; `run_single_dump`
    // implements that. When any query uses a FROM- or IN-subquery, route through
    // it so the `query` subcommand fully supports subqueries. The inline path
    // below stays for the common no-subquery case (one scan, no re-parse).
    let uses_subqueries = parsed.iter().any(|(_, p)| {
        p.from_subplan.is_some() || !p.in_subplans.is_empty() || !p.exists_subplans.is_empty()
    });

    // Cross-phase queries (retained sizes, dominators, N-hop RefPath, edges,
    // gc-roots) cannot be answered by the query-only fast path — it never builds
    // the dominator tree / retained sizes / edge structures. When any query needs
    // one of those, AUTO-ESCALATE to the full analysis pipeline (`run_oql_escalated`)
    // which builds them and produces real rows, instead of the old "requires the
    // full analysis pipeline" error. RefWalk-only queries also set `ref_walk` and
    // will escalate here; that is harmless (the full pipeline resolves them too).
    let needs_full = parsed.iter().any(|(_, p)| {
        !p.late_ops.is_empty()
            || p.needs.retained
            || p.needs.dominator_children
            || p.needs.ref_walk
            || p.needs.gc_roots
    });

    let mut query_results = if uses_subqueries {
        query::run::run_single_dump(input, &parsed, opts.reachable_only)?
    } else if needs_full {
        run_oql_escalated(input, &flat, &union_groups, opts.reachable_only, &opts)?
    } else {
        let source_q = crate::source::HprofSource::from(input);
        let p1 = pass1::Pass1::run(&source_q, false)?;
        if p1.class_ids.len() > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "dump has {} objects, exceeding the {} (u32::MAX) limit of the \
                     analyzer's index scheme; cannot analyze",
                    p1.class_ids.len(),
                    u32::MAX
                ),
            ));
        }
        let needs_sv = flat.iter().any(|(_, p)| p.needs.string_values);
        let addr_vec = if needs_sv {
            query::run::id_map_to_addrs(&p1.id_map)
        } else {
            Vec::new()
        };
        let mut no_in_sets = std::collections::HashMap::new();
        let mut no_exists_bools = std::collections::HashMap::new();
        let (
            g,
            _inbound,
            _fwd_off_c,
            _fwd_tgt_c,
            _in_c,
            query_state,
            refwalk_csr,
            string_values,
            _sv_trunc,
        ) = pass2::Pass2::build(
            &source_q,
            p1,
            cvec::Codec::Deflate9,
            &opts,
            &flat,
            &mut no_in_sets,
            &mut no_exists_bools,
        )?;

        // Query-only path: retained sizes/dominators are not computed, so cross-phase
        // (@retainedHeapSize) queries resolve to actionable errors here.
        // toString(s) queries (finalize_at=P2) use the decoded string_values map.
        // RefPath (`x.field.tail`) queries use the RefWalk CSR captured in the scan.
        // Reachable-only (the query-subcommand default): the scan armed a per-row
        // source-index sidecar; compute GC-reachability now (one rpo_dfs over the
        // forward CSR pass2 already built) and prune each flat result by its
        // captured source index INSIDE resume, before UNION-collapse, so a
        // projected `@objectAddress` (a raw heap address) prunes by the EXACT
        // source dense index rather than a lossy re-read. Skipped under --all.
        let rpo = opts.reachable_only.then(|| {
            crate::rpo_dfs::rpo_dfs(
                g.n,
                &g.gc_root_indices,
                &g.fwd_offsets,
                crate::chunkvec::TgtView::Chunked(&g.fwd_targets),
            )
        });
        let flat_results = query::run::resume_with_string_values(
            query_state,
            &flat,
            string_values,
            refwalk_csr,
            rpo.as_ref().map(|r| r.dfn.as_slice()),
            &addr_vec,
            None,
            None,
        );

        query::run::collapse_union_results(flat_results, &union_groups)
    };

    // Fill in blank oql text and default names (from-target-derived, else
    // `q{N}`) for the printed tables.
    finalize_query_labels(&mut query_results, &query_texts, &parsed);
    annotate_missing_classes(input, &mut query_results, &parsed);
    attach_viz(&mut query_results, &collected);

    if json_out {
        // JSON output: emit a JSON array of QueryResult objects to stdout.
        // Errors are represented inline via the `error` field; always exit 0
        // so the caller can parse the JSON regardless.
        match serde_json::to_string_pretty(&query_results) {
            Ok(j) => println!("{j}"),
            Err(e) => {
                return Err(io::Error::other(format!(
                    "failed to serialize query results as JSON: {e}"
                )));
            }
        }
        return Ok(());
    }

    let mut out = String::new();
    let mut had_error = false;
    for r in query_results.iter() {
        out.push_str(&format!("== {} ==\n", r.name));
        if !r.oql.is_empty() {
            out.push_str(&format!("  {}\n", r.oql));
        }
        if let Some(err) = &r.error {
            had_error = true;
            out.push_str(&format!("error: {err}\n\n"));
            continue;
        }
        let headers: Vec<String> = r.columns.iter().map(|c| c.name.clone()).collect();
        let body: Vec<Vec<String>> = r
            .rows
            .iter()
            .map(|row| row.iter().map(fmt_query_value).collect())
            .collect();
        let ncols = headers.len();
        // Numeric columns (all non-null values are Int or Float) get right-aligned.
        let is_numeric: Vec<bool> = (0..ncols)
            .map(|col| {
                r.rows.iter().all(|row| {
                    matches!(
                        row.get(col),
                        Some(query::model::QueryValue::Int(_))
                            | Some(query::model::QueryValue::Float(_))
                            | Some(query::model::QueryValue::Null)
                            | None
                    )
                }) && r.rows.iter().any(|row| {
                    matches!(
                        row.get(col),
                        Some(query::model::QueryValue::Int(_))
                            | Some(query::model::QueryValue::Float(_))
                    )
                })
            })
            .collect();
        // Compute per-column widths (header width vs max cell width).
        let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
        for row in &body {
            for (i, cell) in row.iter().enumerate() {
                if i < ncols {
                    widths[i] = widths[i].max(cell.chars().count());
                }
            }
        }
        let pad_left = |s: &str, w: usize| -> String {
            let n = s.chars().count();
            if n >= w {
                s.to_string()
            } else {
                format!("{s}{}", " ".repeat(w - n))
            }
        };
        let pad_right = |s: &str, w: usize| -> String {
            let n = s.chars().count();
            if n >= w {
                s.to_string()
            } else {
                format!("{}{s}", " ".repeat(w - n))
            }
        };
        // Header row — left-aligned (even for numeric columns, conventional).
        let hdr_cells: Vec<String> = headers
            .iter()
            .enumerate()
            .map(|(i, h)| {
                if i + 1 < ncols {
                    pad_left(h, widths[i])
                } else {
                    h.clone()
                }
            })
            .collect();
        out.push_str(&hdr_cells.join(" | "));
        out.push('\n');
        // Separator.
        let sep: Vec<String> = widths.iter().map(|&w| "-".repeat(w)).collect();
        out.push_str(&sep.join("-+-"));
        out.push('\n');
        // Data rows — numeric columns right-aligned, others left-aligned.
        for row in &body {
            let cells: Vec<String> = row
                .iter()
                .enumerate()
                .map(|(i, cell)| {
                    if i + 1 < ncols {
                        if i < ncols && is_numeric[i] {
                            pad_right(cell, widths[i])
                        } else {
                            pad_left(cell, widths[i])
                        }
                    } else {
                        cell.clone()
                    }
                })
                .collect();
            out.push_str(&cells.join(" | "));
            out.push('\n');
        }
        let plural = if r.row_count == 1 { "row" } else { "rows" };
        let trunc = if r.truncated { ", truncated" } else { "" };
        out.push_str(&format!("({} {}{})\n", r.row_count, plural, trunc));
        if let Some(note) = &r.note {
            out.push_str(&format!("note: {note}\n"));
        }
        out.push('\n');
    }
    print!("{out}");
    if had_error {
        return Err(io::Error::other(
            "one or more queries returned an error (see output above)",
        ));
    }
    Ok(())
}

/// Produce a minimal empty report with `truncated_input=true` and write it to
/// `output` in the requested `format`.  Used when the file is too small to
/// contain even the HPROF magic / header, so no heap objects can be recovered.
fn emit_truncated_header_report(
    input: &str,
    output: Option<&str>,
    format: OutputFormat,
) -> io::Result<()> {
    use report::{Report, SCHEMA_VERSION, SystemOverview};
    let source_name = std::path::Path::new(input)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(input)
        .to_string();
    let r = Report {
        schema_version: SCHEMA_VERSION,
        generated: report::format::now_iso8601(),
        truncated_input: true,
        overview: SystemOverview {
            file_path: input.to_string(),
            source_name,
            ..Default::default()
        },
        ..Default::default()
    };
    let text = match format {
        OutputFormat::Md => report::render_markdown(&r),
        OutputFormat::MdGraphs => report::render_markdown_graphs(&r),
        OutputFormat::Json => serde_json::to_string_pretty(&r).map_err(io::Error::other)?,
        OutputFormat::Html => html::render_html(&r),
    };
    progress::done();
    write_output(output, &text)
}

/// Run the full `analyze` pipeline end-to-end and write the report.
/// Phase order and the interleaved allocation/free/compress steps are tuned
/// for the peak-RSS budget; the inline comments flag the load-bearing points.
// ── MAT cache reuse ─────────────────────────────────────────────────────────
/// The graph-level state `mat caches` can take from the disk cache instead of
/// re-deriving it.
///
/// `mat caches` used to re-run the entire pipeline — 2h09m on a 44 GB dump —
/// even when a `heap load --with-graph` cache sat next to the dump, because
/// `run()` never looked at `CacheDir`. The cache already holds the forward CSR,
/// the inbound CSR, `idom` and the dominator-children CSR: exactly what the
/// 43-minute pass-2 scan, the 8-minute inbound build and the 17-minute dominator
/// produce. Taking them from disk leaves pass 1 (3.5 min) plus the emit phase.
struct MatCached {
    /// Forward CSR row pointers, `n + 1` entries.
    fwd_off: Vec<u32>,
    /// Forward edge targets, `fwd_off[n]` entries, in the cache's delta+zstd form
    /// already decoded.
    ///
    /// This is the only large array read up front. It is needed by `rpo_dfs` /
    /// `unreachable_retained` (both near the start of the run) *and* verbatim by
    /// the outbound emit near the end, so it cannot be swapped for a chunked copy
    /// or re-read — see `graph_from_mat_cache`.
    fwd_tgt: Vec<u32>,
}

/// Load the graph-level cache entries `mat caches` needs.
///
/// Returns `Ok(None)` — never an error — whenever the cache is absent,
/// incomplete, or does not describe this heap, so the caller falls back to the
/// full pipeline. A missing cache is the normal first-run case, not a failure.
///
/// Only `fwd_off` and `fwd_tgt` come back materialised; the rest of the graph
/// cache is validated here and then re-read at its point of use through the
/// returned [`cache::CacheDir`] (see the body for why).
fn load_mat_cache(
    input: &str,
    p1: &pass1::Pass1,
) -> io::Result<Option<(MatCached, cache::CacheDir)>> {
    // Fine-grained RSS attribution for the from-cache path. `--trace-rss` /
    // `HPROF_TRACE_RSS` already print the coarse `[trace-rss] <stage>` lines; these
    // split the ~28 GB the from-cache window adds into per-array contributions,
    // and the `alloc` lines report each array's size so a run that dies before
    // the end (the from-cache peak does not fit a 32 GiB box) still attributes
    // every array it got through.
    macro_rules! tinfo {
        ($($arg:tt)*) => {
            if crate::trace::enabled() {
                eprintln!("[trace-rss] {}", format!($($arg)*));
            }
        };
    }
    crate::trace::probe("load_mat_cache: enter");
    let cache = cache::CacheDir::for_dump(std::path::Path::new(input))?;
    if !cache.is_valid(cache::CacheMode::Graph) {
        eprintln!("hprof-cache: no usable graph cache next to the dump; running the full pipeline");
        return Ok(None);
    }
    let n = p1.id_map.len();
    // The forward CSR has to be the one pass 2 would have built for THIS heap.
    // The cache key covers the dump's first 64 bytes, its size and its mtime, so
    // a shape mismatch here means a stale cache written by an older build (or a
    // half-written file) — refuse it rather than emit a wrong index.
    let Some(fwd_off) = cache.read_forward_offsets()? else {
        eprintln!("hprof-cache: graph cache has no fwd_off; running the full pipeline");
        return Ok(None);
    };
    tinfo!(
        "load_mat_cache: read fwd_off n={} rows={} = {} MB",
        n,
        fwd_off.len(),
        fwd_off.len() * 4 / (1024 * 1024)
    );
    crate::trace::probe("load_mat_cache: after read_forward_offsets");
    if fwd_off.len() != n + 1 {
        eprintln!(
            "hprof-cache: graph cache covers {} objects but this dump has {n}; \
             running the full pipeline",
            fwd_off.len().saturating_sub(1)
        );
        return Ok(None);
    }
    let total_edges = fwd_off[n] as usize;
    let Some(fwd_tgt) = cache.read_forward_targets(total_edges)? else {
        eprintln!("hprof-cache: graph cache has no usable fwd_tgt; running the full pipeline");
        return Ok(None);
    };
    tinfo!(
        "load_mat_cache: read fwd_tgt flat total_edges={total_edges} = {} MB",
        total_edges * 4 / (1024 * 1024)
    );
    crate::trace::probe("load_mat_cache: after read_forward_targets (fwd_tgt flat resident)");
    // ── Validate the remaining entries, then DROP them ───────────────────────
    // They are re-read at their point of use (see the `mat_reused` branches at
    // the dominator stage, the idom compress and the dominator-children build).
    //
    // They used to be returned and held for the whole run. On the 44 GB dump
    // that is ~12 GB of arrays (inbound body + idom + dominator children) live
    // from here to the end, stacked on top of the 8.9 GB forward targets and a
    // ~15 GB pass-1 baseline — which is why the from-cache path peaked at
    // ~52 GiB and was killed by the OOM killer on a 32 GiB box, *inside this
    // function*, before it ever reached the graph build.
    //
    // The read-and-drop keeps the "unusable cache falls back to the pipeline"
    // contract: the shapes are still checked before the from-cache path is
    // committed to. Re-reading them costs one extra pass over ~12 GB of cache
    // (page-cache resident) and buys ~12 GB of peak.
    let Some((inb_block_off, inb_data)) = cache.read_inbound_blocks()? else {
        eprintln!("hprof-cache: graph cache has no inbound CSR; running the full pipeline");
        return Ok(None);
    };
    tinfo!(
        "load_mat_cache: inb_block_off blocks={} = {} MB, inb_data = {} MB (validated, dropped)",
        inb_block_off.len(),
        inb_block_off.len() * 8 / (1024 * 1024),
        inb_data.len() / (1024 * 1024)
    );
    drop(inb_block_off);
    crate::trace::drop_vec(inb_data);
    crate::trace::probe("load_mat_cache: after read_inbound_blocks (validated, dropped)");
    let Some(idom) = cache.read_idom()? else {
        eprintln!("hprof-cache: graph cache has no idom; running the full pipeline");
        return Ok(None);
    };
    tinfo!(
        "load_mat_cache: idom len={} = {} MB (validated, dropped)",
        idom.len(),
        idom.len() * 4 / (1024 * 1024)
    );
    // `compute_dominators` returns `n + 1` entries: objects 0..n-1 plus the
    // virtual root at index `n` (see `dominator.rs`'s "Indexing convention").
    // Comparing against `n` here made this check false for every cache ever
    // written, so the from-cache path never ran.
    if idom.len() != n + 1 {
        eprintln!(
            "hprof-cache: graph cache has {} idoms for {n} objects (want {}); \
             running the full pipeline",
            idom.len(),
            n + 1
        );
        return Ok(None);
    }
    crate::trace::drop_vec(idom);
    let Some((dc_off, dc_tgt)) = cache.read_dominator_children()? else {
        eprintln!("hprof-cache: graph cache has no dominator children; running the full pipeline");
        return Ok(None);
    };
    tinfo!(
        "load_mat_cache: dc_off rows={} = {} MB, dc_tgt = {} MB (validated, dropped)",
        dc_off.len(),
        dc_off.len() * 4 / (1024 * 1024),
        dc_tgt.len() * 4 / (1024 * 1024)
    );
    // `build_dom_children_csr` emits one row per object plus the virtual root.
    if dc_off.len() != n + 2 || dc_tgt.len() != dc_off[n + 1] as usize {
        eprintln!(
            "hprof-cache: dominator-children CSR has {} rows for {n} objects (want {}); \
             running the full pipeline",
            dc_off.len(),
            n + 2
        );
        return Ok(None);
    }
    drop(dc_off);
    crate::trace::drop_vec(dc_tgt);
    crate::trace::probe("load_mat_cache: exit (fwd_off + fwd_tgt only)");
    Ok(Some((MatCached { fwd_off, fwd_tgt }, cache)))
}

/// Build the `Graph` (plus the cold blobs and empty query state) that the rest
/// of `run()` expects, from the disk cache instead of from pass 2's scans.
///
/// Mirrors what `Pass2::build` returns, minus everything only the heap scan
/// produces: the report-only aggregates (duplicate strings, collections, field
/// stats, alloc frames, thread names, incoming-ref counts) stay empty, and the
/// `InboundBuilder` carries pass 1's id map and nothing else — the inbound CSR
/// is already in the cache and is never built here.
#[allow(clippy::type_complexity)]
fn graph_from_mat_cache(
    source: &crate::source::HprofSource,
    p1: pass1::Pass1,
    c: MatCached,
    opts: &AnalyzeOptions,
) -> io::Result<(
    pass2::Graph,
    pass2::InboundBuilder,
    cvec::CompressedU32,
    cvec::CompressedU32,
    Option<cvec::CompressedU32>,
    query::execute::QueryExecState,
    Option<query::refwalk::RefWalkCsr>,
    std::collections::HashMap<u32, String>,
    bool,
    Vec<u32>,
    Option<crate::id_map::IdMap>,
    // Dense ids of thread objects that are one of their own stack-frame locals.
    // `graph_extras` derives them from pass 1; the pipeline hands them to the
    // emitters through `MatOutboundRescanCtx`, and this path — which never
    // builds that context — has to carry them out by hand.
    Vec<u32>,
)> {
    // The pass-1-derived tables: same code `Pass2::build` runs, so the class
    // histogram, GC roots, thread stacks and synthetic edges cannot drift.
    crate::trace::probe("graph_from_mat_cache: enter (cache arrays resident)");
    let mut ct = pass2::Pass2::class_tables(&p1);
    crate::trace::probe("graph_from_mat_cache: after class_tables");
    let ge = pass2::Pass2::graph_extras(&p1, &ct.class_loader_id, ct.ref_size, opts);
    crate::trace::probe("graph_from_mat_cache: after graph_extras");

    // The same cold codec `Pass2::build` uses for these two arrays.
    #[cfg(feature = "native")]
    let cold = cvec::Codec::Zstd1;
    #[cfg(not(feature = "native"))]
    let cold = cvec::Codec::Deflate1;
    let class_idx_c = cvec::CompressedU32::compress(&ct.class_idx, cold)?;
    let shallow_c = cvec::CompressedU32::compress(&ct.shallow, cold)?;
    let alloc_serial_c = Some(cvec::CompressedU32::compress(&p1.alloc_stack_serial, cold)?);
    // Mirror `Pass2::build`: once the compressed blobs exist the dense arrays are
    // dead weight, and keeping them here held a second, uncompressed copy of both
    // (~2 x n x 4 B, ~5.6 GB on the 44 GB dump) across the whole rpo/dominator
    // window. Everything downstream restores from `shallow_c`/`class_idx_c` when
    // it needs them (see the restore before `compute_retained`), which is exactly
    // what the pipeline path does — there `g.shallow`/`g.class_idx` are empty.
    if cold != cvec::Codec::None {
        crate::trace::drop_vec(std::mem::take(&mut ct.shallow));
        crate::trace::drop_vec(std::mem::take(&mut ct.class_idx));
    }
    crate::trace::probe("graph_from_mat_cache: after compress class_idx/shallow (dense dropped)");

    let n = p1.id_map.len();
    let source_name = source.display_name().to_string();
    let file_path = source.file_path().to_string();
    let pass1::Pass1 {
        format,
        file_size,
        header_timestamp_ms,
        id_size,
        alloc_stack_serial: _,
        id_map,
        ..
    } = p1;
    let inbound = pass2::InboundBuilder::empty(source.clone(), id_size, n);
    // `rpo_dfs` and `unreachable_retained` take the CSR through a `TgtView`,
    // which reads either representation, so the flat targets the cache handed us
    // are passed straight through — no chunked copy is built.
    //
    // MEMORY: the copy used to be built here (a full second array, 9.3 GB on the
    // 44 GB dump) and both copies stayed live through the rpo/unreachable window,
    // because the flat one cannot be dropped — the outbound emit needs it
    // verbatim. That duplicate was the single largest avoidable allocation on the
    // from-cache path. The pipeline builds only the chunked form here and
    // materialises its flat copy much later, after `rpo_dfs` /
    // `unreachable_retained` have released the chunked one; handing the readers a
    // flat slice gives the from-cache path the same one-array property.
    let fwd_tgt_flat = c.fwd_tgt;
    crate::trace::probe("graph_from_mat_cache: flat fwd_tgt kept (no chunked duplicate built)");
    let g = pass2::Graph::from_cached(pass2::CachedGraphParts {
        n,
        format,
        file_size,
        source_name,
        file_path,
        id_size,
        ref_size: ct.ref_size as u8,
        header_timestamp_ms,
        gc_root_indices: ge.gc_root_indices,
        gc_root_types: ge.gc_root_types,
        shallow: ct.shallow,
        class_idx: ct.class_idx,
        class_names: ct.class_names,
        class_loader_id: ct.class_loader_id,
        loader_labels: ge.loader_labels,
        thread_stacks: ge.thread_stacks,
        thread_local_counts: ge.thread_local_counts,
        thread_local_samples: ge.thread_local_samples,
        thread_local_frame_samples: ge.thread_local_frame_samples,
        class_obj_class_idx: ct.class_obj_class_idx,
        jlc_idx: ct.jlc_idx,
        fwd_offsets: c.fwd_off,
        // Empty: this path's targets stay flat (see above), and the two readers
        // that would have wanted the chunked form take the flat slice instead.
        fwd_targets: crate::chunkvec::ChunkU32::default(),
        synthetic_root_count: ge.synthetic_root_count,
        system_classloader_shallow: ge.system_classloader_shallow,
        idom: Vec::new(),
        alloc_stack_serial: Vec::new(),
    });
    crate::trace::probe("graph_from_mat_cache: after Graph::from_cached (before return)");
    Ok((
        g,
        inbound,
        shallow_c,
        class_idx_c,
        alloc_serial_c,
        query::execute::QueryExecState::new(),
        None,
        std::collections::HashMap::new(),
        false,
        fwd_tgt_flat,
        Some(id_map),
        ge.synthetic_self_edges,
    ))
}

fn run(
    input: &str,
    output: Option<&str>,
    format: OutputFormat,
    verbose: bool,
    compress: cvec::Codec,
    opts: AnalyzeOptions,
    mat: Option<mat::MatEmitter>,
) -> io::Result<()> {
    let t_total = Instant::now();
    // Wall-clock markers for the post-2b "dark phase" (build_dom_children_csr,
    // compute_retained, build_model, render). The pass2 t_phase! markers reset at
    // Pass2::build start, so "2b scan done" is pass2-relative; these are relative
    // to run() start (~wall). Gated on HPROF_TIMING like the pass2 markers.
    macro_rules! t_dark {
        ($label:expr) => {
            if std::env::var_os("HPROF_TIMING").is_some() {
                eprintln!(
                    "[timing] {}: {:.3}s",
                    $label,
                    t_total.elapsed().as_secs_f64()
                );
            }
        };
    }

    let t = Instant::now();
    progress::phase("scanning dump (pass 1)");
    let source = crate::source::HprofSource::from(input);
    let mut p1 = match pass1::Pass1::run(&source, mat.is_some()) {
        Ok(p1) => p1,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && could_be_truncated_hprof(input) => {
            // File ended before or during the HPROF header — too truncated to
            // parse any objects. Emit a minimal report with truncated_input=true
            // so callers see exit 0 + a valid report with the warning rather than
            // a hard error.
            return emit_truncated_header_report(input, output, format);
        }
        Err(e) => return Err(e),
    };
    let truncated_input = p1.truncated_input;
    let redacted = p1.redacted;
    log(verbose, "pass1", t.elapsed().as_secs_f64());
    // ── Checkpoint (HPROF_CKPT_SAVE): the object directory built by pass1 —
    // per-object class index / kind / array element count. Offline this answers
    // "what kind of object is each node whose inbound list is broken".
    if let Some(dir) = std::env::var_os("HPROF_CKPT_SAVE") {
        let d = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&d)?;
        write_u32s(&d.join("d_class_ids.bin"), &p1.class_ids)?;
        write_u8s(&d.join("d_kind.bin"), &p1.kind)?;
        write_u32s(&d.join("d_elem_count.bin"), &p1.elem_count)?;
        eprintln!("[ckpt] saved pass1 object directory to {}", d.display());
    }

    // The entire analysis works in u32 pre-order / node-index space (dfn,
    // vertex, forward/inbound CSR, idom). A dump with more than u32::MAX
    // objects would silently overflow every index, so refuse it up front with
    // a clear message rather than emit corrupt results.
    if p1.class_ids.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "dump has {} objects, exceeding the {} (u32::MAX) limit of the \
                 analyzer's index scheme; cannot analyze",
                p1.class_ids.len(),
                u32::MAX
            ),
        ));
    }

    // A valid HPROF header with zero objects means the file was truncated before
    // the heap dump segment. Warn on stderr but continue — the report will be
    // empty, which is still more useful than a hard failure.
    if p1.class_ids.is_empty() {
        eprintln!(
            "warning: '{input}' contains no heap objects — \
             the file may be truncated before the heap dump segment"
        );
    }

    // fast (before the expensive graph build) with a message naming the query.
    let collected = collect_query_texts(&opts)?;
    let query_texts: Vec<String> = collected.iter().map(|c| c.text.clone()).collect();
    let parsed_queries = parse_plan_queries(&query_texts, opts.query_path_depth)?;
    // Subqueries require a two-phase (inner-then-outer) scan of the dump. The
    // full-report pipeline scans once and immediately builds the graph +
    // dominators atop that scan, so it cannot run the inner pass here without an
    // invasive restructure. Per the task's accepted fallback, subqueries are
    // supported only via the `query` subcommand (`run_single_dump`), which
    // re-scans; surface an actionable error rather than silently wrong rows.
    if parsed_queries
        .iter()
        .any(|(_, p)| p.from_subplan.is_some() || !p.in_subplans.is_empty())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "subqueries (FROM (...) / IN (...)) are only supported via the `query` \
             subcommand, which re-scans the dump; they are not available in the \
             full report. Run the query with `hprof-analyzer query <dump> -e '<oql>'`.",
        ));
    }
    // MEMORY-CRITICAL: decide edge retention BEFORE pass2 so a run with no
    // edge-using query (@inbounds / @outbounds / path()) stays byte-for-byte and
    // RSS-identical to today — every new branch below is gated on `run_flags`.
    //
    // `plan_run` needs a `ClassIndexResolver` only to fill `retain_rows` (dense
    // class bits). The dense class universe is built INSIDE pass2 and is not
    // available yet, so here we pass a trivial resolver: this yields the correct
    // BOOLEAN flags (which are computed purely by query inspection). Row-level
    // filtering (L1) is done AFTER pass2 by matching each source row's class name
    // against the edge queries' FROM patterns, so `retain_rows` is not consulted.
    let run_flags = {
        let queries: Vec<query::ast::Query> =
            parsed_queries.iter().map(|(q, _)| q.clone()).collect();
        query::runflags::plan_run(&queries, &NoClassIndex, opts.query_path_depth).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("OQL edge planning error: {}", e.0),
            )
        })?
    };

    let (flat_queries, union_groups) = query::run::expand_union_queries(&parsed_queries);

    let t = Instant::now();
    progress::phase("building object graph (pass 2)");
    // Capture MAT class metadata from p1 before it is consumed by Pass2::build.
    let mut mat_class_meta: Option<mat::MatClassMeta> = if mat.is_some() {
        Some(mat::MatClassMeta::from_pass1(&p1, input))
    } else {
        None
    };
    // Capture hprof file offsets for o2hprof emission. Store as raw LE bytes
    // (CompressedBytes) to avoid a 2x peak during restoration — iterating as
    // u64 chunks avoids the bytes→Vec<u64> copy at emit time.
    let mat_hprof_offsets_c: Option<cvec::CompressedBytes> = if mat.is_some() {
        let bytes: Vec<u8> = {
            let v = &p1.hprof_offsets;
            let mut b = Vec::with_capacity(v.len() * 8);
            for &off in v {
                b.extend_from_slice(&off.to_le_bytes());
            }
            b
        };
        Some(cvec::CompressedBytes::compress(bytes, compress)?)
    } else {
        None
    };
    // `p1.hprof_offsets` (~4.9 GB on the 44 GB dump) has been folded into
    // `mat_hprof_offsets_c` above and is not read again on the MAT path (pass 2
    // and `graph_from_mat_cache` both drop it through their `..` destructuring).
    // Freeing it now instead of at that destructuring takes it out of the
    // from-cache path's load window, which is where the peak is set.
    if mat.is_some() {
        crate::trace::drop_vec(std::mem::take(&mut p1.hprof_offsets));
    }
    // ── MAT from-cache fast path ─────────────────────────────────────────
    // `mat caches` used to re-run the whole pipeline even when a
    // `heap load --with-graph` cache sat next to the dump. Try the cache first;
    // `load_mat_cache` returns None (never an error) when there is nothing
    // usable, and the full pipeline below then runs exactly as before.
    // `HPROF_MAT_NO_CACHE=1` forces that fallback, which is what the A/B parity
    // check compares against.
    // The from-cache path is NOT verified, so it is opt-in.
    //
    // It used to be dead: `load_mat_cache` compared `idom.len()` (always `n + 1`)
    // against `n`, so it returned `None` for every cache ever written and the
    // full pipeline ran instead. With that check fixed the path finally engages —
    // and it then emits `dump.index`, `dump.inbound.index` and
    // `dump.outbound.index` that differ from the full pipeline's (outbound comes
    // out 205 KB short on the 4-philosophers fixture). The commit that added it
    // claimed the two paths were byte-identical, but both of its A/B runs took
    // the pipeline branch, so that comparison was vacuous.
    //
    // Until the three emitters are shown identical, a wrong index is worse than a
    // slow one: keep the default on the pipeline and require `HPROF_MAT_USE_CACHE=1`
    // to exercise the cached path.
    let (mut mat_cached, mat_cache_dir): (Option<MatCached>, Option<cache::CacheDir>) = if mat
        .is_some()
        && std::env::var_os("HPROF_MAT_NO_CACHE").is_none()
        && std::env::var_os("HPROF_MAT_USE_CACHE").is_some()
    {
        match load_mat_cache(input, &p1) {
            Ok(Some((c, dir))) => (Some(c), Some(dir)),
            Ok(None) => (None, None),
            Err(e) => {
                eprintln!("hprof-cache: {e}; running the full pipeline");
                (None, None)
            }
        }
    } else {
        (None, None)
    };
    // Sticky for the rest of the function: `mat_cached` is moved into the graph
    // builder below, but every later guard still needs to know which path ran.
    let mat_reused = mat_cached.is_some();
    // The deferred cache reads (inbound body, idom, dominator children) go
    // through `mat_cache_dir` at their point of use.
    if mat_reused {
        eprintln!(
            "mat caches: reusing the graph cache next to the dump \
             (HPROF_MAT_USE_CACHE=1 opted in; the .index files are byte-identical \
             to the pipeline's, but the --report markdown omits the sections pass \
             2's heap scan produces)"
        );
    }
    let mut no_in_sets = std::collections::HashMap::new();
    let mut no_exists_bools = std::collections::HashMap::new();
    let (
        mut g,
        mut inbound,
        shallow_c,
        class_idx_c,
        alloc_serial_c,
        mut query_state,
        refwalk_csr,
        string_values,
        string_values_truncated,
        // Forward-edge targets, flat. Populated only on the from-cache path,
        // which already has them decoded; the pipeline path allocates and
        // scatter-fills its own copy at the outbound emit.
        mut mat_cached_fwd_tgt,
        // Pass 1's dense address table. On the from-cache path the id map never
        // goes into the `InboundBuilder` (there is no inbound scan to feed), so
        // it is handed over on its own; the pipeline path leaves this `None` and
        // `run()` reads the same table out of `inbound.id_map`.
        mat_cached_id_map,
        // Synthetic `thread → itself` edges, derived from pass 1 by
        // `graph_extras`. Empty on the pipeline path, which reads them off
        // `MatOutboundRescanCtx` instead.
        mat_cached_self_edges,
    ) = if let Some(c) = mat_cached.take() {
        graph_from_mat_cache(&source, p1, c, &opts)?
    } else {
        let r = pass2::Pass2::build(
            &source,
            p1,
            compress,
            &opts,
            &flat_queries,
            &mut no_in_sets,
            &mut no_exists_bools,
        )?;
        (
            r.0,
            r.1,
            r.2,
            r.3,
            r.4,
            r.5,
            r.6,
            r.7,
            r.8,
            Vec::new(),
            None,
            Vec::new(),
        )
    };
    log(
        verbose,
        &format!("pass2 n={}", g.n),
        t.elapsed().as_secs_f64(),
    );
    t_dark!("pass2 done");

    // Take the per-slot source-index sidecar out of the query state now, before it
    // is consumed by `resume` far below. It is populated only when the scan armed
    // reachability capture (`opts.reachable_only`); otherwise it is empty and this
    // is a cheap no-op, keeping the DEFAULT analyze run byte/RSS-identical.
    let row_src_by_slot = query_state.take_row_src_by_slot();

    // Compress the three cold arrays (shallow, class_idx, id_map) that sit idle
    // across the rpo -> inbound -> dominator peak window, freeing their dense
    // Vecs and holding only small blobs. Restored just before each consumer.
    let t = Instant::now();
    // Compress id_map FIRST: it is the largest cold array (~4.1GB dense u64)
    // and sits dense atop the ~6GB fwd CSR while shallow/class_idx compress.
    // The compress-cold RSS max is during shallow's compression, so freeing
    // id_map's 4.1GB before that removes it from the binding peak. id_map is
    // delta-vbyte+deflate (sorted addrs, fast), not a slow permutation deflate.
    //
    // MAT: emit the `idx` LongIndex (dense id -> object address) here, while the
    // id_map is still live inside the InboundBuilder (addresses are lost once it
    // is compressed just below). Also precompute the histogram-row ->
    // class-object-id inverse table once; it feeds both o2c and the outbound
    // pseudo class element downstream.
    // MAT id-space remapping: addresses are only available now (before compress).
    // We snapshot all g.n addresses so MatIdMap::build can sort reachable ones by
    // address after idom is known (post compute_dominators). The snapshot is a
    // Vec<u64> of length g.n; compress immediately so it doesn't sit uncompressed
    // through the inbound + dominator peak window (~90 MB for 11M objects).
    let (mat_coc_snapshot, mat_addrs_c): (
        Option<std::collections::HashMap<u32, u32>>,
        Option<cvec::CompressedU64>,
    ) = if mat.is_some() {
        // The from-cache path keeps pass 1's id map on the side; the pipeline
        // path's copy lives in the `InboundBuilder` until `compress_id_map`.
        let id_map = mat_cached_id_map
            .as_ref()
            .or(inbound.id_map.as_ref())
            .expect("id_map must be live before compress_id_map for MAT idx emit");
        let addrs: Vec<u64> = (0..g.n).map(|i| id_map.addr_at(i)).collect();
        crate::trace::probe("main: after MAT addrs Vec<u64> snapshot (8*n bytes)");
        let coc_snap = g.class_obj_class_idx.clone();
        let addrs_c = cvec::CompressedU64::compress(&addrs, compress)?;
        crate::trace::probe("main: after MAT addrs compress + coc_snap clone");
        (Some(coc_snap), Some(addrs_c))
    } else {
        (None, None)
    };
    // From-cache path: the id map is the one `InboundBuilder::id_map_only` took
    // from pass 1, and the addresses are read straight off it at the `idx`
    // snapshot below — there is nothing to compress away and no inbound scan
    // waiting to use it.
    if !mat_reused {
        inbound.compress_id_map(compress)?;
    }
    // shallow/class_idx were already compressed inside pass2 (before the
    // fwd_targets alloc) to keep their ~4GB dense forms off the binding peak;
    // shallow_c/class_idx_c hold the blobs, g.shallow/g.class_idx are empty.
    log(verbose, "compress-cold", t.elapsed().as_secs_f64());
    t_dark!("compress_id_map done");

    crate::trace::probe("main: after compress_id_map (before rpo_dfs)");
    let t = Instant::now();
    progress::phase("ordering objects (reverse post-order)");
    // From-cache path: the flat target array decoded off `graph.bin` IS the
    // forward CSR for these two readers — it is needed verbatim by the outbound
    // emit far below, so it cannot be replaced by a chunked copy. Hand them the
    // flat slice instead of building a second, chunked, copy of the same array.
    let rpo_tgt = if mat_reused {
        crate::chunkvec::TgtView::Flat(&mat_cached_fwd_tgt)
    } else {
        crate::chunkvec::TgtView::Chunked(&g.fwd_targets)
    };
    let rpo = rpo_dfs::rpo_dfs(g.n, &g.gc_root_indices, &g.fwd_offsets, rpo_tgt);
    crate::trace::probe("main: after rpo_dfs (before compress parent_pre)");
    log(verbose, "rpo", t.elapsed().as_secs_f64());
    t_dark!("rpo_dfs done");

    crate::trace::trim();

    // Retained size within the unreachable forest. This is the ONLY point where
    // both the forward CSR (out-edges) and reachability (rpo.dfn) are alive: the
    // forward CSR is moved into the inbound transpose just below. We extract the
    // unreachable subgraph here, run a self-contained dominator + retained pass
    // on it, and keep only a bounded per-class aggregate on `g` for the report
    // phase. shallow/class_idx are streamed out of their compressed blobs (never
    // re-inflated dense), and the node→dense-id map is a binary search over the
    // sorted unreachable-id list (no n-sized array), so this adds no allocation
    // proportional to the whole heap — it is always on.
    {
        let t = Instant::now();
        progress::phase("retained size (unreachable forest)");
        g.unreachable_retained = unreachable_retained::compute_unreachable_retained(
            g.n,
            &rpo.dfn,
            &g.fwd_offsets,
            rpo_tgt,
            &shallow_c,
            &class_idx_c,
            g.class_names.len(),
            &g.class_obj_class_idx,
            &g.class_names,
        )?;
        crate::trace::probe("main: after unreachable_retained (fwd CSR + dfn still alive)");
        log(verbose, "unreachable-retained", t.elapsed().as_secs_f64());
        crate::trace::trim();
    }
    t_dark!("unreachable_retained done");
    // From-cache path: `rpo_dfs` and `unreachable_retained` were the only readers
    // of the forward targets, and they read the flat array (see `rpo_tgt`); the
    // chunked form was never built, so `g.fwd_targets` is already empty here and
    // the emit phase uses the flat copy the cache handed us.

    // Compress parent_pre (~2 GB dense) between RPO and inbound to reduce
    // the peak during the transpose loop. parent_pre is not needed until
    // compute_dominators; holding it compressed saves ~1.5 GB at inb_flat alloc
    // and at the transpose peak. Decompressed just before compute_dominators.
    let mut rpo = rpo;
    let parent_pre_count = rpo.parent_pre.len();
    let parent_pre_c = if compress != cvec::Codec::None {
        #[cfg(feature = "native")]
        let parent_pre_codec = cvec::Codec::Zstd1;
        #[cfg(not(feature = "native"))]
        let parent_pre_codec = cvec::Codec::Deflate1;
        let c = cvec::CompressedU32::compress(&rpo.parent_pre, parent_pre_codec)?;
        crate::trace::drop_vec(std::mem::take(&mut rpo.parent_pre));
        Some(c)
    } else {
        None
    };
    t_dark!("compress_parent_pre done");
    crate::trace::probe("main: after compress parent_pre (before inbound)");

    // Build the inbound CSR by transposing the forward CSR, avoiding a third
    // full-file scan. The fwd CSR and rpo.dfn are both still alive here:
    // dfn is needed for node→pre-order translation in Phase 4 of the encode.
    // After the transpose the fwd CSR and id_map (inside InboundBuilder) are
    // freed; vertex is rebuilt once inb_flat encoding is done so it never
    // coexists with the large inb_flat intermediate.
    let t = Instant::now();
    progress::phase("building inbound references");

    // MEMORY-CRITICAL edge-retention hook. This is the ONLY point where
    // the forward CSR (`g.fwd_offsets`/`g.fwd_targets`) is still alive — it is
    // consumed by `build_from_fwd` just below. When (and ONLY when) an edge query
    // is armed, we build the two bounded, class-filtered edge structures the
    // resume window needs, both from the live forward CSR:
    //
    //   * `retained_edges` (@outbounds / path): a delta+vbyte store keyed by
    //     SOURCE dense index, retaining only rows whose SOURCE object's class
    //     matches an edge query's FROM pattern (L1). Never expands to a flat
    //     Vec<u32> of all edges (L2 — see retained_edges.rs).
    //
    //   * `retained_inbound` (@inbounds): a bounded transpose of the matched-class
    //     forward edges into a plain (in_off,in_tgt) CSR. This is NOT a survival of
    //     the full ~7.5 GB block-encoded inbound CSR (that is freed at its normal
    //     drop below); it is a small index whose target lists are populated only
    //     for nodes whose class matches an @inbounds query's FROM pattern. `in_off`
    //     is full length (n+1) so the executor can index any node safely; only
    //     matched targets carry referrers.
    //
    // Restoring the dense class_idx here costs ~4 GB, so it is guarded INSIDE the
    // `if` — a no-edge run never restores it and the teardown is byte/RSS-identical
    // to today. `CompressedU32::restore(&self)` takes `&self`, so the later restore
    // at the shallow/class_idx window is unaffected.
    let want_forward = run_flags.retain_forward || run_flags.outbounds_by_rescan;
    let want_inbound = run_flags.retain_inbound;
    let (retained_edges, retained_inbound): RetainedEdgeStructs = if want_forward || want_inbound {
        // Collect the FROM (pattern, instanceof) of every query that actually uses
        // an edge feature; class rows are retained only for these (L1).
        let edge_froms: Vec<(String, bool)> = flat_queries
            .iter()
            .filter(|(q, _)| query_uses_edges(q))
            .map(|(q, _)| (q.from.class_name().to_string(), q.from.instanceof()))
            .collect();

        // Dense class index for each node. In the compressed path we restore it
        // locally (~4 GB, freed at block end) since `restore(&self)` is idempotent
        // and the later shallow/class_idx restore is unaffected. In the (rare)
        // no-compress path `g.class_idx` is already dense — borrow it in place so
        // it survives for the later `compute_retained` read.
        let class_idx_restored: Option<Vec<u32>> = if compress != cvec::Codec::None {
            Some(class_idx_c.restore()?)
        } else {
            None
        };
        let class_idx_ref: &[u32] = class_idx_restored
            .as_deref()
            .unwrap_or(g.class_idx.as_slice());
        // A node's class matches when its class name matches any edge query's FROM
        // pattern. `class_name_matches` is glob-aware and separator-normalizing;
        // INSTANCEOF-inclusive matching is not modeled here (bounded superset would
        // require the subclass table), so a plain glob match against the written
        // FROM pattern is used — over-matching only adds retained rows, never drops.
        let node_matches = |s: usize| -> bool {
            let cn = &g.class_names[class_idx_ref[s] as usize];
            edge_froms
                .iter()
                .any(|(pat, _inst)| query::execute::class_name_matches(cn, pat))
        };

        let n = g.n;
        let fwd_off = &g.fwd_offsets;
        let fwd_tgt = &g.fwd_targets;

        // Forward store (@outbounds / path): rows whose SOURCE matches. The
        // forward targets are chunked (`ChunkU32`); `copy_range` gathers one row's
        // out-edges into a scratch Vec (handles chunk-boundary straddles).
        let retained_edges = if want_forward {
            let mut builder = crate::query::retained_edges::RetainedEdgesBuilder::new();
            let mut scratch: Vec<u32> = Vec::new();
            for s in 0..n {
                if !node_matches(s) {
                    continue;
                }
                let (lo, hi) = (fwd_off[s] as usize, fwd_off[s + 1] as usize);
                fwd_tgt.copy_range(lo, hi, &mut scratch);
                scratch.sort_unstable();
                builder.push_row(s as u32, &scratch);
            }
            Some(builder.finish())
        } else {
            None
        };

        // Bounded inbound transpose (@inbounds): for each forward edge s -> t whose
        // TARGET t matches, record s as a referrer of t. Two-pass counting build so
        // in_tgt is sized exactly; in_off is full length (n+1). Each source row's
        // targets are gathered via `copy_range` (chunked store).
        let retained_inbound = if want_inbound {
            let mut in_off = vec![0u32; n + 1];
            let mut row: Vec<u32> = Vec::new();
            // Pass 1: count referrers per matched target.
            for s in 0..n {
                let (lo, hi) = (fwd_off[s] as usize, fwd_off[s + 1] as usize);
                fwd_tgt.copy_range(lo, hi, &mut row);
                for &t in &row {
                    if node_matches(t as usize) {
                        in_off[t as usize + 1] += 1;
                    }
                }
            }
            // Prefix sum -> offsets.
            for i in 0..n {
                in_off[i + 1] += in_off[i];
            }
            let total = in_off[n] as usize;
            let mut in_tgt = vec![0u32; total];
            let mut cursor = in_off.clone();
            // Pass 2: scatter sources into matched targets' slots.
            for s in 0..n {
                let (lo, hi) = (fwd_off[s] as usize, fwd_off[s + 1] as usize);
                fwd_tgt.copy_range(lo, hi, &mut row);
                for &t in &row {
                    if node_matches(t as usize) {
                        let slot = &mut cursor[t as usize];
                        in_tgt[*slot as usize] = s as u32;
                        *slot += 1;
                    }
                }
            }
            Some((in_off, in_tgt))
        } else {
            None
        };

        // Drop the dense class_idx we restored just for filtering (compress path).
        drop(class_idx_restored);
        (retained_edges, retained_inbound)
    } else {
        // No edge query -> zero allocation; forward CSR teardown identical to today.
        (None, None)
    };

    // fwd_offsets and fwd_targets are moved into build_from_fwd so they can be
    // freed INSIDE the call, before Phase 4 allocates inb_data.
    // MAT: snapshot fwd_off (prefix-sum offsets) and class_idx before the
    // inbound scan consumes InboundBuilder. We do NOT snapshot fwd_tgt here —
    // instead we do a post-inbound HPROF rescan to scatter-fill fwd_tgt from
    // scratch using fwd_off as per-object write cursors. This avoids keeping
    // the ~8 GB fwd_targets ChunkU32 alive across the inb_flat allocation and
    // the ~2.5 GB compressed fwd_tgt_c blob from inflating the outbound window.
    let mat_fwd_snap: Option<(cvec::CompressedU32, cvec::CompressedU32)> = if mat.is_some() {
        let class_idx: Vec<u32> = class_idx_c.restore()?;
        let fwd_off_c = cvec::CompressedU32::compress(&g.fwd_offsets, compress)?;
        let class_idx_c2 = cvec::CompressedU32::compress(&class_idx, compress)?;
        drop(class_idx);
        Some((fwd_off_c, class_idx_c2))
    } else {
        None
    };
    // Save the data needed for the later outbound rescan (id_map, class info,
    // field plans) BEFORE InboundBuilder is consumed. class_addr_to_hist and
    // field_plans_dense are moved out (cheap; small data). id_map_c is cloned
    // (~0.5 GB blob). Must be called after compress_id_map.
    //
    // From-cache path: there is no rescan — the forward CSR comes straight from
    // `graph.bin` — so the context is never built (and must not be: the
    // `InboundBuilder` here carries only pass 1's id map).
    let mat_outbound_rescan_ctx: Option<crate::pass2::MatOutboundRescanCtx> =
        if mat.is_some() && !mat_reused {
            Some(inbound.take_for_outbound_rescan())
        } else {
            None
        };

    // Capture the type-reference graph (class-pair edge counts) inline from the
    // live fwd-CSR before it is consumed by inbound construction. This replaces
    // the old approach of iterating all per-object edges in build_type_ref_graph
    // (which required keeping the full 20 GB ObjGraphCapture alive). The inline
    // scan builds only a HashMap of class-pair counts, costing ~200-500 MB peak.
    // NOTE: g.class_idx was compressed inside Pass2 (to cut the binding peak);
    // restore it transiently here for the scan, then drop it again immediately.
    // Fused capture: one O(n×edges) pass covers both type-ref pair counting and
    // inbound-edge accumulation for the top-OBJ_GRAPH_TOP_N captured nodes,
    // replacing two separate O(n×edges) passes.
    const OBJ_GRAPH_TOP_N: usize = 500_000;
    if opts.obj_graph {
        g.class_idx = class_idx_c.restore()?;
        let class_idx_snap = g.class_idx.clone();
        crate::trace::drop_vec(std::mem::take(&mut g.class_idx));
        let (pairs, pair_fields, obj_graph) = crate::pass2::capture_type_ref_and_obj_graph(
            &g,
            &class_idx_snap,
            OBJ_GRAPH_TOP_N,
            opts.report_size.edge_cap(),
        );
        drop(class_idx_snap);
        g.type_ref_pairs = Some(pairs);
        g.type_ref_pair_fields = Some(pair_fields);
        g.obj_graph_edges = Some(obj_graph);
        crate::trace::probe("main: after capture_type_ref_and_obj_graph");
        t_dark!("capture_type_ref_and_obj_graph done");
    }

    // When --field-stats is requested, save the fwd CSR before inbound consumes it.
    // It is restored after retained computation so build_field_stats can use it.
    // Never on the from-cache path: that path has already freed the chunked
    // forward targets (`mat caches` runs at `--detail default`, where field
    // stats are off anyway).
    let field_stats_fwd_main: Option<(Vec<u32>, crate::chunkvec::ChunkU32)> =
        if opts.field_stats && !mat_reused {
            let total_edges = g.fwd_offsets.last().copied().unwrap_or(0) as usize;
            let fwd_off_copy = g.fwd_offsets.clone();
            let mut fwd_tgt_copy = crate::chunkvec::ChunkU32::zeroed(total_edges);
            for i in 0..total_edges {
                fwd_tgt_copy.set(i, g.fwd_targets.get(i));
            }
            Some((fwd_off_copy, fwd_tgt_copy))
        } else {
            None
        };

    // From-cache path: the inbound CSR is already on disk, so neither the
    // transpose nor the HPROF rescan that rebuilds it runs. The forward CSR is
    // no longer needed either — the emit phase reads `fwd_off` back out of
    // `mat_fwd_snap`.
    let (inb_block_off, inb_data) = if mat_reused {
        drop(std::mem::take(&mut g.fwd_offsets));
        t_dark!("fwd CSR dropped (mat from-cache path)");
        // Filled in by the deferred read at the dominator stage below. Holding
        // the ~5.6 GB inbound body from here (or from `load_mat_cache`, as it
        // used to) is what made the from-cache peak exceed a 32 GiB box.
        (Vec::new(), Vec::new())
    } else if mat.is_some() {
        // Drop fwd_targets BEFORE calling build_mat_scan so that inb_flat
        // allocation (6 GB) does not coexist with fwd_targets (8 GB).
        // build_mat_scan rescans the HPROF file to reconstruct inbound without
        // needing fwd_targets. Inbound peak drops from ~25 GB to ~12 GB.
        drop(std::mem::take(&mut g.fwd_targets));
        drop(std::mem::take(&mut g.fwd_offsets)); // no longer needed; InboundBuilder has in_cursors
        t_dark!("fwd_targets dropped (mat path)");
        inbound.build_mat_scan(
            &rpo.dfn,
            |_src, _fwd| Ok(()), // outbound collected later via HPROF rescan
        )?
    } else if inbound.total_inb > 1_000_000_000
        || std::env::var_os("HPROF_FORCE_RESCAN_INBOUND").is_some()
    {
        // Large dump: drop fwd_targets before inb_flat alloc so both ~N×4B
        // arrays never coexist. Costs one extra HPROF rescan but cuts the
        // inbound peak by ~7-10 GB on 30G+ production dumps.
        progress::phase("building inbound references (rescan path)");
        drop(std::mem::take(&mut g.fwd_targets));
        drop(std::mem::take(&mut g.fwd_offsets));
        crate::trace::trim();
        t_dark!("fwd_targets dropped (rescan path)");
        crate::trace::probe("main: fwd dropped (rescan-inbound path, before inb_flat alloc)");
        inbound.build_mat_scan(&rpo.dfn, |_src, _fwd| Ok(()))?
    } else {
        crate::trace::probe("main: before build_from_fwd call");
        inbound.build_from_fwd(
            std::mem::take(&mut g.fwd_offsets),
            std::mem::take(&mut g.fwd_targets),
            &rpo.dfn,
        )?
    };
    log(verbose, "inbound", t.elapsed().as_secs_f64());
    t_dark!("inbound done");

    crate::trace::trim();

    // Rebuild vertex: dfn is still live and the inbound encode has returned,
    // so the ~2 GB vertex never coexists with inb_flat. vertex = invert(dfn)
    // is a pure O(n) pass; the dominator reads it next.
    let count = parent_pre_count;
    rpo.vertex = rpo_dfs::rebuild_vertex(&rpo.dfn, count);
    crate::trace::probe("main: after rebuild_vertex (post-inbound, dfn live)");
    // Snapshot GC-reachability for `--reachable-only` OQL pruning BEFORE dfn is
    // freed (it is emptied on the next line, then `rpo` is moved into the
    // dominator stage). Guarded on the flag so the DEFAULT analyze run pays no
    // clone and stays byte/RSS-identical. `None` = raw-heap (the analyze default).
    let reach_dfn: Option<Vec<u32>> = if opts.reachable_only {
        Some(rpo.dfn.clone())
    } else {
        None
    };
    // Cross-phase (carry) pruning: a carry result's rows are projected from the
    // carried dense indices, so prune the SEEDS here, before `resume` runs the
    // late stage. A post-hoc row filter (below) cannot cover them: the late stage
    // may drop (deferred WHERE), reorder (ORDER BY) or cap (LIMIT) rows, which
    // would break any positional alignment. Row-expanding late ops are left
    // untouched, matching the row-mode rule. `None` under the raw-heap default.
    if let Some(dfn) = &reach_dfn {
        query_state.prune_cross_phase_reachable(dfn);
    }
    // MAT inbound decode needs dfn (dense→pre-order) to build the per-pre-order
    // offset table into inb_data. Save it compressed before clearing; restore
    // just before use so it doesn't inflate the emit_outbound peak (~40 MB win).
    let mat_dfn_save_c: Option<cvec::CompressedU32> = if mat.is_some() {
        let v = std::mem::take(&mut rpo.dfn);
        Some(cvec::CompressedU32::compress(&v, compress)?)
    } else {
        crate::trace::drop_vec(std::mem::take(&mut rpo.dfn));
        None
    };
    crate::trace::trim();

    // Restore parent_pre from compressed blob before the dominator stage.
    if let Some(c) = parent_pre_c {
        rpo.parent_pre = c.restore()?;
        crate::trace::probe("main: after restore parent_pre (before dominator)");
    }

    // rpo is consumed by compute_dominators. We already saved dfn above.
    // Also save vertex (pre→dense) compressed so it doesn't inflate the
    // emit_outbound peak (~40 MB win).
    let mat_vertex_save_c: Option<cvec::CompressedU32> = if mat.is_some() {
        Some(cvec::CompressedU32::compress(&rpo.vertex, compress)?)
    } else {
        None
    };

    let t = Instant::now();
    progress::phase("computing dominators");
    // From-cache path: read the inbound body + block offsets HERE rather than in
    // `load_mat_cache`. Nothing between there and here touched them (the
    // dominator solver is the only consumer of `inb_block_off`, and it is skipped
    // on this path), so holding them across the rpo/inbound windows bought
    // nothing and cost ~5.6 GB of peak.
    let (inb_block_off, inb_data) = if mat_reused {
        let dir = mat_cache_dir
            .as_ref()
            .expect("from-cache path always has a cache dir");
        let (off, data) = dir.read_inbound_blocks()?.ok_or_else(|| {
            io::Error::other(
                "graph cache lost its inbound CSR mid-run; re-run `heap load --with-graph`",
            )
        })?;
        crate::trace::probe("main: (from-cache) read inbound CSR at dominator stage");
        (off, data)
    } else {
        (inb_block_off, inb_data)
    };
    // rpo moved by value; vertex/parent_pre owned through translation. dfn
    // already freed above. No separate drop(rpo).
    // ── Diagnostic (HPROF_DBG_GRAPH=1): graph stats around the dominator run.
    // Behaviour is unchanged when the variable is unset.
    let dbg_graph = std::env::var_os("HPROF_DBG_GRAPH").is_some();
    if dbg_graph {
        eprintln!(
            "[dbg] before dominator: n={} roots={} inb_block_off={} inb_data_bytes={}",
            g.n,
            g.gc_root_indices.len(),
            inb_block_off.len(),
            inb_data.len()
        );
    }
    // ── Checkpoint the dominator's inputs (HPROF_CKPT_SAVE=<dir>) so the
    // dominator stage can be re-run in seconds instead of re-running the whole
    // ~40 min pipeline. Paired with `dev dom-ckpt <dir>`.
    if let Some(dir) = std::env::var_os("HPROF_CKPT_SAVE") {
        let d = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&d)?;
        write_u32s(&d.join("parent_pre.bin"), &rpo.parent_pre)?;
        write_u32s(&d.join("dfn.bin"), &rpo.dfn)?;
        write_u32s(&d.join("vertex.bin"), &rpo.vertex)?;
        write_u32s(&d.join("roots.bin"), &g.gc_root_indices)?;
        write_u64s(&d.join("inb_block_off.bin"), &inb_block_off)?;
        std::fs::write(d.join("inb_data.bin"), &inb_data)?;
        std::fs::write(d.join("meta.txt"), format!("{}", g.n))?;
        eprintln!("[ckpt] saved dominator inputs to {}", d.display());
    }
    // From-cache path: `idom` came off disk, so the dominator solver does not
    // run. `rpo` is still consumed below (its `vertex`/`dfn` feed the inbound
    // emit), so drop it here the same way `compute_dominators` would have.
    if mat_reused {
        drop(rpo);
        // Read the cached dominator tree HERE rather than in `load_mat_cache`:
        // it is first needed by the compress a few lines below, and holding it
        // from the start of the run cost ~2.3 GB of peak.
        let dir = mat_cache_dir
            .as_ref()
            .expect("from-cache path always has a cache dir");
        g.idom = dir.read_idom()?.ok_or_else(|| {
            io::Error::other("graph cache lost its idom mid-run; re-run `heap load --with-graph`")
        })?;
        crate::trace::probe("main: (from-cache) read idom after dominator stage");
    } else {
        g.idom =
            dominator::compute_dominators(g.n, rpo, &g.gc_root_indices, &inb_block_off, &inb_data)?;
    }
    if dbg_graph {
        let n = g.n;
        let vroot = n as u32;
        let mut n_vroot = 0u64;
        let mut n_undef = 0u64;
        for &d in g.idom.iter() {
            if d == vroot {
                n_vroot += 1;
            } else if d == u32::MAX {
                n_undef += 1;
            }
        }
        eprintln!(
            "[dbg] after dominator: idom_len={} idom==vroot={} ({:.2}%) undef={} ({:.2}%)",
            g.idom.len(),
            n_vroot,
            n_vroot as f64 * 100.0 / n as f64,
            n_undef,
            n_undef as f64 * 100.0 / n as f64
        );
    }
    log(verbose, "dominator", t.elapsed().as_secs_f64());
    t_dark!("dominator done");
    crate::trace::probe("main: after dominator");
    // inb_block_off is only needed by compute_dominators; free it now.
    drop(inb_block_off);
    // Compress g.idom (~2 GB for 514M objects) immediately after dominator so it
    // doesn't inflate the MatIdMap::build + idx/o2hprof emission window. We restore
    // it just before MatIdMap::build, drop it again after, then restore once more
    // before domIn emission. This is a single compress/decompress pair per GB saved.
    let mat_idom_c: Option<cvec::CompressedU32> = if mat.is_some() {
        let c = cvec::CompressedU32::compress(&g.idom, compress)?;
        g.idom = Vec::new();
        crate::trace::trim();
        Some(c)
    } else {
        None
    };
    crate::trace::probe("main: after compress idom (before inb_data compress)");
    // inb_data (vbyte-encoded inbound edges, ~87 MB for vscode) is only needed
    // after emit_outbound (for inb_pre_off build + emit_inbound). Compress it
    // across the emit_outbound peak window to free ~80 MB.
    let inb_data_c: cvec::CompressedBytes = if mat.is_some() {
        cvec::CompressedBytes::compress(inb_data, compress)?
    } else {
        cvec::CompressedBytes::compress(inb_data, cvec::Codec::None)?
    };
    crate::trace::trim();
    // MAT id-space remapping: now that idom is set we can build the mapping from
    // our dense-id space to MAT's (reachable-only, address-sorted, id-0=synthetic).
    // Restore mat_addrs_c here (just before use) so it's uncompressed for the
    // minimum possible window. Restore idom for MatIdMap::build, then drop it again.
    //
    // The master `.index` needs three more things that can only be computed while
    // the dense address table is still resident (MAT ids are address-sorted, so
    // every address→id lookup is a binary search over it): the GC-root maps, the
    // class-loader labels, and MAT's recomputed per-instance heap size (whose
    // alignment constant comes from the address spacing). All three are built
    // here and handed to `emit_dot_index`.
    let mut mat_roots: Option<mat::MatRoots> = None;
    let mut mat_instance_sizes: Option<std::collections::HashMap<u64, i32>> = None;
    let mut mat_root_instance_size: i32 = 0;
    // class row -> class-object address, for class objects MAT drops outright
    // (not in the class cache, yet named by the unreachable-objects histogram).
    let mut mat_unreach_class_addr: std::collections::HashMap<u32, u64> =
        std::collections::HashMap::new();
    // row -> "the row's class is java.lang.ClassLoader or a subclass". Built
    // while the address table is live; consumed later, where `class_idx` is
    // live, to find every class-loader instance in the heap.
    let mut mat_row_is_loader: Vec<bool> = Vec::new();
    let mat_map: Option<mat::MatIdMap> = if let Some(addrs_c) = mat_addrs_c {
        // Restore idom only for MatIdMap::build, then drop immediately after.
        if let Some(ref c) = mat_idom_c {
            g.idom = c.restore()?;
        }
        let addrs = addrs_c.restore()?;
        let mm = mat::MatIdMap::build(g.n, &g.idom, |i| addrs[i]);
        // Drop idom immediately after build; mm.sorted holds old-ids in addr order.
        g.idom = Vec::new();
        crate::trace::trim();
        crate::trace::probe("main: after MatIdMap::build + drop(idom)");
        // Resolve the class-object and class-loader addresses that the MAT
        // `.index` ClassImpl objects need (they carry MAT *ids*, not addresses).
        // Both sets are small (~number of classes / loaders), so the lookups are
        // built here while `addrs` is still resident and then dropped with it.
        if let Some(ref mut meta) = mat_class_meta {
            for (&coid, &row) in g.class_obj_class_idx.iter() {
                let a = addrs[coid as usize];
                let mid = mm.translate(coid as i32);
                if mid > 0 {
                    meta.class_addr_to_mat.insert(a, mid);
                    meta.class_mat_to_addr.insert(mid, a);
                } else {
                    // MAT drops this class object entirely, so it never reaches
                    // the class cache — but MAT's unreachable-objects histogram
                    // still names the class, and its record carries the class
                    // object's address. `addrs` is the last place it is known.
                    mat_unreach_class_addr.insert(row, a);
                }
            }
            let mut loaders: Vec<u64> = g
                .class_loader_id
                .iter()
                .copied()
                .filter(|&a| a != 0)
                .collect();
            loaders.sort_unstable();
            loaders.dedup();
            for la in loaders {
                if let Ok(i) = mm
                    .sorted()
                    .binary_search_by_key(&la, |&old| addrs[old as usize])
                {
                    meta.loader_addr_to_mat.insert(la, (i + 1) as i32);
                }
            }
            crate::trace::probe("main: mat class/loader address maps built");

            // ── GC roots / rootsPerThread / loaderLabels (MAT id space) ──────
            // MAT's `HprofParserHandlerImpl.map2ids` drops every root whose
            // address has no object in the heap, and routes a thread-local root
            // (JAVA_FRAME / JNI_LOCAL / NATIVE_STACK / THREAD_BLOCK) into
            // `rootsPerThread` when its thread serial was already known — which
            // is why `numberOfGCRoots` can be smaller than the record count.
            let sorted = mm.sorted();
            let lookup = |a: u64| -> Option<i32> {
                sorted
                    .binary_search_by_key(&a, |&old| addrs[old as usize])
                    .ok()
                    .map(|i| (i + 1) as i32)
            };
            let mut root_map: std::collections::HashMap<i32, Vec<mat::RootRecord>> =
                std::collections::HashMap::new();
            for (i, &a) in meta.gc_root_addrs.iter().enumerate() {
                let tag = meta.gc_root_types.get(i).copied().unwrap_or(0);
                if let Some(mid) = lookup(a) {
                    root_map.entry(mid).or_default().push(mat::RootRecord {
                        object_id: mid,
                        object_address: a,
                        context_id: 0,
                        context_address: 0,
                        ty: mat::mat_root_type(tag),
                    });
                }
            }
            let mut per_thread: std::collections::HashMap<
                i32,
                std::collections::HashMap<i32, Vec<mat::RootRecord>>,
            > = std::collections::HashMap::new();
            for r in &meta.thread_local_roots {
                let ty = mat::mat_root_type(r.tag);
                if r.referrer_addr == 0 {
                    // MAT: addGCRoot(id, 0, type) → the plain roots map.
                    if let Some(mid) = lookup(r.local_addr) {
                        root_map.entry(mid).or_default().push(mat::RootRecord {
                            object_id: mid,
                            object_address: r.local_addr,
                            context_id: 0,
                            context_address: 0,
                            ty,
                        });
                    }
                    continue;
                }
                if let (Some(tmid), Some(lmid)) = (lookup(r.referrer_addr), lookup(r.local_addr)) {
                    per_thread
                        .entry(tmid)
                        .or_default()
                        .entry(lmid)
                        .or_default()
                        .push(mat::RootRecord {
                            object_id: lmid,
                            object_address: r.local_addr,
                            context_id: tmid,
                            context_address: r.referrer_addr,
                            ty,
                        });
                }
            }
            let mut roots_vec: Vec<(i32, Vec<mat::RootRecord>)> = root_map.into_iter().collect();
            roots_vec.sort_by_key(|&(k, _)| k);
            let mut per_thread_vec: Vec<(i32, Vec<mat::RootLocals>)> = per_thread
                .into_iter()
                .map(|(t, locals)| {
                    let mut v: Vec<(i32, Vec<mat::RootRecord>)> = locals.into_iter().collect();
                    v.sort_by_key(|&(k, _)| k);
                    (t, v)
                })
                .collect();
            per_thread_vec.sort_by_key(|&(k, _)| k);

            // loaderLabels: MAT keys this by the class-loader id of every class
            // *plus* the id of every instance of `java.lang.ClassLoader` and its
            // subclasses (SnapshotImpl.calculateLoaderLabels), which is more
            // class loaders than the distinct `class_loader_id` values: a loader
            // that loads no class in this heap still counts. Label resolution
            // needs the loaded class loader object, so the bootstrap loader is
            // the only one MAT names ("<system class loader>"); the rest get the
            // NO_LABEL placeholder when the class-specific-name resolver finds
            // nothing.
            let coc = mat_coc_snapshot.as_ref();
            let mut loader_classes: std::collections::HashSet<u64> =
                std::collections::HashSet::new();
            let mut jlc_addr: Option<u64> = None;
            let mut row_is_loader: Vec<bool> = vec![false; g.class_names.len()];
            if let Some(coc) = coc {
                // address → class name, for the ClassLoader hierarchy walk.
                let mut name_by_addr: std::collections::HashMap<u64, &str> =
                    std::collections::HashMap::new();
                for (&cdense, &row) in coc.iter() {
                    if let Some(n) = g.class_names.get(row as usize) {
                        name_by_addr.insert(addrs[cdense as usize], n.as_str());
                    }
                }
                jlc_addr = name_by_addr
                    .iter()
                    .find(|(_, n)| **n == "java.lang.ClassLoader" || **n == "java/lang/ClassLoader")
                    .map(|(&a, _)| a);
                if let Some(j) = jlc_addr {
                    let mut children: std::collections::HashMap<u64, Vec<u64>> =
                        std::collections::HashMap::new();
                    for (&addr, &(sup, _, _)) in meta.class_info.iter() {
                        children.entry(sup).or_default().push(addr);
                    }
                    let mut stack = vec![j];
                    while let Some(a) = stack.pop() {
                        if loader_classes.insert(a) {
                            if let Some(cs) = children.get(&a) {
                                stack.extend(cs.iter().copied());
                            }
                        }
                    }
                    for (&cdense, &row) in coc.iter() {
                        if loader_classes.contains(&addrs[cdense as usize]) {
                            if let Some(s) = row_is_loader.get_mut(row as usize) {
                                *s = true;
                            }
                        }
                    }
                }
            }
            mat_row_is_loader = row_is_loader;

            // MAT recomputes the per-instance heap size from the declared
            // fields; the 8-byte object alignment it uses comes from the actual
            // address spacing.
            //
            // `ref_size` must be corrected from the HPROF `id_size` to the
            // detected reference width BEFORE `compute_instance_sizes` runs:
            // that function reads `meta.ref_size` for both the per-reference
            // byte count and the intermediate alignment modulus. With a
            // compressed-oops dump (id_size=8, ref_size=4) the stale value
            // inflated every non-array `ClassImpl.instanceSize` (String 32 vs
            // 24), which then contradicted the `a2s`/`o2ret` tables (both built
            // from the native 4-byte shallow) — producing "shallow > retained".
            meta.ref_size = g.ref_size;
            let object_align =
                mat::compute_object_align(mm.sorted().iter().map(|&old| addrs[old as usize]));
            let sizes = mat::compute_instance_sizes(meta, object_align);
            // Object 0 (the synthetic system class loader) is an instance of
            // java.lang.ClassLoader as far as MAT is concerned: `getHeapSize(0)`
            // resolves through o2c[0] to that class's heapSizePerInstance, which
            // is also its retained size (MAT's own o2ret[0]) and the 56-byte
            // excess in `usedHeapSize` over the sum of the real objects.
            mat_root_instance_size = jlc_addr.and_then(|a| sizes.get(&a).copied()).unwrap_or(0);
            mat_instance_sizes = Some(sizes);
            mat_roots = Some(mat::MatRoots {
                roots: roots_vec,
                per_thread: per_thread_vec,
                loader_labels: Vec::new(), // filled in once `class_idx` is live
            });
            crate::trace::probe("main: mat roots/loaderLabels/instanceSizes built");
        }
        // emit idx: mat-id 0 = address 0x0 (synthetic root), then in mat-id order.
        // Stream addresses from addrs[sorted[i]] — no extra Vec<i64> needed.
        if let Some(ref m) = mat {
            m.emit_long_index_iter(
                "idx",
                std::iter::once(0i64).chain(
                    mm.sorted()
                        .iter()
                        .map(|&old_id| addrs[old_id as usize] as i64),
                ),
            )?;
            drop(addrs); // free ~4 GB after idx emission
            crate::trace::probe("main: after emit idx + drop(addrs) (before o2hprof)");
        } else {
            drop(addrs);
        }
        Some(mm)
    } else {
        None
    };
    // o2hprof: emit after mat_map block so we can move mat_hprof_offsets_c out
    // (freeing the compressed blob before decompressing, avoiding coexistence of
    // the ~2 GB blob and the ~4 GB decompressed bytes).
    if let (Some(m), Some(mm)) = (mat.as_ref(), mat_map.as_ref()) {
        if let Some(off_c) = mat_hprof_offsets_c {
            // offsets_bytes: flat LE u64 bytes (8 bytes per object). CompressedBytes
            // restore() consumes self — the compressed blob is freed when the method
            // takes ownership, before the output Vec<u8> is fully allocated.
            let offsets_bytes = off_c.restore()?;
            m.emit_long_index_iter(
                "o2hprof",
                std::iter::once(0i64).chain(mm.sorted().iter().map(|&old_id| {
                    let lo = old_id as usize * 8;
                    offsets_bytes
                        .get(lo..lo + 8)
                        .and_then(|s| s.try_into().ok())
                        .map(i64::from_le_bytes)
                        .unwrap_or(0)
                })),
            )?;
            drop(offsets_bytes);
        }
    } else {
        drop(mat_hprof_offsets_c);
    }
    crate::trace::probe("main: after emit o2hprof");
    crate::trace::probe("main: before mat_inv (free_addrs done at idx emission)");
    // (`mat_class_meta.ref_size` was corrected to `g.ref_size` back at the
    // `compute_instance_sizes` call site — it must be right *before* the sizes
    // are computed, and `emit_dot_index` reads it from the same field.)
    // Build the row→class-object id inverse table now that mm is available, so
    // we can prefer reachable class-objects when multiple map to the same row.
    let mut mat_inv: Option<Vec<i32>> =
        if let (Some(mm), Some(coc)) = (mat_map.as_ref(), mat_coc_snapshot.as_ref()) {
            Some(mat::build_row_to_classobj_id(coc, g.class_names.len(), mm))
        } else {
            None
        };
    // Patch alias rows: some class names have two histogram rows — a canonical row
    // (JLC_KEY or PRIM_KEY) where the class-object is registered, and an addr-based
    // row where instances are counted. Only the canonical row has inv[row] != -1.
    // For the MAT o2c table, alias rows (same name, inv==-1) must map to the same
    // class-object as the canonical row.
    if let (Some(ref mut inv), Some(ref mm)) = (mat_inv.as_mut(), mat_map.as_ref()) {
        // Build: name → canonical class-object mat-id (first row with inv[row]!=-1)
        let mut name_to_coid: std::collections::HashMap<&str, i32> =
            std::collections::HashMap::new();
        for (row, name) in g.class_names.iter().enumerate() {
            if inv[row] >= 0 {
                name_to_coid.entry(name.as_str()).or_insert(inv[row]);
            }
        }
        // Fill alias rows that have inv==-1 but a canonical entry for the same name exists.
        for (row, name) in g.class_names.iter().enumerate() {
            if inv[row] < 0 {
                if let Some(&coid) = name_to_coid.get(name.as_str()) {
                    inv[row] = coid;
                }
            }
        }
        let _ = mm; // mm borrow ends here
    };
    // MAT id 0 is MAT's synthetic system-class-loader object, whose class is
    // java.lang.ClassLoader. Both `o2c[0]` and `outbound[0]` must reference that
    // class object's MAT id, so compute it once here and share it with the two
    // emitters below.
    let mat_classloader_mat: Option<i32> = match (mat_map.as_ref(), mat_inv.as_ref()) {
        (Some(mm), Some(inv)) => Some(
            g.class_names
                .iter()
                .position(|n| n == "java.lang.ClassLoader" || n == "java/lang/ClassLoader")
                .map(|row| mm.translate(inv[row]))
                .filter(|&v| v > 0)
                .or_else(|| inv.iter().map(|&v| mm.translate(v)).find(|&v| v > 0))
                .unwrap_or(0),
        ),
        _ => None,
    };
    // ── Option B: the missing "object → its own class object" inbound edges ──
    // MAT materialises an "object → its own class object" edge for EVERY object.
    // Our internal graph has it only for plain instances (HPROF INSTANCE_DUMP's
    // class id) and object arrays (OBJ_ARRAY_DUMP's element-class id, which for
    // an object array IS the array's own class object). Primitive arrays and
    // class objects carry no such record, so their class edge is absent from
    // `inb_data` — and `inb_data` also feeds the retained/dominator computation,
    // which is verified digit-for-digit against MAT and must not gain edges. The
    // missing referrers are therefore collected during the outbound emission
    // below (`class_edge_refs`) and merged into the emitted `inbound` only.
    //
    // The affected targets are exactly the primitive-array class objects
    // (`[B`, `[C`, `[S`, `[I`, `[J`, `[F`, `[D`, `[Z`) and the class object of
    // `java.lang.Class`. Object-array class objects need no injection (their
    // arrays already carry the edge), and instances of `java.lang.Class` are
    // handled by the dedup in the inbound emitter.
    let class_edge_class_mats: Option<std::collections::HashSet<i32>> =
        mat_inv.as_ref().map(|inv| {
            let mm = mat_map.as_ref().expect("mat_map built with mat");
            let mut set = std::collections::HashSet::new();
            for (row, name) in g.class_names.iter().enumerate() {
                let n = name.as_str();
                let bytes = n.as_bytes();
                let prim_array = bytes.len() == 2
                    && bytes[0] == b'['
                    && matches!(
                        bytes[1],
                        b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D'
                    );
                if prim_array || n == "java/lang/Class" || n == "java.lang.Class" {
                    let d = inv[row];
                    if d >= 0 {
                        let m = mm.translate(d);
                        if m > 0 {
                            set.insert(m);
                        }
                    }
                }
            }
            set
        });
    // Referrers of each such class object, filled in during the outbound
    // emission (where `class_obj_ids` is live) and merged into `inbound` after.
    let mut class_edge_refs: std::collections::HashMap<i32, Vec<i32>> =
        std::collections::HashMap::new();
    // MAT records a `thread → itself` edge when a thread object appears as one of
    // its own stack-frame locals. Our graph omits self-loops (they cannot affect
    // dominators or retained size, but the graph is kept as-is), so the emitters
    // inject them out of band here.
    let mut mat_self_ref: Option<crate::bitset::Bitset> = if mat.is_some() {
        Some(crate::bitset::Bitset::with_len(g.n))
    } else {
        None
    };
    // `graph_extras` derives the synthetic `thread → itself` edges from pass 1.
    // The pipeline reads them off `MatOutboundRescanCtx`; the from-cache path
    // builds no context, so it gets them handed back by `graph_from_mat_cache`.
    // Both emitters below re-inject them out of band (they are deliberately not
    // in the forward CSR), and the inbound body they lengthen is also what the
    // main `.index`'s `cacheEntry` offsets index into — so dropping them here
    // shifted every class's instance block as well.
    if let Some(z) = mat_self_ref.as_mut() {
        let self_edges: &[u32] = match mat_outbound_rescan_ctx.as_ref() {
            Some(ctx) => &ctx.synthetic_self_edges,
            None => &mat_cached_self_edges,
        };
        for &d in self_edges {
            z.set(d as usize);
        }
    }
    // Resolve class_obj_ids from the raw class_idx rows now that mat_inv is ready.
    // mat_fwd_snap.1 holds the compressed class_idx; restore, map through inv,
    // then re-compress so the 45 MB array doesn't inflate the emit_outbound peak.
    let mat_class_obj_ids_c: Option<cvec::CompressedU32> =
        if let (Some(inv), Some(fwd_snap)) = (mat_inv.as_ref(), mat_fwd_snap.as_ref()) {
            let class_idx_rows = fwd_snap.1.restore()?;
            let result: Vec<u32> = class_idx_rows
                .iter()
                .map(|&row| {
                    let coid = inv[row as usize];
                    if coid < 0 { u32::MAX } else { coid as u32 }
                })
                .collect();
            Some(cvec::CompressedU32::compress(&result, compress)?)
        } else {
            None
        };
    crate::trace::trim();
    crate::trace::probe("main: before emit_outbound");
    // g.idom was compressed earlier (after dominator) and dropped during MatIdMap::build.
    // It remains compressed in mat_idom_c; no re-compression needed here.
    // MAT: emit `outbound` IntArray1N in MAT id order.
    // We rebuild the forward CSR by rescanning the HPROF file using
    // mat_outbound_rescan_ctx (id_map + class info). fwd_off is restored from
    // mat_fwd_snap.0 and used as per-object write cursors (modified in-place):
    // after scatter, fwd_off[d] = end position; start[d] = fwd_off[d-1].
    // MAT's synthetic object 0 (the system class loader) receives an edge from
    // every class object whose HPROF `super_id` or `loader_id` is 0: MAT
    // materialises those null references as edges to object 0, whereas our
    // graph drops them (`add_edge_inner!` skips `dst_addr == 0`). The outbound
    // rescan records the affected class objects here so BOTH the `outbound` and
    // `inbound` emitters can reproduce MAT's shape (without it, `outbound` and
    // `inbound` come out 852 edges short of MAT's on the tiny dump).
    let mut mat_zero_ref: Option<crate::bitset::Bitset> = if mat.is_some() {
        Some(crate::bitset::Bitset::with_len(g.n))
    } else {
        None
    };
    // MAT id -> MAT id of that object's class. Filled while the `outbound` index
    // is emitted (that pass already resolves every object's class object) and
    // consumed by the `inbound` pass, which has to write each class object's
    // instance list first — MAT's `ClassImpl.getObjectIds()` reads a class's
    // instances straight out of the inbound body through `cacheEntry`
    // (`IndexManager.c2objects()` *is* the inbound index; see `emit_dot_index`).
    // One i32 per MAT object; empty when `mat` is None.
    let mut class_mat_of: Vec<i32> = Vec::new();
    // MAT id of each class object -> (0-based offset of that class object's
    // entry in the `inbound` body, instance count written there). Filled by the
    // inbound pass and consumed by `emit_dot_index` for `ClassImpl.cacheEntry`.
    let mut class_inb: std::collections::HashMap<i32, (i32, i32)> =
        std::collections::HashMap::new();
    if let Some(ref m) = mat {
        let mm = mat_map.as_ref().expect("mat_map built with mat");
        if let Some((fwd_off_c, _class_idx_c)) = mat_fwd_snap.as_ref() {
            // Restore fwd_off (prefix-sum offsets), drop compressed blob.
            let mut fwd_off = fwd_off_c.restore()?;
            let total_edges = if !fwd_off.is_empty() {
                fwd_off[fwd_off.len() - 1] as usize
            } else {
                0
            };
            // The emit loop below reads object `d`'s edges as
            // `fwd_off[d - 1]..fwd_off[d]`, i.e. it wants an array whose entry
            // `i` is the END of object `i`'s row. `rescan_outbound` leaves the
            // table in exactly that shape: it uses each entry as a write cursor
            // and increments it once per edge scattered, turning pass 2's
            // `off[i] = start_i` into `off[i] = start_{i+1}`. The from-cache path
            // skips the rescan, so the table is still the raw prefix sum and
            // every row would be read one object behind — the 205 KB-short
            // `outbound.index`. Shift it to the post-rescan convention here.
            // Entry `n` is never a cursor, so it stays the total edge count.
            if mat_reused && !fwd_off.is_empty() {
                let n = fwd_off.len() - 1;
                for i in 0..n {
                    fwd_off[i] = fwd_off[i + 1];
                }
            }
            // From-cache path: the forward targets were decoded off `graph.bin`
            // while the graph was being loaded, so there is nothing to
            // scatter-fill — `rescan_outbound` and the 44 GB re-read it needs
            // are both skipped. Otherwise pre-allocate and fill via the rescan.
            let mut fwd_tgt: Vec<u32> = if mat_reused {
                std::mem::take(&mut mat_cached_fwd_tgt)
            } else {
                vec![0u32; total_edges]
            };
            crate::trace::probe("main: before outbound rescan (fwd_off+fwd_tgt allocated)");
            let zero_ref = mat_zero_ref.as_mut().expect("mat_zero_ref built with mat");
            // ── Fast path (opt-in): take the forward CSR from the on-disk cache
            // instead of re-deriving it with a full HPROF rescan.
            //
            // `graph.bin` holds exactly pass2's `fwd_off`/`fwd_tgt`, and
            // `rescan_outbound` exists only to *reconstruct* that same CSR (it
            // was dropped to save RSS). When the cache is present and its offset
            // table agrees with ours, the 44 GB re-read is pure duplicate work.
            //
            // `zero_ref` is NOT in the cache — it is a MAT-emission detail, not
            // graph state — but it is exactly "class object whose HPROF record
            // has super_id == 0 || loader_id == 0" (see `rescan_outbound`'s
            // CLASS_DUMP arm), and `MatClassMeta::class_info` already carries
            // both ids per class-object address.
            //
            // Default OFF: without `HPROF_MAT_FWD_FROM_CACHE` this is a single
            // env lookup and the rescan path below runs byte-for-byte as before.
            let mut took_cache = mat_reused;
            if mat_reused {
                // `zero_ref` from pass 1's own id map — no compressed blob, and
                // no dependency on `MatOutboundRescanCtx` (which the from-cache
                // path never builds).
                if let (Some(meta), Some(id_map)) =
                    (mat_class_meta.as_ref(), mat_cached_id_map.as_ref())
                {
                    for (&addr, &(super_id, loader_id, _)) in meta.class_info.iter() {
                        if super_id == 0 || loader_id == 0 {
                            if let Some(i) = id_map.index_of(addr) {
                                zero_ref.set(i);
                            }
                        }
                    }
                }
                crate::trace::probe("main: fwd-from-cache: using cached fwd_tgt (no rescan)");
            }
            let cached_fwd =
                if !mat_reused && std::env::var_os("HPROF_MAT_FWD_FROM_CACHE").is_some() {
                    match cache::CacheDir::for_dump(std::path::Path::new(input)) {
                        Ok(c) if c.is_valid(cache::CacheMode::Graph) => {
                            crate::trace::probe("main: fwd-from-cache: reading graph.bin");
                            c.read_forward_edges().ok().flatten()
                        }
                        _ => None,
                    }
                } else {
                    None
                };
            if let Some((c_off, c_tgt)) = cached_fwd {
                // The offset table must be the same CSR we already hold, or the
                // cache belongs to a different graph and must not be trusted.
                let rescan_ctx = mat_outbound_rescan_ctx
                    .as_ref()
                    .expect("rescan context built when mat present and not from cache");
                if c_off == fwd_off && c_tgt.len() == total_edges {
                    if let (Some(meta), Some((blob, len))) =
                        (mat_class_meta.as_ref(), rescan_ctx.id_map_c.as_ref())
                    {
                        let id_map = crate::id_map::IdMap::from_compressed(
                            blob,
                            *len,
                            rescan_ctx.id_map_codec,
                        )?;
                        for (&addr, &(super_id, loader_id, _)) in meta.class_info.iter() {
                            if super_id == 0 || loader_id == 0 {
                                if let Some(i) = id_map.index_of(addr) {
                                    zero_ref.set(i);
                                }
                            }
                        }
                        fwd_tgt = c_tgt;
                        took_cache = true;
                        crate::trace::probe("main: fwd-from-cache: HIT (rescan skipped)");
                    }
                } else {
                    crate::trace::probe("main: fwd-from-cache: offset table mismatch, rescanning");
                }
            }
            if !took_cache {
                let rescan_ctx = mat_outbound_rescan_ctx
                    .as_ref()
                    .expect("rescan context built when mat present and not from cache");
                crate::pass2::rescan_outbound(rescan_ctx, &mut fwd_off, &mut fwd_tgt, zero_ref)?;
            }
            crate::trace::probe("main: after outbound rescan");
            // id_map was live during rescan (2 GB) and is now freed; trim to return
            // freed pages before restoring class_obj_ids, saving ~2 GB from emit peak.
            crate::trace::trim();
            // Restore class_obj_ids AFTER the rescan to avoid inflating the rescan peak by 2 GB.
            let class_obj_ids = mat_class_obj_ids_c
                .as_ref()
                .expect("mat_class_obj_ids_c built when mat present")
                .restore()?;
            // Emit outbound in MAT id order. After scatter, fwd_off[d] = end pos;
            // start[d] = fwd_off[d-1] (or 0 for d==0).
            // Translate fwd_tgt entries (dense ids) to MAT ids in-place to avoid
            // a large per-object scratch Vec that can inflate peak RSS by 1-2 GB
            // for objects with high out-degree (large arrays, class objects).
            let n_entries = mm.mat_count();
            let sorted = mm.sorted();
            // MAT id 0 is MAT's synthetic system-class-loader object: MAT's own
            // `o2c` gives it the class-loader class object, and the inbound entry
            // for that class object lists 0 among its instances. Mirror that so
            // the instance partition below agrees with MAT byte for byte.
            class_mat_of = vec![0i32; n_entries];
            class_mat_of[0] = mat_classloader_mat.unwrap_or(0);
            let mut idx = 0usize;
            // MAT id 0 (the synthetic system-class-loader object) has an outbound
            // list of exactly one element: its class object. Emitting an empty
            // entry there left `outbound` one edge short of MAT's and broke the
            // in == out invariant at the root.
            let root_class = mat_classloader_mat.unwrap_or(0);
            m.emit_outbound_cb(n_entries, |push| {
                if idx == 0 {
                    idx += 1;
                    push(root_class)?;
                    return Ok(());
                }
                let old_id = sorted[idx - 1];
                // MAT id of `old_id` (`sorted()` is in MAT-id order, entry 0 is
                // the synthetic root).
                let mat_id = idx as i32;
                idx += 1;
                let lo = if old_id == 0 {
                    0
                } else {
                    fwd_off[old_id as usize - 1] as usize
                };
                let hi = fwd_off[old_id as usize] as usize;
                let coid = class_obj_ids[old_id as usize];
                let class_mat = if coid == u32::MAX {
                    0i32
                } else {
                    mm.translate(coid as i32).max(0)
                };
                class_mat_of[mat_id as usize] = class_mat;
                // Option B: record this object as a referrer of its own class
                // object when the internal graph lacks that edge (primitive
                // arrays and class objects). Merged into `inbound` below.
                if let Some(set) = class_edge_class_mats.as_ref() {
                    if set.contains(&class_mat) {
                        class_edge_refs.entry(class_mat).or_default().push(mat_id);
                    }
                }
                // Translate dense ids to MAT ids in-place; compact reachable ones to front.
                let mut count = 0usize;
                for i in lo..hi {
                    let mid = mm.translate(fwd_tgt[i] as i32);
                    if mid >= 0 {
                        fwd_tgt[lo + count] = mid as u32;
                        count += 1;
                    }
                }
                fwd_tgt[lo..lo + count].sort_unstable();
                // Emit class_mat first, then remaining edges (dedup, skip class_mat).
                let class_u = class_mat as u32;
                push(class_mat)?;
                // MAT: a class object with a zero super/loader also references
                // object 0. `0` sorts before every real target, so it is emitted
                // first (matching MAT's `[class_obj] ++ sorted(refs)` layout).
                let mut prev = u32::MAX;
                if mat_zero_ref
                    .as_ref()
                    .is_some_and(|z| z.get(old_id as usize))
                {
                    push(0i32)?;
                    prev = 0;
                }
                // A synthetic thread self-edge (`thread → itself`) is not part of
                // the graph, so it is spliced into the sorted window here.
                let mut pending_self = if mat_self_ref
                    .as_ref()
                    .is_some_and(|z| z.get(old_id as usize))
                {
                    Some(mat_id as u32)
                } else {
                    None
                };
                for &v in &fwd_tgt[lo..lo + count] {
                    if let Some(sm) = pending_self {
                        if sm < v {
                            if sm != class_u && sm != prev {
                                push(sm as i32)?;
                                prev = sm;
                            }
                            pending_self = None;
                        }
                    }
                    if v != class_u && v != prev {
                        push(v as i32)?;
                        prev = v;
                    }
                }
                if let Some(sm) = pending_self {
                    if sm != class_u && sm != prev {
                        push(sm as i32)?;
                    }
                }
                Ok(())
            })?;
            crate::trace::probe("main: after emit_outbound_cb (before drops)");
            drop(fwd_tgt);
            drop(fwd_off);
            drop(class_obj_ids);
            crate::trace::trim();
        }
    }
    drop(mat_outbound_rescan_ctx);
    drop(mat_fwd_snap);
    drop(mat_class_obj_ids_c);
    crate::trace::probe(
        "main: after drop(mat_fwd_snap) — restore inb_data + build inb offset table",
    );
    // Restore inb_data now (was compressed across emit_outbound to save ~80 MB).
    let inb_data = inb_data_c.restore()?;
    // MAT inbound: build a block-sampled byte-offset table into inb_data.
    // Stores one u64 offset per INB_BLOCK_MAT pre-orders (~256 MB for 513M nodes).
    // Using u64 avoids overflow when inb_data exceeds 4 GB on large dumps.
    // dfn[dense] = pre_order; vertex[pre_order] = dense_id.
    const INB_BLOCK_MAT: usize = 16;
    let mat_inb_ctx: Option<(Vec<u32>, Vec<u64>, Vec<u32>)> = if let (Some(dfn_c), Some(vertex_c)) =
        (mat_dfn_save_c, mat_vertex_save_c)
    {
        let dfn = dfn_c.restore()?;
        let vertex = vertex_c.restore()?;
        let n = g.n;
        let mut off: Vec<u64> = Vec::with_capacity(n / INB_BLOCK_MAT + 2);
        let mut pos = 0usize;
        for pre in 0..n {
            if pre % INB_BLOCK_MAT == 0 {
                off.push(pos as u64);
            }
            let (count, c0) = vbyte::decode_one(&inb_data[pos..]);
            pos += c0;
            for _ in 0..count {
                let (_, c1) = vbyte::decode_one(&inb_data[pos..]);
                pos += c1;
            }
        }
        crate::trace::probe("main: after inb_pre_off build");
        if std::env::var_os("HPROF_MAT_DBG").is_some() {
            // Diagnostic: inb_data entry structure + dfn/vertex shape.
            let mut p = 0usize;
            let mut sum = 0u64;
            let mut zeros = 0usize;
            let mut entries_with_zero = 0usize;
            let mut max_len = 0u32;
            let mut max_at = 0usize;
            let mut lens: Vec<u32> = Vec::with_capacity(n);
            for e in 0..n {
                let (count, c0) = vbyte::decode_one(&inb_data[p..]);
                p += c0;
                lens.push(count);
                if count == 0 {
                    zeros += 1;
                }
                if count > max_len {
                    max_len = count;
                    max_at = e;
                }
                let mut prev = 0u32;
                let mut saw_zero = false;
                for _ in 0..count {
                    let (d, c1) = vbyte::decode_one(&inb_data[p..]);
                    p += c1;
                    prev = prev.wrapping_add(d);
                    if prev == 0 {
                        saw_zero = true;
                    }
                }
                if saw_zero {
                    entries_with_zero += 1;
                }
                sum += count as u64;
            }
            eprintln!(
                "[mat-dbg] inb_data: n={n} consumed={p}/{} entries={} zero_entries={} sum_counts={} max_len={} (entry {max_at}) entries_with_zero_val={}",
                inb_data.len(),
                n,
                zeros,
                sum,
                max_len,
                entries_with_zero
            );
            let sorted: &[u32] = mat_map.as_ref().map(|m| m.sorted()).unwrap_or(&[]);
            if let Ok(mut f) = std::fs::File::create("/tmp/mat-inbcounts.txt") {
                use std::io::Write;
                let mut s = String::with_capacity(lens.len() * 4);
                for v in &lens {
                    s.push_str(&v.to_string());
                    s.push('\n');
                }
                let _ = f.write_all(s.as_bytes());
            }
            let mut mism = 0usize;
            let mut minp = u32::MAX;
            let mut maxp = 0u32;
            for &old in sorted {
                let pr = dfn[old as usize];
                if pr != old {
                    mism += 1;
                }
                minp = minp.min(pr);
                maxp = maxp.max(pr);
            }
            eprintln!(
                "[mat-dbg] dfn.len={} vertex.len={} dfn[n]={} vertex[0]={} pre!=dense: {}/{} pre_range={}..{}",
                dfn.len(),
                vertex.len(),
                dfn.get(n).copied().unwrap_or(u32::MAX),
                vertex[0],
                mism,
                sorted.len(),
                minp,
                maxp
            );
        }
        Some((dfn, off, vertex))
    } else {
        None
    };
    // MAT: emit `inbound` IntArray1N in MAT id order. Decode each object's
    // referrers on demand from inb_data using the block-offset table.
    if let Some(ref m) = mat {
        let mm = mat_map.as_ref().expect("mat_map built with mat");
        if let Some((_dfn, inb_pre_off, vertex)) = mat_inb_ctx.as_ref() {
            // Entry 0 is MAT's synthetic system-class-loader object: its inbound
            // list is exactly the class objects whose super/loader reference was
            // 0 (see `mat_zero_ref`). `mm.sorted()` is in MAT-id order, so the
            // list comes out sorted, as MAT stores it.
            let root_inb: Vec<i32> = match mat_zero_ref.as_ref() {
                Some(z) => mm
                    .sorted()
                    .iter()
                    .enumerate()
                    .filter(|&(_, &old)| z.get(old as usize))
                    .map(|(i, _)| (i + 1) as i32)
                    .collect(),
                None => Vec::new(),
            };
            // MAT also records an inbound edge from object 0 into the class-loader
            // class object (object 0's own class edge). Our graph has no node for
            // object 0, so inject it here.
            let root_class = mat_classloader_mat.filter(|&v| v > 0);
            // MAT ids of the class objects — the entries that need the
            // instances-first layout and that carry a `cacheEntry` (one entry
            // per class, so this set is tiny).
            let class_obj_mats: std::collections::HashSet<i32> = g
                .class_obj_class_idx
                .keys()
                .filter_map(|&coid| {
                    let mid = mm.translate(coid as i32);
                    if mid > 0 { Some(mid) } else { None }
                })
                .collect();
            // mat id -> (0-based inbound-body offset of its entry, instance
            // count). Consumed by `emit_dot_index` for `ClassImpl.cacheEntry`.
            // Running 0-based body position; entry 0 (the synthetic root) is
            // never a class object, so it only advances the cursor.
            let mut body_pos: i64 = 0;
            if !root_inb.is_empty() {
                body_pos += root_inb.len() as i64;
            }
            let iter = std::iter::once(root_inb).chain(mm.sorted().iter().map(|&old_id| {
                // `inb_data` is indexed by DENSE id: `encode_phase4` writes one
                // count-prefixed entry per dense node, and `dominator.rs` seeks
                // to `vertex[i]` (the dense id) for the node at pre-order `i`.
                // The body values, by contrast, ARE pre-orders — hence the
                // `vertex[prev]` mapping below. Seeking by pre-order (the old
                // `dfn[old_id]`) returned a permutation of MAT's referrer lists.
                let entry = old_id as usize;
                // Seek to block start, then skip (entry % INB_BLOCK_MAT) entries.
                let block_start = entry - (entry % INB_BLOCK_MAT);
                let mut pos = inb_pre_off[block_start / INB_BLOCK_MAT] as usize;
                for _skip in block_start..entry {
                    let (skip_count, c0) = vbyte::decode_one(&inb_data[pos..]);
                    pos += c0;
                    for _ in 0..skip_count {
                        let (_, c1) = vbyte::decode_one(&inb_data[pos..]);
                        pos += c1;
                    }
                }
                let (count, c0) = vbyte::decode_one(&inb_data[pos..]);
                pos += c0;
                let mut e: Vec<i32> = Vec::with_capacity(count as usize);
                let mut prev: u32 = 0;
                for _ in 0..count {
                    let (delta, c1) = vbyte::decode_one(&inb_data[pos..]);
                    pos += c1;
                    prev += delta;
                    if prev > 0 {
                        let dense = vertex[prev as usize] as i32;
                        let mid = mm.translate(dense);
                        if mid >= 0 {
                            e.push(mid);
                        }
                    }
                }
                let mat_id = mm.translate(old_id as i32);
                let is_class_obj = class_obj_mats.contains(&mat_id);
                // Option B: merge in the referrers whose class edge our graph
                // lacks (primitive arrays → their array class object; class
                // objects → the java.lang.Class class object). The internal
                // graph already carries the edge for instances and object
                // arrays, so the dedup below absorbs those duplicates.
                if let Some(extra) = class_edge_refs.get(&mat_id) {
                    e.extend_from_slice(extra);
                }
                // Synthetic thread self-edge (`thread → itself`).
                if mat_self_ref
                    .as_ref()
                    .is_some_and(|z| z.get(old_id as usize))
                {
                    e.push(mat_id);
                }
                e.sort_unstable();
                e.dedup();
                if let Some(rc) = root_class {
                    if mat_id == rc {
                        // 0 is the smallest value, so it stays sorted.
                        e.insert(0, 0);
                    }
                }
                // MAT layout for a CLASS object's inbound entry:
                // [instances ascending] ++ [remaining referrers ascending].
                // `ClassImpl.getObjectIds()` slices the *first* `count` values
                // out of the inbound body, so the instances have to lead.
                // `e` is already sorted ascending, so a stable partition keeps
                // both halves ascending. `class_mat_of[x] == mat_id` is exactly
                // "x is an instance of the class object mat_id"; it can never
                // hold for a non-class object, so this is a no-op there.
                if is_class_obj && !class_mat_of.is_empty() {
                    let mut inst: Vec<i32> = Vec::with_capacity(e.len());
                    let mut rest: Vec<i32> = Vec::with_capacity(e.len());
                    for &x in &e {
                        if class_mat_of.get(x as usize).copied() == Some(mat_id) {
                            inst.push(x);
                        } else {
                            rest.push(x);
                        }
                    }
                    let cnt = inst.len();
                    if cnt > 0 {
                        // `body_pos` is the 0-based index of this entry in the
                        // inbound body, i.e. exactly the `offset` MAT's
                        // `InboundReader.getObjectsOf` wants (`body.getNext(off,
                        // cnt)` == `body[off .. off+cnt)`).
                        class_inb.insert(mat_id, (body_pos as i32, cnt as i32));
                    }
                    inst.extend_from_slice(&rest);
                    e = inst;
                }
                // Empty entries are written as holes and occupy no body space.
                if !e.is_empty() {
                    body_pos += e.len() as i64;
                }
                e
            }));
            m.emit_inbound_iter(iter)?;
            crate::trace::trim();
        }
    }
    drop(mat_inb_ctx);
    drop(mat_zero_ref);
    drop(mat_self_ref);
    drop(class_edge_refs);
    // ~4 bytes/MAT-object, live only across the outbound + inbound emission.
    drop(class_mat_of);
    // Restore g.idom from compressed blob (it was compressed before emit_outbound
    // to save ~1.3 GB of RSS during the outbound + inbound emission window).
    if let Some(c) = mat_idom_c {
        g.idom = c.restore()?;
    }
    // MAT: emit the `domIn` IntIndex in MAT id order. mat-id 0 (synthetic root)
    // has no dominator (superroot = -1, stored as 1). For mat-ids 1..N look up
    // the old dense-id, translate idom[old] to a mat-id, then add 2 per MAT's
    // convention (superroot stored as 1, id 0 → 2, etc.).
    if let Some(ref m) = mat {
        let mm = mat_map.as_ref().expect("mat_map built with mat");
        let n_u = g.n as u32;
        let mc = mm.mat_count();
        let mut domin: Vec<i32> = Vec::with_capacity(mc);
        // id-0 = synthetic superroot, its own dominator is the superroot (-1+2=1)
        domin.push(1i32);
        for &old_id in mm.sorted() {
            let d = g.idom[old_id as usize];
            let mat_idom = if d == n_u || d == u32::MAX {
                // dominated by virtual root = MAT superroot (-1), stored +2 = 1
                1i32
            } else {
                // translate old idom to mat-id (+2 per MAT convention)
                let mid = mm.translate(d as i32);
                if mid < 0 { 1i32 } else { mid + 2 }
            };
            domin.push(mat_idom);
        }
        m.emit_dom_in(&domin)?;
    }
    // inb_data is consumed by emit_inbound (for MAT) and then no longer needed.
    // inb_block_off was already freed right after compute_dominators above.
    drop(inb_data);
    crate::trace::trim();

    // Build the dominator-children CSR ONCE and share it across compute_retained
    // (hasSame DFS) and report::leak_suspects (both previously rebuilt it, ~6GB
    // redundant @514M). Built BEFORE restoring shallow/class_idx: the build's
    // transient (child_deg+child_off+child_tgt ~8GB, child_deg freed inside)
    // must not coexist with the 4GB dense shallow+class_idx -> that stacking
    // was the ~22GB global peak. It reads only idom.
    crate::trace::probe("main: before build_dom_children_csr");
    // From-cache path: `arrays.bin` already holds the dominator-children CSR, so
    // the ~8 GB build transient is skipped entirely. Read it here — its first and
    // only use — rather than holding it from the start of the run.
    let (dc_off, dc_tgt) = if mat_reused {
        let dir = mat_cache_dir
            .as_ref()
            .expect("from-cache path always has a cache dir");
        dir.read_dominator_children()?.ok_or_else(|| {
            io::Error::other(
                "graph cache lost its dominator children mid-run; re-run `heap load --with-graph`",
            )
        })?
    } else {
        retained::build_dom_children_csr(g.n, &g.idom)
    };
    crate::trace::probe("main: after build_dom_children_csr");
    t_dark!("dom_children_csr done");

    // g.idom is kept live (uncompressed) across compute_retained + build_model.
    // A prior version Deflate9-compressed it here (~2 GB) and restored it before
    // build_model to save ~1.7 GB in this window — but profiling showed the global
    // peak RSS is set much earlier (inbound CSR build), so this window is nowhere
    // near the peak; the compress cost ~208s for zero peak-RSS benefit. Removed.

    // MAT: emit o2c (mat-id -> class-object mat-id) and a2s (mat-id -> shallow
    // size) in MAT id order. Restore the compressed blobs transiently for random
    // access by old dense-id; the restore below will do it again for the report
    // phase (restoring a compressed blob is idempotent and cheap).
    if let Some(ref m) = mat {
        let mm = mat_map.as_ref().expect("mat_map built with mat");
        let inv = mat_inv.as_ref().expect("mat_inv built when mat present");
        let class_idx_vec: Vec<u32> = class_idx_c.restore()?;
        let shallow_vec: Vec<u32> = shallow_c.restore()?;
        let mc = mm.mat_count();

        // o2c: mat-id 0 is MAT's synthetic system-class-loader object, whose
        // class is java.lang.ClassLoader. o2c[0] must be THAT class object's
        // MAT id, never 0: SnapshotImpl.getObject(0) misses the class cache and
        // falls into HeapObjectCache.load(0) -> getObject(o2class().get(0)) ->
        // ... which, with o2c[0] == 0, recurses until StackOverflowError (this
        // is what killed MAT's top_components report on a reopened cache).
        let classloader_mat = mat_classloader_mat.unwrap_or(0);
        let mut o2c_vals: Vec<i32> = Vec::with_capacity(mc);
        o2c_vals.push(classloader_mat);
        for &old_id in mm.sorted() {
            let row = class_idx_vec[old_id as usize];
            let class_obj_old = inv[row as usize]; // old dense class-object id (-1 = missing)
            let class_obj_mat = mm.translate(class_obj_old);
            o2c_vals.push(if class_obj_mat >= 0 { class_obj_mat } else { 0 });
        }
        m.emit_int_index("o2c", &o2c_vals)?;
        drop(o2c_vals);

        // a2s is MAT's `ArrayToSize` index: the shallow size of every ARRAY
        // object and 0 for everything else (MAT's own index has a nonzero value
        // for exactly the ids in the arrayObjects BitField). Non-arrays get
        // their size from `o2c` + `ClassImpl.instanceSize`, so storing it here
        // as well made MAT's "Heap Size" views read 24/40/… for plain objects.
        // mat-id 0 is 0 too (it is not an array).
        let mut a2s_vals: Vec<i32> = Vec::with_capacity(mc);
        a2s_vals.push(0i32);
        for &old_id in mm.sorted() {
            let row = class_idx_vec[old_id as usize] as usize;
            let is_array = g.class_names.get(row).is_some_and(|n| n.starts_with('['));
            let sz = if is_array {
                mat::size_compress(shallow_vec[old_id as usize] as i64)
            } else {
                0
            };
            a2s_vals.push(sz);
        }
        // ── loaderLabels ─────────────────────────────────────────────────
        // MAT keys `loaderLabels` by the class-loader id of every class *plus*
        // the id of every instance of `java.lang.ClassLoader` and its
        // subclasses (SnapshotImpl.calculateLoaderLabels) — more class loaders
        // than the distinct `class_loader_id` values, because a loader that
        // loads no class in this heap still counts. The bootstrap loader is the
        // only one MAT names ("<system class loader>"); the rest fall back to
        // the NO_LABEL placeholder when the class-specific-name resolver finds
        // nothing.
        let mut loader_ids: std::collections::BTreeSet<i32> = std::collections::BTreeSet::new();
        loader_ids.insert(0); // MAT's synthetic system class loader at 0x0
        if mat_row_is_loader.len() == g.class_names.len() {
            for i in 0..g.n {
                let row = class_idx_vec[i] as usize;
                if mat_row_is_loader.get(row).copied().unwrap_or(false) {
                    let mid = mm.translate(i as i32);
                    if mid > 0 {
                        loader_ids.insert(mid);
                    }
                }
            }
        }
        if let Some(r) = mat_roots.as_mut() {
            r.loader_labels = loader_ids
                .into_iter()
                .map(|id| {
                    (
                        id,
                        if id == 0 {
                            "<system class loader>".to_string()
                        } else {
                            "__none__".to_string()
                        },
                    )
                })
                .collect();
        }

        drop(class_idx_vec);
        drop(shallow_vec);
        m.emit_int_index("a2s", &a2s_vals)?;
    }

    // Restore shallow/class_idx now that the CSR-build transient has freed
    // child_deg (dominator already freed the inbound CSR too).
    if compress != cvec::Codec::None {
        g.shallow = shallow_c.restore()?;
        g.class_idx = class_idx_c.restore()?;
    }
    drop(shallow_c);
    drop(class_idx_c);
    crate::trace::probe("main: after restore shallow/class_idx");
    t_dark!("restore shallow/class_idx done");
    let t = Instant::now();
    progress::phase("computing retained sizes");
    let class_count = g.class_names.len();
    let (retained, has_same, depth_counts) = retained::compute_retained(
        g.n,
        &g.shallow,
        &g.class_idx,
        class_count,
        &g.class_obj_class_idx,
        g.jlc_idx,
        &dc_off,
        &dc_tgt,
    );
    g.retained = retained;
    g.has_same_class_ancestor = has_same;
    log(verbose, "retained", t.elapsed().as_secs_f64());
    t_dark!("compute_retained done");

    // MAT: emit the `domOut` IntArray1N in MAT id order.
    // Layout: entry[0] = superroot's dom-children, entry[1] = dom-children of
    // mat-id 0 (the synthetic system class loader), entries[2..mc+1] =
    // dom-children of mat-ids 1..mc-1 (real objects). Streaming to avoid a
    // large Vec<Vec<i32>> materialisation.
    //
    // Two details MAT's own index depends on:
    //   * object 0's dominator is the superroot (domIn[0] == 1), so 0 is one of
    //     the superroot's children — without it MAT's dominator traversal never
    //     reaches the synthetic root and Top Consumers collapses;
    //   * EVERY parent's child list is sorted by retained size DESCENDING, not
    //     just the superroot's. MAT's `DominatorTree.writeIndexFiles` calls
    //     `tree.sortByTotalSize(successors)` inside the loop over all parents
    //     (MAT 1.16.1 `DominatorTree.java:405-410`), so each domOut entry is
    //     ordered by `ts[child]` descending. `ArrayUtils.sortDesc` is a stable
    //     sort for entry sizes below `USE_RADIX` (1e6), and the upstream
    //     `ArrayUtils.sort(dom, objectIds, ...)` that produced MAT's child order
    //     is likewise stable, so ties keep ascending mat-id order — which is
    //     exactly our `dc_tgt` order, so a stable `Reverse(retained)` sort
    //     reproduces MAT byte-for-byte.
    // Emitted here, after `compute_retained`, because the sort needs the
    // retained sizes.
    if let Some(ref m) = mat {
        let mm = mat_map.as_ref().expect("mat_map built with mat");
        let n = g.n;
        // entry 0: the superroot's dom-children, biggest retained first.
        // The synthetic mat-id 0 is dominated by the superroot too and is NOT
        // forced last: MAT sorts it in by its retained size (which is
        // `mat_root_instance_size`, the same value o2ret[0] carries). It is
        // seeded FIRST so that, being the smallest object id, it wins the
        // ascending-id tie-break the stable sort preserves.
        let lo0 = dc_off[n] as usize;
        let hi0 = dc_off[n + 1] as usize;
        let mut vroot_children: Vec<(i32, u64)> = Vec::with_capacity(hi0 - lo0 + 1);
        vroot_children.push((0, mat_root_instance_size as u64));
        vroot_children.extend(dc_tgt[lo0..hi0].iter().filter_map(|&v| {
            let mid = mm.translate(v as i32);
            if mid >= 0 {
                Some((mid, g.retained[v as usize]))
            } else {
                None
            }
        }));
        vroot_children.sort_by_key(|b| std::cmp::Reverse(b.1));
        let vroot_children: Vec<i32> = vroot_children.into_iter().map(|(mid, _)| mid).collect();
        let iter = std::iter::once(vroot_children)
            .chain(std::iter::once(Vec::new())) // entry 1: mat-id 0 synthetic root
            .chain(mm.sorted().iter().map(|&old_id| {
                let lo = dc_off[old_id as usize] as usize;
                let hi = dc_off[old_id as usize + 1] as usize;
                let mut kids: Vec<(i32, u64)> = dc_tgt[lo..hi]
                    .iter()
                    .filter_map(|&v| {
                        let mid = mm.translate(v as i32);
                        if mid >= 0 {
                            Some((mid, g.retained[v as usize]))
                        } else {
                            None
                        }
                    })
                    .collect();
                kids.sort_by_key(|b| std::cmp::Reverse(b.1));
                kids.into_iter().map(|(mid, _)| mid).collect::<Vec<i32>>()
            }));
        m.emit_dom_out_iter(iter)?;
        crate::trace::trim();
    }

    // Compute field_stats now (while the saved fwd clone is live and retained is populated),
    // then immediately free the clone to avoid carrying it through build_model's allocations.
    let precomputed_field_stats_main: Option<crate::report::FieldStats> =
        if let Some((fwd_off, fwd_tgt)) = field_stats_fwd_main {
            g.fwd_offsets = fwd_off;
            g.fwd_targets = fwd_tgt;
            let fs = crate::report::build_field_stats(&g);
            g.fwd_offsets = Vec::new();
            g.fwd_targets = crate::chunkvec::ChunkU32::default();
            Some(fs)
        } else {
            None
        };
    t_dark!("field_stats done");

    // Finalize cross-phase (@retainedHeapSize) queries now that retained sizes
    // exist. Phase-1 results pass through; carried indices are joined against
    // g.retained, then all results reassemble in original query order.
    let query_asts: Vec<query::ast::Query> = flat_queries.iter().map(|(q, _)| q.clone()).collect();
    // Dominator stages read idom + the dominator-children CSR (dc_off/dc_tgt),
    // both live in this window. The IdMap is built empty: the dense address
    // table was compressed away at ~L973 (its 4.1GB dense form must not rejoin
    // the RSS peak), and dominator result rows assert on dense indices, not
    // addresses. A later stage that genuinely needs addresses will thread them.
    let id_map = query::stage_runner::IdMap::new(&[]);
    // Thread the query-gated RefWalk CSR into the resume window. Built only when
    // a RefWalk query ran; otherwise the borrowed slices are empty and the shared
    // empty tail map is used, keeping non-RefWalk runs byte/RSS-identical.
    let rw_off: &[u32] = refwalk_csr.as_ref().map_or(&[], |c| &c.fwd_off);
    let rw_tgt: &[u32] = refwalk_csr.as_ref().map_or(&[], |c| &c.fwd_tgt);
    let rw_field: &[u32] = refwalk_csr.as_ref().map_or(&[], |c| &c.fwd_field);
    let rw_names: &[String] = refwalk_csr.as_ref().map_or(&[], |c| &c.field_names);
    let rw_tails = refwalk_csr
        .as_ref()
        .map_or(&*query::stage_runner::EMPTY_REFWALK_TAILS, |c| &c.tails);
    let rw_trunc = refwalk_csr.as_ref().is_some_and(|c| c.truncated);
    // Thread the query-gated edge structures (built at the forward-CSR hook above)
    // into the resume window. Both are `None`/empty on a no-edge run, so the
    // borrowed slices stay empty and behavior is identical to today.
    let in_off: &[u32] = retained_inbound.as_ref().map_or(&[], |(o, _)| o);
    let in_tgt: &[u32] = retained_inbound.as_ref().map_or(&[], |(_, t)| t);
    // Thread the query-gated toString(s) string values into the resume window.
    // Built only when a toString(s) query ran; empty otherwise — non-toString
    // runs keep the shared EMPTY_STRING_VALUES borrow, byte/RSS-identical.
    let sv_ref: &std::collections::HashMap<u32, String> = if string_values.is_empty() {
        &query::stage_runner::EMPTY_STRING_VALUES
    } else {
        &string_values
    };
    // Build the query-gated GC-root-tags lookup (`dense_idx → heap::ROOT_*`) for
    // `@GCRoots`/`@GCRootInfo`/`@info`, ONLY when some plan armed `needs.gc_roots`.
    // Source: zip `g.gc_root_indices` with `g.gc_root_types`, which are aligned
    // 1:1 by construction (both emitted together from the sorted root set in
    // `pass2::mod`; the same pairing `report::build` trusts) — so no fragile
    // address→dense re-derivation is needed and root types can't be mispaired.
    // When no gcroot query ran, the empty static keeps this run byte/RSS-identical.
    let gc_root_tags: std::collections::HashMap<u32, u8> =
        if flat_queries.iter().any(|(_, p)| p.needs.gc_roots) {
            g.gc_root_indices
                .iter()
                .zip(g.gc_root_types.iter())
                .map(|(&idx, &ty)| (idx, ty))
                .collect()
        } else {
            std::collections::HashMap::new()
        };
    let gc_root_tags_ref: &std::collections::HashMap<u32, u8> = if gc_root_tags.is_empty() {
        &query::stage_runner::EMPTY_GC_ROOT_TAGS
    } else {
        &gc_root_tags
    };
    let flat_results = query::stage_runner::resume(
        query_state,
        &query_asts,
        &query::stage_runner::LateCtx {
            retained: &g.retained,
            idom: &g.idom,
            dc_off: &dc_off,
            dc_tgt: &dc_tgt,
            shallow: &g.shallow,
            id_map: &id_map,
            fwd_off: rw_off,
            fwd_tgt: rw_tgt,
            fwd_field: rw_field,
            field_names: rw_names,
            refwalk_tails: rw_tails,
            refwalk_truncated: rw_trunc,
            in_off,
            in_tgt,
            retained_edges: retained_edges.as_ref(),
            string_values: sv_ref,
            string_values_truncated,
            gc_root_tags: gc_root_tags_ref,
            class_idx: &g.class_idx,
            class_names: &g.class_names,
        },
    );

    // `--reachable-only` OQL pruning (opt-in for the analyze command; the default
    // is raw heap, kept byte-identical by the `None` guard). `resume` returns
    // results in slot order (1:1 with `flat_queries`), so `flat_results[i]` is
    // slot `i`. Prune each slot's rows by its scan-captured SOURCE dense index
    // BEFORE UNION-collapse — the same exact-index approach the `query` subcommand
    // uses, so a projected `@objectAddress` (a raw heap address) prunes correctly
    // instead of being mis-read as a dense index. Row-EXPANDING late ops
    // (dominators / AS RETAINED SET / edges) emit rows that are not the original
    // matched objects, so the source sidecar does not align — those slots are left
    // unpruned.
    let mut flat_results = flat_results;
    if let Some(dfn) = &reach_dfn {
        for (slot, r) in flat_results.iter_mut().enumerate() {
            let row_expanding = flat_queries.get(slot).is_some_and(|(_, p)| {
                p.late_ops.iter().any(|op| {
                    matches!(
                        op,
                        query::plan::StageOp::RetainedSet { .. }
                            | query::plan::StageOp::DominatorChildren { .. }
                            | query::plan::StageOp::DominatorOf
                            | query::plan::StageOp::EdgeLookup { .. }
                            | query::plan::StageOp::BoundedPath { .. }
                    )
                })
            });
            if row_expanding {
                continue;
            }
            if let Some(src) = row_src_by_slot.get(&slot) {
                query::run::filter_result_by_src(r, src, dfn);
            }
        }
    }

    let mut query_results = query::run::collapse_union_results(flat_results, &union_groups);

    // Step D: surface the edge-retention note on edge-using result rows. Only
    // present when an edge feature is armed; attaching it to edge-using result
    // rows keeps a no-edge run's JSON byte-identical (`note` is skipped when
    // `None`). After `collapse_union_results`, `query_results` is one row per
    // ORIGINAL top-level query, in `parsed_queries` order — zip against that (a
    // UNION branch's edge use is detected because `plan_run` scans branches too).
    debug_assert_eq!(query_results.len(), parsed_queries.len());
    if let Some(note) = run_flags.retention_note() {
        for (r, (q, _)) in query_results.iter_mut().zip(parsed_queries.iter()) {
            if query_uses_edges(q) && r.note.is_none() {
                r.note = Some(note.clone());
            }
        }
    }

    // MAT: emit the `o2ret` LongIndex in MAT id order.
    // mat-id 0 (the synthetic system class loader) is not a heap object, so
    // MAT's retained-size calculation falls through to `SnapshotImpl
    // .getHeapSize(0)`, which resolves through o2c[0] to java.lang.ClassLoader's
    // heapSizePerInstance — i.e. exactly `mat_root_instance_size`.
    if let Some(ref m) = mat {
        let mm = mat_map.as_ref().expect("mat_map built with mat");
        let mc = mm.mat_count();
        let mut o2ret_vals: Vec<i64> = Vec::with_capacity(mc);
        o2ret_vals.push(mat_root_instance_size as i64); // synthetic root
        for &old_id in mm.sorted() {
            o2ret_vals.push(g.retained[old_id as usize] as i64);
        }
        m.emit_long_index("o2ret", &o2ret_vals)?;
    }

    // MAT: the `UnreachableObjectsHistogram` aggregates: per class row, how many
    // unreachable objects it holds and their summed size. MAT's per-object rule
    // (`GarbageCleaner.createHistogramOfUnreachableObjects`): an array
    // contributes its array size, a class object the used heap size of the class
    // it represents, anything else its `heapSizePerInstance` — which is exactly
    // our `shallow`. Class objects are recorded separately, as the row of the
    // class each one represents, because only `emit_dot_index` knows those
    // classes' used heap sizes.
    //
    // Computed HERE rather than with the emit that consumes it: this scan reads
    // `g.idom`, and `build_model` — which runs before that emit so the report
    // does not have to wait for the remaining index files — consumes it.
    let mat_unreach: Option<mat::MatUnreachableHist> = if mat.is_some() {
        let num_rows = g.class_names.len();
        let mut unreach = mat::MatUnreachableHist {
            count: vec![0i32; num_rows],
            shallow: vec![0i64; num_rows],
            classobj_rows: Vec::new(),
        };
        for i in 0..g.n {
            if g.idom[i] != u32::MAX {
                continue;
            }
            let row = g.class_idx[i] as usize;
            if row >= num_rows {
                continue;
            }
            unreach.count[row] += 1;
            match g.class_obj_class_idx.get(&(i as u32)) {
                Some(&crow) => unreach.classobj_rows.push(crow as i32),
                None => unreach.shallow[row] += g.shallow[i] as i64,
            }
        }
        Some(unreach)
    } else {
        None
    };

    // Restore + aggregate + free the alloc stack serials in a bounded window
    // right after compute_retained (needs g.shallow + g.retained, both live
    // now). Skipped entirely when skip_report is set (mat caches mode).
    let alloc_sites = if opts.skip_report {
        None
    } else if let Some(c) = alloc_serial_c {
        // Stream the deflate blob through a 64 KiB scratch buffer, feeding each
        // serial into the accumulator in index order. Never materialises the
        // ~2GB decompressed byte buffer OR a collected Vec<u32> — the transient
        // is O(64 KiB), well under the binding rpo peak.
        let mut agg = report::AllocAgg::new(&g, opts.alloc_sites_top);
        c.for_each_u32(|serial| agg.push(serial))?;
        let a = agg.finish();
        g.alloc_frames_by_serial = None;
        crate::trace::trim();
        Some(a)
    } else {
        // Codec::None path (never taken on the big dump): aggregate directly.
        let a = report::build_alloc_sites(&g, opts.alloc_sites_top);
        g.alloc_stack_serial = Vec::new();
        g.alloc_frames_by_serial = None;
        Some(a)
    };

    if opts.skip_report {
        // `mat caches` without `--report`: there is no report to build, so skip
        // `build_model` + `render` entirely. The MAT tail below still runs —
        // `.threads` and the master `.index` are not report products, and MAT
        // cannot open the cache at all without the master `.index`. (Returning
        // here instead skipped both, which is how `mat caches` came to emit 9 of
        // the 11 files the `--report` path emits.)
        drop(dc_off);
        drop(dc_tgt);
        log(verbose, "total", t_total.elapsed().as_secs_f64());
    } else {
        let t = Instant::now();
        progress::phase("building report");
        crate::trace::probe("report: before build_model");
        // build_model reads has_same_class_ancestor (system-overview group) and
        // dc_off/dc_tgt (leak-suspect group) and stores only bounded aggregates,
        // so both can be freed immediately after it returns. depth_counts is the
        // B2 dominator-depth histogram tallied during compute_retained's DFS (no
        // separate ~2GB per-object memo scan).
        let mut report = report::build_model(
            &mut g,
            dc_off,
            dc_tgt,
            opts.leak_children_cap,
            &depth_counts,
            &opts,
            alloc_sites,
            precomputed_field_stats_main,
            redacted,
        );
        crate::trace::probe("report: after build_model");
        t_dark!("build_model done");
        g.has_same_class_ancestor = crate::bitset::Bitset::default(); // consumed by build_model
        // dc_off and dc_tgt were moved into build_model and freed early inside it.
        crate::trace::trim();
        // Fill in blank oql text and default names (from-target-derived, else
        // `q{N}`) for the printed tables.
        finalize_query_labels(&mut query_results, &query_texts, &parsed_queries);
        attach_viz(&mut query_results, &collected);
        report.queries = std::mem::take(&mut query_results);
        report.truncated_input = truncated_input;

        let out_text = match format {
            OutputFormat::Md => {
                let md = report::render_markdown(&report);
                crate::trace::probe("report: after render_markdown");
                md
            }
            OutputFormat::MdGraphs => {
                let md = report::render_markdown_graphs(&report);
                crate::trace::probe("report: after render_markdown_graphs");
                md
            }
            OutputFormat::Json => {
                // serde_json over a struct preserves field declaration order and
                // carries no f64 (pct is #[serde(skip)]), so output is
                // deterministic. The model holds only KB-scale aggregates, so
                // serialization is trivially RSS-safe even for huge dumps.
                let js = serde_json::to_string_pretty(&report).map_err(io::Error::other)?;
                crate::trace::probe("report: after serialize_json");
                js
            }
            OutputFormat::Html => {
                let h = if opts.dev_report {
                    html::render_html_dev(&report, opts.bundle_path.as_deref())
                } else {
                    html::render_html(&report)
                };
                crate::trace::probe("report: after render_html");
                h
            }
        };
        log(verbose, "report", t.elapsed().as_secs_f64());
        t_dark!("render done");

        // Clear the progress line before emitting output, so it does not linger on
        // stderr next to the report (or leak into a piped tail).
        progress::done();
        write_output(output, &out_text).map_err(|e| {
            // Name the OUTPUT path here so the analyze error hint does not later
            // re-attribute an output-write failure to the input file.
            let target = output.unwrap_or("<stdout>");
            io::Error::new(e.kind(), format!("cannot write '{target}': {e}"))
        })?;

        log(verbose, "total", t_total.elapsed().as_secs_f64());
        t_dark!("write+total done");
    }

    // MAT: emit i2sv2 (deliberately not emitted — see below) and `.threads`,
    // then the master `.index`. These are the last two files precisely so the
    // report above does not have to wait for them; everything they read that
    // `build_model` consumed (`g.idom`) was already folded into `mat_unreach`.
    if let Some(ref m) = mat {
        let mm = mat_map.as_ref().expect("mat_map built with mat");
        let inv = mat_inv.as_ref().expect("mat_inv built when mat present");

        // i2sv2 (`RetainedSizeCache`) is deliberately NOT emitted. MAT's entry is
        // `-getMinRetainedSize({class object} ∪ its instances)` — the *approximated*
        // retained size of that set, stored negated — and MAT trusts the cache
        // whenever the entry is present. Our aggregate was the plain sum of each
        // instance's retained size, which differs from MAT's for 408 of the small
        // dump's 2036 classes and made the Class Histogram's `Retained Heap`
        // column too large (and its rows mis-ordered). MAT recomputes the cache
        // itself when the file is absent, so leaving it out restores parity.

        // .threads: thread stacks (addresses from mm).
        m.emit_threads(&g.thread_stacks, mm, &g.thread_local_frame_samples)?;

        // .index: master Java serialization stream.
        if let Some(ref meta) = mat_class_meta {
            let empty_roots = mat::MatRoots::default();
            let empty_sizes = std::collections::HashMap::new();
            m.emit_dot_index(
                meta,
                &g.class_names,
                &g.class_loader_id,
                &g.class_obj_class_idx,
                inv,
                mm,
                g.n,
                &g.shallow,
                &g.class_idx,
                mat_roots.as_ref().unwrap_or(&empty_roots),
                mat_instance_sizes.as_ref().unwrap_or(&empty_sizes),
                mat_root_instance_size,
                mat_classloader_mat.unwrap_or(0),
                &class_inb,
                mat_unreach
                    .as_ref()
                    .expect("unreachable histogram built with mat"),
                &mat_unreach_class_addr,
            )?;
        }
    }
    Ok(())
}

/// Emit pass-1 parse stats (counts + class histogram) as JSON to stdout.
fn dump_pass1_json(path: &str) -> io::Result<()> {
    let p = Pass1::run(&crate::source::HprofSource::from(path), false)?;

    let mut class_hist: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for (i, &cidx) in p.class_ids.iter().enumerate() {
        // class_ids holds interned indices; resolve to addr for kinds that
        // reference a class object (0=instance, 3=class-obj). arrays skip.
        if p.kind[i] != 0 && p.kind[i] != 3 {
            continue;
        }
        let addr = p.class_addr_table[cidx as usize];
        if let Some(ci) = p.class_map.get(&addr) {
            let name = p
                .strings
                .get(&ci.name_id)
                .cloned()
                .unwrap_or_else(|| format!("unknown@{addr:#x}"));
            *class_hist.entry(name).or_insert(0) += 1;
        }
    }

    let mut unique_roots: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for &a in &p.gc_root_addrs {
        unique_roots.insert(a);
    }

    print!("{{");
    print!(r#""id_size":{}"#, p.id_size);
    print!(r#","format":"{}""#, p.format);
    print!(r#","instances":{}"#, p.instance_count);
    print!(r#","obj_arrays":{}"#, p.obj_array_count);
    print!(r#","prim_arrays":{}"#, p.prim_array_count);
    print!(r#","classes":{}"#, p.class_dump_count);
    print!(r#","gc_roots_total":{}"#, p.gc_root_addrs.len());
    print!(r#","strings":{}"#, p.strings.len());

    print!(r#","class_histogram":{{"#);
    let mut first = true;
    for (name, count) in &class_hist {
        if !first {
            print!(",");
        }
        let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
        print!(r#""{escaped}":{count}"#);
        first = false;
    }
    print!("}}");

    println!("}}");
    Ok(())
}

/// Parse an object address as written by MAT, a log line, or `@objectAddress`:
/// `0x`-prefixed or bare hex. Rejects anything else rather than guessing.
fn parse_object_address(s: &str) -> anyhow::Result<u64> {
    let t = s.trim();
    let hex = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u64::from_str_radix(hex, 16)
        .map_err(|e| anyhow::anyhow!("'{s}' is not a hex object address: {e}"))
}

/// Why `heap inspect` could not read values, in each case. Returned as the
/// `fields_note` so the caller reports a reason instead of an empty object.
const NO_OFFSETS_NOTE: &str = "this cache has no object-offset table (it predates offset \
     capture). Re-analyze the dump, or pass --build-offsets (one pass-1 scan).";
const COMPRESSED_NOTE: &str = "the dump is compressed (gzip/zip), so record offsets are not \
     directly seekable; uncompress it and re-analyze to read fields.";

/// Read one object's contents straight out of the dump and render them as a JSON
/// object (or, for an array, an element list). See `objread` for why this is a
/// seek rather than a rescan.
///
/// Returns `(fields, address, note)`. `fields` is `None` — with `note` saying
/// why — whenever the values cannot be read, so the caller reports the reason
/// instead of quietly printing an empty object.
/// How far `heap inspect` may follow references, and how many extra objects
/// that may pull in.
///
/// References are *not* expanded by default: one object's graph is unbounded,
/// and a recursive dump of it would be both enormous and slow. `--depth N`
/// opts in, bounded by `budget` so a single inspect cannot walk the heap.
#[derive(Clone, Copy)]
struct Expand<'a> {
    /// Levels of references still allowed to expand.
    depth: u32,
    /// Objects left that expansion may pull in, shared across the whole tree.
    budget: &'a std::cell::Cell<usize>,
}

impl<'a> Expand<'a> {
    /// Take one slot from the budget; `None` when depth or budget is exhausted.
    fn take(self) -> Option<Expand<'a>> {
        let left = self.budget.get();
        if self.depth == 0 || left == 0 {
            return None;
        }
        self.budget.set(left - 1);
        Some(Expand {
            depth: self.depth - 1,
            budget: self.budget,
        })
    }
}

/// How many objects `--depth` may pull in beyond the one asked for.
const EXPAND_BUDGET: usize = 200;

fn inspect_fields(
    dump: &str,
    sess: &hprof_analyzer::cache::CachedSession,
    class_idx: &[u32],
    idx: usize,
    build_offsets: bool,
    depth: u32,
) -> anyhow::Result<(Option<serde_json::Value>, Option<String>, Option<String>)> {
    use hprof_analyzer::objread;
    let kind = sess.pass1.kind.get(idx).copied().unwrap_or(0);

    // 1. The object-offset table. Present on any cache this version wrote.
    let mut offsets = sess.cache.read_hprof_offsets()?;
    if offsets.is_none() && build_offsets {
        eprintln!("[hprof] offsets.bin missing; building it (one pass-1 scan of the dump)…");
        let src = hprof_analyzer::HprofSource::from(dump);
        let p1 = hprof_analyzer::Pass1::run(&src, true)?;
        sess.cache.write_hprof_offsets(&p1.hprof_offsets)?;
        drop(p1);
        offsets = sess.cache.read_hprof_offsets()?;
    }
    let Some(offsets) = offsets else {
        return Ok((None, None, Some(NO_OFFSETS_NOTE.into())));
    };

    // 2. Class objects have no HPROF record (pass 1 records offset 0 for them).
    if kind == 3 {
        return Ok((
            None,
            None,
            Some("this object is a class object; it has no HPROF record to decode".into()),
        ));
    }
    let offset = offsets.get(idx).copied().unwrap_or(0);
    if offset == 0 {
        return Ok((
            None,
            None,
            Some("no HPROF record offset recorded for this object".into()),
        ));
    }

    // 3. Offsets index the decompressed stream; that is a file offset only for
    //    an uncompressed dump. Refuse rather than silently rescan a gzip stream.
    let path = std::path::Path::new(dump);
    if !objread::is_seekable(path)? {
        return Ok((None, None, Some(COMPRESSED_NOTE.into())));
    }

    let budget = std::cell::Cell::new(EXPAND_BUDGET);
    let expand = Expand {
        depth,
        budget: &budget,
    };
    if kind == 0 {
        inspect_instance(dump, path, sess, class_idx, offset, &offsets, expand)
    } else {
        inspect_array(dump, path, sess, class_idx, offset, &offsets, expand)
    }
}

/// Render a plain instance's fields.
///
/// A field whose value is a reference to a `java.lang.String` also carries the
/// decoded text: without it the most interesting field of most objects (the
/// string it holds) reads as an opaque `byte[]` the caller has to chase by hand.
fn inspect_instance(
    dump: &str,
    path: &std::path::Path,
    sess: &hprof_analyzer::cache::CachedSession,
    class_idx: &[u32],
    offset: u64,
    offsets: &[u64],
    expand: Expand<'_>,
) -> anyhow::Result<(Option<serde_json::Value>, Option<String>, Option<String>)> {
    use hprof_analyzer::objread;
    let Some((addr, _class_addr, fields)) = objread::read_instance_at(
        path,
        offset,
        &sess.pass1.class_map,
        &sess.pass1.strings,
        sess.pass1.id_size as usize,
    )?
    else {
        return Ok((
            None,
            None,
            Some("no INSTANCE_DUMP record at the recorded offset".into()),
        ));
    };

    // A subclass field may shadow an inherited one of the same simple name;
    // qualify those with their declaring class so none is lost.
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for f in &fields {
        *counts.entry(f.name.as_str()).or_insert(0) += 1;
    }
    let mut map = serde_json::Map::new();
    for f in &fields {
        let key = if counts[f.name.as_str()] > 1 {
            format!("{}.{}", f.owner.replace('/', "."), f.name)
        } else {
            f.name.clone()
        };
        let v = match &f.value {
            objread::FieldValue::Prim(v) => v.clone(),
            objread::FieldValue::Null => serde_json::Value::Null,
            objread::FieldValue::Ref(a) => ref_json(*a, sess, class_idx, dump, offsets, expand),
        };
        map.insert(key, v);
    }
    // Inspecting a String itself should show the string, not just its `value` field.
    if let Some((text, full_len, truncated)) = string_text(dump, sess, offsets, addr) {
        map.insert("@text".into(), serde_json::json!(text));
        if truncated {
            map.insert("@text_length".into(), serde_json::json!(full_len));
        }
    }
    Ok((
        Some(serde_json::Value::Object(map)),
        Some(format!("0x{addr:x}")),
        None,
    ))
}

/// Render an array's elements, capped at `objread::MAX_ARRAY_ELEMENTS`.
fn inspect_array(
    dump: &str,
    path: &std::path::Path,
    sess: &hprof_analyzer::cache::CachedSession,
    class_idx: &[u32],
    offset: u64,
    offsets: &[u64],
    expand: Expand<'_>,
) -> anyhow::Result<(Option<serde_json::Value>, Option<String>, Option<String>)> {
    use hprof_analyzer::objread;
    let Some(arr) = objread::read_array_at(
        path,
        offset,
        sess.pass1.id_size as usize,
        0,
        objread::MAX_ARRAY_ELEMENTS,
    )?
    else {
        return Ok((
            None,
            None,
            Some("no array record at the recorded offset".into()),
        ));
    };
    let mut o = serde_json::Map::new();
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
                    objread::FieldValue::Ref(a) => {
                        ref_json(*a, sess, class_idx, dump, offsets, expand)
                    }
                })
                .collect(),
        ),
    );
    if arr.truncated() {
        o.insert("@truncated".into(), serde_json::json!(true));
    }
    Ok((
        Some(serde_json::Value::Object(o)),
        Some(format!("0x{:x}", arr.addr)),
        None,
    ))
}

/// The slash-form name of the class object at `class_addr` (the form
/// `pass1::strings` holds; callers dot it for display).
fn class_name_at(sess: &hprof_analyzer::cache::CachedSession, class_addr: u64) -> Option<String> {
    let ci = sess.pass1.class_map.get(&class_addr)?;
    sess.pass1.strings.get(&ci.name_id).cloned()
}

/// Render an object reference as `{"@ref", "@index", "@class"}` — the target's
/// address plus its dense index (so it can be fed back to `heap inspect`) —
/// never a recursive expansion. Adds `@text` when the target is a
/// `java.lang.String`, so a string-valued field reads as text.
fn ref_json(
    addr: u64,
    sess: &hprof_analyzer::cache::CachedSession,
    class_idx: &[u32],
    dump: &str,
    offsets: &[u64],
    expand: Expand<'_>,
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
    if let Some((text, full_len, truncated)) = string_text(dump, sess, offsets, addr) {
        o.insert("@text".into(), serde_json::json!(text));
        if truncated {
            o.insert("@text_length".into(), serde_json::json!(full_len));
        }
    }
    // `--depth`: follow the reference into the target's own record, so a field
    // that holds an object reads as that object instead of as an address. The
    // shared budget bounds how far one inspect can walk.
    if let Some(child) = expand.take() {
        if let Some(rendered) = expand_ref(addr, sess, class_idx, dump, offsets, child) {
            o.insert("@fields".into(), rendered);
        }
    }
    serde_json::Value::Object(o)
}

/// Render the object a reference points at, for `--depth`. `None` when the
/// target has no readable record — a class object, or an address the cache does
/// not know — so the caller keeps the plain address instead of inventing one.
fn expand_ref(
    addr: u64,
    sess: &hprof_analyzer::cache::CachedSession,
    class_idx: &[u32],
    dump: &str,
    offsets: &[u64],
    expand: Expand<'_>,
) -> Option<serde_json::Value> {
    let i = sess.index_of_addr(addr)?;
    if sess.pass1.kind.get(i).copied().unwrap_or(0) == 3 {
        return None;
    }
    let offset = *offsets.get(i)?;
    if offset == 0 {
        return None;
    }
    let path = std::path::Path::new(dump);
    let rendered = if sess.pass1.kind.get(i).copied().unwrap_or(0) == 0 {
        inspect_instance(dump, path, sess, class_idx, offset, offsets, expand)
    } else {
        inspect_array(dump, path, sess, class_idx, offset, offsets, expand)
    };
    rendered.ok().and_then(|(v, _, _)| v)
}

/// Decode the `java.lang.String` at `addr` into `(text, full_len, truncated)`.
///
/// `None` for anything that is not a String, or whose bytes cannot be reached —
/// a String we cannot read must not fail the whole `inspect`.
///
/// Covers both layouts: Java 9+ compact strings (`byte[] value` + `byte coder`,
/// 0 = LATIN1, 1 = UTF-16) and pre-9 (`char[] value` + `int offset` + `int count`).
fn string_text(
    dump: &str,
    sess: &hprof_analyzer::cache::CachedSession,
    offsets: &[u64],
    addr: u64,
) -> Option<(String, u64, bool)> {
    use hprof_analyzer::objread;
    use hprof_analyzer::types::HprofType;

    let path = std::path::Path::new(dump);
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
fn full_char_len(
    ty: hprof_analyzer::types::HprofType,
    coder: i64,
    arr_count: u64,
    jcount: Option<i64>,
) -> u64 {
    use hprof_analyzer::types::HprofType as T;
    match ty {
        T::Byte if coder == 1 => arr_count / 2,
        T::Byte => arr_count,
        T::Char => jcount.map(|c| c.max(0) as u64).unwrap_or(arr_count),
        _ => arr_count,
    }
}

/// Human name for an array's element type.
fn type_name(ty: hprof_analyzer::types::HprofType) -> &'static str {
    use hprof_analyzer::types::HprofType as T;
    match ty {
        T::Object => "object",
        T::Boolean => "boolean",
        T::Char => "char",
        T::Float => "float",
        T::Double => "double",
        T::Byte => "byte",
        T::Short => "short",
        T::Int => "int",
        T::Long => "long",
    }
}

/// One-line rendering of a field value for the non-JSON output.
fn render_field(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(o) if o.contains_key("@ref") => {
            let r = o.get("@ref").and_then(|x| x.as_str()).unwrap_or("?");
            match (
                o.get("@class").and_then(|x| x.as_str()),
                o.get("@index").and_then(|x| x.as_u64()),
            ) {
                (Some(c), Some(i)) => format!("{c} @ {r} (index {i})"),
                _ => format!("ref {r}"),
            }
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::Parser;

    /// `@text_length` must mean *characters* on every path: a UTF-16 `byte[]`
    /// holds two bytes per character, and a pre-9 `char[]` may be shared, so the
    /// String's own `count` — not the backing array's length — is the answer.
    #[test]
    fn full_char_len_halves_utf16_and_prefers_the_strings_own_count() {
        use hprof_analyzer::types::HprofType::{Byte, Char};
        // Java 9+ LATIN1: one byte per character.
        assert_eq!(full_char_len(Byte, 0, 7, None), 7);
        // Java 9+ UTF-16: two bytes per character.
        assert_eq!(full_char_len(Byte, 1, 14, None), 7);
        // Pre-9: the String's own `count` wins over a shared char[]'s length.
        assert_eq!(full_char_len(Char, 0, 1000, Some(3)), 3);
        // ...and falls back to the array when the dump records no `count`.
        assert_eq!(full_char_len(Char, 0, 12, None), 12);
    }

    #[test]
    fn query_path_depth_default_is_5() {
        let cli = Cli::try_parse_from(["hprof-analyzer", "heap.hprof"]).unwrap();
        assert_eq!(cli.query_path_depth, DEFAULT_QUERY_PATH_DEPTH);
        assert_eq!(cli.query_path_depth, 5);
    }

    #[test]
    fn query_path_depth_custom() {
        let cli = Cli::try_parse_from(["hprof-analyzer", "heap.hprof", "--query-path-depth", "3"])
            .unwrap();
        assert_eq!(cli.query_path_depth, 3);
    }

    #[test]
    fn query_path_depth_zero_errors() {
        let err = Cli::try_parse_from(["hprof-analyzer", "heap.hprof", "--query-path-depth", "0"])
            .err()
            .expect("zero depth must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("must be > 0"),
            "zero depth must error actionably, got: {msg}"
        );
    }

    #[test]
    fn query_path_depth_non_numeric_errors() {
        let err =
            Cli::try_parse_from(["hprof-analyzer", "heap.hprof", "--query-path-depth", "abc"])
                .err()
                .expect("non-numeric depth must be rejected");
        // clap rejects the non-numeric value at parse time.
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn query_subcommand_query_path_depth_zero_errors() {
        let err = Cli::try_parse_from([
            "hprof-analyzer",
            "query",
            "heap.hprof",
            "--query-path-depth",
            "0",
        ])
        .err()
        .expect("query subcommand zero depth must be rejected");
        assert!(
            err.to_string().contains("must be > 0"),
            "query subcommand zero depth must error actionably: {err}"
        );
    }

    #[test]
    fn parse_query_path_depth_helper() {
        assert_eq!(parse_query_path_depth("5").unwrap(), 5);
        let zero = parse_query_path_depth("0").unwrap_err();
        assert!(zero.contains("must be > 0"), "0 message: {zero}");
        assert!(
            parse_query_path_depth("abc").is_err(),
            "non-numeric must error"
        );
    }
}
