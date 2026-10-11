//! Delivery evidence for "a cache-assembled query session can reach the edges".
//!
//! The whole point of putting the reference edges into `ReplCache` is that a
//! server warmed from disk answers `@inbounds` / `@outbounds` / `path()` without
//! re-reading the dump. Two things therefore have to be true, and neither is
//! "it looks about right":
//!
//! 1. **Identity, not similarity.** The edges a session gets from `graph.bin`
//!    (source (b), `CacheDir::read_query_cache`) must be the same edges the
//!    pipeline produces live (source (a), `ReplCache::build`) — same offsets,
//!    same targets, element for element.
//! 2. **The negative control.** With `graph.bin` gone the cache must load *no*
//!    edges, so the query path has something observably different to fall back
//!    on. Only the positive direction would not prove anything: a reader that
//!    silently returns empty arrays would pass it.
//!
//! Gated on the philosophers fixture being fully hydrated, matching the other
//! CLI tests; unhydrated LFS pointers make the test a no-op.

use std::path::{Path, PathBuf};

use hprof_analyzer::cache::CacheMode;
use hprof_analyzer::opts::AnalyzeOptions;
use hprof_analyzer::query::run::ReplCache;
use hprof_analyzer::run_oql::FwdTargets;
use hprof_analyzer::source::HprofSource;

/// Copy the committed fixture into a temp dir: the cache lives *next to the
/// dump* (`<dump>.hprof-cache/<hash>`), so writing it against the committed
/// fixture would litter the checkout.
fn staged_fixture(tag: &str) -> Option<(PathBuf, PathBuf)> {
    let src =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dump_4_philosophers.hprof");
    match std::fs::metadata(&src) {
        Ok(m) if m.len() >= 1024 => {}
        _ => return None,
    }
    let dir = std::env::temp_dir().join(format!("hprof-edge-cache-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let dump = dir.join("dump.hprof");
    std::fs::copy(&src, &dump).unwrap();
    Some((dir, dump))
}

/// Write a Graph-mode cache for `dump`, i.e. one that has `graph.bin`.
fn write_graph_cache(dump: &Path) {
    let opts = AnalyzeOptions::default();
    hprof_analyzer::analyze_with_cache(dump, &opts, CacheMode::Graph, |_| {})
        .expect("analyze_with_cache");
}

/// The cache directory a dump's cache lives in, so the test can delete a file
/// out of it for the negative control.
fn graph_bin_of(dump: &Path) -> PathBuf {
    let cache = hprof_analyzer::cache::CacheDir::for_dump(dump).expect("cache dir");
    cache.path.join("graph.bin")
}

#[test]
fn cache_edges_equal_pipeline_edges_and_vanish_without_graph_bin() {
    let Some((dir, dump)) = staged_fixture("parity") else {
        return;
    };
    let dump_str = dump.to_str().unwrap();

    write_graph_cache(&dump);
    let graph_bin = graph_bin_of(&dump);
    assert!(
        graph_bin.exists(),
        "Graph mode must have written graph.bin at {graph_bin:?}"
    );

    // ── Source (b): the disk cache ────────────────────────────────────────────
    let cached = hprof_analyzer::load_query_cache(&dump)
        .expect("load_query_cache")
        .expect("a Graph-mode cache must assemble a session");
    assert!(
        cached.edges.has_forward(),
        "cache-assembled session must carry the forward CSR (got {})",
        cached.edges.summary()
    );
    // The inbound block CSR is deliberately NOT asserted here any more: it is
    // no longer part of what a warm session carries at all. Nothing in the query
    // path ever read it — `compute_dominators` runs in the pipeline, on the live
    // blocks — so holding it resident cost 5.41 GiB on the 44 GB dump for
    // nothing, and `ReplCacheEdges` dropped it (see the type's docs). `@inbounds`
    // is answered by transposing the forward CSR, exactly as the escalated path
    // does. Asserting its absence would only re-state that; the forward half
    // asserted here and compared below is the surviving observable contract.

    // ── Source (a): the pipeline, live ────────────────────────────────────────
    let live = ReplCache::build(&HprofSource::from(dump_str), false).expect("ReplCache::build");
    assert!(
        live.edges.has_forward(),
        "ReplCache::build must carry the forward CSR it moved out of the live graph"
    );

    // ── Identity ──────────────────────────────────────────────────────────────
    assert_eq!(
        cached.edges.fwd_off, live.edges.fwd_off,
        "forward offsets from graph.bin must equal the pipeline's"
    );
    let total = cached.edges.forward_edges();
    assert_eq!(total, live.edges.forward_edges());
    assert!(total > 0, "the fixture must actually have reference edges");
    // `fwd_tgt` is no longer an indexable array: a warm session holds a
    // `FwdTgtStore`, which for a chunked `graph.bin` decodes chunks on demand
    // instead of keeping ~9 GB of `u32` resident. `copy_range` is the read the
    // production consumers use (`build_retained_edges`), so comparing through it
    // checks the same path a query would take — including the on-disk decode
    // and its per-chunk delta base — rather than a test-only accessor.
    let mut cached_tgt: Vec<u32> = Vec::new();
    let mut live_tgt: Vec<u32> = Vec::new();
    cached
        .edges
        .fwd_tgt
        .copy_range(0, total, &mut cached_tgt)
        .expect("read the graph.bin forward targets");
    live.edges
        .fwd_tgt
        .copy_range(0, total, &mut live_tgt)
        .expect("read the pipeline's forward targets");
    assert_eq!(cached_tgt.len(), total, "graph.bin returned a short array");
    assert_eq!(live_tgt.len(), total, "the pipeline returned a short array");
    for i in 0..total {
        assert_eq!(
            cached_tgt[i], live_tgt[i],
            "forward target {i} differs between graph.bin and the pipeline"
        );
    }

    // ── Negative control: no graph.bin, no edges ──────────────────────────────
    std::fs::remove_file(&graph_bin).expect("remove graph.bin");
    let after =
        hprof_analyzer::load_query_cache(&dump).expect("load_query_cache without graph.bin");
    let after = after.expect("the Full cache is still valid without graph.bin");
    assert!(
        after.edges.is_empty(),
        "without graph.bin the session must carry NO edges, else the fall-back \
         path can never be observed to differ (got {})",
        after.edges.summary()
    );

    // The rest of the session must still be assembled: dropping the edges is a
    // degradation of that one capability, not of the warm start itself.
    assert_eq!(
        after.n, cached.n,
        "object count must survive losing graph.bin"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
