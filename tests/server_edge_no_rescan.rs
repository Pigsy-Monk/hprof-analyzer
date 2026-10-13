//! Delivery-2 evidence, at the routing decision: an edge query is answered from
//! a cache-assembled session under the server's default rescan policy, and
//! refused the moment the session has no edges — the negative control that
//! proves the answer really came from the edges rather than from a hatch that
//! still rescans.
//!
//! This drives `run_query_json_policy` directly, which is where the decision
//! lives (`edges_servable`). The HTTP layer on top of it is covered by
//! `tests/cli_server.rs`; going through a real server process here would only
//! add a port, a second process and a temp directory to the same assertion. The
//! end-to-end form was checked by hand as well — a default-policy server started
//! on a dump whose cache has `graph.bin` answers `SELECT @outbounds FROM
//! java.lang.String LIMIT 5` with real addresses (identical to `heap query`'s),
//! and the same server on the same dump with `graph.bin` deleted answers
//! `{"kind":"rescan_refused"}`.
//!
//! Gated on the philosophers fixture being hydrated, like the other CLI tests.

use std::path::{Path, PathBuf};

use hprof_analyzer::opts::AnalyzeOptions;
use hprof_analyzer::query::run::ReplCache;

const OQL: &str = "SELECT @outbounds FROM java.lang.String LIMIT 5";

fn staged_fixture(tag: &str) -> Option<(PathBuf, PathBuf)> {
    let src =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dump_4_philosophers.hprof");
    match std::fs::metadata(&src) {
        Ok(m) if m.len() >= 1024 => {}
        _ => return None,
    }
    let dir = std::env::temp_dir().join(format!("hprof-edge-srv-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let dump = dir.join("dump.hprof");
    std::fs::copy(&src, &dump).unwrap();
    Some((dir, dump))
}

/// Run the query against a warm session under the default rescan policy
/// (`no_rescan = true`) and return the response as JSON.
fn ask(dump: &Path, cache: &mut Option<ReplCache>) -> serde_json::Value {
    hprof_analyzer::query::server::run_query_json_policy(
        dump.to_str().unwrap(),
        OQL,
        4,
        false,
        cache,
        None,
        None,
        true,
    )
}

#[test]
fn no_rescan_answers_outbounds_from_the_cache_edges_and_refuses_without_them() {
    let Some((dir, dump)) = staged_fixture("outbounds") else {
        return;
    };

    // A Graph-mode cache, i.e. one that has `graph.bin`.
    hprof_analyzer::analyze_with_cache(
        &dump,
        &AnalyzeOptions::default(),
        hprof_analyzer::cache::CacheMode::Graph,
        |_| {},
    )
    .expect("analyze_with_cache");

    // Warm session, exactly as `serve.rs::try_warm_start` assembles it.
    let warm = hprof_analyzer::load_query_cache(&dump)
        .expect("load_query_cache")
        .expect("a Graph-mode cache must assemble a session");
    assert!(
        warm.edges.has_forward(),
        "the warm session must carry the edges (got {})",
        warm.edges.summary()
    );

    let mut cache = Some(warm);
    let answered = ask(&dump, &mut cache);
    let text = answered.to_string();
    assert_eq!(answered["ok"], serde_json::json!(true), "{text}");
    assert!(
        !text.contains("rescan_refused"),
        "under the default rescan policy an edge query must be answered from the \
         cache, not refused: {text}"
    );
    assert!(
        !text.contains("the full analysis pipeline"),
        "the resident path must have served the edges, not errored: {text}"
    );
    // Not just "some rows": the values must be real objects.
    let rows = answered["result"]["rows"].as_array().expect("rows");
    assert!(!rows.is_empty(), "the edge query must produce rows: {text}");
    assert!(
        rows[0][0].to_string().contains("obj_ref"),
        "an edge row must be a real object reference, not Null: {text}"
    );

    // ── Negative control ──────────────────────────────────────────────────────
    // Same query, same server policy, same session — with the edges removed, as
    // a cache written without `--with-graph` (or one whose `graph.bin` is gone)
    // would be. It must now be refused, which is what shows the arm above was
    // answered *from the edges*.
    let mut stripped = Some(
        ReplCache::build(
            &hprof_analyzer::source::HprofSource::from(dump.to_str().unwrap()),
            false,
        )
        .expect("ReplCache::build"),
    );
    stripped.as_mut().unwrap().edges = Default::default();
    assert!(stripped.as_ref().unwrap().edges.is_empty());

    let refused = ask(&dump, &mut stripped);
    let text = refused.to_string();
    assert!(
        text.contains("rescan_refused"),
        "without edges the query has nothing to answer from and must be \
         refused under the default rescan policy; got: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
