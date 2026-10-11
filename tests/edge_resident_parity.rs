//! Delivery-2 parity: an edge query answered from a warm session must produce
//! the SAME rows as the escalated re-scan.
//!
//! Answering without re-reading the dump is only half the claim. The other half
//! is that the answer is the same one — a warm path that returns the right row
//! *count* with `Null` values where the escalated path returns addresses would
//! be worse than the refusal it replaced, because it would look like it worked.
//! This test pins the two paths against each other row for row.
//!
//! Gated on the philosophers fixture being hydrated, like the other CLI tests.

use std::path::Path;

use hprof_analyzer::opts::AnalyzeOptions;
use hprof_analyzer::query::run::ReplCache;
use hprof_analyzer::source::HprofSource;

fn fixture() -> Option<String> {
    let p = format!(
        "{}/tests/fixtures/dump_4_philosophers.hprof",
        env!("CARGO_MANIFEST_DIR")
    );
    match std::fs::metadata(&p) {
        Ok(m) if m.len() >= 1024 => Some(p),
        _ => None,
    }
}

fn plan_of(
    oql: &str,
) -> (
    hprof_analyzer::query::ast::Query,
    hprof_analyzer::query::plan::QueryPlan,
) {
    let q = hprof_analyzer::query::parse::parse(oql).expect("parse");
    let plan = hprof_analyzer::query::plan::plan_query(&q, 4).expect("plan");
    let plan = hprof_analyzer::query::optimize::optimize(
        plan,
        &q,
        &hprof_analyzer::query::optimize::SchemaStats::default(),
    );
    (q, plan)
}

/// Render a result's rows as strings so the two paths can be compared without
/// depending on the JSON shape.
fn render(rows: &[Vec<hprof_analyzer::query::model::QueryValue>]) -> Vec<String> {
    rows.iter().map(|r| format!("{r:?}")).collect::<Vec<_>>()
}

#[test]
fn resident_edge_rows_match_the_escalated_rows() {
    let Some(path) = fixture() else { return };
    let oql = "SELECT @outbounds FROM java.lang.String LIMIT 5";

    let cache =
        ReplCache::build(&HprofSource::from(path.as_str()), false).expect("ReplCache::build");
    assert!(
        cache.edges.has_forward(),
        "ReplCache::build must carry the forward CSR"
    );

    let (q, plan) = plan_of(oql);
    let resident = hprof_analyzer::query::run::run_resident_only(&cache, &[(q, plan)], false)
        .expect("resident");

    let opts = AnalyzeOptions::default();
    let escalated =
        hprof_analyzer::run_oql_query(path.as_str(), oql, false, &opts).expect("escalated");

    assert_eq!(resident.len(), 1);
    assert_eq!(escalated.len(), 1);
    assert!(
        escalated[0].error.is_none(),
        "escalated run errored: {:?}",
        escalated[0].error
    );
    assert!(
        resident[0].error.is_none(),
        "resident run errored: {:?}",
        resident[0].error
    );

    let a = render(&resident[0].rows);
    let b = render(&escalated[0].rows);
    assert_eq!(
        a, b,
        "warm-session rows differ from escalated rows for `{oql}`"
    );

    let _ = Path::new(&path);
}
