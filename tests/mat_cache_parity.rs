//! `mat caches`' from-cache fast path must emit byte-identical index files to
//! the full pipeline.
//!
//! This is the gate the cache-reuse commit only *claimed*. Its A/B runs both
//! took the pipeline branch — `load_mat_cache` compared the idom count against
//! `n` instead of `n + 1`, so the fast path never engaged — which made the
//! comparison vacuous. Two real divergences were hiding behind it:
//!
//!   * the forward-CSR offset table reached the emitters in pass 2's
//!     prefix-sum form (`off[i] = start_i`) instead of the post-rescan form
//!     `rescan_outbound` leaves behind (`off[i] = start_{i+1}`), so every
//!     object's outbound row was read one object behind;
//!   * the synthetic `thread → itself` edges never reached the emitters, which
//!     shortened `outbound` and `inbound` and shifted every `cacheEntry` offset
//!     in the main `.index`.
//!
//! The test therefore does two things: it byte-compares all 11 emitted files,
//! and it asserts on the fast path's stderr banner — a comparison that silently
//! falls back to the pipeline proves nothing, which is exactly how the original
//! bug survived.

use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURE: &str = "dump_4_philosophers.hprof";
/// The dump is copied to this name so the emitted files have predictable stems.
const STEM: &str = "dump";
const FILES: &[&str] = &[
    "a2s.index",
    "domIn.index",
    "domOut.index",
    "idx.index",
    "inbound.index",
    "index",
    "o2c.index",
    "o2hprof.index",
    "o2ret.index",
    "outbound.index",
    "threads",
];

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Run `mat caches <dump> <out>` with `env`, returning stderr.
fn run_caches(dump: &Path, out: &Path, report: &Path, env: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hprof-analyzer"));
    cmd.arg("mat")
        .arg("caches")
        .arg(dump)
        .arg(out)
        .arg("--report")
        .arg(report);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("spawn `mat caches`");
    assert!(
        output.status.success(),
        "`mat caches` failed ({:?}):\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn mat_caches_from_cache_matches_the_pipeline() {
    let src = fixture_dir().join(FIXTURE);
    if !src.exists() {
        eprintln!("skip mat_caches_from_cache_matches_the_pipeline: {FIXTURE} absent");
        return;
    }

    let root = std::env::temp_dir().join("hprof_mat_cache_parity");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create temp root");
    let dump = root.join(format!("{STEM}.hprof"));
    std::fs::copy(&src, &dump).expect("copy fixture");

    // The fast path needs a `heap load --with-graph` cache beside the dump.
    let load = Command::new(env!("CARGO_BIN_EXE_hprof-analyzer"))
        .arg("heap")
        .arg("load")
        .arg(&dump)
        .arg("--with-graph")
        .output()
        .expect("spawn `heap load`");
    assert!(
        load.status.success(),
        "`heap load --with-graph` failed:\n{}",
        String::from_utf8_lossy(&load.stderr)
    );

    let (dir_a, dir_b) = (root.join("A"), root.join("B"));
    let stderr_a = run_caches(
        &dump,
        &dir_a,
        &root.join("rA.md"),
        &[("HPROF_MAT_USE_CACHE", "1")],
    );
    run_caches(
        &dump,
        &dir_b,
        &root.join("rB.md"),
        &[("HPROF_MAT_NO_CACHE", "1")],
    );

    // Anti-vacuity: without this the test still passes when `load_mat_cache`
    // bails out and both runs take the pipeline.
    assert!(
        stderr_a.contains("reusing the graph cache"),
        "the from-cache run did not engage the fast path; its stderr was:\n{stderr_a}"
    );

    for name in FILES {
        let a = std::fs::read(dir_a.join(format!("{STEM}.{name}"))).expect("read A");
        let b = std::fs::read(dir_b.join(format!("{STEM}.{name}"))).expect("read B");
        assert_eq!(
            a.len(),
            b.len(),
            "{STEM}.{name}: {} bytes from cache vs {} from the pipeline",
            a.len(),
            b.len()
        );
        assert!(
            a == b,
            "{STEM}.{name}: same length ({} bytes) but different content",
            a.len()
        );
    }
}
