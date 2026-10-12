# The resident server and the graph cache

hprof-analyzer runs two ways. One is a batch job that reads a dump once and
writes a report. The other is a **server** that keeps the analysis resident and
answers questions against it. The server is the interesting one: it is the only
way to ask ad-hoc questions of a multi-GB dump without paying the pipeline
again, and the graph cache is what makes starting it cheap.

## Two ways to run

| | CLI batch | `server` |
|---|---|---|
| Command | `hprof-analyzer dump.hprof report.html` | `hprof-analyzer server dump.hprof` |
| Shape | one process, one pass, one output | long-lived, loopback HTTP, many questions |
| Output | HTML / JSON / Markdown report | OQL results, report sections, JSON |
| Answers follow-ups | no — re-run and re-parse | yes — the analysis stays resident |
| Memory | pipeline peak, then exit | stays resident for the session |

Use the CLI to produce a report you will hand to someone. Use the server when you
want to keep asking the dump things — "how many of these are there", "who
references this object", "what is this field's value" — without re-reading it.

## The standard workflow

```
# Step 1: build the cache — one pass over the dump, writes <dump>.hprof-cache/
hprof-analyzer heap load --with-graph dump.hprof

# Step 2: start the server on the same dump
hprof-analyzer server dump.hprof
```

`heap load --with-graph` on the **44 GB** dump: **46m46s**, peak **26.43 GiB**.
It writes the report, the pass-1 tables, the six dense arrays and `graph.bin`
(the reference edges) into `<dump>.hprof-cache/<hash>/` next to the dump.

The server then **warm-starts from that cache in 57.3 s** — no pipeline, no
second parse of the dump.

Without `--with-graph` the cache has no edges, so a cache-backed session cannot
answer `@inbounds` / `@outbounds` / `path()`, and the server falls back to
re-reading the dump (or refuses, under `--no-rescan`). Always build the graph.

## Warm start does not happen on its own

**Starting the server does not start the analysis.** `try_warm_start()` lives
inside `ensure_analysis()`, which is called from the HTTP handlers — it is
triggered by **`POST /analyze`** (or by a `GET /report`). Until one of those
arrives, the server sits at `not_started` with a few MB of RSS.

```
# this is what actually warms the session
curl -X POST http://127.0.0.1:7070/analyze
curl    http://127.0.0.1:7070/status      # → {"status":"ready"} when done
```

If you start the server and query nothing, you will see a process using almost
no memory and conclude the cache did not work. It did — nothing asked it to
load yet.

## The log line that tells you it worked

A warm start prints exactly one line to stderr:

```
hprof-analyzer server: warm start from disk cache (<dump>) — edges: forward=<N> edges (on-disk chunks)
```

Read the parenthetical. **It must say `on-disk chunks`.** The forward-target
array is stored chunked in `graph.bin` and decoded a block at a time; that is
what keeps the resident set small. If the line says `resident` instead, the
whole edge array was materialised into memory and the memory model below no
longer holds — that is a regression, not a variant.

If the line does not appear at all, the cache was missing or undecodable and the
server silently ran the full pipeline instead.

## Memory

On the **44 GB** dump, on a **32 GB** machine:

| | resident |
|---|---|
| server, steady state | **21.0 GiB** |
| server, peak | **27.9 GiB** |

That is ~0.48× the dump for the steady state and ~0.63× at the peak. The peak is
not at startup — it is when a query pulls in something the resident cache does
not hold, and the server re-reads the dump *while the analysis stays resident*,
so the cost is roughly additive. `--no-rescan` turns those queries into a
`rescan_refused` response instead of letting them push the process over the
edge.

## How the edges are stored

`graph.bin`'s `fwd_tgt` — the forward edge targets — is **not** one flat array.
It is a chunked container: **1,000,000 values per chunk, each chunk an
independent zstd frame with its own delta base** (the value immediately
preceding that chunk, so any single chunk decodes on its own). On the 44 GB
dump the CSR holds 2.3 billion edges, i.e. **2,326 chunks**, and the container
costs +0.45% on disk versus one frame. Decoding one chunk takes 2.9–9.2 ms
(mean 6.7 ms).

Reads go through a random-access reader that keeps only the most recently
decoded chunk — one 4 MB raw buffer plus one compressed frame at a time. The
whole 8.87 GB array is never resident, which is the single reason the steady
state fits in 21 GiB.

The other half of the CSR, `fwd_off` (the row pointers), *is* kept resident:
2.3 GiB, and every edge lookup needs it.

## What is fast, what is slow

The chunked store makes **point** queries cheap and **class-level** queries
expensive, and the gap is large enough to plan around.

| query | time | why |
|---|---|---|
| `SELECT s.value FROM java.lang.String s LIMIT 5` | **0.118 s** | reads fields by `seek`ing into the dump via `offsets.bin` — no rescan |
| point query (one object's edges) | **~7 ms** | touches one or two chunks |
| `SELECT @outbounds FROM java.lang.String LIMIT 5` | **42.87 s** | matches millions of objects scattered across the whole CSR → every chunk is read |
| `SELECT @inbounds FROM java.lang.String LIMIT 5` | **150.86 s** | same, plus a transpose of the forward CSR |

A class-level `@outbounds` / `@inbounds` query is not slow because the store is
chunked — it is slow because the answer genuinely needs the whole edge array.
Asking for one object's edges, or reading a field value, is milliseconds.

Reading field values is the fast path worth remembering: `offsets.bin` records
each object's byte offset in the `.hprof`, so the resident session seeks
straight to the record instead of re-scanning the dump.
