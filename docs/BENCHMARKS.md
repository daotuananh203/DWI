# v1.0 Synthetic Benchmarks

Run bounded synthetic scan and MCP pagination benchmarks with:

```text
python -m dwi benchmark
python -m dwi benchmark --scale 10 --scale 100
```

The harness creates disposable temporary fixtures, never uses real user data,
and reports wall-clock duration, peak memory where available, node/file counts,
finding counts, known bytes, termination reason, and pagination duration. Normal
unit tests use only tiny scales; performance thresholds are not CI pass/fail
criteria because host speed varies.

## Batch 2 RC validation record

The disposable synthetic benchmark completed on the RC without private source
or user paths in the recorded metrics:

| Scale | Files | Nodes | Findings | Duration (ms) | Peak memory (bytes) | Termination |
|---:|---:|---:|---:|---:|---:|---|
| 10 | 10 | 51 | 10 | 100.667 | 84,180 | completed |
| 100 | 100 | 501 | 100 | 929.227 | 465,423 | completed |
| 500 | 500 | 2,501 | 500 | 4,489.552 | 2,208,792 | completed |

MCP pagination completed in 1, 4, and 20 pages respectively for the 10, 100,
and 500 synthetic scales, using the benchmark's page limit of 50. These are
evaluation observations, not release performance guarantees.
