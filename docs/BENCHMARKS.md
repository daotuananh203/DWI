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
