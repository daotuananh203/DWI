# v1.0 Read-only Evaluation Evidence

`python -m dwi evaluate-readonly` runs the deterministic System Intelligence
scan against the current Windows machine with no cleanup, quarantine, journal
creation, or mutation path. Use `--root PATH` for a bounded local fixture and
`--max-seconds`, `--max-nodes`, and `--max-files` to reduce the shared Scan
Safety Gate budgets. Network scanning remains denied by default.

The command emits structured counts and status categories only. It does not
persist findings, export personal paths, upload data, or include private
machine reports in the repository.

Example disposable evaluation:

```text
python -m dwi evaluate-readonly --root PATH --max-seconds 10 --max-nodes 2000 --max-files 2000
```

Evaluation record template:

| Field | Value |
|---|---|
| DWI version / commit | Fill at evaluation time |
| OS / Python | Fill at evaluation time |
| Dataset or fixture | Disposable fixture or local machine, explicitly stated |
| Network permission | Denied unless explicitly documented |
| Limits | Seconds, nodes, files |
| Termination | Completed, partial, or limit reason |
| Roots | Counts/statuses only; do not commit private paths |
| Findings | Count and manually inspectable safety observations |
| Performance | Wall clock and node/file counts |
| Failures | Permission/partial/reparse observations |
| Mutation | Must remain `false` |

## Batch 2 RC validation record

The RC validation run used the local Windows host with network scanning
disabled and the hard limits below. Only aggregate results are recorded;
private roots and findings are intentionally omitted.

| Field | Result |
|---|---|
| Version | `1.0.0rc1` |
| Python / platform | CPython 3.12.8 / Windows 10 |
| Limits | 5 seconds, 2,000 nodes, 2,000 files |
| Termination | `node_limit` with a partial bounded result |
| Nodes / files observed | 2,000 / 819 |
| Network allowed | `false` |
| Mutation started | `false` |
| Observation failures | 1; conservative partial result |
| Root status | 12 skipped, 1 partial; no mutation path entered |
