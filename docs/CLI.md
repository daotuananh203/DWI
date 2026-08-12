# CLI usage

The CLI is a presentation adapter over the deterministic engine. It does not
provide arbitrary deletion or raw-path mutation.

```powershell
dwi --version
dwi scan PATH
dwi scan PATH --json
dwi scan-system --root PATH --json
dwi scan-system --json
dwi cleanup PATH --json
```

`scan` analyzes one explicit workspace. `scan-system` discovers approved
developer-storage roots; network paths remain denied unless the caller uses
the explicit `--allow-network` opt-in. Both scanners use finite time, node and
file limits. Partial, failed and denied observations remain visible.

The cleanup CLI presents an engine-generated review. Human confirmation uses
the exact phrase below and is not an agent confirmation mechanism:

```powershell
dwi cleanup PATH --json --confirm-phrase "I reviewed this exact cleanup plan."
```

Cleanup is Quarantine + Journal + Undo. Results are per-item and may be
blocked, partial or reconciliation-required. No command named `delete`,
`remove`, `delete_file` or `restore_to` is provided.

JSON output is local and may contain paths because it is user-facing storage
information. DWI does not upload reports or emit telemetry. Exit behavior and
machine-readable statuses are preserved by the existing CLI adapter; blocked,
partial and recovery failures use distinct nonzero outcomes.

For read-only release evaluation and synthetic benchmarks:

```powershell
dwi evaluate-readonly --max-seconds 5 --max-nodes 2000 --max-files 2000
dwi benchmark
```
