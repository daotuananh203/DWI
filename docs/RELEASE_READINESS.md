# v1.0 Engineering Release-Readiness Checklist

This is evidence tracking, not a release authorization. No tag, push, publish,
or final installer release is performed by the hardening batch.

- [ ] Normal tests green; skipped tests documented and platform-justified.
- [ ] MCP cardinality, message-size, pagination, and resource-limit tests green.
- [ ] Desktop cancellation/close and CLI regressions green.
- [ ] Safety/adversarial suite green with no unresolved P0/P1 safety bug.
- [ ] Fault injection and crash/restart reconciliation evidence reviewed.
- [ ] Windows path matrix reviewed on a supported Windows environment.
- [ ] Real-machine read-only evaluation run and manually inspected.
- [ ] Synthetic benchmark results recorded without private paths.
- [ ] Package build is reproducible; EN/VI resources and entry points included.
- [ ] Clean-environment install/import/CLI/Desktop/MCP smoke green.
- [ ] No permanent delete, telemetry, cloud, upload, or default network listener.
- [ ] Diagnostics are local, deterministic, redacted, and free of capability/proof material.
- [ ] Runtime dependencies and licenses reviewed.
- [ ] Version source is consistent across package, CLI, Desktop, and MCP.
- [ ] Public repository hygiene, documentation, installer validation, and release steps reviewed.

## Skipped-test audit

Current skips are platform capability conditions, not hidden safety failures:

- Windows mutation/application integration tests require `os.name == "nt"`.
- Symlink/reparse tests skip only when the host cannot create the required
  fixture; Windows-capable CI/manual evaluation must run them.
- No skipped test authorizes mutation or weakens the deterministic policy path.

## Existing fault/recovery evidence

The frozen mutation/application suite already exercises claim failure, orphan
claims, committed-but-unjournaled quarantine/restore, partial multi-item
execution, unexpected item failure, journal corruption, replay, and idempotent
reconciliation. Any release claim remains limited to those tested filesystem
semantics; this checklist does not claim crash-proof atomic transactions.

## Mandatory Batch 2 release blockers

The following are intentionally deferred and are not started by the Batch 1/2
freeze:

- Package artifact build verification is pending because the current environment
  lacks the `build` package.
- Wheel/sdist installation in a clean environment is not yet verified.
- Windows installer build/validation is incomplete.
- Signing strategy/status is unresolved.
- Open-source licensing and dependency-license review are incomplete.
- Final public EN/VI documentation is incomplete.
- Final public-release audit is incomplete.
- Direct `ScanLimits(0)` remains an immediate bounded termination while MCP
  rejects zero; this conservative consistency debt may be resolved or
  documented in Batch 2.
