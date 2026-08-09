# DWI v0.5 MCP / Agent Integration

v0.5 exposes DWI through a minimal MCP-compatible JSON-RPC adapter. The MCP
caller is untrusted, even when the server is running on the same machine.

## Transport and dependency boundary

The implementation uses only Python standard-library JSON-RPC handling. It
supports the MCP `initialize`, `tools/list`, and `tools/call` methods over
stdin/stdout. `python -m dwi mcp` and `python -m dwi.mcp` do not open TCP,
HTTP, or cloud listeners. Protocol output is written only to stdout; no debug
logging is written there.

The stdio transport accepts at most 1 MiB per incoming JSON message and emits
at most 1 MiB per response. An oversized line is rejected before JSON/schema
processing, drained without retaining it, and the next complete line remains
usable. Oversized responses return a bounded `RESOURCE_LIMIT` protocol error.

No dependency was added. A future packaged MCP SDK may replace this small
adapter only if it preserves the same schemas and trust boundary.

MCP scan budgets are bounded at the untrusted boundary. The normal defaults
and maximum caller-requestable values are `max_seconds=300.0`,
`max_nodes=100000`, and `max_files=100000`, matching the existing system scan
safety gate. A caller may request a smaller positive finite budget, but cannot
request zero, negative, non-integral integer limits, NaN, Infinity, booleans as
integers, or a value above these hard caps. Invalid values return
`INVALID_REQUEST` before scan logic is invoked; values are not silently
clamped.

Caller collections are bounded before item validation: `dwi_scan_system.roots`
allows at most 32 roots and `dwi_create_cleanup_review.finding_ids` allows at
most 256 IDs. Over-limit collections return `RESOURCE_LIMIT`; malformed item
types return `INVALID_REQUEST`. There is no silent truncation.

## Trust boundary

```text
untrusted MCP JSON request
    -> strict schema validation
    -> local MCP service
    -> in-memory opaque handle store
    -> deterministic scan / policy / application service
    -> internal mutation layer
```

The handle store is server-owned and non-persistent. Every handle contains a
random lookup token, but the token is not authority. The authoritative payload
is held only in memory and is bound to the exact scan, finding IDs, cleanup
session, human confirmation, runtime, or recovery identity that created it.
Unknown, wrong-type, stale, consumed, and cross-session handles fail closed.
Restart creates a new empty store and invalidates all handles, including
execution and recovery authority.

The live handle store has a hard capacity of 256 entries by default. Each
entry's authoritative payload is retained only until its 900-second TTL. Every
issue and lookup opportunistically purges expired entries before proceeding;
capacity exhaustion purges first and then fails closed with `RESOURCE_LIMIT`
without evicting active authority. Expired entries are removed from the live
store, including consumed entries. A bounded payload-free tombstone may be
retained for one TTL to return `STALE_HANDLE`; it never restores authority and
is bounded by the same 256-entry limit.

MCP read models never serialize `TrustedScanContext`, `TrustedSnapshotSet`,
`PlanValidation`, `ExecutionAuthorization`, private proofs, capability objects,
or confirmation objects. Paths may appear in findings and recovery read models
because they are user-visible storage information; paths are never accepted as
mutation targets.

## Tool surface

Read-only tools:

- `dwi_scan_system` and `dwi_scan_root` — engine scan and opaque scan handle.
- `dwi_get_scan_summary` — bounded scan summary.
- `dwi_list_findings` — paginated engine findings and informational finding IDs.
- `dwi_get_finding` — one finding read model.
- `dwi_explain_finding` — deterministic evidence, safety decision, and rule trace.

Cleanup and recovery tools:

- `dwi_create_cleanup_review` — accepts only a scan handle and finding IDs from
  that exact scan; no raw path, risk, action, snapshot, validation, or
  authorization fields.
- `dwi_get_cleanup_review` — returns the immutable engine review read model.
- `dwi_request_cleanup_execution` — returns an execution handle only after
  trusted human confirmation.
- `dwi_execute_cleanup` — consumes one execution handle and calls the existing
  application service with a fresh engine revalidator.
- `dwi_get_execution_status` — returns per-item result reality without tokens.
- `dwi_get_recovery_status` — returns validated recovery read models.
- `dwi_request_undo` — consumes a server-owned recovery handle; no restore
  destination is accepted.

There is deliberately no MCP confirmation tool. The trusted CLI/Desktop
boundary must call the internal `McpService.confirm_from_human_channel` method
with the server-issued human-channel token. An agent-supplied phrase such as
`yes` or `CONFIRM` cannot create `HumanConfirmation`.

Potentially large read lists use a maximum page size of 100 and a default page
size of 50. `dwi_list_findings`, `dwi_get_scan_summary` root observations,
`dwi_get_cleanup_review` plan items, `dwi_get_execution_status` item results,
and `dwi_get_recovery_status` accept a server-issued read-only cursor. Cursors
are bound to the current server-owned handle and result set; they carry no
mutation authority and stale/forged cursors fail closed.

## Execution and recovery

The complete flow remains:

```text
engine scan
  -> server-owned scan handle
  -> engine CleanupPlan / CleanupSession
  -> WAITING_FOR_HUMAN_CONFIRMATION
  -> trusted human channel confirmation
  -> READY_FOR_EXECUTION handle
  -> fresh EngineRevalidator
  -> PlanValidation
  -> ExecutionAuthorization
  -> Quarantine + Journal
  -> per-item result and recovery handles
  -> validated recovery-handle Undo
```

The agent cannot supply current snapshots, scan context, policy labels,
validation, authorization, or confirmation. Changed evidence, activity,
reachability, protection, identity, root, or journal state blocks execution or
surfaces `RECONCILIATION_REQUIRED`. Execution handles are consumed atomically
before engine work, so replay and concurrent duplicate requests have one
winner. Recovery handles use the same one-shot rule.

Cleanup is always reversible Quarantine + Journal + Undo. Permanent deletion,
automatic cleanup, telemetry, analytics, cloud/API calls, and network mutation
are absent.

## Machine-facing errors and results

The adapter uses stable English codes including `INVALID_HANDLE`,
`WRONG_HANDLE_TYPE`, `STALE_HANDLE`, `CONSUMED_HANDLE`,
`HUMAN_CONFIRMATION_REQUIRED`, `REVALIDATION_BLOCKED`,
`RECONCILIATION_REQUIRED`, `EXECUTION_FAILED`, `PARTIAL_RESULT`,
`RECOVERY_NOT_FOUND`, `INVALID_REQUEST`, `RESOURCE_LIMIT`, and
`INTERNAL_ERROR`.

Execution results preserve `transactional: false` and per-item outcomes. A
partial quarantine is reported as `PARTIAL_RESULT`; it is never collapsed into
a generic failure and never treated as atomic success.
