# Developer Workspace Intelligence (DWI)

DWI is a developer-storage intelligence and safe-cleanup system that discovers
development artifacts across an entire machine, explains provenance,
regenerability, reachability, and risk using deterministic evidence, and exposes
the same safety engine through Desktop, CLI, and MCP interfaces for humans and
AI agents.

Existing disk analyzers answer:

> What is using disk space?

DWI is intended to answer:

> What storage may be reclaimed, what evidence supports that conclusion, and what could make reclaiming it unsafe?

## North Star and current status

The final product is a whole-system Developer Storage Intelligence & Safe
Cleanup System. It will combine machine-wide discovery, deterministic safety
analysis, cleanup planning, immediate revalidation, Trash/Quarantine,
auditable journals, Undo/recovery, Desktop, CLI, and MCP interfaces over one
shared engine.

The typed domain model, detector-neutral evidence contracts, bounded artifact
analyzers, explicit dispatcher, workspace scanner, structured Git context,
bounded System Intelligence discovery, size accounting, standard-library
CLI/report adapters, and v0.3 cleanup planning/validation/authorization
contracts are implemented. The current internal milestone also contains
isolated, reversible Quarantine/Journal/Undo primitives guarded to explicitly
marked disposable directories under the operating-system temporary directory,
plus a separate engine-issued approved-local-root gate for bounded Windows
validation. An internal, presentation-neutral application service now
orchestrates exact review, human confirmation, fresh revalidation, and
per-item quarantine without accepting raw paths. An internal human-facing CLI
adapter now presents that flow in one process; it is pre-public, does not
serialize capabilities, and is not a raw-path mutation API. v0.4 Desktop now
provides the same flow through a native Tkinter shell, controller/state model,
background worker, EN/VI resources, findings explanations, and Recovery/Undo.
v0.5 MCP is implemented as a local-only untrusted JSON-RPC adapter; permanent
deletion and LLM decision-path integration remain absent.

Run a bounded report from one explicit workspace root:

```text
python -m dwi scan PATH
python -m dwi scan PATH --json
python -m dwi scan-system --root PATH --allow-network
python -m dwi scan-system --json
python -m dwi cleanup PATH
python -m dwi cleanup PATH --json --confirm-phrase "I reviewed this exact cleanup plan."
python -m dwi desktop
python -m dwi mcp
```

## Desktop v0.4

Desktop is internal/pre-public and Windows-oriented. It is presentation plus
orchestration over the frozen deterministic scan, Safety Policy, cleanup
application, and mutation layers. It supports system overview, partial-scan
visibility, findings filtering/search/sort, evidence and RuleTrace details,
exact cleanup review and HumanConfirmation, fresh revalidation, per-item
quarantine outcomes, reconciliation-required handling, and Recovery/Undo.

The application uses the trusted in-process capability model. It never accepts
a raw cleanup path, manufactures `RiskLabel` or `ActionEligibility`, creates
`PlanValidation` or `ExecutionAuthorization`, serializes capabilities, or
performs filesystem mutation directly. Cleanup is Quarantine + Journal + Undo;
there is no permanent deletion, telemetry, upload, cloud/API call, or network
listener. MCP uses stdin/stdout only and treats every caller as untrusted.
The developer smoke path owns its temporary fixture and never targets
arbitrary real-machine data.

The scanner recognizes only the documented artifact names, does not follow
links or reparse points, excludes `.git` from cleanup candidates, and reports
unknown or incomplete observations conservatively.

`scan-system` applies the Scan Safety Gate: local fixed drives and approved
local roots are allowed, UNC/network roots are denied by default, links and
reparse points are never followed, and limits or cancellation produce
deterministic partial results. Use `--allow-network` only for an explicit
opt-in; network scanning is never the default.

DWI analysis and public interfaces are offline-first and read-only. The
internal human CLI, Desktop, and MCP are cleanup presentation/request adapters
and only delegate through the reviewed disposable-root or approved-local-root gate
described above. The gate binds lexical paths to authoritative Windows
final paths, rejects short-name aliases to protected roots, and claims each
plan item before writing mutation lifecycle records. DWI performs no telemetry, automatic diagnostic upload, HTTP, cloud, or
API communication. Network filesystem access
is denied by default; explicit `--allow-network` may perform filesystem I/O on
approved UNC, mapped, or other network-backed roots. Reports containing paths
remain local to the machine.

Read the documents in this order:

1. [Project vision](docs/PROJECT_VISION.md)
2. [Domain model](docs/DOMAIN_MODEL.md)
3. [Safety invariants](docs/SAFETY_INVARIANTS.md)
4. [Architecture](docs/ARCHITECTURE.md)
5. [Evidence catalog](docs/EVIDENCE_CATALOG.md)
6. [Adversarial cases](docs/ADVERSARIAL_CASES.md)
7. [Roadmap](docs/ROADMAP.md)
8. [Tasks](TASKS.md)
9. [MCP boundary](docs/MCP.md)

## Safety position

DWI must work without an AI provider. Deterministic evidence collection and ordered safety rules are the source of truth. An LLM may eventually explain an already-computed result, but it must never participate in the safety decision path.

Artifact names never map directly to risk labels. A low-risk label is available only after sufficient evidence passes the ordered safety gates. Runtime uncertainty defaults to `REVIEW_REQUIRED`.

The current bounded implementation boundary and exactly one next task are recorded in [TASKS.md](TASKS.md).

The v0.3 contract layer defines immutable engine-generated cleanup plans,
explicit trusted scan/root bindings, review sessions, typed human confirmation,
immediate revalidation, and separate engine-provenance-backed execution
authorization. A `CleanupPlan` is a proposal, not permission to mutate data.
The internal application service accepts only that exact review/confirmation/
validation/authorization chain and records reversible per-item moves in an
append-only journal; it is not a public cleanup executor.
The mutation functions are intentionally kept in the internal `dwi.mutation`
module and are not exported as convenient top-level package APIs. In addition
to the marked disposable test-root capability, the internal Windows gate can
issue an approved-local-root capability only from the exact authorized plan;
it rejects protected/system/network/reparse/root-escape cases. Any future
untrusted interface must use opaque engine-issued handles rather than
constructing mutation capabilities.

The current reversible strategy is DWI-managed same-volume quarantine with a
chained local journal and recovery identifiers. The internal cleanup CLI is a
single-process review/confirmation adapter: its engine capabilities are never
serialized or accepted from callers, and Undo is addressed only by an
engine-issued recovery identifier during that process. MCP adds only
server-owned opaque handles and does not persist authority across restart.
Windows Recycle Bin integration is deferred until deterministic recovery
metadata, auditable state, and restart-safe Undo semantics are demonstrated.
There is no public release, arbitrary raw-path mutation API, or permanent
deletion.

Future cleanup operations must consume immutable engine-generated plans and
validated plan-item identifiers. No interface may expose arbitrary raw-path
deletion.

## Release and language strategy

Versions v0.1 through v0.5 are internal development milestones. DWI will be
released publicly on GitHub only as v1.0.0, after the complete North Star and
the full Definition of Done in [docs/ROADMAP.md](docs/ROADMAP.md) are reached.

DWI is bilingual:

- English (`en`) is the primary language for international users and public
  GitHub documentation.
- Vietnamese (`vi`) supports Vietnamese users.

Human-facing Desktop, CLI, messages, and documentation will support
localization. MCP machine-facing contracts remain stable and language-neutral:
JSON keys, enums, `RiskLabel` values, MCP tool names, API/schema identifiers,
and internal evidence keys do not change by language. Future public
documentation will provide `README.md` in English and `README.vi.md` in
Vietnamese. Human confirmation remains outside the MCP agent channel.
