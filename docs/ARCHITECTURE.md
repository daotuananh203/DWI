# Architecture

## Architectural position

DWI is engine-first and deterministic. The core must remain usable without an AI API, cloud service, or agent. Interfaces are adapters around the analysis result, not alternate decision engines.

The final product extends the current engine to whole-system developer-storage
intelligence and safe cleanup. Desktop, CLI, and MCP are presentation/request
interfaces over the same core. They must never create an alternate safety path.

## Shared product pipeline

The diagram includes future public cleanup stages. v0.3 also implements an
internal presentation-neutral application service and a human-facing CLI
adapter. The CLI and v0.4 Desktop are single-process, pre-public
presentation/orchestration boundaries. v0.5 MCP is a separate local-only
untrusted request boundary over the same service.

```text
Filesystem observations
        |
        v
Evidence collection
        |
        v
Bounded candidate discovery + explicit selection
        |
        v
Artifact analysis / interpretation
        |
        v
Ordered Safety Policy gates
        |
        v
RiskLabel + ActionEligibility + RuleTrace
        |
        +--> ReclaimPriority (independent value calculation)
        |
        v
CleanupPlan -> Review -> HumanConfirmation -> PlanValidation
        |
        v
ExecutionAuthorization -> Internal Application Service
        |
        v
Quarantine -> Journal/Undo
        |
        +--> CLI / Desktop adapters
        |
        +--> untrusted MCP request
                |
                v
          strict schemas -> opaque in-memory handle store
                |
                v
          same Application Service / Mutation layer
```

The first implementation should use simple typed Python modules. It must not begin with a YAML rule language, dynamic plugin loading, entry-point discovery, distributed services, or unnecessary abstraction layers.

## Responsibilities

- **Filesystem observation:** reads paths and metadata, records failures explicitly, and does not decide safety.
- **Workspace discovery:** accepts one explicit ordinary root, visits supported descendants in deterministic order, does not follow symlinks/junctions/reparse points, and stops discovery below an identified candidate.
- **System discovery:** accepts approved local roots and known tool-specific global cache roots, applies the Scan Safety Gate, records denied/skipped boundaries, and never treats arbitrary large directories as developer storage.
- **Scan Safety Gate:** allows local fixed drives and explicit local roots, denies UNC/network/mapped roots by default, supports explicit network opt-in, records inaccessible/racing paths, and applies deterministic cancellation/time/node/file limits.
- **Size accounting:** recursively counts regular files inside an identified candidate without following links; incomplete counts and failures remain explicit and size never changes `RiskLabel`.
- **Evidence collection:** normalizes observations into structured evidence with provenance and status.
- **Candidate selection:** prevents arbitrary files, source trees, and project roots from entering the cleanup-analysis path.
- **Git boundary:** observes exactly one explicit `.git` directory or `.git` file for structured protection/context, records failures and raw gitdir references, never follows external targets, and excludes Git metadata from `CleanupCandidate` inputs. `NEVER_DELETE` is a protection outcome, not reclaim eligibility.
- **Artifact analysis:** interprets evidence for Python, Node.js, and minimal Git context.

The current bounded artifact layer has explicit analyzers for `__pycache__`,
`.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.venv`/`venv`, `node_modules`,
`dist`, `build`, and `.next`. Each analyzer accepts one candidate path, records
raw observations, and returns a separate domain interpretation. The `.venv`
analyzer does not inspect parent project files. Node analyzers do not perform
package-manager-wide reachability or cross-project discovery.

The single-candidate dispatcher uses an explicit artifact-name decision table.
It is not a recursive scanner, registry, plugin mechanism, or dynamic discovery
system; an unknown basename returns no analysis result.
- **Safety Policy:** applies ordered gates and produces the risk label, action eligibility, and rule trace.
- **Reclaim ranking:** estimates reclaim priority independently from safety.
- **CLI/reporting:** presents deterministic findings in human-readable and JSON forms without changing conclusions. Its internal `cleanup` command displays the engine-generated plan, requires the exact typed confirmation, delegates fresh validation/authorization/quarantine/journal/Undo to the application service, and exposes no raw target or trusted capability. Capabilities are not persisted across processes.
- **Cleanup planning:** pure v0.3 logic creates immutable engine-generated plans from eligible Findings, complete trusted scan context, canonical approved-root bindings, and valid filesystem identity snapshots. Mutation-capable snapshots retain both lexical and authoritative final paths; raw paths are not accepted as plan inputs.
- **Plan validation:** pure v0.3 logic requires a new trusted scan context and compares current snapshots immediately before execution, returning valid, stale, blocked, or inconclusive states; it can only preserve or increase conservatism.
- **Execution authorization:** pure v0.3 logic issues metadata-only authorization from an internal engine proof bound to the exact plan and validation state; it is not implied by `SAFE`, `ELIGIBLE_FOR_EXPLICIT_ACTION`, copied tokens, or public validation fields.
- **Mutation Safety Gate:** accepts only the exact authorized plan, its valid immediate validation, a private unconsumed plan-item authorization, and the plan's engine-approved local root. It resolves lexical paths through an authoritative Windows final-path handle API after ordinary ancestry checks, rejects filesystem roots, network/UNC/mapped/unknown volumes, system/protected roots, linked/reparse paths, and root escapes, and compares both path identities at execution time.
- **Isolated mutation primitive:** accepts only the exact authorized plan and engine-issued disposable or approved-local-root/quarantine/journal capabilities; it atomically claims each plan item before writing lifecycle records, rechecks identity/type/reparse/root/evidence/policy state immediately, and uses only same-filesystem non-overwriting Windows rename.
- **Cleanup application service:** accepts one engine-generated cleanup session, exact typed human confirmation, and an internal engine revalidator capability. The revalidator must supply a `TrustedSnapshotSet` for the exact plan, bound to fresh evaluation identity, rule-engine version, scan provenance, snapshot digest, and creation time; caller mappings or hand-built snapshots are rejected. After confirmation, the service performs fresh evidence/interpretation/policy validation, obtains one-shot engine authorization, delegates to the internal mutation primitive, and reports each item independently. It accepts no raw path. The internal CLI and v0.4 Desktop are trusted presentation adapters; v0.5 MCP reaches this service only through server-owned opaque state.
- **Cleanup execution:** future public executor accepts only authorized engine plans, prefers Trash/Quarantine, and records an audit journal for Undo/recovery.

The scanner adapts each dispatcher result through a single-candidate selection
boundary. Weak or ambiguous artifact identity is represented as a rejected
finding with effective `REVIEW_REQUIRED` posture; it is not promoted to a
cleanup candidate or silently passed to policy. Accepted results preserve raw
evidence and interpretation, then invoke the existing Safety Policy. `.git`
directories and `.git` files are recorded as protected context only.
The structured `GitContextObservation` preserves the observed node, evidence,
object form, and any un-followed `gitdir` reference. It never enters artifact
dispatch or candidate selection.

The `scan_system` API orchestrates approved roots through the same workspace
pipeline and adds explicit global-cache analysis for pip, uv, npm, pnpm, and
yarn structures only where bounded local markers are defensible. Global cache
findings remain ordinary `Finding` objects and therefore pass through the same
candidate selection and Safety Policy. System reports keep workspace findings,
global storage, denied boundaries, partial sizes, and scan termination separate.

Root status is part of the planning safety boundary: `COMPLETE` means no root or
finding observation failures were recorded, `PARTIAL` means traversal or
evidence was incomplete, and `FAILED` means safe observation failed. The legacy
`SCANNED` value is not equivalent to `COMPLETE` and is treated as incomplete
for planning. A global cache root with failed evidence is `PARTIAL`, so it
cannot silently satisfy cleanup planning.

## Boundary rules

Detectors contribute evidence. They do not own the final risk label. The Safety Policy must not depend on detector-specific implementation details beyond the documented evidence contract.

Reachability is an ordered hard gate. If a reference or active consumer is confirmed, the Safety Policy must produce at least `REVIEW_REQUIRED`; `SAFE` and `REGENERATABLE` are unavailable. A `RegenerabilityState` observation can support policy evaluation, but it cannot directly produce `RiskLabel.REGENERATABLE`.

Artifact names are candidate-identification hints only. They never map directly to labels, and runtime uncertainty defaults to `REVIEW_REQUIRED`.

The domain core must not know whether a result came from the internal CLI,
Desktop, or MCP. The CLI and Desktop are trusted presentation adapters; MCP is
an untrusted request adapter with no alternate safety engine.

## Future architecture, explicitly out of MVP

The project may later add an optional LLM explanation layer, broader detector
registry, multi-project reachability graph, persistent index, or public cleanup
executor. Each must consume already-computed core results and must not bypass
safety policy. The internal disposable-root and approved-local mutation
primitives are not a public executor or a substitute for proven Windows
Recycle Bin integration.

## Determinism and auditability

Evaluation inputs must be explicit and serializable enough for tests and reports. A result must include the rule-engine version or equivalent evaluation identity, the evidence used, the ordered rule trace, and any observation failures that affected certainty.

## Windows scope

The MVP targets Windows filesystem behavior. Junctions, reparse points, symlinks, permissions, and `.git` files must be treated as first-class uncertainty sources. Cross-platform behavior is deferred until the Windows semantics are specified and tested.

The current CLI provides read-only `scan`/`scan-system` reporting plus a
pre-public, single-process human-confirmed `cleanup` adapter. `scan-system` is
read-only, offline-first, and network-deny-by-default; it performs no
telemetry, HTTP, cloud, or API communication. The cleanup adapter does not
accept `delete`, `remove`, or `quarantine` raw-path commands, `--force`, or
`--yes`, and it does not persist capabilities. Desktop provides a native
presentation path and MCP provides a local-only opaque-handle request path over
the same application service. Neither creates a second mutation path. There is
no process-wide activity scan, cross-project reachability, or project-wide
package-manager analysis. The internal v0.3 application service delegates
only reversible quarantine/restore moves after its hard disposable-test-root
or approved-local-root gate; no public executor, permanent deletion, or
Windows Recycle Bin integration is implemented.

Before requesting a new `PlanValidation` or `ExecutionAuthorization`, the
service first inspects existing recovery state. Inventory inspection is
read-only. A narrowly scoped restart reconciliation may append only
hash-chained journal metadata for pre-existing orphan claims or crash-window
records; it never creates a quarantine root or claim, creates a new cleanup
lifecycle/payload, moves candidate data, or moves quarantine payloads. A
reconciliation result stops that invocation with `RECONCILIATION_REQUIRED`.
This metadata reconciliation is recovery handling, not candidate mutation.

Python filesystem APIs cannot make a multi-operation path traversal perfectly
atomic against concurrent replacement. The scanner and size collector
revalidate the current path, type/reparse state, and available identity before
and after bounded directory enumeration. Global-storage roots and their direct
children also receive a pre-enumeration/containment check. Detected races are
recorded as failures/ambiguity, and links are never intentionally followed. A
replacement in the remaining validation-to-operation window is a platform
limitation and must remain conservative in any future cleanup executor.

## AI and MCP boundary

AI/LLM components are outside the deterministic decision path. They may request
scans, explanations, cleanup-plan creation, plan validation, or execution of an
already-authorized plan. They must never decide `RiskLabel`,
`ActionEligibility`, `PlanValidation`, or `ExecutionAuthorization`.

The internal journal uses a genesis-linked sequence chain and explicit
recoverable post-rename states. Filesystem reality is authoritative when a
final journal append fails; reconciliation never converts a committed rename
to an ordinary failure. The chain provides corruption/tamper evidence, not
authenticated cryptographic trust, and cannot detect deletion of a complete
final line without external terminal metadata.

Authorization ownership is claimed with an `O_CREAT|O_EXCL` local claim file
before the first lifecycle record. This prevents same-item replay across local
processes when the filesystem honors atomic exclusive creation. It does not
make append ordering for unrelated items a distributed transaction; journal
corruption or ambiguous writes still fail closed.
An interruption after claim-file creation but before the
`AUTHORIZATION_CLAIMED` journal append can leave an orphan claim file. Bounded
restart reconciliation validates the claim payload, journals it as
`AUTHORIZATION_CLAIMED` followed by `FAILED` without moving data, and retains
the claim file as a replay lock. Malformed or unjournalable claims remain
blocked with an auditable reconciliation-required state.

Pre-authorization reconciliation is intentionally limited to append-only
journal metadata for state that already existed before the new cleanup
attempt. It is deterministic and idempotent: repeated reconciliation does not
create duplicate lifecycle records, new claims, quarantine roots, or payloads.

MCP cleanup operations accept only server-owned opaque handles bound to
engine-generated scan findings and plan items. An operation such as
`delete_file(path)` is prohibited. Execution revalidates immediately before
acting, prefers Quarantine, and remains auditable. The agent cannot provide
human confirmation or serialized proof/capability objects. The current
mutation runtime remains internal and accepts only marked disposable test
roots or engine-issued approved local roots.

## v1.0 hardening foundation

The public scan adapters use shared finite limits: 300 seconds, 100,000 nodes,
and 100,000 files. Booleans, non-finite numbers, invalid numeric types, and
over-limit values are rejected before scan dispatch; omitted limits resolve to
those bounded defaults rather than unlimited traversal. MCP collection inputs
are bounded before item validation and large read models use bounded,
read-only pagination. Its local stdio transport caps requests and responses at
1 MiB and never opens a network listener.

The release-readiness layer adds a read-only real-machine evaluation command,
disposable synthetic scan/pagination benchmarks, single-source development
versioning, package metadata, and a Windows build script. These adapters do
not create journal, quarantine, recovery, or authorization state. Build
artifacts, installer/signing validation, and public release remain outside this
batch.

## Localization boundary

Human-facing Desktop, CLI, messages, and documentation use a shared
localization boundary for English (`en`) and Vietnamese (`vi`). Localization
must affect presentation only; it must not create separate safety logic or
change deterministic conclusions.

Machine-readable contracts remain language-neutral and stable. JSON keys,
enums, `RiskLabel` values, MCP tool names, API/schema identifiers, and internal
evidence keys are not translated. Desktop runtime i18n is implemented from
packaged resources; CLI/runtime localization remains future work. Public
documentation will provide English `README.md` and Vietnamese `README.vi.md`.
