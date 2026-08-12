# Safety Invariants

These invariants are architectural constraints. Future implementation, tests, CLI output, and integrations must preserve them.

1. Missing evidence must never result in `SAFE`; the default is `REVIEW_REQUIRED`.
2. Observation failures are not evidence of safety. Permission errors, timeouts, parser failures, unreadable metadata, and detector errors reduce certainty.
3. Protected VCS and system artifacts must not become disposable merely because they are stale.
4. Reachability is a hard safety gate. A confirmed reference or active consumer imposes a minimum `REVIEW_REQUIRED` label and prevents both `SAFE` and `REGENERATABLE`.
5. Regenerability is not equivalent to safety. `RegenerabilityState` is reproducibility evidence/property; `RiskLabel.REGENERATABLE` is a separate Safety Policy conclusion. A reproducible artifact can still be active, referenced, expensive, or unsafe to reclaim now.
6. Staleness must not directly determine `RiskLabel`; it primarily influences `ReclaimPriority`.
7. Every risk label must be explainable through the exact evidence and ordered rules that produced it.
8. The decision path is deterministic: identical evidence and identical rule-engine version produce identical results.
9. Unknown provenance increases uncertainty; it must not automatically imply `SAFE` or `NEVER_DELETE`.
10. `NEVER_DELETE` is a hard protection floor once sufficient protection evidence exists.
11. Explicit negative evidence is stronger than absence of evidence. Active confirmation of “no references” is distinct from “no references were found.”
12. Conflicting evidence fails closed. Conservative evidence wins; evidence must not be averaged into false confidence.
13. Safety policy must not use weighted scoring. It uses ordered gates and precedence rules. Scoring is permitted only for `ReclaimPriority`.
14. Unknown tool or filesystem state must not be guessed. Broken links, unresolved junctions, corrupted lockfiles, and inaccessible paths produce uncertainty.
15. LLMs and AI agents must never participate in the safety decision path. They may later explain an already-computed decision.
16. `RiskLabel` is monotonic during one evaluation. A rule may escalate caution but must not de-escalate a label already established in that evaluation.

17. `.git` directories and `.git` files are `ObservedNode`s for protection/context only and must never enter the `CleanupCandidate` pipeline. `NEVER_DELETE` expresses a protection floor, not reclaim eligibility.

18. The v0.2 Scan Safety Gate allows only approved local fixed drives or
explicit local roots by default. UNC, network, mapped, removable, symlink, and
reparse roots are denied or skipped conservatively; network roots require an
explicit opt-in.

19. System discovery must remain inside approved roots. Before traversing a
current directory or enumerating an approved global-storage root, the path must
be revalidated as an ordinary directory. It must not follow symlinks, junctions,
or reparse points, and inaccessible, out-of-bound, or racing paths must be
recorded and skipped rather than guessed.

20. Cancellation, time limits, node limits, and file limits produce explicit
partial scan state. A partial result never treats unvisited paths as absent,
safe, or reclaimable.

21. System discovery is read-only and offline-first. DWI performs no telemetry,
diagnostic upload, HTTP, cloud, or API communication. Network filesystem I/O is
denied by default and only occurs for explicitly opted-in approved network
roots; it is not a telemetry or cloud communication path.

## v0.3 planning and authorization invariants

22. A cleanup plan may be created only from engine-produced `Finding` objects
and complete supporting snapshots. An interface-provided raw path list is not a
plan and cannot become a plan item.

23. Every plan item is immutable and binds the exact artifact, path, filesystem
identity, evidence, rule trace, size, risk, action, protection, reachability,
and activity snapshot from which it was created.

24. Revalidation is immediate and deterministic. Disappearance, identity/type
change, symlink/junction/reparse substitution, protection/reference/activity
change, evidence insufficiency, size change, or a more cautious Safety Policy
posture blocks or invalidates the plan.

25. Revalidation may never make a plan more permissive. `SAFE` and
`ELIGIBLE_FOR_EXPLICIT_ACTION` do not authorize execution. `REVIEW_REQUIRED`,
`NEVER_DELETE`, active/reference uncertainty, protection, and incomplete or
failed evidence cannot authorize execution.

26. `ExecutionAuthorization` is separate from `CleanupPlan` and
`PlanValidation`, binds an engine-issued proof and successful validation state,
and has private one-shot plan-item consumption. A consumed item cannot be
replayed, while unconsumed items in a validated multi-item plan remain
independently attributable. Authorization itself performs no mutation.

27. Every future mutation attempt must be attributable to an engine-generated
plan item and produce an auditable journal record. The first mutation release
must be reversible through Trash/Quarantine and Undo; permanent deletion is
out of scope.

28. Cleanup planning and validation require an explicit engine-issued trusted
scan context. Omitted, unknown, partial, failed, denied, skipped, or
incomplete scan state must fail closed and cannot produce executable planning
state.

29. Every cleanup plan retains an engine-derived canonical approved-root
binding. Candidate paths must be absolute, normalized, contained by that root,
and backed by a valid positive filesystem identity with a lexical-to-
authoritative final-path binding; relative, escaping, mismatched, symlink,
junction, and reparse-backed paths are not plannable.

30. `PlanValidation` success requires an engine-issued capability bound to the
exact immutable plan, current snapshot set, trusted revalidation context, and
validation state. Equivalent public fields or copied tokens cannot manufacture
authorization.

31. A mutation state must reflect filesystem reality. If a quarantine or
restore rename has committed but its final journal append fails, the result is
an explicit recoverable post-rename state, never an ordinary `FAILED` state.
Durable pre-mutation intent must retain the original path, destination,
recovery identity, plan identity, item identity, expected filesystem identity,
and intended transition.

32. The append-only mutation journal uses explicit genesis, strictly monotonic
sequence numbers, previous-record hashes, and current-record hashes. Broken
chains, edits, duplicate lines, missing middle records, reordering, and
incomplete final lines fail closed. This is corruption/tamper evidence, not
authenticated cryptographic trust; complete-journal rewrite attacks remain an
external trust-boundary concern.

33. A real-filesystem mutation root must be an engine-issued approved local
directory on a fixed Windows volume. Filesystem roots, UNC/network/mapped or
unknown volumes, system/Program Files/ProgramData locations, and linked or
reparse-backed roots are denied. The root capability is bound to the exact
plan-approved root; it is not an arbitrary path permission.

34. Immediately before a rename, the mutation layer must revalidate the exact
plan item, canonical/root-bound path, ordinary ancestry, existence, positive
filesystem identity, directory type, reparse state, same-volume quarantine,
validated evidence/policy snapshot, and authorization item. Any uncertainty,
replacement, collision, lock/permission failure, or race blocks without a
copy/delete fallback.

35. The internal v0.3 reversible strategy is DWI-managed same-volume
quarantine with journaled recovery metadata. Windows Recycle Bin integration is
not used until deterministic recovery identity, auditability, and restart-safe
Undo semantics can be demonstrated without weakening these invariants.

36. Mutation planning and execution bind both the lexical requested path and
the authoritative Windows final path. The final path is obtained through a
Windows handle/final-path API only after ordinary ancestry and reparse checks;
if it cannot be established, mutation is denied. Short-name aliases such as
8.3 paths are compared using the authoritative final path and cannot bypass
protected-root policy.

37. A mutation authorization item must be claimed atomically before any
`PLANNED` or `QUARANTINING` record is written. In-process claims are one-shot;
the local filesystem claim file prevents a second process from claiming the
same plan item. A claimed-but-not-started operation is reconciled explicitly;
rejected replay does not append a misleading lifecycle failure. If a process
stops after the atomic claim but before `AUTHORIZATION_CLAIMED` is journaled,
restart reconciliation validates the complete claim payload, appends the
claimed and failed records without moving data, and retains the claim file as
a replay lock. Malformed or unjournalable claims remain blocked with an
auditable reconciliation-required state; no automatic retry is permitted.

38. The internal application service requires an exact immutable review and
typed `HumanConfirmation` before it requests fresh engine revalidation. Fresh
state must be an opaque `TrustedSnapshotSet` bound to the exact plan digest
and item IDs, evaluation identity, rule-engine version, scan provenance,
snapshot digest, and creation time; a caller mapping, replayed state, or hand-
constructed set cannot qualify. Confirmation does not create policy,
validation, or authorization. Changed, stale, partial, failed, or conflicting
evidence after confirmation blocks execution.

39. The internal human CLI is presentation/orchestration only. It cannot
construct or accept trusted scan state, `RiskLabel`, `ActionEligibility`,
successful validation, authorization, or raw-path mutation requests. It must
use the exact typed confirmation and application-service chain, must not expose
`--force`/`--yes` bypasses, and must not serialize engine capabilities across
processes. Its reversible action remains quarantine plus journal and Undo.

40. Before a new cleanup authorization, pre-authorization recovery
reconciliation may append metadata describing pre-existing DWI recovery state.
It cannot begin or mutate a new cleanup operation: no candidate move/rename,
quarantine-payload move, quarantine-root creation, execution-claim creation,
or new cleanup lifecycle is permitted. If reconciliation is required, the
application returns `RECONCILIATION_REQUIRED` and does not request fresh plan
validation or new execution authorization in that invocation.

## Future executor invariants

The following invariants apply when cleanup planning and execution enter the
roadmap. They do not authorize implementation in v0.1.

F1. Agent and MCP interfaces must never accept arbitrary filesystem paths as
cleanup targets.

F2. Cleanup execution requires an immutable plan generated by the deterministic
engine. Interface-provided path lists are not plans.

F3. Every plan must be revalidated immediately before execution against the
current filesystem and relevant evidence.

F4. Any material filesystem or evidence change invalidates or blocks the plan.

F5. Revalidation may make execution more conservative, never less
conservative, and must not lower an established monotonic `RiskLabel`.

F6. No cleanup action may bypass Safety Policy, candidate selection, plan
validation, or execution authorization.

F7. Cleanup execution must produce an auditable record containing the plan,
validation result, authorization, actions, failures, and resulting quarantine
or recovery identifiers.

F8. The initial cleanup release must use Trash/Quarantine plus a journal and
Undo/recovery path. Permanent deletion is out of scope until explicitly
authorized by a separate design.

## Default posture

The system must prove that an artifact meets the requirements for a low-risk label. It must not infer safety because a dangerous condition was not detected.

Artifact names, verified regenerability, and low staleness are not sufficient by themselves to produce a `RiskLabel`. Runtime uncertainty defaults to `REVIEW_REQUIRED`.

Evidence requirements must make minimum confidence explicit. `LOW` confidence does not silently qualify as strong safety evidence, and `NOT_OBSERVED` does not qualify as confirmed negative evidence.

## Separation of concerns

The following questions must not be collapsed into one field:

- What kind of artifact is this?
- Is it reproducible?
- Is it currently active or reachable?
- Is it protected?
- What is the intrinsic risk of reclaiming it?
- Is any action eligible right now?
- Is reclaiming it worthwhile?

## Review standard

The current v0.4 layer includes a separate internal mutation primitive and an
internal human CLI adapter. It
supports explicitly marked disposable directories for tests and an
engine-issued approved-local-root gate for real-Windows validation. It
performs only authorized, reversible same-volume quarantine/restore moves and
append-only journal writes; the CLI and Desktop are single-process and
pre-public, with no capability persistence, permanent deletion, or copy/delete
fallback. v0.5 MCP is a local-only untrusted adapter that stores authority only
in non-persistent server memory and delegates through the same application
service. Any public cleanup
executor still requires a separate approved design covering confirmation,
recovery, journaling, race conditions, and failure handling.

`SAFE` and `ELIGIBLE_FOR_EXPLICIT_ACTION` are not execution authorization. A
future executor must require an immutable engine-generated plan, immediate
revalidation, and explicit `ExecutionAuthorization`.

For the narrowly supported disposable scanner path, the root must contain one
ordinary non-reparse file named `.dwi-disposable-root` whose exact content is
`DWI-DISPOSABLE-ROOT-v0.3`. The pytest-cache detector accepts this marker only
as an explicit bounded-scope contract: it emits high-confidence evidence for
recreation availability, no retained consumer within the declared disposable
fixture, inactive runtime use, and ordinary protection. A normal unmarked
workspace, a malformed marker, an ambiguous cache layout, or any unknown
observation remains `REVIEW_REQUIRED`; missing evidence is never converted into
absence, inactivity, unreferenced state, or ordinary protection.

## v0.5 MCP boundary invariants

41. MCP requests are untrusted. A request may contain only strict schema fields;
cleanup selection is bound to server-owned scan handles and engine-generated
finding/item identifiers. Raw mutation paths, safety fields, current
snapshots, trusted contexts, validation, authorization, and private proof
objects are rejected.

42. MCP handle authority lives in a server-owned, non-persistent registry.
Handle kinds are distinct, lookup fails closed, expiry is conservative, and
execution/recovery handles are atomically one-shot. Restart invalidates all
authority-bearing handles.

43. MCP cannot create `HumanConfirmation`. The confirmation tool is absent from
the MCP registry; only a separate trusted human-channel adapter may bind the
exact immutable review to confirmation. Agent-supplied phrases are not consent.

44. MCP execution calls the existing application service with a fresh engine
revalidator. Revalidation and authorization remain core-owned immediately
before mutation, and per-item outcomes/reconciliation state are returned
without capability material. Undo resolves only server-owned recovery state and
never accepts a restore destination.

45. v0.5 transport is local stdin/stdout only. No TCP/HTTP listener, cloud
relay, telemetry, upload, or network mutation is configured.

## v1.0 hardening Batch 1/2 invariants

46. MCP caller collections are bounded before item validation: roots are capped
at 32 and cleanup finding IDs at 256. Read-only list results use a maximum
page size of 100; over-limit input is rejected and never silently truncated.

47. MCP stdio messages and responses are capped at 1 MiB. Oversized input is
rejected before JSON/schema/engine work, drained without unbounded buffering,
and does not turn a partial line into a valid request.

48. All public scan limits use finite typed values and shared hard caps of 300
seconds, 100,000 nodes, and 100,000 files. Caller-created zero or negative
 budgets are rejected; no zero value means unlimited work.

49. The developer machine evaluation command is read-only, network-deny by
default, count/status-oriented, and does not create cleanup, quarantine,
journal, recovery, or mutation state. Synthetic benchmarks use disposable
temporary fixtures only.
