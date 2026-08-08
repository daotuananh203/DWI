# Architecture

## Architectural position

DWI is engine-first and deterministic. The core must remain usable without an AI API, cloud service, or agent. Interfaces are adapters around the analysis result, not alternate decision engines.

The final product extends the current engine to whole-system developer-storage
intelligence and safe cleanup. Desktop, CLI, and MCP are presentation/request
interfaces over the same core. They must never create an alternate safety path.

## Shared product pipeline

The diagram includes future cleanup stages. v0.1 currently stops after the
deterministic CLI/JSON report; no cleanup stage is implemented.

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
CleanupPlan -> PlanValidation -> ExecutionAuthorization
        |
        v
CleanupExecutor -> Trash/Quarantine -> Journal/Undo
        |
        +--> CLI / Desktop / MCP adapters
```

The first implementation should use simple typed Python modules. It must not begin with a YAML rule language, dynamic plugin loading, entry-point discovery, distributed services, or unnecessary abstraction layers.

## Responsibilities

- **Filesystem observation:** reads paths and metadata, records failures explicitly, and does not decide safety.
- **Workspace discovery:** accepts one explicit ordinary root, visits supported descendants in deterministic order, does not follow symlinks/junctions/reparse points, and stops discovery below an identified candidate.
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
- **CLI/reporting:** presents deterministic findings in human-readable and JSON forms without changing conclusions.
- **Cleanup planning:** future engine-generated immutable plans identify stable plan items; plans are proposals, not authorization.
- **Plan validation:** future immediate revalidation checks current filesystem/evidence and can only preserve or increase conservatism.
- **Execution authorization:** future engine-controlled permission gate after validation; it is not implied by `SAFE` or `ELIGIBLE_FOR_EXPLICIT_ACTION`.
- **Cleanup execution:** future executor accepts only authorized engine plans, prefers Trash/Quarantine, and records an audit journal for Undo/recovery.

The scanner adapts each dispatcher result through a single-candidate selection
boundary. Weak or ambiguous artifact identity is represented as a rejected
finding with effective `REVIEW_REQUIRED` posture; it is not promoted to a
cleanup candidate or silently passed to policy. Accepted results preserve raw
evidence and interpretation, then invoke the existing Safety Policy. `.git`
directories and `.git` files are recorded as protected context only.
The structured `GitContextObservation` preserves the observed node, evidence,
object form, and any un-followed `gitdir` reference. It never enters artifact
dispatch or candidate selection.

## Boundary rules

Detectors contribute evidence. They do not own the final risk label. The Safety Policy must not depend on detector-specific implementation details beyond the documented evidence contract.

Reachability is an ordered hard gate. If a reference or active consumer is confirmed, the Safety Policy must produce at least `REVIEW_REQUIRED`; `SAFE` and `REGENERATABLE` are unavailable. A `RegenerabilityState` observation can support policy evaluation, but it cannot directly produce `RiskLabel.REGENERATABLE`.

Artifact names are candidate-identification hints only. They never map directly to labels, and runtime uncertainty defaults to `REVIEW_REQUIRED`.

The domain core must not know whether a result came from the CLI, a future desktop UI, or a future MCP adapter. Future adapters are documented possibilities only and are not MVP components.

## Future architecture, explicitly out of MVP

The project may later add a desktop UI, MCP adapter, optional LLM explanation layer, broader detector registry, multi-project reachability graph, persistent index, or cleanup planner. Each must consume already-computed core results and must not bypass safety policy.

## Determinism and auditability

Evaluation inputs must be explicit and serializable enough for tests and reports. A result must include the rule-engine version or equivalent evaluation identity, the evidence used, the ordered rule trace, and any observation failures that affected certainty.

## Windows scope

The MVP targets Windows filesystem behavior. Junctions, reparse points, symlinks, permissions, and `.git` files must be treated as first-class uncertainty sources. Cross-platform behavior is deferred until the Windows semantics are specified and tested.

The current CLI is reporting-only. It has no deletion, cleanup planning,
undo/trash, process-wide activity scan, cross-project reachability, or
project-wide package-manager analysis.

## AI and MCP boundary

AI/LLM components are outside the deterministic decision path. They may request
scans, explanations, cleanup-plan creation, plan validation, or execution of an
already-authorized plan. They must never decide `RiskLabel`,
`ActionEligibility`, `PlanValidation`, or `ExecutionAuthorization`.

MCP cleanup operations must accept only engine-generated `plan_id` and
plan-item identifiers. An operation such as `delete_file(path)` is prohibited.
Execution must revalidate immediately before acting, prefer
Trash/Quarantine, and remain auditable. These are future boundaries, not v0.1
runtime behavior.

## Localization boundary

Human-facing Desktop, CLI, messages, and documentation use a shared
localization boundary for English (`en`) and Vietnamese (`vi`). Localization
must affect presentation only; it must not create separate safety logic or
change deterministic conclusions.

Machine-readable contracts remain language-neutral and stable. JSON keys,
enums, `RiskLabel` values, MCP tool names, API/schema identifiers, and internal
evidence keys are not translated. Runtime i18n is future work. Public
documentation will provide English `README.md` and Vietnamese `README.vi.md`.
