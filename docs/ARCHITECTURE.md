# Architecture

## Architectural position

DWI is engine-first and deterministic. The core must remain usable without an AI API, cloud service, or agent. Interfaces are adapters around the analysis result, not alternate decision engines.

## MVP pipeline

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
CLI table and JSON report
```

The first implementation should use simple typed Python modules. It must not begin with a YAML rule language, dynamic plugin loading, entry-point discovery, distributed services, or unnecessary abstraction layers.

## Responsibilities

- **Filesystem observation:** reads paths and metadata, records failures explicitly, and does not decide safety.
- **Workspace discovery:** accepts one explicit ordinary root, visits supported descendants in deterministic order, does not follow symlinks/junctions/reparse points, and stops discovery below an identified candidate.
- **Size accounting:** recursively counts regular files inside an identified candidate without following links; incomplete counts and failures remain explicit and size never changes `RiskLabel`.
- **Evidence collection:** normalizes observations into structured evidence with provenance and status.
- **Candidate selection:** prevents arbitrary files, source trees, and project roots from entering the cleanup-analysis path.
- **Git boundary:** observes `.git` directories and `.git` files for protection/context, but excludes them from `CleanupCandidate` inputs. `NEVER_DELETE` is a protection outcome, not reclaim eligibility.
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

The scanner adapts each dispatcher result through a single-candidate selection
boundary. Weak or ambiguous artifact identity is represented as a rejected
finding with effective `REVIEW_REQUIRED` posture; it is not promoted to a
cleanup candidate or silently passed to policy. Accepted results preserve raw
evidence and interpretation, then invoke the existing Safety Policy. `.git`
directories and `.git` files are recorded as protected context only.

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
