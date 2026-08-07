# Domain Model

This document defines the vocabulary that future implementation tasks must refine into types. The names are intentionally descriptive and are not yet a public API contract.

## Core objects

### ObservedNode

A filesystem object inspected for context. It may be a file, directory, link, junction, reparse point, or an inaccessible path. An `ObservedNode` is not automatically eligible for cleanup analysis.

### CleanupCandidate

An artifact that has passed an explicit candidate-selection boundary and may be evaluated by safety policy. Candidate status must be based on artifact evidence, not merely a matching directory name.

User-authored source code and project roots must not become candidates by default. `.git` directories and `.git` files are `ObservedNode`s for protection/context only; they are never `CleanupCandidate` inputs.

### Evidence

A structured observation supporting or limiting a conclusion. Evidence should identify its source, observation status, confidence, timestamp or evaluation context where relevant, and whether it is positive, negative, unknown, or conflicting.

### RuleTrace

An auditable record of the ordered rules and evidence that produced a result. A trace must make it possible to explain both the selected label and the gates that prevented a less cautious label.

## State dimensions

These dimensions must remain distinct:

- **ObservationStatus:** observed, not-observed, confirmed-absent, failed, timed-out, inaccessible, or unknown. `NOT_OBSERVED` means no observation or marker was found; `CONFIRMED_ABSENT` means an active check established absence.
- **Confidence:** how strongly the evidence supports a specific interpretation. A generic `EvidenceRequirement` may declare a minimum confidence; `LOW` must not silently satisfy a stronger requirement. Confidence must not be used to average contradictory safety claims.
- **Provenance:** the likely generator or ecosystem, such as Python, pytest, npm, Next.js, or Git.
- **RegenerabilityState:** a reproducibility property/evidence dimension describing whether and under what conditions an artifact can be recreated. It is not a risk label and does not by itself authorize any action.
- **RegenerationCost:** an estimate of time, network, credentials, compute, storage, or lost local state required to recreate it.
- **ReachabilityState:** whether references or active consumers are confirmed, explicitly checked and absent, unknown, or conflicting.
- **ActivityState:** whether the artifact appears active at evaluation time, inactive, or unknown.
- **ProtectionClass:** ordinary, protected, system-protected, repository-protected, or unknown.
- **RiskLabel:** the Safety Policy's intrinsic caution conclusion about reclaiming the artifact under the evaluated evidence. `REGENERATABLE` is a policy conclusion, not a copy of `RegenerabilityState`.
- **ActionEligibility:** whether an operation is blocked, requires review, or is eligible for a future explicitly authorized action.
- **ReclaimPriority:** independent prioritization based on size, staleness, regeneration cost, and other value signals. It is not a safety score.

## Risk labels

Labels are ordered from less to more cautious:

`SAFE < REGENERATABLE < REVIEW_REQUIRED < NEVER_DELETE`

- `SAFE`: sufficient positive evidence satisfies all strict low-risk gates, including the required reachability and activity checks. It is not a promise that every future operation is harmless.
- `REGENERATABLE`: Safety Policy conclusion that the artifact may be reproducible and conditionally reclaimable after all applicable gates pass, but it does not meet the stricter `SAFE` gates. Verified regenerability alone is insufficient.
- `REVIEW_REQUIRED`: evidence is incomplete, uncertain, stale, failed, or context-dependent. Human review is required.
- `NEVER_DELETE`: sufficient protection evidence establishes a hard floor against deletion-oriented actions, including repository or system protection.

Risk labels are not current activity. A confirmed reference or active consumer is a hard gate: the minimum `RiskLabel` is `REVIEW_REQUIRED`, so it cannot be `SAFE` or `REGENERATABLE`. An artifact may have `RegenerabilityState = REPRODUCIBLE` while its `RiskLabel = REVIEW_REQUIRED` because it is referenced, active, or otherwise fails a safety gate. `ActionEligibility` may still be `BLOCKED` independently.

`NEVER_DELETE` is protection semantics, not reclaim eligibility. In particular, Git metadata is observed for context and protection and is excluded from the cleanup-candidate pipeline.

## Evidence semantics

`NOT_OBSERVED` is not a confirmed negative. It represents absence of an observation and remains uncertain. It cannot carry directional negative polarity. `CONFIRMED_ABSENT` is reserved for an actively checked absence and must carry explicit negative polarity.

`EvidenceRequirement` expresses a detector-neutral evidence key and minimum confidence without defining detector-specific rules. Policy evaluation must fail closed when a requirement is missing or its minimum confidence is not met.

The model must distinguish:

- “No reference was found” from “references were actively checked and confirmed absent.”
- “The detector did not observe a marker” from “the marker was checked and confirmed absent.”
- “The path could not be read” from “the path was read and contains no relevant evidence.”
- “A generator is known” from “the generator is only guessed from a name.”

Unknown or failed evidence is not a negative safety fact.

## Regenerability and risk are separate

`RegenerabilityState` answers a reproducibility question: can the artifact be recreated, and what evidence and conditions support that claim? `RiskLabel.REGENERATABLE` answers a safety-policy question: after the ordered safety gates are applied, is conditional reclaimability the most appropriate conclusion? The latter requires more than a verified recipe or generator. Confirmed reachability, active use, protection evidence, unresolved uncertainty, and conflicting observations can all prevent `REGENERATABLE` even when regeneration is proven.

## Evaluation boundary

The conceptual flow is:

```text
ObservedNode
  -> evidence collection
  -> candidate selection
  -> artifact interpretation
  -> ordered safety gates
  -> RiskLabel + ActionEligibility + RuleTrace
  -> independent ReclaimPriority
```

Detectors may contribute evidence and artifact interpretations. They must not directly assign the final risk label.
