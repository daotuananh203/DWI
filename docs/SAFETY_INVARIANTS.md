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

## Default posture

The system must prove that an artifact meets the requirements for a low-risk label. It must not infer safety because a dangerous condition was not detected.

Artifact names, verified regenerability, and low staleness are not sufficient by themselves to produce a `RiskLabel`. Runtime uncertainty defaults to `REVIEW_REQUIRED`.

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

The MVP only analyzes and reports. It does not delete, move, quarantine, or otherwise mutate user data. Any future cleanup operation requires a separate approved design covering confirmation, recovery, journaling, race conditions, and failure handling.
