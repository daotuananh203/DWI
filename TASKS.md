# DWI Tasks

## Current state

The documentation-first initialization is complete. There is no scanner, detector, CLI, rule engine, or application code yet.

## Next task — exactly one

- [ ] Implement the typed domain model and evidence schema skeleton, with unit tests for conservative defaults, monotonic risk escalation, and separation of intrinsic risk from current activity.

### Acceptance criteria

- The model represents observed nodes, cleanup candidates, evidence status, provenance, regenerability, reachability, activity, protection, risk, action eligibility, reclaim priority, and rule traces.
- Unknown or failed evidence cannot produce `SAFE`.
- Confirmed references or active consumers impose a minimum `REVIEW_REQUIRED` label and cannot produce `SAFE` or `REGENERATABLE`.
- `.git` directories and `.git` files remain `ObservedNode` protection/context only and cannot become `CleanupCandidate` inputs; `NEVER_DELETE` is not reclaim eligibility.
- `RegenerabilityState` records reproducibility evidence/property separately from `RiskLabel.REGENERATABLE`; verified regenerability alone cannot determine the risk label.
- Risk labels can only escalate during one evaluation.
- Active runtime state can block action without changing the artifact's intrinsic risk label.
- Tests are deterministic and do not inspect or modify a user's real filesystem.
- No scanner, detector implementation, CLI, deletion behavior, or new external dependency is added.

Future work is described in [docs/ROADMAP.md](docs/ROADMAP.md), but it is not authorized by this task list.
