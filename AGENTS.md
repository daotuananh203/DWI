# Instructions for AI Coding Agents

These rules apply to every agent working in this repository.

## Before changing anything

- Read [README.md](README.md), the relevant documents under `docs/`, and [TASKS.md](TASKS.md).
- Work on one bounded task at a time. The active task must have explicit acceptance criteria.
- Treat the documentation as part of the source of truth, not as optional background material.
- Check the current working tree before editing and preserve unrelated user changes.

## Non-negotiable constraints

- Preserve every invariant in [docs/SAFETY_INVARIANTS.md](docs/SAFETY_INVARIANTS.md).
- Keep the decision path deterministic, auditable, and explainable from structured evidence.
- Never introduce an LLM, AI agent, cloud API, or probabilistic model into the safety decision path.
- Never implement deletion or automatic cleanup unless a future task explicitly authorizes it and defines the safety and recovery design.
- Do not treat a directory name, age, or regenerability alone as proof of safety.
- Treat confirmed references or active consumers as a hard gate: the minimum `RiskLabel` is `REVIEW_REQUIRED`; never classify the artifact as `SAFE` or `REGENERATABLE`.
- Treat `.git` directories and `.git` files as `ObservedNode` protection/context, never as `CleanupCandidate` inputs. `NEVER_DELETE` expresses protection semantics, not reclaim eligibility.
- Keep `RegenerabilityState` as reproducibility evidence/property. `RiskLabel.REGENERATABLE` is a separate Safety Policy conclusion and requires more than verified regenerability.
- Missing, failed, unknown, or conflicting observations must remain conservative.

## Scope discipline

- Do not silently expand the MVP beyond Windows, CLI/reporting, Python, Node.js, and minimal Git protection/context.
- Do not add desktop UI, web UI, FastAPI, MCP, Docker analysis, Hugging Face analysis, Ollama analysis, dynamic plugin discovery, or cloud features unless the roadmap and an approved task explicitly move them into scope.
- Avoid new dependencies. Every dependency must have a documented reason and a task-level approval.
- Stop and ask for direction before changing architecture, safety assumptions, public domain meaning, or MVP boundaries.

## Completion protocol

Before reporting a task complete:

1. Run the relevant tests or documentation checks.
2. Review the diff for accidental scope expansion.
3. Report every file changed.
4. Report every check or test run and its result.
5. Report unresolved questions and assumptions.

Agents must not claim a safety property that has not been demonstrated by evidence and tests.
