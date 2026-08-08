# DWI Tasks

## Current state

The typed domain model, detector-neutral contracts, four Python cache analyzers,
the bounded `.venv` analyzer, bounded Node.js analyzers for `node_modules`,
`dist`, `build`, and `.next`, and an explicit single-candidate dispatcher are
implemented and covered by deterministic synthetic/tempdir tests.

There is still no recursive workspace scanner, disk-wide discovery, CLI, UI,
MCP adapter, LLM integration, cleanup execution, or dynamic plugin system.

## Next task — exactly one

- [ ] Add an explicit candidate-selection and safety-policy adapter for one dispatcher result.

### Acceptance criteria

- Consume exactly one `AnalysisResult` and explicit candidate-selection evidence.
- Preserve observations → evidence → interpretation → domain states → Safety Policy.
- Never assign a risk label inside a detector or from an artifact name.
- Preserve confirmed-reachability, active-runtime, protection, uncertainty, conflict, and monotonic-risk gates.
- Keep `RegenerabilityState`, `RiskLabel`, `ActivityState`, `ActionEligibility`, and `ReclaimPriority` separate.
- Use synthetic inputs only; do not add recursive scanning, CLI, cleanup, UI, MCP, LLM, plugins, or dependencies.

Future work is described in [docs/ROADMAP.md](docs/ROADMAP.md), but it is not authorized by this task list.
