# DWI Tasks

## Current state

The v0.1 Workspace Intelligence layer is frozen. The v0.2 System Intelligence
layer now adds bounded approved-root discovery, a fail-closed Scan Safety Gate,
shared traversal limits/cancellation, explicit system-scan metadata, and
detector-neutral global cache analysis for pip, uv, npm, pnpm, and yarn where
local structure is defensible. All current behavior is covered by
synthetic/tempdir and mocked-boundary tests.

There is still no cleanup execution, UI, MCP adapter, LLM integration,
telemetry, cloud/API access, background service, or dynamic plugin system.
System scanning remains bounded, read-only, offline-first, and developer-storage
aware. Git remains structured protection/context only and is not a cleanup
candidate. Cleanup planning, revalidation, execution authorization,
Trash/Quarantine, journaling, and Undo are future roadmap capabilities.

## Next task — exactly one

- [ ] Define the bounded v0.3 Safe Cleanup planning and immediate revalidation contract.

### Acceptance criteria

- Specify immutable engine-generated cleanup plans, plan-item identifiers,
  immediate filesystem/evidence revalidation, and conservative invalidation.
- Preserve the existing observations → evidence → interpretation → Safety Policy
  pipeline and all fail-closed invariants.
- Keep `SAFE` separate from execution authorization and keep Git metadata as
  protection/context only.
- Do not execute cleanup, move/delete files, add Trash/Undo, implement Desktop,
  MCP, i18n runtime, or add new dependencies.

Future work is described in [docs/ROADMAP.md](docs/ROADMAP.md), but it is not authorized by this task list.
