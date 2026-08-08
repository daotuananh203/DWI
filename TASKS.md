# DWI Tasks

## Current state

The typed domain model, detector-neutral contracts, four Python cache analyzers,
the bounded `.venv` analyzer, bounded Node.js analyzers for `node_modules`,
`dist`, `build`, and `.next`, an explicit single-candidate dispatcher, the
bounded workspace scanner, read-only size accounting, and deterministic CLI
reports are implemented and covered by synthetic/tempdir tests.

There is still no disk-wide discovery, UI, MCP adapter, LLM integration,
cleanup execution, or dynamic plugin system. Git is currently represented only
as a scanner boundary; a structured Git protection/context adapter is not yet
implemented. Cleanup planning, revalidation, execution authorization,
Trash/Quarantine, journaling, and Undo are future roadmap capabilities.

## Next task — exactly one

- [ ] Add a bounded structured Git protection/context observation adapter for `.git` directories and `.git` files.

### Acceptance criteria

- Inspect only one explicitly supplied `.git` directory or `.git` file.
- Produce an immutable `ObservedNode` protection/context result, never a `CleanupCandidate`.
- Preserve `NEVER_DELETE` as protection semantics, not reclaim eligibility.
- Record missing, failed, symlinked, and ambiguous observations conservatively.
- Do not implement repository history analysis, reachability graphs, cleanup, or new dependencies.

Future work is described in [docs/ROADMAP.md](docs/ROADMAP.md), but it is not authorized by this task list.
