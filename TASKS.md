# DWI Tasks

## Current state

The typed domain model, detector-neutral contracts, four Python cache analyzers,
the bounded `.venv` analyzer, bounded Node.js analyzers for `node_modules`,
`dist`, `build`, and `.next`, an explicit single-candidate dispatcher, the
bounded workspace scanner, read-only size accounting, and deterministic CLI
reports are implemented and covered by synthetic/tempdir tests.

There is still no disk-wide discovery, UI, MCP adapter, LLM integration,
cleanup execution, or dynamic plugin system. Git is currently represented only
as a structured scanner protection/context observation and is not a cleanup
candidate. Cleanup planning, revalidation, execution authorization,
Trash/Quarantine, journaling, and Undo are future roadmap capabilities.

## Next task — exactly one

- [ ] Define the bounded v0.2 System Intelligence discovery contract for approved global developer-storage locations.

### Acceptance criteria

- Specify approved Windows global locations, boundary ownership, and candidate
  categories without implementing whole-system traversal.
- Preserve observations → evidence → interpretation → Safety Policy and all
  existing fail-closed invariants.
- Keep Git metadata as protection/context only and keep machine-readable
  identifiers stable.
- Do not implement whole-system scanning, cleanup, Desktop, MCP, i18n runtime,
  or new dependencies.

Future work is described in [docs/ROADMAP.md](docs/ROADMAP.md), but it is not authorized by this task list.
