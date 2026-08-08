# Developer Workspace Intelligence (DWI)

DWI is a developer-storage intelligence and safe-cleanup system that discovers
development artifacts across an entire machine, explains provenance,
regenerability, reachability, and risk using deterministic evidence, and exposes
the same safety engine through Desktop, CLI, and MCP interfaces for humans and
AI agents.

Existing disk analyzers answer:

> What is using disk space?

DWI is intended to answer:

> What storage may be reclaimed, what evidence supports that conclusion, and what could make reclaiming it unsafe?

## North Star and current status

The final product is a whole-system Developer Storage Intelligence & Safe
Cleanup System. It will combine machine-wide discovery, deterministic safety
analysis, cleanup planning, immediate revalidation, Trash/Quarantine,
auditable journals, Undo/recovery, Desktop, CLI, and MCP interfaces over one
shared engine.

The typed domain model, detector-neutral evidence contracts, bounded artifact
analyzers, explicit dispatcher, workspace scanner, structured Git context,
bounded System Intelligence discovery, size accounting, standard-library
CLI/report adapters, and v0.3 cleanup planning/validation/authorization
contracts are implemented. The current internal milestone is v0.3 Safe Cleanup
design. It remains analysis-and-contract-only: it does not delete or move
files, execute plans, implement Trash/Quarantine, call an LLM, expose MCP, or
provide a UI.

Run a bounded report from one explicit workspace root:

```text
python -m dwi scan PATH
python -m dwi scan PATH --json
python -m dwi scan-system --root PATH --allow-network
python -m dwi scan-system --json
```

The scanner recognizes only the documented artifact names, does not follow
links or reparse points, excludes `.git` from cleanup candidates, and reports
unknown or incomplete observations conservatively.

`scan-system` applies the Scan Safety Gate: local fixed drives and approved
local roots are allowed, UNC/network roots are denied by default, links and
reparse points are never followed, and limits or cancellation produce
deterministic partial results. Use `--allow-network` only for an explicit
opt-in; network scanning is never the default.

DWI is offline-first and read-only. It performs no telemetry, automatic
diagnostic upload, HTTP, cloud, or API communication. Network filesystem access
is denied by default; explicit `--allow-network` may perform filesystem I/O on
approved UNC, mapped, or other network-backed roots. Reports containing paths
remain local to the machine.

Read the documents in this order:

1. [Project vision](docs/PROJECT_VISION.md)
2. [Domain model](docs/DOMAIN_MODEL.md)
3. [Safety invariants](docs/SAFETY_INVARIANTS.md)
4. [Architecture](docs/ARCHITECTURE.md)
5. [Evidence catalog](docs/EVIDENCE_CATALOG.md)
6. [Adversarial cases](docs/ADVERSARIAL_CASES.md)
7. [Roadmap](docs/ROADMAP.md)
8. [Tasks](TASKS.md)

## Safety position

DWI must work without an AI provider. Deterministic evidence collection and ordered safety rules are the source of truth. An LLM may eventually explain an already-computed result, but it must never participate in the safety decision path.

Artifact names never map directly to risk labels. A low-risk label is available only after sufficient evidence passes the ordered safety gates. Runtime uncertainty defaults to `REVIEW_REQUIRED`.

The current bounded implementation boundary and exactly one next task are recorded in [TASKS.md](TASKS.md).

The v0.3 contract layer defines immutable engine-generated cleanup plans,
explicit trusted scan/root bindings, immediate revalidation, and separate
engine-provenance-backed execution authorization. A `CleanupPlan` is a proposal,
not permission to mutate data; cleanup execution remains unimplemented.

Future cleanup operations must consume immutable engine-generated plans and
validated plan-item identifiers. No interface may expose arbitrary raw-path
deletion.

## Release and language strategy

Versions v0.1 through v0.5 are internal development milestones. DWI will be
released publicly on GitHub only as v1.0.0, after the complete North Star and
the full Definition of Done in [docs/ROADMAP.md](docs/ROADMAP.md) are reached.

DWI is bilingual:

- English (`en`) is the primary language for international users and public
  GitHub documentation.
- Vietnamese (`vi`) supports Vietnamese users.

Human-facing Desktop, CLI, messages, and documentation will support
localization. Machine-readable contracts remain stable and language-neutral:
JSON keys, enums, `RiskLabel` values, MCP tool names, API/schema identifiers,
and internal evidence keys do not change by language. Future public
documentation will provide `README.md` in English and `README.vi.md` in
Vietnamese. Runtime i18n is not implemented in v0.3.
