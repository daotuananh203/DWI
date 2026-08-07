# Developer Workspace Intelligence (DWI)

DWI is a documentation-first specification for a Windows-focused tool that helps developers understand which generated workspace artifacts may be reclaimable, how cautious the decision should be, and why.

Existing disk analyzers answer:

> What is using disk space?

DWI is intended to answer:

> What storage may be reclaimed, what evidence supports that conclusion, and what could make reclaiming it unsafe?

## Current status

This repository currently contains the project constitution and domain specifications only. The MVP is analysis-and-reporting-only. It does not delete files, call an LLM, access a cloud service, or provide a UI.

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

The first implementation task is recorded in [TASKS.md](TASKS.md). No implementation work is part of this initialization.
