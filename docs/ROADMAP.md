# Roadmap

## Completed initialization

- Project vision and scope boundaries.
- Domain vocabulary and risk-label semantics.
- Safety invariants and conservative evidence posture.
- Architecture boundaries and evidence pipeline.
- Initial Python, Node.js, and Git evidence catalog.
- Adversarial case catalog.

## Completed bounded analysis layer

- Typed immutable domain model and detector-neutral evidence contracts.
- Read-only analyzers for the four initial Python caches.
- Read-only `.venv` / `venv` analysis with a candidate-local boundary.
- Read-only Node.js analysis for `node_modules`, `dist`, `build`, and `.next`.
- Explicit single-candidate dispatcher with no recursive discovery.
- Synthetic and temporary-directory adversarial tests for the bounded analyzers.

## MVP

The MVP remains Windows-only and analysis/reporting-only:

- Typed domain model and evidence schema.
- Deterministic ordered safety policy.
- Python and Node.js artifact detectors.
- Minimal Git protection/context observation; `.git` directories and `.git` files remain outside the `CleanupCandidate` pipeline.
- Filesystem scanner with explicit handling of permissions, links, junctions, and reparse points.
- CLI table output and JSON reports.
- Deterministic unit and fixture tests.

The MVP does not delete, move, quarantine, or automatically clean user data.

## Post-MVP

Potential extensions, each requiring a separate scope decision:

- Broader package-manager and IDE coverage.
- Multi-project reachability graph and shared-cache analysis.
- Persistent local index for faster repeated scans.
- Desktop or local web presentation.
- Cleanup planning with human confirmation, move-to-trash, recovery journal, and race-condition handling.
- MCP read-only adapter.
- Optional LLM explanation layer that can only summarize already-computed evidence and decisions.

## Thesis and research extensions

- Ground-truth dataset of workspace artifacts and manually reviewed labels.
- Evaluation of safety precision, recall, and false-positive behavior by label.
- Scan time and memory measurements on representative Windows workspaces.
- User study comparing evidence-based explanations with size-only disk reports.
- Empirical study of shared reachability and reclaim priority.
- Reproducible experiment reports and limitations analysis.

All roadmap items after the MVP are ideas, not authorization to implement them.
