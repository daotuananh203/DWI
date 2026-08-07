# Project Vision

## Problem

Developer workspaces accumulate generated data: Python environments and caches, Node.js dependencies and build output, package-manager data, IDE metadata, logs, temporary files, and other artifacts that may be reproducible. Existing disk analyzers are useful for locating large paths, but size alone does not explain whether reclaiming a path is safe or worthwhile.

DWI focuses on semantic workspace analysis. It combines filesystem observations with artifact knowledge and explicit safety rules to produce a cautious, auditable report.

## Product thesis

> A developer disk tool should explain not only what consumes space, but what may be reclaimed, how risky that would be, and why.

## MVP

The MVP is deliberately narrow:

- Windows only.
- CLI/reporting interface only.
- Python and Node.js artifact analysis.
- Minimal Git awareness for protection and context, including `.git` directories and `.git` files.
- Deterministic findings with structured evidence and explanations.
- Four risk labels: `SAFE`, `REGENERATABLE`, `REVIEW_REQUIRED`, and `NEVER_DELETE`.
- No file deletion, automatic cleanup, desktop UI, web UI, FastAPI, MCP, LLM integration, Docker analysis, Hugging Face analysis, Ollama analysis, dynamic plugin discovery, or cloud features.

## Non-goals

DWI is not a generic disk visualizer, antivirus product, backup system, source-code analyzer, package manager, or autonomous cleanup agent. It must not infer that user-authored source code or a project root is disposable merely because it is large or old.

## Design values

- **Safety by proof:** a low-risk label requires supporting evidence; absence of detected danger is not proof of safety.
- **Offline first:** core analysis must work without an AI provider, network access, or cloud account.
- **Evidence before labels:** detectors and observations provide facts; a separate policy derives labels.
- **Conservative uncertainty:** unknown, failed, or conflicting observations reduce certainty and fail closed.
- **Reachability as a hard gate:** a confirmed reference or active consumer means the minimum risk is `REVIEW_REQUIRED`; it cannot be `SAFE` or `REGENERATABLE`.
- **Reproducibility is not safety:** `RegenerabilityState` describes whether recreation is possible and under what conditions. `RiskLabel.REGENERATABLE` is a separate Safety Policy conclusion and requires additional gates.
- **Protection is not candidacy:** `.git` directories and `.git` files are observed for protection/context and are never `CleanupCandidate` inputs. `NEVER_DELETE` describes protection semantics, not reclaim eligibility.
- **No name-based labels:** artifact names identify evidence to investigate; they do not directly map to `RiskLabel`. Runtime uncertainty defaults to `REVIEW_REQUIRED`.
- **Explainability:** every result carries the evidence and rule trace that produced it.
- **Small increments:** the MVP prefers simple typed Python modules over speculative frameworks.

## Success for this initialization

Another engineer or coding agent can read the repository and understand the product, its boundaries, its safety model, the intended evidence vocabulary, adversarial cases, and exactly one next implementation task without guessing at the project's governing principles.
