# Evidence Catalog

This is a specification of candidate evidence, not an implementation or a promise that an artifact is safe. A detector must collect enough contextual evidence before the Safety Policy can classify a candidate.

## Interpretation key

- **Initial evidence posture** is not a `RiskLabel` and must never be interpreted as an artifact-name-to-label mapping.
- **Reachability check** describes the evidence needed to rule out active or cross-project use.
- **Regeneration requirement** includes commands, metadata, network, credentials, or local state that may be needed.
- A missing marker, inaccessible path, name-only match, or runtime uncertainty must not be treated as proof of safety; runtime uncertainty defaults to `REVIEW_REQUIRED`.
- A low-risk label is available only after sufficient evidence passes all applicable ordered Safety Policy gates. Confirmed references or active consumers impose a minimum `REVIEW_REQUIRED` label.

## Python artifacts

| Artifact | Identifying evidence | Likely provenance | Regeneration requirement / cost | Reachability and edge cases | Initial evidence posture (not a RiskLabel) |
|---|---|---|---|---|---|
| `__pycache__` | Directory contains Python bytecode such as `.pyc` and is associated with source or package files | Python interpreter | Recreated by importing or running Python; usually low cost | Check links, permissions, and whether the path is a protected package/cache location | Candidate identity requires corroborating evidence; low-risk labels require all gates and confirmed non-reachability; uncertainty => `REVIEW_REQUIRED` |
| `.pytest_cache` | Pytest cache markers such as `README.md` or `CACHEDIR.TAG` | pytest | Recreated by running tests; usually low cost | Confirm it is a test cache and not user-authored data or a symlinked path | Reproducibility evidence only; runtime uncertainty or confirmed reference => `REVIEW_REQUIRED` |
| `.mypy_cache` | Mypy cache structure and metadata | mypy | Recreated by type checking; may require dependencies and configuration | Confirm the directory is not a manually maintained artifact | Reproducibility evidence only; do not derive a risk label from the name |
| `.ruff_cache` | Ruff cache markers or known cache layout | Ruff | Recreated by Ruff; usually low cost | Check for ambiguous names and inaccessible metadata | Reproducibility evidence only; uncertainty => `REVIEW_REQUIRED` |
| `.venv` / `venv` | Directory marker plus valid `pyvenv.cfg` and interpreter layout | Python virtual-environment tooling | Recreate from project metadata; may require network, credentials, native wheels, or local packages; bounded cost remains unknown | Check active interpreter references, project lockfiles, scripts, links, and partial/corrupt environments | Context-dependent candidate; verified regeneration alone is insufficient; active/reference uncertainty => `REVIEW_REQUIRED` |
| pip download/cache data | Known pip cache layout and metadata, not merely a directory name | pip | Re-download packages; network and package availability may be required | May be shared across projects and may contain valuable offline dependencies | Shared-cache context must be established before any policy conclusion; uncertainty => `REVIEW_REQUIRED` |

## Node.js artifacts

| Artifact | Identifying evidence | Likely provenance | Regeneration requirement / cost | Reachability and edge cases | Initial evidence posture (not a RiskLabel) |
|---|---|---|---|---|---|
| `node_modules` | Bounded package tree, package manifests within inspected package entries, and local package-manager markers where present | npm, pnpm, yarn, or another Node tool | Reinstall from project manifest/lockfile; may require network, private registry access, native builds, or exact Node version | Shared stores, workspace reachability, nearby project manifests, and cross-project consumers are outside this detector | Context-dependent candidate; reproducibility evidence alone cannot produce `REGENERATABLE`; uncertainty => `REVIEW_REQUIRED` |
| `dist` | Bounded output markers and build metadata observations | Unknown until tool-specific evidence is available | Rebuild from source; cost varies and may require secrets, generated inputs, or network; bounded cost remains unknown | Generic output and manifest files may be user-authored; do not assume every `dist` directory is generated | Generic build evidence is insufficient for strong provenance; candidate and risk require additional gates |
| `build` | Bounded output markers and build metadata observations | Unknown until tool-specific evidence is available | Rebuild from source; cost varies and may require secrets, generated inputs, or network; bounded cost remains unknown | Generic output and manifest files may be user-authored or deployment input | Generic build evidence is insufficient for strong provenance; runtime or provenance uncertainty => `REVIEW_REQUIRED` |
| `.next` | Next.js build/cache markers and project metadata | Next.js | Recreated by the Next.js build/dev workflow; cost varies | Check whether it is used by a running process or deployment workflow | Reproducibility evidence only; active or referenced => minimum `REVIEW_REQUIRED` |
| npm/pnpm/yarn cache | Tool-specific cache layout and metadata | npm, pnpm, or yarn | Usually refetched; network, registry, and disk costs apply | May be shared by many projects; cache corruption or offline use matters | Shared-cache evidence required; uncertainty => `REVIEW_REQUIRED` |

## Git protection and context

Git control metadata is observed only for protection and context. It is not a cleanup artifact. `.git` directories and `.git` files remain `ObservedNode`s and are excluded from `CleanupCandidate` selection; `NEVER_DELETE` is protection semantics, not reclaim eligibility.

| Artifact | Identifying evidence | Likely provenance | Regeneration requirement / cost | Reachability and edge cases | Initial evidence posture (not a RiskLabel) |
|---|---|---|---|---|---|
| `.git` directory | Git control files such as `HEAD`, `objects`, `refs`, or `config` | Git repository | Not a disposable cache; recovery may require a remote or may be impossible | Observe only the bounded direct-root control layout; repository history, worktrees, alternates, submodules, and permissions are not analyzed | `ObservedNode` only; never a `CleanupCandidate`. `NEVER_DELETE` is protection semantics, not reclaim eligibility |
| `.git` file | File containing a `gitdir:` reference, common for worktrees/submodules | Git worktree or submodule | Not a disposable cache | Record one bounded `gitdir:` reference without opening or traversing its target; broken or inaccessible references remain protected/uncertain | `ObservedNode` only; never a `CleanupCandidate`. `NEVER_DELETE` is protection semantics, not reclaim eligibility |

## Evidence requirements shared by all artifacts

Future detectors should record the exact path, observed object type, marker evidence, provenance basis, `RegenerabilityState` evidence, observation failures, regeneration conditions, reachability checks, protection findings, and rule version. Artifact names alone are insufficient. A detector must not emit `RiskLabel.REGENERATABLE`; that label belongs to the Safety Policy after all gates pass.

For the first `__pycache__` detector, the contract additionally records the exact directory-name observation. This is raw path evidence used to prevent a name-only match from establishing artifact identity; it is not a domain-state or risk conclusion. An embedded source filename reference is recorded separately from recreation-input availability; the former does not prove that the latter is present.

The `.pytest_cache` detector likewise records its exact directory name separately from raw `CACHEDIR.TAG`, `README.md`, and direct layout observations. Marker names alone do not establish pytest provenance or a safety conclusion.

## Bounded artifact-layer implementation notes

The `.venv` / `venv` analyzer inspects only the candidate itself: exact name,
`pyvenv.cfg`, the Windows `Scripts/python.exe` layout, and optional metadata
physically inside the candidate. It never searches the parent for a project
manifest or lockfile. Valid local structure therefore produces at most
`CONDITIONALLY_REPRODUCIBLE`, with tool-neutral provenance
`python-virtual-environment`; recreation-input availability and regeneration
cost remain unknown.

The `node_modules` analyzer inspects direct package directories and one bounded
level for scoped packages, their `package.json` manifests, and local package-
manager markers such as npm's hidden lock marker. It does not inspect nearby
project manifests, shared stores, package-manager workspaces, or package-wide
reachability.

The `dist` and `build` analyzers inspect only direct output files/directories and
recognized build metadata files at the candidate root. Generic `index.js` plus
`manifest.json` evidence can describe user-authored data, so it does not produce
strong build-tool provenance or conditional regenerability. Source inputs outside
the candidate are not inspected and regeneration cost remains unknown. The
`.next` analyzer retains its bounded Next.js-specific metadata, output structure,
and configuration requirements, but its regeneration cost also remains unknown.

All five analyzers keep runtime activity, references, and protection unknown
unless a later evidence source explicitly replaces those observations. The
dispatcher accepts one explicit path and selects only by its basename; it does
not discover other candidates.

The `.mypy_cache` detector records its exact directory name separately from raw version-directory and module metadata/data observations. An exact name, a generic cache marker, or an incomplete metadata/data pair does not establish mypy provenance or a safety conclusion.

The `.ruff_cache` detector records its exact directory name separately from raw `CACHEDIR.TAG`, Ruff-generated `.gitignore`, version-directory, and cache-key observations. Root markers or version-directory names alone do not establish Ruff provenance or a safety conclusion.

The `.pytest_cache` detector likewise records its exact directory name separately from raw `CACHEDIR.TAG`, `README.md`, and direct layout observations. Marker names alone do not establish pytest provenance or a safety conclusion.

## Open catalog questions

- Which exact lockfile formats and package-manager stores are in MVP scope?
- What minimum Windows process/activity evidence can be collected reliably without administrative privileges?
- How should shared package stores be represented when one project can be rebuilt but other projects may depend on the same data?

## End-to-end bounded reporting notes

The workspace scanner accepts one explicit ordinary root and discovers only the
supported artifact names. It does not follow symlinks, junctions, or reparse
points, and it does not recurse into an identified candidate for further
discovery. A candidate's size is a separate read-only observation: known bytes
are reported only when traversal is complete, while skipped links and read
failures make the size incomplete. Size never changes a risk label.

`.git` directories and `.git` files are protected/context observations and are
not `CleanupCandidate` inputs. The scanner records their paths but does not
assign a reclaim conclusion to them. Rejected candidate-selection results are
reported with an effective `REVIEW_REQUIRED` posture and retain their raw
evidence; they do not receive a Safety Policy decision until admitted.

## Structured Git context observation

The bounded Git adapter accepts exactly one explicit `.git` path. A normal
`.git` directory is inspected only at its direct root for the required control
layout (`HEAD`, `config`, `objects`, and `refs`); repository history and object
graphs are never traversed. A `.git` file is parsed for one `gitdir:` reference,
but its target is recorded and never opened or traversed. External, missing,
malformed, unreadable, symlinked, and reparse-point cases remain protected and
ambiguous/failed rather than being guessed.

The scanner stores structured `GitContextObservation` results while retaining
the derived protected-path view for compatibility. Git observations are never
sent to the artifact dispatcher or admitted as cleanup candidates.
