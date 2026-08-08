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
| `.venv` / `venv` | Directory marker plus valid `pyvenv.cfg`, interpreter layout, and project context | Python `venv`, virtualenv, uv, or another tool | Recreate from project metadata; may require network, credentials, native wheels, or local packages; cost varies | Check active interpreter references, project lockfiles, scripts, links, and partial/corrupt environments | Context-dependent candidate; verified regeneration alone is insufficient; active/reference uncertainty => `REVIEW_REQUIRED` |
| pip download/cache data | Known pip cache layout and metadata, not merely a directory name | pip | Re-download packages; network and package availability may be required | May be shared across projects and may contain valuable offline dependencies | Shared-cache context must be established before any policy conclusion; uncertainty => `REVIEW_REQUIRED` |

## Node.js artifacts

| Artifact | Identifying evidence | Likely provenance | Regeneration requirement / cost | Reachability and edge cases | Initial evidence posture (not a RiskLabel) |
|---|---|---|---|---|---|
| `node_modules` | Package tree plus nearby `package.json` and, where present, a lockfile | npm, pnpm, yarn, or another Node tool | Reinstall from manifest/lockfile; may require network, private registry access, native builds, or exact Node version | Check workspace packages, symlinks, shared stores, and package/lockfile consistency | Context-dependent candidate; reproducibility evidence alone cannot produce `REGENERATABLE`; uncertainty => `REVIEW_REQUIRED` |
| `dist` | Build output markers and project build configuration | Project build tool | Rebuild from source; cost varies and may require secrets, generated inputs, or network | Do not assume every `dist` directory is generated; verify provenance and deployment use | Build evidence only; candidate and risk require provenance, reachability, activity, and protection gates |
| `build` | Build output markers and tool-specific metadata | Project build tool | Rebuild from source; cost varies | May be user-authored or deployment input; verify before classifying | Ambiguous artifact identity; runtime or provenance uncertainty => `REVIEW_REQUIRED` |
| `.next` | Next.js build/cache markers and project metadata | Next.js | Recreated by the Next.js build/dev workflow; cost varies | Check whether it is used by a running process or deployment workflow | Reproducibility evidence only; active or referenced => minimum `REVIEW_REQUIRED` |
| npm/pnpm/yarn cache | Tool-specific cache layout and metadata | npm, pnpm, or yarn | Usually refetched; network, registry, and disk costs apply | May be shared by many projects; cache corruption or offline use matters | Shared-cache evidence required; uncertainty => `REVIEW_REQUIRED` |

## Git protection and context

Git control metadata is observed only for protection and context. It is not a cleanup artifact. `.git` directories and `.git` files remain `ObservedNode`s and are excluded from `CleanupCandidate` selection; `NEVER_DELETE` is protection semantics, not reclaim eligibility.

| Artifact | Identifying evidence | Likely provenance | Regeneration requirement / cost | Reachability and edge cases | Initial evidence posture (not a RiskLabel) |
|---|---|---|---|---|---|
| `.git` directory | Git control files such as `HEAD`, `objects`, `refs`, or `config` | Git repository | Not a disposable cache; recovery may require a remote or may be impossible | Observe for repository protection/context; inspect worktrees, alternates, submodules, and permissions | `ObservedNode` only; never a `CleanupCandidate`. `NEVER_DELETE` is protection semantics, not reclaim eligibility |
| `.git` file | File containing a `gitdir:` reference, common for worktrees/submodules | Git worktree or submodule | Not a disposable cache | Observe the reference for protection/context; broken or inaccessible references remain protected/uncertain | `ObservedNode` only; never a `CleanupCandidate`. `NEVER_DELETE` is protection semantics, not reclaim eligibility |

## Evidence requirements shared by all artifacts

Future detectors should record the exact path, observed object type, marker evidence, provenance basis, `RegenerabilityState` evidence, observation failures, regeneration conditions, reachability checks, protection findings, and rule version. Artifact names alone are insufficient. A detector must not emit `RiskLabel.REGENERATABLE`; that label belongs to the Safety Policy after all gates pass.

For the first `__pycache__` detector, the contract additionally records the exact directory-name observation. This is raw path evidence used to prevent a name-only match from establishing artifact identity; it is not a domain-state or risk conclusion. An embedded source filename reference is recorded separately from recreation-input availability; the former does not prove that the latter is present.

## Open catalog questions

- Which exact lockfile formats and package-manager stores are in MVP scope?
- What minimum Windows process/activity evidence can be collected reliably without administrative privileges?
- How should shared package stores be represented when one project can be rebuilt but other projects may depend on the same data?
