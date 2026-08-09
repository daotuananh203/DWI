# Adversarial and Ambiguous Cases

These cases define the failure-oriented design and future test fixtures. They are documented before filesystem scanning so that implementation does not encode optimistic assumptions.

## Python

- `pyvenv.cfg` exists, but project metadata is missing, broken, or inconsistent.
- A virtual environment is partially deleted or its interpreter target no longer exists.
- A directory resembles `.venv` but contains user-authored files or unrelated data.
- A cache is behind a symlink or junction whose target cannot be resolved.
- Permission is denied while reading a marker, lockfile, or directory contents.
- A virtual environment is currently selected by a running process or IDE.

## Node.js

- `package.json` and the lockfile disagree on versions or package manager.
- A lockfile is empty, corrupted, unreadable, or generated for a different tool.
- `node_modules` contains symlinked workspace packages or native modules.
- `dist` or `build` is user-authored, deployed directly, or required as an input to another process.
- A package cache is shared by multiple projects or is needed for offline development.

## Git and Windows filesystem behavior

- `.git` is a file rather than a directory because the path is a worktree or submodule.
- Git alternates, submodules, or worktree references point outside the scanned root.
- A junction or reparse point creates an apparent orphan or duplicate path.
- A symlink references a candidate from another project.
- A path disappears or changes between observation steps.
- A protected path is stale but remains part of a repository or system workflow.

## System Intelligence and Scan Safety Gate

- A UNC, mapped, or network-backed root is supplied without explicit opt-in.
- A fixed-drive classification is unavailable or the root is removable rather
  than fixed.
- A user-provided root is a symlink, junction, or reparse point.
- A directory disappears between root approval and traversal.
- Cancellation or node/file/time limits stop traversal midway.
- A pip, uv, npm, pnpm, or yarn cache has only a familiar name but no bounded
  tool-specific structure.
- A valid global cache is shared by projects whose reachability was not
  inspected.
- A report contains partial known bytes and must not call them reclaimable.

## Evidence conflicts and failures

- Two detectors assign incompatible provenance to the same node.
- One observation says a path is inactive while another confirms an active reference.
- A parser fails after a marker was found.
- A timeout prevents checking reachability.
- The filesystem reports an object type that the current implementation cannot interpret.

## Cleanup planning and authorization

- A caller supplies a raw path list instead of engine-generated Findings.
- A caller omits scan completeness or supplies an unknown, partial, failed,
  denied, or skipped scan context.
- A candidate uses a relative path, `..` escape, wrong root, outside-root path,
  invalid filesystem identity, or a symlink/reparse-backed identity.
- A rejected, `REVIEW_REQUIRED`, `NEVER_DELETE`, active, referenced, protected,
  incomplete, or blocked finding is presented for planning.
- A plan item path disappears, changes identity/type, or becomes a
  symlink/junction/reparse point before validation.
- Evidence, rule trace, size, protection, reachability, activity, or Safety
  Policy posture changes after planning.
- A partial or failed SystemScan is incorrectly treated as complete.
- A stale validation token or replayed authorization is presented to an
  executor.
- A Windows 8.3 alias resolves to `Program Files`, `Program Files (x86)`,
  `ProgramData`, or `Windows`, or authoritative final-path resolution fails.
- A lexical path and authoritative final path differ at planning or immediate
  mutation revalidation, including a reparse/junction substitution.
- Two concurrent attempts claim the same authorization item, or a process
  stops after the claim and before `PLANNED`.
- A caller constructs an apparently `VALID` `PlanValidation`, copies a token,
  modifies validation fields, or presents validation for a different plan.
- A future quarantine destination is occupied, unavailable, or cannot be
  journaled after a crash.
- A human confirmation is missing, forged, stale, bound to another plan, or
  based on a modified review snapshot.
- The human CLI receives an unsafe `--force`/`--yes` flag or a raw `delete`,
  `remove`, or `quarantine` command; these must be rejected before the service.
- CLI JSON output leaks an authorization capability, proof token, or another
  value that could be replayed by a later process.
- Filesystem identity, policy posture, scan completeness, or evidence changes
  after confirmation and before fresh validation.
- An orphan authorization claim is discovered after restart; it must be
  journaled as claimed-then-failed or remain reconciliation-required without
  candidate/payload mutation or automatic retry. The allowed journal append is
  metadata reconciliation for the pre-existing recovery state, not a new
  cleanup lifecycle.
- A quarantine rename commits but its final `QUARANTINED` journal append fails.
- A restore rename commits but its final `RESTORED` journal append fails.
- A journal record is edited, deleted, reordered, duplicated, truncated, or
  has a broken sequence/previous-hash link.
- An AI agent attempts arbitrary raw-path deletion or attempts to manufacture
  a risk, validation, or authorization result.

Each case must fail closed. Planning and validation record structured reasons;
the isolated mutation layer additionally owns journaled recovery and replay
handling below either an explicitly marked disposable temporary root or an
engine-issued approved local root. A committed rename remains explicitly
recoverable when final journalization fails. The gate rejects system,
network/UNC/mapped, filesystem-root, protected, linked/reparse, and
out-of-plan targets. It never accepts a user-workspace or arbitrary raw-path
mutation target. Authorization claims occur before `PLANNED`; a rejected
replay produces no extra mutation lifecycle record, and restart reconciliation
handles a claimed-but-not-started state.

The internal application service adds an exact review/confirmation gate and
reports multi-item outcomes independently; it never implies transactionality.
The human CLI is a single-process presentation/orchestration adapter. It uses
an engine-issued recovery identifier for immediate Undo and does not persist or
reconstruct trusted capabilities across processes.

## Required behavior

Confirmed references or active consumers have a hard minimum of `REVIEW_REQUIRED` and can never result in `SAFE` or `REGENERATABLE`. `.git` directories and `.git` files are protection/context observations only; they must remain `ObservedNode`s and must never be admitted as `CleanupCandidate`s. `NEVER_DELETE` describes protection semantics rather than reclaim eligibility.

Tests must distinguish verified `RegenerabilityState` from the policy conclusion `RiskLabel.REGENERATABLE`. A proven regeneration recipe must not override confirmed reachability, active use, protection, or unresolved evidence.

All cases above must fail closed: preserve uncertainty, record the failure or conflict in evidence, avoid de-escalating an existing label, and prefer `REVIEW_REQUIRED` or `NEVER_DELETE` according to the protection evidence. They must not be “handled” by guessing from a directory name.

The first domain-model task should cover representative fixtures for unknown evidence, failed evidence, conflicting evidence, hard protection, and monotonic escalation. Full filesystem-specific fixtures belong to later detector and scanner tasks.
