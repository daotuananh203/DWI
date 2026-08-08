"""Disposable-root-only reversible mutation primitives for internal v0.3 tests.

This module is intentionally separate from the pure cleanup contracts. It does
not expose raw-path cleanup APIs, does not delete, and does not copy/delete as a
fallback. Mutation is accepted only for an engine-authorized plan and an
explicit marked directory below the operating system temporary directory.
"""

from __future__ import annotations

import json
import ntpath
import os
import stat
import tempfile
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Callable

from .cleanup import (
    CleanupPlan,
    ExecutionAuthorization,
    FilesystemIdentity,
    PlanId,
    PlanItemId,
    PlanValidation,
    QuarantineRecord,
    QuarantineState,
    RecoveryMetadata,
    _canonical_absolute_path,
    _digest,
    _path_is_within,
)
from .domain import NodeKind


_DISPOSABLE_MARKER = ".dwi-disposable-root"
_DISPOSABLE_MARKER_CONTENT = "DWI-DISPOSABLE-ROOT-v0.3\n"
_MUTATION_ROOT_CAPABILITY = object()
_JOURNAL_SCHEMA = "dwi-journal-v0.3"
_GENESIS_PREVIOUS_HASH = "GENESIS:dwi-journal-v0.3"
MutationClock = Callable[[], str]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class MutationRefused(RuntimeError):
    """A mutation request was rejected before an unsafe filesystem operation."""


class JournalError(RuntimeError):
    """The append-only journal could not be safely read or written."""


class JournalCorruptionError(JournalError):
    """The journal contains an incomplete, malformed, or tampered record."""


@dataclass(frozen=True)
class DisposableRoot:
    path: str
    _capability: object | None = None

    @property
    def is_engine_trusted(self) -> bool:
        return self._capability is _MUTATION_ROOT_CAPABILITY


def _safe_directory_metadata(path: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise MutationRefused(f"cannot observe disposable directory: {path}") from error
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise MutationRefused(f"disposable directory is not an ordinary directory: {path}")
    return metadata


def create_disposable_root(path: str | os.PathLike[str]) -> DisposableRoot:
    """Accept only a marked child directory of the OS temporary directory."""

    canonical = _verify_marked_disposable_path(os.fspath(path))
    return DisposableRoot(canonical, _MUTATION_ROOT_CAPABILITY)


def _verify_marked_disposable_path(path: str) -> str:
    if os.name != "nt":
        raise MutationRefused("disposable mutation primitives are Windows-only")
    canonical = _canonical_absolute_path(path)
    temporary = _canonical_absolute_path(tempfile.gettempdir())
    if canonical is None or temporary is None or canonical == temporary or not _path_is_within(canonical, temporary):
        raise MutationRefused("disposable root must be a child of the OS temporary directory")
    _validate_ordinary_ancestry(canonical, temporary)
    marker = os.path.join(canonical, _DISPOSABLE_MARKER)
    try:
        marker_metadata = os.lstat(marker)
        if stat.S_ISLNK(marker_metadata.st_mode) or _is_reparse(marker_metadata) or not stat.S_ISREG(marker_metadata.st_mode):
            raise MutationRefused("disposable-root marker is not an ordinary file")
        # Universal newline handling keeps the marker stable across Windows
        # text-mode line endings while still requiring the exact marker text.
        with open(marker, "r", encoding="utf-8") as stream:
            if stream.read() != _DISPOSABLE_MARKER_CONTENT:
                raise MutationRefused("disposable-root marker content is invalid")
    except OSError as error:
        raise MutationRefused("disposable-root marker could not be safely observed") from error
    return canonical


@dataclass(frozen=True)
class QuarantineRoot:
    path: str
    disposable_path: str
    _capability: object | None = None

    @property
    def is_engine_trusted(self) -> bool:
        return (
            self._capability is _MUTATION_ROOT_CAPABILITY
            and _path_is_within(self.path, self.disposable_path)
        )


def create_quarantine_root(root: DisposableRoot, relative_path: str = ".dwi-quarantine") -> QuarantineRoot:
    if not root.is_engine_trusted:
        raise MutationRefused("quarantine root requires an engine-issued disposable root")
    _verify_marked_disposable_path(root.path)
    if not relative_path or os.path.isabs(relative_path) or "/" in relative_path or "\\" in relative_path or relative_path in {".", ".."}:
        raise MutationRefused("quarantine root must be a simple relative child of the disposable root")
    path = _canonical_absolute_path(os.path.join(root.path, relative_path))
    if path is None or not _path_is_within(path, root.path):
        raise MutationRefused("quarantine root escaped the disposable root")
    _safe_directory_metadata(path)
    root_metadata = _safe_directory_metadata(root.path)
    quarantine_metadata = _safe_directory_metadata(path)
    if getattr(root_metadata, "st_dev", 0) != getattr(quarantine_metadata, "st_dev", 0):
        raise MutationRefused("quarantine root is not on the disposable root filesystem")
    return QuarantineRoot(path, root.path, _MUTATION_ROOT_CAPABILITY)


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _node_kind(metadata: os.stat_result) -> NodeKind:
    if stat.S_ISLNK(metadata.st_mode):
        return NodeKind.SYMLINK
    if _is_reparse(metadata):
        return NodeKind.REPARSE_POINT
    if stat.S_ISDIR(metadata.st_mode):
        return NodeKind.DIRECTORY
    if stat.S_ISREG(metadata.st_mode):
        return NodeKind.FILE
    return NodeKind.UNKNOWN


def _validate_ordinary_ancestry(path: str, root: str) -> None:
    """Reject linked/reparse ancestors without resolving them."""

    canonical_path = _canonical_absolute_path(path)
    canonical_root = _canonical_absolute_path(root)
    if canonical_path is None or canonical_root is None or not _path_is_within(canonical_path, canonical_root):
        raise MutationRefused("path is outside its approved ordinary root")
    current = canonical_root
    _safe_directory_metadata(current)
    relative = ntpath.relpath(canonical_path, canonical_root)
    if relative == ".":
        return
    for component in relative.split("\\"):
        current = os.path.join(current, component)
        _safe_directory_metadata(current)


def _observe_identity(path: str) -> tuple[FilesystemIdentity | None, str | None]:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        return None, f"path observation failed: {type(error).__name__}"
    device = getattr(metadata, "st_dev", 0)
    inode = getattr(metadata, "st_ino", 0)
    try:
        identity = FilesystemIdentity(device, inode, _node_kind(metadata), _is_reparse(metadata))
    except ValueError as error:
        return None, f"filesystem identity is invalid: {error}"
    return identity, None


def _same_identity(expected: FilesystemIdentity, actual: FilesystemIdentity) -> bool:
    return expected == actual


def _lexists(path: str) -> bool:
    return os.path.lexists(path)


def _require_mutation_roots(root: DisposableRoot, quarantine_root: QuarantineRoot) -> None:
    if not root.is_engine_trusted:
        raise MutationRefused("mutation requires an engine-issued disposable root")
    _verify_marked_disposable_path(root.path)
    if not quarantine_root.is_engine_trusted or quarantine_root.disposable_path != root.path:
        raise MutationRefused("quarantine root is not bound to the disposable root")
    _safe_directory_metadata(root.path)
    _safe_directory_metadata(quarantine_root.path)


def _require_bound_journal(journal: AuditJournal, root: DisposableRoot) -> None:
    if not isinstance(journal, AuditJournal) or not journal.is_engine_trusted or journal.disposable_path != root.path:
        raise MutationRefused("journal is not bound to the disposable root")


def _entry_payload(entry: "JournalEntry", include_hash: bool = True) -> dict[str, object]:
    identity = {
        "device": entry.filesystem_identity.device,
        "inode": entry.filesystem_identity.inode,
        "object_type": entry.filesystem_identity.object_type.value,
        "is_reparse": entry.filesystem_identity.is_reparse,
    }
    payload: dict[str, object] = {
        "schema": _JOURNAL_SCHEMA,
        "entry_id": entry.entry_id,
        "plan_id": entry.plan_id,
        "plan_item_id": entry.plan_item_id,
        "validation_identity": entry.validation_identity,
        "authorization_identity": entry.authorization_identity,
        "original_path": entry.original_path,
        "quarantine_path": entry.quarantine_path,
        "filesystem_identity": identity,
        "timestamp": entry.timestamp,
        "status": entry.status.value,
        "failure_reason": entry.failure_reason,
        "recovery_id": entry.recovery_id,
    }
    payload["sequence"] = entry.sequence
    payload["previous_record_hash"] = entry.previous_record_hash
    if include_hash:
        payload["record_hash"] = entry.record_hash
    return payload


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _entry_hash(entry: "JournalEntry") -> str:
    return _digest(_entry_payload(entry, include_hash=False))


@dataclass(frozen=True)
class JournalEntry:
    entry_id: str
    plan_id: str
    plan_item_id: str
    validation_identity: str
    authorization_identity: str
    original_path: str
    quarantine_path: str | None
    filesystem_identity: FilesystemIdentity
    timestamp: str
    status: QuarantineState
    recovery_id: str
    failure_reason: str | None = None
    record_hash: str = ""
    sequence: int = 0
    previous_record_hash: str = ""

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value.strip() for value in (
            self.entry_id, self.plan_id, self.plan_item_id, self.validation_identity,
            self.authorization_identity, self.timestamp, self.recovery_id,
        )):
            raise ValueError("journal identifiers and timestamp must not be empty")
        if _canonical_absolute_path(self.original_path) is None:
            raise ValueError("journal original path must be absolute and normalized")
        if self.quarantine_path is not None and _canonical_absolute_path(self.quarantine_path) is None:
            raise ValueError("journal quarantine path must be absolute and normalized")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence <= 0:
            raise ValueError("journal sequence must be a positive integer")
        if not isinstance(self.previous_record_hash, str) or not self.previous_record_hash.strip():
            raise ValueError("journal previous record hash must not be empty")


@dataclass(frozen=True)
class AuditJournal:
    path: str
    disposable_path: str
    _capability: object | None = None

    @property
    def is_engine_trusted(self) -> bool:
        return self._capability is _MUTATION_ROOT_CAPABILITY and _path_is_within(self.path, self.disposable_path)

    def _check_path(self) -> None:
        if not self.is_engine_trusted:
            raise JournalError("journal is not bound to an engine-issued disposable root")
        try:
            _verify_marked_disposable_path(self.disposable_path)
        except MutationRefused as error:
            raise JournalError("journal disposable root is not a valid marked temporary root") from error
        parent = os.path.dirname(self.path)
        if not _path_is_within(parent, self.disposable_path):
            raise JournalError("journal path escaped the disposable root")
        if _lexists(self.path):
            try:
                metadata = os.lstat(self.path)
            except OSError as error:
                raise JournalError("journal could not be observed") from error
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
                raise JournalError("journal path is linked, reparse-backed, or not a file")

    def read_entries(self) -> tuple[JournalEntry, ...]:
        self._check_path()
        if not _lexists(self.path):
            return ()
        try:
            with open(self.path, "r", encoding="utf-8", newline="") as stream:
                lines = stream.readlines()
        except OSError as error:
            raise JournalError("journal could not be read") from error
        entries: list[JournalEntry] = []
        seen: set[str] = set()
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                raise JournalCorruptionError(f"journal line {line_number} is empty")
            if not line.endswith("\n"):
                raise JournalCorruptionError(f"journal line {line_number} is truncated")
            try:
                payload = json.loads(line)
                if not isinstance(payload, dict) or payload.get("schema") != _JOURNAL_SCHEMA:
                    raise JournalCorruptionError(f"journal line {line_number} has an unsupported schema")
                identity_payload = payload["filesystem_identity"]
                entry = JournalEntry(
                    payload["entry_id"], payload["plan_id"], payload["plan_item_id"],
                    payload["validation_identity"], payload["authorization_identity"],
                    payload["original_path"], payload["quarantine_path"],
                    FilesystemIdentity(
                        identity_payload["device"], identity_payload["inode"],
                        NodeKind(identity_payload["object_type"]), identity_payload["is_reparse"],
                    ),
                    payload["timestamp"], QuarantineState(payload["status"]),
                    payload["recovery_id"], payload.get("failure_reason"), payload["record_hash"],
                    payload["sequence"], payload["previous_record_hash"],
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise JournalCorruptionError(f"journal line {line_number} is invalid") from error
            expected_previous = entries[-1].record_hash if entries else _GENESIS_PREVIOUS_HASH
            if entry.entry_id in seen:
                raise JournalCorruptionError(f"journal line {line_number} repeats an entry identifier")
            if entry.sequence != line_number or entry.previous_record_hash != expected_previous:
                raise JournalCorruptionError(f"journal line {line_number} failed sequence-chain validation")
            if entry.record_hash != _entry_hash(entry):
                raise JournalCorruptionError(f"journal line {line_number} failed integrity validation")
            seen.add(entry.entry_id)
            entries.append(entry)
        return tuple(entries)

    def append(self, entry: JournalEntry) -> None:
        self._check_path()
        entries = self.read_entries()
        if any(existing.entry_id == entry.entry_id for existing in entries):
            raise JournalError("journal entry id already exists")
        expected_sequence = len(entries) + 1
        expected_previous = entries[-1].record_hash if entries else _GENESIS_PREVIOUS_HASH
        if entry.sequence != expected_sequence or entry.previous_record_hash != expected_previous:
            raise JournalError("journal sequence chain is invalid")
        if entry.record_hash != _entry_hash(entry):
            raise JournalError("journal entry integrity hash is invalid")
        try:
            with open(self.path, "a", encoding="utf-8", newline="\n") as stream:
                stream.write(_canonical_json(_entry_payload(entry)) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as error:
            raise JournalError("journal append failed") from error


def create_audit_journal(root: DisposableRoot, relative_path: str = ".dwi-journal.jsonl") -> AuditJournal:
    if not root.is_engine_trusted:
        raise MutationRefused("journal requires an engine-issued disposable root")
    _verify_marked_disposable_path(root.path)
    if not relative_path or os.path.isabs(relative_path) or "/" in relative_path or "\\" in relative_path or relative_path in {".", ".."}:
        raise MutationRefused("journal path must be a simple relative child of the disposable root")
    path = _canonical_absolute_path(os.path.join(root.path, relative_path))
    if path is None or not _path_is_within(path, root.path):
        raise MutationRefused("journal path escaped the disposable root")
    return AuditJournal(path, root.path, _MUTATION_ROOT_CAPABILITY)


@dataclass(frozen=True)
class MutationFailure:
    plan_item_id: PlanItemId | None
    state: QuarantineState
    reason: str


@dataclass(frozen=True)
class QuarantineResult:
    plan_id: PlanId
    records: tuple[QuarantineRecord, ...]
    failures: tuple[MutationFailure, ...]


@dataclass(frozen=True)
class RestoreResult:
    recovery_id: str
    state: QuarantineState
    journal_entry: JournalEntry | None
    failure_reason: str | None = None


@dataclass(frozen=True)
class ReconciliationResult:
    entries: tuple[JournalEntry, ...]
    failures: tuple[str, ...]


def _make_entry(
    journal: AuditJournal,
    *,
    plan_id: str,
    plan_item_id: str,
    validation_identity: str,
    authorization_identity: str,
    original_path: str,
    quarantine_path: str | None,
    filesystem_identity: FilesystemIdentity,
    status: QuarantineState,
    recovery_id: str,
    timestamp: str,
    failure_reason: str | None = None,
) -> JournalEntry:
    entries = journal.read_entries()
    sequence = len(entries) + 1
    previous_record_hash = entries[-1].record_hash if entries else _GENESIS_PREVIOUS_HASH
    entry = JournalEntry(
        f"{recovery_id}-entry-{sequence:08d}", plan_id, plan_item_id,
        validation_identity, authorization_identity, original_path,
        quarantine_path, filesystem_identity, timestamp, status, recovery_id,
        failure_reason, "", sequence, previous_record_hash,
    )
    return JournalEntry(
        entry.entry_id, entry.plan_id, entry.plan_item_id,
        entry.validation_identity, entry.authorization_identity,
        entry.original_path, entry.quarantine_path, entry.filesystem_identity,
        entry.timestamp, entry.status, entry.recovery_id, entry.failure_reason,
        _entry_hash(entry), entry.sequence, entry.previous_record_hash,
    )


def _record_from_entry(entry: JournalEntry) -> QuarantineRecord:
    metadata = RecoveryMetadata(
        entry.recovery_id,
        entry.original_path,
        entry.quarantine_path,
        PlanId(entry.plan_id),
        PlanItemId(entry.plan_item_id),
        entry.timestamp,
        entry.timestamp if entry.status in {
            QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED,
            QuarantineState.QUARANTINED,
            QuarantineState.RESTORE_COMMITTED_UNJOURNALED,
            QuarantineState.RESTORED,
        } else None,
        entry.filesystem_identity,
    )
    return QuarantineRecord(metadata, entry.status, entry.failure_reason)


def _recoverable_entry(
    journal: AuditJournal,
    base: JournalEntry,
    status: QuarantineState,
    reason: str,
) -> JournalEntry:
    """Create and best-effort persist a post-rename recoverable state."""

    try:
        entry = _make_entry(
            journal,
            plan_id=base.plan_id,
            plan_item_id=base.plan_item_id,
            validation_identity=base.validation_identity,
            authorization_identity=base.authorization_identity,
            original_path=base.original_path,
            quarantine_path=base.quarantine_path,
            filesystem_identity=base.filesystem_identity,
            status=status,
            recovery_id=base.recovery_id,
            timestamp=base.timestamp,
            failure_reason=reason,
        )
        try:
            journal.append(entry)
        except JournalError:
            pass
        return entry
    except JournalError:
        # The durable QUARANTINING/RESTORING intent remains the source of
        # recovery metadata. This in-memory state must not be persisted with a
        # duplicate sequence when the journal cannot be read.
        unsigned = replace(base, status=status, failure_reason=reason, record_hash="")
        return replace(unsigned, record_hash=_entry_hash(unsigned))


def _move_reality(source: str, destination: str, expected: FilesystemIdentity) -> str:
    source_identity, source_error = _observe_identity(source)
    destination_identity, destination_error = _observe_identity(destination)
    if destination_identity == expected and source_error is not None:
        return "committed"
    if source_identity == expected and destination_error is not None:
        return "not_committed"
    return "ambiguous"


def _validate_plan_item_before_move(plan: CleanupPlan, item_path: str, expected: FilesystemIdentity, root: DisposableRoot, quarantine_root: QuarantineRoot) -> tuple[FilesystemIdentity | None, str | None]:
    _require_mutation_roots(root, quarantine_root)
    if not _path_is_within(plan.approved_root.path, root.path) or not _path_is_within(item_path, root.path):
        return None, "plan root or item path is outside the disposable root"
    if not _path_is_within(item_path, plan.approved_root.path):
        return None, "plan item path is outside its approved root"
    try:
        _validate_ordinary_ancestry(plan.approved_root.path, root.path)
        _validate_ordinary_ancestry(item_path, plan.approved_root.path)
    except (MutationRefused, ValueError) as error:
        return None, f"approved-root ancestry is not ordinary: {error}"
    identity, error = _observe_identity(item_path)
    if error is not None or identity is None:
        return None, error or "path identity could not be observed"
    if not _same_identity(expected, identity):
        return None, "path identity/type/reparse state changed before mutation"
    if not identity.is_suitable_for_planning:
        return None, "path is no longer an ordinary directory with a valid identity"
    quarantine_metadata = _safe_directory_metadata(quarantine_root.path)
    if getattr(identity, "device", None) != getattr(quarantine_metadata, "st_dev", None):
        return None, "source and quarantine roots are not on the same filesystem"
    return identity, None


def quarantine_plan(
    plan: CleanupPlan,
    validation: PlanValidation,
    authorization: ExecutionAuthorization,
    disposable_root: DisposableRoot,
    quarantine_root: QuarantineRoot,
    journal: AuditJournal,
    *,
    clock: MutationClock = _utc_now,
) -> QuarantineResult:
    """Move only an exactly authorized plan into a disposable quarantine root."""

    if not isinstance(plan, CleanupPlan):
        raise MutationRefused("quarantine requires a CleanupPlan")
    _require_mutation_roots(disposable_root, quarantine_root)
    _require_bound_journal(journal, disposable_root)
    item_ids = tuple(item.plan_item_id for item in plan.items)
    if not authorization.is_authorized or not validation.is_valid or not authorization.matches_validation(validation) or authorization.plan_id != plan.plan_id or authorization.authorized_item_ids != item_ids:
        return QuarantineResult(plan.plan_id, (), (MutationFailure(None, QuarantineState.FAILED, "plan item authorization is missing, forged, stale, or mismatched"),))

    records: list[QuarantineRecord] = []
    failures: list[MutationFailure] = []
    for item in plan.items:
        snapshot = item.snapshot
        mutation_committed = False
        quarantining: JournalEntry | None = None
        quarantined: JournalEntry | None = None
        recovery_id = f"recovery-{_digest((plan.plan_id, item.plan_item_id))[:32]}"
        quarantine_path = _canonical_absolute_path(os.path.join(quarantine_root.path, recovery_id))
        if quarantine_path is None or not _path_is_within(quarantine_path, quarantine_root.path):
            failures.append(MutationFailure(item.plan_item_id, QuarantineState.FAILED, "quarantine destination escaped the approved root"))
            continue
        try:
            planned = _make_entry(
                journal,
                plan_id=plan.plan_id.value,
                plan_item_id=item.plan_item_id.value,
                validation_identity=validation.validation_token,
                authorization_identity=authorization.authorization_token,
                original_path=snapshot.path,
                quarantine_path=quarantine_path,
                filesystem_identity=snapshot.filesystem_identity,
                status=QuarantineState.PLANNED,
                recovery_id=recovery_id,
                timestamp=clock(),
            )
            journal.append(planned)
            identity, reason = _validate_plan_item_before_move(plan, snapshot.path, snapshot.filesystem_identity, disposable_root, quarantine_root)
            if reason is not None or identity is None:
                raise MutationRefused(reason or "pre-mutation validation failed")
            if _lexists(quarantine_path):
                raise MutationRefused("quarantine destination already exists; overwrite is forbidden")
            quarantining = _make_entry(
                journal,
                plan_id=plan.plan_id.value,
                plan_item_id=item.plan_item_id.value,
                validation_identity=validation.validation_token,
                authorization_identity=authorization.authorization_token,
                original_path=snapshot.path,
                quarantine_path=quarantine_path,
                filesystem_identity=identity,
                status=QuarantineState.QUARANTINING,
                recovery_id=recovery_id,
                timestamp=clock(),
            )
            journal.append(quarantining)
            if os.name != "nt":
                raise MutationRefused("safe non-overwriting Windows rename is required")
            os.rename(snapshot.path, quarantine_path)
            mutation_committed = True
            quarantined = _make_entry(
                journal,
                plan_id=plan.plan_id.value,
                plan_item_id=item.plan_item_id.value,
                validation_identity=validation.validation_token,
                authorization_identity=authorization.authorization_token,
                original_path=snapshot.path,
                quarantine_path=quarantine_path,
                filesystem_identity=identity,
                status=QuarantineState.QUARANTINED,
                recovery_id=recovery_id,
                timestamp=clock(),
            )
            try:
                journal.append(quarantined)
            except (JournalError, OSError) as error:
                reason = f"quarantine rename committed but final journal append failed: {error}"
                recoverable = _recoverable_entry(
                    journal,
                    quarantined,
                    QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED,
                    reason,
                )
                records.append(_record_from_entry(recoverable))
                failures.append(MutationFailure(item.plan_item_id, recoverable.status, reason))
                continue
            records.append(_record_from_entry(quarantined))
        except (MutationRefused, JournalError, OSError) as error:
            reason = str(error)
            if mutation_committed or _move_reality(snapshot.path, quarantine_path, snapshot.filesystem_identity) == "committed":
                base = quarantined or quarantining
                if base is not None:
                    reason = f"quarantine rename committed but final journal append failed: {reason}"
                    recoverable = _recoverable_entry(
                        journal,
                        base,
                        QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED,
                        reason,
                    )
                    records.append(_record_from_entry(recoverable))
                    failures.append(MutationFailure(item.plan_item_id, recoverable.status, reason))
                    continue
            try:
                failed = _make_entry(
                    journal,
                    plan_id=plan.plan_id.value,
                    plan_item_id=item.plan_item_id.value,
                    validation_identity=validation.validation_token,
                    authorization_identity=authorization.authorization_token,
                    original_path=snapshot.path,
                    quarantine_path=quarantine_path,
                    filesystem_identity=snapshot.filesystem_identity,
                    status=QuarantineState.FAILED,
                    recovery_id=recovery_id,
                    timestamp=clock(),
                    failure_reason=reason,
                )
                journal.append(failed)
            except JournalError:
                pass
            failures.append(MutationFailure(item.plan_item_id, QuarantineState.FAILED, reason))
    return QuarantineResult(plan.plan_id, tuple(records), tuple(failures))


def reconcile_pending_operations(
    journal: AuditJournal,
    disposable_root: DisposableRoot,
    quarantine_root: QuarantineRoot,
    *,
    clock: MutationClock = _utc_now,
) -> ReconciliationResult:
    """Resolve journaled crash windows conservatively without moving data."""

    _require_mutation_roots(disposable_root, quarantine_root)
    _require_bound_journal(journal, disposable_root)
    entries = list(journal.read_entries())
    latest: dict[str, JournalEntry] = {}
    for entry in entries:
        latest[entry.recovery_id] = entry
    failures: list[str] = []
    for recovery_id, entry in sorted(latest.items()):
        if entry.status not in {QuarantineState.QUARANTINING, QuarantineState.RESTORING}:
            continue
        source = entry.original_path
        destination = entry.quarantine_path
        try:
            if destination is None or not _path_is_within(destination, quarantine_root.path) or not _path_is_within(source, disposable_root.path):
                raise MutationRefused("journaled recovery path escaped the disposable root")
            source_identity, source_error = _observe_identity(source)
            destination_identity, destination_error = _observe_identity(destination)
            if entry.status is QuarantineState.QUARANTINING:
                if destination_identity == entry.filesystem_identity and source_error is not None:
                    status = QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED
                    reason = "recovered quarantine rename committed before final journal update"
                elif source_identity == entry.filesystem_identity and destination_error is not None:
                    status = QuarantineState.FAILED
                    reason = "recovered move did not complete"
                else:
                    status = QuarantineState.FAILED
                    reason = "crash-window state is ambiguous; no move was attempted"
            else:
                if source_identity == entry.filesystem_identity and destination_error is not None:
                    status = QuarantineState.RESTORE_COMMITTED_UNJOURNALED
                    reason = "recovered restore rename committed before final journal update"
                elif destination_identity == entry.filesystem_identity and source_error is not None:
                    status = QuarantineState.FAILED
                    reason = "recovered restore did not complete"
                else:
                    status = QuarantineState.FAILED
                    reason = "restore crash-window state is ambiguous; no move was attempted"
            recovered = _make_entry(
                journal,
                plan_id=entry.plan_id,
                plan_item_id=entry.plan_item_id,
                validation_identity=entry.validation_identity,
                authorization_identity=entry.authorization_identity,
                original_path=entry.original_path,
                quarantine_path=entry.quarantine_path,
                filesystem_identity=entry.filesystem_identity,
                status=status,
                recovery_id=entry.recovery_id,
                timestamp=clock(),
                failure_reason=reason if status is QuarantineState.FAILED else None,
            )
            entries.append(recovered)
            try:
                journal.append(recovered)
            except JournalError as error:
                failures.append(f"{recovery_id}: recoverable state could not be journaled: {error}")
        except (MutationRefused, JournalError, OSError) as error:
            failures.append(f"{recovery_id}: {error}")
    return ReconciliationResult(tuple(entries), tuple(failures))


def restore_recovery(
    recovery_id: str,
    journal: AuditJournal,
    disposable_root: DisposableRoot,
    quarantine_root: QuarantineRoot,
    *,
    clock: MutationClock = _utc_now,
) -> RestoreResult:
    """Restore one valid journaled recovery without overwriting any destination."""

    _require_mutation_roots(disposable_root, quarantine_root)
    if not recovery_id.strip():
        return RestoreResult(recovery_id, QuarantineState.FAILED, None, "recovery identifier is empty")
    reconciliation = reconcile_pending_operations(journal, disposable_root, quarantine_root, clock=clock)
    entries = tuple(entry for entry in reconciliation.entries if entry.recovery_id == recovery_id)
    if not entries:
        return RestoreResult(recovery_id, QuarantineState.FAILED, None, "recovery entry was not found")
    terminal_restore = next((entry for entry in reversed(entries) if entry.status in {
        QuarantineState.RESTORED,
        QuarantineState.RESTORE_COMMITTED_UNJOURNALED,
    }), None)
    if terminal_restore is not None:
        return RestoreResult(recovery_id, terminal_restore.status, terminal_restore)
    quarantined = next((entry for entry in reversed(entries) if entry.status in {
        QuarantineState.QUARANTINED,
        QuarantineState.QUARANTINE_COMMITTED_UNJOURNALED,
    }), None)
    if quarantined is None or quarantined.quarantine_path is None:
        return RestoreResult(recovery_id, QuarantineState.FAILED, entries[-1], "no valid quarantined recovery state exists")
    original = quarantined.original_path
    destination = quarantined.quarantine_path
    mutation_committed = False
    restoring: JournalEntry | None = None
    restored: JournalEntry | None = None
    try:
        if not _path_is_within(original, disposable_root.path) or not _path_is_within(destination, quarantine_root.path):
            raise MutationRefused("restore path escaped the disposable root")
        parent = os.path.dirname(original)
        _validate_ordinary_ancestry(parent, disposable_root.path)
        _validate_ordinary_ancestry(destination, quarantine_root.path)
        if _lexists(original):
            raise MutationRefused("original destination already exists; overwrite is forbidden")
        identity, error = _observe_identity(destination)
        if error is not None or identity is None:
            raise MutationRefused(error or "quarantine item is missing")
        if not _same_identity(quarantined.filesystem_identity, identity) or not identity.is_suitable_for_planning:
            raise MutationRefused("quarantine item identity/type/reparse state changed")
        restoring = _make_entry(
            journal,
            plan_id=quarantined.plan_id,
            plan_item_id=quarantined.plan_item_id,
            validation_identity=quarantined.validation_identity,
            authorization_identity=quarantined.authorization_identity,
            original_path=original,
            quarantine_path=destination,
            filesystem_identity=identity,
            status=QuarantineState.RESTORING,
            recovery_id=recovery_id,
            timestamp=clock(),
        )
        journal.append(restoring)
        if os.name != "nt":
            raise MutationRefused("safe non-overwriting Windows rename is required")
        os.rename(destination, original)
        mutation_committed = True
        restored = _make_entry(
            journal,
            plan_id=quarantined.plan_id,
            plan_item_id=quarantined.plan_item_id,
            validation_identity=quarantined.validation_identity,
            authorization_identity=quarantined.authorization_identity,
            original_path=original,
            quarantine_path=destination,
            filesystem_identity=identity,
            status=QuarantineState.RESTORED,
            recovery_id=recovery_id,
            timestamp=clock(),
        )
        try:
            journal.append(restored)
        except (JournalError, OSError) as error:
            reason = f"restore rename committed but final journal append failed: {error}"
            recoverable = _recoverable_entry(
                journal,
                restored,
                QuarantineState.RESTORE_COMMITTED_UNJOURNALED,
                reason,
            )
            return RestoreResult(recovery_id, recoverable.status, recoverable, reason)
        return RestoreResult(recovery_id, QuarantineState.RESTORED, restored)
    except (MutationRefused, JournalError, OSError) as error:
        reason = str(error)
        if mutation_committed or _move_reality(destination, original, quarantined.filesystem_identity) == "committed":
            base = restored or restoring or quarantined
            reason = f"restore rename committed but final journal append failed: {reason}"
            recoverable = _recoverable_entry(
                journal,
                base,
                QuarantineState.RESTORE_COMMITTED_UNJOURNALED,
                reason,
            )
            return RestoreResult(recovery_id, recoverable.status, recoverable, reason)
        try:
            failed = _make_entry(
                journal,
                plan_id=quarantined.plan_id,
                plan_item_id=quarantined.plan_item_id,
                validation_identity=quarantined.validation_identity,
                authorization_identity=quarantined.authorization_identity,
                original_path=original,
                quarantine_path=destination,
                filesystem_identity=quarantined.filesystem_identity,
                status=QuarantineState.FAILED,
                recovery_id=recovery_id,
                timestamp=clock(),
                failure_reason=reason,
            )
            journal.append(failed)
            return RestoreResult(recovery_id, QuarantineState.FAILED, failed, reason)
        except JournalError:
            return RestoreResult(recovery_id, QuarantineState.FAILED, quarantined, reason)
