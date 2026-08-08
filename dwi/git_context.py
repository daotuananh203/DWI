"""Bounded read-only Git protection/context observation."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .detector_support import failed_evidence, not_observed_evidence, observed_evidence, unknown_evidence
from .domain import Confidence, Evidence, EvidenceBundle, NodeKind, ObservationStatus, ObservedNode, ProtectionClass


_SOURCE = "git-context-observer"
_MAX_GITDIR_FILE_BYTES = 4096
_REQUIRED_DIRECTORY_ENTRIES = {
    "HEAD": "file",
    "config": "file",
    "objects": "directory",
    "refs": "directory",
}


class GitObjectForm(str, Enum):
    DIRECTORY = "directory"
    FILE = "file"
    MISSING = "missing"
    INACCESSIBLE = "inaccessible"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class GitContextObservation:
    """Protection/context result for exactly one explicit `.git` path."""

    node: ObservedNode
    observations: tuple[Evidence, ...]
    object_form: GitObjectForm
    reference_target: str | None = None
    target_followed: bool = False

    @property
    def evidence(self) -> EvidenceBundle:
        return EvidenceBundle(observations=self.observations)

    @property
    def is_protection_context(self) -> bool:
        return self.node.protection is ProtectionClass.REPOSITORY_PROTECTED

    @property
    def valid_structure(self) -> bool:
        return any(
            item.key == "git_structure_observation"
            and item.observation_status is ObservationStatus.OBSERVED
            and item.confidence is Confidence.HIGH
            for item in self.observations
        )


def _reparse(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _observed(key: str, description: str, *, value: str | None = None) -> Evidence:
    return observed_evidence(_SOURCE, key, description, value=value)


def _failed(key: str, description: str) -> Evidence:
    return failed_evidence(_SOURCE, key, description)


def _unknown(key: str, description: str, *, value: str | None = None) -> Evidence:
    evidence = unknown_evidence(_SOURCE, key, description)
    if value is None:
        return evidence
    return Evidence(
        key=evidence.key,
        source=evidence.source,
        description=evidence.description,
        observation_status=evidence.observation_status,
        polarity=evidence.polarity,
        confidence=evidence.confidence,
        value=value,
    )


def _base_observations(path: Path) -> list[Evidence]:
    return [
        _observed(
            "git_path_name_observation",
            "The explicit path has the exact .git basename.",
            value=path.name,
        ),
        _observed(
            "protection_indicator_observation",
            "An explicit .git path is repository-protected context and is not a cleanup candidate.",
            value=ProtectionClass.REPOSITORY_PROTECTED.value,
        ),
    ]


def _uninspectable(
    path: Path,
    object_form: GitObjectForm,
    node_kind: NodeKind,
    reason: str,
) -> GitContextObservation:
    observations = _base_observations(path)
    observations.extend(
        (
            _observed("git_object_type_observation", "The .git path object type was observed.", value=node_kind.value)
            if node_kind is not NodeKind.UNKNOWN
            else not_observed_evidence(_SOURCE, "git_object_type_observation", "The .git path object was not observed."),
            _failed("git_structure_observation", reason),
        )
    )
    return GitContextObservation(
        node=ObservedNode(str(path), node_kind, ProtectionClass.REPOSITORY_PROTECTED),
        observations=tuple(observations),
        object_form=object_form,
    )


def _inspect_directory(path: Path) -> GitContextObservation:
    observations = _base_observations(path)
    observations.append(_observed("git_object_type_observation", "The .git path is a directory.", value=NodeKind.GIT_DIRECTORY.value))
    entries: dict[str, str] = {}
    ambiguous = False
    try:
        with os.scandir(path) as scanned:
            for entry in sorted(scanned, key=lambda item: (item.name.casefold(), item.name)):
                metadata = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or _reparse(metadata):
                    ambiguous = True
                    continue
                if stat.S_ISREG(metadata.st_mode):
                    entries[entry.name] = "file"
                elif stat.S_ISDIR(metadata.st_mode):
                    entries[entry.name] = "directory"
                else:
                    entries[entry.name] = "other"
    except (OSError, ValueError) as error:
        observations.append(_failed("git_structure_observation", f"The .git directory could not be inspected: {type(error).__name__}."))
        return GitContextObservation(
            node=ObservedNode(str(path), NodeKind.GIT_DIRECTORY, ProtectionClass.REPOSITORY_PROTECTED),
            observations=tuple(observations),
            object_form=GitObjectForm.INACCESSIBLE,
        )

    missing = [name for name in _REQUIRED_DIRECTORY_ENTRIES if name not in entries]
    wrong_type = [
        name for name, expected in _REQUIRED_DIRECTORY_ENTRIES.items()
        if name in entries and entries[name] != expected
    ]
    if ambiguous:
        observations.append(_failed("git_structure_observation", "A direct .git entry was a symlink or reparse point; structure is ambiguous."))
        form = GitObjectForm.AMBIGUOUS
    elif missing or wrong_type:
        detail = "The .git directory is missing or has invalid required control entries."
        observations.append(_failed("git_structure_observation", detail))
        form = GitObjectForm.AMBIGUOUS
    else:
        observations.append(
            _observed(
                "git_structure_observation",
                "The direct .git control layout was observed without recursive repository inspection.",
                value="HEAD,config,objects,refs",
            )
        )
        form = GitObjectForm.DIRECTORY
    return GitContextObservation(
        node=ObservedNode(str(path), NodeKind.GIT_DIRECTORY, ProtectionClass.REPOSITORY_PROTECTED),
        observations=tuple(observations),
        object_form=form,
    )


def _inspect_file(path: Path) -> GitContextObservation:
    observations = _base_observations(path)
    observations.append(_observed("git_object_type_observation", "The .git path is a file.", value=NodeKind.GIT_FILE.value))
    try:
        with path.open("rb") as stream:
            data = stream.read(_MAX_GITDIR_FILE_BYTES + 1)
        if len(data) > _MAX_GITDIR_FILE_BYTES:
            raise ValueError("gitdir file exceeds bounded observation size")
        text = data.decode("utf-8")
    except (OSError, UnicodeError, ValueError) as error:
        observations.append(_failed("gitdir_reference_observation", f"The .git file could not be read reliably: {type(error).__name__}."))
        return GitContextObservation(
            node=ObservedNode(str(path), NodeKind.GIT_FILE, ProtectionClass.REPOSITORY_PROTECTED),
            observations=tuple(observations),
            object_form=GitObjectForm.INACCESSIBLE,
        )

    lines = text.splitlines()
    if len(lines) == 1 and lines[0].startswith("gitdir:"):
        target = lines[0][len("gitdir:"):].strip()
    else:
        target = ""
    if not target or "\x00" in target:
        observations.append(_failed("gitdir_reference_observation", "The .git file did not contain one valid gitdir reference."))
        form = GitObjectForm.AMBIGUOUS
        reference = None
    else:
        observations.extend(
            (
                _observed("gitdir_reference_observation", "A gitdir reference was recorded without following its target.", value=target),
                _unknown(
                    "gitdir_target_boundary_observation",
                    "The gitdir target was not followed; external or ambiguous target context remains uninspected.",
                    value="not_followed",
                ),
            )
        )
        observations.append(
            _observed(
                "git_structure_observation",
                "The .git file form was structurally recognized without following the gitdir target.",
                value="gitdir-reference",
            )
        )
        form = GitObjectForm.FILE
        reference = target
    return GitContextObservation(
        node=ObservedNode(str(path), NodeKind.GIT_FILE, ProtectionClass.REPOSITORY_PROTECTED),
        observations=tuple(observations),
        object_form=form,
        reference_target=reference,
    )


def observe_git_path(path: str | os.PathLike[str]) -> GitContextObservation:
    """Observe exactly one explicit `.git` path without following references."""
    inspected_path = Path(path)
    if inspected_path.name != ".git":
        raise ValueError("Git context observation requires an explicit .git path")
    try:
        metadata = os.lstat(inspected_path)
    except FileNotFoundError:
        return _uninspectable(inspected_path, GitObjectForm.MISSING, NodeKind.UNKNOWN, "The .git path was not observed.")
    except PermissionError:
        return _uninspectable(inspected_path, GitObjectForm.INACCESSIBLE, NodeKind.INACCESSIBLE, "The .git path could not be read.")
    except OSError:
        return _uninspectable(inspected_path, GitObjectForm.INACCESSIBLE, NodeKind.INACCESSIBLE, "The .git path could not be observed reliably.")

    if stat.S_ISLNK(metadata.st_mode):
        return _uninspectable(inspected_path, GitObjectForm.AMBIGUOUS, NodeKind.SYMLINK, "The .git path is a symlink and was not followed.")
    if _reparse(metadata):
        return _uninspectable(inspected_path, GitObjectForm.AMBIGUOUS, NodeKind.REPARSE_POINT, "The .git path is a reparse point and was not followed.")
    if stat.S_ISDIR(metadata.st_mode):
        return _inspect_directory(inspected_path)
    if stat.S_ISREG(metadata.st_mode):
        return _inspect_file(inspected_path)
    return _uninspectable(inspected_path, GitObjectForm.AMBIGUOUS, NodeKind.UNKNOWN, "The .git path has an unsupported filesystem object type.")
