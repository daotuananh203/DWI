"""Bounded read-only analysis for the initial Node.js artifact candidates."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .contracts import ArtifactKind, EvidenceAssessment, contract_for, requirements_by_key
from .detector_support import (
    activity_from_evidence,
    confirmed_absent_evidence,
    context_unknown_evidence,
    failed_evidence,
    key_conflicts,
    key_has_uncertainty,
    not_observed_evidence,
    observed_evidence,
    observed_node_kind,
    positive_evidence_meets,
    protection_from_evidence,
    reachability_from_evidence,
    unknown_evidence,
)
from .domain import (
    ActivityState,
    Confidence,
    Evidence,
    EvidenceBundle,
    NodeKind,
    ObservedNode,
    ProtectionClass,
    Provenance,
    ReclaimPriority,
    RegenerabilityState,
    RegenerationCost,
    ReachabilityState,
)


_DETECTOR_SOURCE = "node-artifact-detector"
_NAME_KEYS = {
    ArtifactKind.NODE_MODULES: ("node_modules", "node_modules_directory_name_observation"),
    ArtifactKind.DIST: ("dist", "dist_directory_name_observation"),
    ArtifactKind.BUILD: ("build", "build_directory_name_observation"),
    ArtifactKind.NEXT_BUILD: (".next", "next_build_directory_name_observation"),
}


@dataclass(frozen=True)
class NodeArtifactDetection:
    """Raw observations for one explicitly selected Node.js artifact path."""

    artifact: ArtifactKind
    node: ObservedNode
    observations: tuple[Evidence, ...]

    def contract_assessment(self) -> EvidenceAssessment:
        return contract_for(self.artifact).assess(self.observations)

    @property
    def evidence(self) -> EvidenceBundle:
        return self.contract_assessment().bundle


@dataclass(frozen=True)
class NodeArtifactInterpretation:
    """Domain-state interpretation without a RiskLabel or action decision."""

    artifact: ArtifactKind
    provenance: Provenance | None
    regenerability: RegenerabilityState
    regeneration_cost: RegenerationCost
    reachability: ReachabilityState
    activity: ActivityState
    protection: ProtectionClass
    reclaim_priority: ReclaimPriority = ReclaimPriority.UNKNOWN


NodeModulesDetection = NodeArtifactDetection
BuildArtifactDetection = NodeArtifactDetection
NextBuildDetection = NodeArtifactDetection
NodeModulesInterpretation = NodeArtifactInterpretation
BuildArtifactInterpretation = NodeArtifactInterpretation
NextBuildInterpretation = NodeArtifactInterpretation


def _observed(
    key: str,
    description: str,
    *,
    confidence: Confidence = Confidence.HIGH,
    value: str | None = None,
) -> Evidence:
    return observed_evidence(_DETECTOR_SOURCE, key, description, confidence=confidence, value=value)


def _not_observed(key: str, description: str) -> Evidence:
    return not_observed_evidence(_DETECTOR_SOURCE, key, description)


def _confirmed_absent(key: str, description: str) -> Evidence:
    return confirmed_absent_evidence(_DETECTOR_SOURCE, key, description)


def _unknown(key: str, description: str) -> Evidence:
    return unknown_evidence(_DETECTOR_SOURCE, key, description)


def _failed(key: str, description: str) -> Evidence:
    return failed_evidence(_DETECTOR_SOURCE, key, description)


def _name_observation(path: Path, artifact: ArtifactKind) -> Evidence:
    expected_name, key = _NAME_KEYS[artifact]
    if path.name == expected_name:
        return _observed(key, f"The inspected path has the exact {expected_name} directory name.", value=path.name)
    return _confirmed_absent(key, f"The inspected path does not have the exact {expected_name} directory name.")


def _uninspectable(path: Path, artifact: ArtifactKind, node_kind: NodeKind, structural_keys: tuple[str, ...]) -> NodeArtifactDetection:
    path_observation = (
        _not_observed("path_object_observation", "The inspected path was not observed.")
        if node_kind is NodeKind.UNKNOWN
        else _observed(
            "path_object_observation",
            f"The inspected path is a {node_kind.value}, not a directory.",
            value=node_kind.value,
        )
    )
    observations = [
        _name_observation(path, artifact),
        path_observation,
        _failed("metadata_readability_observation", "The candidate directory could not be read reliably."),
        _not_observed("generator_indicator_observation", "Artifact structure could not be inspected."),
        _unknown("recreation_input_availability_observation", "Recreation inputs were not inspected."),
    ]
    observations.extend(
        _not_observed(key, "The artifact structural observation could not be inspected.")
        for key in structural_keys
    )
    if artifact in {ArtifactKind.DIST, ArtifactKind.BUILD}:
        observations.append(_unknown("source_input_observation", "Source inputs outside the candidate were not inspected."))
    observations.extend(context_unknown_evidence(_DETECTOR_SOURCE))
    return NodeArtifactDetection(
        artifact=artifact,
        node=ObservedNode(str(path), node_kind, ProtectionClass.UNKNOWN),
        observations=tuple(observations),
    )


def _read_json_object(path: Path, *, required_key: str | None = None) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            return "failed"
        text = path.read_text(encoding="utf-8", errors="replace")
        value = json.loads(text)
    except (OSError, PermissionError, json.JSONDecodeError):
        return "failed"
    if not isinstance(value, dict) or (required_key is not None and required_key not in value):
        return "weak"
    return "valid"


def _has_nonempty_direct_file(path: Path) -> tuple[bool, bool]:
    """Return (valid, observation_failed) for one bounded directory level."""

    try:
        with os.scandir(path) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                candidate = Path(entry.path)
                try:
                    if not entry.is_symlink() and entry.is_file(follow_symlinks=False):
                        if candidate.stat().st_size > 0:
                            return True, False
                except (PermissionError, OSError):
                    return False, True
    except (PermissionError, OSError):
        return False, True
    return False, False


def _node_modules_package_dirs(path: Path) -> tuple[list[Path], bool, bool]:
    packages: list[Path] = []
    had_directory = False
    failed = False
    try:
        with os.scandir(path) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                if entry.name in {".bin", ".package-lock.json"}:
                    continue
                candidate = Path(entry.path)
                try:
                    if entry.is_symlink():
                        failed = True
                        continue
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    had_directory = True
                    if entry.name.startswith("@"):
                        try:
                            with os.scandir(candidate) as scoped_entries:
                                for scoped in sorted(scoped_entries, key=lambda item: item.name):
                                    scoped_path = Path(scoped.path)
                                    if scoped.is_symlink() or not scoped.is_dir(follow_symlinks=False):
                                        failed = True
                                    else:
                                        packages.append(scoped_path)
                        except (PermissionError, OSError):
                            failed = True
                    else:
                        packages.append(candidate)
                except (PermissionError, OSError):
                    failed = True
    except (PermissionError, OSError):
        failed = True
    return packages, had_directory, failed


def _package_tree_evidence(path: Path) -> tuple[Evidence, Evidence, bool, bool]:
    packages, had_directory, failed = _node_modules_package_dirs(path)
    manifest_valid = False
    manifest_failed = False
    for package in packages:
        result = _read_json_object(package / "package.json", required_key="name")
        if result == "valid":
            manifest_valid = True
        elif result == "failed":
            manifest_failed = True
    if manifest_valid:
        manifest = _observed("package_manifest_observation", "A bounded package directory contained a valid package.json manifest.", value="package.json")
    elif manifest_failed:
        manifest = _failed("package_manifest_observation", "A bounded package.json manifest could not be read or parsed.")
    elif had_directory:
        manifest = _confirmed_absent("package_manifest_observation", "Observed direct package directories contained no valid package.json manifest.")
    else:
        manifest = _confirmed_absent("package_manifest_observation", "No direct package directory was observed.")

    if manifest_valid and not failed:
        tree = _observed("dependency_tree_observation", "A bounded non-symlinked package directory with a valid manifest was observed.", value="bounded-package-tree")
    elif failed or manifest_failed:
        tree = _failed("dependency_tree_observation", "The bounded package tree contained an unreadable or ambiguous entry.")
    elif had_directory:
        tree = _observed("dependency_tree_observation", "Package directories were observed without sufficient manifest evidence.", confidence=Confidence.LOW, value="package-directories-only")
    else:
        tree = _confirmed_absent("dependency_tree_observation", "No direct package directory was observed.")
    return manifest, tree, manifest_valid, failed or manifest_failed


def _package_manager_indicator(path: Path) -> Evidence:
    try:
        npm_lock = path / ".package-lock.json"
        if npm_lock.exists():
            result = _read_json_object(npm_lock, required_key="lockfileVersion")
            if result == "valid":
                return _observed("package_manager_indicator", "The local npm hidden package lock marker was observed.", value="npm")
            return _failed("package_manager_indicator", "The local npm hidden package lock marker was corrupt or unreadable.")
        pnpm_store = path / ".pnpm"
        if pnpm_store.is_dir() and not pnpm_store.is_symlink():
            return _observed("package_manager_indicator", "A local pnpm package-tree marker was observed.", value="pnpm")
        yarn_state = path / ".yarn-state.yml"
        if yarn_state.is_file() and not yarn_state.is_symlink() and yarn_state.stat().st_size > 0:
            return _observed("package_manager_indicator", "A local Yarn state marker was observed.", value="yarn")
    except (PermissionError, OSError):
        return _failed("package_manager_indicator", "Local package-manager markers could not be inspected.")
    return _confirmed_absent("package_manager_indicator", "No supported local package-manager marker was observed inside node_modules.")


def inspect_node_modules(path: str | os.PathLike[str]) -> NodeModulesDetection:
    """Inspect one node_modules path and bounded package entries only."""

    inspected_path = Path(path)
    node_kind = observed_node_kind(inspected_path)
    structural = (
        "node_modules_directory_name_observation",
        "package_manifest_observation",
        "dependency_tree_observation",
    )
    if node_kind is not NodeKind.DIRECTORY:
        return _uninspectable(inspected_path, ArtifactKind.NODE_MODULES, node_kind, structural)
    try:
        manifest, tree, manifest_valid, tree_failed = _package_tree_evidence(inspected_path)
        manager = _package_manager_indicator(inspected_path)
        metadata = _observed("metadata_readability_observation", "The node_modules root and bounded package entries were readable.")
    except (PermissionError, OSError) as error:
        manifest = _failed("package_manifest_observation", f"Package manifests could not be inspected: {error}.")
        tree = _failed("dependency_tree_observation", f"The bounded package tree could not be inspected: {error}.")
        manager = _failed("package_manager_indicator", f"Package-manager markers could not be inspected: {error}.")
        metadata = _failed("metadata_readability_observation", "The node_modules entries could not be read reliably.")
        manifest_valid = False
        tree_failed = True
    structural_valid = manifest_valid and not tree_failed
    observations = (
        _name_observation(inspected_path, ArtifactKind.NODE_MODULES),
        _observed("path_object_observation", "The inspected path is a directory.", value=NodeKind.DIRECTORY.value),
        metadata,
        _observed("generator_indicator_observation", "A bounded Node package tree and valid package manifest were observed.", value="node-package-tree")
        if structural_valid
        else _observed("generator_indicator_observation", "Only partial Node package-tree evidence was observed.", confidence=Confidence.LOW, value="node-package-tree-partial")
        if not tree_failed
        else _failed("generator_indicator_observation", "Node package-tree provenance could not be inspected reliably."),
        _unknown("recreation_input_availability_observation", "Project manifests and package-manager-wide inputs outside the candidate were not inspected."),
        manifest,
        tree,
        manager,
        *context_unknown_evidence(_DETECTOR_SOURCE),
    )
    return NodeArtifactDetection(ArtifactKind.NODE_MODULES, ObservedNode(str(inspected_path), NodeKind.DIRECTORY, ProtectionClass.UNKNOWN), observations)


def _build_output_marker(path: Path, artifact: ArtifactKind) -> tuple[Evidence, bool, bool]:
    output_extensions = {".js", ".mjs", ".cjs", ".css", ".map", ".html", ".wasm"}
    output_names = {"index.html", "index.js", "server.js"}
    try:
        with os.scandir(path) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                candidate = Path(entry.path)
                if entry.is_symlink():
                    continue
                if entry.is_file(follow_symlinks=False):
                    if candidate.stat().st_size > 0 and (candidate.name in output_names or candidate.suffix.lower() in output_extensions):
                        return _observed("build_output_marker", f"A bounded {artifact.value} output file was observed.", value=candidate.name), True, False
                elif entry.is_dir(follow_symlinks=False) and entry.name in {"assets", "static", "chunks", "server", "js", "css"}:
                    valid, failed = _has_nonempty_direct_file(candidate)
                    if valid:
                        return _observed("build_output_marker", f"A bounded {artifact.value} output directory with non-empty files was observed.", value=entry.name), True, False
                    if failed:
                        return _failed("build_output_marker", f"The {artifact.value} output directory could not be inspected reliably."), False, True
    except (PermissionError, OSError) as error:
        return _failed("build_output_marker", f"The {artifact.value} output could not be inspected: {error}."), False, True
    return _confirmed_absent("build_output_marker", f"No defensible {artifact.value} output marker was observed at the candidate root."), False, False


_BUILD_CONFIG_NAMES = {"asset-manifest.json", "manifest.json", "webpack-stats.json", "vite-manifest.json", "build-manifest.json"}


def _build_configuration(path: Path, artifact: ArtifactKind) -> tuple[Evidence, bool, bool]:
    try:
        with os.scandir(path) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                if entry.name not in _BUILD_CONFIG_NAMES:
                    continue
                candidate = Path(entry.path)
                result = _read_json_object(candidate)
                if result == "valid":
                    return _observed("build_configuration_observation", f"A bounded {artifact.value} build metadata JSON file was observed.", value=entry.name), True, False
                if result == "weak":
                    return _observed("build_configuration_observation", f"A {artifact.value} build metadata file was present but structurally weak.", confidence=Confidence.LOW, value=entry.name), False, False
                return _failed("build_configuration_observation", f"The {artifact.value} build metadata file was corrupt or unreadable."), False, True
    except (PermissionError, OSError) as error:
        return _failed("build_configuration_observation", f"The {artifact.value} build metadata could not be inspected: {error}."), False, True
    return _confirmed_absent("build_configuration_observation", f"No supported bounded {artifact.value} build metadata file was observed."), False, False


def _build_detection(path: str | os.PathLike[str], artifact: ArtifactKind) -> NodeArtifactDetection:
    inspected_path = Path(path)
    output_key = "build_output_marker"
    config_key = "build_configuration_observation"
    name_key = _NAME_KEYS[artifact][1]
    structural = (name_key, output_key, config_key)
    node_kind = observed_node_kind(inspected_path)
    if node_kind is not NodeKind.DIRECTORY:
        return _uninspectable(inspected_path, artifact, node_kind, structural)
    output, output_valid, output_failed = _build_output_marker(inspected_path, artifact)
    config, config_valid, config_failed = _build_configuration(inspected_path, artifact)
    observations = (
        _name_observation(inspected_path, artifact),
        _observed("path_object_observation", "The inspected path is a directory.", value=NodeKind.DIRECTORY.value),
        _observed("metadata_readability_observation", f"The {artifact.value} root and bounded entries were readable.")
        if not output_failed and not config_failed
        else _failed("metadata_readability_observation", f"The {artifact.value} root or bounded metadata could not be read reliably."),
        _observed("generator_indicator_observation", f"Generic bounded {artifact.value} output and metadata were observed, but tool-specific provenance was not established.", confidence=Confidence.LOW, value="node-build-output-generic")
        if output_valid and config_valid
        else _observed("generator_indicator_observation", f"Only partial {artifact.value} output evidence was observed.", confidence=Confidence.LOW, value="node-build-output-partial")
        if not output_failed and not config_failed
        else _failed("generator_indicator_observation", f"{artifact.value} provenance could not be inspected reliably."),
        _unknown("recreation_input_availability_observation", "Source inputs and build configuration outside the candidate were not inspected."),
        output,
        config,
        _unknown("source_input_observation", "Source inputs outside the candidate boundary were intentionally not inspected."),
        *context_unknown_evidence(_DETECTOR_SOURCE),
    )
    return NodeArtifactDetection(artifact, ObservedNode(str(inspected_path), NodeKind.DIRECTORY, ProtectionClass.UNKNOWN), observations)


def inspect_dist(path: str | os.PathLike[str]) -> BuildArtifactDetection:
    return _build_detection(path, ArtifactKind.DIST)


def inspect_build(path: str | os.PathLike[str]) -> BuildArtifactDetection:
    return _build_detection(path, ArtifactKind.BUILD)


def _next_metadata(path: Path) -> tuple[Evidence, bool, bool]:
    try:
        build_id = path / "BUILD_ID"
        if build_id.is_symlink() or not build_id.is_file():
            return _confirmed_absent("next_metadata_marker", "No regular Next.js BUILD_ID marker was observed."), False, False
        if build_id.read_text(encoding="utf-8", errors="replace").strip():
            return _observed("next_metadata_marker", "A non-empty Next.js BUILD_ID marker was observed.", value="BUILD_ID"), True, False
        return _failed("next_metadata_marker", "The Next.js BUILD_ID marker was empty."), False, True
    except (PermissionError, OSError) as error:
        return _failed("next_metadata_marker", f"Next.js metadata could not be inspected: {error}."), False, True


def _next_project_configuration(path: Path) -> tuple[Evidence, bool, bool]:
    for name in ("required-server-files.json", "routes-manifest.json", "app-build-manifest.json"):
        result = _read_json_object(path / name)
        if result == "valid":
            return _observed("project_configuration_observation", "A bounded Next.js project/build configuration JSON file was observed.", value=name), True, False
        if result == "weak":
            return _observed("project_configuration_observation", "A Next.js configuration file was present but structurally weak.", confidence=Confidence.LOW, value=name), False, False
        if result == "failed" and (path / name).exists():
            return _failed("project_configuration_observation", f"The Next.js configuration file {name} was corrupt or unreadable."), False, True
    return _confirmed_absent("project_configuration_observation", "No supported bounded Next.js project configuration marker was observed."), False, False


def inspect_next_build(path: str | os.PathLike[str]) -> NextBuildDetection:
    inspected_path = Path(path)
    structural = (
        "next_build_directory_name_observation",
        "next_metadata_marker",
        "build_output_marker",
        "project_configuration_observation",
    )
    node_kind = observed_node_kind(inspected_path)
    if node_kind is not NodeKind.DIRECTORY:
        return _uninspectable(inspected_path, ArtifactKind.NEXT_BUILD, node_kind, structural)
    metadata, metadata_valid, metadata_failed = _next_metadata(inspected_path)
    output, output_valid, output_failed = _build_output_marker(inspected_path, ArtifactKind.NEXT_BUILD)
    config, config_valid, config_failed = _next_project_configuration(inspected_path)
    full = metadata_valid and output_valid and config_valid
    observations = (
        _name_observation(inspected_path, ArtifactKind.NEXT_BUILD),
        _observed("path_object_observation", "The inspected path is a directory.", value=NodeKind.DIRECTORY.value),
        _observed("metadata_readability_observation", "The .next root and bounded entries were readable.")
        if not metadata_failed and not output_failed and not config_failed
        else _failed("metadata_readability_observation", "The .next root or bounded metadata could not be read reliably."),
        _observed("generator_indicator_observation", "Defensible bounded Next.js metadata, output, and configuration were observed.", value="nextjs")
        if full
        else _observed("generator_indicator_observation", "Only partial Next.js structure was observed.", confidence=Confidence.LOW, value="nextjs-partial")
        if not metadata_failed and not output_failed and not config_failed
        else _failed("generator_indicator_observation", "Next.js provenance could not be inspected reliably."),
        _unknown("recreation_input_availability_observation", "Next.js source inputs and project configuration outside the candidate were not inspected."),
        metadata,
        output,
        config,
        *context_unknown_evidence(_DETECTOR_SOURCE),
    )
    return NodeArtifactDetection(ArtifactKind.NEXT_BUILD, ObservedNode(str(inspected_path), NodeKind.DIRECTORY, ProtectionClass.UNKNOWN), observations)


def _interpret(
    detection: NodeArtifactDetection,
    structural_keys: tuple[str, ...],
    generator: str,
    *,
    require_generator_evidence: bool = False,
) -> NodeArtifactInterpretation:
    requirements = requirements_by_key(detection.artifact)
    observations = detection.observations
    interpretation_keys = structural_keys + (("generator_indicator_observation",) if require_generator_evidence else ())
    structural_valid = all(positive_evidence_meets(observations, key, requirements) for key in interpretation_keys)
    structural_conflict = any(key_conflicts(observations, key) for key in interpretation_keys)
    structural_uncertainty = any(key_has_uncertainty(observations, key) for key in interpretation_keys)
    provenance = (
        Provenance("node", generator, Confidence.HIGH, structural_keys)
        if structural_valid and not structural_conflict and not structural_uncertainty
        else None
    )
    if structural_conflict:
        regenerability = RegenerabilityState.CONFLICTING
        regeneration_cost = RegenerationCost.UNKNOWN
    elif structural_valid and not structural_uncertainty:
        regenerability = RegenerabilityState.CONDITIONALLY_REPRODUCIBLE
        regeneration_cost = RegenerationCost.UNKNOWN
    else:
        regenerability = RegenerabilityState.UNKNOWN
        regeneration_cost = RegenerationCost.UNKNOWN
    return NodeArtifactInterpretation(
        artifact=detection.artifact,
        provenance=provenance,
        regenerability=regenerability,
        regeneration_cost=regeneration_cost,
        reachability=reachability_from_evidence(observations, requirements),
        activity=activity_from_evidence(observations),
        protection=protection_from_evidence(observations),
    )


def interpret_node_modules(detection: NodeModulesDetection) -> NodeModulesInterpretation:
    return _interpret(
        detection,
        ("node_modules_directory_name_observation", "package_manifest_observation", "dependency_tree_observation"),
        "node-package-tree",
    )


def interpret_dist(detection: BuildArtifactDetection) -> BuildArtifactInterpretation:
    return _interpret(
        detection,
        ("dist_directory_name_observation", "build_output_marker", "build_configuration_observation"),
        "node-build-tool",
        require_generator_evidence=True,
    )


def interpret_build(detection: BuildArtifactDetection) -> BuildArtifactInterpretation:
    return _interpret(
        detection,
        ("build_directory_name_observation", "build_output_marker", "build_configuration_observation"),
        "node-build-tool",
        require_generator_evidence=True,
    )


def interpret_next_build(detection: NextBuildDetection) -> NextBuildInterpretation:
    return _interpret(
        detection,
        ("next_build_directory_name_observation", "next_metadata_marker", "build_output_marker", "project_configuration_observation"),
        "nextjs",
    )
