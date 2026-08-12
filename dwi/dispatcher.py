"""Explicit single-candidate dispatcher for the bounded artifact analyzers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .contracts import ArtifactKind
from .global_storage import GlobalStorageDetection, GlobalStorageInterpretation
from .mypy_cache import MypyCacheDetection, MypyCacheInterpretation, inspect_mypy_cache, interpret_mypy_cache
from .node_artifacts import (
    BuildArtifactDetection,
    BuildArtifactInterpretation,
    NextBuildDetection,
    NextBuildInterpretation,
    NodeModulesDetection,
    NodeModulesInterpretation,
    inspect_build,
    inspect_dist,
    inspect_next_build,
    inspect_node_modules,
    interpret_build,
    interpret_dist,
    interpret_next_build,
    interpret_node_modules,
)
from .pycache import PycacheDetection, PycacheInterpretation, inspect_pycache, interpret_pycache
from .pytest_cache import PytestCacheDetection, PytestCacheInterpretation, inspect_pytest_cache, interpret_pytest_cache
from .ruff_cache import RuffCacheDetection, RuffCacheInterpretation, inspect_ruff_cache, interpret_ruff_cache
from .venv import PythonVenvDetection, PythonVenvInterpretation, inspect_python_venv, interpret_python_venv


Detection = (
    PycacheDetection
    | PytestCacheDetection
    | MypyCacheDetection
    | RuffCacheDetection
    | PythonVenvDetection
    | NodeModulesDetection
    | BuildArtifactDetection
    | NextBuildDetection
    | GlobalStorageDetection
)
Interpretation = (
    PycacheInterpretation
    | PytestCacheInterpretation
    | MypyCacheInterpretation
    | RuffCacheInterpretation
    | PythonVenvInterpretation
    | NodeModulesInterpretation
    | BuildArtifactInterpretation
    | NextBuildInterpretation
    | GlobalStorageInterpretation
)


@dataclass(frozen=True)
class AnalysisResult:
    """The result of one explicit artifact analysis, with no safety label."""

    artifact: ArtifactKind
    detection: Detection
    interpretation: Interpretation


def analyze_candidate(
    path: str | os.PathLike[str],
    *,
    disposable_root: bool = False,
) -> AnalysisResult | None:
    """Analyze one explicitly named candidate; never discovers neighboring paths."""

    candidate = Path(path)
    name = candidate.name
    if name == "__pycache__":
        detection = inspect_pycache(candidate)
        return AnalysisResult(ArtifactKind.PYCACHE, detection, interpret_pycache(detection))
    if name == ".pytest_cache":
        detection = inspect_pytest_cache(candidate, disposable_root=disposable_root)
        return AnalysisResult(ArtifactKind.PYTEST_CACHE, detection, interpret_pytest_cache(detection))
    if name == ".mypy_cache":
        detection = inspect_mypy_cache(candidate)
        return AnalysisResult(ArtifactKind.MYPY_CACHE, detection, interpret_mypy_cache(detection))
    if name == ".ruff_cache":
        detection = inspect_ruff_cache(candidate)
        return AnalysisResult(ArtifactKind.RUFF_CACHE, detection, interpret_ruff_cache(detection))
    if name in {".venv", "venv"}:
        detection = inspect_python_venv(candidate)
        return AnalysisResult(ArtifactKind.PYTHON_VENV, detection, interpret_python_venv(detection))
    if name == "node_modules":
        detection = inspect_node_modules(candidate)
        return AnalysisResult(ArtifactKind.NODE_MODULES, detection, interpret_node_modules(detection))
    if name == "dist":
        detection = inspect_dist(candidate)
        return AnalysisResult(ArtifactKind.DIST, detection, interpret_dist(detection))
    if name == "build":
        detection = inspect_build(candidate)
        return AnalysisResult(ArtifactKind.BUILD, detection, interpret_build(detection))
    if name == ".next":
        detection = inspect_next_build(candidate)
        return AnalysisResult(ArtifactKind.NEXT_BUILD, detection, interpret_next_build(detection))
    return None


dispatch_analysis = analyze_candidate
