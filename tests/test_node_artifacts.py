import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from dwi import (
    ArtifactKind,
    Confidence,
    Evidence,
    EvidencePolarity,
    ObservationStatus,
    RegenerabilityState,
    inspect_build,
    inspect_dist,
    inspect_next_build,
    inspect_node_modules,
    interpret_build,
    interpret_dist,
    interpret_next_build,
    interpret_node_modules,
)


def _evidence_for(detection, key: str):
    return [item for item in detection.observations if item.key == key]


def _write_valid_node_modules(path: Path) -> None:
    package = path / "sample-package"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        json.dumps({"name": "sample-package", "version": "1.0.0"}),
        encoding="utf-8",
    )
    (path / ".package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3}),
        encoding="utf-8",
    )


def _write_valid_build(path: Path) -> None:
    path.mkdir()
    (path / "index.js").write_text("bundle", encoding="utf-8")
    (path / "manifest.json").write_text(json.dumps({"files": ["index.js"]}), encoding="utf-8")


def _write_valid_next(path: Path) -> None:
    path.mkdir()
    (path / "BUILD_ID").write_text("synthetic-build", encoding="utf-8")
    (path / "server").mkdir()
    (path / "server" / "index.js").write_text("server", encoding="utf-8")
    (path / "required-server-files.json").write_text(
        json.dumps({"version": 1}),
        encoding="utf-8",
    )


class NodeArtifactDetectorTests(unittest.TestCase):
    def test_valid_node_modules_has_conditional_regenerability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "node_modules"
            path.mkdir()
            _write_valid_node_modules(path)

            detection = inspect_node_modules(path)
            interpretation = interpret_node_modules(detection)

            self.assertIsNotNone(interpretation.provenance)
            self.assertEqual(interpretation.provenance.generator, "node-package-tree")
            self.assertEqual(
                interpretation.regenerability,
                RegenerabilityState.CONDITIONALLY_REPRODUCIBLE,
            )
            self.assertEqual(interpretation.regeneration_cost.value, "unknown")
            self.assertEqual(interpretation.reachability.value, "unknown")

    def test_valid_dist_and_build_have_separate_interpretations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            dist = root / "dist"
            build = root / "build"
            _write_valid_build(dist)
            _write_valid_build(build)

            dist_interpretation = interpret_dist(inspect_dist(dist))
            build_interpretation = interpret_build(inspect_build(build))

            self.assertEqual(dist_interpretation.artifact, ArtifactKind.DIST)
            self.assertEqual(build_interpretation.artifact, ArtifactKind.BUILD)
            self.assertIsNone(dist_interpretation.provenance)
            self.assertIsNone(build_interpretation.provenance)
            self.assertEqual(dist_interpretation.regenerability, RegenerabilityState.UNKNOWN)
            self.assertEqual(build_interpretation.regenerability, RegenerabilityState.UNKNOWN)
            self.assertEqual(dist_interpretation.regeneration_cost.value, "unknown")
            self.assertEqual(build_interpretation.regeneration_cost.value, "unknown")

    def test_generic_dist_build_structure_does_not_claim_build_tool_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for name, inspect, interpret in (
                ("dist", inspect_dist, interpret_dist),
                ("build", inspect_build, interpret_build),
            ):
                with self.subTest(name=name):
                    path = root / name
                    _write_valid_build(path)
                    (path / "README.txt").write_text(
                        "User-authored output-like data.",
                        encoding="utf-8",
                    )

                    detection = inspect(path)
                    interpretation = interpret(detection)

                    self.assertEqual(
                        _evidence_for(detection, "build_output_marker")[0].confidence,
                        Confidence.HIGH,
                    )
                    self.assertEqual(
                        _evidence_for(detection, "build_configuration_observation")[0].confidence,
                        Confidence.HIGH,
                    )
                    self.assertIsNone(interpretation.provenance)
                    self.assertEqual(
                        interpretation.regenerability,
                        RegenerabilityState.UNKNOWN,
                    )

    def test_valid_next_build_requires_bounded_next_structure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / ".next"
            _write_valid_next(path)

            interpretation = interpret_next_build(inspect_next_build(path))

            self.assertIsNotNone(interpretation.provenance)
            self.assertEqual(interpretation.provenance.generator, "nextjs")
            self.assertEqual(interpretation.regenerability, RegenerabilityState.CONDITIONALLY_REPRODUCIBLE)
            self.assertEqual(interpretation.regeneration_cost.value, "unknown")

    def test_name_only_matches_never_establish_identity(self) -> None:
        builders = (
            ("node_modules", lambda path: inspect_node_modules(path), lambda detection: interpret_node_modules(detection)),
            ("dist", lambda path: inspect_dist(path), lambda detection: interpret_dist(detection)),
            ("build", lambda path: inspect_build(path), lambda detection: interpret_build(detection)),
            (".next", lambda path: inspect_next_build(path), lambda detection: interpret_next_build(detection)),
        )
        for name, inspect, interpret in builders:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary_directory:
                path = Path(temporary_directory) / name
                path.mkdir()
                (path / "notes.txt").write_text("unrelated", encoding="utf-8")
                self.assertIsNone(interpret(inspect(path)).provenance)

    def test_partial_and_weak_structure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            node_modules = root / "node_modules"
            node_modules.mkdir()
            (node_modules / "sample-package").mkdir()
            node_assessment = inspect_node_modules(node_modules).contract_assessment()

            dist = root / "dist"
            dist.mkdir()
            (dist / "index.js").write_text("bundle", encoding="utf-8")
            (dist / "manifest.json").write_text("[]", encoding="utf-8")
            dist_detection = inspect_dist(dist)

            next_build = root / ".next"
            _write_valid_next(next_build)
            (next_build / "required-server-files.json").write_text("[]", encoding="utf-8")
            next_detection = inspect_next_build(next_build)

            self.assertIn("dependency_tree_observation", node_assessment.confidence_shortfalls)
            self.assertIn("build_configuration_observation", dist_detection.contract_assessment().confidence_shortfalls)
            self.assertIn("project_configuration_observation", next_detection.contract_assessment().confidence_shortfalls)
            self.assertIsNone(interpret_dist(dist_detection).provenance)
            self.assertIsNone(interpret_next_build(next_detection).provenance)

    def test_corrupt_metadata_is_observation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            node_modules = root / "node_modules"
            node_modules.mkdir()
            package = node_modules / "sample-package"
            package.mkdir()
            (package / "package.json").write_text("{broken", encoding="utf-8")
            node_detection = inspect_node_modules(node_modules)

            build = root / "build"
            build.mkdir()
            (build / "index.js").write_text("bundle", encoding="utf-8")
            (build / "manifest.json").write_text("{broken", encoding="utf-8")
            build_detection = inspect_build(build)

            self.assertEqual(_evidence_for(node_detection, "package_manifest_observation")[0].observation_status, ObservationStatus.FAILED)
            self.assertEqual(_evidence_for(build_detection, "build_configuration_observation")[0].observation_status, ObservationStatus.FAILED)
            self.assertIsNone(interpret_node_modules(node_detection).provenance)
            self.assertIsNone(interpret_build(build_detection).provenance)

    def test_inaccessible_shapes_do_not_get_guessed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            node_modules = root / "node_modules"
            node_modules.mkdir()
            (node_modules / "sample-package").mkdir()
            (node_modules / "sample-package" / "package.json").mkdir()
            node_detection = inspect_node_modules(node_modules)

            dist = root / "dist"
            dist.mkdir()
            (dist / "index.js").mkdir()
            dist_detection = inspect_dist(dist)

            self.assertTrue(node_detection.contract_assessment().has_uncertainty)
            self.assertEqual(_evidence_for(dist_detection, "build_output_marker")[0].observation_status, ObservationStatus.CONFIRMED_ABSENT)
            self.assertIsNone(interpret_node_modules(node_detection).provenance)
            self.assertIsNone(interpret_dist(dist_detection).provenance)

    def test_conflicting_structural_evidence_fails_closed(self) -> None:
        builders = (
            (ArtifactKind.NODE_MODULES, _write_valid_node_modules, inspect_node_modules, interpret_node_modules, "package_manifest_observation"),
            (ArtifactKind.DIST, _write_valid_build, inspect_dist, interpret_dist, "build_output_marker"),
            (ArtifactKind.BUILD, _write_valid_build, inspect_build, interpret_build, "build_output_marker"),
            (ArtifactKind.NEXT_BUILD, _write_valid_next, inspect_next_build, interpret_next_build, "next_metadata_marker"),
        )
        names = {
            ArtifactKind.NODE_MODULES: "node_modules",
            ArtifactKind.DIST: "dist",
            ArtifactKind.BUILD: "build",
            ArtifactKind.NEXT_BUILD: ".next",
        }
        for artifact, writer, inspect, interpret, key in builders:
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as temporary_directory:
                path = Path(temporary_directory) / names[artifact]
                writer(path)
                detection = inspect(path)
                conflicting = replace(
                    detection,
                    observations=detection.observations + (
                        Evidence(
                            key=key,
                            source="synthetic-test",
                            description="A synthetic structural contradiction.",
                            observation_status=ObservationStatus.CONFIRMED_ABSENT,
                            polarity=EvidencePolarity.CONTRADICTS,
                            confidence=Confidence.HIGH,
                        ),
                    ),
                )
                self.assertTrue(conflicting.contract_assessment().has_conflicts)
                self.assertEqual(interpret(conflicting).regenerability, RegenerabilityState.CONFLICTING)

    def test_repeated_evaluation_is_deterministic(self) -> None:
        builders = (
            ("node_modules", _write_valid_node_modules, inspect_node_modules, interpret_node_modules),
            ("dist", _write_valid_build, inspect_dist, interpret_dist),
            ("build", _write_valid_build, inspect_build, interpret_build),
            (".next", _write_valid_next, inspect_next_build, interpret_next_build),
        )
        for name, writer, inspect, interpret in builders:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary_directory:
                path = Path(temporary_directory) / name
                writer(path)
                first = inspect(path)
                second = inspect(path)
                self.assertEqual(first, second)
                self.assertEqual(interpret(first), interpret(second))


if __name__ == "__main__":
    unittest.main()
