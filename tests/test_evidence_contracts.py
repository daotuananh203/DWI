import unittest
from dataclasses import replace

from dwi import (
    ArtifactKind,
    Confidence,
    Evidence,
    EvidencePolarity,
    EvidenceRequirement,
    ExpectedDomainInterpretation,
    ObservationStatus,
    all_contracts,
    contract_for,
    fixture_by_id,
    initial_artifact_fixtures,
)


class EvidenceContractTests(unittest.TestCase):
    def test_contracts_cover_initial_python_and_node_artifacts(self) -> None:
        contracts = all_contracts()
        self.assertEqual({contract.artifact for contract in contracts}, set(ArtifactKind))
        self.assertEqual(len(contracts), 9)
        raw_common_keys = {
            "path_object_observation",
            "metadata_readability_observation",
            "generator_indicator_observation",
            "recreation_input_observation",
            "reference_check_observation",
            "runtime_activity_observation",
            "protection_indicator_observation",
        }
        forbidden_domain_keys = {
            "provenance",
            "regenerability",
            "reachability",
            "activity",
            "protection",
            "risk_label",
        }
        for contract in contracts:
            keys = {requirement.key for requirement in contract.requirements}
            self.assertTrue(raw_common_keys.issubset(keys))
            self.assertTrue(keys.isdisjoint(forbidden_domain_keys))

    def test_normal_fixtures_satisfy_contracts_without_assigning_risk(self) -> None:
        fixtures = [fixture for fixture in initial_artifact_fixtures() if not fixture.adversarial]
        self.assertEqual(len(fixtures), 10)
        for fixture in fixtures:
            assessment = fixture.assess_contract()
            self.assertTrue(assessment.evidence_sufficient, fixture.fixture_id)
            self.assertFalse(hasattr(assessment, "risk_label"))
            self.assertIsInstance(
                fixture.expected_interpretation,
                ExpectedDomainInterpretation,
            )
            for domain_state in (
                "provenance",
                "regenerability",
                "reachability",
                "activity",
                "protection",
                "reclaim_priority",
            ):
                self.assertFalse(hasattr(fixture, domain_state))

    def test_contract_assessment_uses_raw_observations_not_expected_output(self) -> None:
        fixture = fixture_by_id("normal_pycache")
        without_expected_output = replace(fixture, expected_interpretation=None)
        self.assertEqual(
            fixture.assess_contract(),
            without_expected_output.assess_contract(),
        )
        self.assertEqual(
            fixture.assess_contract().bundle.observations,
            fixture.observations,
        )

    def test_missing_metadata_fails_closed(self) -> None:
        assessment = fixture_by_id("adversarial_venv_missing_project_metadata").assess_contract()
        self.assertIn("project_metadata_observation", assessment.missing_keys)
        self.assertFalse(assessment.evidence_sufficient)

    def test_corrupt_metadata_fails_closed(self) -> None:
        assessment = fixture_by_id("adversarial_node_modules_corrupt_lockfile").assess_contract()
        self.assertTrue(assessment.has_uncertainty)
        self.assertFalse(assessment.evidence_sufficient)

    def test_weak_evidence_fails_minimum_confidence(self) -> None:
        assessment = fixture_by_id("adversarial_weak_pycache_evidence").assess_contract()
        self.assertIn("python_bytecode_marker", assessment.confidence_shortfalls)
        self.assertFalse(assessment.evidence_sufficient)

    def test_conflicting_evidence_fails_closed(self) -> None:
        assessment = fixture_by_id("adversarial_conflicting_reachability").assess_contract()
        self.assertTrue(assessment.has_conflicts)
        self.assertFalse(assessment.evidence_sufficient)

    def test_assumed_absence_is_not_confirmed_absence(self) -> None:
        assumed = fixture_by_id("adversarial_assumed_absence").assess_contract()
        confirmed = fixture_by_id("confirmed_absence").assess_contract()
        self.assertTrue(assumed.has_uncertainty)
        self.assertFalse(assumed.evidence_sufficient)
        self.assertFalse(confirmed.has_uncertainty)
        self.assertTrue(confirmed.evidence_sufficient)

    def test_symlink_reference_ambiguity_fails_closed(self) -> None:
        assessment = fixture_by_id("adversarial_symlink_reference_ambiguity").assess_contract()
        self.assertTrue(assessment.has_uncertainty)
        self.assertFalse(assessment.evidence_sufficient)

    def test_contract_can_express_a_minimum_without_detector_logic(self) -> None:
        contract = contract_for(ArtifactKind.PYCACHE)
        requirements = {requirement.key: requirement for requirement in contract.requirements}
        self.assertEqual(
            requirements["path_object_observation"].minimum_confidence,
            Confidence.HIGH,
        )
        custom = EvidenceRequirement("synthetic_context", Confidence.MEDIUM)
        self.assertEqual(custom.minimum_confidence, Confidence.MEDIUM)

    def test_not_observed_cannot_be_used_as_negative_contract_evidence(self) -> None:
        with self.assertRaises(ValueError):
            Evidence(
                key="reference_check_observation",
                source="synthetic-fixture",
                description="Invalid assumed negative.",
                observation_status=ObservationStatus.NOT_OBSERVED,
                polarity=EvidencePolarity.CONTRADICTS,
                confidence=Confidence.HIGH,
            )


if __name__ == "__main__":
    unittest.main()
