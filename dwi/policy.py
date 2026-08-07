"""Minimal deterministic safety-policy primitives for DWI."""

from __future__ import annotations

from dataclasses import dataclass

from .domain import (
    ActionEligibility,
    ActivityState,
    CleanupCandidate,
    Confidence,
    EvidenceBundle,
    EvidenceRequirement,
    ProtectionClass,
    Provenance,
    ReclaimPriority,
    RegenerabilityState,
    RegenerationCost,
    ReachabilityState,
    RiskLabel,
    RuleOutcome,
    RuleTrace,
    RuleTraceEntry,
)


def escalate_risk(current: RiskLabel, proposed: RiskLabel) -> RiskLabel:
    """Return the more cautious label; labels never de-escalate."""

    return proposed if proposed.rank > current.rank else current


@dataclass(frozen=True)
class SafetyContext:
    candidate: CleanupCandidate
    evidence: EvidenceBundle
    provenance: Provenance | None
    regenerability: RegenerabilityState
    regeneration_cost: RegenerationCost
    reachability: ReachabilityState
    activity: ActivityState
    protection: ProtectionClass
    reclaim_priority: ReclaimPriority = ReclaimPriority.UNKNOWN
    established_risk: RiskLabel = RiskLabel.SAFE
    provenance_requirement: EvidenceRequirement = EvidenceRequirement("provenance", Confidence.HIGH)

    def __post_init__(self) -> None:
        if self.candidate.node.protection is not self.protection:
            raise ValueError("policy protection must match the candidate node protection")


@dataclass(frozen=True)
class SafetyDecision:
    risk_label: RiskLabel
    regenerability: RegenerabilityState
    reachability: ReachabilityState
    activity: ActivityState
    protection: ProtectionClass
    action_eligibility: ActionEligibility
    reclaim_priority: ReclaimPriority
    rule_trace: RuleTrace


def evaluate_safety(context: SafetyContext, *, engine_version: str = "dwi-domain-0.1") -> SafetyDecision:
    """Evaluate only typed synthetic context; never reads the filesystem or performs an action."""

    label = context.established_risk
    entries: list[RuleTraceEntry] = []

    def apply_rule(
        rule_id: str,
        condition: bool,
        proposed: RiskLabel | None,
        reason: str,
        evidence_keys: tuple[str, ...] = (),
        outcome: RuleOutcome | None = None,
    ) -> None:
        nonlocal label
        next_label = label if proposed is None else escalate_risk(label, proposed)
        if outcome is None:
            if condition and proposed is not None:
                outcome = RuleOutcome.ESCALATED if next_label.rank > label.rank else RuleOutcome.BLOCKED
            else:
                outcome = RuleOutcome.PASSED
        if condition and proposed is not None:
            label = next_label
        entries.append(RuleTraceEntry(rule_id, outcome, reason, evidence_keys))

    if context.protection in {
        ProtectionClass.SYSTEM_PROTECTED,
        ProtectionClass.REPOSITORY_PROTECTED,
    }:
        apply_rule(
            "protection_floor",
            True,
            RiskLabel.NEVER_DELETE,
            "Sufficient protection evidence establishes a NEVER_DELETE floor.",
        )
    elif context.protection in {ProtectionClass.PROTECTED, ProtectionClass.UNKNOWN, ProtectionClass.CONFLICTING}:
        apply_rule(
            "protection_uncertain",
            True,
            RiskLabel.REVIEW_REQUIRED,
            "Protection is not sufficiently known for a low-risk conclusion.",
        )
    else:
        apply_rule("protection_floor", False, None, "No protection escalation was established.")

    if not context.evidence.is_complete:
        apply_rule(
            "required_evidence",
            True,
            RiskLabel.REVIEW_REQUIRED,
            "Required evidence is missing; absence of evidence is not evidence of safety.",
            tuple(sorted(context.evidence.missing_keys)),
        )
    else:
        apply_rule("required_evidence", False, None, "All declared evidence keys are present.")

    if context.evidence.confidence_shortfalls:
        apply_rule(
            "minimum_confidence",
            True,
            RiskLabel.REVIEW_REQUIRED,
            "One or more evidence items do not meet their declared minimum confidence.",
            tuple(sorted(context.evidence.confidence_shortfalls)),
        )
    else:
        apply_rule("minimum_confidence", False, None, "All evidence meets its declared minimum confidence.")

    if context.evidence.has_uncertainty:
        apply_rule(
            "uncertain_evidence",
            True,
            RiskLabel.REVIEW_REQUIRED,
            "Evidence failed, is unknown, or lacks sufficient certainty; the result must fail closed.",
            tuple(item.key for item in context.evidence.observations if item.is_uncertain),
        )
    else:
        apply_rule("uncertain_evidence", False, None, "All evidence has sufficient observation status and certainty.")

    if context.evidence.has_conflicts:
        apply_rule(
            "conflicting_evidence",
            True,
            RiskLabel.REVIEW_REQUIRED,
            "Conflicting evidence fails closed; conservative evidence wins.",
        )
    else:
        apply_rule("conflicting_evidence", False, None, "No conflicting evidence was recorded.")

    if context.provenance is None or not context.provenance.meets_confidence(context.provenance_requirement.minimum_confidence):
        apply_rule(
            "provenance_known",
            True,
            RiskLabel.REVIEW_REQUIRED,
            "Provenance is unknown or below its declared minimum confidence.",
        )
    else:
        apply_rule("provenance_known", False, None, "Provenance is supported by known evidence.")

    if context.reachability is ReachabilityState.CONFIRMED_REFERENCED:
        apply_rule(
            "confirmed_reachability",
            True,
            RiskLabel.REVIEW_REQUIRED,
            "A confirmed reference or active consumer is a hard safety gate.",
        )
    elif context.reachability in {ReachabilityState.UNKNOWN, ReachabilityState.CONFLICTING}:
        apply_rule(
            "reachability_uncertain",
            True,
            RiskLabel.REVIEW_REQUIRED,
            "Reachability is unknown or conflicting; the result must fail closed.",
        )
    else:
        apply_rule(
            "confirmed_non_reachability",
            False,
            None,
            "References were actively checked and confirmed absent.",
        )

    if context.activity in {ActivityState.UNKNOWN, ActivityState.CONFLICTING}:
        apply_rule(
            "activity_uncertain",
            True,
            RiskLabel.REVIEW_REQUIRED,
            "Runtime activity is unknown or conflicting.",
        )
    else:
        apply_rule(
            "activity_uncertain",
            False,
            None,
            "Runtime activity is known for this evaluation.",
        )

    if context.regenerability in {
        RegenerabilityState.UNKNOWN,
        RegenerabilityState.CONFLICTING,
        RegenerabilityState.NOT_REPRODUCIBLE,
    }:
        apply_rule(
            "regenerability_evidence",
            True,
            RiskLabel.REVIEW_REQUIRED,
            "Regenerability evidence is absent, conflicting, or does not establish reproducibility.",
        )
    else:
        # This is a policy conclusion only after the other gates have run.
        # It deliberately does not assign SAFE, and it never overrides a
        # confirmed-reference or other REVIEW_REQUIRED escalation.
        apply_rule(
            "policy_regeneratable_conclusion",
            True,
            RiskLabel.REGENERATABLE,
            "Regenerability evidence supports a conditional policy conclusion after applicable gates.",
        )

    if label is RiskLabel.NEVER_DELETE or context.activity is ActivityState.ACTIVE_RUNTIME:
        action = ActionEligibility.BLOCKED
    elif label is RiskLabel.REVIEW_REQUIRED:
        action = ActionEligibility.REQUIRES_REVIEW
    else:
        action = ActionEligibility.ELIGIBLE_FOR_EXPLICIT_ACTION

    if context.activity is ActivityState.ACTIVE_RUNTIME:
        entries.append(
            RuleTraceEntry(
                "active_runtime_action_gate",
                RuleOutcome.BLOCKED,
                "Active runtime state blocks action without changing intrinsic RiskLabel.",
                (),
            )
        )

    return SafetyDecision(
        risk_label=label,
        regenerability=context.regenerability,
        reachability=context.reachability,
        activity=context.activity,
        protection=context.protection,
        action_eligibility=action,
        reclaim_priority=context.reclaim_priority,
        rule_trace=RuleTrace(engine_version=engine_version, entries=tuple(entries)),
    )
