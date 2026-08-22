"""Pure deterministic orchestration for technical-control assessment manifests."""

from __future__ import annotations

from collections import Counter
from typing import Final

from .canonical import sha256_digest
from .models import (
    AssessmentManifest,
    AssessmentRequest,
    AssessmentStatus,
    ControlAssessment,
    ControlObservation,
    CoverageState,
    DriftKind,
    DriftRecord,
    EvidenceCoverage,
    RiskLevel,
    RiskRollup,
)

RISK_WEIGHTS: Final[dict[RiskLevel, int]] = {
    RiskLevel.CRITICAL: 100,
    RiskLevel.HIGH: 75,
    RiskLevel.MEDIUM: 50,
    RiskLevel.LOW: 25,
    RiskLevel.INFORMATIONAL: 0,
}
SEVERITY_ORDER: Final[dict[RiskLevel, int]] = {
    RiskLevel.INFORMATIONAL: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}
EXPOSURE_ORDER: Final[dict[AssessmentStatus, int]] = {
    AssessmentStatus.PASS: 0,
    AssessmentStatus.NOT_ASSESSED: 0,
    AssessmentStatus.PARTIAL: 1,
    AssessmentStatus.FAIL: 2,
    AssessmentStatus.ERROR: 3,
}


def derive_coverage(observation: ControlObservation) -> EvidenceCoverage:
    """Derive an explicit collection/evidence coverage outcome from one observation."""

    percent = (observation.observed_population * 100) // observation.expected_population
    if observation.collector_state == CoverageState.ERROR:
        state = CoverageState.ERROR
        reason = "collector reported an evaluation or collection error"
    elif observation.collector_state == CoverageState.UNAVAILABLE:
        state = CoverageState.UNAVAILABLE
        reason = "collector source was explicitly unavailable"
    elif observation.observed_population == observation.expected_population:
        state = CoverageState.COMPLETE
        reason = "expected population was observed with evidence references"
    else:
        state = CoverageState.PARTIAL
        reason = "observed population is smaller than expected population"
    return EvidenceCoverage(
        control_id=observation.control_id,
        control_version=observation.control_version,
        state=state,
        expected_population=observation.expected_population,
        observed_population=observation.observed_population,
        coverage_percent=percent,
        evidence_hashes=observation.evidence_hashes,
        reason=reason,
    )


def _control_assessment(
    observation: ControlObservation,
    coverage: EvidenceCoverage,
) -> ControlAssessment:
    return ControlAssessment(
        control_id=observation.control_id,
        control_version=observation.control_version,
        status=observation.status,
        severity=observation.severity,
        summary=observation.summary,
        explanation_code=observation.explanation_code,
        owner_team=observation.owner_team,
        assessed_at=observation.assessed_at,
        evidence_ids=observation.evidence_ids,
        evidence_hashes=observation.evidence_hashes,
        coverage=coverage,
    )


def _exposure_points(assessment: ControlAssessment) -> int:
    weight = RISK_WEIGHTS[assessment.severity]
    if assessment.status == AssessmentStatus.PARTIAL:
        return weight // 2
    if assessment.status in {AssessmentStatus.FAIL, AssessmentStatus.ERROR}:
        return weight
    return 0


def build_risk_rollup(assessments: tuple[ControlAssessment, ...]) -> RiskRollup:
    """Compute the transparent fixed v1 risk prioritization summary."""

    raw_points = sum(_exposure_points(item) for item in assessments)
    maximum_points = sum(RISK_WEIGHTS[item.severity] for item in assessments)
    contributors = tuple(item for item in assessments if _exposure_points(item) > 0)
    highest = (
        max(contributors, key=lambda item: SEVERITY_ORDER[item.severity]).severity
        if contributors
        else None
    )
    status_counts = Counter(item.status for item in assessments)
    coverage_counts = Counter(item.coverage.state for item in assessments)
    return RiskRollup(
        raw_points=raw_points,
        maximum_points=maximum_points,
        risk_percent=(raw_points * 100) // maximum_points if maximum_points else 0,
        highest_contributing_severity=highest,
        contributing_control_count=len(contributors),
        error_control_count=status_counts[AssessmentStatus.ERROR],
        status_counts={status: status_counts[status] for status in AssessmentStatus},
        coverage_counts={state: coverage_counts[state] for state in CoverageState},
    )


def _drift_record(
    current: ControlAssessment,
    baseline: AssessmentManifest | None,
    *,
    profile_matches: bool,
) -> DriftRecord:
    if baseline is None:
        return DriftRecord(
            control_id=current.control_id,
            control_version=current.control_version,
            kind=DriftKind.NEW,
            current_status=current.status,
            current_coverage_percent=current.coverage.coverage_percent,
            reason="no baseline manifest was supplied",
        )
    prior_by_id = {item.control_id: item for item in baseline.controls}
    previous = prior_by_id.get(current.control_id)
    if previous is None:
        return DriftRecord(
            control_id=current.control_id,
            control_version=current.control_version,
            kind=DriftKind.NEW,
            current_status=current.status,
            current_coverage_percent=current.coverage.coverage_percent,
            reason="control does not exist in baseline manifest",
        )
    if not profile_matches or previous.control_version != current.control_version:
        return DriftRecord(
            control_id=current.control_id,
            control_version=current.control_version,
            kind=DriftKind.NOT_COMPARABLE,
            previous_status=previous.status,
            current_status=current.status,
            previous_coverage_percent=previous.coverage.coverage_percent,
            current_coverage_percent=current.coverage.coverage_percent,
            reason="baseline profile or control version is incompatible",
        )
    previous_order = EXPOSURE_ORDER[previous.status]
    current_order = EXPOSURE_ORDER[current.status]
    if previous.status != AssessmentStatus.PASS and current.status == AssessmentStatus.PASS:
        kind, reason = DriftKind.RESOLVED, "current result passed after a non-pass baseline result"
    elif current_order > previous_order:
        kind, reason = DriftKind.REGRESSED, "current result has greater exposure than baseline"
    elif current_order < previous_order:
        kind, reason = DriftKind.IMPROVED, "current result has lower exposure than baseline"
    elif current.coverage.coverage_percent != previous.coverage.coverage_percent or (
        current.coverage.state != previous.coverage.state
    ):
        kind, reason = DriftKind.COVERAGE_CHANGED, "current evidence coverage differs from baseline"
    else:
        kind, reason = DriftKind.UNCHANGED, "result status and coverage match baseline"
    return DriftRecord(
        control_id=current.control_id,
        control_version=current.control_version,
        kind=kind,
        previous_status=previous.status,
        current_status=current.status,
        previous_coverage_percent=previous.coverage.coverage_percent,
        current_coverage_percent=current.coverage.coverage_percent,
        reason=reason,
    )


def assess(request: AssessmentRequest) -> AssessmentManifest:
    """Build and seal a deterministic assessment manifest from supplied observations."""

    ordered_observations = tuple(
        sorted(request.observations, key=lambda item: (item.control_id, item.control_version))
    )
    coverage = tuple(derive_coverage(item) for item in ordered_observations)
    controls = tuple(
        _control_assessment(item, cover)
        for item, cover in zip(ordered_observations, coverage, strict=True)
    )
    baseline = request.baseline_manifest
    profile_matches = bool(
        baseline
        and baseline.assessment_profile_id == request.assessment_profile_id
        and baseline.assessment_profile_version == request.assessment_profile_version
    )
    drift = tuple(
        _drift_record(item, baseline, profile_matches=profile_matches) for item in controls
    )
    input_hashes = tuple(
        sha256_digest(item.model_dump(mode="json", exclude_none=True))
        for item in ordered_observations
    )
    return AssessmentManifest(
        tenant_id=request.tenant_id,
        assessment_profile_id=request.assessment_profile_id,
        assessment_profile_version=request.assessment_profile_version,
        assessed_at=request.assessed_at,
        controls=controls,
        coverage=coverage,
        drift=drift,
        risk_rollup=build_risk_rollup(controls),
        input_hashes=input_hashes,
    ).seal()
