"""Deterministic synthetic ccm-assessor contract builders."""

from __future__ import annotations

from ccm_assessor.evaluator import assess
from ccm_assessor.models import (
    AssessmentRequest,
    AssessmentStatus,
    ControlObservation,
    CoverageState,
    RiskLevel,
)

TENANT = "demo_tenant"
HASH_A = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)


def observation(
    control_id: str = "identity_mfa_coverage",
    *,
    version: str = "1.0.0",
    status: AssessmentStatus = AssessmentStatus.PASS,
    severity: RiskLevel = RiskLevel.HIGH,
    expected: int = 100,
    observed: int = 100,
    collector_state: CoverageState = CoverageState.COMPLETE,
    hash_value: str | None = HASH_A,
    tenant_id: str = TENANT,
) -> ControlObservation:
    return ControlObservation(
        tenant_id=tenant_id,
        control_id=control_id,
        control_version=version,
        status=status,
        severity=severity,
        summary=f"synthetic {control_id} result",
        explanation_code="synthetic_fixture",
        owner_team="cloud_security",
        assessed_at="2026-08-22T00:00:00Z",
        expected_population=expected,
        observed_population=observed,
        collector_state=collector_state,
        evidence_ids=(f"evidence_{control_id}",) if hash_value else (),
        evidence_hashes=(hash_value,) if hash_value else (),
    )


def request(*items: ControlObservation, baseline=None, version: str = "1.0.0") -> AssessmentRequest:
    return AssessmentRequest(
        tenant_id=TENANT,
        assessment_profile_id="baseline_profile",
        assessment_profile_version=version,
        assessed_at="2026-08-22T00:00:00Z",
        observations=items or (observation(),),
        baseline_manifest=baseline,
    )


def manifest(*items: ControlObservation, version: str = "1.0.0"):
    return assess(request(*items, version=version))
