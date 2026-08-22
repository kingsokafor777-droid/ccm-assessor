"""Build deterministic synthetic ccm-assessor fixtures without external state."""

from __future__ import annotations

import json
from pathlib import Path

from ccm_assessor.evaluator import assess
from ccm_assessor.models import (
    AssessmentRequest,
    AssessmentStatus,
    ControlObservation,
    CoverageState,
    RiskLevel,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
TENANT = "demo_tenant"
HASH_A = "sha256:" + ("a" * 64)
HASH_B = "sha256:" + ("b" * 64)


def observation(
    control_id: str,
    *,
    version: str = "1.0.0",
    status: AssessmentStatus,
    severity: RiskLevel,
    expected: int,
    observed: int,
    coverage: CoverageState,
    hash_value: str | None,
) -> ControlObservation:
    return ControlObservation(
        tenant_id=TENANT,
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
        collector_state=coverage,
        evidence_ids=(f"evidence_{control_id}",) if hash_value else (),
        evidence_hashes=(hash_value,) if hash_value else (),
    )


def write_json(name: str, value: object) -> None:
    (FIXTURES / name).write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    baseline_request = AssessmentRequest(
        tenant_id=TENANT,
        assessment_profile_id="baseline_profile",
        assessment_profile_version="1.0.0",
        assessed_at="2026-08-21T00:00:00Z",
        observations=(
            observation(
                "identity_mfa_coverage",
                status=AssessmentStatus.FAIL,
                severity=RiskLevel.HIGH,
                expected=100,
                observed=100,
                coverage=CoverageState.COMPLETE,
                hash_value=HASH_A,
            ),
        ),
    )
    baseline = assess(baseline_request)
    request = AssessmentRequest(
        tenant_id=TENANT,
        assessment_profile_id="baseline_profile",
        assessment_profile_version="1.0.0",
        assessed_at="2026-08-22T00:00:00Z",
        baseline_manifest=baseline,
        observations=(
            observation(
                "identity_mfa_coverage",
                status=AssessmentStatus.PASS,
                severity=RiskLevel.HIGH,
                expected=100,
                observed=100,
                coverage=CoverageState.COMPLETE,
                hash_value=HASH_A,
            ),
            observation(
                "storage_encryption_coverage",
                status=AssessmentStatus.PARTIAL,
                severity=RiskLevel.HIGH,
                expected=80,
                observed=60,
                coverage=CoverageState.PARTIAL,
                hash_value=HASH_B,
            ),
        ),
    )
    manifest = assess(request)
    write_json("safe-baseline-manifest.json", baseline.model_dump(mode="json", exclude_none=True))
    write_json("safe-request.json", request.model_dump(mode="json", exclude_none=True))
    write_json("safe-manifest.json", manifest.model_dump(mode="json", exclude_none=True))


if __name__ == "__main__":
    main()
