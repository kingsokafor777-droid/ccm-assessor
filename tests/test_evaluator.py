from __future__ import annotations

from ccm_assessor.evaluator import assess, build_risk_rollup, derive_coverage
from ccm_assessor.models import AssessmentStatus, CoverageState, DriftKind, RiskLevel

from .helpers import manifest, observation, request


def test_coverage_derivation_keeps_complete_partial_unavailable_and_error_visible() -> None:
    assert derive_coverage(observation()).state == CoverageState.COMPLETE
    assert derive_coverage(observation(expected=10, observed=8)).state == CoverageState.PARTIAL
    unavailable = observation(
        status=AssessmentStatus.NOT_ASSESSED,
        expected=10,
        observed=0,
        collector_state=CoverageState.UNAVAILABLE,
        hash_value=None,
    )
    assert derive_coverage(unavailable).state == CoverageState.UNAVAILABLE
    error = observation(
        control_id="logging_availability",
        status=AssessmentStatus.ERROR,
        expected=10,
        observed=0,
        collector_state=CoverageState.ERROR,
        hash_value=None,
    )
    assert derive_coverage(error).state == CoverageState.ERROR


def test_risk_rollup_uses_disclosed_fixed_policy_and_counts_errors() -> None:
    result = assess(
        request(
            observation(status=AssessmentStatus.PASS, severity=RiskLevel.HIGH),
            observation(
                control_id="storage_encryption_coverage",
                status=AssessmentStatus.PARTIAL,
                severity=RiskLevel.HIGH,
                expected=10,
                observed=5,
            ),
            observation(
                control_id="logging_availability",
                status=AssessmentStatus.ERROR,
                severity=RiskLevel.MEDIUM,
                expected=10,
                observed=0,
                collector_state=CoverageState.ERROR,
                hash_value=None,
            ),
        )
    )
    rollup = build_risk_rollup(result.controls)
    assert rollup.raw_points == 87
    assert rollup.maximum_points == 200
    assert rollup.risk_percent == 43
    assert rollup.highest_contributing_severity == RiskLevel.HIGH
    assert rollup.error_control_count == 1


def test_drift_classifies_all_closed_categories() -> None:
    baseline_fail = manifest(observation(status=AssessmentStatus.FAIL))
    resolved = assess(request(observation(status=AssessmentStatus.PASS), baseline=baseline_fail))
    assert resolved.drift[0].kind == DriftKind.RESOLVED
    baseline_pass = manifest(observation(status=AssessmentStatus.PASS))
    regressed = assess(request(observation(status=AssessmentStatus.FAIL), baseline=baseline_pass))
    assert regressed.drift[0].kind == DriftKind.REGRESSED
    improved = assess(request(observation(status=AssessmentStatus.PARTIAL), baseline=baseline_fail))
    assert improved.drift[0].kind == DriftKind.IMPROVED
    unchanged = assess(request(observation(), baseline=baseline_pass))
    assert unchanged.drift[0].kind == DriftKind.UNCHANGED
    coverage_changed = assess(request(observation(expected=10, observed=8), baseline=baseline_pass))
    assert coverage_changed.drift[0].kind == DriftKind.COVERAGE_CHANGED
    incompatible = assess(request(observation(version="2.0.0"), baseline=baseline_pass))
    assert incompatible.drift[0].kind == DriftKind.NOT_COMPARABLE
    assert assess(request(observation(control_id="new_control"))).drift[0].kind == DriftKind.NEW
