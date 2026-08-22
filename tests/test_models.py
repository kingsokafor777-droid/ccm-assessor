from __future__ import annotations

import pytest
from pydantic import ValidationError

from ccm_assessor.evaluator import assess
from ccm_assessor.models import AssessmentManifest, AssessmentStatus, CoverageState

from .helpers import HASH_A, TENANT, manifest, observation, request


def test_observation_rejects_population_evidence_and_status_inconsistency() -> None:
    with pytest.raises(ValidationError):
        observation(observed=101)
    with pytest.raises(ValidationError):
        observation(observed=1, hash_value=None)
    with pytest.raises(ValidationError):
        observation(status=AssessmentStatus.NOT_ASSESSED)
    with pytest.raises(ValidationError):
        observation(hash_value="sha256:not-valid")


def test_request_rejects_duplicate_or_cross_tenant_observations_and_baseline() -> None:
    item = observation()
    with pytest.raises(ValidationError):
        request(item, item)
    with pytest.raises(ValidationError):
        request(observation(tenant_id="other_tenant"))
    baseline = manifest()
    with pytest.raises(ValidationError):
        request(baseline=baseline.model_copy(update={"tenant_id": "other_tenant"}))


def test_manifest_is_sealed_and_rejects_coverage_misalignment() -> None:
    sealed = manifest()
    assert sealed.verify_integrity() and sealed.manifest_id is not None
    assert not sealed.model_copy(update={"assessed_at": "2026-08-23T00:00:00Z"}).verify_integrity()
    with pytest.raises(ValidationError):
        AssessmentManifest(
            tenant_id=TENANT,
            assessment_profile_id="baseline_profile",
            assessment_profile_version="1.0.0",
            assessed_at="2026-08-22T00:00:00Z",
            controls=sealed.controls,
            coverage=(),
            drift=sealed.drift,
            risk_rollup=sealed.risk_rollup,
            input_hashes=(HASH_A,),
        )


def test_not_assessed_with_zero_observation_is_valid_and_visible() -> None:
    item = observation(
        control_id="logging_availability",
        status=AssessmentStatus.NOT_ASSESSED,
        expected=10,
        observed=0,
        collector_state=CoverageState.UNAVAILABLE,
        hash_value=None,
    )
    result = assess(request(item))
    assert result.controls[0].status == AssessmentStatus.NOT_ASSESSED
    assert result.coverage[0].state == CoverageState.UNAVAILABLE
