"""Strict deterministic contracts for ccm-assessor v1.

These contracts report versioned technical assessment data and do not make an
audit, certification, attestation, or framework-conformance determination.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Annotated, Any, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .canonical import require_digest, sha256_digest, stable_identifier

SCHEMA_VERSION: Final = "ccm.assessor/v1"
UTC_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
UTCDateTime = Annotated[str, StringConstraints(pattern=UTC_TIMESTAMP_PATTERN.pattern)]
StableId = Annotated[str, StringConstraints(pattern=ID_PATTERN.pattern)]
NonEmpty = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class StrictModel(BaseModel):
    """Fail closed on unknown or coercible public contract fields."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class AssessmentStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_ASSESSED = "not_assessed"
    ERROR = "error"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class CoverageState(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class DriftKind(str, Enum):
    NEW = "new"
    RESOLVED = "resolved"
    REGRESSED = "regressed"
    IMPROVED = "improved"
    UNCHANGED = "unchanged"
    COVERAGE_CHANGED = "coverage_changed"
    NOT_COMPARABLE = "not_comparable"


class ControlObservation(StrictModel):
    """A caller-supplied, evidence-bound technical control result."""

    tenant_id: StableId
    control_id: StableId
    control_version: NonEmpty
    status: AssessmentStatus
    severity: RiskLevel
    summary: NonEmpty
    explanation_code: StableId
    owner_team: StableId
    assessed_at: UTCDateTime
    expected_population: int = Field(ge=1, le=10_000_000)
    observed_population: int = Field(ge=0, le=10_000_000)
    collector_state: CoverageState
    evidence_ids: tuple[StableId, ...] = ()
    evidence_hashes: tuple[str, ...] = ()

    @field_validator("evidence_hashes")
    @classmethod
    def _validate_hashes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for digest in value:
            require_digest(digest)
        return value

    @model_validator(mode="after")
    def _validate_evidence_and_population(self) -> ControlObservation:
        if self.observed_population > self.expected_population:
            raise ValueError("observed_population must not exceed expected_population")
        if len(self.evidence_ids) != len(self.evidence_hashes):
            raise ValueError("evidence_ids and evidence_hashes must have matching lengths")
        if self.observed_population > 0 and not self.evidence_ids:
            raise ValueError("observed_population requires evidence references")
        if self.status == AssessmentStatus.NOT_ASSESSED and self.evidence_ids:
            raise ValueError("not_assessed observations must not bind evidence references")
        return self


class EvidenceCoverage(StrictModel):
    control_id: StableId
    control_version: NonEmpty
    state: CoverageState
    expected_population: int = Field(ge=1)
    observed_population: int = Field(ge=0)
    coverage_percent: int = Field(ge=0, le=100)
    evidence_hashes: tuple[str, ...]
    reason: NonEmpty


class ControlAssessment(StrictModel):
    control_id: StableId
    control_version: NonEmpty
    status: AssessmentStatus
    severity: RiskLevel
    summary: NonEmpty
    explanation_code: StableId
    owner_team: StableId
    assessed_at: UTCDateTime
    evidence_ids: tuple[StableId, ...]
    evidence_hashes: tuple[str, ...]
    coverage: EvidenceCoverage


class DriftRecord(StrictModel):
    control_id: StableId
    control_version: NonEmpty
    kind: DriftKind
    previous_status: AssessmentStatus | None = None
    current_status: AssessmentStatus
    previous_coverage_percent: int | None = Field(default=None, ge=0, le=100)
    current_coverage_percent: int = Field(ge=0, le=100)
    reason: NonEmpty


class RiskRollup(StrictModel):
    policy_id: Literal["ccm.assessor.risk/v1"] = "ccm.assessor.risk/v1"
    raw_points: int = Field(ge=0)
    maximum_points: int = Field(ge=0)
    risk_percent: int = Field(ge=0, le=100)
    highest_contributing_severity: RiskLevel | None = None
    contributing_control_count: int = Field(ge=0)
    error_control_count: int = Field(ge=0)
    status_counts: dict[AssessmentStatus, int]
    coverage_counts: dict[CoverageState, int]


class AssessmentManifest(StrictModel):
    """A sealed, reproducible aggregation over supplied current observations."""

    schema_version: Literal["ccm.assessor/v1"] = SCHEMA_VERSION
    manifest_id: StableId | None = None
    tenant_id: StableId
    assessment_profile_id: StableId
    assessment_profile_version: NonEmpty
    assessed_at: UTCDateTime
    controls: tuple[ControlAssessment, ...]
    coverage: tuple[EvidenceCoverage, ...]
    drift: tuple[DriftRecord, ...]
    risk_rollup: RiskRollup
    input_hashes: tuple[str, ...]
    manifest_hash: str | None = None

    @field_validator("input_hashes", "manifest_hash")
    @classmethod
    def _validate_hashes(
        cls,
        value: tuple[str, ...] | str | None,
    ) -> tuple[str, ...] | str | None:
        if value is None:
            return None
        if isinstance(value, str):
            return require_digest(value)
        for digest in value:
            require_digest(digest)
        return value

    @model_validator(mode="after")
    def _validate_alignment(self) -> AssessmentManifest:
        keys = tuple((item.control_id, item.control_version) for item in self.controls)
        if len(keys) != len(set(keys)):
            raise ValueError("manifest controls must be unique by ID and version")
        if tuple((item.control_id, item.control_version) for item in self.coverage) != keys:
            raise ValueError("manifest coverage must align with ordered controls")
        return self

    def hash_projection(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json",
            exclude={"manifest_hash", "manifest_id"},
            exclude_none=True,
        )

    def computed_hash(self) -> str:
        return sha256_digest(self.hash_projection())

    def seal(self) -> AssessmentManifest:
        content_hash = self.computed_hash()
        return self.model_copy(
            update={
                "manifest_hash": content_hash,
                "manifest_id": stable_identifier("assessment", {"manifest_hash": content_hash}),
            }
        )

    def verify_integrity(self) -> bool:
        return (
            self.manifest_hash is not None
            and self.manifest_id is not None
            and self.manifest_hash == self.computed_hash()
            and self.manifest_id
            == stable_identifier("assessment", {"manifest_hash": self.manifest_hash})
        )


class AssessmentRequest(StrictModel):
    schema_version: Literal["ccm.assessor/v1"] = SCHEMA_VERSION
    tenant_id: StableId
    assessment_profile_id: StableId
    assessment_profile_version: NonEmpty
    assessed_at: UTCDateTime
    observations: tuple[ControlObservation, ...]
    baseline_manifest: AssessmentManifest | None = None

    @model_validator(mode="after")
    def _validate_request(self) -> AssessmentRequest:
        if not self.observations:
            raise ValueError("assessment requests require at least one observation")
        keys = tuple((item.control_id, item.control_version) for item in self.observations)
        if len(keys) != len(set(keys)):
            raise ValueError("observations must be unique by control ID and version")
        if any(item.tenant_id != self.tenant_id for item in self.observations):
            raise ValueError("all observations must belong to the request tenant")
        if self.baseline_manifest and self.baseline_manifest.tenant_id != self.tenant_id:
            raise ValueError("baseline manifest must belong to the request tenant")
        return self
