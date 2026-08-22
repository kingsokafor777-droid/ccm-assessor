"""Export JSON Schema artifacts for ccm-assessor public contracts."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from ccm_assessor.models import (
    AssessmentManifest,
    AssessmentRequest,
    ControlObservation,
    DriftRecord,
    EvidenceCoverage,
    RiskRollup,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas" / "v1"
MODELS: dict[str, type[BaseModel]] = {
    "assessment-manifest.schema.json": AssessmentManifest,
    "assessment-request.schema.json": AssessmentRequest,
    "control-observation.schema.json": ControlObservation,
    "drift-record.schema.json": DriftRecord,
    "evidence-coverage.schema.json": EvidenceCoverage,
    "risk-rollup.schema.json": RiskRollup,
}


def main() -> None:
    SCHEMAS.mkdir(parents=True, exist_ok=True)
    for filename, model in MODELS.items():
        rendered = json.dumps(
            model.model_json_schema(), indent=2, ensure_ascii=False, sort_keys=True
        )
        (SCHEMAS / filename).write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
