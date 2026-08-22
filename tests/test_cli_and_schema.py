from __future__ import annotations

import json
from pathlib import Path

from ccm_assessor.cli import main

ROOT = Path(__file__).resolve().parents[1]


def test_cli_validates_fixture_and_assesses_to_output(tmp_path, capsys) -> None:
    manifest = ROOT / "fixtures" / "safe-manifest.json"
    assert main(["validate", str(manifest)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    output = tmp_path / "manifest.json"
    request_path = ROOT / "fixtures" / "safe-request.json"
    assert main(["assess", str(request_path), "--output", str(output)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    assert json.loads(output.read_text(encoding="utf-8"))["manifest_hash"]


def test_cli_rejects_malformed_or_tampered_json(tmp_path, capsys) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    assert main(["assess", str(malformed)]) == 2
    assert json.loads(capsys.readouterr().out)["valid"] is False
    tampered = tmp_path / "tampered.json"
    payload = json.loads((ROOT / "fixtures" / "safe-manifest.json").read_text(encoding="utf-8"))
    payload["assessed_at"] = "2026-08-23T00:00:00Z"
    tampered.write_text(json.dumps(payload), encoding="utf-8")
    assert main(["validate", str(tampered)]) == 2
    assert json.loads(capsys.readouterr().out)["valid"] is False


def test_exported_schema_inventory_is_complete() -> None:
    names = {path.name for path in (ROOT / "schemas" / "v1").glob("*.json")}
    assert names == {
        "assessment-manifest.schema.json",
        "assessment-request.schema.json",
        "control-observation.schema.json",
        "drift-record.schema.json",
        "evidence-coverage.schema.json",
        "risk-rollup.schema.json",
    }
