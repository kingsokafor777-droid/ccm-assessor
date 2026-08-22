"""Local-only strict JSON validation and deterministic assessment command line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .evaluator import assess
from .models import AssessmentManifest, AssessmentRequest


def _read_json(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"could not read JSON from {path}") from exc


def _emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def _validate(path: Path) -> int:
    try:
        manifest = AssessmentManifest.model_validate_json(_read_json(path))
        if not manifest.verify_integrity():
            raise ValueError("manifest hash or deterministic ID does not verify")
    except (ValidationError, ValueError) as exc:
        _emit({"valid": False, "error": str(exc)})
        return 2
    _emit(
        {
            "valid": True,
            "manifest_id": manifest.manifest_id,
            "manifest_hash": manifest.manifest_hash,
        }
    )
    return 0


def _assess(request_path: Path, output_path: Path | None) -> int:
    try:
        manifest = assess(AssessmentRequest.model_validate_json(_read_json(request_path)))
    except (ValidationError, ValueError) as exc:
        _emit({"valid": False, "error": str(exc)})
        return 2
    rendered = (
        json.dumps(manifest.model_dump(mode="json", exclude_none=True), indent=2, sort_keys=True)
        + "\n"
    )
    if output_path:
        output_path.write_text(rendered, encoding="utf-8")
    _emit(
        {
            "valid": True,
            "manifest_id": manifest.manifest_id,
            "manifest_hash": manifest.manifest_hash,
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ccm-assessor")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="validate a sealed assessment manifest")
    validate.add_argument("manifest", type=Path)
    run = commands.add_parser("assess", help="build a sealed manifest from a strict JSON request")
    run.add_argument("request", type=Path)
    run.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "validate":
        return _validate(args.manifest)
    return _assess(args.request, args.output)
