"""Validate the wheel contains the intended ccm-assessor package contents."""

from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    wheels = sorted((ROOT / "dist").glob("ccm_assessor-*.whl"))
    if len(wheels) != 1:
        raise SystemExit("expected exactly one ccm_assessor wheel in dist/")
    with ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
    required = {
        "ccm_assessor/__init__.py",
        "ccm_assessor/canonical.py",
        "ccm_assessor/evaluator.py",
    }
    missing = sorted(required - names)
    if missing:
        raise SystemExit(f"wheel missing expected files: {', '.join(missing)}")
    forbidden = sorted(
        name for name in names if name.startswith(("tests/", "fixtures/", ".github/"))
    )
    if forbidden:
        raise SystemExit(f"wheel contains non-package artifacts: {', '.join(forbidden)}")
    print(f"VALID wheel={wheels[0].name} files={len(names)}")


if __name__ == "__main__":
    main()
