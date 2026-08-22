.PHONY: fixtures schemas quality test package-check

fixtures:
	PYTHONPATH=src python3 scripts/build_fixtures.py

schemas:
	PYTHONPATH=src python3 scripts/export_schemas.py

quality:
	PYTHONPATH=src ruff check .
	PYTHONPATH=src ruff format --check .
	PYTHONPATH=src mypy src
	PYTHONPATH=src pytest

test: fixtures schemas quality

package-check:
	python3 -m pip wheel --no-deps --wheel-dir dist .
	python3 scripts/check_package.py
