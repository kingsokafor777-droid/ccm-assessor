# ccm-assessor

`ccm-assessor` is a local-first Python package for deterministic technical-assessment orchestration. It accepts caller-supplied control observations and evidence references, derives visible coverage, compares a compatible baseline, applies a transparent fixed risk policy, and seals the resulting manifest.

It is part of the Continuous Control Monitoring & Evidence Engineering program. It produces **technical assessment data**, not a certification, attestation, audit opinion, or statement that an organization conforms to any framework.

## What it owns

| Capability | v0.1 behavior |
|---|---|
| Assessment input | Strict, versioned, tenant-scoped control observations with evidence IDs and SHA-256 references. |
| Coverage | Explicit `complete`, `partial`, `unavailable`, and `error` states; missing evidence never becomes a pass. |
| Drift | Control-version and profile-aware `new`, `resolved`, `regressed`, `improved`, `unchanged`, `coverage_changed`, and `not_comparable` classifications. |
| Risk | Fixed disclosed weights and raw/maximum/percentage rollup; a prioritization signal, not an enterprise-risk calculation. |
| Integrity | Canonical JSON, SHA-256 input binding, sealed manifest hash, and deterministic manifest ID. |
| CLI | File-only strict JSON `assess` and `validate` operations. |

## Deliberate boundaries

This package has no cloud SDK, live-provider request, database client, scheduler, credentials, network client, wall-clock call, raw evidence payload, AI model, deletion action, or compliance/certification conclusion. The caller supplies all timestamps and input facts.

For the assessment and monitoring context, see [`docs/design.md`](docs/design.md). The sealed examples under `fixtures/` are synthetic release artifacts, not customer evidence.

## Quick start

```bash
python3 -m pip install ccm-assessor
ccm-assessor assess fixtures/safe-request.json --output manifest.json
ccm-assessor validate manifest.json
```

## Local quality gate

```bash
PYTHONPATH=src python3 scripts/build_fixtures.py
PYTHONPATH=src python3 scripts/export_schemas.py
PYTHONPATH=src ruff check .
PYTHONPATH=src ruff format --check .
PYTHONPATH=src mypy src
PYTHONPATH=src pytest
PYTHONPATH=src make package-check
```

## Security reporting

Please follow [SECURITY.md](SECURITY.md). Do not open public issues containing real evidence payloads, cloud identifiers, credentials, or sensitive assessment context.

## License

Apache-2.0. See [LICENSE](LICENSE).
