# ccm-assessor design contract

## Purpose and boundary

`ccm-assessor` turns supplied, sealed technical-control results and evidence metadata into a deterministic assessment manifest. It is an orchestration and interpretation layer: it does not collect cloud data, execute control rules, open database connections, call an AI model, make network requests, or determine whether an organization is certified or compliant.

NIST defines information-security continuous monitoring as maintaining awareness of security, vulnerabilities, and threats at a frequency sufficient to support risk-based decisions [1]. NIST’s ISCM assessment guidance also distinguishes program effectiveness and completeness from a bare control result [2]. Those principles inform this repository’s explicit coverage and evidence boundaries; they do not make an output a NIST assessment, audit opinion, certification, or attestation.

## Inputs and deterministic output

The evaluator accepts only caller-supplied JSON-native contracts. Every assessment request contains a tenant identifier, a profile/version identifier, a fixed `assessed_at` timestamp, sealed control observations, and optional baseline manifest data. The process is pure: the same valid request produces byte-identical canonical output and the same SHA-256 manifest hash.

| Input | Requirement | Effect on output |
|---|---|---|
| Control observation | One control ID/version, result status, configured severity, evidence references/hashes, observed versus expected population, and collector state. | Produces a control assessment and an evidence-coverage record. |
| Evidence reference | Content-addressed `sha256:<hex>` reference only; no raw payloads or secret material. | Bound into the manifest and used for coverage identity. |
| Baseline manifest | Same tenant and compatible assessment profile. | Enables deterministic drift comparison only; never changes the current result. |
| Policy version | Explicit `ccm.assessor/v1` and risk policy ID. | Binds rollup semantics to the manifest. |

## Coverage policy

Coverage is a first-class result, not a hidden confidence score. The expected population must be greater than or equal to the observed population. A fully observed population with valid evidence is `complete`; a shortfall is `partial`; explicitly unavailable source data is `unavailable`; and an evaluator/collector failure is `error`. A `not_assessed` technical result remains `not_assessed` regardless of coverage. The library does not convert missing or unavailable evidence into a pass.

## Drift policy

Drift comparison is control-version aware. A control is comparable only when its ID, version, tenant, and assessment profile match between current and baseline manifests. Comparable controls receive one closed drift classification: `new`, `resolved`, `regressed`, `improved`, `unchanged`, or `coverage_changed`. Incompatible control versions or profiles receive `not_comparable` and are counted separately. No baseline can suppress, rewrite, or downgrade a current assessment.

## Risk rollup policy

The v1 rollup is a transparent prioritization signal, not an enterprise-risk calculation. Only `fail`, `partial`, and `error` control results contribute exposure points. Severity weights are fixed: critical 100, high 75, medium 50, low 25, and informational 0. A partial result contributes half its weight; an error contributes the full configured weight and is reported separately; a pass and a not-assessed result contribute zero points. The manifest reports raw points, maximum reachable points, a bounded integer percentage, highest contributing severity, count by result status, and coverage-state counts. Consumers must consider coverage gaps alongside the score.

## Manifest integrity and compatibility

The sealed assessment manifest contains the request projection, sorted control assessments, coverage records, drift records, rollup, policy/version IDs, and input hashes. Its `manifest_hash` excludes itself and is computed with the `ccm-jcs/v1` canonical JSON profile and SHA-256. v1 changes that alter result, coverage, drift, or rollup semantics require a new profile or policy version. New optional display fields may be introduced only when excluded from the v1 semantic projection.

## Non-negotiable rules

| Rule | Enforcement |
|---|---|
| Missing, partial, unavailable, or error coverage must remain visible. | Closed coverage enum; strict model validation; manifest counts. |
| No raw evidence payload, token, password, private key, or connection string enters a contract. | Recursive sensitive-key rejection. |
| Current assessments remain independent of a baseline. | Baseline is used only after current assessment construction. |
| Control profile/version incompatibility cannot be silently compared. | `not_comparable` drift classification. |
| Rollups cannot claim compliance, attestation, or certification. | Scope language in contracts and documentation; no framework-pass field. |
| Evaluation cannot use clock, network, cloud, database, or AI state. | Caller-supplied timestamp and pure function boundary. |

## References

[1] [NIST glossary — Information Security Continuous Monitoring](https://csrc.nist.gov/glossary/term/information_security_continuous_monitoring)

[2] [NIST SP 800-137A — Assessing Information Security Continuous Monitoring Programs](https://csrc.nist.gov/pubs/sp/800/137/a/final)
