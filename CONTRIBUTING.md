# Contributing

Contributions must preserve deterministic, local-first behavior. New input fields require a compatibility decision, generated schema refresh, fixture update, tests for success and failure paths, and documentation of whether the field affects the sealed semantic projection.

Do not add cloud SDKs, credentials, live network calls, wall-clock behavior, database clients, background schedulers, raw evidence payloads, copied framework text, or claims of certification. All timestamps and evidence references must be caller supplied.

Before opening a pull request, run `make test` and `make package-check`. Protected `main` requires passing CI and CodeQL plus one review.
