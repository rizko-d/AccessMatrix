# Roadmap

The v0.1 release is intentionally small: explicit requests, supplied test identities,
and authorization expectations. No discovered endpoint executes automatically.

## v0.1 — Read-only authorization regression CLI

- JSON configuration, supplied environment credentials, anonymous identity.
- Verified identities and explicit positive controls.
- GET/HEAD execution with bounded responses, timeouts and origin restrictions.
- Status and JSON assertions; PASS / FAIL / INCONCLUSIVE / ERROR.
- Terminal and JSON reports; local vulnerable/fixed fixture API.
- Automated tests and CI. No runtime dependencies outside Go's standard library.

## v0.2 — Assessment workflows (not implemented)

- Explicit owner/tenant resource fixtures and reusable request templates.
- Isolated cookie sessions.
- Opt-in mutation tests with setup, state verification and cleanup.
- Response normalization and static HTML reports.

Gate: mutation outcomes are verified by state, not status alone; cleanup failures remain visible.

## v0.3 — CI regression workflows (not implemented)

- JUnit export, baseline comparison, tags and coverage-change reporting.
- Bounded concurrency and request-rate limits.

Gate: skipped, failed, errored or inconclusive required checks cannot become a green build.
Basic CI and conservative exit codes are included already in v0.1.

## v0.4 — Import assistance (not implemented)

- OpenAPI and Postman import to unreviewed test skeletons.
- Operation coverage and missing-expectation reports.

Gate: imported requests need reviewed scope, credentials and expectations before execution.

## Explicit non-goals

Endpoint/ID brute forcing, token guessing or theft, JWT forging, exploit chaining,
automatic severity ratings, AI verdicts, hosted dashboards and plugin frameworks.
