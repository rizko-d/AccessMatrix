# AccessMatrix — API Authorization Testing CLI

[![CI](https://github.com/rizko-d/AccessMatrix/actions/workflows/ci.yml/badge.svg)](https://github.com/rizko-d/AccessMatrix/actions/workflows/ci.yml)
[![Go 1.24+](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Verify who can access what.** AccessMatrix replays explicitly configured API requests with supplied test identities and checks your authorization expectations. It helps test object-level authorization (BOLA/IDOR), function-level restrictions, and anonymous access without guessing which permissions your application should have.

A `200 OK` is not automatically a vulnerability. A `403` is not automatically safe.
AccessMatrix checks resource assertions, verifies identities, and runs positive controls before trusting a result.

- Go CLI and reusable Go package; no third-party Go dependencies.
- Explicit identity/request matrix with environment-based credentials.
- Read-only GET/HEAD requests, same-origin restrictions, verified TLS, no redirects.
- PASS / FAIL / INCONCLUSIVE / ERROR with assertion-level evidence.
- Terminal and JSON reports without raw response bodies or credentials.
- Reproducible local API in deliberately vulnerable and fixed modes.

[Project page](https://rizko-d.github.io/AccessMatrix/) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [Domain glossary](CONTEXT.md)

## Build

Requires Go 1.24 or newer.

```sh
git clone https://github.com/rizko-d/AccessMatrix.git
cd AccessMatrix
go build -trimpath -o bin/accessmatrix ./cmd/accessmatrix
./bin/accessmatrix version
```

Or install the CLI directly:

```sh
go install github.com/rizko-d/AccessMatrix/cmd/accessmatrix@latest
```

## Local demo

The fixture API holds only synthetic invoices. It binds to a literal loopback address;
`-vulnerable` deliberately removes the invoice-ownership check. The admin restriction remains enforced in both modes.

**Terminal 1:**

```sh
./bin/accessmatrix demo -vulnerable
```

**Terminal 2:**

```sh
export ALICE_TOKEN=demo-alice-token
export BOB_TOKEN=demo-bob-token
export ADMIN_TOKEN=demo-admin-token

./bin/accessmatrix validate -config examples/demo.json
./bin/accessmatrix run -config examples/demo.json
```

The demo defines 12 request/identity combinations. Expected results:

| Mode | PASS | FAIL | Exit code |
|---|---:|---:|---:|
| Vulnerable | 10 | 2 | 1 |
| Fixed | 12 | 0 | 0 |

The deliberate failures are Alice reading Bob's invoice and Bob reading Alice's invoice.
Stop Terminal 1 with Ctrl-C and start the fixed API:

```sh
./bin/accessmatrix demo
```

Run the same configuration again. No expectations need to change.

To export JSON, choose a **new** output path:

```sh
mkdir -p reports
./bin/accessmatrix run -config examples/demo.json -format json -output reports/fixed.json
```

Report files are created with owner-only permissions and existing files are never overwritten.
Without `-output`, the report goes to stdout. The CLI does not automatically load `.env` files.

## Configuration

[`examples/demo.json`](examples/demo.json) is a complete working configuration.
For a different API, change the origin, identity probes, resource requests and explicit expectations.
Only put environment-variable names in credential fields—not literal credentials.

```json
{
  "version": 1,
  "base_url": "https://api.example.test",
  "identities": [
    {
      "name": "alice",
      "header": "Authorization",
      "prefix": "Bearer ",
      "token_env": "ALICE_TOKEN",
      "check": {
        "path": "/me",
        "assertions": [{"pointer": "/id", "equals": "alice"}]
      }
    },
    {"name": "anonymous", "anonymous": true}
  ],
  "tests": [
    {
      "id": "alice-invoice",
      "method": "GET",
      "path": "/invoices/alice-1",
      "control": "alice",
      "assertions": [
        {"pointer": "/id", "equals": "alice-1"},
        {"pointer": "/owner", "equals": "alice"}
      ],
      "expectations": {
        "alice": {"access": "allow", "statuses": [200]},
        "anonymous": {"access": "deny", "statuses": [401, 403, 404]}
      }
    }
  ]
}
```

### Policy fields

| Field | Meaning |
|---|---|
| `version` | Configuration schema version; currently `1`. |
| `base_url` | One HTTP(S) origin, without a path, query, fragment or user info. HTTPS required except loopback demo targets. |
| `timeout_ms` | Per-request timeout; defaults to 5000, maximum 120000. |
| `max_body_bytes` | Response limit; defaults to 1048576, maximum 16777216. |
| `identities` | Named authenticated or anonymous profiles. |
| `header` / `prefix` / `token_env` | Credential header, optional prefix and environment variable. Use `Authorization` or an `X-*` API-key header. |
| `check` | GET identity probe; requires status 200 and assertions proving the subject. Required for authenticated profiles. |
| `tests[].path` | Root-relative request path on the configured origin. |
| `tests[].control` | Identity explicitly expected to have access; checked before other identities. |
| `tests[].assertions` | Resource assertions. GET needs at least one equality assertion; HEAD accepts none. |
| `tests[].expectations` | Explicit identity-to-policy entries. Omitted identities are not tested for that request. |
| `access` | `allow` or `deny`. |
| `statuses` | Explicit acceptable HTTP status codes for that expectation. |

Assertions use JSON Pointer, not JSONPath: `/id`, `/items/0/id`, `~1` for a literal slash, and `~0` for a literal tilde.
Each assertion supplies exactly one of `equals` or `exists`:

```json
{"pointer": "/id", "equals": "alice-1"}
```

```json
{"pointer": "/metadata", "exists": true}
```

An existence check alone does not prove resource identity. Choose equality assertions that actually identify the protected resource; matching a generic `"success": true` field is weak evidence.

`validate` checks structure and policy without reading credentials or making requests. `run` resolves credentials before network activity, verifies identities, then executes positive controls and matrix checks sequentially.

## Verdicts and exit codes

| Verdict | Meaning |
|---|---|
| `PASS` | The configured expectation is satisfied. |
| `FAIL` | Evidence establishes a mismatch: protected data is returned to a denied identity, or an allowed identity receives a recognized denial. |
| `INCONCLUSIVE` | A response cannot establish the authorization outcome. |
| `ERROR` | Execution, prerequisites, or response processing failed. |

For GET denial tests, matching all protected-resource assertions is evidence of a failure—even when the server returns a denial status. Partial assertion matches on denied GET requests remain INCONCLUSIVE, even with an expected denial status. Unexpected success responses without matching resource evidence remain inconclusive.
Rate limits, server failures and redirects remain INCONCLUSIVE even if their bodies match resource assertions. Other GET responses must contain valid JSON; empty, malformed or oversized denial bodies produce ERROR, not PASS. HEAD cannot prove body disclosure and has narrower evidence than GET.
Identity-check failures prevent authorization testing. A failed positive control blocks dependent checks instead of producing misleading passes.

| Exit | Meaning |
|---:|---|
| `0` | All executed checks passed, or validation succeeded. |
| `1` | At least one policy failure; no errors or inconclusive results. |
| `2` | Invalid configuration, execution/reporting error, or any ERROR/INCONCLUSIVE result. Takes precedence over `1`. |

A passing suite means only the configured checks passed—not that the API has no authorization vulnerabilities.

## Evidence and request controls

- Reports include test name, identity, expected access, observed status, verdict, reason and assertion match flags. No raw request/response bodies or credential values.
- Identity sessions share neither cookies nor cached credentials. No cookie jar or environment proxy is used.
- Redirects are never followed. TLS verification cannot be disabled.
- Requests are sequential with per-request deadlines and bounded response bodies. No automatic retry, crawling, brute forcing or resource-ID enumeration.
- Only GET and HEAD are supported in v0.1. Some APIs implement state changes through GET; review the supplied endpoints before running.
- Configurations and reports may still contain sensitive business labels. Treat them as assessment artifacts and keep real credentials out of paths, assertion values and configuration files.

## Development

```sh
gofmt -w .
go vet ./...
go test -race -count=1 -cover ./...
go build -trimpath -o bin/accessmatrix ./cmd/accessmatrix
```

Tests use local fixture servers and synthetic credentials. CI tests the minimum Go version and a newer Go version.
The exported package exposes `Load`, `Validate`, and `Run`; the CLI handles environment lookup, report serialization and exit codes.

## Limits / next releases

v0.1 does not import OpenAPI/Postman, refresh OAuth tokens, maintain cookie sessions, test mutations, discover tenant relationships, normalize dynamic fields, generate HTML findings reports or automatically rate severity.

See [ROADMAP.md](ROADMAP.md) for planned assessment workflows, CI regression features and import assistance. [Engine contract and limitations](docs/engine.md) documents exact validation limits, report semantics, JSON-only response handling, ASCII URL/pointer restrictions, trusted DNS and raw-value redaction limits.

## License

[MIT](LICENSE).
