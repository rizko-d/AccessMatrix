# Engine contract and limitations

## Scope and public seams

Defensive authorization regression over explicitly supplied endpoints and test identities. No discovery, payload generation, account creation, mutation methods, or exploit automation. Standard library only; module `github.com/rizko-d/AccessMatrix`.

```go
func Load(r io.Reader) (Config, error)
func Validate(c Config) error
func Run(ctx context.Context, c Config, lookup func(string) (string, bool)) (Report, error)
```

Configuration types: `Config`, `Identity`, `Probe`, `Test`, `Expectation`, `Assertion`. Report types: `Report`, `Result`, `AssertionResult`. Configuration version is integer `1`; report version is string `"0.1"`. Their exported fields and JSON tags are the contract in `config.go` and `runner.go`.

`Load` validates one strict JSON document without environment access or requests. `Validate` is pure. `Run` revalidates, takes a deep snapshot, resolves all credentials, verifies authenticated identities, and executes the matrix sequentially. All state belongs to that invocation. Tests exercise these three seams with synthetic credentials and `httptest`.

## Glossary

- **Identity:** named caller; either anonymous or one environment-backed authentication header.
- **Credential:** nonempty printable ASCII environment value supplied by `lookup`, never a literal config token. `prefix` is public authentication scheme text, not secret storage.
- **Identity check / probe:** configured same-origin GET (typically `/me`) requiring status 200 and all assertions, including an equality proving identity.
- **Protected resource proof:** all configured GET assertions match and at least one is exact equality. The author must choose an equality that uniquely identifies protected data, not a generic success envelope.
- **Assertion:** JSON Pointer plus exactly one `equals` JSON value or `exists` Boolean. `null` exists when present; absent is distinct. Empty pointer selects the complete document. RFC 6901 `~0` and `~1`, object keys, and zero-based array indices are supported. Array indices cannot have leading zeroes. Numbers compare exact decimal values, never floating-point approximations.
- **Expectation:** explicit `allow` or `deny` plus a nonempty set of acceptable statuses for each selected identity in a test. Omitted expectations do not execute a request or produce a result row. Allow statuses are 200–299; deny statuses are 400–499 excluding 429.
- **Positive control:** explicit identity expected to be allowed. It executes first for each test regardless of identity listing order. Every dependent row requires its PASS.
- **Matrix:** tests in configuration order, each with explicitly selected identities in configuration order. Execution order may differ to run the control first; result order does not.
- **PASS:** expected allow status with matching proof, or expected denial status with no matching resource assertions. HEAD confirms status only.
- **FAIL:** allow receives 401/403/404 with a valid response, or denied GET returns the matching protected resource even under a denial status.
- **INCONCLUSIVE:** redirects, 429, 5xx, unexpected 2xx/4xx, or allow assertion mismatch. Denied HEAD 2xx is always inconclusive.
- **ERROR:** unsafe/incomplete observation or blocked prerequisite; never evidence of correct denial.

## Fail-closed behavior

Identity verification failure prevents all matrix traffic and produces ERROR rows for the entire matrix. A failed positive control retains its actual verdict and produces ERROR dependent rows for that test; other tests may still execute.

Redirects, 429, and 5xx take precedence and remain INCONCLUSIVE regardless of body content. Otherwise network/TLS/timeouts, response read failures, oversized bodies, malformed/empty JSON, duplicate keys, invalid Unicode, or excessive JSON complexity produce ERROR. Malformed denial bodies cannot PASS. Successful GET evaluation requires JSON regardless of content type; HTML/text/empty denial pages are deliberately not considered evidence. HEAD never parses or asserts a response body and its successful allow reason is `status_verified`.

Setup failures return an empty report and a static error. Observation failures are verdict rows with nil function error; callers must inspect verdicts. Cancellation returns a non-nil context error and may include only previously completed tests. Such a partial report is never a successful completed run. No new requests start after observed cancellation. Caller-owned configuration must not be concurrently mutated during validation/snapshot; after snapshot, lookup callbacks and other runs cannot change this run's state.

## Security boundaries and limits

- Absolute HTTP(S) origin only: no path (including trailing slash), query, fragment, or userinfo. Plain HTTP accepts only a literal loopback address or `localhost`; HTTPS uses normal system trust and hostname verification.
- Root-relative paths only; no authority/absolute URL, fragments, backslashes, dot segments, encoded control characters, or recursive encoding bypasses. Paths and queries are bounded ASCII; Unicode paths and unusual literal-percent encodings are outside v0.1. JSON values may contain valid Unicode.
- Authentication headers are `Authorization` or syntactically valid `X-*` API-key headers only. No Host, Cookie, Proxy-Authorization, framing headers, arbitrary custom headers, or implicit environment reads. Anonymous carries neither credential fields nor an identity check.
- Fresh transport per run (direct `RoundTrip`, without the redirect-processing client), no proxy, no cookie jar, no redirects, no connection reuse, no compression, and no retries. Tokens go only to the configured origin and only on their identity's requests.
- Timeout: zero selects 5000 ms; explicit maximum 120000 ms. Body limit: zero selects 1048576 bytes; maximum 16777216 bytes. Header limit: 65536 bytes. Every request has a context deadline covering network and body reading.
- Config input: 4 MiB. At most 128 identities, 1024 tests, 128 assertions per probe/test, 128-character names, 8192-byte paths, 4096-byte pointers, and 8192-byte credentials. JSON nesting is bounded to 128 levels, number tokens to 4096 bytes, and each document to 65536 JSON values (including containers). Unknown/miscased fields, trailing JSON, duplicate decoded keys, null schema fields (except equality values), and lone UTF-16 surrogates are rejected.
- Reports contain fixed reason codes, status, Boolean assertion outcomes, and configured identifiers/pointers only. No response values, URLs, queries, tokens, or remote error strings. Any configured report metadata containing a resolved raw credential is replaced as a whole with `[REDACTED]`, including partial/error reports. Constant schema/verdict/reason strings are not reflected input.

## Limitations

Passing a finite matrix is not proof that an API is secure. Assertions, identities, and expected statuses are supplied by the operator and may be insufficient or wrong. Equality to generic/null data is technically valid but weak evidence. GET/HEAD are not guaranteed side-effect-free by a remote server. HEAD cannot prove protected-data disclosure. Partial assertion matches on denied GET requests remain INCONCLUSIVE instead of PASS. Response timing, sensitive fields not covered by assertions, cache behavior, and server-side forwarding are not analyzed.

DNS and operating-system trust configuration are trusted; this is not an SSRF sandbox or DNS-pinning system. Explicit HTTPS targets may resolve to private addresses. Loopback HTTP is unencrypted and localhost resolution is trusted. Tokens remain in Go process memory and are not securely zeroed. Metadata redaction matches raw resolved values, not arbitrary encodings or fragments. Use public IDs and pointers rather than embedding credentials. Server-side requests, logging, and processing are outside the client's control. No login flows, cookies, refresh tokens, mTLS configuration, custom CA configuration, arbitrary methods, or browser sessions are supported.
