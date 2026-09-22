# Domain glossary

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
