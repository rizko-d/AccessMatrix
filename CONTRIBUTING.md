# Contributing

Use Go 1.24 or newer. This project deliberately has no third-party Go dependencies.

```sh
gofmt -w .
go vet ./...
go test -race -count=1 -cover ./...
go build -trimpath -o bin/accessmatrix ./cmd/accessmatrix
```

Add regression tests at the exported `Load`, `Validate`, `Run` interfaces or CLI
command seam. Use `httptest` and synthetic credentials. Do not hit live APIs in tests.
Test behavior rather than private implementation. Include positive controls and
negative cases; a status code alone is not evidence of protected-resource access.

Never commit tokens, response bodies from real services, customer endpoints or
local reports. Keep report output redacted and terminal-safe. Do not weaken origin,
TLS, redirect, response-size or credential-isolation controls to make a test pass.
Keep new features in scope with ROADMAP.md. Prefer a small concrete function to a
new abstraction with one implementation.
