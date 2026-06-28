# Contributing

Thanks for your interest in this project. It is a research / proof-of-concept tool,
so contributions are welcome but reviewed with that scope in mind.

## Getting started

```bash
git clone https://github.com/harishmurkal/suci-supi-tool.git
cd suci-supi-tool
go build ./cmd/suci-tool
go test ./...
```

Requires Go 1.24+.

## Before opening a pull request

- Run `gofmt -w .` so the code is formatted.
- Run `go vet ./...` and `go test ./...`; both must pass.
- Add or update unit tests for any behavior change.
- Keep documentation (`README.md`, `ARCHITECTURE.md`, `docs/`) in sync with code changes.
- Do not commit key material, real subscriber data, or environment-specific paths.

## Adding a new protection scheme

The typical flow (see `ARCHITECTURE.md` for details):

1. Add the scheme constant in `pkg/suci/types.go`.
2. Implement encryption in `pkg/suci/encryptor.go`.
3. Implement decryption in `pkg/suci/decryptor.go` and `pkg/suciutil/parser.go`.
4. Update parsing/validation in `pkg/suciutil/parser.go`.
5. Add comprehensive tests.

## License

By contributing, you agree that your contributions will be licensed under the
Apache License 2.0, consistent with the rest of the project.
