# Testing Guide

This document covers all testing procedures for the SUCI-SUPI Tool.

## Quick Start

```bash
# Run all unit tests
go test -v ./...

# Run via scripts (from project root)
.\scripts\test.ps1          # Windows
./scripts/test.sh            # Linux/macOS
```

## Unit Tests

The Go test suite covers parsing, encryption, decryption, and key management across all supported profiles (NULL-SCHEME, A, B, C, D, E, F).

### Test Files

| File | Tests | Coverage |
|------|-------|----------|
| `pkg/suci/parser_test.go` | `TestParseSUCI_ValidIMSI`, `TestParseSUCI_InvalidFormat`, `TestDecodeMSIN_TBCD`, `TestEncodeMSIN_TBCD_specExample`, `TestConstructSUPI_IMSI`, `TestParseCryptogram_ProfileA`, `TestParseCryptogram_TooShort`, `TestErrorCode_String`, `TestSchemeID_*` | SUCI/SUPI parsing, TBCD MSIN, cryptogram smoke tests |
| `pkg/suci/encryptor_test.go` | `TestConstructSUPI_IMSI`, `TestConstructSUPI_InvalidIMSILength`, `TestParseCryptogram_ProfileA`, `TestParseCryptogram_TooShort`, `TestErrorCode_String` | Cryptogram handling, SUPI construction, error codes |
| `pkg/suci/loadgen_test.go` | `TestRunLoadGen_ProfileD_EndToEnd`, `TestRunLoadGen_ProfileD_DecryptOnly` | Load generation for Profile D end-to-end and decrypt-only |
| `pkg/suci/benchmark_test.go` | Benchmarks via `-bench=.` | Encryption/decryption performance with memory metrics |
| `pkg/keys/keystore_test.go` | `TestEnvKeyStore_ProfileD`, `TestFileKeyStore_SingleFile_ProfileD` | Key storage and retrieval for Profile D |

### Running Specific Tests

```bash
# Run parser tests only
go test -v -run TestParseSUCI ./pkg/suci

# Run encryptor tests only
go test -v -run TestConstructSUPI ./pkg/suci

# Run keystore tests only
go test -v -run TestEnvKeyStore ./pkg/keys
```

## Benchmarks

```bash
# Run all benchmarks with memory allocation stats
go test -bench=. -benchmem ./...

# Run benchmarks for suci package only
go test -bench=. -benchmem ./pkg/suci
```

## Test Coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Or use the Makefile target
make test-coverage
```

## Regression Tests

The regression test suite validates the compiled binary across multiple categories. Build the binary first, then run the regression suite.

### Prerequisites

```bash
# Build the binary
.\scripts\build.ps1          # Windows
./scripts/build.sh            # Linux/macOS
```

### Running Regression Tests

```bash
# Run all regression tests (from project root)
.\scripts\regression_tests.ps1                      # Windows
./scripts/regression_tests.sh                        # Linux/macOS

# Run specific category
.\scripts\regression_tests.ps1 -Category sanity      # Windows
./scripts/regression_tests.sh sanity                  # Linux/macOS
```

### Categories

| Category | Description |
|----------|-------------|
| `sanity` | Version/help commands, NULL-SCHEME basic deconceal |
| `cli` | Help/version flags, invalid commands, missing required arguments |
| `functional` | NULL-SCHEME with various IMSI formats (valid, 15-digit MSIN, MCC variants, 3-digit MNC) |
| `error` | Invalid SUCI format, missing SUCI prefix, malformed input, specific error codes |
| `keygen` | Key generation for all profiles (A, B, C, D), ranges, public key export |
| `conceal` | Conceal/deconceal round-trips for NULL-SCHEME, Profiles A, B, C, D (including D variants add17/add19) |
| `unit` | Go package unit tests (pkg/keys, pkg/suci) |
| `all` | All categories (default) |

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make test` | Run all unit tests with verbose output |
| `make test-coverage` | Generate HTML coverage report |
| `make test-bench` | Run benchmarks with memory allocation stats |

## Test Verification Checklist

For a complete verification of the tool, run through this sequence:

1. **Build**: `make build-all` or `.\scripts\build.ps1`
2. **Unit tests**: `go test -v ./...`
3. **Benchmarks**: `go test -bench=. -benchmem ./pkg/suci`
4. **Regression tests**: `.\scripts\regression_tests.ps1` or `./scripts/regression_tests.sh`
5. **Manual spot check**:
   ```bash
   # NULL-SCHEME round-trip
   ./build/suci-supi-tool-linux-amd64 conceal --supi "imsi-123450123456789" --scheme null
   ./build/suci-supi-tool-linux-amd64 deconceal --suci "suci-0-123-450-0000-0-0-21436587f9"

   # Profile A round-trip (generate keys first)
   ./build/suci-supi-tool-linux-amd64 keygen --start-id 0 --output-dir ./test-keys
   ./build/suci-supi-tool-linux-amd64 conceal --supi "imsi-310260987654321" --scheme a --key-dir ./test-keys
   # Copy the output SUCI and use it for deconceal:
   ./build/suci-supi-tool-linux-amd64 deconceal --suci "<output-suci>" --key-dir ./test-keys
   ```
