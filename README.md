# SUCI-SUPI Conversion Tool

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20998143.svg)](https://doi.org/10.5281/zenodo.20998143)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

A comprehensive Go implementation for 5G SUCI (Subscription Concealed Identifier) to SUPI (Subscription Permanent Identifier) conversion and vice versa, following 3GPP TS 33.501 and TS 33.703 specifications.

> **Research / proof-of-concept tool.** This project exists to evaluate and benchmark classical, post-quantum, and hybrid SUCI protection schemes. It is **not** a production component and is **not** part of any 3GPP-certified product. Profiles A–C and NULL-SCHEME follow 3GPP definitions; **Profiles E, F, and G, and the ML-KEM-1024 (NIST Level 5) option for Profiles C–F, are tool extensions and are not 3GPP-standardized.** Do not use it to protect real subscriber identities.

## Features

### Current Support
- ✅ **SUPI to SUCI Concealment** (encryption - UE operation)
    - NULL-SCHEME (Scheme ID 0) - Plaintext MSIN encoded as 3GPP TBCD
    - ECIES Profile A (Scheme ID 1) - Curve25519/X25519
    - ECIES Profile B (Scheme ID 2) - NIST P-256/secp256r1
    - **PQC Profile C (Scheme ID 3) - ML-KEM-768** (Post-Quantum Cryptography)
    - **Hybrid Profile D (Scheme ID 4) - ML-KEM-768 + X25519** (Hybrid PQC + classical)
        - **Profile D-add17**: Nonce-based freshness + profile/variant binding in KDF (Solution #17)
        - **Profile D-add19**: AES-256-GCM AEAD with AAD binding (Solution #19)
    - **Profile E (Scheme ID 5) - Nested Hybrid ML-KEM-768 + X25519** (two independent encryption layers)
    - **Profile F (Scheme ID 6) - Wrapper Hybrid ML-KEM-768 + X25519** (ECIES unchanged, PQ wraps ephemeral key)
    - **Profile G (Scheme ID 7) - Symmetric SUCI** (two-layer symmetric concealment with subscriber key ID + Kmaster)
- **Optional ML-KEM-1024 (NIST Level 5)** for schemes C–F is a **tool extension** (not 3GPP-default): use `--security-level 5` on `conceal`, `keygen`, and `loadgen`; on `deconceal` omit the flag to infer from the HN ML-KEM private key, or pass `5` to assert the parameter set. Default remains **3** (ML-KEM-768).
- ✅ **SUCI to SUPI De-concealment** (decryption - HN operation)
    - NULL-SCHEME (Scheme ID 0) - Plaintext MSIN encoded as 3GPP TBCD
    - ECIES Profile A (Scheme ID 1) - Curve25519/X25519
    - ECIES Profile B (Scheme ID 2) - NIST P-256/secp256r1
    - **PQC Profile C (Scheme ID 3) - ML-KEM-768** (Post-Quantum Cryptography)
    - **Hybrid Profile D (Scheme ID 4) - ML-KEM-768 + X25519** (Hybrid PQC + classical)
        - Auto-detects Profile D variants (baseline, add17, add19) — no flag needed
    - **Profile E (Scheme ID 5) - Nested Hybrid ML-KEM-768 + X25519**
    - **Profile F (Scheme ID 6) - Wrapper Hybrid ML-KEM-768 + X25519**
    - **Profile G (Scheme ID 7) - Symmetric SUCI**
- ✅ **HN Key Generation** - Generate key pairs for any Key ID (0-255)
    - Profile A keys (Curve25519/X25519)
    - Profile B keys (P-256/secp256r1)
    - **Profile C keys (ML-KEM-768)** - Post-Quantum keys
    - **Profile D keys (Hybrid ML-KEM-768 + X25519)** - Hybrid composite keys
    - **Profile E keys (Nested Hybrid ML-KEM-768 + X25519)** - Nested composite keys
    - **Profile F keys (Wrapper Hybrid ML-KEM-768 + X25519)** - Wrapper composite keys
    - **Profile G key bundles (Symmetric)** - `hn-key-<id>-profile-g.json` + subscriber mapping template
    - Batch generation support
    - **Multiple output formats: PEM, DER, Hex, JWK**
- ✅ **Key Inspection** - Analyze key files in any format
    - Auto-detect PEM, DER, Hex, JWK formats
    - Public key derivation from private keys
    - JSON output for scripting/automation
- ✅ **Comprehensive Error Handling** with detailed error codes
- ✅ **3GPP TBCD MSIN Encoding** - low nibble first with `0xF` high-nibble padding for odd digits
- ✅ **Flexible Key Management** - Easy key store integration
  
Key storage and keystore helpers:

- File-based key layout: Profile D/E/F supports a two-file layout (`hn-key-<id>-profile-{d|e|f}-mlkem.pem` and `hn-key-<id>-profile-{d|e|f}-x25519.pem`) and a single-file combined PEM fallback (`hn-key-<id>-profile-{d|e|f}.pem`) for convenience.
- `EnvKeyStore` support: on CI or test environments you can export `HN_KEY_<id>_PROFILE_{D|E|F}_MLKEM` and `HN_KEY_<id>_PROFILE_{D|E|F}_X25519` to provide Profile D/E/F keys via environment variables.
- `FileKeyStore` will automatically detect paired Profile D/E/F files and present them as a single logical key entry in the `inspect` and `deconceal` tooling.

Example: provide Profile D components via environment variables (bash):
```
export HN_KEY_1_PROFILE_D_MLKEM="$(cat keys/hn-key-1-profile-d-mlkem.pem)"
export HN_KEY_1_PROFILE_D_X25519="$(cat keys/hn-key-1-profile-d-x25519.pem)"
# then run the tool with --use-env or let it auto-detect
./suci-supi-tool deconceal --suci "<suci>" --use-env
```

Short note on single-file Profile D:
For convenience you may also store both private components in a single PEM file named `hn-key-<id>-profile-d.pem` that contains two PEM blocks (ML-KEM private block followed by X25519 private block). The `FileKeyStore` will parse this combined file as a Profile D composite key.
- ✅ **IMSI and NAI Support** - Type 0 and Type 1 identifiers
- ✅ **Round-Trip Verified** - Conceal → Deconceal produces original SUPI

### Post-Quantum Cryptography (PQC) Support

Profile C implements **3GPP TS 33.703** post-quantum SUCI protection:

| Component | Algorithm | Details |
|-----------|-----------|---------|
| **KEM** | ML-KEM-768 | NIST FIPS 203, 128-bit security level |
| **KDF** | ANSI-X9.63-KDF (SHA3-256) | SharedInfo1 = KEM ciphertext |
| **MAC** | KMAC256 | 64-bit tag, CustomString = "SUCI-MAC" |
| **Encryption** | AES-256-CTR | Zero ICB, 32-byte key |

**Key Sizes:**
- Public Key: 1184 bytes
- Private Key: 2400 bytes
- KEM Ciphertext: 1088 bytes
- Shared Secret: 32 bytes

### Planned Features
- 🔄 **Hardware Security Module (HSM)** integration
- 🔄 **REST API** for service deployment

## Quick Start

```bash
# Build the tool
go build -o suci-supi-tool ./cmd/suci-tool

# Or build for all platforms
.\scripts\build.ps1          # Windows
./scripts/build.sh            # Linux/macOS

# Generate keys
./suci-supi-tool keygen --start-id 1

# Conceal SUPI → SUCI (Profile A)
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme a --key-id 1

# Deconceal SUCI → SUPI
./suci-supi-tool deconceal --suci "suci-0-123-450-0000-0-0-21436587f9"

# Run tests
go test -v ./...
```

See [docs/examples.md](docs/examples.md) for more usage examples.

## Architecture

The tool follows Go standard project layout:

```
suci-supi-tool/
├── cmd/
│   └── suci-tool/
│       └── main.go            # CLI entry point (conceal, deconceal, keygen, inspect, loadgen)
├── pkg/
│   ├── suci/
│   │   ├── types.go          # Error codes, constants, types
│   │   ├── parser.go         # SUCI string parsing & validation
│   │   ├── encryptor.go      # ECIES encryption (Profile A/B)
│   │   ├── decryptor.go      # ECIES decryption (Profile A/B)
│   │   ├── converter.go      # Main conversion orchestration
│   │   ├── loadgen.go        # Load generator (p50/p95/p99 + throughput)
│   │   ├── benchmark_test.go # Benchmarks (end-to-end / decrypt-only / parse-only)
│   │   ├── parser_test.go    # Unit tests (parser)
│   │   └── encryptor_test.go # Unit tests (encryptor)
│   ├── keys/
│   │   ├── keystore.go       # Key management & retrieval
│   │   ├── keygen.go         # HN key pair generation (multi-format)
│   │   └── inspect.go        # Key file inspection & analysis
│   ├── slog/
│   │   └── slog.go           # Structured logging
│   └── suciutil/
│       └── parser.go         # SUPI parsing utilities
├── scripts/
│   ├── build.ps1             # Cross-platform build (Windows)
│   ├── build.sh              # Cross-platform build (Linux/macOS)
│   ├── test.ps1              # Unit test runner (Windows)
│   ├── test.sh               # Unit test runner (Linux/macOS)
│   ├── regression_tests.ps1  # Functional regression tests (Windows)
│   ├── regression_tests.sh   # Functional regression tests (Linux/macOS)
│   ├── details_collector.ps1 # Comprehensive command/log collection (Windows)
│   └── details_collector.sh  # Comprehensive command/log collection (Linux/macOS)
├── docs/
│   ├── testing.md            # Testing & verification guide
│   ├── examples.md           # Practical usage examples
│   ├── profiles/             # Profile-specific documentation
│   └── README.md             # Documentation index
├── go.mod                    # Go module definition
├── Makefile                  # Build automation
├── README.md                 # This file
└── ARCHITECTURE.md           # Architecture details
```

## SUCI Format

SUCI (Subscription Concealed Identifier) is a structured identifier with well-defined components, not a single opaque blob:

```
SUCI = | SUPI Type | Home Network Identifier | Routing Indicator | Protection Scheme ID | HN Public Key ID | Scheme Output |
```

**String Representation:**
```
suci-<type>-<mcc>-<mnc>-<routingInd>-<schemeId>-<keyId>-<schemeOutput>
```

### Components

#### SUPI Type (0–7)
Identifies what type of permanent identifier is being concealed:

| Value | Meaning | Home Network Identifier Format |
|-------|---------|-------------------------------|
| 0 | IMSI (International Mobile Subscriber Identity) | MCC + MNC |
| 1 | Network Specific Identifier (NSI) | Realm (5G HND) |
| 2 | Global Line Identifier (GLI) | Realm (5G HND) |
| 3 | Global Cable Identifier (GCI) | Realm (5G HND) |
| 4–7 | Spare for future use | — |

#### Home Network Identifier
- **For IMSI (Type 0)**: MCC (3 digits) + MNC (2-3 digits)
- **For NSI/GLI/GCI**: Realm name (DNS-style identifier)

Purpose: Enables correct routing and public key selection without revealing subscriber identity.

#### Routing Indicator (1–4 digits)
- Routes SUCI toward the correct UDM/SIDF instance
- Used for load balancing or regional distribution
- Does **not** reveal actual subscriber identity

#### Protection Scheme ID (0–15)

| Value | Meaning | Algorithm |
|-------|---------|-----------|
| 0x0 | NULL-SCHEME | No protection (plaintext MSIN in 3GPP TBCD) |
| 0x1 | Profile A | ECIES with Curve25519/X25519 |
| 0x2 | Profile B | ECIES with NIST P-256/secp256r1 |
| 0x3 | Profile C | ML-KEM-768 (Pure PQC) |
| 0x4 | Profile D | Hybrid ML-KEM-768 + X25519 (variants: baseline, add17, add19) |
| 0x5 | Profile E | Nested Hybrid ML-KEM-768 + X25519 |
| 0x6 | Profile F | Wrapper Hybrid ML-KEM-768 + X25519 |
| 0x7 | Profile G | Symmetric SUCI (two-layer) |
| 0x8–0xB | Reserved | Future standardized schemes |
| 0xC–0xF | Proprietary | Operator-specific (PQC, Hybrid, etc.) |

> **Note**: NULL-SCHEME (0x0) should not be used in production networks.

#### Home Network Public Key ID (0–255)
- Selects which HN public key was used for encryption
- Supports key rotation without breaking UEs in the field
- UE includes this ID so network can select corresponding private key

### Scheme Output Structure

The format depends on the Protection Scheme ID:

MSIN is encoded as 3GPP TBCD before concealment. For encrypted profiles, the AES-CTR ciphertext length equals the TBCD payload length (`ceil(msin_digits/2)` bytes). For NULL-SCHEME, scheme output carries this TBCD payload directly.

#### ECIES Profiles (0x1 / 0x2)
```
| ECC Ephemeral Public Key | Ciphertext | MAC Tag |
```

| Component | Profile A | Profile B | Description |
|-----------|-----------|-----------|-------------|
| Ephemeral Public Key | 32 bytes (64 hex) | 33 bytes (66 hex) | Fresh per SUCI, prevents linkability |
| Ciphertext | Variable | Variable | Encrypted MSIN (subscriber identity) |
| MAC Tag | 8 bytes (16 hex) | 8 bytes (16 hex) | Integrity protection (HMAC-SHA-256 truncated) |

**Minimum lengths:**
- Profile A: 40 bytes (32 + 0 + 8)
- Profile B: 41 bytes (33 + 0 + 8)

#### PQC Profile C (0x3) - ML-KEM-768
```
| KEM Ciphertext | Encrypted MSIN | KMAC Tag |
```

| Component | Size | Description |
|-----------|------|-------------|
| KEM Ciphertext | 1088 bytes | ML-KEM-768 encapsulation |
| Ciphertext | Variable | AES-256-CTR encrypted MSIN |
| KMAC Tag | 8 bytes | KMAC256 integrity tag |

**Minimum length:** 1096 bytes (1088 + 0 + 8)

#### Hybrid Profile D (0x4) - ML-KEM-768 + X25519

Profile D supports three wire-format variants sharing the same Scheme ID 4:

**Baseline:**
```
| KEM Ciphertext (1088) | Eph X25519 PK (32) | Encrypted MSIN | KMAC Tag (8) |
```

**add17 (Solution #17) — nonce + KDF binding:**
```
| KEM Ciphertext (1088) | Eph X25519 PK (32) | 0x01 | Nonce (16) | Encrypted MSIN | KMAC Tag (8) |
```

**add19 (Solution #19) — AES-256-GCM AEAD:**
```
| KEM Ciphertext (1088) | Eph X25519 PK (32) | 0x02 | Encrypted MSIN | GCM Tag (16) |
```

#### Profile E (0x5) - Nested Hybrid ML-KEM-768 + X25519
```
| Eph X25519 PK (32) | Enc KEM CT (1088) | Enc MSIN (variable) | MAC_ECC (8) | MAC_PQ (8) |
```

| Component | Size | Description |
|-----------|------|-------------|
| Eph X25519 PK | 32 bytes | Ephemeral X25519 public key |
| Enc KEM CT | 1088 bytes | AES-256-CTR encrypted ML-KEM-768 ciphertext |
| Enc MSIN | Variable | AES-256-CTR encrypted MSIN (PQ layer) |
| MAC_ECC | 8 bytes | KMAC256 tag over encrypted KEM ciphertext |
| MAC_PQ | 8 bytes | KMAC256 tag over encrypted MSIN |

**Minimum length:** 1136 bytes (32 + 1088 + 0 + 8 + 8)

#### Profile F (0x6) - Wrapper Hybrid ML-KEM-768 + X25519
```
| KEM CT (1088) | Enc Eph PK (32) | Enc MSIN (variable) | MAC_ECIES (8) | MAC_PQ (8) |
```

| Component | Size | Description |
|-----------|------|-------------|
| KEM CT | 1088 bytes | ML-KEM-768 ciphertext |
| Enc Eph PK | 32 bytes | AES-256-CTR encrypted ephemeral X25519 public key |
| Enc MSIN | Variable | AES-128-CTR encrypted MSIN (standard ECIES) |
| MAC_ECIES | 8 bytes | HMAC-SHA-256 tag (truncated, ECIES layer) |
| MAC_PQ | 8 bytes | KMAC256 tag over encrypted ephemeral key |

**Minimum length:** 1136 bytes (1088 + 32 + 0 + 8 + 8)

#### Profile G (0x7) - Symmetric SUCI (Tool Extension)
```
| R | KeyCipherText (5) | MACkey | CipherText | MACmsin |
```

Profile G scheme output fields:
- `R`: random value (`8` bytes at level 3, `16` bytes at level 5)
- `KeyCipherText`: encrypted subscriber key ID (`5` bytes)
- `MACkey`: MAC over `R || KeyCipherText` (`16` bytes at level 3, `32` bytes at level 5)
- `CipherText`: encrypted MSIN (TBCD payload, variable length)
- `MACmsin`: MAC over `R || CipherText` (`16` bytes at level 3, `32` bytes at level 5)

Key material for Profile G is file-based only:
- `hn-key-<id>-profile-g.json` contains HN symmetric key and level.
- `hn-key-<id>-profile-g-subscribers.json` contains `SubscriberKeyID -> Kmaster` mappings.

Concealment/de-concealment notes:
- `conceal --scheme g` requires `--subscriber-key-id` (10 hex chars).
- HN de-concealment tries fixed window fallback `{current_window, previous_window}`.

| Variant | KDF SharedInfo1 | Symmetric | MAC | Extra |
|---------|-----------------|-----------|-----|-------|
| Baseline | `kemCT \|\| ephPK` | AES-256-CTR | KMAC256 (8 B) | — |
| add17 | `kemCT \|\| ephPK \|\| nonce \|\| 0x04 \|\| 0x01` | AES-256-CTR | KMAC256 (8 B) | 16 B random nonce |
| add19 | `kemCT \|\| ephPK \|\| 0x04 \|\| 0x02` | AES-256-GCM | GCM tag (16 B) | 12 B nonce from KDF |

De-concealment auto-detects the variant from the wire format — no CLI flag needed.

#### Proprietary Schemes (0xC–0xF)
For proprietary protection schemes (including PQC and Hybrid variants):

> **Maximum Size**: The scheme output shall be a maximum of **3000 octets plus the size of the input** (encrypted MSIN).

This allows operators to implement:
- Custom PQC algorithms
- Hybrid schemes (classical + PQC)
- Future cryptographic approaches

### What Gets Encrypted

| SUPI Type | Encrypted in Scheme Output | Not Encrypted (for routing) |
|-----------|---------------------------|----------------------------|
| IMSI | MSIN (subscriber-specific part) | MCC + MNC |
| NSI | Username part | Realm |
| GLI | Username part | Realm |
| GCI | Username part | Realm |

> The Home Network Identifier is **intentionally not encrypted** — the network needs it for routing, but cannot learn the actual subscriber identity from it.

### SUCI Length Considerations

SUCI is **variable length** due to:

| Component | Size | Notes |
|-----------|------|-------|
| SUPI Type | Few bits | Fixed |
| Protection Scheme ID | 4 bits | Fixed |
| Public Key ID | 1 byte | Fixed |
| Routing Indicator | 1–4 digits | Variable |
| Ephemeral Key / KEM CT | 32–1088 bytes | Depends on scheme |
| Ciphertext | Variable | Depends on MSIN length |
| MAC/KMAC Tag | 8 bytes | Fixed |

**Trade-off**: SUCI is significantly longer than SUPI/IMSI — this is the cost of privacy and security.

### Example
```
suci-0-123-45-012-2-101-0253fd4d2ccb9603c12dcfd179c2e71e...
      │  │  │  │  │  │   └── Scheme Output (ephemeral key + ciphertext + MAC)
      │  │  │  │  │  └────── Key ID: 101
      │  │  │  │  └───────── Scheme: Profile B (ECIES P-256)
      │  │  │  └──────────── Routing Indicator: 012
      │  │  └─────────────── MNC: 45
      │  └────────────────── MCC: 123
      └───────────────────── Type: IMSI-based
```

## Conversion Flow

```
SUCI Input
    ↓
1. Parse & Validate SUCI String
    ↓
2. Validate Scheme ID (0-7)
    ↓
3. Validate Key ID (if scheme ≠ 0)
    ↓
4. Validate Scheme-Key Match
    ↓
5. Validate Scheme Output Length
    ↓
6. Decrypt MSIN (ECIES for 1/2, PQC/Hybrid for 3/4/5/6, symmetric for 7)
    ↓
7. Decode MSIN (3GPP TBCD)
    ↓
8. Construct SUPI
    ↓
SUPI Output
```

## Protection Schemes

| Scheme ID | Name | Algorithm | Key Type |
|-----------|------|-----------|----------|
| 0 | NULL-SCHEME | No encryption (TBCD payload) | None |
| 1 | Profile A | ECIES | Curve25519/X25519 |
| 2 | Profile B | ECIES | NIST P-256 |
| 3 | Profile C | ML-KEM-768 | PQC (Post-Quantum) |
| 4 | Profile D | Hybrid ML-KEM-768 + X25519 | ML-KEM + X25519 |
| 5 | Profile E | Nested Hybrid ML-KEM-768 + X25519 | ML-KEM + X25519 |
| 6 | Profile F | Wrapper Hybrid ML-KEM-768 + X25519 | ML-KEM + X25519 |
| 7 | Profile G | Symmetric SUCI (two-layer) | Symmetric (subscriber key ID + Kmaster) |

## Error Codes

### Parse Errors (0x1xx)
- `0x101` - E_PARSE_SUCI: Invalid SUCI format

### Cryptographic Errors (0x2xx)
- `0x201` - E_CURVE_MISMATCH: Key curve doesn't match scheme
- `0x202` - E_TAG_MISMATCH: MAC verification failed
- `0x203` - E_INVALID_EC_KEY: Invalid elliptic curve key format
- `0x204` - E_SCHEME_OUTPUT_TOO_SHORT: Insufficient data length
- `0x205` - E_MSIN_ENCODING: MSIN decoding failed
- `0x206` - E_INVALID_IMSI_LENGTH: IMSI length out of range (5-15)
- `0x207` - E_INVALID_PQC_KEY: Invalid PQC key format
- `0x208` - E_KEM_ENCAPSULATE_FAILED: ML-KEM encapsulation failed
- `0x209` - E_KEM_DECAPSULATE_FAILED: ML-KEM decapsulation failed
- `0x20A` - E_KMAC_FAILED: KMAC256 computation failed

### Validation Errors (0x3xx)
- `0x301` - E_INVALID_SCHEME_ID: Unsupported scheme
- `0x302` - E_INVALID_TYPE: Invalid identity type
- `0x303` - E_INVALID_KEY_ID: Key ID out of range
- `0x304` - E_UNKNOWN_KEY_ID: Key not found in store
- `0x305` - E_INVALID_SUBSCRIBER_KEY_ID: Invalid subscriber key ID (expected 10 hex chars / 5 bytes)

## Usage

### Build
```bash
# Requires Go 1.24+ (https://go.dev/dl/)
cd suci-supi-tool
go build -o suci-supi-tool ./cmd/suci-tool

# Format sources before committing
gofmt -w .
```

### Generate HN Keys
```bash
# Generate a single key pair (Profile A and B) for Key ID 1
./suci-supi-tool keygen --start-id 1

# Generate Profile C (PQC/ML-KEM-768) keys
./suci-supi-tool keygen --start-id 1 --profile c

# Generate Profile C keys with ML-KEM-1024 (security level 5, tool extension)
./suci-supi-tool keygen --start-id 1 --profile c --security-level 5

# Generate Profile D (Hybrid ML-KEM-768 + X25519) keys
./suci-supi-tool keygen --start-id 1 --profile d

# Generate Profile E (Nested Hybrid) keys for Key ID 1
./suci-supi-tool keygen --start-id 1 --profile e

# Generate Profile F (Wrapper Hybrid) keys for Key ID 1
./suci-supi-tool keygen --start-id 1 --profile f

# Generate all profile keys (A, B, C, D, E, F) for Key ID 1
./suci-supi-tool keygen --start-id 1 --profile all

# Generate keys for all 256 possible Key IDs (0-255)
./suci-supi-tool keygen --range 0-255 --output-dir ./keys --verbose

# Generate only Profile A keys for specific IDs
./suci-supi-tool keygen --range 0,5,10,15 --profile a

# Generate keys with public keys saved
./suci-supi-tool keygen --range 0-10 --save-public --output-dir ./my-keys

# Generate keys in different output formats
./suci-supi-tool keygen --start-id 1 --format pem   # PEM format (default)
./suci-supi-tool keygen --start-id 1 --format der   # Binary DER format
./suci-supi-tool keygen --start-id 1 --format hex   # Raw hex (3GPP test vectors)
./suci-supi-tool keygen --start-id 1 --format jwk   # JSON Web Key format
```

### Inspect Keys
```bash
# Inspect a key file (auto-detects format)
./suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-a.pem

# Show public key derivation
./suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-b.pem --show-public

# Output as JSON
./suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-a.pem --output json

# Inspect different formats (all auto-detected)
./suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-a.hex
./suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-a.jwk
```

### Run SUPI to SUCI Concealment
```bash
# Conceal SUPI to SUCI using Profile A (auto-select or generate key)
./suci-supi-tool conceal --supi "imsi-123450123456789"

# Conceal with specific scheme and key ID
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme b --key-id 5

# Conceal with NULL scheme (no encryption, plaintext TBCD MSIN)
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme null

# Conceal with PQC Profile C (ML-KEM-768, post-quantum)
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme c --key-id 1

# Conceal with PQC Profile C using ML-KEM-1024 (security level 5, tool extension)
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme c --key-id 1 --security-level 5

# Conceal with Hybrid Profile D (ML-KEM-768 + X25519) — baseline
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme d --key-id 1

# Conceal with Profile D add17 (nonce + KDF binding)
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme d --key-id 1 --add-17

# Conceal with Profile D add19 (AES-256-GCM AEAD)
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme d --key-id 1 --add-19

# Conceal with Nested Hybrid Profile E
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme e --key-id 1

# Conceal with Wrapper Hybrid Profile F
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme f --key-id 1

# Conceal with custom routing indicator
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme a --routing-ind 1234
```

### Run SUCI to SUPI De-concealment
```bash
# Example with NULL-SCHEME (Scheme 0)
./suci-supi-tool deconceal --suci "suci-0-123-45-012-0-0-1032547698"

# Example with ECIES Profile B (Scheme 2)
./suci-supi-tool deconceal --suci "suci-0-123-45-012-2-101-0253fd4d..." --key-file keys/hn-private-key-101.pem

# Example with PQC Profile C (Scheme 3)
./suci-supi-tool deconceal --suci "suci-0-123-45-012-3-1-<scheme-output>" --key-file keys/hn-key-1-profile-c.pem

# Example with ML-KEM-1024 keys (optional flag; omit to infer from the HN private key)
./suci-supi-tool deconceal --suci "suci-0-123-45-012-3-1-<scheme-output>" --key-file keys/hn-key-1-profile-c.pem --security-level 5

# Example with Hybrid Profile D (Scheme 4)
./suci-supi-tool deconceal --suci "suci-0-123-45-012-4-1-<scheme-output>" --key-dir ./keys

# Example with Nested Hybrid Profile E (Scheme 5)
./suci-supi-tool deconceal --suci "suci-0-123-45-012-5-1-<scheme-output>" --key-dir ./keys

# Example with Wrapper Hybrid Profile F (Scheme 6)
./suci-supi-tool deconceal --suci "suci-0-123-45-012-6-1-<scheme-output>" --key-dir ./keys

# Using environment variable for key
export HN_PRIVATE_KEY="-----BEGIN EC PRIVATE KEY-----..."
./suci-supi-tool deconceal --suci "suci-0-123-45-012-1-5-a1b2c3d4..."
```

### Round-Trip Example
```bash
# Generate a key
./suci-supi-tool keygen --start-id 1

# Conceal SUPI to SUCI
SUCI=$(./suci-supi-tool conceal --supi "imsi-123450123456789" --key-id 1)
echo "SUCI: $SUCI"

# De-conceal SUCI back to SUPI
./suci-supi-tool deconceal --suci "$SUCI"
# Output: imsi-123450123456789
```

## Runtime Debugging

Enable debug output for troubleshooting with either:

- Environment variable: `SUCI_DEBUG=1` or `DEBUG=1`
- Global CLI flag: `--debug` or `-d` (consumed before subcommand parsing)

When enabled the tool prints internal debug data (ephemeral public keys, ciphertexts, derived keys, MACs and decrypted MSIN bytes). Debugging output is off by default.

### Expected Output
```
SUPI: imsi-123450123456789
```

Or in case of error:
```
Error: E_TAG_MISMATCH (0x202) - MAC verification failed
```

## Performance / Research

This repo includes two complementary approaches:

1. **Go benchmarks** (mean latency + allocs/op) via `go test -bench ...`
2. **Load generator** (tail latency p50/p95/p99 + throughput) via `loadgen`

### Load generator (p50/p95/p99)

The `loadgen` command runs conversions in-process and avoids file I/O by generating the key material and input SUCI in-memory.

```powershell
# End-to-end SUCI→SUPI (includes parsing + crypto + SUPI formatting)
go run ./cmd/suci-tool loadgen --scheme a --mode end-to-end --n 100000 --concurrency 8 --warmup 1000

# Crypto-only deconceal (decrypt + MSIN decode; excludes SUCI regex parsing)
go run ./cmd/suci-tool loadgen --scheme a --mode decrypt-only --n 100000 --concurrency 8 --warmup 1000

# Parse-only (regex parse/validation only)
go run ./cmd/suci-tool loadgen --scheme a --mode parse-only --n 100000 --concurrency 8 --warmup 1000

# JSON output for scripting
go run ./cmd/suci-tool loadgen --scheme b --mode end-to-end --n 50000 --concurrency 16 --output json

# Run Profile F loadgen with ML-KEM-1024 (security level 5)
go run ./cmd/suci-tool loadgen --scheme f --mode end-to-end --n 50000 --concurrency 16 --security-level 5
```

### Details collector scripts

The repo includes `scripts/details_collector.sh` and `scripts/details_collector.ps1` to run a broad command set and log the output to a timestamped file. Both scripts now support ML-KEM `security-level 5` for profiles C-F.

```bash
# Linux/macOS
./scripts/details_collector.sh --supi imsi-123450123456789 --security-level 5
```

```powershell
# Windows
.\scripts\details_collector.ps1 -Supi imsi-123450123456789 -SecurityLevel 5
```

Supported inputs:

- SUPI via `--supi` / `-Supi` or `SUPI`
- loadgen overrides via `--loadgen-*` / `-Loadgen*` or `LOADGEN_*`
- ML-KEM level via `--security-level` / `-SecurityLevel`, `SECURITY_LEVEL`, or `DETAILS_SECURITY_LEVEL`

### Benchmarks (mean + allocations)

See [TESTING_GUIDE.md](docs/testing.md) for benchmark and profiling recipes (`-benchmem`, `-cpuprofile`, `-memprofile`) and how to interpret the results.

## Key Management

The tool supports multiple ways to provide Home Network private keys:

1. **PEM Files**: Standard PKCS#8 or SEC1 format
2. **Environment Variables**: For containerized deployments
3. **Custom Key Store**: Implement the `KeyStore` interface for HSM/Vault integration

### Key Store Interface
```go
type KeyStore interface {
    GetPrivateKey(keyID uint8, scheme SchemeID) (crypto.PrivateKey, error)
}
```

## ECIES Cryptogram Structure

### Profile A (Curve25519)
```
[Ephemeral Public Key: 32 bytes] || [Ciphertext: variable] || [MAC: 8 bytes]
Minimum length: 40 bytes
```

### Profile B (secp256r1)
```
[Compressed Public Key: 33 bytes] || [Ciphertext: variable] || [MAC: 8 bytes]
Minimum length: 41 bytes
```

### ECIES Process
1. **ECDH**: Compute shared secret from HN private key and ephemeral public key
2. **KDF**: Derive encryption and MAC keys using ANSI-X9.63-KDF with SHA-256
3. **MAC Verify**: Validate first 8 bytes of HMAC-SHA-256
4. **Decrypt**: AES-128-CTR decryption using derived encryption key

## Testing

### Unit Tests
```bash
# Run all unit tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./pkg/suci/...

# Or use the test script (cleans environment)
.\scripts\test.ps1            # Windows
```

### Regression Tests
```bash
# Run all functional tests
.\scripts\regression_tests.ps1

# Run specific category
.\scripts\regression_tests.ps1 -Category sanity      # Basic tests
.\scripts\regression_tests.ps1 -Category functional  # Feature tests
.\scripts\regression_tests.ps1 -Category cli         # CLI tests
.\scripts\regression_tests.ps1 -Category error       # Error handling tests
```

**Test Coverage:**
- ✅ 23 unit tests passing
- ✅ 17 regression tests passing (100%)
- Categories: Sanity, Functional, CLI, Error Handling

### Build
```bash
# Build for all platforms
.\scripts\build.ps1           # Windows
./scripts/build.sh             # Linux/macOS

# Outputs binaries in ./build/ directory:
# - Windows (amd64)
# - Linux (amd64)
# - macOS (Intel & Apple Silicon)
```

See [docs/testing.md](docs/testing.md) for comprehensive testing documentation.

## Contributing

When adding new features (e.g., PQC support):

1. Add new scheme constants in `types.go`
2. Implement encryption logic in `encryptor.go`
3. Implement decryption logic in `decryptor.go`
4. Update validation in `parser.go`
5. Add comprehensive tests

## How to Cite

If you use this tool or its benchmarking results, please cite the archived release.
This software is permanently archived on Zenodo with a DOI, and GitHub renders a
"Cite this repository" button from [CITATION.cff](CITATION.cff).

**DOI:** [10.5281/zenodo.20998143](https://doi.org/10.5281/zenodo.20998143)

Suggested IEEE-style reference:

> H. Muralidhara, *SUCI-SUPI Conversion Tool: Classical, Post-Quantum, and Hybrid SUCI Protection for 5G*, version 2.3.0. Zenodo, 2026. doi: 10.5281/zenodo.20998143.

BibTeX:

```bibtex
@software{muralidhara_suci_supi_tool_2026,
  author    = {Muralidhara, Harish},
  title     = {{SUCI-SUPI Conversion Tool: Classical, Post-Quantum, and Hybrid SUCI Protection for 5G}},
  version   = {2.3.0},
  publisher = {Zenodo},
  year      = {2026},
  doi       = {10.5281/zenodo.20998143},
  url       = {https://doi.org/10.5281/zenodo.20998143}
}
```

The DOI above resolves to version 2.3.0 specifically. To always reference the latest
version, use the "Cite all versions" (concept) DOI shown on the
[Zenodo record](https://doi.org/10.5281/zenodo.20998143).

## References

- **3GPP TS 33.501**: Security architecture and procedures for 5G System
- **3GPP TS 33.703**: Study on post-quantum cryptography for 5G (PQC SUCI protection)
- **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
- **ECIES**: Elliptic Curve Integrated Encryption Scheme
- **RFC 7748**: Elliptic Curves for Security (Curve25519)
- **FIPS 186-4**: Digital Signature Standard (secp256r1)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.

Copyright 2026 Nokia.

---

**Version**: 2.3.0  
**Last Updated**: March 2026
