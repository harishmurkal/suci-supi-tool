# SUCI-SUPI Tool Architecture

## System Overview

The SUCI-SUPI tool is designed with modularity, extensibility, and security in mind. The architecture follows the single responsibility principle and supports **bidirectional conversion** between SUPI and SUCI formats:

- **Concealment (SUPI → SUCI)**: Typically performed at the UE (User Equipment) to protect subscriber identity
- **De-concealment (SUCI → SUPI)**: Typically performed at the HN (Home Network) to recover the original identity

The tool supports Post-Quantum Cryptography (PQC) via **Profile C** (standalone ML-KEM-768), **Profile D** (parallel hybrid ML-KEM-768 + X25519, with add17/add19 variants), **Profile E** (nested hybrid), and **Profile F** (wrapper hybrid). It also supports **Profile G** (Scheme ID 7), a symmetric two-layer SUCI concealment profile with file-based subscriber key material.

**Tool extension — ML-KEM-1024 (NIST Level 5):** 3GPP TS 33.703 describes ML-KEM-768 for profiles C–F. This tool optionally uses **ML-KEM-1024** with the same scheme IDs (3–6); only KEM ciphertext and ML-KEM key byte lengths change (shared secret remains 32 bytes). Default remains **Level 3 / ML-KEM-768**. Select Level 5 via CLI `--security-level 5` on `conceal`, `deconceal` (optional; omitted means infer from HN private key), `keygen`, and `loadgen`. PEM types `ML-KEM-1024 PRIVATE KEY` / `ML-KEM-1024 PUBLIC KEY` distinguish 1024 keys from `ML-KEM-768 *`.

## Protection Scheme Overview

| Profile | Scheme ID | Status | KEM/Key Exchange | KDF | MAC | Encryption |
|---------|-----------|--------|------------------|-----|-----|------------|
| NULL | 0 | ✓ Implemented | None | N/A | N/A | None |
| A | 1 | ✓ Implemented | X25519 (ECDH) | ANSI-X9.63 (SHA-256) | HMAC-SHA-256 | AES-128-CTR |
| B | 2 | ✓ Implemented | P-256 (ECDH) | ANSI-X9.63 (SHA-256) | HMAC-SHA-256 | AES-128-CTR |
| **C** | **3** | **✓ Implemented** | **ML-KEM-768** | **ANSI-X9.63 (SHA3-256)** | **KMAC256** | **AES-256-CTR** |
| **D** | **4** | **✓ Implemented** | ML-KEM-768 + X25519 (Hybrid) | Combiner (SHA3-256) | KMAC256 | AES-256-CTR |
| **D-add17** | 4 (variant) | **✓ Implemented** | ML-KEM-768 + X25519 | Combiner + nonce + profile/variant binding | KMAC256 | AES-256-CTR |
| **D-add19** | 4 (variant) | **✓ Implemented** | ML-KEM-768 + X25519 | Combiner + profile/variant binding | AES-256-GCM (AEAD) | AES-256-GCM |
| **E** | **5** | **✓ Implemented** | **ML-KEM-768 + X25519 (Nested)** | **ANSI-X9.63 (SHA3-256)** | **KMAC256 (32 B)** | **AES-256-CTR** |
| **F** | **6** | **✓ Implemented** | **ML-KEM-768 + X25519 (Wrapper)** | **ANSI-X9.63 (SHA-256 / SHA3-256)** | **HMAC-SHA-256 + KMAC256** | **AES-128-CTR + AES-256-CTR** |
| **G** | **7** | **✓ Implemented** | **Symmetric key + subscriber Kmaster** | **HKDF-SHA-256 (L3) / SHA3-256 KDF (L5)** | **HMAC-SHA-256 (L3) / KMAC256 (L5)** | **AES-128-CTR (L3) / AES-256-CTR (L5)** |

## Module Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                       CLI Layer (cmd/suci-tool/main.go)                  │
│  • Command parsing (conceal, deconceal, keygen, inspect, loadgen, version, help) │
│  • User interaction                                                  │
│  • Output formatting                                                 │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
          ▼                        ▼                        ▼
┌──────────────────────────────┐  ┌───────────────────────────────────┐
│ Converter Layer (converter)  │  │      Keys Layer (keys)            │
│                              │  │                                   │
│ • ConvertSUCItoSUPI          │  │  ┌─────────────────────────────┐  │
│ • ConvertSUPItoSUCI          │  │  │  keygen.go                  │  │
│ • Error handling             │  │  │  • Profile A-F generation   │  │
│                              │  │  │  • Multi-format (PEM/DER/   │  │
│ ┌─────────────────────────┐  │  │  │    Hex/JWK)                 │  │
│ │  parser.go              │  │  │  │  • Batch generation         │  │
│ │  • SUCI/SUPI parsing    │  │  │  └─────────────────────────────┘  │
│ │  • Regex validation     │  │  │                                   │
│ │  • MSIN encode/decode   │  │  │  ┌─────────────────────────────┐  │
│ └─────────────────────────┘  │  │  │  inspect.go                 │  │
│                              │  │  │  • Key file analysis        │  │
│ ┌─────────────────────────┐  │  │  │  • Format auto-detection    │  │
│ │  encryptor.go           │  │  │  │  • Public key derivation    │  │
│ │  • ECIES encryption     │  │  │  │  • JSON/text output         │  │
│ │  • SUCI construction    │  │  │  └─────────────────────────────┘  │
│ └─────────────────────────┘  │  │                                   │
│                              │  │  ┌─────────────────────────────┐  │
│ ┌─────────────────────────┐  │  │  │  keystore.go                │  │
│ │  decryptor.go           │  │  │  │  • File-based storage       │  │
│ │  • ECIES decryption     │  │  │  │  • Environment vars         │  │
│ │  • MAC verification     │  │  │  │  • Key caching              │  │
│ └─────────────────────────┘  │  │  └─────────────────────────────┘  │
└──────────────────────────────┘  └───────────────────────────────────┘
                │                              │
                └──────────────┬───────────────┘
                               ▼
                     ┌─────────────────┐
                     │  Types Module   │
                     │  (types.go)     │
                     │                 │
                     │ • Error codes   │
                     │ • Constants     │
                     │ • Data types    │
                     └─────────────────┘
```

## Data Flow Diagrams

### SUPI to SUCI Concealment Flow (UE Operation)

```
┌────────────────┐
│  User Input    │
│  (SUPI String) │  e.g., imsi-123450123456789
└────────┬───────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  1. Parse SUPI String                                │
│     • Regex validation                               │
│     • Field extraction (MCC, MNC, MSIN)              │
│     • Length validation (5-15 digits IMSI)           │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  2. Retrieve or Generate Key                         │
│     • Lookup by Key ID (0-255) if specified          │
│     • Auto-select from keystore if not specified     │
│     • Generate new key if none available             │
│     • Derive public key from private key             │
└────────┬─────────────────────────────────────────────┘
         │
         ├─────────────────┬───────────────────────────────┐
         │                 │                               │
         ▼                 ▼                               ▼
    Scheme 0       Scheme 1/2 (ECIES)              Scheme 3-6 (PQC/Hybrid)
  (NULL-SCHEME)     (Profile A/B)                    (Profile C/D/E/F)
         │                 │                               │
         ▼                 ▼                               ▼
 ┌──────────────┐  ┌────────────────────────────────┐  ┌─────────────────────────────┐
│ Encode MSIN  │  │  3. ECIES Encrypt               │  │  3. ML-KEM/Hybrid Encrypt   │
│ as 3GPP TBCD │  │     • Generate ephemeral key    │  │     (Profile C/D/E/F)       │
 └──────┬───────┘  │     • ECDH shared secret       │
        │          │     • KDF derive enc+mac keys  │
        │          │     • AES-CTR encrypt MSIN     │
        │          │     • HMAC-SHA-256 compute MAC │
        │          └────────────┬───────────────────┘
        │                       │
        └───────────────────────┴────────────────┐
                                                 │
                                                 ▼
                              ┌────────────────────────────────────┐
                              │  4. Construct SUCI String           │
                              │     suci-<type>-<mcc>-<mnc>-        │
                              │     <routingInd>-<schemeId>-        │
                              │     <keyId>-<schemeOutput>          │
                              └────────────────────────────────────┘
```

### SUCI to SUPI De-concealment Flow (HN Operation)

```
┌────────────────┐
│  User Input    │
│  (SUCI String) │
└────────┬───────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  1. Parse SUCI String                                │
│     • Regex validation                               │
│     • Field extraction (type, MCC, MNC, etc.)        │
│     • Hex decoding of scheme output                  │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  2. Validate Scheme & Type                           │
│     • Check scheme ID (0, 1, 2, 3, 4, 5, 6, or 7)    │
│     • Validate identity type (IMSI or NAI)           │
└────────┬─────────────────────────────────────────────┘
         │
         ├─────────────────┬───────────────────┐
         │                 │                   │
         ▼                 ▼                   ▼
    Scheme 0       Scheme 1/2 (ECIES)   Scheme 3/4/5/6 (PQC/Hybrid)   Scheme 7 (Symmetric)
  (NULL-SCHEME)     (Profile A/B)       (Profile C/D/E/F)
         │                 │                   │
         │                 ▼                   ▼
         │     ┌────────────────────────────────────┐
         │     │  3. Retrieve Private Key           │
         │     │     • Lookup by Key ID             │
         │     │     • Validate key type/curve      │
         │     └────────────┬───────────────────────┘
         │                  │
         │                  ▼
         │     ┌────────────────────────────────────┐
         │     │  4. Parse Cryptogram               │
         │     │     • Extract ephemeral pubkey     │
         │     │     • Extract ciphertext           │
         │     │     • Extract MAC tag              │
         │     └────────────┬───────────────────────┘
         │                  │
         │                  ▼
         │     ┌────────────────────────────────────┐
         │     │  5. ECIES Decryption               │
         │     │     • ECDH shared secret           │
         │     │     • KDF key derivation           │
         │     │     • MAC verification             │
         │     │     • AES-CTR decryption           │
         │     └────────────┬───────────────────────┘
         │                  │
         └──────────────────┴────────────────────────┐
                            │                        │
                            ▼                        │
           ┌────────────────────────────────┐        │
           │  6. Decode MSIN                │        │
           │     • Decode as 3GPP TBCD      │        │
           │     • Validate nibbles/padding │        │
           └────────────────┬───────────────┘        │
                            │                        │
                            ▼                        │
           ┌────────────────────────────────┐        │
           │  7. Construct SUPI             │        │
           │     • Validate IMSI length     │        │
           │     • Build SUPI string        │        │
           └────────────────┬───────────────┘        │
                            │                        │
                            ▼                        │
                   ┌─────────────────┐               │
                   │  SUPI Output    │               │
                   │  (Success)      │               │
                   └─────────────────┘               │
                                                      │
                                                      ▼
                                            ┌──────────────────┐
                                            │  Error Output    │
                                            │  (Error Code)    │
                                            └──────────────────┘
```

## Component Details

### 1. Parser Module (`pkg/suciutil/parser.go`)

The canonical parsing implementation lives in **`pkg/suciutil/parser.go`**. The **`pkg/suci`** package exposes compatibility wrappers in `compat.go` and type aliases so that tests and callers can use either package.

**Responsibilities:**
- SUCI string validation using regex (scheme IDs 0–6)
- Component extraction (MCC, MNC, scheme ID, etc.)
- Hex decoding of scheme output
- MSIN decoding (3GPP TBCD only)
- SUPI construction
- Cryptogram parsing for Profile A/B (`ParseCryptogram`), Profile C (`ParsePQCCryptogram`), Profile D (`ParseProfileDCryptogram`), Profile E (`ParseProfileECryptogram`), and Profile F (`ParseProfileFCryptogram`)

**Key Functions:**
- `ParseSUCI(string) (*ParsedSUCI, ErrorCode)`
- `ParseCryptogram([]byte, SchemeID) (*Cryptogram, ErrorCode)`
- `ParsePQCCryptogram([]byte) (*PQCCryptogram, ErrorCode)` — Profile C
- `ParseProfileDCryptogram([]byte) (*HybridCryptogram, ErrorCode)` — Profile D
- `ParseProfileECryptogram([]byte) (*ProfileECryptogram, ErrorCode)` — Profile E (Nested Hybrid)
- `ParseProfileFCryptogram([]byte) (*ProfileFCryptogram, ErrorCode)` — Profile F (Wrapper Hybrid)
- `EncodeMSIN_TBCD(string) ([]byte, ErrorCode)` / `DecodeMSIN_TBCD([]byte) (string, ErrorCode)` (wrappers around `suciutil.EncodeMSIN_TBCDCode` / `DecodeMSIN_TBCDCode`)
- `ConstructSUPI(IdentityType, string, string, string) (string, ErrorCode)`
- `ConstructSUCI(...) string`

**Extensibility Points:**
- Extend TBCD handling if 3GPP rules change (encoding is centralized in `pkg/suciutil/msin_tbcd.go`)
- Support additional identity types
- Custom SUPI formats

---

### 2. Encryptor Module (`pkg/suci/encryptor.go`)

**Responsibilities:**
- SUPI string parsing and validation (via suciutil)
- ECIES encryption for Profile A (Curve25519) and Profile B (secp256r1)
- PQC encryption for Profile C (ML-KEM-768) and Hybrid Profiles D/E/F (ML-KEM-768 + X25519)
- Key derivation (ANSI-X9.63-KDF for A/B; SHA3-256 KDF for C/D/E/F)
- MAC computation (HMAC-SHA-256 for A/B; KMAC256 for C/D/E/F)
- AES-CTR encryption (AES-128 for A/B; AES-256 for C/D/E/F)
- SUCI string construction (via suciutil.ConstructSUCI)

**Key Functions:**
- `EncryptECIES([]byte, interface{}, SchemeID, ProfileDVariant) ([]byte, ErrorCode)` — dispatches to A/B/C/D/E/F (variant selects baseline/add17/add19 for D)
- `encryptProfileA([]byte, []byte) ([]byte, ErrorCode)`
- `encryptProfileB([]byte, *ecdsa.PublicKey) ([]byte, ErrorCode)`
- `encryptProfileC([]byte, interface{}) ([]byte, ErrorCode)` — ML-KEM-768
- `encryptProfileD([]byte, interface{}) ([]byte, ErrorCode)` — Hybrid ML-KEM + X25519 (baseline)
- `encryptProfileDAdd17([]byte, interface{}) ([]byte, ErrorCode)` — add17: nonce + profile/variant binding in KDF
- `encryptProfileDAdd19([]byte, interface{}) ([]byte, ErrorCode)` — add19: AES-256-GCM AEAD with AAD
- `encryptProfileE([]byte, interface{}) ([]byte, ErrorCode)` — Nested Hybrid (ECC wraps PQ ciphertext, PQ wraps MSIN)
- `encryptProfileF([]byte, interface{}) ([]byte, ErrorCode)` — Wrapper Hybrid (ECIES unchanged, PQ wraps ephemeral key)
- `ConstructSUCI(...)` (in suciutil) and `GetPublicKeyFromPrivate(interface{}, SchemeID) (interface{}, error)` (in suciutil)

**ECIES Encryption Flow:**
```
1. Generate ephemeral key pair (same curve as HN public key)
2. Compute shared secret via ECDH
3. Derive encryption key (16 bytes) and MAC key (32 bytes) via KDF
4. Encrypt MSIN using AES-128-CTR (zero IV)
5. Compute MAC over ciphertext using HMAC-SHA-256
6. Construct scheme output: ephemeral_pub || ciphertext || mac_tag
```

**Extensibility Points:**
- Add new ECIES profiles
- Support alternative KDF algorithms
- Post-Quantum Cryptography (PQC) schemes
- Custom MSIN encoding formats

---

### 3. Decryptor Module (`pkg/suci/decryptor.go` and `pkg/suciutil/parser.go`)

**Responsibilities:**
- ECIES decryption for Profile A (Curve25519) and Profile B (secp256r1)
- PQC decryption for Profile C (ML-KEM-768) and Hybrid for Profiles D/E/F (ML-KEM-768 + X25519)
- Key derivation (ANSI-X9.63-KDF; SHA3-256 + KMAC256 for C/D/E/F)
- MAC verification (HMAC-SHA-256 for A/B; KMAC256 for C/D/E/F)
- AES-CTR decryption

**Key Functions:**
- `DecryptECIES(*Cryptogram, interface{}, SchemeID) ([]byte, ErrorCode)` — A/B only
- `DecryptPQC(*PQCCryptogram, interface{}) ([]byte, ErrorCode)` — Profile C
- `DecryptHybrid(*HybridCryptogram, interface{}) ([]byte, ErrorCode)` — Profile D (dispatches on `Variant` field: baseline/add17/add19)
- `decryptProfileA(*Cryptogram, interface{}) ([]byte, ErrorCode)`
- `decryptProfileB(*Cryptogram, interface{}) ([]byte, ErrorCode)`
- `decryptProfileC(*PQCCryptogram, interface{}) ([]byte, ErrorCode)`
- `decryptProfileD(*HybridCryptogram, interface{}) ([]byte, ErrorCode)` — baseline
- `decryptProfileDAdd17(*HybridCryptogram, interface{}) ([]byte, ErrorCode)` — add17 variant
- `decryptProfileDAdd19(*HybridCryptogram, interface{}) ([]byte, ErrorCode)` — add19 variant (AEAD)
- `DecryptNestedHybrid(*ProfileECryptogram, interface{}) ([]byte, ErrorCode)` — Profile E (Nested Hybrid)
- `DecryptWrapperHybrid(*ProfileFCryptogram, interface{}) ([]byte, ErrorCode)` — Profile F (Wrapper Hybrid)
- `decryptProfileE(*ProfileECryptogram, interface{}) ([]byte, ErrorCode)` — nested: ECDH → decrypt KEM CT → ML-KEM decap → decrypt MSIN
- `decryptProfileF(*ProfileFCryptogram, interface{}) ([]byte, ErrorCode)` — wrapper: ML-KEM decap → decrypt eph pub → ECDH → decrypt MSIN

The converter uses `pkg/suciutil` for parsing and decryption (ParseSUCI, ParseCryptogram, ParseProfileDCryptogram, ParseProfileECryptogram, ParseProfileFCryptogram, DecryptECIES, DecryptPQC, DecryptHybrid, DecryptNestedHybrid, DecryptWrapperHybrid). The parser auto-detects the variant from the wire format — no CLI flag is needed for de-concealment.

**Extensibility Points:**
- Add new ECIES profiles
- Support alternative KDF algorithms
- Post-Quantum Cryptography (PQC) schemes
- Hardware-accelerated crypto operations

---

### 4. Key Store Module (`pkg/keys/keystore.go`)

**Responsibilities:**
- Private key management
- Key retrieval by Key ID and Scheme
- Support multiple storage backends
 - Support Profile D/E/F composite keys (two-file MLKEM+X25519 and single-file combined PEM)
 - Support Profile G file bundles (`hn-key-<id>-profile-g.json` + `hn-key-<id>-profile-g-subscribers.json`)
- Key caching for performance

**Interfaces:**
```go
type KeyStore interface {
  GetPrivateKey(keyID uint8, scheme SchemeID) (interface{}, error)
}
```

**Implementations:**
- `FileKeyStore` - files from disk (PEM for A-F, JSON bundle for Profile G)
- `EnvKeyStore` - Environment variables (including HN_KEY_{id}_PROFILE_{D|E|F}_MLKEM / _X25519)
- `MemoryKeyStore` - In-memory storage (testing)
- `SingleFileKeyStore` - Single key file; key ID and scheme taken from the SUCI string (used with `--key-file`, including Profile G JSON)

**Extensibility Points:**
- HSM integration (PKCS#11)
- Cloud KMS (AWS, Azure, GCP)
- HashiCorp Vault integration
- Database-backed key store

---

### 5. Key Generation Module (`pkg/keys/keygen.go`)

**Responsibilities:**
- Generate cryptographically secure key pairs
- Support Profile A (Curve25519/X25519), Profile B (P-256), Profile C (ML-KEM-768), Profile D (Parallel Hybrid), Profile E (Nested Hybrid), and Profile F (Wrapper Hybrid) — all using ML-KEM-768 + X25519 composite keys for D/E/F
- Batch key generation for any Key ID range (0-255)
- Multi-format output (PEM, DER, Hex, JWK); Profiles D/E/F support PEM only
- Optional public key export

**Key Functions:**
```go
// Generate a single key pair
GenerateKeyPair(keyID uint8, scheme SchemeID) (*KeyPair, error)

// Generate multiple key pairs
GenerateKeyPairBatch(startID, endID uint8, scheme SchemeID) ([]*KeyPair, error)

// Save key pair to files (SaveKeyPairWithFormat for format choice; Profile D writes two files or combined PEM)
SaveKeyPair(keyPair *KeyPair, outputDir string, savePublic bool) error
SaveKeyPairWithFormat(keyPair *KeyPair, outputDir string, savePublic bool, format KeyFormat) error

// Generate and save in one operation
GenerateAndSaveKeys(config *KeyGenConfig) (int, error)
```

**KeyPair Structure:**
```go
type KeyPair struct {
    PrivateKey    interface{}  // Raw bytes (A), *ecdsa.PrivateKey (B), ML-KEM bytes (C), or *ProfileDPrivateKeys (D/E/F)
    PublicKey     interface{}  // Corresponding public key (or *ProfileDPublicKeys for D/E/F)
    PrivateKeyPEM []byte       // PEM-encoded private key
    PublicKeyPEM  []byte       // PEM-encoded public key
    KeyID         uint8        // Key identifier (0-255)
    Scheme        SchemeID     // Profile A, B, C, D, E, or F
}
```

**Key Generation Flow:**
```
┌────────────────┐
│  User Request  │
│  (keygen cmd)  │
└────────┬───────┘
         │
         ▼
┌─────────────────────────────────────┐
│  Parse Options                      │
│  • Key ID range (0-255)             │
│  • Profile (a/b/c/d/e/f/both/all)   │
│  • Output directory                 │
│  • Save public keys flag            │
└────────┬────────────────────────────┘
         │
         ├────────┬────────┬────────┬────────┐
         ▼        ▼        ▼        ▼        ▼
   Profile A   Profile B  Profile C  Profile D   Profile E   Profile F   both/all
  ┌──────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
  │Curve25519│ │ P-256  │ │ML-KEM  │ │Hybrid  │ │Nested  │ │Wrapper │ │ A+B or │
  │  keygen  │ │ keygen │ │ 768    │ │ D keys │ │ E keys │ │ F keys │ │ A-F    │
  └────┬─────┘ └────┬───┘ └────┬───┘ └────┬───┘ └────┬───┘ └────┬───┘ └────┬───┘
       │               │               │               │
       └───────────────┴───────────────┴───────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  PEM/DER/Hex/   │
              │  JWK & File Save│
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Output Files   │
              │ hn-key-X-*.pem  │ (Profile D: -mlkem.pem, -x25519.pem, or -profile-d.pem)
              └─────────────────┘
```

**Cryptographic Details:**
- **Profile A**: Uses Go's `crypto/rand` and `golang.org/x/crypto/curve25519`
  - 32 random bytes clamped per X25519 spec
  - Public key derived from basepoint multiplication
- **Profile B**: Uses Go's `crypto/ecdsa` with `elliptic.P256()`
  - Standard ECDSA key generation
  - PKCS#8 format for private key, PKIX for public key
- **Profile C**: Uses `github.com/cloudflare/circl/kem/mlkem/mlkem768`
  - ML-KEM-768 key generation (1184-byte public, 2400-byte private)
- **Profile D**: Generates both ML-KEM-768 and X25519 key pairs; saved as two files (`hn-key-{id}-profile-d-mlkem.pem`, `hn-key-{id}-profile-d-x25519.pem`) or single combined PEM
- **Profile E**: Same composite key structure as D; saved as `hn-key-{id}-profile-e-mlkem.pem` and `hn-key-{id}-profile-e-x25519.pem`
- **Profile F**: Same composite key structure as D; saved as `hn-key-{id}-profile-f-mlkem.pem` and `hn-key-{id}-profile-f-x25519.pem`

**Key Format Support:**
| Format | Extension | Description |
|--------|-----------|-------------|
| PEM | `.pem` | Human-readable, OpenSSL compatible |
| DER | `.der` | Binary ASN.1, compact storage |
| Hex | `.hex` | Raw hex bytes, 3GPP test vectors |
| JWK | `.jwk` | JSON Web Key, REST APIs |

---

### 6. Key Inspection Module (`pkg/keys/inspect.go`)

**Responsibilities:**
- Analyze and display key file information
- Auto-detect key format (PEM, DER, Hex, JWK)
- Derive public key from private key
- Support Profile A, B, C, D, E, and F keys (including Profile D/E/F two-file and single-file combined)
- Directory scan with `--key-dir` (optional `--recursive`, `--show-invalid`)
- Support text and JSON output formats

**Key Functions:**
```go
// Inspect a key file and return detailed information
InspectKey(config *InspectConfig) (*KeyInfo, error)

// Auto-detect key format
detectKeyFormat(data []byte) KeyFormat

// Parse different formats
parsePEMKey(data []byte) (*KeyInfo, error)
parseDERKey(data []byte) (*KeyInfo, error)
parseHexKey(data []byte) (*KeyInfo, error)
parseJWKKey(data []byte) (*KeyInfo, error)

// Derive public key from private key
derivePublicKey(keyInfo *KeyInfo, data []byte) error

// Output formatters
FormatKeyInfo(info *KeyInfo) string
FormatKeyInfoJSON(info *KeyInfo) (string, error)
```

**KeyInfo Structure:**
```go
type KeyInfo struct {
    FilePath      string         // Path to the key file (or "file1,file2" for Profile D pair)
    FileName      string         // Base name of file(s)
    Format        KeyFormat      // PEM, DER, Hex, JWK
    KeyType       string         // "private" or "public"
    Profile       string         // A (X25519), B (P-256), C (ML-KEM-768), D/E/F (Hybrid)
    Scheme        suciutil.SchemeID // 1, 2, 3, 4, 5, or 6
    KeyID         int            // From filename, or -1
    KeySizeBits   int            // 256 for A/B; varies for C/D
    KeySizeBytes  int            // Byte length
    Algorithm     string         // X25519, ECDH-P256, ML-KEM-768, or ML-KEM-768+X25519
    Curve         string         // Curve25519, P-256, or N/A
    Fingerprint   string         // SHA256 of public key (or combined for D)
    PublicKeyHex   string         // Hex-encoded public key
    PublicKeyPEM   string         // PEM-encoded public key
    PrivateKeyHex  string         // If --show-private
    Error         string         // Non-empty if inspection failed
}
```

**Format Auto-Detection Flow:**
```
┌────────────────┐
│  Key File      │
│  (raw bytes)   │
└────────┬───────┘
         │
         ▼
┌────────────────────────────────────┐
│  Check for PEM Header              │
│  ("-----BEGIN")                    │
│  ───────────────────────────────   │
│  Yes → PEM format                  │
└────────┬───────────────────────────┘
         │ No
         ▼
┌────────────────────────────────────┐
│  Check for JWK Structure           │
│  (JSON with "kty" field)           │
│  ───────────────────────────────   │
│  Yes → JWK format                  │
└────────┬───────────────────────────┘
         │ No
         ▼
┌────────────────────────────────────┐
│  Check if Hex-Only Content         │
│  (all chars 0-9, a-f, A-F)         │
│  ───────────────────────────────   │
│  Yes → Hex format                  │
└────────┬───────────────────────────┘
         │ No
         ▼
┌────────────────────────────────────┐
│  Default to DER format             │
│  (binary ASN.1)                    │
└────────────────────────────────────┘
```

---

### 7. Converter Module (`pkg/suci/converter.go`)

**Responsibilities:**
- Orchestrate bidirectional conversion workflow
- Coordinate between parser, encryptor, decryptor, and key store
- Handle NULL-SCHEME vs encrypted schemes
- Key auto-selection and generation for concealment
- Error aggregation and reporting

**Key Functions:**
- `ConvertSUCItoSUPI(string) ConversionResult` - De-concealment
- `ConvertSUPItoSUCI(ConcealmentConfig) ConcealmentResult` - Concealment
- `handleNullScheme(*ParsedSUCI) (string, ErrorCode)`
- `handleEncryptedScheme(*ParsedSUCI) (string, ErrorCode)`
- `findOrGenerateKey(keyID int, scheme, keyDir string) (interface{}, int, ErrorCode)`

**ConcealmentConfig Structure:**
```go
type ConcealmentConfig struct {
    SUPI         string         // Input SUPI (e.g., "imsi-123450123456789")
    SchemeID     suciutil.SchemeID // 0=NULL, 1=A, 2=B, 3=C (PQC), 4=D, 5=E, 6=F
    KeyID        int            // Key ID (0-255) or -1 for auto-select
    RoutingInd   string         // Routing indicator (default "0000")
    KeyDirectory string         // Directory containing HN keys
}
```

---

### 8. Types Module (`pkg/suci/types.go`)

**Responsibilities:**
- Define error codes and messages
- Define constants (schemes, encodings, lengths)
- Define data structures
- Type safety and validation

**Key Types:**
- `ErrorCode` - Structured error handling
- `SchemeID` - Protection scheme enumeration (0–6)
- `IdentityType` - IMSI vs NAI
- `ParsedSUCI` - Parsed SUCI components (SchemeID 0–6)
- `ConversionResult` - Output wrapper
- `Cryptogram` - ECIES cryptogram (Profile A/B)
- `PQCCryptogram` - PQC cryptogram (Profile C)
- `HybridCryptogram` - Hybrid cryptogram (Profile D)
- `ProfileECryptogram` - Nested Hybrid cryptogram (Profile E)
- `ProfileFCryptogram` - Wrapper Hybrid cryptogram (Profile F)
- `ProfileDPrivateKeys` / `ProfileDPublicKeys` - Composite keys for Profile D/E/F (type aliases `ProfileEPrivateKeys`, `ProfileFPrivateKeys`, etc.)

---

### 9. Load Generator Module (`pkg/suci/loadgen.go`)

**Responsibilities:**
- Synthetic SUCI generation and end-to-end benchmarking
- Configurable concurrency, iteration count, and warmup
- Tail-latency measurement (p50, p95, p99)
- Multiple operating modes for isolating bottlenecks

**Key Types and Functions:**
- `LoadGenMode` — `"end-to-end"`, `"decrypt-only"`, `"parse-only"`
- `LoadGenConfig` — iteration count, concurrency, warmup, scheme, MSIN, MCC/MNC, key ID, routing indicator
- `LoadGenResult` — total ops, elapsed time, throughput (ops/sec), latency percentiles
- `RunLoadGen(LoadGenConfig) (*LoadGenResult, error)` — main entry point
- `FormatLoadGenResultText(*LoadGenResult) string` — human-readable output
- `FormatLoadGenResultJSON(*LoadGenResult) (string, error)` — JSON output

**Supported Schemes:** null, a, b, c, d, e, f

---

### 10. Debug Logging Module (`pkg/slog/slog.go`)

**Responsibilities:**
- Conditional debug output controlled by `SUCI_DEBUG` or `DEBUG` environment variables
- Runtime toggle via `SetEnabled(bool)`

**Key Functions:**
- `Debugf(format, args...)` — prints only when `Enabled` is true
- `SetEnabled(bool)` — enable/disable at runtime

---

## Error Handling Strategy


### Error Code Structure

```
0xABCD
  ││└└─ Specific error within category
  │└─── Error category
  └──── Major category

Categories:
  0x1xx - Parse/Format errors
  0x2xx - Cryptographic errors
  0x3xx - Validation errors
```

#### Error Codes

| Code   | Category       | Name/Description                  | Typical Cause                  |
|--------|---------------|-----------------------------------|--------------------------------|
| 0x101  | Parse/Format  | E_PARSE_SUCI: Invalid SUCI format | Malformed input                |
| 0x102  | Parse/Format  | E_PARSE_SUPI: Invalid SUPI format | Malformed input                |
| 0x201  | Cryptographic | E_CURVE_MISMATCH: Key curve mismatch | Key curve doesn't match scheme |
| 0x202  | Cryptographic | E_TAG_MISMATCH: MAC verification failed | Wrong key or corrupted data   |
| 0x203  | Cryptographic | E_INVALID_EC_KEY: Invalid EC key  | Malformed PEM or key data      |
| 0x204  | Cryptographic | E_SCHEME_OUTPUT_TOO_SHORT: Insufficient data | Truncated cryptogram   |
| 0x205  | Cryptographic | E_MSIN_ENCODING: MSIN decode failed | Invalid MSIN format           |
| 0x206  | Cryptographic | E_INVALID_IMSI_LENGTH: IMSI length invalid | IMSI < 5 or > 15 digits |
| 0x207  | Cryptographic | E_ENCRYPTION_FAILED: Encryption failed | Encryption operation failed   |
| 0x208  | Cryptographic | E_INVALID_PQC_KEY: Invalid PQC key format | Invalid ML-KEM key format    |
| 0x209  | Cryptographic | E_KEM_ENCAPSULATE_FAILED: ML-KEM encapsulation failed | PQC error         |
| 0x20A  | Cryptographic | E_KEM_DECAPSULATE_FAILED: ML-KEM decapsulation failed | PQC error         |
| 0x20B  | Cryptographic | E_KMAC_FAILED: KMAC256 computation failed | PQC error                  |
| 0x301  | Validation    | E_INVALID_SCHEME_ID: Unsupported scheme | Not 0/1/2/3/4/5/6            |
| 0x302  | Validation    | E_INVALID_TYPE: Invalid identity type | Type not 0 or 1               |
| 0x303  | Validation    | E_INVALID_KEY_ID: Invalid key ID  | Key ID > 255                   |
| 0x304  | Validation    | E_UNKNOWN_KEY_ID: Key not in store | Key not in store               |
| 0x305  | Validation    | E_INVALID_SUBSCRIBER_KEY_ID: Invalid subscriber key ID | Not 10 hex chars   |

### Error Propagation

```
┌─────────────┐
│  Operation  │
└──────┬──────┘
       │
       ▼
   Success?
    │    │
   Yes   No
    │    │
    │    ▼
    │  ┌──────────────┐
    │  │ Return Error │
    │  │ Code         │
    │  └──────┬───────┘
    │         │
    ▼         ▼
┌──────────────────┐
│ ConversionResult │
│ • SUPI (success) │
│ • ErrorCode      │
└──────────────────┘
```

---

## Security Considerations

### Key Management
- **Principle of Least Privilege**: Keys only accessible when needed
- **Secure Storage**: PEM encryption, HSM integration
- **Key Rotation**: Support for multiple active keys
- **Audit Logging**: Track all key access attempts

### Cryptographic Operations
- **Constant-Time Operations**: Prevent timing attacks
- **MAC Verification**: Use `hmac.Equal()` for constant-time comparison
- **Zeroization**: Clear sensitive data from memory after use
- **Random Number Generation**: Use crypto/rand for all random values

### Input Validation
- **Regex Validation**: Strict SUCI format checking
- **Length Checks**: Validate all buffer sizes
- **Range Validation**: Check key IDs, scheme IDs, etc.
- **Sanitization**: Prevent injection attacks in logs

---

## Post-Quantum Cryptography (PQC) Support

### Overview

The tool supports Post-Quantum Cryptography (PQC) for SUCI protection per **3GPP TS 33.703**. This implements NIST FIPS 203 ML-KEM (Module-Lattice Key Encapsulation Mechanism), formerly known as CRYSTALS-Kyber.

### PQC Profiles

| Profile | Scheme ID | KEM | KDF | MAC | Encryption |
|---------|-----------|-----|-----|-----|------------|
| **Profile C** | 3 | ML-KEM-768 | ANSI-X9.63-KDF (SHA3-256) | KMAC256 (64-bit tag) | AES-256-CTR |
| **Profile D** | 4 | ML-KEM-768 + X25519 (Hybrid) | Combiner (SP 800-227) | KMAC256 (64-bit tag) | AES-256-CTR |
| **Profile E** | 5 | ML-KEM-768 + X25519 (Nested) | ANSI-X9.63-KDF (SHA3-256) | KMAC256 (32-byte tags) | AES-256-CTR |
| **Profile F** | 6 | ML-KEM-768 + X25519 (Wrapper) | ANSI-X9.63-KDF (SHA-256 / SHA3-256) | HMAC-SHA-256 + KMAC256 | AES-128-CTR + AES-256-CTR |

### Profile C (Standalone ML-KEM-768) - 3GPP TS 33.703 Solution #7

**Cryptographic Parameters:**
- **KEM**: ML-KEM-768 (NIST FIPS 203)
  - Public key: 1184 bytes
  - Private (decapsulation) key: 2400 bytes
  - Ciphertext: 1088 bytes
  - Shared secret: 32 bytes
- **KDF**: ANSI-X9.63-KDF with SHA3-256
  - Input: 32-byte shared secret
  - SharedInfo1: ML-KEM ciphertext (1088 bytes)
  - Output: 64 bytes (32-byte AES key + 32-byte MAC key)
- **MAC**: KMAC256
  - Key: 32 bytes
  - Output: 8 bytes (64-bit tag)
  - CustomString: "SUCI-MAC"
- **Encryption**: AES-256-CTR
  - Key: 32 bytes
  - ICB (Initial Counter Block): 16 bytes (zero IV)

### Profile C: PQC SUCI Concealment Flow (UE Operation)

```
┌────────────────┐
│  SUPI Input    │
│  (MSIN)        │
└────────┬───────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  1. ML-KEM-768 Encapsulation                         │
│     • Input: HN public key (1184 bytes)              │
│     • Output: Ciphertext (1088 bytes)                │
│     • Output: Shared Secret (32 bytes)               │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  2. Key Derivation (ANSI-X9.63-KDF with SHA3-256)    │
│     • SharedSecret (32 bytes)                        │
│     • SharedInfo1 = ML-KEM ciphertext (1088 bytes)   │
│     • Output: encKey (32 bytes) || macKey (32 bytes) │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  3. AES-256-CTR Encryption                           │
│     • Key: encKey (32 bytes)                         │
│     • ICB: zeros (16 bytes)                          │
│     • Input: MSIN (variable length)                  │
│     • Output: encrypted MSIN                         │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  4. KMAC256 Computation                              │
│     • Key: macKey (32 bytes)                         │
│     • Data: ciphertext (encrypted MSIN)              │
│     • CustomString: "SUCI-MAC"                       │
│     • Output: MAC tag (8 bytes)                      │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  5. Construct Scheme Output                          │
│     kemCiphertext (1088) || encMSIN || macTag (8)    │
└────────────────────────────────────────────────────────┘
```

### Profile C: PQC SUCI De-concealment Flow (HN Operation)

```
┌────────────────────┐
│  SUCI Input        │
│  (Scheme Output)   │
└────────┬───────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  1. Parse Scheme Output                              │
│     • kemCiphertext = first 1088 bytes               │
│     • encMSIN = bytes[1088 : len-8]                  │
│     • macTag = last 8 bytes                          │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  2. ML-KEM-768 Decapsulation                         │
│     • Input: kemCiphertext (1088 bytes)              │
│     • Input: HN private key (2400 bytes)             │
│     • Output: Shared Secret (32 bytes)               │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  3. Key Derivation (ANSI-X9.63-KDF with SHA3-256)    │
│     • SharedSecret (32 bytes)                        │
│     • SharedInfo1 = kemCiphertext (1088 bytes)       │
│     • Output: encKey (32 bytes) || macKey (32 bytes) │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  4. KMAC256 Verification                             │
│     • Key: macKey (32 bytes)                         │
│     • Data: encMSIN                                  │
│     • CustomString: "SUCI-MAC"                       │
│     • Compare with received macTag (8 bytes)         │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  5. AES-256-CTR Decryption                           │
│     • Key: encKey (32 bytes)                         │
│     • ICB: zeros (16 bytes)                          │
│     • Input: encMSIN                                 │
│     • Output: MSIN (plaintext)                       │
└────────────────────────────────────────────────────────┘
```

### Profile C Constants

```go
const (
    SchemeProfileC SchemeID = 3  // Standalone ML-KEM-768

    // ML-KEM-768 parameters
    MLKEM768_PUBLIC_KEY_LEN  = 1184  // bytes
    MLKEM768_PRIVATE_KEY_LEN = 2400  // bytes
    MLKEM768_CIPHERTEXT_LEN  = 1088  // bytes
    MLKEM768_SHARED_SECRET   = 32    // bytes

    // Profile C derived key lengths
    ProfileC_ENC_KEY_LEN = 32  // AES-256 key
    ProfileC_MAC_KEY_LEN = 32  // KMAC256 key
    ProfileC_MAC_TAG_LEN = 8   // 64-bit MAC tag
)
```

### Profile D (Hybrid ML-KEM + X25519)

**Status:** Fully implemented (UE concealment and HN de-concealment). Converter handles scheme ID 4 for both directions.

Profile D combines ML-KEM-768 (PQC) with X25519 (classic ECC). Combiner: `CombinedSecret = SHA3-256(ss1 || ss2)`; then ANSI-X9.63-KDF with SHA3-256, `SharedInfo1 = kemCiphertext || ephPublicKey`, yields encKey and macKey (same as Profile C). Symmetric layer: AES-256-CTR, KMAC256 (8-byte tag).

**Key storage (Profile D):** Two files per Key ID: `hn-key-{id}-profile-d-mlkem.pem`, `hn-key-{id}-profile-d-x25519.pem`, or a single combined `hn-key-{id}-profile-d.pem` with both PEM blocks. Keystore returns composite `ProfileDPrivateKeys`; `GetPublicKeyFromPrivate` returns `ProfileDPublicKeys`.

The full Profile C and Profile D concealment and de-concealment flows are documented as step-by-step diagrams in the sections below (PQC and ECC branches, key derivation, MAC, and encrypt/decrypt stages). Rendered flowchart figures are available in [docs/](docs/): `profile-c-concealment.png`, `profile-c-deconcealment.png`, `profile-d-concealment.png`, and `profile-d-deconcealment.png` (see [docs/README.md](docs/README.md)).

---

#### Profile D: Hybrid SUCI Concealment Flow (UE Operation)

Two branches (PQC + ECC) feed into key derivation; then symmetric encryption and MAC. Final output = PQ Ciphertext ‖ Eph. public key ‖ Ciphertext ‖ MAC tag.

```
                    ┌─────────────────────────────────┐
                    │  Post Quantum Public key of HN   │
                    │  (ML-KEM-768, 1184 bytes)        │
                    └──────────────┬───────────────────┘
                                   │
    ┌──────────────────────────────┼──────────────────────────────┐
    │  PQC branch                  │                              │
    │  1> Key encapsulation       ▼                              │
    │     • ML-KEM-768 Encapsulate                                │
    │     • Output: PQ Ciphertext (1088), Eph. shared key 1 (32)  │
    └──────────────────────────────┬──────────────────────────────┘
                                   │
                    ┌──────────────┴───────────────────┐
                    │  Public key of HN (X25519, 32 B)  │
                    └──────────────┬───────────────────┘
                                   │
    ┌──────────────────────────────┼──────────────────────────────┐
    │  ECC branch                  │                              │
    │  2> Eph. keypair generation  ▼                              │
    │     • Generate ephemeral X25519 keypair                     │
    │     • Output: Eph. public key (32), Eph. private key (32)   │
    │  3> Key agreement                                           │
    │     • ECDH(Eph. private key, HN X25519 public key)           │
    │     • Output: Eph. shared key 2 (32)                         │
    └──────────────────────────────┬──────────────────────────────┘
                                   │
    Eph. shared key 1, Eph. shared key 2, Eph. public key
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  4> Key derivation                                                │
│     • Combiner: CombinedSecret = SHA3-256(ss1 ‖ ss2)             │
│     • SharedInfo1 = PQ Ciphertext ‖ Eph. public key               │
│     • ANSI-X9.63-KDF with SHA3-256 → encKey (32), macKey (32)    │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  5> Symmetric encryption (AES-256-CTR)                            │
│     • Input: Plaintext block (MSIN), Eph. enc. key, ICB (zero)   │
│     • Output: Ciphertext value                                    │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  6> MAC function (KMAC256)                                         │
│     • Input: Eph. mac key, Ciphertext value                       │
│     • Output: MAC-tag value (8 bytes)                             │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  Final output = PQ Ciphertext ‖ Eph. public key ‖ Ciphertext ‖   │
│                 MAC tag                                          │
└──────────────────────────────────────────────────────────────────┘
```

---

#### Profile D: Hybrid SUCI De-concealment Flow (HN Operation)

Two branches (PQC decapsulation + ECC key agreement) feed into key derivation; then MAC verification and symmetric decryption.

```
    ┌─────────────────────────────────┐     ┌─────────────────────────┐
    │  PQ secret key of HN            │     │  PQ Ciphertext of UE    │
    │  (ML-KEM-768, 2400 bytes)       │     │  (1088 bytes)           │
    └──────────────┬──────────────────┘     └────────────┬────────────┘
                   │                                     │
    ┌──────────────┴────────────────────────────────────┴──────────┐
    │  PQC branch  1> Key Decapsulation                             │
    │     • ML-KEM-768 Decapsulate                                  │
    │     • Output: Eph. shared key 1 (32)                          │
    └──────────────┬────────────────────────────────────────────────┘
                   │
    ┌──────────────┴───────────────────┐     ┌─────────────────────────┐
    │  Private key of HN (X25519, 32 B) │     │  Eph. public key of UE  │
    └──────────────┬───────────────────┘     │  (32 bytes)             │
                   │                          └────────────┬────────────┘
    ┌──────────────┴──────────────────────────────────────┴──────────┐
    │  ECC branch  2> Key agreement                                  │
    │     • ECDH(HN X25519 private key, Eph. public key of UE)        │
    │     • Output: Eph. shared key 2 (32)                            │
    └──────────────┬─────────────────────────────────────────────────┘
                   │
    Eph. shared key 1, Eph. shared key 2
                   │
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  3> Key derivation                                                │
│     • Combiner: CombinedSecret = SHA3-256(ss1 ‖ ss2)             │
│     • SharedInfo1 = kemCiphertext ‖ ephPublicKey                  │
│     • KDF → Eph. dec. key (32), Eph. mac key (32)                 │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  4> MAC function (verif.)                                         │
│     • Key: Eph. mac key; Data: Ciphertext value                   │
│     • Compare computed tag with received MAC-tag value            │
└────────┬─────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│  5> If MAC valid then symmetric decryption (AES-256-CTR)           │
│     • Input: Ciphertext value, Eph. dec. key, ICB (zero)          │
│     • Output: Plaintext block (MSIN)                              │
└──────────────────────────────────────────────────────────────────┘
```

---

### Profile D Variants (add17 / add19) — Group B Security Enhancements

Profile D supports three wire-format variants, all sharing the same Scheme ID 4 and the same ML-KEM-768 + X25519 hybrid key exchange. The variant is encoded as a single byte at offset 1120 in the scheme output (immediately after the 1088-byte KEM ciphertext and 32-byte ephemeral public key).

| Variant | Byte | KDF SharedInfo1 | Symmetric | MAC | Nonce |
|---------|------|-----------------|-----------|-----|-------|
| Baseline | 0x00 (implicit) | `kemCT \|\| ephPK` | AES-256-CTR | KMAC256 (8 B) | None |
| add17 | 0x01 | `kemCT \|\| ephPK \|\| nonce \|\| profileByte \|\| variantByte` | AES-256-CTR | KMAC256 (8 B) | 16 B random |
| add19 | 0x02 | `kemCT \|\| ephPK \|\| profileByte \|\| variantByte` | AES-256-GCM (AEAD) | GCM tag (16 B) | 12 B from KDF |

#### Wire format layout

```
Baseline:  [KEM CT 1088] [Eph PK 32]                                [CT variable] [MAC 8]
add17:     [KEM CT 1088] [Eph PK 32] [0x01] [Nonce 16]             [CT variable] [MAC 8]
add19:     [KEM CT 1088] [Eph PK 32] [0x02]                        [CT variable] [AEAD tag 16]
```

#### add17 (Solution #17) — Nonce-based freshness + KDF binding

1. A random 16-byte nonce is generated per concealment operation for replay/freshness protection.
2. The KDF `SharedInfo1` is extended: `kemCiphertext || ephPublicKey || nonce || 0x04 (profileD) || 0x01 (add17)`. This binds the derived keys to the profile and variant, preventing cross-variant oracle attacks.
3. The nonce is placed in the wire format at offset 1121 (after the variant byte).
4. Symmetric encryption and MAC remain identical to baseline (AES-256-CTR + KMAC256).

#### add19 (Solution #19) — AEAD (AES-256-GCM)

1. Replaces the separate AES-256-CTR encryption + KMAC256 MAC with a single AES-256-GCM AEAD operation.
2. KDF `SharedInfo1` includes profile and variant binding: `kemCiphertext || ephPublicKey || 0x04 || 0x02`.
3. KDF output is extended to 44 bytes: 32-byte AEAD key + 12-byte GCM nonce (derived, not random).
4. AAD (Additional Authenticated Data) = `pqCiphertext || ephPublicKey`, binding the ciphertext integrity to the key exchange.
5. The GCM authentication tag (16 bytes) replaces the KMAC256 tag in the wire format.

#### Auto-detection on de-concealment

The parser examines byte 1120 of the scheme output:
- If the remaining length matches baseline layout (no variant byte): baseline.
- `0x01` → add17 (expects 16-byte nonce following the variant byte).
- `0x02` → add19 (expects 16-byte AEAD tag instead of 8-byte KMAC tag).

No CLI flag is needed for de-concealment — variant detection is fully automatic.

#### CLI usage

```bash
# Concealment with variant selection (--add-17 or --add-19)
suci-supi-tool conceal --msin 0123456789 --scheme-id 4 --key-id 1 \
  --pub-key-ml-kem hn-key-1-profile-d-mlkem-pub.pem \
  --pub-key-x25519 hn-key-1-profile-d-x25519-pub.pem --add-17

suci-supi-tool conceal --msin 0123456789 --scheme-id 4 --key-id 1 \
  --pub-key-ml-kem hn-key-1-profile-d-mlkem-pub.pem \
  --pub-key-x25519 hn-key-1-profile-d-x25519-pub.pem --add-19

# De-concealment (auto-detects variant — no flag needed)
suci-supi-tool deconceal --suci "suci-0-..." --key-ml-kem ... --key-x25519 ...
```

---

### Profile E (Nested Hybrid — ML-KEM-768 + X25519) — Scheme ID 5

Profile E implements a **nested hybrid** construction where two independent encryption layers protect the SUPI. The ECC layer protects the PQ ciphertext while the PQ layer independently protects the MSIN. Neither shared secret is combined — they operate as separate encryption layers.

**Cryptographic Parameters:**
- **KEM**: ML-KEM-768 (1088-byte ciphertext, 32-byte shared secret)
- **ECDH**: X25519 (32-byte ephemeral public key, 32-byte shared secret)
- **KDF**: ANSI-X9.63-KDF with SHA3-256 (for both layers)
- **MAC**: KMAC256 (32-byte tags, CustomString = "SUCI-MAC")
- **Encryption**: AES-256-CTR with zero IV (for both layers)

**Scheme Output (Wire Format):**
```
| Eph X25519 PK (32) | Enc KEM CT (1088) | Enc MSIN (variable) | MAC_ECC (32) | MAC_PQ (32) |
```
Minimum length: 1184 bytes (32 + 1088 + 0 + 32 + 32)

**UE Concealment Flow (Profile E):**
```
1. Generate ephemeral X25519 keypair
2. ECDH(eph_priv, HN_x25519_pub) → ss_ecc (32 bytes)
3. ML-KEM-768 Encapsulate(HN_mlkem_pub) → (kem_ct, ss_pq)
4. KDF(ss_ecc, SharedInfo1=kem_ct) → ecc_encKey (32) || ecc_macKey (32)
5. AES-256-CTR encrypt kem_ct with ecc_encKey → enc_kem_ct
6. KDF(ss_pq, SharedInfo1=eph_pub) → pq_encKey (32) || pq_macKey (32)
7. AES-256-CTR encrypt MSIN with pq_encKey → enc_msin
8. KMAC256(ecc_macKey, enc_kem_ct) → mac_ecc (32 bytes)
9. KMAC256(pq_macKey, enc_msin) → mac_pq (32 bytes)
10. Output: eph_pub || enc_kem_ct || enc_msin || mac_ecc || mac_pq
```

**HN De-concealment Flow (Profile E):**
```
1. Parse: eph_pub (32) | enc_kem_ct (1088) | enc_msin (var) | mac_ecc (32) | mac_pq (32)
2. ECDH(HN_x25519_priv, eph_pub) → ss_ecc
3. KDF(ss_ecc, SharedInfo1=enc_kem_ct[:1088 raw]) → ecc_encKey || ecc_macKey
   Note: SharedInfo1 uses the ENCRYPTED KEM CT as wire-observable data
4. Verify KMAC256(ecc_macKey, enc_kem_ct) == mac_ecc
5. AES-256-CTR decrypt enc_kem_ct with ecc_encKey → kem_ct
6. ML-KEM-768 Decapsulate(kem_ct, HN_mlkem_priv) → ss_pq
7. KDF(ss_pq, SharedInfo1=eph_pub) → pq_encKey || pq_macKey
8. Verify KMAC256(pq_macKey, enc_msin) == mac_pq
9. AES-256-CTR decrypt enc_msin with pq_encKey → MSIN
```

**Key Storage (Profile E):** Same composite key structure as Profile D — two files per Key ID: `hn-key-{id}-profile-e-mlkem.pem` and `hn-key-{id}-profile-e-x25519.pem`.

---

### Profile F (Wrapper Hybrid — ML-KEM-768 + X25519) — Scheme ID 6

Profile F implements a **wrapper hybrid** construction where the standard ECIES (Profile A) encryption is unchanged, and PQC only wraps the ephemeral public key. This provides backward-compatibility friendly PQ protection — the ECIES layer is identical to Profile A.

**Cryptographic Parameters:**
- **ECIES Layer (inner)**: Standard Profile A ECIES — X25519 ECDH, ANSI-X9.63-KDF with SHA-256, HMAC-SHA-256 (8-byte tag), AES-128-CTR
- **PQC Wrapper (outer)**: ML-KEM-768 encapsulate, ANSI-X9.63-KDF with SHA3-256, KMAC256 (32-byte tag), AES-256-CTR

**Scheme Output (Wire Format):**
```
| KEM CT (1088) | Enc Eph PK (32) | Enc MSIN (variable) | MAC_ECIES (8) | MAC_PQ (32) |
```
Minimum length: 1160 bytes (1088 + 32 + 0 + 8 + 32)

**UE Concealment Flow (Profile F):**
```
1. Generate ephemeral X25519 keypair
2. ECDH(eph_priv, HN_x25519_pub) → ss_ecies
3. KDF_SHA256(ss_ecies, SharedInfo1=eph_pub) → ecies_encKey (16) || ecies_macKey (32)
4. AES-128-CTR encrypt MSIN with ecies_encKey → enc_msin
5. HMAC-SHA-256(ecies_macKey, enc_msin)[:8] → mac_ecies (8 bytes)
6. ML-KEM-768 Encapsulate(HN_mlkem_pub) → (kem_ct, ss_pq)
7. KDF_SHA3(ss_pq, SharedInfo1=kem_ct) → pq_encKey (32) || pq_macKey (32)
8. AES-256-CTR encrypt eph_pub with pq_encKey → enc_eph_pub
9. KMAC256(pq_macKey, enc_eph_pub) → mac_pq (32 bytes)
10. Output: kem_ct || enc_eph_pub || enc_msin || mac_ecies || mac_pq
```

**HN De-concealment Flow (Profile F):**
```
1. Parse: kem_ct (1088) | enc_eph_pub (32) | enc_msin (var) | mac_ecies (8) | mac_pq (32)
2. ML-KEM-768 Decapsulate(kem_ct, HN_mlkem_priv) → ss_pq
3. KDF_SHA3(ss_pq, SharedInfo1=kem_ct) → pq_encKey || pq_macKey
4. Verify KMAC256(pq_macKey, enc_eph_pub) == mac_pq
5. AES-256-CTR decrypt enc_eph_pub with pq_encKey → eph_pub
6. ECDH(HN_x25519_priv, eph_pub) → ss_ecies
7. KDF_SHA256(ss_ecies, SharedInfo1=eph_pub) → ecies_encKey || ecies_macKey
8. Verify HMAC-SHA-256(ecies_macKey, enc_msin)[:8] == mac_ecies
9. AES-128-CTR decrypt enc_msin with ecies_encKey → MSIN
```

**Key Storage (Profile F):** Same composite key structure as Profile D — two files per Key ID: `hn-key-{id}-profile-f-mlkem.pem` and `hn-key-{id}-profile-f-x25519.pem`.

---

### Security Comparison: Profile D vs E vs F

| Property | Profile D (Parallel) | Profile E (Nested) | Profile F (Wrapper) |
|----------|---------------------|-------------------|---------------------|
| Scheme ID | 4 | 5 | 6 |
| Architecture | Combined shared secrets | Two independent encryption layers | ECIES unchanged, PQ wraps ephemeral key |
| PQ Resistance | ✓ (hybrid combiner) | ✓ (outer ECC + inner PQ) | ✓ (PQ wraps ephemeral key) |
| Classical Resistance | ✓ (ECDH in combiner) | ✓ (independent ECDH layer) | ✓ (standard ECIES layer) |
| MAC Tags | 1 × 8 B (KMAC256) | 2 × 32 B (KMAC256) | 1 × 8 B (HMAC) + 1 × 32 B (KMAC256) |
| Key Derivation | SHA3-256 combiner + KDF | Separate KDFs per layer | SHA-256 KDF + SHA3-256 KDF |
| Backward Compat | Low | Low | High (inner = Profile A) |
| Output Size | ~1133 B (5-digit MSIN) | ~1189 B (5-digit MSIN) | ~1165 B (5-digit MSIN) |

---

## Future Extensions

### 1. ~~Profile D HN (de-concealment)~~ — **IMPLEMENTED**

Profile D HN de-concealment is now fully implemented: `ParseProfileDCryptogram`, `decryptProfileD`, `DecryptHybrid` in both `pkg/suci/decryptor.go` and `pkg/suciutil/parser.go`. The converter handles scheme ID 4 for both conceal and deconceal operations.

### 2. ~~Profile E (Nested Hybrid)~~ — **IMPLEMENTED**

Profile E is fully implemented: `encryptProfileE`, `decryptProfileE`, `DecryptNestedHybrid`, `ParseProfileECryptogram` across `pkg/suci/encryptor.go`, `pkg/suci/decryptor.go`, and `pkg/suciutil/parser.go`. Scheme ID 5. CLI supports `--profile e` / `--scheme e`.

### 3. ~~Profile F (Wrapper Hybrid)~~ — **IMPLEMENTED**

Profile F is fully implemented: `encryptProfileF`, `decryptProfileF`, `DecryptWrapperHybrid`, `ParseProfileFCryptogram` across `pkg/suci/encryptor.go`, `pkg/suci/decryptor.go`, and `pkg/suciutil/parser.go`. Scheme ID 6. CLI supports `--profile f` / `--scheme f`.

### 2. REST API Service

```go
type SUCIService struct {
    converter *Converter
}

func (s *SUCIService) HandleDeconceal(w http.ResponseWriter, r *http.Request)
func (s *SUCIService) HandleConceal(w http.ResponseWriter, r *http.Request)
```

### 3. Performance Optimizations

- **Connection Pooling**: For HSM/KMS connections
- **Key Caching**: LRU cache for frequently used keys
- **Parallel Processing**: Batch conversion support
- **Hardware Acceleration**: Use AES-NI, AVX instructions

---

## Testing Strategy

### Unit Tests
- Parser validation tests
- Cryptographic operation tests
- Error handling tests
- Mock key store tests

### Integration Tests
- End-to-end conversion tests
- Multiple profile tests
- Key store integration tests

### Performance Tests
- Go benchmarks (mean latency + allocs/op) via `go test -bench ... -benchmem`
- Load generator (tail latency p50/p95/p99 + throughput) via `loadgen`
- CPU and heap profiling via `-cpuprofile`, `-memprofile` + `go tool pprof`

### Security Tests
- Fuzzing input validation
- Timing attack resistance
- Key exposure prevention

---

## Deployment Models

### 1. CLI Tool (Current)
```
User → CLI → Converter → KeyStore → Result
```

### 2. Library Integration
```go
import "github.com/harishmurkal/suci-supi-tool/pkg/suci"

converter := suci.NewConverter(keyStore)
result := converter.ConvertSUCItoSUPI(suciString)
```

### 3. Microservice
```
HTTP Request → REST API → Converter → KeyStore → HTTP Response
```

### 4. Sidecar Container
```
UDM Pod ← gRPC → SUCI-SUPI Sidecar → KMS
```

---

## Scripts

The `scripts/` directory contains build, test, and analysis scripts for both Linux (`.sh`) and Windows (`.ps1`).

| Script | Platform | Description |
|--------|----------|-------------|
| `build.sh` / `build.ps1` | Linux / Windows | Cross-compile binaries for Linux, Windows, and macOS (amd64) |
| `test.sh` / `test.ps1` | Linux / Windows | Run Go unit tests (`./...`) with coverage, then benchmarks (`-bench . -benchmem`) for `pkg/suci` |
| `regression_tests.sh` / `regression_tests.ps1` | Linux / Windows | CLI-level regression suite: sanity, functional, error handling, keygen, conceal/deconceal round-trips (all profiles + D variants), and Go unit tests |
| `details_collector.sh` / `details_collector.ps1` | Linux / Windows | Comprehensive data collection: keygen (A-F), inspect, conceal/deconceal (all profiles + D add17/add19), loadgen, and Go benchmarks. Output logged to a timestamped file. Supports SUPI input, loadgen overrides, and ML-KEM security level selection (`3` or `5`) for profiles C-F. |
| `run_time_with_rss.sh` | Linux | Wrapper that runs a command in the background while polling `/proc/{pid}/status` to report peak RSS (memory) usage |
| `repo_stats.ps1` | Windows | Repository statistics (line counts, file counts, etc.) |

For the details collector scripts, security-level precedence matches the script flags first, then environment, then default:

- Linux: `--security-level`, then `SECURITY_LEVEL` or `DETAILS_SECURITY_LEVEL`, then `3`
- Windows: `-SecurityLevel`, then `SECURITY_LEVEL` or `DETAILS_SECURITY_LEVEL`, then `3`

---

## Dependencies

### External Libraries
- `golang.org/x/crypto` - Curve25519, SHA3, crypto primitives
- `filippo.io/edwards25519` - Edwards25519 field operations
- `github.com/cloudflare/circl` - ML-KEM-768 (PQC) for Profile C, D, E, and F

### Standard Library
- `crypto/aes` - AES encryption
- `crypto/ecdsa` - ECDSA operations
- `crypto/elliptic` - Elliptic curve operations
- `crypto/hmac` - HMAC operations
- `crypto/sha256` - SHA-256 hashing
- `encoding/hex` - Hex encoding/decoding
- `encoding/pem` - PEM file parsing
- `regexp` - Regular expressions

---

## Configuration Management

### Environment Variables
```
HN_KEY_{keyID}_PROFILE_A            - X25519 private key (Profile A)
HN_KEY_{keyID}_PROFILE_B            - P-256 private key (Profile B)
HN_KEY_{keyID}_PROFILE_C            - ML-KEM-768 private key (Profile C)
HN_KEY_{keyID}_PROFILE_D_MLKEM     - ML-KEM-768 private key (Profile D, part 1)
HN_KEY_{keyID}_PROFILE_D_X25519    - X25519 private key (Profile D, part 2)
HN_KEY_{keyID}_PROFILE_E_MLKEM     - ML-KEM-768 private key (Profile E, part 1)
HN_KEY_{keyID}_PROFILE_E_X25519    - X25519 private key (Profile E, part 2)
HN_KEY_{keyID}_PROFILE_F_MLKEM     - ML-KEM-768 private key (Profile F, part 1)
HN_KEY_{keyID}_PROFILE_F_X25519    - X25519 private key (Profile F, part 2)
KEYSTORE_TYPE - file|env|hsm|kms
KEYSTORE_PATH - Path to keys directory
LOG_LEVEL - debug|info|warn|error
SUCI_DEBUG - enable internal debug output (1=true). Also supported: DEBUG
```

### Configuration File (Future)
```yaml
keystore:
  type: file
  path: ./keys
  cache_size: 100
  ttl: 3600

logging:
  level: info
  format: json

api:
  port: 8080
  tls_enabled: true
```

---

This architecture provides a solid foundation for current requirements including full bidirectional SUPI/SUCI conversion across all protection profiles (NULL, A, B, C, D with add17/add19 variants, E, and F) while allowing seamless integration of future enhancements such as service-based deployments and HSM/KMS key management.
