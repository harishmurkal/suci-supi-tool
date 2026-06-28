# SUCI-SUPI Tool Examples

This document provides practical examples for using the SUCI-SUPI conversion tool.

## Table of Contents

- [Key Generation Examples](#key-generation-examples)
- [Key Inspection Examples](#key-inspection-examples)
- [Concealment Examples (SUPI → SUCI)](#concealment-examples-supi--suci)
- [De-concealment Examples (SUCI → SUPI)](#de-concealment-examples-suci--supi)
- [Round-Trip Examples](#round-trip-examples)
- [Environment Variables](#environment-variables)
- [Error Handling Examples](#error-handling-examples)
- [Performance Examples (Benchmarks + LoadGen)](#performance-examples-benchmarks--loadgen)

---

## Key Generation Examples

### Generate a Single Key Pair

```bash
# Generate both Profile A and Profile B keys for Key ID 1
./suci-supi-tool keygen --start-id 1 --output-dir ./keys

# Output:
# Generated 2 key(s) in './keys'
```

### Generate Keys for All Key IDs (0-255)

```bash
# Generate all 512 keys (256 IDs × 2 profiles)
./suci-supi-tool keygen --range 0-255 --output-dir ./keys --verbose

# Output (verbose):
#   Generated: Key ID 0 - Profile A (Curve25519)
#   Generated: Key ID 0 - Profile B (P-256)
#   Generated: Key ID 1 - Profile A (Curve25519)
#   ...
#   Generated: Key ID 255 - Profile B (P-256)
#
# Successfully generated 512 key(s) in './keys'
```

### Generate Only Profile A Keys

```bash
# Generate Curve25519 keys only for IDs 0, 5, 10
./suci-supi-tool keygen --range 0,5,10 --profile a --output-dir ./keys

# Output:
# Generated 3 key(s) in './keys'
```

### Generate Profile C (PQC) Keys

```bash
# Generate ML-KEM-768 (post-quantum) keys for Key ID 1
./suci-supi-tool keygen --start-id 1 --profile c --output-dir ./keys

# Generate all profile keys (A, B, C, D, E, F, and G) for Key IDs 0-10
./suci-supi-tool keygen --range 0-10 --profile all --output-dir ./keys

# Output:
# Generated 77 key(s) in './keys' (7 profiles × 11 IDs)
# Note: profiles D/E/F each write two private key files per Key ID (-mlkem and -x25519).

### Generate Profile D (Hybrid) Keys

```bash
# Generate hybrid Profile D keys (ML-KEM + X25519) for Key ID 1
./suci-supi-tool keygen --start-id 1 --profile d --output-dir ./keys

# Output:
# Generated 1 key(s) in './keys' (Profile D produces ML-KEM + X25519 components)
```

### Generate Profile E (Nested Hybrid) Keys

```bash
# Generate nested hybrid Profile E keys (ML-KEM + X25519) for Key ID 1
./suci-supi-tool keygen --start-id 1 --profile e --output-dir ./keys

# Output:
# Generated 1 key(s) in './keys' (Profile E produces ML-KEM + X25519 components)
```

### Generate Profile F (Wrapper Hybrid) Keys

```bash
# Generate wrapper hybrid Profile F keys (ML-KEM + X25519) for Key ID 1
./suci-supi-tool keygen --start-id 1 --profile f --output-dir ./keys

# Output:
# Generated 1 key(s) in './keys' (Profile F produces ML-KEM + X25519 components)
```

### Generate Profile G (Symmetric) Keys

```bash
# Generate Profile G key bundle for Key ID 1
./suci-supi-tool keygen --start-id 1 --profile g --output-dir ./keys

# Output:
# Generated 1 key(s) in './keys'
# Files:
#   hn-key-1-profile-g.json
#   hn-key-1-profile-g-subscribers.json
```

### Generate Keys with Public Keys

```bash
# Generate keys and save public keys too
./suci-supi-tool keygen --range 0-10 --save-public --output-dir ./keys --verbose

# Creates files:
#   hn-key-0-profile-a.pem      (private)
#   hn-key-0-profile-a.pub.pem  (public)
#   hn-key-0-profile-b.pem      (private)
#   hn-key-0-profile-b.pub.pem  (public)
#   hn-key-0-profile-c.pem      (private - ML-KEM-768)
#   hn-key-0-profile-c.pub.pem  (public - ML-KEM-768)
#   hn-key-0-profile-d-mlkem.pem (private - ML-KEM component)
#   hn-key-0-profile-d-x25519.pem (private - X25519 component)
#   hn-key-0-profile-d-mlkem.pub.pem (public)
#   hn-key-0-profile-d-x25519.pub.pem (public)
#   hn-key-0-profile-e-mlkem.pem (private - ML-KEM component for Profile E)
#   hn-key-0-profile-e-x25519.pem (private - X25519 component for Profile E)
#   hn-key-0-profile-f-mlkem.pem (private - ML-KEM component for Profile F)
#   hn-key-0-profile-f-x25519.pem (private - X25519 component for Profile F)
#   hn-key-0-profile-g.json (private - HN symmetric key bundle)
#   hn-key-0-profile-g-subscribers.json (private - subscriber key map template)
#   ...
```

### Generate Keys in Different Formats

```bash
# PEM format (default, human-readable)
./suci-supi-tool keygen --start-id 1 --format pem --output-dir ./keys

# DER format (binary ASN.1)
./suci-supi-tool keygen --start-id 1 --format der --output-dir ./keys

# Hex format (raw bytes, 3GPP test vectors)
./suci-supi-tool keygen --start-id 1 --format hex --output-dir ./keys

# JWK format (JSON Web Key, REST APIs)
./suci-supi-tool keygen --start-id 1 --format jwk --save-public --output-dir ./keys
```

**Output Files by Format:**

| Format | Private Key File | Public Key File |
|--------|------------------|-----------------|
| PEM | `hn-key-1-profile-a.pem` | `hn-key-1-profile-a.pub.pem` |
| PEM | `hn-key-1-profile-c.pem` | `hn-key-1-profile-c.pub.pem` |
| DER | `hn-key-1-profile-a.der` | `hn-key-1-profile-a.pub.der` |
| Hex | `hn-key-1-profile-a.hex` | `hn-key-1-profile-a.pub.hex` |
| JWK | `hn-key-1-profile-a.jwk` | `hn-key-1-profile-a.pub.jwk` |
| JWK | `hn-key-1-profile-c.jwk` | `hn-key-1-profile-c.pub.jwk` |

---

## Key Inspection Examples

### Basic Key Inspection

```bash
# Inspect a PEM key file (format auto-detected)
./suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-a.pem
```

**Expected Output:**
```
=== Key Information ===
File:        ./keys/hn-key-1-profile-a.pem
Format:      PEM
Type:        PRIVATE_KEY
Profile:     A (X25519/Curve25519)
Algorithm:   X25519
Key Size:    256 bits

Fingerprint: SHA256:abc123...
```

### Show Public Key Derivation

```bash
# Derive and display the public key from a private key
./suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-a.pem --show-public
```

**Expected Output:**
```
=== Key Information ===
File:        ./keys/hn-key-1-profile-a.pem
Format:      PEM
Type:        PRIVATE_KEY
Profile:     A (X25519/Curve25519)
Algorithm:   X25519
Key Size:    256 bits

Public Key (Hex):
  3f1e2d4c5b6a7890...

Fingerprint: SHA256:abc123...
```

### JSON Output (for Scripting)

```bash
# Output key information as JSON
./suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-b.pem --output json
```

**Expected Output:**
```json
{
  "file_path": "./keys/hn-key-1-profile-b.pem",
  "format": "PEM",
  "key_type": "PRIVATE_KEY",
  "profile": "B",
  "scheme": "ECIES",
  "algorithm": "ECDH-P256",
  "curve": "P-256",
  "key_size_bits": 256,
  "fingerprint": "SHA256:abc123..."
}
```

### Inspect Different Formats

```bash
# Inspect Hex format (3GPP test vectors)
./suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-a.hex --show-public

# Inspect JWK format (JSON Web Key)
./suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-b.jwk

# Inspect DER format (binary)
./suci-supi-tool inspect --key-file ./keys/hn-key-1-profile-a.der
```

### Inspect Profile D (Hybrid) Keys

```bash
# Inspect a directory to see Profile D pairs (mlkem + x25519) or single-file combined keys
./suci-supi-tool inspect --key-dir ./keys
```

**Notes:** The `inspect` command detects two-file Profile D keys (`hn-key-{id}-profile-d-mlkem.pem` + `hn-key-{id}-profile-d-x25519.pem`) and single-file combined `hn-key-{id}-profile-d.pem` entries and presents them as a single logical key item.

---

## Concealment Examples (SUPI → SUCI)

### Example 1: NULL-SCHEME Concealment (No Encryption)

```bash
# Conceal SUPI without encryption (NULL-SCHEME)
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme null
```

**Expected Output:**
```
suci-0-123-450-0000-0-0-21436587f9
```

**Explanation:**
- Input: `imsi-123450123456789`
- MCC: `123`, MNC: `450`, MSIN: `123456789`
- Scheme ID: `0` (NULL-SCHEME)
- MSIN encoded as 3GPP TBCD (low nibble first; odd-length MSIN padded with `F`): `21436587f9`

---

### Example 2: Profile A Concealment (Curve25519)

```bash
# First, generate a key if not already done
./suci-supi-tool keygen --start-id 5 --profile a

# Conceal with Profile A
./suci-supi-tool conceal --supi "imsi-310260987654321" --scheme a --key-id 5 --verbose
```

**Expected Output (verbose):**
```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                         SUCI-SUPI Conversion Tool                             ║
║                              Version 1.2.0                                    ║
╚═══════════════════════════════════════════════════════════════════════════════╝
Converting SUPI to SUCI (concealment)...
Input SUPI: imsi-310260987654321

Protection Scheme: ECIES Profile A (Curve25519)
Key ID: 5
Routing Indicator: 0000
Key Directory: ./keys

---

### Example: Profile D Concealment (Hybrid ML-KEM + X25519)

```bash
# Generate Profile D keys if not present
./suci-supi-tool keygen --start-id 1 --profile d --output-dir ./keys

# Conceal with Profile D
./suci-supi-tool conceal --supi "imsi-310260987654321" --scheme d --key-id 1 --verbose
```

**Notes:** Profile D uses a hybrid construction combining ML-KEM-768 and X25519. Home Network keys are stored as a pair (`hn-key-{id}-profile-d-mlkem.pem` and `hn-key-{id}-profile-d-x25519.pem`) or a single-file concatenation (`hn-key-{id}-profile-d.pem`).

---

### Example: Profile E Concealment (Nested Hybrid)

```bash
# Generate Profile E keys if not present
./suci-supi-tool keygen --start-id 1 --profile e --output-dir ./keys

# Conceal with Profile E (Nested Hybrid)
./suci-supi-tool conceal --supi "imsi-310260987654321" --scheme e --key-id 1 --verbose
```

**Expected Output:**
```
suci-0-310-260-0000-5-1-<32-byte-eph-pubkey><1088-byte-enc-kem-ct><enc-msin><32-byte-mac-ecc><32-byte-mac-pq>
```

**Explanation:**
- Scheme ID: `5` (Profile E - Nested Hybrid)
- Two independent encryption layers: ECC protects KEM ciphertext, PQ protects MSIN
- Two 32-byte KMAC256 MAC tags (instead of one 8-byte tag)

---

### Example: Profile F Concealment (Wrapper Hybrid)

```bash
# Generate Profile F keys if not present
./suci-supi-tool keygen --start-id 1 --profile f --output-dir ./keys

# Conceal with Profile F (Wrapper Hybrid)
./suci-supi-tool conceal --supi "imsi-310260987654321" --scheme f --key-id 1 --verbose
```

**Expected Output:**
```
suci-0-310-260-0000-6-1-<1088-byte-kem-ct><32-byte-enc-eph-pubkey><enc-msin><8-byte-mac-ecies><32-byte-mac-pq>
```

**Explanation:**
- Scheme ID: `6` (Profile F - Wrapper Hybrid)
- Standard ECIES (Profile A) is unchanged; PQ wraps the ephemeral key
- HMAC-SHA-256 (8 bytes) for ECIES + KMAC256 (32 bytes) for PQ wrapper

✓ Concealment successful!
SUCI: suci-0-310-260-0000-1-5-<32-byte-ephemeral-pubkey><ciphertext><8-byte-mac>
Key ID used: 5
```

---

### Example: Profile G Concealment (Symmetric)

```bash
# 1) Generate Profile G key files (main key + subscriber map template)
./suci-supi-tool keygen --start-id 1 --profile g --output-dir ./keys

# 2) Edit subscriber map and set real Kmaster values (example entry shown)
#    keys/hn-key-1-profile-g-subscribers.json:
#    { "subscribers": { "0011223344": "00112233445566778899aabbccddeeff" } }

# 3) Conceal using scheme g and subscriber-key-id
./suci-supi-tool conceal \
  --supi "imsi-310260987654321" \
  --scheme g \
  --key-id 1 \
  --subscriber-key-id 0011223344 \
  --key-dir ./keys
```

**Notes:**
- Profile G uses Scheme ID `7` and the HN key ID field as the Profile-G key bundle selector.
- `--subscriber-key-id` is required for `conceal --scheme g` (5 bytes / 10 hex chars).
- De-concealment for Profile G uses file-based key material only and tries `{current_window, previous_window}`.

---

## End-to-End Profile D Example (Keygen → Env Vars → Deconceal)

This example demonstrates generating Profile D keys, creating a SUCI with `conceal`, exporting the Profile D private components to environment variables, and successfully de-concealing the SUCI using `--use-env`.

Bash (Linux/macOS):

```bash
# 1) Generate Profile D keys (ML-KEM + X25519) for Key ID 251
./suci-supi-tool keygen --start-id 251 --profile d --output-dir ./keys --save-public

# 2) Conceal a SUPI to produce a SUCI (uses key-dir public components)
SUCI=$(./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme d --key-id 251 --key-dir ./keys)
echo "Generated SUCI: $SUCI"

# 3) Export Profile D private components into environment variables (PEM content)
export HN_KEY_251_PROFILE_D_MLKEM="$(cat keys/hn-key-251-profile-d-mlkem.pem)"
export HN_KEY_251_PROFILE_D_X25519="$(cat keys/hn-key-251-profile-d-x25519.pem)"

# 4) De-conceal using the environment-backed keystore
./suci-supi-tool deconceal --suci "$SUCI" --use-env

# Expected output:
# imsi-123450123456789
```

PowerShell (Windows):

```powershell
# 1) Generate Profile D keys
.\suci-supi-tool keygen --start-id 251 --profile d --output-dir .\keys --save-public

# 2) Conceal to obtain SUCI
$SUCI = .\suci-supi-tool conceal --supi "imsi-123450123456789" --scheme d --key-id 251 --key-dir .\keys
Write-Host "Generated SUCI: $SUCI"

# 3) Export env vars with PEM content
$env:HN_KEY_251_PROFILE_D_MLKEM = Get-Content -Raw .\keys\hn-key-251-profile-d-mlkem.pem
$env:HN_KEY_251_PROFILE_D_X25519 = Get-Content -Raw .\keys\hn-key-251-profile-d-x25519.pem

# 4) De-conceal using env-backed keystore
.\suci-supi-tool deconceal --suci $SUCI --use-env

# Expected output:
# imsi-123450123456789
```

### Example 3: Profile B Concealment (P-256)

```bash
# Generate Profile B key
./suci-supi-tool keygen --start-id 101 --profile b

# Conceal with Profile B and custom routing indicator
./suci-supi-tool conceal \
  --supi "imsi-001011234567890" \
  --scheme b \
  --key-id 101 \
  --routing-ind 1234
```

**Expected Output:**
```
suci-0-001-011-1234-2-101-<33-byte-compressed-pubkey><ciphertext><8-byte-mac>
```

---

### Example 4: Profile C Concealment (ML-KEM-768 - PQC)

```bash
# Generate Profile C key (post-quantum)
./suci-supi-tool keygen --start-id 1 --profile c

# Conceal with Profile C (ML-KEM-768)
./suci-supi-tool conceal \
  --supi "imsi-310260987654321" \
  --scheme c \
  --key-id 1
```

**Expected Output:**
```
suci-0-310-260-0000-3-1-<1088-byte-kem-ciphertext><ciphertext><8-byte-kmac-tag>
```

**Explanation:**
- Scheme ID: `3` (Profile C - PQC)
- Uses ML-KEM-768 encapsulation (NIST FIPS 203)
- KDF: ANSI-X9.63-KDF with SHA3-256
- MAC: KMAC256 with 64-bit tag
- Encryption: AES-256-CTR

---

### Example 5: Auto Key Selection

```bash
# Generate some keys first
./suci-supi-tool keygen --range 0,5,10 --output-dir ./keys

# Conceal with auto key selection (-1 or omit --key-id)
./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme a --key-dir ./keys
```

The tool will automatically select the first available key from the keystore. If no keys exist, it will generate a new key with ID 0.

---

## De-concealment Examples (SUCI → SUPI)

### Example 5: NULL-SCHEME De-concealment

```bash
./suci-supi-tool deconceal \
  --suci "suci-0-123-45-012-0-0-1032547698"
```

**Expected Output:**
```
imsi-123450123456789
```

---

### Example 6: Profile A De-concealment

```bash
./suci-supi-tool deconceal \
  --suci "suci-0-310-260-1234-1-5-..." \
  --key-dir ./keys \
  --verbose
```

---

### Example 7: Profile B De-concealment

```bash
./suci-supi-tool deconceal \
  --suci "suci-0-001-01-0000-2-101-..." \
  --key-dir ./keys
```

---

### Example 8: Profile C De-concealment (ML-KEM-768 - PQC)

```bash
# De-conceal a Profile C SUCI (post-quantum)
./suci-supi-tool deconceal \
  --suci "suci-0-310-260-0000-3-1-..." \
  --key-dir ./keys \
  --verbose
```

**Explanation:**
- Scheme ID `3` triggers PQC decryption
- Uses ML-KEM-768 decapsulation
- Verifies KMAC256 MAC tag
- Decrypts with AES-256-CTR

---

### Example 9: Profile D De-concealment (Hybrid)

```bash
# De-conceal a Profile D SUCI (hybrid ML-KEM + X25519)
./suci-supi-tool deconceal \
  --suci "suci-0-310-260-0000-4-1-..." \
  --key-dir ./keys \
  --verbose
```

**Notes:** The tool will locate both `hn-key-{id}-profile-d-mlkem.pem` and `hn-key-{id}-profile-d-x25519.pem` or accept a single-file `hn-key-{id}-profile-d.pem` containing concatenated PEM blocks.

---

### Example 10: Profile E De-concealment (Nested Hybrid)

```bash
# De-conceal a Profile E SUCI (nested hybrid ML-KEM + X25519)
./suci-supi-tool deconceal \
  --suci "suci-0-310-260-0000-5-1-..." \
  --key-dir ./keys \
  --verbose
```

**Notes:** The tool will locate `hn-key-{id}-profile-e-mlkem.pem` and `hn-key-{id}-profile-e-x25519.pem`.

---

### Example 11: Profile F De-concealment (Wrapper Hybrid)

```bash
# De-conceal a Profile F SUCI (wrapper hybrid ML-KEM + X25519)
./suci-supi-tool deconceal \
  --suci "suci-0-310-260-0000-6-1-..." \
  --key-dir ./keys \
  --verbose
```

**Notes:** The tool will locate `hn-key-{id}-profile-f-mlkem.pem` and `hn-key-{id}-profile-f-x25519.pem`.

---

## Round-Trip Examples

### Example 9: Complete Round-Trip (Profile A)

```bash
# Step 1: Generate a key
./suci-supi-tool keygen --start-id 1 --profile a

# Step 2: Conceal SUPI to SUCI
SUCI=$(./suci-supi-tool conceal --supi "imsi-123450123456789" --scheme a --key-id 1)
echo "Concealed SUCI: $SUCI"

# Step 3: De-conceal SUCI back to SUPI
SUPI=$(./suci-supi-tool deconceal --suci "$SUCI")
echo "De-concealed SUPI: $SUPI"

# Expected: imsi-123450123456789
```

### Example 10: Complete Round-Trip (Profile B)

```bash
# Generate and test Profile B
./suci-supi-tool keygen --start-id 5 --profile b

SUCI=$(./suci-supi-tool conceal --supi "imsi-999991234567890" --scheme b --key-id 5)
echo "SUCI: $SUCI"

./suci-supi-tool deconceal --suci "$SUCI" --verbose
# Output: imsi-999991234567890
```

### Example 11: Complete Round-Trip (Profile C - PQC)

```bash
# Generate PQC key
./suci-supi-tool keygen --start-id 1 --profile c

# Conceal with ML-KEM-768
SUCI=$(./suci-supi-tool conceal --supi "imsi-310260987654321" --scheme c --key-id 1)
echo "SUCI (PQC): $SUCI"

# De-conceal back to SUPI
./suci-supi-tool deconceal --suci "$SUCI"
# Output: imsi-310260987654321
```

### Example 12: Complete Round-Trip (Profile E - Nested Hybrid)

```bash
# Generate Profile E key
./suci-supi-tool keygen --start-id 1 --profile e

# Conceal with Nested Hybrid
SUCI=$(./suci-supi-tool conceal --supi "imsi-310260987654321" --scheme e --key-id 1)
echo "SUCI (Nested): $SUCI"

# De-conceal back to SUPI
./suci-supi-tool deconceal --suci "$SUCI"
# Output: imsi-310260987654321
```

### Example 13: Complete Round-Trip (Profile F - Wrapper Hybrid)

```bash
# Generate Profile F key
./suci-supi-tool keygen --start-id 1 --profile f

# Conceal with Wrapper Hybrid
SUCI=$(./suci-supi-tool conceal --supi "imsi-310260987654321" --scheme f --key-id 1)
echo "SUCI (Wrapper): $SUCI"

# De-conceal back to SUPI
./suci-supi-tool deconceal --suci "$SUCI"
# Output: imsi-310260987654321
```

---

## Environment Variables

### Example 10: Using Environment Variables for Keys

```bash
# Export private key as environment variable
export HN_KEY_5_PROFILE_A="$(cat keys/hn-key-5-profile-a.pem)"

# Run with env flag
./suci-supi-tool deconceal \
  --suci "suci-0-310-260-1234-1-5-..." \
  --use-env
```

```bash
# Profile D uses two environment variables (both PEMs required)
export HN_KEY_1_PROFILE_D_MLKEM="$(cat keys/hn-key-1-profile-d-mlkem.pem)"
export HN_KEY_1_PROFILE_D_X25519="$(cat keys/hn-key-1-profile-d-x25519.pem)"
./suci-supi-tool deconceal --suci "..." --use-env
```

```bash
# Profile E/F follow the same pattern
export HN_KEY_1_PROFILE_E_MLKEM="$(cat keys/hn-key-1-profile-e-mlkem.pem)"
export HN_KEY_1_PROFILE_E_X25519="$(cat keys/hn-key-1-profile-e-x25519.pem)"
./suci-supi-tool deconceal --suci "..." --use-env
```

Note: the tool also supports runtime debug logging. Set `SUCI_DEBUG=1` or `DEBUG=1`, or pass `--debug` / `-d` to enable internal debug output.

---

## Error Handling Examples

### Example 6: Invalid SUCI Format

```bash
./suci-supi-tool deconceal --suci "invalid-format"
```

**Output:**
```
Error: error-0101: Invalid SUCI format
```

---

### Example 7: Missing Private Key

```bash
./suci-supi-tool deconceal \
  --suci "suci-0-310-260-1234-1-99-..."
```

**Output:**
```
Error: error-0304: Key ID not found in key store
```

---

### Example 8: MAC Verification Failure

When using wrong private key:

```bash
./suci-supi-tool deconceal \
  --suci "suci-0-310-260-1234-1-5-..." \
  --key-dir ./wrong-keys
```

**Output:**
```
Error: error-0202: MAC verification failed
```

---

## Cryptogram Structure Examples

### Profile A Cryptogram Breakdown

For a SUCI using Profile A (Curve25519):

```
Scheme Output (hex): 
  a1b2c3d4... (32 bytes ephemeral pubkey)
  + e5f61234... (variable length ciphertext)
  + 5a6b7c8d9e0f1a2b (8 bytes MAC tag)
```

**Minimum length:** 40 bytes (32 + 0 + 8)

### Profile B Cryptogram Breakdown

For a SUCI using Profile B (P-256):

```
Scheme Output (hex):
  02/03 + x-coordinate (33 bytes compressed pubkey)
  + ciphertext (variable length)
  + MAC tag (8 bytes)
```

**Minimum length:** 41 bytes (33 + 0 + 8)

---

## Testing Workflow

### Complete Test Sequence

```bash
# 1. Build the tool
go build -o suci-supi-tool .

# 2. Create keys directory
mkdir -p keys

# 3. Generate test keys
openssl genpkey -algorithm X25519 -out keys/hn-key-1-profile-a.pem
openssl ecparam -name prime256v1 -genkey -noout -out keys/hn-key-1-profile-b.pem

# 4. Test NULL-SCHEME
./suci-supi-tool deconceal \
  --suci "suci-0-123-45-012-0-0-1032547698" \
  --verbose

# 5. View help
./suci-supi-tool help

# 6. Check version
./suci-supi-tool version
```

---

## Integration Examples

### Docker Integration

```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .
RUN go build -o suci-supi-tool .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/suci-supi-tool .

ENTRYPOINT ["./suci-supi-tool"]
CMD ["help"]
```

### Kubernetes Secret for Keys

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: hn-private-keys
type: Opaque
data:
  HN_KEY_5_PROFILE_A: <base64-encoded-pem>
  HN_KEY_101_PROFILE_B: <base64-encoded-pem>
```

---

## Performance Testing

### Benchmark Example

```bash
# Create test script
cat > test-benchmark.sh << 'EOF'
#!/bin/bash
for i in {1..1000}; do
  ./suci-supi-tool deconceal \
    --suci "suci-0-123-45-012-0-0-1032547698" \
    > /dev/null
done
EOF

chmod +x test-benchmark.sh

# Run benchmark
time ./test-benchmark.sh
```

---

## Debugging Tips

### Enable Verbose Mode

```bash
./suci-supi-tool deconceal \
  --suci "..." \
  --verbose
```

### Verify Key Format

```bash
# Check Profile A key
openssl pkey -in keys/hn-key-5-profile-a.pem -text -noout

# Check Profile B key
openssl ec -in keys/hn-key-101-profile-b.pem -text -noout
```

### Decode Scheme Output Manually (NULL-SCHEME TBCD)

For NULL-SCHEME, the scheme output is MSIN in TBCD (two decimal digits per byte, low nibble first; the last nibble is `F` if the MSIN has an odd number of digits). Example MSIN `0123456789` → hex payload `1032547698` (5 bytes). You can inspect raw bytes with:

```bash
echo "1032547698" | xxd -r -p | xxd -p
# e.g. 1032547698
```

---

## Production Recommendations

1. **Key Rotation**: Regularly rotate Home Network keys
2. **Monitoring**: Log all conversion attempts and failures
3. **Rate Limiting**: Implement rate limiting for API endpoints
4. **Audit Trail**: Maintain audit logs for compliance
5. **HSM Integration**: Use Hardware Security Modules in production
6. **Backup Keys**: Securely backup private keys with proper encryption

---

For more information, see the main [README.md](README.md) or run:
```bash
./suci-supi-tool help
```

---

## Performance Examples (Benchmarks + LoadGen)

Use **benchmarks** for mean latency + allocations (`ns/op`, `B/op`, `allocs/op`), and use **loadgen** for tail latency (p50/p95/p99) + throughput under concurrency.

### Mean latency + allocations (benchmarks)

```powershell
# End-to-end (parse + crypto + SUPI construction)
go test .\pkg\suci -bench "ConvertSUCItoSUPI_ProfileA_EndToEnd" -benchmem -count=1

# Crypto-only (decrypt + MSIN decode; excludes SUCI parsing)
go test .\pkg\suci -bench "Deconceal_ProfileA_DecryptOnly$" -benchmem -count=1

# Parse-only
go test .\pkg\suci -bench "ParseSUCI_ProfileA$" -benchmem -count=1

# Parallel scaling
go test .\pkg\suci -bench "DecryptOnly_Parallel$" -benchmem -count=1 -cpu 1,2,4,8
```

### Tail latency + throughput (load generator)

```powershell
# End-to-end SUCI→SUPI with p50/p95/p99
go run . loadgen --scheme a --mode end-to-end --n 100000 --concurrency 8 --warmup 1000

# Crypto-only
go run . loadgen --scheme a --mode decrypt-only --n 100000 --concurrency 8 --warmup 1000

# Parse-only
go run . loadgen --scheme a --mode parse-only --n 100000 --concurrency 8 --warmup 1000

# JSON output
go run . loadgen --scheme b --mode end-to-end --n 50000 --concurrency 16 --output json
```

### RSS 
```powershell
./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -mode decrypt-only -scheme b -concurrency 1                             
```

### Quick Commands

./build/suci-supi-tool-linux-amd64 keygen -profile a -range 1-10 -save-public -verbose
./build/suci-supi-tool-linux-amd64 keygen -profile b -range 1-10 -save-public -verbose
./build/suci-supi-tool-linux-amd64 keygen -profile c -range 1-10 -save-public -verbose
./build/suci-supi-tool-linux-amd64 keygen -profile d -range 1-10 -save-public -verbose
./build/suci-supi-tool-linux-amd64 keygen -profile e -range 1-10 -save-public -verbose
./build/suci-supi-tool-linux-amd64 keygen -profile f -range 1-10 -save-public -verbose

./build/suci-supi-tool-linux-amd64 inspect -key-dir ./keys/ -show-public -show-private

./build/suci-supi-tool-linux-amd64 inspect -key-file ./keys/hn-key-10-profile-a.pem -show-public -show-private
./build/suci-supi-tool-linux-amd64 inspect -key-file ./keys/hn-key-10-profile-a.pub.pem -show-public -show-private

./build/suci-supi-tool-linux-amd64 inspect -key-file ./keys/hn-key-10-profile-b.pem -show-public -show-private
./build/suci-supi-tool-linux-amd64 inspect -key-file ./keys/hn-key-10-profile-b.pub.pem -show-public -show-private

./build/suci-supi-tool-linux-amd64 inspect -key-file ./keys/hn-key-10-profile-c.pem -show-public -show-private
./build/suci-supi-tool-linux-amd64 inspect -key-file ./keys/hn-key-10-profile-c.pub.pem -show-public -show-private

./build/suci-supi-tool-linux-amd64 inspect -key-file ./keys/hn-key-10-profile-d-mlkem.pem -show-public -show-private
./build/suci-supi-tool-linux-amd64 inspect -key-file ./keys/hn-key-10-profile-d-mlkem.pub.pem -show-public -show-private
./build/suci-supi-tool-linux-amd64 inspect -key-file ./keys/hn-key-10-profile-d-x25519.pem -show-public -show-private
./build/suci-supi-tool-linux-amd64 inspect -key-file ./keys/hn-key-10-profile-d-x25519.pub.pem -show-public -show-private

./build/suci-supi-tool-linux-amd64 conceal -key-id 1 -routing-ind 0000 -scheme a -supi imsi-123456789012345 -verbose
./build/suci-supi-tool-linux-amd64 deconceal -verbose -suci suci-0-123-456-0000-1-1-543b7a77d5a23b5d82d19b91bcebb342bed4e30b8edbda1dc7b4d018acd6fb711a2cb572f7297729013a49c81b1117b6cf

./build/suci-supi-tool-linux-amd64 conceal -key-id 1 -routing-ind 0000 -scheme b -supi imsi-123456789012345 -verbose
./build/suci-supi-tool-linux-amd64 deconceal -verbose -suci suci-0-123-456-0000-2-1-0395b187635a1813a0244352aa91363c37f08e4eec8aa406d51876f9748fca140868b0a13512c4d53056a0e5d2c3b6574e94

./build/suci-supi-tool-linux-amd64 conceal -key-id 1 -routing-ind 0000 -scheme c -supi imsi-123456789012345 -verbose
./build/suci-supi-tool-linux-amd64 deconceal -verbose -suci suci-0-123-456-0000-3-1-a925f2eff5093e9cc8ca97983e03982e4a01e17d693c3c4c8b578f9887fd6aa8d27dc702507bcdb583e67bb7e29d74f67959457248c22719b68b1fda3aa923a0846b451505047012fd32f32af5ed1b378e015b69774fcf3bad0213fa6f7e1f2f228e9ab58d763eecaf13422bd2be5c6ba637a82345a7d4466ca2acf00c41e56e8ee5117d5e84e24671441f8e356ffd427bf6124a2285dff4096e7db30c47bb48e34d5a03c725b455a6920ebcf0ed9cf808e27bba18e9f14f309340b070fbf4943806a93db4633a8f31e9b9e0595190323a4bec43a8911d911c881163ab538e42679b1d574233d2b19c148f2ddd5100986ceb3a36cadbee4cd948bb165ae811c701518cb474c4deee5733439515435fef5b53496d8839cc84455a25bd8dbb2273174b7909ede219f8f2b12f924721ef3636e5fea547424ccb35eac66582026eb8d49f322ff6fa63994b1cfa7a8960419e0c74ae4536d5c069fbd69d8bb57029aaaeece4eacb918336b2fb6d6abe9115e84a9ad7884c236bc4592e32dad9ec102024fbf98a3b29391d5fa2bffa3356caac8ad41dc44034bee633c88865f818ff260c57297f216914099b53d38d2060a280b34efc315c66e7219771ae389c783c494a3152595b266c1a06f4aaef9b8d4bea58178991020c81696bd5ba0606aea4c1f3923d1c8a32d61c2251fb36f5a337849b2567de6886fe39db35dca944723ad9e1de354e3dd159013325c2831f17486099372e648e187b4b83aaf999e91610b1f7c3c2d8954f87f18736bd3307aa8a4d4a5cd43ca16de03a820018a123cf7a29012649cd26dda3e8305a2cde0e37c882bccb0141d825a37bb52e1bd9216aa2620b0855f494dd04675dbbb9b7f4037363f21e91a8e5f84b61ce5242f9d695cd19551f8dbb6acadd6f22fc2065afa77342ef1c66f65bfbe95d6aba976b443d7c07390dc85d8eb152d64577dcd60dbb56b32e3e64ba5ce1d5ac5dda06a389971534b795be39613640510c295d89c5d2c63f74a9a1e0ddda21c438e1cbd98f7cdc52455c414c0c1c99e7b20ccbd28d984663ef705b3d7af2828e6f4a1cd46d4b407bc6d5b5d834bae62575c75f724971a2930675712381736dc059f72c031552211345ddbd4c225207d53b09791c1863036e6ffd483a8b6c8645fb97876d92c978a9b29790768d60940b19e872453128c42429ee97e6bb18fc0892f68346ef364ddba7bf04eb1706b3a6831fe3638887b7db4d5efe891558478a26fc5a8dfc698cef19fc6d25c8e4e9967d40ccc76aafe8f61938145a52c2f4bb3bf0c3a1fa5ff94fa69571aef4b47a4c27d4da7f5c82d029036c4e701d26c7f58eebb4d1d88a70fb037cd70e3e672a0d94fce870f167555293beb546d90af599c96583e3220b25e8a6f2900bb90df4997d4c5bc28b0719015df65024eb928098d0b3cc39dfd05526c15d59fddaf4887d268c347f99cbbeb3d4dd904b18fdbf1de88491ec9cabbf6fa3ce76568c83736e76d39c008c2d8007f43c0e09dafe8800d17e9aea26b6b867de866c4a0aaf75263dd2b07b02e79d9d05

./build/suci-supi-tool-linux-amd64 conceal -key-id 1 -routing-ind 0000 -scheme d -supi imsi-123456789012345 -verbose
./build/suci-supi-tool-linux-amd64 deconceal -verbose -suci suci-0-123-456-0000-4-1-dd67de2fc52d11dc05364155fed8c0f35f4f9439cf2ed7862dc625d37f4de9ef997353073012b2e00a6f102e180116e6fe4a67659ba131b0cdafb266de51f2c7c6837681c35f1d6d3d91b89f83a348c5d62dbbb3e0d7b002c39b9124d0b8a7c87b8428b84c32763de93fd7ff7e48e8d6dfa17e5e3651c82c6727bea2b71cd2a5f58c88524579a9c447ff739cdfbca2a1980a9cd5418052810f257b1c4606869146fa46d5fee008af384383984530a7ac791bfbfb1bb057c8b38d1df476cbc002a44a2dd5ac321a4cd9421e0b7e00a4ae9ff0c325ce8d320f2b22c254d115936434a1d2769df22ec5721fbc9fe2e3e8ecf15419ec7ec7f33e54bd8ad3929b3168c05324e99f07435074ab5ed653edccbd207068ab3f39a1c75063966736c10d17cca6a30984a454f89d17fbbd8648c02d03b9de50809093008a0a86c1c5280d89bdd94f63ab067ae7ad178057ce0a6495b45d4ba1ff1ac59d07ea5849a6d7b827c4a3d38dacf0ba06e036dbcbbed59d7dc7380840de446f01e615386a73375f3c899c18fe98d062867ba479b9cc70fba05cce22e650526c83086480aea687c9976f895b118a4f891d4b3a838d35d558463fd55e4bf06b38dd24c09eaa46b3399ebe8c4360795d71d652fda402cb1f5353ce57a09598e2672e24ca0f25573d8c449bce9bf1001a9070b5e74bdf3ea3b35bb8e6de17f2f026f0327c78fdf989859f0c28d864088b65ad0e019e1c011f0be923829267724976a1bb38777f9dff049afbc66376c434eaaa7713b83c37de928b60ded135156eccd83cbf281163868ce5d32f649cc6ecbb4d3f02a6043083794582d6180609158aa3150f60a891feecd8ee4cb6a38a429d88c5eaa5421306a8168c376a90b628a5e2a70f27373149671d8aed35bb25fb78f5971ae905a1440c563b87829aff6af8192cc0119da97348be30f82f428739c95f0cf82d422e78a1ab7792bd976c3c718fe97842ab19a7a27b530932b714f0d6009d7972541c00427bc0927534bc7e9b1efb1c7392a853fafaea54daba5c92919d87825d823e309c0adf026e3d702f87b279ac0f28bda348a406e749b8310ebeaa640c92ae2a1c37f69082be1fde650d961d5f8241e891714b04f6b673ae103830cb35306842a24d1339ca012768950e8be08fe5a58ea85a5345cfed0fc5cd2dd68850e8c44d6c3e4e5c11546b33da453663b57751f43c3e26a86dbd429152717f6d8330d693743ca0e55f8f32653e657271ad43115bdcd8fa03b928fe06e4a185af39636b3e942e6254b288f99cf6db9113655f6a0a41ae0768ca2b06675a4805421d46143e09514e89cdad61a8d42b30d9fb5e93309720dd1e1054dff68ad4709f637eff8e126c4e14c1e140de800232d4f52216218f337d9fc29070ede689098958b77848e2c517417c7bb6d73415ea2feecf4530c875f3c5de8f770f6e2314c656646f7c037a69a228fc5419d990a0b56c9eaf6ea4b463f202b8d2bd6dfa12d7494c706ded2f918b4ca2084ed3d5b667a78ada6928fe659a648ee280442b3a9960c06183d33b628ef51522a455d6f7bcad0e233512dc79842114736c47b16546cc055f6b85703c36

./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -concurrency 1 -n 100000 -warmup 1000 -scheme a -mode parse-only
./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -concurrency 1 -n 100000 -warmup 1000 -scheme a -mode decrypt-only
./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -concurrency 1 -n 100000 -warmup 1000 -scheme a -mode end-to-end

./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -concurrency 1 -n 100000 -warmup 1000 -scheme b -mode parse-only
./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -concurrency 1 -n 100000 -warmup 1000 -scheme b -mode decrypt-only
./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -concurrency 1 -n 100000 -warmup 1000 -scheme b -mode end-to-end

./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -concurrency 1 -n 100000 -warmup 1000 -scheme c -mode parse-only
./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -concurrency 1 -n 100000 -warmup 1000 -scheme c -mode decrypt-only
./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -concurrency 1 -n 100000 -warmup 1000 -scheme c -mode end-to-end

./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -concurrency 1 -n 100000 -warmup 1000 -scheme d -mode parse-only
./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -concurrency 1 -n 100000 -warmup 1000 -scheme d -mode decrypt-only
./run_time_with_rss.sh ./build/suci-supi-tool-linux-amd64 loadgen -concurrency 1 -n 100000 -warmup 1000 -scheme d -mode end-to-end
