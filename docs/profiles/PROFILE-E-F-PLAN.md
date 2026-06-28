# Profile E & F Implementation Plan — ✅ COMPLETED

**Status:** All tasks completed and verified  
**Completion Date:** March 19, 2026  
**Version:** 1.4.0

---

## Original Plan

Reference files used as authoritative input:

- `suci-supi-tool/docs/profile-e-group-b2.md` — Profile E (Nested Hybrid, Group B2)
- `suci-supi-tool/docs/profile-f-group-c.md` — Profile F (Wrapper Hybrid, Group C)

---

## Task Completion Summary

### ✅ 1. Design Profile-E implementation (Nested Hybrid — Scheme ID 5)

**Implemented in:**
- `pkg/suci/encryptor.go` — `encryptProfileE()`
- `pkg/suci/decryptor.go` — `decryptProfileE()`, `DecryptNestedHybrid()`
- `pkg/suciutil/parser.go` — `ParseProfileECryptogram()`, `DecryptNestedHybrid()`
- `pkg/suci/types.go` — `ProfileECryptogram`, `SchemeProfileE = 5`
- `pkg/suci/compat.go` — `ParseProfileECryptogram()` wrapper, type aliases

**UE Flow:** Ephemeral X25519 → ECDH → AES-256-CTR encrypt KEM CT → ML-KEM encap → AES-256-CTR encrypt MSIN → dual KMAC256 MACs  
**HN Flow:** ECDH → verify MAC_ECC → decrypt KEM CT → ML-KEM decap → verify MAC_PQ → decrypt MSIN

**Byte Layout:**
```
| Eph X25519 PK (32) | Enc KEM CT (1088) | Enc MSIN (var) | MAC_ECC (32) | MAC_PQ (32) |
```
Minimum: 1184 bytes

### ✅ 2. Design Profile-F implementation (Wrapper Hybrid — Scheme ID 6)

**Implemented in:**
- `pkg/suci/encryptor.go` — `encryptProfileF()`
- `pkg/suci/decryptor.go` — `decryptProfileF()`, `DecryptWrapperHybrid()`
- `pkg/suciutil/parser.go` — `ParseProfileFCryptogram()`, `DecryptWrapperHybrid()`
- `pkg/suci/types.go` — `ProfileFCryptogram`, `SchemeProfileF = 6`
- `pkg/suci/compat.go` — `ParseProfileFCryptogram()` wrapper, type aliases

**UE Flow:** Standard ECIES (Profile A) encrypt MSIN → ML-KEM encap → AES-256-CTR encrypt eph pub → KMAC256 MAC  
**HN Flow:** ML-KEM decap → verify PQ MAC → decrypt eph pub → ECDH → verify ECIES MAC → decrypt MSIN

**Byte Layout:**
```
| KEM CT (1088) | Enc Eph PK (32) | Enc MSIN (var) | MAC_ECIES (8) | MAC_PQ (32) |
```
Minimum: 1160 bytes

### ✅ 3. CLI changes

**Implemented in:** `main.go`

- `--profile e` / `--profile nested` for keygen
- `--profile f` / `--profile wrapper` for keygen
- `--scheme e` / `--scheme nested` for conceal
- `--scheme f` / `--scheme wrapper` for conceal
- Verbose output shows "Nested Hybrid Profile E" / "Wrapper Hybrid Profile F"

### ✅ 4. Go code changes

- **New structs:** `ProfileECryptogram`, `ProfileFCryptogram` (in `types.go` and `suciutil/parser.go`)
- **Type aliases:** `ProfileEPrivateKeys`, `ProfileEPublicKeys`, `ProfileFPrivateKeys`, `ProfileFPublicKeys` = `ProfileDPrivateKeys`/`ProfileDPublicKeys`
- **New cryptogram formats:** Wire format parsing in `ParseProfileECryptogram()`, `ParseProfileFCryptogram()`
- **Encrypt/decrypt functions:** `encryptProfileE()`, `encryptProfileF()`, `decryptProfileE()`, `decryptProfileF()`
- **Converter integration:** `handleEncryptedScheme()` updated for scheme IDs 5 and 6
- **Keystore:** `FileKeyStore.GetPrivateKey()` and `EnvKeyStore.GetPrivateKey()` updated for profiles E and F
- **Keygen:** `generateProfileEKey()`, `generateProfileFKey()`, `saveCompositeKeyPair()` with profile suffix

### ✅ 5. Implementation (replaces pseudocode)

Full Go implementation across 11 source files — all compiling and working.

### ✅ 6. Security comparison

| Property | Profile D (Parallel) | Profile E (Nested) | Profile F (Wrapper) |
|----------|---------------------|-------------------|---------------------|
| Scheme ID | 4 | 5 | 6 |
| Architecture | Combined shared secrets | Two independent encryption layers | ECIES unchanged, PQ wraps eph key |
| PQ Resistance | ✓ (hybrid combiner) | ✓ (outer ECC + inner PQ) | ✓ (PQ wraps ephemeral key) |
| Classical Resistance | ✓ (ECDH in combiner) | ✓ (independent ECDH layer) | ✓ (standard ECIES layer) |
| MAC Tags | 1 × 8 B | 2 × 32 B | 1 × 8 B + 1 × 32 B |
| Backward Compat | Low | Low | High (inner = Profile A) |

### ✅ 7. Benchmarks and testing

**16 unit tests added** covering:
- Scheme ID validation for E/F
- Round-trip encrypt/decrypt for E/F
- Empty MSIN edge case for E/F
- Wrong key detection for E/F
- Public key derivation for E/F
- End-to-end converter integration for E/F
- Constants validation for E/F
- Cryptogram parsing edge cases for E/F

**CLI verification:**
- `keygen --profile e` → generates ML-KEM + X25519 key pair
- `keygen --profile f` → generates ML-KEM + X25519 key pair
- `conceal --scheme e` → produces SUCI with scheme ID 5
- `conceal --scheme f` → produces SUCI with scheme ID 6
- `deconceal` round-trip → recovers original SUPI for both profiles

**Load generator support:** `loadgen --scheme e` and `loadgen --scheme f` both supported.

---

## Files Modified

| File | Changes |
|------|---------|
| `pkg/suci/types.go` | Added `SchemeProfileE=5`, `SchemeProfileF=6`, cryptogram structs, length constants |
| `pkg/suci/encryptor.go` | Added `encryptProfileE()`, `encryptProfileF()` |
| `pkg/suci/decryptor.go` | Added `decryptProfileE()`, `decryptProfileF()`, `DecryptNestedHybrid()`, `DecryptWrapperHybrid()` |
| `pkg/suci/converter.go` | Added E/F branches in `handleEncryptedScheme()` |
| `pkg/suci/compat.go` | Added `ParseProfileECryptogram`, `ParseProfileFCryptogram`, type aliases |
| `pkg/suci/loadgen.go` | Added E/F support in load generator |
| `pkg/suci/encryptor_test.go` | Added 16 new tests for E/F |
| `pkg/suciutil/parser.go` | Added E/F constants, structs, parsing, decryption |
| `pkg/keys/keygen.go` | Added `generateProfileEKey()`, `generateProfileFKey()` |
| `pkg/keys/keystore.go` | Added E/F key loading in `FileKeyStore` and `EnvKeyStore` |
| `main.go` | Added E/F to all CLI scheme/profile parsers |

---

## Constraints Satisfied

- ✅ Profile E and F are NOT variants of Profile D — separate scheme IDs (5 and 6)
- ✅ Implementation is clean and modular — separate encrypt/decrypt functions per profile
- ✅ Byte layouts are explicit and documented in types.go and ARCHITECTURE.md
- ✅ Focus on implementation — working code with full tests