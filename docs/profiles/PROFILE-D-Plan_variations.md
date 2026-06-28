# Profile-D add17/add19 Implementation Blueprint — COMPLETED

> **Status: IMPLEMENTED** (March 2026)
> All items in this blueprint have been implemented and verified:
> - add17 (Solution #17): nonce-based freshness + profile/variant binding in KDF
> - add19 (Solution #19): AES-256-GCM AEAD with AAD binding
> - Variant byte wire format with backward-compatible baseline
> - CLI flags `--add-17` and `--add-19`
> - Auto-detection on de-concealment (no flag needed)
> - Round-trip verified for all three variants (baseline, add17, add19)

## A. Baseline Understanding

### Current baseline Profile-D (from reference file)

**Concealment flow:**
1. **PQC branch:** ML-KEM-768 encapsulation → `pqCiphertext` (1088 bytes), `ss1` (32 bytes)
2. **ECC branch:** Ephemeral X25519 keypair → `ss2 = X25519(ephPriv, hnX25519Pub)`, `ephPublicKey` (32 bytes)
3. **Combiner:** `CombinedSecret = SHA3-256(ss1 || ss2)`
4. **KDF:** ANSI-X9.63-KDF with SHA3-256, `SharedInfo1 = pqCiphertext || ephPublicKey`, output = `encKey` (32) || `macKey` (32)
5. **Symmetric:** AES-256-CTR (zero IV), KMAC256 over ciphertext, MAC tag 8 bytes
6. **Output:** `pqCiphertext || ephPublicKey || ciphertext || macTag`

**De-concealment flow:**
1. Parse: `pqCiphertext`, `ephPublicKey`, `ciphertext`, `macTag`
2. ML-KEM decapsulate → `ss1`
3. X25519 ECDH → `ss2`
4. `CombinedSecret = SHA3-256(ss1 || ss2)`
5. KDF with same `SharedInfo1`
6. Verify KMAC256, decrypt AES-256-CTR

**Properties:**
- Parallel hybrid, combiner + KDF
- Context binding only via `SharedInfo1` (pqCiphertext || ephPublicKey)
- No freshness, no variant marker, no AEAD, no profile/variant in KDF

---

## B. add17 Design (Solution #17 – stronger context binding + freshness)

### add17 concealment flow

1. Same as baseline: ML-KEM encapsulate, X25519 ECDH, `CombinedSecret = SHA3-256(ss1 || ss2)`.
2. **Nonce:** 16-byte random nonce.
3. **KDF inputs (extended):**
   - Z = CombinedSecret (unchanged)
   - SharedInfo1 = `pqCiphertext || ephPublicKey || nonce || profileID || hybridCode`
   - `profileID` = 0x04 (Profile-D)
   - `hybridCode` = 0x17 (add17)
4. KDF output = `encKey` (32) || `macKey` (32).
5. Symmetric: AES-256-CTR (zero IV), KMAC256 over ciphertext (unchanged).
6. **Output layout:** `pqCiphertext || ephPublicKey || nonce || ciphertext || macTag`

### add17 de-concealment flow

1. Parse: `pqCiphertext`, `ephPublicKey`, `nonce`, `ciphertext`, `macTag`.
2. Same as baseline: decapsulate, ECDH, combiner.
3. SharedInfo1 = `pqCiphertext || ephPublicKey || nonce || profileID || hybridCode`.
4. Derive keys, verify KMAC256, decrypt.

### add17 KDF inputs

| Input | Value |
|------|-------|
| Z | CombinedSecret (SHA3-256(ss1\|\|ss2)) |
| SharedInfo1 | pqCiphertext \|\| ephPublicKey \|\| nonce \|\| 0x04 \|\| 0x17 |
| Output | encKey (32) \|\| macKey (32) |

### add17 context binding

- Profile ID: 0x04
- Hybrid code: 0x17
- Nonce: 16 bytes (freshness)

### add17 MAC inputs

- Same as baseline: KMAC256(ciphertext, macKey), tag 8 bytes.

### add17 scheme output layout

```
[0:1088]     pqCiphertext
[1088:1120]  ephPublicKey
[1120:1136]  nonce (16 bytes)
[1136:N-8]   ciphertext
[N-8:N]      macTag (8 bytes)
```

### add17 parser changes

- Minimum length: 1088 + 32 + 16 + 8 = 1144 bytes.
- Slice: `nonce = schemeOutput[1120:1136]`, `ciphertext = schemeOutput[1136:len-8]`, `macTag = schemeOutput[len-8:]`.

### add17 compatibility

- **Not compatible** with baseline. Baseline has no nonce; add17 has 16-byte nonce before ciphertext.
- Baseline: `pqCiphertext || ephPublicKey || ciphertext || macTag`.
- add17: `pqCiphertext || ephPublicKey || nonce || ciphertext || macTag`.
- Wire format differs; baseline ciphertexts cannot be parsed as add17.

---

## C. add19 Design (Solution #19 – AEAD + AAD)

### add19 concealment flow

1. Same as baseline: ML-KEM encapsulate, X25519 ECDH, `CombinedSecret = SHA3-256(ss1 || ss2)`.
2. **KDF inputs:**
   - Z = CombinedSecret
   - SharedInfo1 = `pqCiphertext || ephPublicKey || profileID || hybridCode`
   - profileID = 0x04, hybridCode = 0x19
3. KDF output = `aeadKey` (32) || `nonce` (12 for AES-GCM).
4. **AAD:** `pqCiphertext || ephPublicKey`.
5. **AEAD:** AES-256-GCM(plaintext, aeadKey, nonce, AAD).
6. **Output layout:** `pqCiphertext || ephPublicKey || nonce || ciphertext || tag`

### add19 de-concealment flow

1. Parse: `pqCiphertext`, `ephPublicKey`, `nonce` (12), `ciphertext`, `tag` (16).
2. Same as baseline: decapsulate, ECDH, combiner.
3. SharedInfo1 = `pqCiphertext || ephPublicKey || 0x04 || 0x19`.
4. Derive aeadKey and nonce.
5. AES-GCM Open with AAD = `pqCiphertext || ephPublicKey`.

### add19 KDF inputs

| Input | Value |
|------|-------|
| Z | CombinedSecret |
| SharedInfo1 | pqCiphertext \|\| ephPublicKey \|\| 0x04 \|\| 0x19 |
| Output | aeadKey (32) \|\| nonce (12) |

### add19 context binding

- AAD = `pqCiphertext || ephPublicKey` (authenticated).
- Profile/variant in KDF SharedInfo1.

### add19 AEAD inputs

- Key: 32 bytes from KDF.
- Nonce: 12 bytes from KDF.
- AAD: `pqCiphertext || ephPublicKey`.
- Plaintext: MSIN bytes.
- Tag: 16 bytes (AES-GCM standard).

### add19 scheme output layout

```
[0:1088]     pqCiphertext
[1088:1120]  ephPublicKey
[1120:1132]  nonce (12 bytes)
[1132:N-16]  ciphertext (AEAD output)
[N-16:N]     tag (16 bytes)
```

### add19 parser changes

- Minimum length: 1088 + 32 + 12 + 16 = 1148 bytes.
- Slice: `nonce = schemeOutput[1120:1132]`, `ciphertext = schemeOutput[1132:len-16]`, `tag = schemeOutput[len-16:]`.

### add19 compatibility

- **Not compatible** with baseline. Different structure (nonce, AEAD tag 16 vs MAC 8).

---

## D. Wire Format and CLI Recommendation

### Can the current wire format be reused?

**No.** Both add17 and add19 require extra fields (nonce, different tag size for add19). Baseline has no variant marker.

### Options

| Option | Pros | Cons |
|--------|------|------|
| Same wire format | None | Impossible for add17/add19 |
| Extended wire format | Single Scheme ID 4, variants distinguishable | Need variant marker or length-based detection |
| Profile-D subformat version byte | Explicit variant, future-proof | Extra byte in scheme output |
| New Scheme ID | Clean separation | Requires spec change, not desired |

### Recommended design: Profile-D subformat version byte

Add a **variant byte** at a fixed offset so the parser can choose the right format:

**Baseline (variant 0):**
```
pqCiphertext(1088) || ephPublicKey(32) || ciphertext || macTag(8)
```
No change; existing ciphertexts stay valid.

**Extended format (variant byte after ephPublicKey):**
```
pqCiphertext(1088) || ephPublicKey(32) || variant(1) || [variant-specific payload]
```

- Variant 0: baseline (no variant byte in legacy; treat as implicit 0).
- Variant 1 (add17): `nonce(16) || ciphertext || macTag(8)`.
- Variant 2 (add19): `nonce(12) || ciphertext || tag(16)`.

**Detection logic:**
- If `len(schemeOutput) == 1088 + 32 + ciphertextLen + 8` and no variant byte → baseline.
- If `len(schemeOutput) >= 1088 + 32 + 1` and byte at 1120 is 0x01 → add17.
- If byte at 1120 is 0x02 → add19.

**Backward compatibility:** Baseline has no variant byte. Two approaches:

1. **Length-based:** Baseline min = 1128. add17 min = 1145 (1128 + 1 + 16). If len ≥ 1145 and byte[1120] in {0x01, 0x02}, treat as extended.
2. **Always check byte 1120:** If it is 0x01 or 0x02, use extended; otherwise baseline.

**Exact binary layout (extended):**

```
Offset    Length   Field
------    ------   -----
0         1088     pqCiphertext
1088      32       ephPublicKey
1120      1        variant (0x00=baseline*, 0x01=add17, 0x02=add19)
1121      ...      variant-specific

* Baseline: no variant byte; payload starts at 1120.
```

**Refined layout for backward compatibility:**
- Baseline: `[0:1088] pqCiphertext || [1088:1120] ephPublicKey || [1120:] ciphertext||macTag` (unchanged).
- add17: `[0:1088] pqCiphertext || [1088:1120] ephPublicKey || [1120] 0x01 || [1121:1137] nonce || [1137:] ciphertext||macTag`.
- add19: `[0:1088] pqCiphertext || [1088:1120] ephPublicKey || [1120] 0x02 || [1121:1133] nonce || [1133:] ciphertext||tag`.

Parser: if `len >= 1145` and `schemeOutput[1120] == 0x01` → add17; if `schemeOutput[1120] == 0x02` → add19; else → baseline.

---

## E. Go Code Changes

### Files to modify

| File | Changes |
|------|---------|
| `pkg/suci/types.go` | Add `ProfileDVariant`, `ProfileDVariantConfig`, extend `HybridCryptogram` |
| `pkg/suci/encryptor.go` | Variant dispatch, `encryptProfileDAdd17`, `encryptProfileDAdd19` |
| `pkg/suci/decryptor.go` | Variant dispatch, `decryptProfileDAdd17`, `decryptProfileDAdd19` |
| `pkg/suciutil/parser.go` | `ParseProfileDCryptogram` variant detection, `HybridCryptogram` with variant |
| `pkg/suci/converter.go` | Pass `ProfileDVariant` in `ConcealmentConfig` |
| `main.go` | Add `-add-17`, `-add-19` flags, help text |

### Structs and constants

```go
// pkg/suci/types.go (or suciutil)

const (
    ProfileDVariantBaseline ProfileDVariant = 0
    ProfileDVariantAdd17    ProfileDVariant = 1
    ProfileDVariantAdd19    ProfileDVariant = 2
)

type ProfileDVariant uint8

func (v ProfileDVariant) String() string {
    switch v {
    case ProfileDVariantBaseline: return "baseline"
    case ProfileDVariantAdd17:    return "add17"
    case ProfileDVariantAdd19:    return "add19"
    default: return "unknown"
    }
}

// Variant-specific constants
const (
    ProfileD_Add17_NonceLen   = 16
    ProfileD_Add19_NonceLen   = 12
    ProfileD_Add19_TagLen     = 16
    ProfileD_VariantByteOffset = 1120  // after ephPublicKey
)

// HybridCryptogram extended
type HybridCryptogram struct {
    KEMCiphertext      []byte
    EphemeralPublicKey []byte
    Variant            ProfileDVariant  // 0=baseline, 1=add17, 2=add19
    Nonce              []byte           // add17: 16 bytes, add19: 12 bytes, baseline: nil
    Ciphertext         []byte
    MACTag             []byte           // add17/baseline: 8 bytes; add19: 16 bytes (AEAD tag)
}

// ConcealmentConfig extended
type ConcealmentConfig struct {
    SUPI             string
    SchemeID         suciutil.SchemeID
    ProfileDVariant  ProfileDVariant    // only used when SchemeID == ProfileD
    KeyID            int
    RoutingInd       string
    KeyDirectory     string
}
```

### Parser updates

```go
// ParseProfileDCryptogram: detect variant and parse accordingly
func ParseProfileDCryptogram(cryptogram []byte) (*HybridCryptogram, ErrorCode) {
    minBaseline := MLKEM768_CIPHERTEXT_LEN + ProfileD_EphPubKeyLen + ProfileC_MAC_TAG_LEN
    if len(cryptogram) < minBaseline {
        return nil, E_SCHEME_OUTPUT_TOO_SHORT
    }
    kemEnd := MLKEM768_CIPHERTEXT_LEN
    ephEnd := kemEnd + ProfileD_EphPubKeyLen

    h := &HybridCryptogram{
        KEMCiphertext:      cryptogram[0:kemEnd],
        EphemeralPublicKey: cryptogram[kemEnd:ephEnd],
    }

    // Check for extended format: variant byte at 1120
    if len(cryptogram) >= ephEnd+1 {
        v := cryptogram[ephEnd]
        if v == 0x01 {
            // add17: nonce(16) || ciphertext || macTag(8)
            if len(cryptogram) < ephEnd+1+ProfileD_Add17_NonceLen+ProfileC_MAC_TAG_LEN {
                return nil, E_SCHEME_OUTPUT_TOO_SHORT
            }
            h.Variant = ProfileDVariantAdd17
            h.Nonce = cryptogram[ephEnd+1 : ephEnd+1+ProfileD_Add17_NonceLen]
            macStart := len(cryptogram) - ProfileC_MAC_TAG_LEN
            h.Ciphertext = cryptogram[ephEnd+1+ProfileD_Add17_NonceLen : macStart]
            h.MACTag = cryptogram[macStart:]
            return h, 0
        }
        if v == 0x02 {
            // add19: nonce(12) || ciphertext || tag(16)
            if len(cryptogram) < ephEnd+1+ProfileD_Add19_NonceLen+ProfileD_Add19_TagLen {
                return nil, E_SCHEME_OUTPUT_TOO_SHORT
            }
            h.Variant = ProfileDVariantAdd19
            h.Nonce = cryptogram[ephEnd+1 : ephEnd+1+ProfileD_Add19_NonceLen]
            tagStart := len(cryptogram) - ProfileD_Add19_TagLen
            h.Ciphertext = cryptogram[ephEnd+1+ProfileD_Add19_NonceLen : tagStart]
            h.MACTag = cryptogram[tagStart:]
            return h, 0
        }
    }

    // Baseline: no variant byte
    h.Variant = ProfileDVariantBaseline
    macStart := len(cryptogram) - ProfileC_MAC_TAG_LEN
    h.Ciphertext = cryptogram[ephEnd:macStart]
    h.MACTag = cryptogram[macStart:]
    return h, 0
}
```

### Encrypt/decrypt dispatch

- `EncryptECIES` / `encryptProfileD`: if `ConcealmentConfig.ProfileDVariant == Add17` → `encryptProfileDAdd17`; if `Add19` → `encryptProfileDAdd19`; else → current `encryptProfileD`.
- `DecryptHybrid` / `decryptProfileD`: branch on `HybridCryptogram.Variant` to baseline, add17, or add19.

### CLI flag parsing

```go
// concealCmd
add17Flag := concealCmd.Bool("add-17", false, "Profile D: use Solution #17 variant (freshness + context binding)")
add19Flag := concealCmd.Bool("add-19", false, "Profile D: use Solution #19 variant (AEAD + AAD)")

// In handleConcealCommand, when scheme is d:
var profileDVariant suci.ProfileDVariant
if *add19Flag {
    profileDVariant = suci.ProfileDVariantAdd19
} else if *add17Flag {
    profileDVariant = suci.ProfileDVariantAdd17
} else {
    profileDVariant = suci.ProfileDVariantBaseline
}
config.ProfileDVariant = profileDVariant
```

### Help text

```
  --add-17             [Profile D only] Use Solution #17 variant: nonce-based freshness + profile/variant binding in KDF
  --add-19             [Profile D only] Use Solution #19 variant: AES-GCM AEAD with AAD binding
```

---

## F. Pseudocode

### Baseline Profile-D (unchanged)

```
encrypt_baseline(plaintext, pub):
  kemCt, ss1 = MLKEM.Encapsulate(pub.MLKEM)
  ephPriv, ephPub = X25519.GenKeypair()
  ss2 = X25519(ephPriv, pub.X25519)
  combined = SHA3-256(ss1 || ss2)
  sharedInfo = kemCt || ephPub
  encKey, macKey = KDF(combined, sharedInfo)
  ct = AES256CTR(plaintext, encKey)
  tag = KMAC256(ct, macKey)
  return kemCt || ephPub || ct || tag
```

### add17

```
encrypt_add17(plaintext, pub):
  kemCt, ss1 = MLKEM.Encapsulate(pub.MLKEM)
  ephPriv, ephPub = X25519.GenKeypair()
  ss2 = X25519(ephPriv, pub.X25519)
  combined = SHA3-256(ss1 || ss2)
  nonce = random(16)
  sharedInfo = kemCt || ephPub || nonce || 0x04 || 0x17
  encKey, macKey = KDF(combined, sharedInfo)
  ct = AES256CTR(plaintext, encKey)
  tag = KMAC256(ct, macKey)
  return kemCt || ephPub || 0x01 || nonce || ct || tag
```

### add19

```
encrypt_add19(plaintext, pub):
  kemCt, ss1 = MLKEM.Encapsulate(pub.MLKEM)
  ephPriv, ephPub = X25519.GenKeypair()
  ss2 = X25519(ephPriv, pub.X25519)
  combined = SHA3-256(ss1 || ss2)
  sharedInfo = kemCt || ephPub || 0x04 || 0x19
  aeadKey, nonce = KDF(combined, sharedInfo)  // 32 + 12 bytes
  aad = kemCt || ephPub
  ct, tag = AES256GCM.Seal(plaintext, aeadKey, nonce, aad)
  return kemCt || ephPub || 0x02 || nonce || ct || tag
```

---

## G. Migration and Testing Plan

### Preserving old test vectors

- Keep baseline tests as-is.
- Baseline format unchanged; existing vectors remain valid.

### New test vectors

- add17: one or more round-trip vectors with known MSIN, keys, and expected scheme output.
- add19: same.
- Store in `*_test.go` or JSON files.

### Auto-detection during de-concealment

- Parser inspects byte at offset 1120.
- 0x01 → add17, 0x02 → add19, else → baseline.
- No extra CLI flag for deconceal; variant is in the ciphertext.

### Safe failure on ambiguity

- If `len < 1129` → baseline only.
- If `len >= 1129` and byte[1120] ∉ {0x01, 0x02} → treat as baseline (ciphertext starts at 1120).
- If byte[1120] == 0x01 but length too short → `E_SCHEME_OUTPUT_TOO_SHORT`.
- Same for 0x02.

---

## H. Security Notes

1. **add17:** Nonce gives per-message freshness; profile/variant in KDF reduces cross-profile and mix-and-match risk.
2. **add19:** AEAD gives authenticated encryption; AAD binds kemCt and ephPub; single primitive reduces misuse risk.
3. **Key management:** Same key material (ML-KEM + X25519); no new key types.
4. **No new security claims:** Improvements are structural (binding, freshness, AEAD), not new algorithms.

---

## I. Final Recommendation

| Criterion | add17 | add19 |
|-----------|-------|-------|
| Implement first | ✓ | |
| Easier | ✓ (smaller change, same MAC) | |
| Safer | | ✓ (AEAD) |
| Production suitability | ✓ (incremental) | ✓ (modern design) |
| Closer to TR 33.704 Group-B | ✓ (Solution #17) | ✓ (Solution #19) |

**Recommendation:**

1. **Implement add17 first** – minimal change (nonce + KDF context), keeps AES-CTR + KMAC, easier to validate.
2. **Implement add19 second** – better long-term design (AEAD, AAD).
3. **Use the variant byte** – explicit, unambiguous, backward compatible with baseline.
4. **Default:** Baseline when neither `-add-17` nor `-add-19` is set.
