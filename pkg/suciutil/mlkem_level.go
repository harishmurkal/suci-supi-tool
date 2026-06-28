package suciutil

import (
	"fmt"
	"strconv"
)

// MLKEMSecurityLevel selects the ML-KEM parameter set for PQC profiles (C–F).
// Default matches 3GPP TS 33.703 ML-KEM-768 (NIST Level 3). Level 5 enables ML-KEM-1024
// as a tool extension (same scheme IDs, different KEM byte lengths).
type MLKEMSecurityLevel uint8

const (
	// MLKEMSecurityUnset (0) is treated as MLKEMSecurityLevel3 in NormalizeMLKEMSecurityLevel.
	MLKEMSecurityUnset  MLKEMSecurityLevel = 0
	MLKEMSecurityLevel3 MLKEMSecurityLevel = 3 // ML-KEM-768
	MLKEMSecurityLevel5 MLKEMSecurityLevel = 5 // ML-KEM-1024
)

// ML-KEM-1024 sizes (FIPS 203 / CIRCL mlkem1024 MarshalBinary lengths).
const (
	MLKEM1024_PUBLIC_KEY_LEN  = 1568
	MLKEM1024_PRIVATE_KEY_LEN = 3168
	MLKEM1024_CIPHERTEXT_LEN  = 1568
	MLKEM1024_SHARED_SECRET   = 32
)

// NormalizeMLKEMSecurityLevel maps CLI/API values to a supported level; unknown values default to Level 3.
func NormalizeMLKEMSecurityLevel(v MLKEMSecurityLevel) MLKEMSecurityLevel {
	switch v {
	case MLKEMSecurityUnset, MLKEMSecurityLevel3:
		return MLKEMSecurityLevel3
	case MLKEMSecurityLevel5:
		return MLKEMSecurityLevel5
	default:
		return MLKEMSecurityLevel3
	}
}

// ParseMLKEMSecurityLevel parses "3" or "5" for CLI flags.
func ParseMLKEMSecurityLevel(s string) (MLKEMSecurityLevel, error) {
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return MLKEMSecurityUnset, fmt.Errorf("invalid security-level %q: %w", s, err)
	}
	switch n {
	case 3:
		return MLKEMSecurityLevel3, nil
	case 5:
		return MLKEMSecurityLevel5, nil
	default:
		return MLKEMSecurityUnset, fmt.Errorf("security-level must be 3 (ML-KEM-768) or 5 (ML-KEM-1024), got %d", n)
	}
}

// KEMCiphertextLen returns the ML-KEM ciphertext length for the given level.
func KEMCiphertextLen(level MLKEMSecurityLevel) int {
	switch NormalizeMLKEMSecurityLevel(level) {
	case MLKEMSecurityLevel5:
		return MLKEM1024_CIPHERTEXT_LEN
	default:
		return MLKEM768_CIPHERTEXT_LEN
	}
}

// MLKEMPublicKeyLen returns the ML-KEM encapsulation key length for the given level.
func MLKEMPublicKeyLen(level MLKEMSecurityLevel) int {
	switch NormalizeMLKEMSecurityLevel(level) {
	case MLKEMSecurityLevel5:
		return MLKEM1024_PUBLIC_KEY_LEN
	default:
		return MLKEM768_PUBLIC_KEY_LEN
	}
}

// MLKEMPrivateKeyLen returns the ML-KEM decapsulation key length for the given level.
func MLKEMPrivateKeyLen(level MLKEMSecurityLevel) int {
	switch NormalizeMLKEMSecurityLevel(level) {
	case MLKEMSecurityLevel5:
		return MLKEM1024_PRIVATE_KEY_LEN
	default:
		return MLKEM768_PRIVATE_KEY_LEN
	}
}

// MLKEMSharedSecretLen is 32 for all ML-KEM parameter sets in FIPS 203.
func MLKEMSharedSecretLen(_ MLKEMSecurityLevel) int { return MLKEM768_SHARED_SECRET }

// InferMLKEMSecurityLevelFromMLKEMPrivateLen maps raw ML-KEM private key length to a level.
func InferMLKEMSecurityLevelFromMLKEMPrivateLen(n int) (MLKEMSecurityLevel, error) {
	switch n {
	case MLKEM768_PRIVATE_KEY_LEN:
		return MLKEMSecurityLevel3, nil
	case MLKEM1024_PRIVATE_KEY_LEN:
		return MLKEMSecurityLevel5, nil
	default:
		return MLKEMSecurityUnset, fmt.Errorf("unsupported ML-KEM private key length: %d", n)
	}
}

// InferMLKEMSecurityLevelFromPrivateKey returns the ML-KEM level implied by stored key material.
func InferMLKEMSecurityLevelFromPrivateKey(privateKey interface{}, scheme SchemeID) (MLKEMSecurityLevel, error) {
	switch scheme {
	case SchemeProfileC:
		b, ok := privateKey.([]byte)
		if !ok {
			return MLKEMSecurityUnset, fmt.Errorf("profile C key must be []byte")
		}
		return InferMLKEMSecurityLevelFromMLKEMPrivateLen(len(b))
	case SchemeProfileD, SchemeProfileE, SchemeProfileF:
		c, ok := privateKey.(*ProfileDPrivateKeys)
		if !ok || c == nil {
			return MLKEMSecurityUnset, fmt.Errorf("expected *ProfileDPrivateKeys")
		}
		return InferMLKEMSecurityLevelFromMLKEMPrivateLen(len(c.MLKEMPrivate))
	default:
		return MLKEMSecurityLevel3, nil
	}
}

// ProfileCMinLen returns minimum scheme output length for Profile C at the given KEM size.
func ProfileCMinLen(level MLKEMSecurityLevel) int {
	return KEMCiphertextLen(level) + ProfileC_MAC_TAG_LEN
}

// ProfileDMinLen returns minimum Profile D baseline layout length.
func ProfileDMinLen(level MLKEMSecurityLevel) int {
	return KEMCiphertextLen(level) + ProfileD_EphPubKeyLen + ProfileC_MAC_TAG_LEN
}

// ProfileEMinLen returns minimum Profile E layout length.
func ProfileEMinLen(level MLKEMSecurityLevel) int {
	kem := KEMCiphertextLen(level)
	return ProfileE_EphPubKeyLen + kem + ProfileC_MAC_TAG_LEN + ProfileC_MAC_TAG_LEN
}

// ProfileFMinLen returns minimum Profile F layout length.
func ProfileFMinLen(level MLKEMSecurityLevel) int {
	kem := KEMCiphertextLen(level)
	return kem + ProfileF_EncEphLen + ProfileC_MAC_TAG_LEN + MAC_TAG_LEN
}

// SchemePQCUsesMLKEM reports whether the scheme uses ML-KEM (profiles C–F).
func SchemePQCUsesMLKEM(s SchemeID) bool {
	return s == SchemeProfileC || s == SchemeProfileD || s == SchemeProfileE || s == SchemeProfileF
}

// InferLikelyMLKEMLevelFromSchemeOutput uses scheme output length heuristics: ML-KEM-1024
// layouts are longer than any valid ML-KEM-768 layout for these profiles, so this is safe
// for display/parsing when the ML-KEM private key is not yet available.
func InferLikelyMLKEMLevelFromSchemeOutput(schemeID SchemeID, schemeOutput []byte) MLKEMSecurityLevel {
	n := len(schemeOutput)
	switch schemeID {
	case SchemeProfileC:
		if n >= MLKEM1024_CIPHERTEXT_LEN+1+ProfileC_MAC_TAG_LEN {
			return MLKEMSecurityLevel5
		}
	case SchemeProfileD:
		if n >= MLKEM1024_CIPHERTEXT_LEN+ProfileD_EphPubKeyLen+1+ProfileC_MAC_TAG_LEN {
			return MLKEMSecurityLevel5
		}
	case SchemeProfileE:
		if n >= ProfileEMinLen(MLKEMSecurityLevel5) {
			return MLKEMSecurityLevel5
		}
	case SchemeProfileF:
		if n >= ProfileFMinLen(MLKEMSecurityLevel5) {
			return MLKEMSecurityLevel5
		}
	}
	return MLKEMSecurityLevel3
}
