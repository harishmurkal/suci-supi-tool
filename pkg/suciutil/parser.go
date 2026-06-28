package suciutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strconv"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/harishmurkal/suci-supi-tool/pkg/slog"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

// ConstructSUCI constructs a SUCI string from its components (STUB)
func ConstructSUCI(identityType IdentityType, mcc, mnc, routingInd string, schemeID SchemeID, keyID uint8, schemeOutput []byte) string {
	// SUCI format: suci-<type>-<mcc>-<mnc>-<routingInd>-<schemeId>-<keyId>-<schemeOutput>
	// <type>: 0 (IMSI) or 1 (NAI)
	// <mcc>: 3 digits
	// <mnc>: 2 or 3 digits
	// <routingInd>: 1-4 digits
	// <schemeId>: 0 (NULL), 1 (Profile A), 2 (Profile B), 3 (Profile C)
	// <keyId>: 0-255
	// <schemeOutput>: hex-encoded

	// Defensive: pad mcc/mnc if needed
	mccStr := mcc
	if len(mccStr) < 3 {
		mccStr = fmt.Sprintf("%03s", mccStr)
	}
	mncStr := mnc
	if len(mncStr) < 2 {
		mncStr = fmt.Sprintf("%02s", mncStr)
	}

	// Defensive: routingInd as-is (should be 1-4 digits)
	routingIndStr := routingInd

	// Defensive: schemeOutput hex encoding
	schemeOutputHex := hex.EncodeToString(schemeOutput)

	return fmt.Sprintf(
		"suci-%d-%s-%s-%s-%d-%d-%s",
		identityType,
		mccStr,
		mncStr,
		routingIndStr,
		schemeID,
		keyID,
		schemeOutputHex,
	)
}
func GetPublicKeyFromPrivate(privateKey interface{}, schemeID SchemeID) (interface{}, error) {
	switch schemeID {
	case SchemeProfileA:
		privKeyBytes, ok := privateKey.([]byte)
		if !ok || len(privKeyBytes) != 32 {
			return nil, fmt.Errorf("invalid Profile A private key")
		}
		publicKey, err := curve25519.X25519(privKeyBytes, curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("failed to derive public key: %w", err)
		}
		return publicKey, nil

	case SchemeProfileB:
		ecPrivKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("invalid Profile B private key")
		}
		return &ecPrivKey.PublicKey, nil

	case SchemeProfileC:
		privKeyBytes, ok := privateKey.([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid Profile C private key")
		}
		level, err := InferMLKEMSecurityLevelFromMLKEMPrivateLen(len(privKeyBytes))
		if err != nil {
			return nil, fmt.Errorf("invalid Profile C private key: %w", err)
		}
		switch level {
		case MLKEMSecurityLevel5:
			var privKey mlkem1024.PrivateKey
			if err := privKey.Unpack(privKeyBytes); err != nil {
				return nil, fmt.Errorf("failed to unpack Profile C private key: %w", err)
			}
			pubKey := privKey.Public()
			pubKeyBytes, err := pubKey.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal Profile C public key: %w", err)
			}
			return pubKeyBytes, nil
		default:
			var privKey mlkem768.PrivateKey
			if err := privKey.Unpack(privKeyBytes); err != nil {
				return nil, fmt.Errorf("failed to unpack Profile C private key: %w", err)
			}
			pubKey := privKey.Public()
			pubKeyBytes, err := pubKey.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal Profile C public key: %w", err)
			}
			return pubKeyBytes, nil
		}

	case SchemeProfileD:
		composite, ok := privateKey.(*ProfileDPrivateKeys)
		if !ok || composite == nil {
			return nil, fmt.Errorf("invalid Profile D private key: expected *ProfileDPrivateKeys")
		}
		if len(composite.X25519Private) != 32 {
			return nil, fmt.Errorf("invalid Profile D private key lengths")
		}
		level, err := InferMLKEMSecurityLevelFromMLKEMPrivateLen(len(composite.MLKEMPrivate))
		if err != nil {
			return nil, fmt.Errorf("invalid Profile D ML-KEM private key: %w", err)
		}
		var mlkemPubBytes []byte
		switch level {
		case MLKEMSecurityLevel5:
			var mlkemPriv mlkem1024.PrivateKey
			if err := mlkemPriv.Unpack(composite.MLKEMPrivate); err != nil {
				return nil, fmt.Errorf("failed to unpack Profile D ML-KEM private key: %w", err)
			}
			mlkemPub := mlkemPriv.Public()
			mlkemPubBytes, err = mlkemPub.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal Profile D ML-KEM public key: %w", err)
			}
		default:
			var mlkemPriv mlkem768.PrivateKey
			if err := mlkemPriv.Unpack(composite.MLKEMPrivate); err != nil {
				return nil, fmt.Errorf("failed to unpack Profile D ML-KEM private key: %w", err)
			}
			mlkemPub := mlkemPriv.Public()
			mlkemPubBytes, err = mlkemPub.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal Profile D ML-KEM public key: %w", err)
			}
		}
		x25519Pub, err := curve25519.X25519(composite.X25519Private, curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("failed to derive Profile D X25519 public key: %w", err)
		}
		return &ProfileDPublicKeys{MLKEMPublic: mlkemPubBytes, X25519Public: x25519Pub}, nil

	case SchemeProfileE, SchemeProfileF:
		composite, ok := privateKey.(*ProfileDPrivateKeys)
		if !ok || composite == nil {
			return nil, fmt.Errorf("invalid Profile %s private key: expected *ProfileDPrivateKeys", schemeID)
		}
		if len(composite.X25519Private) != 32 {
			return nil, fmt.Errorf("invalid Profile %s private key lengths", schemeID)
		}
		level, err := InferMLKEMSecurityLevelFromMLKEMPrivateLen(len(composite.MLKEMPrivate))
		if err != nil {
			return nil, fmt.Errorf("invalid Profile %s ML-KEM private key: %w", schemeID, err)
		}
		var mlkemPubBytes []byte
		switch level {
		case MLKEMSecurityLevel5:
			var mlkemPriv mlkem1024.PrivateKey
			if err := mlkemPriv.Unpack(composite.MLKEMPrivate); err != nil {
				return nil, fmt.Errorf("failed to unpack Profile %s ML-KEM private key: %w", schemeID, err)
			}
			mlkemPub := mlkemPriv.Public()
			mlkemPubBytes, err = mlkemPub.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal Profile %s ML-KEM public key: %w", schemeID, err)
			}
		default:
			var mlkemPriv mlkem768.PrivateKey
			if err := mlkemPriv.Unpack(composite.MLKEMPrivate); err != nil {
				return nil, fmt.Errorf("failed to unpack Profile %s ML-KEM private key: %w", schemeID, err)
			}
			mlkemPub := mlkemPriv.Public()
			mlkemPubBytes, err = mlkemPub.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal Profile %s ML-KEM public key: %w", schemeID, err)
			}
		}
		x25519Pub, err := curve25519.X25519(composite.X25519Private, curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("failed to derive Profile %s X25519 public key: %w", schemeID, err)
		}
		return &ProfileDPublicKeys{MLKEMPublic: mlkemPubBytes, X25519Public: x25519Pub}, nil

	default:
		return nil, fmt.Errorf("unsupported scheme: %d", schemeID)
	}
}

// Error codes
const (
	// Parse Errors (0x1xx)
	E_PARSE_SUCI ErrorCode = 0x101
	E_PARSE_SUPI ErrorCode = 0x102

	// Cryptographic Errors (0x2xx)
	E_CURVE_MISMATCH          ErrorCode = 0x201
	E_TAG_MISMATCH            ErrorCode = 0x202
	E_INVALID_EC_KEY          ErrorCode = 0x203
	E_SCHEME_OUTPUT_TOO_SHORT ErrorCode = 0x204
	E_MSIN_ENCODING           ErrorCode = 0x205
	E_INVALID_IMSI_LENGTH     ErrorCode = 0x206
	E_ENCRYPTION_FAILED       ErrorCode = 0x207
	E_INVALID_PQC_KEY         ErrorCode = 0x208
	E_KEM_ENCAPSULATE_FAILED  ErrorCode = 0x209
	E_KEM_DECAPSULATE_FAILED  ErrorCode = 0x20A
	E_KMAC_FAILED             ErrorCode = 0x20B

	// Validation Errors (0x3xx)
	E_INVALID_SCHEME_ID         ErrorCode = 0x301
	E_INVALID_TYPE              ErrorCode = 0x302
	E_INVALID_KEY_ID            ErrorCode = 0x303
	E_UNKNOWN_KEY_ID            ErrorCode = 0x304
	E_INVALID_SUBSCRIBER_KEY_ID ErrorCode = 0x305
)

// Scheme IDs
const (
	SchemeNullScheme SchemeID = 0
	SchemeProfileA   SchemeID = 1
	SchemeProfileB   SchemeID = 2
	SchemeProfileC   SchemeID = 3
	SchemeProfileD   SchemeID = 4 // Hybrid ML-KEM-768 + X25519
	SchemeProfileE   SchemeID = 5 // Nested Hybrid (ECC protects PQ ciphertext, PQ protects SUPI)
	SchemeProfileF   SchemeID = 6 // Wrapper Hybrid (ECIES unchanged, PQ wraps ephemeral key)
	SchemeProfileG   SchemeID = 7 // Symmetric two-layer concealment
)

// Identity types
const (
	TypeIMSI IdentityType = 0
	TypeNAI  IdentityType = 1
)

// Cryptogram length constants
const (
	ProfileA_PubKeyLen = 32
	ProfileA_MACLen    = 8
	ProfileA_MinLen    = ProfileA_PubKeyLen + ProfileA_MACLen

	ProfileB_PubKeyLen = 33
	ProfileB_MACLen    = 8
	ProfileB_MinLen    = ProfileB_PubKeyLen + ProfileB_MACLen

	AES_KEY_LEN    = 16
	AES_IV_LEN     = 16
	HMAC_KEY_LEN   = 32
	MAC_TAG_LEN    = 8
	KDF_OUTPUT_LEN = AES_KEY_LEN + HMAC_KEY_LEN

	MLKEM768_PUBLIC_KEY_LEN  = 1184
	MLKEM768_PRIVATE_KEY_LEN = 2400
	MLKEM768_CIPHERTEXT_LEN  = 1088
	MLKEM768_SHARED_SECRET   = 32

	ProfileC_ENC_KEY_LEN = 32
	ProfileC_MAC_KEY_LEN = 32
	ProfileC_MAC_TAG_LEN = 8
	ProfileC_KDF_OUTPUT  = ProfileC_ENC_KEY_LEN + ProfileC_MAC_KEY_LEN
	ProfileC_MinLen      = MLKEM768_CIPHERTEXT_LEN + ProfileC_MAC_TAG_LEN

	ProfileD_EphPubKeyLen = 32
	ProfileD_MinLen       = MLKEM768_CIPHERTEXT_LEN + ProfileD_EphPubKeyLen + ProfileC_MAC_TAG_LEN

	// Profile D variant-specific constants (add17, add19)
	ProfileD_Add17_NonceLen = 16
	ProfileD_Add19_NonceLen = 12
	ProfileD_Add19_TagLen   = 16

	// Profile E (Nested Hybrid) constants
	// Output: EphPub(32) || EncryptedKEMCT(1088) || KEMMAC(8) || EncryptedMSIN || MSINMAC(8)
	ProfileE_EphPubKeyLen = 32
	ProfileE_MinLen       = ProfileE_EphPubKeyLen + MLKEM768_CIPHERTEXT_LEN + ProfileC_MAC_TAG_LEN + ProfileC_MAC_TAG_LEN // 1136

	// Profile F (Wrapper Hybrid) constants
	// Output: KEMCT(1088) || EncEph(32) || PQCMAC(8) || Ciphertext || MAC(8)
	ProfileF_EncEphLen = 32
	ProfileF_MinLen    = MLKEM768_CIPHERTEXT_LEN + ProfileF_EncEphLen + ProfileC_MAC_TAG_LEN + MAC_TAG_LEN // 1136

	// Profile G (Symmetric) constants
	// Output: R || KeyCipherText(5) || MACkey || CipherText || MACmsin
	ProfileG_KeyCipherTextLen = 5
	ProfileG_Level3_RLen      = 8
	ProfileG_Level5_RLen      = 16
	ProfileG_Level3_MACLen    = 16
	ProfileG_Level5_MACLen    = 32
	ProfileG_Level3_MinLen    = ProfileG_Level3_RLen + ProfileG_KeyCipherTextLen + ProfileG_Level3_MACLen + ProfileG_Level3_MACLen
	ProfileG_Level5_MinLen    = ProfileG_Level5_RLen + ProfileG_KeyCipherTextLen + ProfileG_Level5_MACLen + ProfileG_Level5_MACLen

	// Profile G fixed time-window policy.
	ProfileG_DefaultWindowSizeSeconds = int64(300) // 5 minutes
)

// ProfileDVariant identifies the Profile D sub-format (baseline, add17, add19)
type ProfileDVariant uint8

const (
	ProfileDVariantBaseline ProfileDVariant = 0
	ProfileDVariantAdd17    ProfileDVariant = 1
	ProfileDVariantAdd19    ProfileDVariant = 2
)

func (v ProfileDVariant) String() string {
	switch v {
	case ProfileDVariantBaseline:
		return "baseline"
	case ProfileDVariantAdd17:
		return "add17"
	case ProfileDVariantAdd19:
		return "add19"
	default:
		return "unknown"
	}
}

// ProfileDPrivateKeys holds both private keys for Profile D (hybrid).
type ProfileDPrivateKeys struct {
	MLKEMPrivate  []byte // 2400 bytes
	X25519Private []byte // 32 bytes
}

// ProfileDPublicKeys holds both public keys for Profile D (hybrid).
type ProfileDPublicKeys struct {
	MLKEMPublic  []byte // 1184 bytes
	X25519Public []byte // 32 bytes
}

const (
	IMSI_MIN_LEN = 5
	IMSI_MAX_LEN = 15
)

type ErrorCode uint16

func (e ErrorCode) Error() string {
	msg, ok := errorMessages[e]
	if !ok {
		return fmt.Sprintf("error-%.4x (unknown error)", uint16(e))
	}
	return fmt.Sprintf("error-%.4x: %s", uint16(e), msg)
}

var errorMessages = map[ErrorCode]string{
	E_PARSE_SUCI:                "Invalid SUCI format",
	E_PARSE_SUPI:                "Invalid SUPI format",
	E_CURVE_MISMATCH:            "Key curve doesn't match protection scheme",
	E_TAG_MISMATCH:              "MAC verification failed",
	E_INVALID_EC_KEY:            "Invalid elliptic curve key format",
	E_SCHEME_OUTPUT_TOO_SHORT:   "Scheme output too short for selected profile",
	E_MSIN_ENCODING:             "Failed to decode MSIN",
	E_INVALID_IMSI_LENGTH:       "IMSI length out of valid range (5-15 digits)",
	E_ENCRYPTION_FAILED:         "Encryption operation failed",
	E_INVALID_PQC_KEY:           "Invalid ML-KEM key format or length",
	E_KEM_ENCAPSULATE_FAILED:    "ML-KEM encapsulation operation failed",
	E_KEM_DECAPSULATE_FAILED:    "ML-KEM decapsulation operation failed",
	E_KMAC_FAILED:               "KMAC256 computation failed",
	E_INVALID_SCHEME_ID:         "Unsupported or invalid scheme ID",
	E_INVALID_TYPE:              "Invalid identity type",
	E_INVALID_KEY_ID:            "Key ID out of valid range (0-255)",
	E_UNKNOWN_KEY_ID:            "Key ID not found in key store",
	E_INVALID_SUBSCRIBER_KEY_ID: "Invalid subscriber key ID (expected 10 hex chars / 5 bytes)",
}

type SchemeID uint8

func (s SchemeID) String() string {
	switch s {
	case SchemeNullScheme:
		return "NULL-SCHEME"
	case SchemeProfileA:
		return "ECIES-Profile-A (Curve25519)"
	case SchemeProfileB:
		return "ECIES-Profile-B (secp256r1)"
	case SchemeProfileC:
		return "PQC-Profile-C (ML-KEM-768)"
	case SchemeProfileD:
		return "Hybrid-Profile-D (ML-KEM-768+X25519)"
	case SchemeProfileE:
		return "NestedHybrid-Profile-E (ML-KEM-768+X25519)"
	case SchemeProfileF:
		return "WrapperHybrid-Profile-F (ML-KEM-768+X25519)"
	case SchemeProfileG:
		return "Symmetric-Profile-G (Two-layer symmetric concealment)"
	default:
		return fmt.Sprintf("Unknown-Scheme-%d", s)
	}
}

func (s SchemeID) IsValid() bool {
	return s >= SchemeNullScheme && s <= SchemeProfileG
}

func (s SchemeID) RequiresDecryption() bool {
	return s == SchemeProfileA || s == SchemeProfileB || s == SchemeProfileC || s == SchemeProfileD || s == SchemeProfileE || s == SchemeProfileF || s == SchemeProfileG
}

type IdentityType uint8

func (t IdentityType) String() string {
	switch t {
	case TypeIMSI:
		return "IMSI"
	case TypeNAI:
		return "NAI"
	default:
		return fmt.Sprintf("Unknown-Type-%d", t)
	}
}

func (t IdentityType) IsValid() bool {
	return t == TypeIMSI || t == TypeNAI
}

type ParsedSUCI struct {
	Type         IdentityType
	MCC          string
	MNC          string
	RoutingInd   string
	SchemeID     SchemeID
	KeyID        uint8
	SchemeOutput []byte
}

func (p *ParsedSUCI) GetHomeNetworkID() string {
	return p.MCC + p.MNC
}

type ConversionResult struct {
	SUPI  string
	Error *ErrorCode
}

func (r *ConversionResult) IsSuccess() bool {
	return r.Error == nil
}

func (r *ConversionResult) GetErrorString() string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Error()
}

type Cryptogram struct {
	EphemeralPublicKey []byte
	Ciphertext         []byte
	MACTag             []byte
}

type PQCCryptogram struct {
	KEMCiphertext []byte
	Ciphertext    []byte
	MACTag        []byte
}

// HybridCryptogram represents the parsed Profile D (Hybrid ML-KEM + X25519) cryptogram structure
type HybridCryptogram struct {
	KEMCiphertext      []byte          // ML-KEM-768 ciphertext (1088 bytes)
	EphemeralPublicKey []byte          // X25519 ephemeral public key (32 bytes)
	Variant            ProfileDVariant // 0=baseline, 1=add17, 2=add19
	Nonce              []byte          // add17: 16 bytes, add19: 12 bytes, baseline: nil
	Ciphertext         []byte          // Encrypted MSIN
	MACTag             []byte          // add17/baseline: 8 bytes; add19: 16 bytes (AEAD tag)
}

// ProfileECryptogram represents the parsed Profile E (Nested Hybrid) cryptogram structure
// Layout: EphPub(32) || EncryptedKEMCT(1088) || KEMMAC(8) || EncryptedMSIN || MSINMAC(8)
type ProfileECryptogram struct {
	EphemeralPublicKey []byte // X25519 ephemeral public key (32 bytes) = c1
	EncryptedKEMCT     []byte // AES-256-CTR encrypted ML-KEM ciphertext (1088 bytes) = c2 body
	KEMMACTag          []byte // KMAC256 MAC over encrypted KEM ciphertext (8 bytes) = c2 mac
	Ciphertext         []byte // AES-256-CTR encrypted MSIN = c3 body
	MACTag             []byte // KMAC256 MAC over encrypted MSIN (8 bytes) = c3 mac
}

// ProfileFCryptogram represents the parsed Profile F (Wrapper Hybrid) cryptogram structure
// Layout: KEMCT(1088) || EncEph(32) || PQCMAC(8) || Ciphertext || MAC(8)
type ProfileFCryptogram struct {
	KEMCiphertext   []byte // ML-KEM-768 ciphertext (1088 bytes)
	EncryptedEphKey []byte // AES-256-CTR encrypted ephemeral public key (32 bytes)
	PQCMACTag       []byte // KMAC256 MAC over encrypted eph key (8 bytes)
	Ciphertext      []byte // AES-128-CTR encrypted MSIN
	MACTag          []byte // HMAC-SHA-256 MAC (8 bytes)
}

// ProfileGCryptogram represents the parsed Profile G (Symmetric) cryptogram structure.
// Layout: R || KeyCipherText(5) || MACkey || CipherText || MACmsin
type ProfileGCryptogram struct {
	R             []byte
	KeyCipherText []byte
	MACkey        []byte
	Ciphertext    []byte
	MACmsin       []byte
}

// ProfileGPrivateKeys contains key material for Profile G operations.
// HNSymmetricKey is selected by SUCI key ID. SubscriberKMasters maps a 5-byte
// subscriber key ID (hex string, lowercase, 10 chars) to a 16-byte Kmaster.
type ProfileGPrivateKeys struct {
	HNSymmetricKey     []byte
	SubscriberKMasters map[string][]byte
	WindowSizeSeconds  int64
}

// Profile E/F use the same key structure as Profile D (ML-KEM-768 + X25519)
type ProfileEPrivateKeys = ProfileDPrivateKeys
type ProfileEPublicKeys = ProfileDPublicKeys
type ProfileFPrivateKeys = ProfileDPrivateKeys
type ProfileFPublicKeys = ProfileDPublicKeys

// ConcealmentResult represents the result of SUPI to SUCI conversion
// (moved from encryptor.go)
type ConcealmentResult struct {
	SUCI       string     // The resulting SUCI string
	KeyID      uint8      // Key ID used for concealment
	SchemeID   SchemeID   // Scheme used
	Error      *ErrorCode // Error code if concealment failed
	PublicKey  []byte     // The HN public key used (for reference)
	PrivateKey []byte     // The HN private key used (for keygen cases)
}

func (r *ConcealmentResult) IsSuccess() bool {
	return r.Error == nil
}

func (r *ConcealmentResult) GetErrorString() string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Error()
}

var suciRegex = regexp.MustCompile(`^suci-([01])-(\d{3})-(\d{2,3})-(\d{1,4})-([0-7])-(\d{1,3})-([0-9a-fA-F]+)$`)

// ParseSUCI parses and validates a SUCI string
func ParseSUCI(suciStr string) (*ParsedSUCI, ErrorCode) {
	matches := suciRegex.FindStringSubmatch(suciStr)
	if matches == nil {
		return nil, E_PARSE_SUCI
	}

	typeStr := matches[1]
	mcc := matches[2]
	mnc := matches[3]
	routingInd := matches[4]
	schemeIDStr := matches[5]
	keyIDStr := matches[6]
	schemeOutputHex := matches[7]

	typeVal, _ := strconv.ParseUint(typeStr, 10, 8)
	identityType := IdentityType(typeVal)
	if !identityType.IsValid() {
		return nil, E_INVALID_TYPE
	}

	schemeIDVal, _ := strconv.ParseUint(schemeIDStr, 10, 8)
	schemeID := SchemeID(schemeIDVal)
	if !schemeID.IsValid() {
		return nil, E_INVALID_SCHEME_ID
	}

	keyIDVal, err := strconv.ParseUint(keyIDStr, 10, 8)
	if err != nil || keyIDVal > 255 {
		return nil, E_INVALID_KEY_ID
	}
	keyID := uint8(keyIDVal)

	schemeOutput, err := hex.DecodeString(schemeOutputHex)
	if err != nil {
		return nil, E_PARSE_SUCI
	}

	if schemeID == SchemeProfileA && len(schemeOutput) < ProfileA_MinLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
	if schemeID == SchemeProfileB && len(schemeOutput) < ProfileB_MinLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
	if schemeID == SchemeProfileC && len(schemeOutput) < ProfileC_MinLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
	if schemeID == SchemeProfileD && len(schemeOutput) < ProfileD_MinLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
	if schemeID == SchemeProfileE && len(schemeOutput) < ProfileE_MinLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
	if schemeID == SchemeProfileF && len(schemeOutput) < ProfileF_MinLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
	if schemeID == SchemeProfileG && len(schemeOutput) < ProfileG_Level3_MinLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}

	return &ParsedSUCI{
		Type:         identityType,
		MCC:          mcc,
		MNC:          mnc,
		RoutingInd:   routingInd,
		SchemeID:     schemeID,
		KeyID:        keyID,
		SchemeOutput: schemeOutput,
	}, 0
}

// ConstructSUPI constructs a SUPI from a SUCI
func ConstructSUPI(identityType IdentityType, mcc, mnc, msin string) (string, ErrorCode) {
	switch identityType {
	case TypeIMSI:
		imsi := mcc + mnc + msin
		if len(imsi) < IMSI_MIN_LEN || len(imsi) > IMSI_MAX_LEN {
			return "", E_INVALID_IMSI_LENGTH
		}
		return fmt.Sprintf("imsi-%s", imsi), 0
	case TypeNAI:
		return fmt.Sprintf("nai-%s", msin), 0
	default:
		return "", E_INVALID_TYPE
	}
}

// ParseCryptogram parses a cryptogram
func ParseCryptogram(schemeOutput []byte, scheme SchemeID) (*Cryptogram, ErrorCode) {
	var pubKeyLen, macLen int
	switch scheme {
	case SchemeProfileA:
		pubKeyLen = ProfileA_PubKeyLen
		macLen = ProfileA_MACLen
		if len(schemeOutput) < ProfileA_MinLen {
			return nil, E_SCHEME_OUTPUT_TOO_SHORT
		}
	case SchemeProfileB:
		pubKeyLen = ProfileB_PubKeyLen
		macLen = ProfileB_MACLen
		if len(schemeOutput) < ProfileB_MinLen {
			return nil, E_SCHEME_OUTPUT_TOO_SHORT
		}
	default:
		return nil, E_INVALID_SCHEME_ID
	}
	macStartIdx := len(schemeOutput) - macLen
	ciphertextLen := macStartIdx - pubKeyLen
	if ciphertextLen < 0 {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
	return &Cryptogram{
		EphemeralPublicKey: schemeOutput[0:pubKeyLen],
		Ciphertext:         schemeOutput[pubKeyLen:macStartIdx],
		MACTag:             schemeOutput[macStartIdx:],
	}, 0
}

// ParsePQCCryptogram parses Profile C scheme output using ML-KEM-768 layout (backward compatible).
func ParsePQCCryptogram(cryptogram []byte) (*PQCCryptogram, ErrorCode) {
	return ParsePQCCryptogramForLevel(cryptogram, MLKEMSecurityLevel3)
}

// ParsePQCCryptogramForLevel parses Profile C output for ML-KEM-768 (level 3) or ML-KEM-1024 (level 5).
func ParsePQCCryptogramForLevel(cryptogram []byte, level MLKEMSecurityLevel) (*PQCCryptogram, ErrorCode) {
	level = NormalizeMLKEMSecurityLevel(level)
	kemLen := KEMCiphertextLen(level)
	if len(cryptogram) < kemLen+ProfileC_MAC_TAG_LEN {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
	macStart := len(cryptogram) - ProfileC_MAC_TAG_LEN
	kem := make([]byte, kemLen)
	copy(kem, cryptogram[0:kemLen])
	ciphertext := make([]byte, macStart-kemLen)
	copy(ciphertext, cryptogram[kemLen:macStart])
	mac := make([]byte, ProfileC_MAC_TAG_LEN)
	copy(mac, cryptogram[macStart:])

	return &PQCCryptogram{
		KEMCiphertext: kem,
		Ciphertext:    ciphertext,
		MACTag:        mac,
	}, 0
}

// ParseProfileDCryptogram parses Profile D using ML-KEM-768 layout.
func ParseProfileDCryptogram(cryptogram []byte) (*HybridCryptogram, ErrorCode) {
	return ParseProfileDCryptogramForLevel(cryptogram, MLKEMSecurityLevel3)
}

// ParseProfileDCryptogramForLevel parses Profile D for the given ML-KEM parameter set.
// Baseline: KEMCiphertext || EphemeralPublicKey (32) || Ciphertext || MACTag (8)
// add17:    KEMCiphertext || EphemeralPublicKey || 0x01 || nonce(16) || Ciphertext || MACTag (8)
// add19:    KEMCiphertext || EphemeralPublicKey || 0x02 || nonce(12) || Ciphertext || tag(16)
func ParseProfileDCryptogramForLevel(cryptogram []byte, level MLKEMSecurityLevel) (*HybridCryptogram, ErrorCode) {
	level = NormalizeMLKEMSecurityLevel(level)
	kemLen := KEMCiphertextLen(level)
	minLen := kemLen + ProfileD_EphPubKeyLen + ProfileC_MAC_TAG_LEN
	if len(cryptogram) < minLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}

	kemEnd := kemLen
	ephEnd := kemEnd + ProfileD_EphPubKeyLen

	kem := make([]byte, kemLen)
	copy(kem, cryptogram[0:kemEnd])

	ephPub := make([]byte, ProfileD_EphPubKeyLen)
	copy(ephPub, cryptogram[kemEnd:ephEnd])

	// Check for extended format: variant byte at offset 1120
	if len(cryptogram) >= ephEnd+1 {
		v := cryptogram[ephEnd]
		if v == 0x01 {
			// add17: nonce(16) || ciphertext || macTag(8)
			if len(cryptogram) < ephEnd+1+ProfileD_Add17_NonceLen+ProfileC_MAC_TAG_LEN {
				return nil, E_SCHEME_OUTPUT_TOO_SHORT
			}
			nonce := make([]byte, ProfileD_Add17_NonceLen)
			copy(nonce, cryptogram[ephEnd+1:ephEnd+1+ProfileD_Add17_NonceLen])
			macStart := len(cryptogram) - ProfileC_MAC_TAG_LEN
			ciphertext := make([]byte, macStart-(ephEnd+1+ProfileD_Add17_NonceLen))
			copy(ciphertext, cryptogram[ephEnd+1+ProfileD_Add17_NonceLen:macStart])
			mac := make([]byte, ProfileC_MAC_TAG_LEN)
			copy(mac, cryptogram[macStart:])
			return &HybridCryptogram{
				KEMCiphertext:      kem,
				EphemeralPublicKey: ephPub,
				Variant:            ProfileDVariantAdd17,
				Nonce:              nonce,
				Ciphertext:         ciphertext,
				MACTag:             mac,
			}, 0
		}
		if v == 0x02 {
			// add19: nonce(12) || ciphertext || tag(16)
			if len(cryptogram) < ephEnd+1+ProfileD_Add19_NonceLen+ProfileD_Add19_TagLen {
				return nil, E_SCHEME_OUTPUT_TOO_SHORT
			}
			nonce := make([]byte, ProfileD_Add19_NonceLen)
			copy(nonce, cryptogram[ephEnd+1:ephEnd+1+ProfileD_Add19_NonceLen])
			tagStart := len(cryptogram) - ProfileD_Add19_TagLen
			ciphertext := make([]byte, tagStart-(ephEnd+1+ProfileD_Add19_NonceLen))
			copy(ciphertext, cryptogram[ephEnd+1+ProfileD_Add19_NonceLen:tagStart])
			mac := make([]byte, ProfileD_Add19_TagLen)
			copy(mac, cryptogram[tagStart:])
			return &HybridCryptogram{
				KEMCiphertext:      kem,
				EphemeralPublicKey: ephPub,
				Variant:            ProfileDVariantAdd19,
				Nonce:              nonce,
				Ciphertext:         ciphertext,
				MACTag:             mac,
			}, 0
		}
	}

	// Baseline: no variant byte
	macStart := len(cryptogram) - ProfileC_MAC_TAG_LEN
	ciphertext := make([]byte, macStart-ephEnd)
	copy(ciphertext, cryptogram[ephEnd:macStart])
	mac := make([]byte, ProfileC_MAC_TAG_LEN)
	copy(mac, cryptogram[macStart:])
	return &HybridCryptogram{
		KEMCiphertext:      kem,
		EphemeralPublicKey: ephPub,
		Variant:            ProfileDVariantBaseline,
		Ciphertext:         ciphertext,
		MACTag:             mac,
	}, 0
}

// ValidateKeySchemeMatch checks if the private key matches the scheme
func ValidateKeySchemeMatch(privateKey interface{}, scheme SchemeID) ErrorCode {
	switch scheme {
	case SchemeProfileA:
		if keyBytes, ok := privateKey.([]byte); !ok || len(keyBytes) != 32 {
			return E_CURVE_MISMATCH
		}
		return 0
	case SchemeProfileB:
		if ecKey, ok := privateKey.(*ecdsa.PrivateKey); !ok || ecKey.Curve != elliptic.P256() {
			return E_CURVE_MISMATCH
		}
		return 0
	case SchemeProfileC:
		keyBytes, ok := privateKey.([]byte)
		if !ok {
			return E_CURVE_MISMATCH
		}
		if _, err := InferMLKEMSecurityLevelFromMLKEMPrivateLen(len(keyBytes)); err != nil {
			return E_CURVE_MISMATCH
		}
		return 0
	case SchemeProfileD:
		composite, ok := privateKey.(*ProfileDPrivateKeys)
		if !ok || composite == nil || len(composite.X25519Private) != 32 {
			return E_CURVE_MISMATCH
		}
		if _, err := InferMLKEMSecurityLevelFromMLKEMPrivateLen(len(composite.MLKEMPrivate)); err != nil {
			return E_CURVE_MISMATCH
		}
		return 0
	case SchemeProfileE:
		composite, ok := privateKey.(*ProfileDPrivateKeys)
		if !ok || composite == nil || len(composite.X25519Private) != 32 {
			return E_CURVE_MISMATCH
		}
		if _, err := InferMLKEMSecurityLevelFromMLKEMPrivateLen(len(composite.MLKEMPrivate)); err != nil {
			return E_CURVE_MISMATCH
		}
		return 0
	case SchemeProfileF:
		composite, ok := privateKey.(*ProfileDPrivateKeys)
		if !ok || composite == nil || len(composite.X25519Private) != 32 {
			return E_CURVE_MISMATCH
		}
		if _, err := InferMLKEMSecurityLevelFromMLKEMPrivateLen(len(composite.MLKEMPrivate)); err != nil {
			return E_CURVE_MISMATCH
		}
		return 0
	case SchemeProfileG:
		material, ok := privateKey.(*ProfileGKeyMaterial)
		if !ok || material == nil {
			return E_CURVE_MISMATCH
		}
		level := NormalizeMLKEMSecurityLevel(material.SecurityLevel)
		_, _, keyLen := profileGParams(level)
		if len(material.HNSymmetricKey) != keyLen || len(material.SubscriberKeys) == 0 {
			return E_CURVE_MISMATCH
		}
		return 0
	case SchemeNullScheme:
		return 0
	default:
		return E_INVALID_SCHEME_ID
	}
}

// DecryptECIES performs ECIES decryption for Profile A or Profile B
func DecryptECIES(cryptogram *Cryptogram, privateKey interface{}, scheme SchemeID) ([]byte, ErrorCode) {
	switch scheme {
	case SchemeProfileA:
		return decryptProfileA(cryptogram, privateKey)
	case SchemeProfileB:
		return decryptProfileB(cryptogram, privateKey)
	default:
		return nil, E_INVALID_SCHEME_ID
	}
}

// DecryptPQC performs PQC decryption for Profile C (ML-KEM-768)
func DecryptPQC(pqcCryptogram *PQCCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	return decryptProfileC(pqcCryptogram, privateKey)
}

// decryptProfileA handles ECIES Profile A (Curve25519/X25519)
func decryptProfileA(cryptogram *Cryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	slog.Debugf("[DEBUG] DecryptECIES/ProfileA: EphemeralPublicKey: %x\n", cryptogram.EphemeralPublicKey)
	slog.Debugf("[DEBUG] DecryptECIES/ProfileA: Ciphertext: %x\n", cryptogram.Ciphertext)
	slog.Debugf("[DEBUG] DecryptECIES/ProfileA: MAC: %x\n", cryptogram.MACTag)
	privKeyBytes, ok := privateKey.([]byte)
	if !ok || len(privKeyBytes) != 32 {
		return nil, E_INVALID_EC_KEY
	}
	if len(cryptogram.EphemeralPublicKey) != ProfileA_PubKeyLen {
		return nil, E_INVALID_EC_KEY
	}
	sharedSecret, err := curve25519.X25519(privKeyBytes, cryptogram.EphemeralPublicKey)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}
	derivedKeys := kdfANSIX963(sharedSecret, KDF_OUTPUT_LEN)
	if len(derivedKeys) < KDF_OUTPUT_LEN {
		return nil, E_INVALID_EC_KEY
	}
	encKey := derivedKeys[0:AES_KEY_LEN]
	macKey := derivedKeys[AES_KEY_LEN:KDF_OUTPUT_LEN]
	if errCode := verifyMAC(cryptogram, macKey); errCode != 0 {
		return nil, errCode
	}
	plaintext, errCode := decryptAESCTR(cryptogram.Ciphertext, encKey)
	if errCode != 0 {
		return nil, errCode
	}
	return plaintext, 0
}

// decryptProfileB handles ECIES Profile B (secp256r1/NIST P-256)
func decryptProfileB(cryptogram *Cryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	privKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, E_INVALID_EC_KEY
	}
	if privKey.Curve != elliptic.P256() {
		return nil, E_CURVE_MISMATCH
	}
	if len(cryptogram.EphemeralPublicKey) != ProfileB_PubKeyLen {
		return nil, E_INVALID_EC_KEY
	}
	ephemeralPubKey, err := decompressP256Point(cryptogram.EphemeralPublicKey)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}
	sharedX, _ := privKey.Curve.ScalarMult(ephemeralPubKey.X, ephemeralPubKey.Y, privKey.D.Bytes())
	sharedSecret := sharedX.Bytes()
	if len(sharedSecret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(sharedSecret):], sharedSecret)
		sharedSecret = padded
	}
	derivedKeys := kdfANSIX963(sharedSecret, KDF_OUTPUT_LEN)
	if len(derivedKeys) < KDF_OUTPUT_LEN {
		return nil, E_INVALID_EC_KEY
	}
	encKey := derivedKeys[0:AES_KEY_LEN]
	macKey := derivedKeys[AES_KEY_LEN:KDF_OUTPUT_LEN]
	if errCode := verifyMAC(cryptogram, macKey); errCode != 0 {
		return nil, errCode
	}
	plaintext, errCode := decryptAESCTR(cryptogram.Ciphertext, encKey)
	if errCode != 0 {
		return nil, errCode
	}
	return plaintext, 0
}

// decryptProfileC handles PQC Profile C (ML-KEM-768 or ML-KEM-1024)
func decryptProfileC(pqcCryptogram *PQCCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	privKeyBytes, ok := privateKey.([]byte)
	if !ok {
		return nil, E_INVALID_PQC_KEY
	}
	kemLen := len(pqcCryptogram.KEMCiphertext)
	switch kemLen {
	case MLKEM768_CIPHERTEXT_LEN:
		if len(privKeyBytes) != MLKEM768_PRIVATE_KEY_LEN {
			return nil, E_INVALID_PQC_KEY
		}
		var privKey mlkem768.PrivateKey
		if err := privKey.Unpack(privKeyBytes); err != nil {
			return nil, E_INVALID_PQC_KEY
		}
		sharedSecret := make([]byte, MLKEM768_SHARED_SECRET)
		privKey.DecapsulateTo(sharedSecret, pqcCryptogram.KEMCiphertext)
		return decryptProfileCFromSS(sharedSecret, pqcCryptogram)
	case MLKEM1024_CIPHERTEXT_LEN:
		if len(privKeyBytes) != MLKEM1024_PRIVATE_KEY_LEN {
			return nil, E_INVALID_PQC_KEY
		}
		var privKey mlkem1024.PrivateKey
		if err := privKey.Unpack(privKeyBytes); err != nil {
			return nil, E_INVALID_PQC_KEY
		}
		sharedSecret := make([]byte, MLKEM1024_SHARED_SECRET)
		privKey.DecapsulateTo(sharedSecret, pqcCryptogram.KEMCiphertext)
		return decryptProfileCFromSS(sharedSecret, pqcCryptogram)
	default:
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
}

func decryptProfileCFromSS(sharedSecret []byte, pqcCryptogram *PQCCryptogram) ([]byte, ErrorCode) {
	derivedKeys := kdfANSIX963SHA3Decrypt(sharedSecret, pqcCryptogram.KEMCiphertext, ProfileC_KDF_OUTPUT)
	if len(derivedKeys) < ProfileC_KDF_OUTPUT {
		return nil, E_KEM_DECAPSULATE_FAILED
	}
	encKey := derivedKeys[0:ProfileC_ENC_KEY_LEN]
	macKey := derivedKeys[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT]
	if errCode := verifyKMAC256(pqcCryptogram.Ciphertext, pqcCryptogram.MACTag, macKey); errCode != 0 {
		return nil, errCode
	}
	plaintext, errCode := decryptAES256CTR(pqcCryptogram.Ciphertext, encKey)
	if errCode != 0 {
		return nil, errCode
	}
	return plaintext, 0
}

// mlkemDecapsulate runs ML-KEM decapsulation for 768 or 1024 key/ciphertext sizes.
func mlkemDecapsulate(mlkemPriv []byte, kemCiphertext []byte) ([]byte, ErrorCode) {
	switch len(kemCiphertext) {
	case MLKEM768_CIPHERTEXT_LEN:
		if len(mlkemPriv) != MLKEM768_PRIVATE_KEY_LEN {
			return nil, E_INVALID_PQC_KEY
		}
		var pk mlkem768.PrivateKey
		if err := pk.Unpack(mlkemPriv); err != nil {
			return nil, E_INVALID_PQC_KEY
		}
		ss := make([]byte, MLKEM768_SHARED_SECRET)
		pk.DecapsulateTo(ss, kemCiphertext)
		return ss, 0
	case MLKEM1024_CIPHERTEXT_LEN:
		if len(mlkemPriv) != MLKEM1024_PRIVATE_KEY_LEN {
			return nil, E_INVALID_PQC_KEY
		}
		var pk mlkem1024.PrivateKey
		if err := pk.Unpack(mlkemPriv); err != nil {
			return nil, E_INVALID_PQC_KEY
		}
		ss := make([]byte, MLKEM1024_SHARED_SECRET)
		pk.DecapsulateTo(ss, kemCiphertext)
		return ss, 0
	default:
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
}

// DecryptHybrid performs hybrid decryption for Profile D (ML-KEM-768 + X25519)
func DecryptHybrid(hybridCryptogram *HybridCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	switch hybridCryptogram.Variant {
	case ProfileDVariantAdd17:
		return decryptProfileDAdd17(hybridCryptogram, privateKey)
	case ProfileDVariantAdd19:
		return decryptProfileDAdd19(hybridCryptogram, privateKey)
	default:
		return decryptProfileD(hybridCryptogram, privateKey)
	}
}

// decryptProfileD handles Hybrid Profile D (ML-KEM + X25519)
func decryptProfileD(hybridCryptogram *HybridCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	privKeys, ok := privateKey.(*ProfileDPrivateKeys)
	if !ok {
		return nil, E_INVALID_PQC_KEY
	}
	if len(privKeys.X25519Private) != 32 {
		return nil, E_INVALID_EC_KEY
	}
	if len(hybridCryptogram.EphemeralPublicKey) != ProfileD_EphPubKeyLen {
		return nil, E_INVALID_EC_KEY
	}

	sharedSecret1, errCode := mlkemDecapsulate(privKeys.MLKEMPrivate, hybridCryptogram.KEMCiphertext)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 2: X25519 ECDH
	sharedSecret2, err := curve25519.X25519(privKeys.X25519Private, hybridCryptogram.EphemeralPublicKey)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 3: Combine shared secrets using SHA3-256
	combiner := sha3.New256()
	combiner.Write(sharedSecret1)
	combiner.Write(sharedSecret2)
	combinedSecret := combiner.Sum(nil)

	// STEP 4: Derive keys using ANSI-X9.63-KDF with SHA3-256
	// SharedInfo1 = KEMCiphertext || EphemeralPublicKey
	sharedInfo1 := make([]byte, 0, len(hybridCryptogram.KEMCiphertext)+len(hybridCryptogram.EphemeralPublicKey))
	sharedInfo1 = append(sharedInfo1, hybridCryptogram.KEMCiphertext...)
	sharedInfo1 = append(sharedInfo1, hybridCryptogram.EphemeralPublicKey...)

	derivedKeys := kdfANSIX963SHA3Decrypt(combinedSecret, sharedInfo1, ProfileC_KDF_OUTPUT)
	if len(derivedKeys) < ProfileC_KDF_OUTPUT {
		return nil, E_KEM_DECAPSULATE_FAILED
	}

	encKey := derivedKeys[0:ProfileC_ENC_KEY_LEN]
	macKey := derivedKeys[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT]

	// STEP 5: Verify MAC using KMAC256
	if errCode := verifyKMAC256(hybridCryptogram.Ciphertext, hybridCryptogram.MACTag, macKey); errCode != 0 {
		return nil, errCode
	}

	// STEP 6: Decrypt ciphertext using AES-256-CTR
	plaintext, errCode := decryptAES256CTR(hybridCryptogram.Ciphertext, encKey)
	if errCode != 0 {
		return nil, errCode
	}

	return plaintext, 0
}

// decryptProfileDAdd17 handles add17 variant: SharedInfo1 = kemCt || ephPub || nonce || 0x04 || 0x17
func decryptProfileDAdd17(hybridCryptogram *HybridCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	privKeys, ok := privateKey.(*ProfileDPrivateKeys)
	if !ok || len(privKeys.X25519Private) != 32 {
		return nil, E_INVALID_PQC_KEY
	}
	if len(hybridCryptogram.Nonce) != ProfileD_Add17_NonceLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}

	sharedSecret1, errCode := mlkemDecapsulate(privKeys.MLKEMPrivate, hybridCryptogram.KEMCiphertext)
	if errCode != 0 {
		return nil, errCode
	}

	sharedSecret2, err := curve25519.X25519(privKeys.X25519Private, hybridCryptogram.EphemeralPublicKey)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	combiner := sha3.New256()
	combiner.Write(sharedSecret1)
	combiner.Write(sharedSecret2)
	combinedSecret := combiner.Sum(nil)

	// SharedInfo1 = kemCt || ephPub || nonce || profileID(0x04) || hybridCode(0x17)
	sharedInfo1 := make([]byte, 0, len(hybridCryptogram.KEMCiphertext)+len(hybridCryptogram.EphemeralPublicKey)+ProfileD_Add17_NonceLen+2)
	sharedInfo1 = append(sharedInfo1, hybridCryptogram.KEMCiphertext...)
	sharedInfo1 = append(sharedInfo1, hybridCryptogram.EphemeralPublicKey...)
	sharedInfo1 = append(sharedInfo1, hybridCryptogram.Nonce...)
	sharedInfo1 = append(sharedInfo1, 0x04, 0x17)

	derivedKeys := kdfANSIX963SHA3Decrypt(combinedSecret, sharedInfo1, ProfileC_KDF_OUTPUT)
	encKey := derivedKeys[0:ProfileC_ENC_KEY_LEN]
	macKey := derivedKeys[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT]

	if errCode := verifyKMAC256(hybridCryptogram.Ciphertext, hybridCryptogram.MACTag, macKey); errCode != 0 {
		return nil, errCode
	}
	return decryptAES256CTR(hybridCryptogram.Ciphertext, encKey)
}

// decryptProfileDAdd19 handles add19 variant: AEAD with AAD = kemCt || ephPub
func decryptProfileDAdd19(hybridCryptogram *HybridCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	privKeys, ok := privateKey.(*ProfileDPrivateKeys)
	if !ok || len(privKeys.X25519Private) != 32 {
		return nil, E_INVALID_PQC_KEY
	}
	if len(hybridCryptogram.Nonce) != ProfileD_Add19_NonceLen || len(hybridCryptogram.MACTag) != ProfileD_Add19_TagLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}

	sharedSecret1, errCode := mlkemDecapsulate(privKeys.MLKEMPrivate, hybridCryptogram.KEMCiphertext)
	if errCode != 0 {
		return nil, errCode
	}

	sharedSecret2, err := curve25519.X25519(privKeys.X25519Private, hybridCryptogram.EphemeralPublicKey)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	combiner := sha3.New256()
	combiner.Write(sharedSecret1)
	combiner.Write(sharedSecret2)
	combinedSecret := combiner.Sum(nil)

	// SharedInfo1 = kemCt || ephPub || profileID(0x04) || hybridCode(0x19)
	sharedInfo1 := make([]byte, 0, len(hybridCryptogram.KEMCiphertext)+len(hybridCryptogram.EphemeralPublicKey)+2)
	sharedInfo1 = append(sharedInfo1, hybridCryptogram.KEMCiphertext...)
	sharedInfo1 = append(sharedInfo1, hybridCryptogram.EphemeralPublicKey...)
	sharedInfo1 = append(sharedInfo1, 0x04, 0x19)

	// KDF output = aeadKey(32) || nonce(12)
	kdfOutput := ProfileC_ENC_KEY_LEN + ProfileD_Add19_NonceLen
	derived := kdfANSIX963SHA3Decrypt(combinedSecret, sharedInfo1, kdfOutput)
	aeadKey := derived[0:ProfileC_ENC_KEY_LEN]
	derivedNonce := derived[ProfileC_ENC_KEY_LEN:kdfOutput]

	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, E_ENCRYPTION_FAILED
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, E_ENCRYPTION_FAILED
	}
	aad := make([]byte, 0, len(hybridCryptogram.KEMCiphertext)+len(hybridCryptogram.EphemeralPublicKey))
	aad = append(aad, hybridCryptogram.KEMCiphertext...)
	aad = append(aad, hybridCryptogram.EphemeralPublicKey...)

	ciphertextWithTag := append(hybridCryptogram.Ciphertext, hybridCryptogram.MACTag...)
	plaintext, err := aead.Open(nil, derivedNonce, ciphertextWithTag, aad)
	if err != nil {
		return nil, E_TAG_MISMATCH
	}
	return plaintext, 0
}

// --- STUB HELPERS FOR CRYPTO ---
func kdfANSIX963(z []byte, keyLen int) []byte {
	// ANSI X9.63 KDF: DerivedKey = Hash(Z || Counter || SharedInfo1)
	// For Profile A, SharedInfo1 is empty
	var result []byte
	counter := uint32(1)
	for len(result) < keyLen {
		h := sha256.New()
		h.Write(z)
		// Counter as 4 bytes (big-endian)
		counterBytes := []byte{
			byte(counter >> 24),
			byte(counter >> 16),
			byte(counter >> 8),
			byte(counter),
		}
		h.Write(counterBytes)
		// No SharedInfo1 for Profile A
		result = append(result, h.Sum(nil)...)
		counter++
	}
	return result[:keyLen]
}

func verifyMAC(cryptogram *Cryptogram, macKey []byte) ErrorCode {
	// HMAC-SHA-256 over (ephemeralPubKey || ciphertext), first 16 bytes
	macInput := append(cryptogram.EphemeralPublicKey, cryptogram.Ciphertext...)
	mac := hmac.New(sha256.New, macKey)
	mac.Write(macInput)
	computedMAC := mac.Sum(nil)
	expectedMAC := computedMAC[:ProfileA_MACLen]
	if !bytes.Equal(expectedMAC, cryptogram.MACTag) {
		return E_TAG_MISMATCH
	}
	return 0
}

func decryptAESCTR(ciphertext, key []byte) ([]byte, ErrorCode) {
	// AES-128-CTR decryption with zero IV
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}
	iv := make([]byte, 16)
	slog.Debugf("[DEBUG] AES-CTR Decrypt: key=%x iv=%x\n", key, iv)
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, 0
}

type p256Point struct{ X, Y *big.Int }

func decompressP256Point(data []byte) (*p256Point, error) {
	// Compressed format: [0x02/0x03][32-byte X]
	if len(data) != 33 {
		return nil, fmt.Errorf("invalid compressed P-256 point length")
	}
	prefix := data[0]
	x := new(big.Int).SetBytes(data[1:33])
	curve := elliptic.P256()
	y, err := decompressY(curve, x, prefix)
	if err != nil {
		return nil, err
	}
	return &p256Point{X: x, Y: y}, nil
}

// decompressY calculates Y from X and prefix for P-256
func decompressY(curve elliptic.Curve, x *big.Int, prefix byte) (*big.Int, error) {
	// y^2 = x^3 + ax + b mod p
	params := curve.Params()
	x3 := new(big.Int).Exp(x, big.NewInt(3), params.P)
	// Curve parameter 'a' is -3 for P-256; compute a = p-3 (mod p)
	a := new(big.Int).Sub(params.P, big.NewInt(3))
	ax := new(big.Int).Mul(a, x)
	ax.Mod(ax, params.P)
	rhs := new(big.Int).Add(x3, ax)
	rhs.Add(rhs, params.B)
	rhs.Mod(rhs, params.P)
	y := new(big.Int).ModSqrt(rhs, params.P)
	if y == nil {
		return nil, fmt.Errorf("failed to decompress Y coordinate")
	}
	// Check parity
	if (prefix == 0x02 && y.Bit(0) == 1) || (prefix == 0x03 && y.Bit(0) == 0) {
		y.Sub(params.P, y)
	}
	return y, nil
}

func kdfANSIX963SHA3Decrypt(z, sharedInfo1 []byte, keyLen int) []byte {
	// ANSI X9.63 KDF: DerivedKey = SHA3-256(Z || Counter || SharedInfo1)
	var result []byte
	counter := uint32(1)
	for len(result) < keyLen {
		h := sha3.New256()
		h.Write(z)
		counterBytes := []byte{
			byte(counter >> 24),
			byte(counter >> 16),
			byte(counter >> 8),
			byte(counter),
		}
		h.Write(counterBytes)
		h.Write(sharedInfo1)
		result = append(result, h.Sum(nil)...)
		counter++
	}
	return result[:keyLen]
}

func verifyKMAC256(ciphertext, macTag, macKey []byte) ErrorCode {
	// KMAC256(K, X, L, S) where:
	// K = key (32 bytes)
	// X = data (encrypted MSIN)
	// L = output length in bits (64)
	// S = customization string ("SUCI-MAC")
	customString := []byte("SUCI-MAC")
	kmac := sha3.NewCShake256(nil, customString)
	encodedKey := encodeString(macKey)
	padded := bytepad(encodedKey, 136)
	kmac.Write(padded)
	kmac.Write(ciphertext)
	kmac.Write(rightEncode(64))
	result := make([]byte, 8)
	kmac.Read(result)
	if !bytes.Equal(result, macTag) {
		return E_TAG_MISMATCH
	}
	return 0
}

func decryptAES256CTR(ciphertext, key []byte) ([]byte, ErrorCode) {
	if len(key) != 32 {
		return nil, E_ENCRYPTION_FAILED
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, E_ENCRYPTION_FAILED
	}
	icb := make([]byte, AES_IV_LEN)
	stream := cipher.NewCTR(block, icb)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, 0
}

// leftEncode encodes an integer per NIST SP 800-185
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{1, 0}
	}

	n := 1
	tmp := x
	for tmp > 255 {
		tmp >>= 8
		n++
	}

	result := make([]byte, n+1)
	result[0] = byte(n)
	for i := n; i > 0; i-- {
		result[i] = byte(x)
		x >>= 8
	}
	return result
}

// rightEncode encodes an integer per NIST SP 800-185
func rightEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0, 1}
	}
	n := 1
	tmp := x
	for tmp > 255 {
		tmp >>= 8
		n++
	}
	result := make([]byte, n+1)
	result[n] = byte(n)
	for i := n - 1; i >= 0; i-- {
		result[i] = byte(x)
		x >>= 8
	}
	return result
}

// encodeString encodes a byte string per NIST SP 800-185
func encodeString(s []byte) []byte {
	encoded := leftEncode(uint64(len(s) * 8))
	return append(encoded, s...)
}

// bytepad pads the input to a multiple of w bytes
func bytepad(x []byte, w int) []byte {
	encoded := leftEncode(uint64(w))
	buf := append(encoded, x...)

	padLen := w - (len(buf) % w)
	if padLen == w {
		padLen = 0
	}
	padding := make([]byte, padLen)
	return append(buf, padding...)
}

// ParseProfileECryptogram parses Profile E using ML-KEM-768 layout.
func ParseProfileECryptogram(cryptogram []byte) (*ProfileECryptogram, ErrorCode) {
	return ParseProfileECryptogramForLevel(cryptogram, MLKEMSecurityLevel3)
}

// ParseProfileECryptogramForLevel parses Profile E (Nested Hybrid) for the given ML-KEM size.
// Layout: EphPub(32) || EncryptedKEMCT || KEMMAC(8) || EncryptedMSIN || MSINMAC(8)
func ParseProfileECryptogramForLevel(cryptogram []byte, level MLKEMSecurityLevel) (*ProfileECryptogram, ErrorCode) {
	level = NormalizeMLKEMSecurityLevel(level)
	kemLen := KEMCiphertextLen(level)
	minLen := ProfileEMinLen(level)
	if len(cryptogram) < minLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}

	ephEnd := ProfileE_EphPubKeyLen // 32
	encKEMEnd := ephEnd + kemLen
	kemMACEnd := encKEMEnd + ProfileC_MAC_TAG_LEN
	msinMACStart := len(cryptogram) - ProfileC_MAC_TAG_LEN

	if msinMACStart < kemMACEnd {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}

	ephPub := make([]byte, ProfileE_EphPubKeyLen)
	copy(ephPub, cryptogram[0:ephEnd])

	encKEMCT := make([]byte, kemLen)
	copy(encKEMCT, cryptogram[ephEnd:encKEMEnd])

	kemMAC := make([]byte, ProfileC_MAC_TAG_LEN)
	copy(kemMAC, cryptogram[encKEMEnd:kemMACEnd])

	encMSIN := make([]byte, msinMACStart-kemMACEnd)
	copy(encMSIN, cryptogram[kemMACEnd:msinMACStart])

	msinMAC := make([]byte, ProfileC_MAC_TAG_LEN)
	copy(msinMAC, cryptogram[msinMACStart:])

	return &ProfileECryptogram{
		EphemeralPublicKey: ephPub,
		EncryptedKEMCT:     encKEMCT,
		KEMMACTag:          kemMAC,
		Ciphertext:         encMSIN,
		MACTag:             msinMAC,
	}, 0
}

// ParseProfileFCryptogram parses Profile F using ML-KEM-768 layout.
func ParseProfileFCryptogram(cryptogram []byte) (*ProfileFCryptogram, ErrorCode) {
	return ParseProfileFCryptogramForLevel(cryptogram, MLKEMSecurityLevel3)
}

// ParseProfileFCryptogramForLevel parses Profile F for the given ML-KEM size.
// Layout: KEMCT || EncEph(32) || PQCMAC(8) || Ciphertext || MAC(8)
func ParseProfileFCryptogramForLevel(cryptogram []byte, level MLKEMSecurityLevel) (*ProfileFCryptogram, ErrorCode) {
	level = NormalizeMLKEMSecurityLevel(level)
	kemLen := KEMCiphertextLen(level)
	minLen := ProfileFMinLen(level)
	if len(cryptogram) < minLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}

	kemEnd := kemLen
	encEphEnd := kemEnd + ProfileF_EncEphLen
	pqcMACEnd := encEphEnd + ProfileC_MAC_TAG_LEN
	macStart := len(cryptogram) - MAC_TAG_LEN

	if macStart < pqcMACEnd {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}

	kemCT := make([]byte, kemLen)
	copy(kemCT, cryptogram[0:kemEnd])

	encEph := make([]byte, ProfileF_EncEphLen)
	copy(encEph, cryptogram[kemEnd:encEphEnd])

	pqcMAC := make([]byte, ProfileC_MAC_TAG_LEN)
	copy(pqcMAC, cryptogram[encEphEnd:pqcMACEnd])

	ct := make([]byte, macStart-pqcMACEnd)
	copy(ct, cryptogram[pqcMACEnd:macStart])

	mac := make([]byte, MAC_TAG_LEN)
	copy(mac, cryptogram[macStart:])

	return &ProfileFCryptogram{
		KEMCiphertext:   kemCT,
		EncryptedEphKey: encEph,
		PQCMACTag:       pqcMAC,
		Ciphertext:      ct,
		MACTag:          mac,
	}, 0
}

// DecryptNestedHybrid performs Profile E (Nested Hybrid) decryption
// Flow: ECDH → decrypt KEM ciphertext → ML-KEM decapsulate → decrypt MSIN
func DecryptNestedHybrid(cryptogram *ProfileECryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	privKeys, ok := privateKey.(*ProfileDPrivateKeys)
	if !ok || privKeys == nil {
		return nil, E_INVALID_PQC_KEY
	}
	if len(privKeys.X25519Private) != 32 {
		return nil, E_INVALID_EC_KEY
	}
	// STEP 1: ECDH to recover k1
	k1, err := curve25519.X25519(privKeys.X25519Private, cryptogram.EphemeralPublicKey)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 2: Derive encryption and MAC keys from k1
	// SharedInfo1 = ephemeral public key
	derivedKeys1 := kdfANSIX963SHA3Decrypt(k1, cryptogram.EphemeralPublicKey, ProfileC_KDF_OUTPUT)
	if len(derivedKeys1) < ProfileC_KDF_OUTPUT {
		return nil, E_ENCRYPTION_FAILED
	}
	encKey1 := derivedKeys1[0:ProfileC_ENC_KEY_LEN]
	macKey1 := derivedKeys1[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT]

	// STEP 3: Verify MAC over encrypted KEM ciphertext
	if errCode := verifyKMAC256(cryptogram.EncryptedKEMCT, cryptogram.KEMMACTag, macKey1); errCode != 0 {
		return nil, errCode
	}

	// STEP 4: Decrypt KEM ciphertext
	kemCT, errCode := decryptAES256CTR(cryptogram.EncryptedKEMCT, encKey1)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 5: ML-KEM decapsulation to recover k0
	k0, errCode := mlkemDecapsulate(privKeys.MLKEMPrivate, kemCT)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 6: Derive encryption and MAC keys from k0
	// SharedInfo1 = original KEM ciphertext (decrypted)
	derivedKeys0 := kdfANSIX963SHA3Decrypt(k0, kemCT, ProfileC_KDF_OUTPUT)
	if len(derivedKeys0) < ProfileC_KDF_OUTPUT {
		return nil, E_KEM_DECAPSULATE_FAILED
	}
	encKey0 := derivedKeys0[0:ProfileC_ENC_KEY_LEN]
	macKey0 := derivedKeys0[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT]

	// STEP 7: Verify MAC over encrypted MSIN
	if errCode := verifyKMAC256(cryptogram.Ciphertext, cryptogram.MACTag, macKey0); errCode != 0 {
		return nil, errCode
	}

	// STEP 8: Decrypt MSIN
	plaintext, errCode := decryptAES256CTR(cryptogram.Ciphertext, encKey0)
	if errCode != 0 {
		return nil, errCode
	}

	return plaintext, 0
}

// DecryptWrapperHybrid performs Profile F (Wrapper Hybrid) decryption
// Flow: ML-KEM decapsulate → decrypt ephemeral key → ECDH → verify MAC → decrypt MSIN
func DecryptWrapperHybrid(cryptogram *ProfileFCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	privKeys, ok := privateKey.(*ProfileDPrivateKeys)
	if !ok || privKeys == nil {
		return nil, E_INVALID_PQC_KEY
	}
	if len(privKeys.X25519Private) != 32 {
		return nil, E_INVALID_EC_KEY
	}

	kemSS, errCode := mlkemDecapsulate(privKeys.MLKEMPrivate, cryptogram.KEMCiphertext)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 2: Derive PQC encryption and MAC keys from KEM shared secret
	// SharedInfo1 = KEM ciphertext
	pqcDerived := kdfANSIX963SHA3Decrypt(kemSS, cryptogram.KEMCiphertext, ProfileC_KDF_OUTPUT)
	if len(pqcDerived) < ProfileC_KDF_OUTPUT {
		return nil, E_KEM_DECAPSULATE_FAILED
	}
	pqcEncKey := pqcDerived[0:ProfileC_ENC_KEY_LEN]
	pqcMacKey := pqcDerived[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT]

	// STEP 3: Verify PQC MAC over encrypted ephemeral key
	if errCode := verifyKMAC256(cryptogram.EncryptedEphKey, cryptogram.PQCMACTag, pqcMacKey); errCode != 0 {
		return nil, errCode
	}

	// STEP 4: Decrypt ephemeral public key
	ephPub, errCode := decryptAES256CTR(cryptogram.EncryptedEphKey, pqcEncKey)
	if errCode != 0 {
		return nil, errCode
	}
	if len(ephPub) != 32 {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 5: ECDH to compute shared secret (same as Profile A)
	sharedSecret, err := curve25519.X25519(privKeys.X25519Private, ephPub)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 6: Derive ECIES keys (same as Profile A: ANSI-X9.63-KDF with SHA-256)
	derivedKeys := kdfANSIX963(sharedSecret, KDF_OUTPUT_LEN)
	if len(derivedKeys) < KDF_OUTPUT_LEN {
		return nil, E_INVALID_EC_KEY
	}
	encKey := derivedKeys[0:AES_KEY_LEN]
	macKey := derivedKeys[AES_KEY_LEN:KDF_OUTPUT_LEN]

	// STEP 7: Verify ECIES MAC (HMAC-SHA-256 over ephPub || ciphertext)
	eciesCryptogram := &Cryptogram{
		EphemeralPublicKey: ephPub,
		Ciphertext:         cryptogram.Ciphertext,
		MACTag:             cryptogram.MACTag,
	}
	if errCode := verifyMAC(eciesCryptogram, macKey); errCode != 0 {
		return nil, errCode
	}

	// STEP 8: Decrypt MSIN using AES-128-CTR (same as Profile A)
	plaintext, errCode := decryptAESCTR(cryptogram.Ciphertext, encKey)
	if errCode != 0 {
		return nil, errCode
	}

	return plaintext, 0
}
