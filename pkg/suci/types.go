package suci

import (
	"fmt"

	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
)

// Error codes following the specification from the flow diagram
const (
	// Parse Errors (0x1xx)
	E_PARSE_SUCI ErrorCode = 0x101 // Invalid SUCI format
	E_PARSE_SUPI ErrorCode = 0x102 // Invalid SUPI format

	// Cryptographic Errors (0x2xx)
	E_CURVE_MISMATCH          ErrorCode = 0x201 // Key curve doesn't match scheme
	E_TAG_MISMATCH            ErrorCode = 0x202 // MAC verification failed
	E_INVALID_EC_KEY          ErrorCode = 0x203 // Invalid elliptic curve key format
	E_SCHEME_OUTPUT_TOO_SHORT ErrorCode = 0x204 // Insufficient data length
	E_MSIN_ENCODING           ErrorCode = 0x205 // MSIN decoding failed
	E_INVALID_IMSI_LENGTH     ErrorCode = 0x206 // IMSI length out of range
	E_ENCRYPTION_FAILED       ErrorCode = 0x207 // Encryption operation failed
	E_INVALID_PQC_KEY         ErrorCode = 0x208 // Invalid ML-KEM key format
	E_KEM_ENCAPSULATE_FAILED  ErrorCode = 0x209 // ML-KEM encapsulation failed
	E_KEM_DECAPSULATE_FAILED  ErrorCode = 0x20A // ML-KEM decapsulation failed
	E_KMAC_FAILED             ErrorCode = 0x20B // KMAC256 computation failed

	// Validation Errors (0x3xx)
	E_INVALID_SCHEME_ID         ErrorCode = 0x301 // Unsupported scheme
	E_INVALID_TYPE              ErrorCode = 0x302 // Invalid identity type
	E_INVALID_KEY_ID            ErrorCode = 0x303 // Key ID out of range
	E_UNKNOWN_KEY_ID            ErrorCode = 0x304 // Key not found in store
	E_INVALID_SUBSCRIBER_KEY_ID ErrorCode = 0x305 // Invalid subscriber key ID format
)

// Scheme IDs as per 3GPP TS 33.501 and TS 33.703 (PQC)
const (
	SchemeNullScheme SchemeID = 0 // NULL-SCHEME (no encryption)
	SchemeProfileA   SchemeID = 1 // ECIES Profile A (Curve25519/X25519)
	SchemeProfileB   SchemeID = 2 // ECIES Profile B (NIST P-256/secp256r1)
	SchemeProfileC   SchemeID = 3 // PQC Profile C (ML-KEM-768 standalone) per 3GPP TS 33.703
	SchemeProfileD   SchemeID = 4 // Hybrid Profile D (ML-KEM-768 + X25519) per 3GPP TS 33.703
	SchemeProfileE   SchemeID = 5 // Nested Hybrid Profile E (ECC protects PQ ciphertext, PQ protects SUPI)
	SchemeProfileF   SchemeID = 6 // Wrapper Hybrid Profile F (ECIES unchanged, PQ wraps ephemeral key)
	SchemeProfileG   SchemeID = 7 // Symmetric Profile G (two-layer symmetric SUCI concealment)
)

// Identity types
const (
	TypeIMSI IdentityType = 0 // IMSI-based SUPI
	TypeNAI  IdentityType = 1 // NAI-based SUPI
)

// Cryptogram length constants
const (
	// Profile A (Curve25519)
	ProfileA_PubKeyLen = 32                                   // Raw X25519 public key
	ProfileA_MACLen    = 8                                    // First 8 bytes of HMAC-SHA-256
	ProfileA_MinLen    = ProfileA_PubKeyLen + ProfileA_MACLen // 40 bytes

	// Profile B (secp256r1)
	ProfileB_PubKeyLen = 33                                   // Compressed point (0x02/0x03 + X coordinate)
	ProfileB_MACLen    = 8                                    // First 8 bytes of HMAC-SHA-256
	ProfileB_MinLen    = ProfileB_PubKeyLen + ProfileB_MACLen // 41 bytes

	// AES-CTR parameters (Profile A/B: AES-128)
	AES_KEY_LEN    = 16                         // AES-128
	AES_IV_LEN     = 16                         // 128-bit IV
	HMAC_KEY_LEN   = 32                         // HMAC-SHA-256 key
	MAC_TAG_LEN    = 8                          // Truncated MAC to 64 bits
	KDF_OUTPUT_LEN = AES_KEY_LEN + HMAC_KEY_LEN // 48 bytes total

	// Profile C (ML-KEM-768 PQC) per 3GPP TS 33.703
	MLKEM768_PUBLIC_KEY_LEN  = 1184 // ML-KEM-768 encapsulation key (bytes)
	MLKEM768_PRIVATE_KEY_LEN = 2400 // ML-KEM-768 decapsulation key (bytes)
	MLKEM768_CIPHERTEXT_LEN  = 1088 // ML-KEM-768 ciphertext (bytes)
	MLKEM768_SHARED_SECRET   = 32   // ML-KEM shared secret length (bytes)

	ProfileC_ENC_KEY_LEN = 32                                             // AES-256 key
	ProfileC_MAC_KEY_LEN = 32                                             // KMAC256 key
	ProfileC_MAC_TAG_LEN = 8                                              // 64-bit MAC tag
	ProfileC_KDF_OUTPUT  = ProfileC_ENC_KEY_LEN + ProfileC_MAC_KEY_LEN    // 64 bytes
	ProfileC_MinLen      = MLKEM768_CIPHERTEXT_LEN + ProfileC_MAC_TAG_LEN // 1096 bytes minimum

	// Profile D (Hybrid ML-KEM-768 + X25519) per 3GPP TS 33.703
	ProfileD_EphPubKeyLen = 32                                                                     // X25519 ephemeral public key
	ProfileD_MinLen       = MLKEM768_CIPHERTEXT_LEN + ProfileD_EphPubKeyLen + ProfileC_MAC_TAG_LEN // 1128 bytes minimum

	// Profile E (Nested Hybrid) byte layout:
	// EphPub(32) || EncryptedKEMCT(1088) || KEMMAC(8) || EncryptedMSIN || MSINMAC(8)
	ProfileE_EphPubKeyLen = 32
	ProfileE_MinLen       = ProfileE_EphPubKeyLen + MLKEM768_CIPHERTEXT_LEN + ProfileC_MAC_TAG_LEN + ProfileC_MAC_TAG_LEN // 1136

	// Profile F (Wrapper Hybrid) byte layout:
	// KEMCT(1088) || EncEph(32) || PQCMAC(8) || Ciphertext || MAC(8)
	ProfileF_EncEphLen = 32
	ProfileF_MinLen    = MLKEM768_CIPHERTEXT_LEN + ProfileF_EncEphLen + ProfileC_MAC_TAG_LEN + MAC_TAG_LEN // 1136

	// Profile G (Symmetric) byte layout:
	// R || KeyCipherText(5) || MACkey || CipherText(variable) || MACmsin
	ProfileG_KeyCipherTextLen = 5
	ProfileG_Level3_RLen      = 8
	ProfileG_Level5_RLen      = 16
	ProfileG_Level3_MACLen    = 16
	ProfileG_Level5_MACLen    = 32
	ProfileG_Level3_MinLen    = ProfileG_Level3_RLen + ProfileG_KeyCipherTextLen + ProfileG_Level3_MACLen + ProfileG_Level3_MACLen
	ProfileG_Level5_MinLen    = ProfileG_Level5_RLen + ProfileG_KeyCipherTextLen + ProfileG_Level5_MACLen + ProfileG_Level5_MACLen
)

// IMSI length constraints
const (
	IMSI_MIN_LEN = 5  // Minimum IMSI length (MCC + MNC + MSIN)
	IMSI_MAX_LEN = 15 // Maximum IMSI length
)

// ErrorCode represents a specific error in SUCI processing
type ErrorCode uint16

// Error returns the formatted error string
func (e ErrorCode) Error() string {
	msg, ok := errorMessages[e]
	if !ok {
		return fmt.Sprintf("error-%.4x (unknown error)", uint16(e))
	}
	return fmt.Sprintf("error-%.4x: %s", uint16(e), msg)
}

// errorMessages maps error codes to human-readable descriptions
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

// SchemeID represents the protection scheme used for SUCI
type SchemeID uint8

// String returns the name of the scheme
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
		return "Hybrid-Profile-D (ML-KEM-768 + X25519)"
	case SchemeProfileE:
		return "NestedHybrid-Profile-E (ML-KEM-768 + X25519)"
	case SchemeProfileF:
		return "WrapperHybrid-Profile-F (ML-KEM-768 + X25519)"
	case SchemeProfileG:
		return "Symmetric-Profile-G (Two-layer symmetric concealment)"
	default:
		return fmt.Sprintf("Unknown-Scheme-%d", s)
	}
}

// IsValid checks if the scheme ID is supported
func (s SchemeID) IsValid() bool {
	return s >= SchemeNullScheme && s <= SchemeProfileG
}

// RequiresDecryption returns true if the scheme requires cryptographic decryption
func (s SchemeID) RequiresDecryption() bool {
	return s == SchemeProfileA || s == SchemeProfileB || s == SchemeProfileC || s == SchemeProfileD || s == SchemeProfileE || s == SchemeProfileF || s == SchemeProfileG
}

// IdentityType represents the type of subscriber identity
type IdentityType uint8

// String returns the string representation of the identity type
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

// IsValid checks if the identity type is valid
func (t IdentityType) IsValid() bool {
	return t == TypeIMSI || t == TypeNAI
}

// ParsedSUCI represents the parsed components of a SUCI string
type ParsedSUCI struct {
	Type         IdentityType // 0=IMSI, 1=NAI
	MCC          string       // Mobile Country Code (3 digits)
	MNC          string       // Mobile Network Code (2-3 digits)
	RoutingInd   string       // Routing Indicator (1-4 digits)
	SchemeID     SchemeID     // Protection scheme (0, 1, or 2)
	KeyID        uint8        // Home Network key identifier (0-255)
	SchemeOutput []byte       // Hex-decoded scheme output (plaintext or ciphertext)
}

// GetHomeNetworkID returns the concatenated MCC+MNC
func (p *ParsedSUCI) GetHomeNetworkID() string {
	return p.MCC + p.MNC
}

// ConversionResult represents the result of SUCI to SUPI conversion
type ConversionResult struct {
	SUPI  string     // The resulting SUPI (e.g., "imsi-123450123456789")
	Error *ErrorCode // Error code if conversion failed
}

// IsSuccess returns true if the conversion was successful
func (r *ConversionResult) IsSuccess() bool {
	return r.Error == nil
}

// GetErrorString returns the formatted error string
func (r *ConversionResult) GetErrorString() string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Error()
}

// Cryptogram represents the parsed ECIES cryptogram structure
type Cryptogram struct {
	EphemeralPublicKey []byte // Ephemeral public key from UE
	Ciphertext         []byte // Encrypted MSIN
	MACTag             []byte // MAC tag (8 bytes)
}

// PQCCryptogram represents the parsed PQC (ML-KEM) cryptogram structure for Profile C
type PQCCryptogram struct {
	KEMCiphertext []byte // ML-KEM-768 ciphertext (1088 bytes)
	Ciphertext    []byte // Encrypted MSIN
	MACTag        []byte // MAC tag (8 bytes)
}

// HybridCryptogram represents the parsed hybrid cryptogram structure for Profile D (ML-KEM-768 + X25519)
type HybridCryptogram struct {
	KEMCiphertext      []byte                   // ML-KEM-768 ciphertext (1088 bytes)
	EphemeralPublicKey []byte                   // X25519 ephemeral public key (32 bytes)
	Variant            suciutil.ProfileDVariant // 0=baseline, 1=add17, 2=add19
	Nonce              []byte                   // add17: 16 bytes, add19: 12 bytes, baseline: nil
	Ciphertext         []byte                   // Encrypted MSIN
	MACTag             []byte                   // add17/baseline: 8 bytes; add19: 16 bytes (AEAD tag)
}

// ProfileECryptogram represents the parsed Profile E (Nested Hybrid) cryptogram structure
// Layout: EphPub(32) || EncryptedKEMCT(1088) || KEMMAC(8) || EncryptedMSIN || MSINMAC(8)
type ProfileECryptogram struct {
	EphemeralPublicKey []byte // X25519 ephemeral public key (32 bytes)
	EncryptedKEMCT     []byte // AES-256-CTR encrypted ML-KEM ciphertext (1088 bytes)
	KEMMACTag          []byte // KMAC256 MAC over encrypted KEM ciphertext (8 bytes)
	Ciphertext         []byte // AES-256-CTR encrypted MSIN
	MACTag             []byte // KMAC256 MAC over encrypted MSIN (8 bytes)
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

// ProfileGCryptogram represents the parsed Profile G (Symmetric) cryptogram structure
// Layout: R || KeyCipherText(5) || MACkey || CipherText || MACmsin
type ProfileGCryptogram struct {
	R             []byte // Random value: Level 3 = 8 bytes, Level 5 = 16 bytes
	KeyCipherText []byte // Encrypted subscriber key ID (5 bytes)
	MACkey        []byte // MAC over R || KeyCipherText
	Ciphertext    []byte // Encrypted MSIN (variable length)
	MACmsin       []byte // MAC over R || Ciphertext
}
