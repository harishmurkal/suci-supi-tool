package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
	"golang.org/x/crypto/curve25519"
)

// QuantumMetrics holds PQC-specific key/ciphertext sizes for educational display.
type QuantumMetrics struct {
	SecretKeySize  int `json:"sk_bytes"`
	PublicKeySize  int `json:"pk_bytes"`
	CiphertextSize int `json:"ct_bytes"`
}

// ProfileMetadata holds static reference data for a cryptographic profile.
type ProfileMetadata struct {
	OID       string
	NISTLevel string
}

var profileMetadataTable = map[string]ProfileMetadata{
	"X25519":             {OID: "1.3.101.110", NISTLevel: "~Level 1 (128-bit)"},
	"ECDSA/P-256":        {OID: "1.2.840.10045.3.1.7", NISTLevel: "Level 1 (128-bit)"},
	"ML-KEM-768":         {OID: "2.16.840.1.101.3.4.4.2", NISTLevel: "Level 3 (192-bit)"},
	"ML-KEM-768+X25519":  {OID: "Composite (ML-KEM-768 + X25519)", NISTLevel: "Level 3 (hybrid)"},
	"ML-KEM-1024":        {OID: "2.16.840.1.101.3.4.4.3", NISTLevel: "Level 5 (256-bit)"},
	"ML-KEM-1024+X25519": {OID: "Composite (ML-KEM-1024 + X25519)", NISTLevel: "Level 5 (hybrid)"},
}

var mlkem768Metrics = &QuantumMetrics{
	SecretKeySize:  2400,
	PublicKeySize:  1184,
	CiphertextSize: 1088,
}

var mlkem1024Metrics = &QuantumMetrics{
	SecretKeySize:  suciutil.MLKEM1024_PRIVATE_KEY_LEN,
	PublicKeySize:  suciutil.MLKEM1024_PUBLIC_KEY_LEN,
	CiphertextSize: suciutil.MLKEM1024_CIPHERTEXT_LEN,
}

func inferCompositeProfileFromFilename(filename string) (suciutil.SchemeID, string, bool) {
	lower := strings.ToLower(filename)
	switch {
	case strings.Contains(lower, "profile-d"):
		return suciutil.SchemeProfileD, "D (Hybrid ML-KEM-768+X25519)", true
	case strings.Contains(lower, "profile-e"):
		return suciutil.SchemeProfileE, "E (Nested Hybrid ML-KEM-768+X25519)", true
	case strings.Contains(lower, "profile-f"):
		return suciutil.SchemeProfileF, "F (Wrapper Hybrid ML-KEM-768+X25519)", true
	case strings.Contains(lower, "profile-g"):
		return suciutil.SchemeProfileG, "G (Symmetric SUCI)", true
	default:
		return suciutil.SchemeNullScheme, "", false
	}
}

// KeyFormat represents supported key file formats
type KeyFormat string

const (
	FormatPEM  KeyFormat = "pem"  // PEM encoded (default)
	FormatDER  KeyFormat = "der"  // DER (binary ASN.1)
	FormatHex  KeyFormat = "hex"  // Raw hex bytes
	FormatJWK  KeyFormat = "jwk"  // JSON Web Key
	FormatJSON KeyFormat = "json" // Profile-G key JSON
	FormatAuto KeyFormat = "auto" // Auto-detect
)

// KeyInfo contains detailed information about a key
type KeyInfo struct {
	FilePath       string            `json:"file_path"`
	FileName       string            `json:"file_name"`
	Format         KeyFormat         `json:"format"`
	KeyType        string            `json:"key_type"`       // "private" or "public"
	Profile        string            `json:"profile"`        // "A (Curve25519/X25519)" or "B (P-256/secp256r1)"
	Scheme         suciutil.SchemeID `json:"scheme_id"`      // 1 or 2
	KeyID          int               `json:"key_id"`         // Extracted from filename, -1 if unknown
	KeySizeBits    int               `json:"key_size_bits"`  // 256 for both profiles
	KeySizeBytes   int               `json:"key_size_bytes"` // 32 for both
	Algorithm      string            `json:"algorithm"`      // "X25519" or "ECDSA"
	Curve          string            `json:"curve"`          // "Curve25519" or "P-256"
	Fingerprint    string            `json:"fingerprint"`    // SHA-256 of public key
	PublicKeyHex   string            `json:"public_key_hex,omitempty"`
	PublicKeyPEM   string            `json:"public_key_pem,omitempty"`
	PrivateKeyHex  string            `json:"private_key_hex,omitempty"` // Only shown with --show-private
	RawBytes       []byte            `json:"-"`                         // Internal use
	PrivateKey     interface{}       `json:"-"`                         // Parsed private key
	PublicKey      interface{}       `json:"-"`                         // Parsed/derived public key
	OID            string            `json:"oid,omitempty"`             // Algorithm OID
	NISTLevel      string            `json:"nist_level,omitempty"`      // NIST security level
	Entropy        float64           `json:"entropy,omitempty"`         // Shannon entropy (bits)
	EntropyPct     string            `json:"entropy_pct,omitempty"`     // Entropy as percentage string
	IntegrityOK    *bool             `json:"integrity_ok,omitempty"`    // Integrity check result
	IntegrityMsg   string            `json:"integrity_msg,omitempty"`   // Integrity check detail
	CoordX         string            `json:"coord_x,omitempty"`         // EC public key X coordinate (hex)
	CoordY         string            `json:"coord_y,omitempty"`         // EC public key Y coordinate (hex)
	QuantumMetrics *QuantumMetrics   `json:"quantum_metrics,omitempty"` // PQC size metrics
	Error          string            `json:"error,omitempty"`
}

// InspectConfig holds configuration for key inspection
type InspectConfig struct {
	KeyFile      string // Path to key file
	ShowPublic   bool   // Derive and show public key
	ShowPrivate  bool   // Show private key bytes (security risk!)
	OutputFormat string // "text" or "json"
}

// InspectKey inspects a key file and returns detailed information
func InspectKey(config *InspectConfig) (*KeyInfo, error) {
	info := &KeyInfo{
		FilePath: config.KeyFile,
		FileName: filepath.Base(config.KeyFile),
		KeyID:    -1,
	}

	// Read file
	data, err := os.ReadFile(config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	info.RawBytes = data

	// Detect format
	info.Format = detectKeyFormat(data)

	// Parse key based on format
	if err := parseKeyData(info, data); err != nil {
		info.Error = err.Error()
		return info, nil // Return partial info with error
	}

	// Extract key ID from filename
	info.KeyID = extractKeyIDFromFilename(info.FileName)

	// Derive public key if requested and we have a private key
	if config.ShowPublic && info.KeyType == "private" {
		if err := derivePublicKey(info); err != nil {
			info.Error = fmt.Sprintf("failed to derive public key: %v", err)
		}
	}

	// Show private key hex if requested (security warning!)
	if config.ShowPrivate && info.PrivateKey != nil {
		info.PrivateKeyHex = getPrivateKeyHex(info)
	}

	return info, nil
}

// detectKeyFormat detects the format of key data
func detectKeyFormat(data []byte) KeyFormat {
	// Check for PEM format
	if block, _ := pem.Decode(data); block != nil {
		return FormatPEM
	}

	// Check for Profile-G JSON key files
	if isProfileGJSON(data) {
		return FormatJSON
	}

	// Check for hex-only content (allow whitespace)
	cleaned := strings.TrimSpace(string(data))
	if isHexString(cleaned) {
		return FormatHex
	}

	// Check for JWK (JSON with "kty" field)
	if isJWK(data) {
		return FormatJWK
	}

	// Assume DER if binary
	return FormatDER
}

// isHexString checks if a string contains only hex characters
func isHexString(s string) bool {
	// Remove common separators
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")

	if len(s) == 0 {
		return false
	}

	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isJWK checks if data is a JSON Web Key
func isJWK(data []byte) bool {
	var jwk map[string]interface{}
	if err := json.Unmarshal(data, &jwk); err != nil {
		return false
	}
	_, hasKty := jwk["kty"]
	return hasKty
}

// parseKeyData parses key data based on detected format
func parseKeyData(info *KeyInfo, data []byte) error {
	switch info.Format {
	case FormatPEM:
		return parsePEMKey(info, data)
	case FormatDER:
		return parseDERKey(info, data)
	case FormatHex:
		return parseHexKey(info, data)
	case FormatJWK:
		return parseJWKKey(info, data)
	case FormatJSON:
		return parseJSONKey(info, data)
	default:
		return fmt.Errorf("unsupported format: %s", info.Format)
	}
}

func isProfileGJSON(data []byte) bool {
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return false
	}
	if _, ok := obj["hn_symmetric_key_hex"]; ok {
		return true
	}
	if _, ok := obj["subscribers"]; ok {
		return true
	}
	return false
}

func parseJSONKey(info *KeyInfo, data []byte) error {
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("failed to parse JSON key: %w", err)
	}

	if rawKey, ok := obj["hn_symmetric_key_hex"]; ok {
		keyHex, ok := rawKey.(string)
		if !ok || strings.TrimSpace(keyHex) == "" {
			return fmt.Errorf("invalid Profile G key JSON: hn_symmetric_key_hex")
		}
		keyBytes, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(strings.ToLower(keyHex)), "0x"))
		if err != nil {
			return fmt.Errorf("invalid Profile G symmetric key hex: %w", err)
		}
		if len(keyBytes) != 16 && len(keyBytes) != 32 {
			return fmt.Errorf("invalid Profile G symmetric key length: %d", len(keyBytes))
		}
		levelText := "3"
		if len(keyBytes) == 32 {
			levelText = "5"
		}

		info.KeyType = "private"
		info.Profile = "G (Symmetric SUCI)"
		info.Scheme = suciutil.SchemeProfileG
		info.Algorithm = "Profile-G Symmetric (Level " + levelText + ")"
		info.Curve = "N/A"
		info.KeySizeBits = len(keyBytes) * 8
		info.KeySizeBytes = len(keyBytes)
		info.PrivateKey = keyBytes
		info.Fingerprint = computeFingerprint(keyBytes)
		return nil
	}

	if rawSubs, ok := obj["subscribers"]; ok {
		subs, ok := rawSubs.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid Profile G subscribers JSON: subscribers must be object")
		}
		totalBytes := 0
		for _, v := range subs {
			kmHex, ok := v.(string)
			if !ok {
				return fmt.Errorf("invalid Profile G subscriber map value")
			}
			km, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(strings.ToLower(kmHex)), "0x"))
			if err != nil {
				return fmt.Errorf("invalid Profile G subscriber Kmaster hex: %w", err)
			}
			if len(km) != 16 {
				return fmt.Errorf("invalid Profile G subscriber Kmaster length: %d", len(km))
			}
			totalBytes += len(km)
		}

		info.KeyType = "private"
		info.Profile = "G (Symmetric SUCI Subscribers)"
		info.Scheme = suciutil.SchemeProfileG
		info.Algorithm = "Profile-G Subscriber Kmaster Map"
		info.Curve = "N/A"
		info.KeySizeBits = totalBytes * 8
		info.KeySizeBytes = totalBytes
		return nil
	}

	return fmt.Errorf("unsupported JSON key format")
}

// parsePEMKey parses a PEM-encoded key
func parsePEMKey(info *KeyInfo, data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "X25519 PRIVATE KEY":
		info.KeyType = "private"
		info.Profile = "A (Curve25519/X25519)"
		info.Scheme = suciutil.SchemeProfileA
		if inferredScheme, inferredProfile, ok := inferCompositeProfileFromFilename(info.FileName); ok {
			info.Scheme = inferredScheme
			info.Profile = inferredProfile
		}
		info.Algorithm = "X25519"
		info.Curve = "Curve25519"
		info.KeySizeBits = 256
		info.KeySizeBytes = 32
		if len(block.Bytes) == 32 {
			info.PrivateKey = block.Bytes
		} else {
			return fmt.Errorf("invalid X25519 private key length: %d", len(block.Bytes))
		}

	case "X25519 PUBLIC KEY":
		info.KeyType = "public"
		info.Profile = "A (Curve25519/X25519)"
		info.Scheme = suciutil.SchemeProfileA
		if inferredScheme, inferredProfile, ok := inferCompositeProfileFromFilename(info.FileName); ok {
			info.Scheme = inferredScheme
			info.Profile = inferredProfile
		}
		info.Algorithm = "X25519"
		info.Curve = "Curve25519"
		info.KeySizeBits = 256
		info.KeySizeBytes = 32
		if len(block.Bytes) == 32 {
			info.PublicKey = block.Bytes
			info.PublicKeyHex = hex.EncodeToString(block.Bytes)
			info.Fingerprint = computeFingerprint(block.Bytes)
		} else {
			return fmt.Errorf("invalid X25519 public key length: %d", len(block.Bytes))
		}

	case "ML-KEM-768 PRIVATE KEY":
		info.KeyType = "private"
		info.Profile = "C (ML-KEM-768/PQC)"
		info.Scheme = suciutil.SchemeProfileC
		if inferredScheme, inferredProfile, ok := inferCompositeProfileFromFilename(info.FileName); ok {
			info.Scheme = inferredScheme
			info.Profile = inferredProfile
		}
		info.Algorithm = "ML-KEM-768"
		info.Curve = "N/A"
		info.KeySizeBits = 6144
		info.KeySizeBytes = 2400
		if len(block.Bytes) == 2400 {
			info.PrivateKey = block.Bytes
		} else {
			return fmt.Errorf("invalid ML-KEM-768 private key length: %d", len(block.Bytes))
		}

	case "ML-KEM-768 PUBLIC KEY":
		info.KeyType = "public"
		info.Profile = "C (ML-KEM-768/PQC)"
		info.Scheme = suciutil.SchemeProfileC
		if inferredScheme, inferredProfile, ok := inferCompositeProfileFromFilename(info.FileName); ok {
			info.Scheme = inferredScheme
			info.Profile = inferredProfile
		}
		info.Algorithm = "ML-KEM-768"
		info.Curve = "N/A"
		info.KeySizeBits = 6144
		info.KeySizeBytes = 1184
		if len(block.Bytes) == 1184 {
			info.PublicKey = block.Bytes
			info.PublicKeyHex = hex.EncodeToString(block.Bytes)
			info.Fingerprint = computeFingerprint(block.Bytes)
		} else {
			return fmt.Errorf("invalid ML-KEM-768 public key length: %d", len(block.Bytes))
		}

	case "ML-KEM-1024 PRIVATE KEY":
		info.KeyType = "private"
		info.Profile = "C (ML-KEM-1024/PQC)"
		info.Scheme = suciutil.SchemeProfileC
		if inferredScheme, inferredProfile, ok := inferCompositeProfileFromFilename(info.FileName); ok {
			info.Scheme = inferredScheme
			info.Profile = inferredProfile
		}
		info.Algorithm = "ML-KEM-1024"
		info.Curve = "N/A"
		info.KeySizeBits = 8192
		info.KeySizeBytes = suciutil.MLKEM1024_PRIVATE_KEY_LEN
		if len(block.Bytes) == suciutil.MLKEM1024_PRIVATE_KEY_LEN {
			info.PrivateKey = block.Bytes
		} else {
			return fmt.Errorf("invalid ML-KEM-1024 private key length: %d", len(block.Bytes))
		}

	case "ML-KEM-1024 PUBLIC KEY":
		info.KeyType = "public"
		info.Profile = "C (ML-KEM-1024/PQC)"
		info.Scheme = suciutil.SchemeProfileC
		if inferredScheme, inferredProfile, ok := inferCompositeProfileFromFilename(info.FileName); ok {
			info.Scheme = inferredScheme
			info.Profile = inferredProfile
		}
		info.Algorithm = "ML-KEM-1024"
		info.Curve = "N/A"
		info.KeySizeBits = 8192
		info.KeySizeBytes = suciutil.MLKEM1024_PUBLIC_KEY_LEN
		if len(block.Bytes) == suciutil.MLKEM1024_PUBLIC_KEY_LEN {
			info.PublicKey = block.Bytes
			info.PublicKeyHex = hex.EncodeToString(block.Bytes)
			info.Fingerprint = computeFingerprint(block.Bytes)
		} else {
			return fmt.Errorf("invalid ML-KEM-1024 public key length: %d", len(block.Bytes))
		}

	case "PRIVATE KEY":
		// PKCS#8 format - could be ECDSA
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			return parseECDSAPrivateKey(info, ecdsaKey)
		}
		return fmt.Errorf("unsupported PKCS#8 key type")

	case "EC PRIVATE KEY":
		// SEC1 format
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse EC private key: %w", err)
		}
		return parseECDSAPrivateKey(info, key)

	case "PUBLIC KEY":
		// PKIX format
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}
		if ecdsaKey, ok := key.(*ecdsa.PublicKey); ok {
			return parseECDSAPublicKey(info, ecdsaKey)
		}
		return fmt.Errorf("unsupported public key type")

	default:
		return fmt.Errorf("unsupported PEM type: %s", block.Type)
	}

	return nil
}

// parseECDSAPrivateKey extracts info from an ECDSA private key
func parseECDSAPrivateKey(info *KeyInfo, key *ecdsa.PrivateKey) error {
	info.KeyType = "private"
	info.PrivateKey = key
	info.PublicKey = &key.PublicKey
	info.Algorithm = "ECDSA"

	switch key.Curve {
	case elliptic.P256():
		info.Profile = "B (P-256/secp256r1)"
		info.Scheme = suciutil.SchemeProfileB
		info.Curve = "P-256"
		info.KeySizeBits = 256
		info.KeySizeBytes = 32
	case elliptic.P384():
		info.Profile = "P-384"
		info.Curve = "P-384"
		info.KeySizeBits = 384
		info.KeySizeBytes = 48
	case elliptic.P521():
		info.Profile = "P-521"
		info.Curve = "P-521"
		info.KeySizeBits = 521
		info.KeySizeBytes = 66
	default:
		return fmt.Errorf("unsupported elliptic curve")
	}

	// Compute fingerprint from public key
	pubBytes := elliptic.Marshal(key.Curve, key.PublicKey.X, key.PublicKey.Y)
	info.Fingerprint = computeFingerprint(pubBytes)

	return nil
}

// parseECDSAPublicKey extracts info from an ECDSA public key
func parseECDSAPublicKey(info *KeyInfo, key *ecdsa.PublicKey) error {
	info.KeyType = "public"
	info.PublicKey = key
	info.Algorithm = "ECDSA"

	switch key.Curve {
	case elliptic.P256():
		info.Profile = "B (P-256/secp256r1)"
		info.Scheme = suciutil.SchemeProfileB
		info.Curve = "P-256"
		info.KeySizeBits = 256
		info.KeySizeBytes = 32
	default:
		return fmt.Errorf("unsupported elliptic curve")
	}

	pubBytes := elliptic.Marshal(key.Curve, key.X, key.Y)
	info.PublicKeyHex = hex.EncodeToString(pubBytes)
	info.Fingerprint = computeFingerprint(pubBytes)

	return nil
}

// parseDERKey parses a DER-encoded key
func parseDERKey(info *KeyInfo, data []byte) error {
	// Try PKCS#8 private key
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			info.Format = FormatDER
			return parseECDSAPrivateKey(info, ecdsaKey)
		}
	}

	// Try SEC1 EC private key
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		info.Format = FormatDER
		return parseECDSAPrivateKey(info, key)
	}

	// Try PKIX public key
	if key, err := x509.ParsePKIXPublicKey(data); err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PublicKey); ok {
			info.Format = FormatDER
			return parseECDSAPublicKey(info, ecdsaKey)
		}
	}

	// Check if it's raw 32-byte key (X25519)
	if len(data) == 32 {
		info.Format = FormatDER
		info.KeyType = "private" // Assume private for raw bytes
		info.Profile = "A (Curve25519/X25519)"
		info.Scheme = suciutil.SchemeProfileA
		info.Algorithm = "X25519"
		info.Curve = "Curve25519"
		info.KeySizeBits = 256
		info.KeySizeBytes = 32
		info.PrivateKey = data
		return nil
	}

	return fmt.Errorf("failed to parse DER key")
}

// parseHexKey parses a hex-encoded key
func parseHexKey(info *KeyInfo, data []byte) error {
	// Clean hex string
	hexStr := strings.TrimSpace(string(data))
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, ":", "")
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, "\r", "")

	keyBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("failed to decode hex: %w", err)
	}

	// Determine key type based on length
	switch len(keyBytes) {
	case 32:
		// Could be X25519 private or public key
		info.KeyType = "private" // Assume private
		info.Profile = "A (Curve25519/X25519)"
		info.Scheme = suciutil.SchemeProfileA
		info.Algorithm = "X25519"
		info.Curve = "Curve25519"
		info.KeySizeBits = 256
		info.KeySizeBytes = 32
		info.PrivateKey = keyBytes

	case 33:
		// Compressed P-256 public key
		info.KeyType = "public"
		info.Profile = "B (P-256/secp256r1)"
		info.Scheme = suciutil.SchemeProfileB
		info.Algorithm = "ECDSA"
		info.Curve = "P-256"
		info.KeySizeBits = 256
		info.KeySizeBytes = 32
		info.PublicKeyHex = hexStr
		info.Fingerprint = computeFingerprint(keyBytes)

	case 65:
		// Uncompressed P-256 public key
		info.KeyType = "public"
		info.Profile = "B (P-256/secp256r1)"
		info.Scheme = suciutil.SchemeProfileB
		info.Algorithm = "ECDSA"
		info.Curve = "P-256"
		info.KeySizeBits = 256
		info.KeySizeBytes = 32
		info.PublicKeyHex = hexStr
		info.Fingerprint = computeFingerprint(keyBytes)

	case 1184:
		// ML-KEM-768 public key
		info.KeyType = "public"
		info.Profile = "C (ML-KEM-768/PQC)"
		info.Scheme = suciutil.SchemeProfileC
		info.Algorithm = "ML-KEM-768"
		info.Curve = "N/A"
		info.KeySizeBits = 6144 // 768 * 8
		info.KeySizeBytes = 1184
		info.PublicKeyHex = hexStr
		info.Fingerprint = computeFingerprint(keyBytes)

	case 2400:
		// ML-KEM-768 private key
		info.KeyType = "private"
		info.Profile = "C (ML-KEM-768/PQC)"
		info.Scheme = suciutil.SchemeProfileC
		info.Algorithm = "ML-KEM-768"
		info.Curve = "N/A"
		info.KeySizeBits = 6144
		info.KeySizeBytes = 2400
		info.PrivateKey = keyBytes

	case suciutil.MLKEM1024_PUBLIC_KEY_LEN:
		info.KeyType = "public"
		info.Profile = "C (ML-KEM-1024/PQC)"
		info.Scheme = suciutil.SchemeProfileC
		info.Algorithm = "ML-KEM-1024"
		info.Curve = "N/A"
		info.KeySizeBits = 8192
		info.KeySizeBytes = len(keyBytes)
		info.PublicKeyHex = hexStr
		info.Fingerprint = computeFingerprint(keyBytes)

	case suciutil.MLKEM1024_PRIVATE_KEY_LEN:
		info.KeyType = "private"
		info.Profile = "C (ML-KEM-1024/PQC)"
		info.Scheme = suciutil.SchemeProfileC
		info.Algorithm = "ML-KEM-1024"
		info.Curve = "N/A"
		info.KeySizeBits = 8192
		info.KeySizeBytes = len(keyBytes)
		info.PrivateKey = keyBytes

	default:
		return fmt.Errorf("unexpected key length: %d bytes", len(keyBytes))
	}

	return nil
}

// parseJWKKey parses a JSON Web Key
func parseJWKKey(info *KeyInfo, data []byte) error {
	var jwk map[string]interface{}
	if err := json.Unmarshal(data, &jwk); err != nil {
		return fmt.Errorf("failed to parse JWK: %w", err)
	}

	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)

	switch kty {
	case "OKP":
		// Octet Key Pair (X25519, Ed25519)
		if crv == "X25519" {
			info.Profile = "A (Curve25519/X25519)"
			info.Scheme = suciutil.SchemeProfileA
			info.Algorithm = "X25519"
			info.Curve = "Curve25519"
			info.KeySizeBits = 256
			info.KeySizeBytes = 32

			if _, hasD := jwk["d"]; hasD {
				info.KeyType = "private"
			} else {
				info.KeyType = "public"
			}
		} else {
			return fmt.Errorf("unsupported OKP curve: %s", crv)
		}

	case "EC":
		// Elliptic Curve
		if crv == "P-256" {
			info.Profile = "B (P-256/secp256r1)"
			info.Scheme = suciutil.SchemeProfileB
			info.Algorithm = "ECDSA"
			info.Curve = "P-256"
			info.KeySizeBits = 256
			info.KeySizeBytes = 32

			if _, hasD := jwk["d"]; hasD {
				info.KeyType = "private"
			} else {
				info.KeyType = "public"
			}
		} else {
			return fmt.Errorf("unsupported EC curve: %s", crv)
		}

	case "KEM":
		alg, _ := jwk["alg"].(string)
		switch {
		case alg == "ML-KEM-768" || crv == "ML-KEM-768":
			info.Profile = "C (ML-KEM-768/PQC)"
			info.Scheme = suciutil.SchemeProfileC
			info.Algorithm = "ML-KEM-768"
			info.Curve = "N/A"
			info.KeySizeBits = 6144
			info.KeySizeBytes = 2400
			if _, hasD := jwk["d"]; hasD {
				info.KeyType = "private"
			} else {
				info.KeyType = "public"
				info.KeySizeBytes = 1184
			}
		case alg == "ML-KEM-1024":
			info.Profile = "C (ML-KEM-1024/PQC)"
			info.Scheme = suciutil.SchemeProfileC
			info.Algorithm = "ML-KEM-1024"
			info.Curve = "N/A"
			info.KeySizeBits = 8192
			info.KeySizeBytes = suciutil.MLKEM1024_PRIVATE_KEY_LEN
			if _, hasD := jwk["d"]; hasD {
				info.KeyType = "private"
			} else {
				info.KeyType = "public"
				info.KeySizeBytes = suciutil.MLKEM1024_PUBLIC_KEY_LEN
			}
		default:
			return fmt.Errorf("unsupported KEM algorithm: %s", alg)
		}

	default:
		return fmt.Errorf("unsupported JWK key type: %s", kty)
	}

	return nil
}

// extractKeyIDFromFilename extracts key ID from filenames like:
// hn-key-{id}-profile-{a|b|c}.pem
// hn-key-{id}-profile-{d|e|f}.pem
// hn-key-{id}-profile-{d|e|f}-{mlkem|x25519}.pem
func extractKeyIDFromFilename(filename string) int {
	re := regexp.MustCompile(`hn-key-(\d+)-profile-[a-g](?:-(?:mlkem|x25519|subscribers))?`)
	matches := re.FindStringSubmatch(filename)
	if len(matches) >= 2 {
		var id int
		fmt.Sscanf(matches[1], "%d", &id)
		return id
	}
	return -1
}

// derivePublicKey derives the public key from a private key
func derivePublicKey(info *KeyInfo) error {
	switch info.Scheme {
	case suciutil.SchemeProfileA, suciutil.SchemeProfileD, suciutil.SchemeProfileE, suciutil.SchemeProfileF:
		// X25519: derive public key using curve25519
		if privBytes, ok := info.PrivateKey.([]byte); ok {
			// Composite profiles carry both ML-KEM (2400B) and X25519 (32B) components as files.
			// Only X25519 private keys can derive a public key here.
			if len(privBytes) != 32 {
				return nil
			}
			pubKey, err := deriveX25519PublicKey(privBytes)
			if err != nil {
				return err
			}
			info.PublicKey = pubKey
			info.PublicKeyHex = hex.EncodeToString(pubKey)
			info.Fingerprint = computeFingerprint(pubKey)

			// Create PEM
			info.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{
				Type:  "X25519 PUBLIC KEY",
				Bytes: pubKey,
			}))
		}

	case suciutil.SchemeProfileB:
		// ECDSA: public key is already in the private key
		if ecdsaKey, ok := info.PrivateKey.(*ecdsa.PrivateKey); ok {
			pubBytes := elliptic.Marshal(ecdsaKey.Curve, ecdsaKey.PublicKey.X, ecdsaKey.PublicKey.Y)
			info.PublicKeyHex = hex.EncodeToString(pubBytes)
			info.Fingerprint = computeFingerprint(pubBytes)

			// Create PEM
			pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
			if err == nil {
				info.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{
					Type:  "PUBLIC KEY",
					Bytes: pubKeyBytes,
				}))
			}
		}
	}

	return nil
}

// deriveX25519PublicKey derives a public key from X25519 private key bytes
func deriveX25519PublicKey(privateKey []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("invalid private key length: %d", len(privateKey))
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	return publicKey, nil
}

// computeFingerprint computes SHA-256 fingerprint of key bytes
func computeFingerprint(keyBytes []byte) string {
	hash := sha256.Sum256(keyBytes)
	return hex.EncodeToString(hash[:])
}

// getPrivateKeyHex returns hex representation of private key
func getPrivateKeyHex(info *KeyInfo) string {
	switch info.Scheme {
	case suciutil.SchemeProfileA:
		if privBytes, ok := info.PrivateKey.([]byte); ok {
			return hex.EncodeToString(privBytes)
		}
	case suciutil.SchemeProfileG:
		if privBytes, ok := info.PrivateKey.([]byte); ok {
			return hex.EncodeToString(privBytes)
		}
	case suciutil.SchemeProfileB:
		if ecdsaKey, ok := info.PrivateKey.(*ecdsa.PrivateKey); ok {
			return hex.EncodeToString(ecdsaKey.D.Bytes())
		}
	}
	return ""
}

// EnrichKeyInfo populates OID, NIST level, entropy, integrity, coordinates,
// and quantum metrics on an already-parsed KeyInfo.
func EnrichKeyInfo(info *KeyInfo) {
	if info == nil || info.Error != "" {
		return
	}

	// OID and NIST level from static table
	lookupKey := info.Algorithm
	if info.Algorithm == "ECDSA" && info.Curve != "" {
		lookupKey = "ECDSA/" + info.Curve
	}
	if meta, ok := profileMetadataTable[lookupKey]; ok {
		info.OID = meta.OID
		info.NISTLevel = meta.NISTLevel
	}

	// Entropy: computed over raw private key bytes when available
	if privBytes := getPrivateKeyBytes(info); len(privBytes) > 0 {
		bits := computeShannonEntropy(privBytes)
		info.Entropy = math.Round(bits*100) / 100
		pct := (bits / 8.0) * 100
		info.EntropyPct = fmt.Sprintf("%.1f%% (%.2f/8.00 bits)", pct, bits)
	}

	// Integrity check
	ok, msg := checkIntegrity(info)
	info.IntegrityOK = &ok
	info.IntegrityMsg = msg

	// P-256 coordinate extraction
	extractECCoordinates(info)

	// Quantum metrics for ML-KEM profiles
	enrichQuantumMetrics(info)
}

func getPrivateKeyBytes(info *KeyInfo) []byte {
	switch info.Scheme {
	case suciutil.SchemeProfileA, suciutil.SchemeProfileD, suciutil.SchemeProfileE, suciutil.SchemeProfileF:
		if b, ok := info.PrivateKey.([]byte); ok {
			return b
		}
	case suciutil.SchemeProfileG:
		if b, ok := info.PrivateKey.([]byte); ok {
			return b
		}
	case suciutil.SchemeProfileB:
		if ecKey, ok := info.PrivateKey.(*ecdsa.PrivateKey); ok {
			return ecKey.D.Bytes()
		}
	case suciutil.SchemeProfileC:
		if b, ok := info.PrivateKey.([]byte); ok {
			return b
		}
	}
	return nil
}

// computeShannonEntropy returns Shannon entropy in bits (max 8.0 for byte data).
func computeShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var entropy float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// checkIntegrity performs a profile-specific integrity check.
func checkIntegrity(info *KeyInfo) (bool, string) {
	switch {
	case info.Algorithm == "ECDSA" && info.Curve == "P-256":
		return checkECIntegrity(info)
	case info.Algorithm == "X25519":
		return checkX25519Integrity(info)
	case info.Algorithm == "ML-KEM-768", info.Algorithm == "ML-KEM-1024":
		return checkMLKEMIntegrity(info)
	case info.Algorithm == "ML-KEM-768+X25519", info.Algorithm == "ML-KEM-1024+X25519":
		return true, "composite key (components validated individually)"
	}
	return true, "no specific check available"
}

func checkECIntegrity(info *KeyInfo) (bool, string) {
	var pub *ecdsa.PublicKey
	if ecKey, ok := info.PrivateKey.(*ecdsa.PrivateKey); ok {
		pub = &ecKey.PublicKey
	} else if ecPub, ok := info.PublicKey.(*ecdsa.PublicKey); ok {
		pub = ecPub
	}
	if pub == nil {
		return true, "no public key to validate"
	}
	if pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return true, "point is on curve"
	}
	return false, "point is NOT on curve"
}

func checkX25519Integrity(info *KeyInfo) (bool, string) {
	if info.KeyType == "private" {
		if b, ok := info.PrivateKey.([]byte); ok && len(b) == 32 {
			return true, "key length valid (32 bytes)"
		}
		return false, "invalid private key length"
	}
	if b, ok := info.PublicKey.([]byte); ok && len(b) == 32 {
		return true, "key length valid (32 bytes)"
	}
	return true, "key length check skipped"
}

func checkMLKEMIntegrity(info *KeyInfo) (bool, string) {
	if info.KeyType == "private" {
		if b, ok := info.PrivateKey.([]byte); ok {
			switch len(b) {
			case suciutil.MLKEM768_PRIVATE_KEY_LEN, suciutil.MLKEM1024_PRIVATE_KEY_LEN:
				return true, fmt.Sprintf("private key length valid (%d bytes)", len(b))
			default:
				return false, fmt.Sprintf("unexpected private key length: %d (expected %d or %d)", len(b), suciutil.MLKEM768_PRIVATE_KEY_LEN, suciutil.MLKEM1024_PRIVATE_KEY_LEN)
			}
		}
	}
	if info.KeyType == "public" {
		if b, ok := info.PublicKey.([]byte); ok {
			switch len(b) {
			case suciutil.MLKEM768_PUBLIC_KEY_LEN, suciutil.MLKEM1024_PUBLIC_KEY_LEN:
				return true, fmt.Sprintf("public key length valid (%d bytes)", len(b))
			default:
				return false, fmt.Sprintf("unexpected public key length: %d (expected %d or %d)", len(b), suciutil.MLKEM768_PUBLIC_KEY_LEN, suciutil.MLKEM1024_PUBLIC_KEY_LEN)
			}
		}
	}
	return true, "key material not available for length check"
}

func extractECCoordinates(info *KeyInfo) {
	var pub *ecdsa.PublicKey
	if ecKey, ok := info.PrivateKey.(*ecdsa.PrivateKey); ok {
		pub = &ecKey.PublicKey
	} else if ecPub, ok := info.PublicKey.(*ecdsa.PublicKey); ok {
		pub = ecPub
	}
	if pub == nil || pub.X == nil || pub.Y == nil {
		return
	}
	info.CoordX = hex.EncodeToString(pub.X.Bytes())
	info.CoordY = hex.EncodeToString(pub.Y.Bytes())
}

func enrichQuantumMetrics(info *KeyInfo) {
	switch info.Algorithm {
	case "ML-KEM-768", "ML-KEM-768+X25519":
		info.QuantumMetrics = mlkem768Metrics
	case "ML-KEM-1024", "ML-KEM-1024+X25519":
		info.QuantumMetrics = mlkem1024Metrics
	}
}

// FormatKeyInfo formats key info as text with structured sections.
func FormatKeyInfo(info *KeyInfo) string {
	var sb strings.Builder

	sb.WriteString("\n╔════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                       KEY INFORMATION                         ║\n")
	sb.WriteString("╚════════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("  File:         %s\n", info.FilePath))
	sb.WriteString(fmt.Sprintf("  Format:       %s\n", strings.ToUpper(string(info.Format))))
	sb.WriteString(fmt.Sprintf("  Key Type:     %s\n", info.KeyType))
	if info.KeyID >= 0 {
		sb.WriteString(fmt.Sprintf("  Key ID:       %d\n", info.KeyID))
	}

	// [ALGORITHM INFO]
	sb.WriteString("\n  [ALGORITHM INFO]\n")
	sb.WriteString(fmt.Sprintf("  ├─ 3GPP Profile:   %s\n", info.Profile))
	sb.WriteString(fmt.Sprintf("  ├─ Algorithm:      %s\n", info.Algorithm))
	if info.Curve != "" && info.Curve != "N/A" {
		sb.WriteString(fmt.Sprintf("  ├─ Curve:          %s\n", info.Curve))
	}
	if info.OID != "" {
		sb.WriteString(fmt.Sprintf("  ├─ OID:            %s\n", info.OID))
	}
	if info.NISTLevel != "" {
		sb.WriteString(fmt.Sprintf("  ├─ Security Level: %s\n", info.NISTLevel))
	}
	sb.WriteString(fmt.Sprintf("  └─ Key Size:       %d bits (%d bytes)\n", info.KeySizeBits, info.KeySizeBytes))

	// [COORDINATES] -- Profile B only
	if info.CoordX != "" && info.CoordY != "" {
		sb.WriteString("\n  [COORDINATES]\n")
		sb.WriteString(fmt.Sprintf("  ├─ X: %s\n", info.CoordX))
		sb.WriteString(fmt.Sprintf("  └─ Y: %s\n", info.CoordY))
	}

	// [QUANTUM METRICS] -- PQC profiles
	if info.QuantumMetrics != nil {
		sb.WriteString("\n  [QUANTUM METRICS]\n")
		sb.WriteString(fmt.Sprintf("  ├─ Secret Key (sk):  %d bytes\n", info.QuantumMetrics.SecretKeySize))
		sb.WriteString(fmt.Sprintf("  ├─ Public Key (pk):  %d bytes\n", info.QuantumMetrics.PublicKeySize))
		sb.WriteString(fmt.Sprintf("  └─ Ciphertext (ct):  %d bytes\n", info.QuantumMetrics.CiphertextSize))
	}

	// [FINGERPRINTS]
	if info.Fingerprint != "" {
		sb.WriteString("\n  [FINGERPRINTS]\n")
		sb.WriteString(fmt.Sprintf("  └─ SHA-256: %s\n", info.Fingerprint))
	}

	// [SECURITY CHECK]
	if info.IntegrityOK != nil || info.EntropyPct != "" {
		sb.WriteString("\n  [SECURITY CHECK]\n")
		if info.IntegrityOK != nil {
			status := "PASS"
			if !*info.IntegrityOK {
				status = "FAIL"
			}
			sb.WriteString(fmt.Sprintf("  ├─ Integrity:  %s  (%s)\n", status, info.IntegrityMsg))
		}
		if info.EntropyPct != "" {
			sb.WriteString(fmt.Sprintf("  └─ Entropy:    %s\n", info.EntropyPct))
		}
	}

	// Public key data (when requested)
	if info.PublicKeyHex != "" {
		sb.WriteString("\n  [PUBLIC KEY]\n")
		for i := 0; i < len(info.PublicKeyHex); i += 64 {
			end := i + 64
			if end > len(info.PublicKeyHex) {
				end = len(info.PublicKeyHex)
			}
			sb.WriteString(fmt.Sprintf("    %s\n", info.PublicKeyHex[i:end]))
		}
	}

	if info.PublicKeyPEM != "" {
		sb.WriteString("\n  [PUBLIC KEY PEM]\n")
		for _, line := range strings.Split(info.PublicKeyPEM, "\n") {
			if line != "" {
				sb.WriteString(fmt.Sprintf("    %s\n", line))
			}
		}
	}

	if info.PrivateKeyHex != "" {
		sb.WriteString("\n  ⚠️  [PRIVATE KEY] - SENSITIVE:\n")
		sb.WriteString(fmt.Sprintf("    %s\n", info.PrivateKeyHex))
	}

	if info.Error != "" {
		sb.WriteString(fmt.Sprintf("\n  ⚠️  Warning: %s\n", info.Error))
	}

	sb.WriteString("\n")
	return sb.String()
}

// FormatKeyInfoJSON formats key info as JSON
func FormatKeyInfoJSON(info *KeyInfo) (string, error) {
	jsonBytes, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}
