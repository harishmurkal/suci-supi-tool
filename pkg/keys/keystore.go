package keys

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
)

// Common errors
var (
	ErrKeyNotFound   = errors.New("key not found")
	ErrInvalidKey    = errors.New("invalid key format")
	ErrInvalidScheme = errors.New("invalid scheme")
	ErrCurveMismatch = errors.New("key curve doesn't match scheme")
)

// KeyStore interface for managing Home Network private keys
// Implementations can use files, environment variables, HSM, or vaults
type KeyStore interface {
	GetPrivateKey(keyID uint8, scheme suciutil.SchemeID) (interface{}, error)
}

// FileKeyStore implements KeyStore using PEM files on disk
type FileKeyStore struct {
	keyDirectory string
	keyCache     map[string]interface{} // Cache loaded keys
}

// NewFileKeyStore creates a new file-based key store
func NewFileKeyStore(keyDirectory string) *FileKeyStore {
	return &FileKeyStore{
		keyDirectory: keyDirectory,
		keyCache:     make(map[string]interface{}),
	}
}

// GetPrivateKey loads a private key from a PEM file
// Expected file naming: hn-key-{keyID}-{scheme}.pem
// Profile D/E/F: hn-key-{keyID}-profile-{d|e|f}-mlkem.pem and hn-key-{keyID}-profile-{d|e|f}-x25519.pem
func (f *FileKeyStore) GetPrivateKey(keyID uint8, scheme suciutil.SchemeID) (interface{}, error) {
	if scheme == suciutil.SchemeProfileG {
		keyPath := fmt.Sprintf("%s/hn-key-%d-profile-g.json", f.keyDirectory, keyID)
		if cachedKey, exists := f.keyCache[keyPath]; exists {
			return cachedKey, nil
		}
		keyMaterial, err := loadProfileGKeyMaterialFromFile(keyPath, keyID, true)
		if err != nil {
			return nil, err
		}
		f.keyCache[keyPath] = keyMaterial
		return keyMaterial, nil
	}

	if scheme == suciutil.SchemeProfileD || scheme == suciutil.SchemeProfileE || scheme == suciutil.SchemeProfileF {
		var profileSuffix string
		switch scheme {
		case suciutil.SchemeProfileD:
			profileSuffix = "profile-d"
		case suciutil.SchemeProfileE:
			profileSuffix = "profile-e"
		case suciutil.SchemeProfileF:
			profileSuffix = "profile-f"
		}
		cacheKey := fmt.Sprintf("%s/hn-key-%d-%s", f.keyDirectory, keyID, profileSuffix)
		if cachedKey, exists := f.keyCache[cacheKey]; exists {
			return cachedKey, nil
		}
		composite, err := loadCompositeKeys(f.keyDirectory, keyID, profileSuffix)
		if err != nil {
			return nil, err
		}
		f.keyCache[cacheKey] = composite
		return composite, nil
	}

	var filename string
	switch scheme {
	case suciutil.SchemeProfileA:
		filename = fmt.Sprintf("hn-key-%d-profile-a.pem", keyID)
	case suciutil.SchemeProfileB:
		filename = fmt.Sprintf("hn-key-%d-profile-b.pem", keyID)
	case suciutil.SchemeProfileC:
		filename = fmt.Sprintf("hn-key-%d-profile-c.pem", keyID)
	default:
		return nil, ErrInvalidScheme
	}

	keyPath := fmt.Sprintf("%s/%s", f.keyDirectory, filename)

	if cachedKey, exists := f.keyCache[keyPath]; exists {
		return cachedKey, nil
	}

	privateKey, err := loadPrivateKeyFromFile(keyPath, scheme)
	if err != nil {
		return nil, err
	}

	f.keyCache[keyPath] = privateKey
	return privateKey, nil
}

// loadCompositeKeys loads both composite private keys (ML-KEM + X25519) from directory.
func loadCompositeKeys(keyDir string, keyID uint8, profileSuffix string) (*suciutil.ProfileDPrivateKeys, error) {
	mlkemPath := fmt.Sprintf("%s/hn-key-%d-%s-mlkem.pem", keyDir, keyID, profileSuffix)
	x25519Path := fmt.Sprintf("%s/hn-key-%d-%s-x25519.pem", keyDir, keyID, profileSuffix)
	// Try two-file layout first
	mlkemData, errMl := os.ReadFile(mlkemPath)
	x25519Data, errX := os.ReadFile(x25519Path)
	if errMl == nil && errX == nil {
		mlkemBlock, _ := pem.Decode(mlkemData)
		if mlkemBlock == nil {
			return nil, ErrInvalidKey
		}
		x25519Block, _ := pem.Decode(x25519Data)
		if x25519Block == nil {
			return nil, ErrInvalidKey
		}

		mlkemPriv, err := parseProfileCKey(mlkemBlock)
		if err != nil {
			return nil, err
		}
		x25519Priv, err := parseProfileAKey(x25519Block)
		if err != nil {
			return nil, err
		}

		mlkemBytes, ok := mlkemPriv.([]byte)
		if !ok || (len(mlkemBytes) != suciutil.MLKEM768_PRIVATE_KEY_LEN && len(mlkemBytes) != suciutil.MLKEM1024_PRIVATE_KEY_LEN) {
			return nil, ErrInvalidKey
		}
		x25519Bytes, ok := x25519Priv.([]byte)
		if !ok || len(x25519Bytes) != 32 {
			return nil, ErrInvalidKey
		}

		return &suciutil.ProfileDPrivateKeys{
			MLKEMPrivate:  mlkemBytes,
			X25519Private: x25519Bytes,
		}, nil
	}

	// If two-file layout not present, try single-file containing both PEM blocks
	singlePath := fmt.Sprintf("%s/hn-key-%d-%s.pem", keyDir, keyID, profileSuffix)
	singleData, err := os.ReadFile(singlePath)
	if err != nil {
		// prefer original two-file error semantics
		return nil, ErrKeyNotFound
	}

	// Decode multiple PEM blocks from single file
	var mlkemBytes []byte
	var x25519Bytes []byte
	rest := singleData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if (block.Type == "ML-KEM-768 PRIVATE KEY" && len(block.Bytes) == suciutil.MLKEM768_PRIVATE_KEY_LEN) ||
			(block.Type == "ML-KEM-1024 PRIVATE KEY" && len(block.Bytes) == suciutil.MLKEM1024_PRIVATE_KEY_LEN) {
			mlkemBytes = block.Bytes
			continue
		}
		if block.Type == "X25519 PRIVATE KEY" && len(block.Bytes) == 32 {
			x25519Bytes = block.Bytes
			continue
		}
		if mlkemBytes == nil && (len(block.Bytes) == suciutil.MLKEM768_PRIVATE_KEY_LEN || len(block.Bytes) == suciutil.MLKEM1024_PRIVATE_KEY_LEN) {
			mlkemBytes = block.Bytes
			continue
		}
		if len(block.Bytes) == 32 && x25519Bytes == nil {
			x25519Bytes = block.Bytes
			continue
		}
	}

	if mlkemBytes == nil || x25519Bytes == nil {
		return nil, ErrInvalidKey
	}

	return &suciutil.ProfileDPrivateKeys{
		MLKEMPrivate:  mlkemBytes,
		X25519Private: x25519Bytes,
	}, nil
}

// loadPrivateKeyFromFile loads and parses a private key from a PEM file
func loadPrivateKeyFromFile(filePath string, scheme suciutil.SchemeID) (interface{}, error) {
	if scheme == suciutil.SchemeProfileG {
		return loadProfileGKeyMaterialFromFile(filePath, 0, true)
	}

	// Read PEM file
	pemData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, ErrKeyNotFound
	}

	// Decode PEM block
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidKey
	}

	switch scheme {
	case suciutil.SchemeProfileA:
		// For Curve25519, we expect raw 32-byte private key
		// or PKCS#8 format
		return parseProfileAKey(block)

	case suciutil.SchemeProfileB:
		// For P-256, we expect PKCS#8 or SEC1 format
		return parseProfileBKey(block)

	case suciutil.SchemeProfileC:
		// For ML-KEM-768, we expect raw 2400-byte private key
		return parseProfileCKey(block)

	default:
		return nil, ErrInvalidScheme
	}
}

type profileGKeyFile struct {
	Profile           string `json:"profile"`
	SecurityLevel     int    `json:"security_level"`
	HNSymmetricKeyHex string `json:"hn_symmetric_key_hex"`
	WindowSizeSeconds int64  `json:"window_size_seconds"`
}

type profileGSubscriberMapFile struct {
	Subscribers map[string]string `json:"subscribers"`
}

func parseHexKeyStrict(s string, wantLen int) ([]byte, error) {
	v := strings.TrimSpace(strings.ToLower(s))
	v = strings.TrimPrefix(v, "0x")
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, err
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf("expected %d bytes, got %d", wantLen, len(b))
	}
	return b, nil
}

func loadProfileGSubscribers(mainKeyPath string) (map[string][]byte, error) {
	// Sidecar mapping file: same base with -subscribers.json suffix.
	base := strings.TrimSuffix(mainKeyPath, ".json")
	subPath := base + "-subscribers.json"
	data, err := os.ReadFile(subPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string][]byte{}, nil
		}
		return nil, ErrInvalidKey
	}
	var in profileGSubscriberMapFile
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, ErrInvalidKey
	}
	out := make(map[string][]byte, len(in.Subscribers))
	for rawID, rawKmaster := range in.Subscribers {
		normID, err := suciutil.NormalizeProfileGSubscriberKeyID(rawID)
		if err != nil {
			return nil, ErrInvalidKey
		}
		kmaster, err := parseHexKeyStrict(rawKmaster, 16)
		if err != nil {
			return nil, ErrInvalidKey
		}
		out[normID] = kmaster
	}
	return out, nil
}

func inferProfileGKeyIDFromPath(path string) uint8 {
	base := filepath.Base(path)
	parts := strings.Split(base, "-")
	if len(parts) >= 3 && parts[0] == "hn" && parts[1] == "key" {
		// unexpected split for current naming; fall through
	}
	// Expected naming: hn-key-<id>-profile-g.json
	var keyID int
	if _, err := fmt.Sscanf(base, "hn-key-%d-profile-g.json", &keyID); err == nil && keyID >= 0 && keyID <= 255 {
		return uint8(keyID)
	}
	return 0
}

func loadProfileGKeyMaterialFromFile(mainKeyPath string, keyID uint8, loadSubscribers bool) (*suciutil.ProfileGKeyMaterial, error) {
	data, err := os.ReadFile(mainKeyPath)
	if err != nil {
		return nil, ErrKeyNotFound
	}
	var in profileGKeyFile
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, ErrInvalidKey
	}
	level := suciutil.NormalizeMLKEMSecurityLevel(suciutil.MLKEMSecurityLevel(in.SecurityLevel))
	wantKeyLen := 16
	if level == suciutil.MLKEMSecurityLevel5 {
		wantKeyLen = 32
	}
	hnKey, err := parseHexKeyStrict(in.HNSymmetricKeyHex, wantKeyLen)
	if err != nil {
		return nil, ErrInvalidKey
	}

	subs := map[string][]byte{}
	if loadSubscribers {
		var loadErr error
		subs, loadErr = loadProfileGSubscribers(mainKeyPath)
		if loadErr != nil {
			return nil, loadErr
		}
	}
	resolvedID := keyID
	if resolvedID == 0 {
		resolvedID = inferProfileGKeyIDFromPath(mainKeyPath)
	}

	return &suciutil.ProfileGKeyMaterial{
		HNKeyID:           resolvedID,
		SecurityLevel:     level,
		HNSymmetricKey:    hnKey,
		SubscriberKeys:    subs,
		WindowSizeSeconds: in.WindowSizeSeconds,
	}, nil
}

// parseProfileAKey parses a Curve25519 private key
func parseProfileAKey(block *pem.Block) (interface{}, error) {
	// Handle X25519 PRIVATE KEY format (generated by our keygen)
	if block.Type == "X25519 PRIVATE KEY" {
		if len(block.Bytes) == 32 {
			return block.Bytes, nil
		}
		return nil, ErrInvalidKey
	}

	// Try to parse as PKCS#8
	if block.Type == "PRIVATE KEY" {
		// PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidKey
		}

		// Extract raw bytes for Curve25519
		if keyBytes, ok := key.([]byte); ok && len(keyBytes) == 32 {
			return keyBytes, nil
		}
		return nil, ErrInvalidKey
	}

	// Try raw 32-byte key
	if len(block.Bytes) == 32 {
		return block.Bytes, nil
	}

	return nil, ErrInvalidKey
}

// parseProfileBKey parses a P-256 (secp256r1) private key
func parseProfileBKey(block *pem.Block) (interface{}, error) {
	var privateKey *ecdsa.PrivateKey
	var err error

	// Try PKCS#8 format first
	if block.Type == "PRIVATE KEY" {
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, ErrInvalidKey
		}
		var ok bool
		privateKey, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrInvalidKey
		}
	} else if block.Type == "EC PRIVATE KEY" {
		// Try SEC1 EC private key format
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidKey
		}
	} else {
		return nil, ErrInvalidKey
	}

	return privateKey, nil
}

// parseProfileCKey parses an ML-KEM-768 or ML-KEM-1024 private key (raw decapsulation key bytes).
func parseProfileCKey(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "ML-KEM-768 PRIVATE KEY":
		if len(block.Bytes) == suciutil.MLKEM768_PRIVATE_KEY_LEN {
			return block.Bytes, nil
		}
		return nil, ErrInvalidKey
	case "ML-KEM-1024 PRIVATE KEY":
		if len(block.Bytes) == suciutil.MLKEM1024_PRIVATE_KEY_LEN {
			return block.Bytes, nil
		}
		return nil, ErrInvalidKey
	}
	switch len(block.Bytes) {
	case suciutil.MLKEM768_PRIVATE_KEY_LEN, suciutil.MLKEM1024_PRIVATE_KEY_LEN:
		return block.Bytes, nil
	default:
		return nil, ErrInvalidKey
	}
}

// MemoryKeyStore implements KeyStore using in-memory key storage
// Useful for testing and development
type MemoryKeyStore struct {
	keys map[string]interface{} // Key: "keyID-scheme", Value: private key
}

// NewMemoryKeyStore creates a new in-memory key store
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{
		keys: make(map[string]interface{}),
	}
}

// AddKey adds a private key to the memory store
func (m *MemoryKeyStore) AddKey(keyID uint8, scheme suciutil.SchemeID, privateKey interface{}) {
	keyName := fmt.Sprintf("%d-%d", keyID, scheme)
	m.keys[keyName] = privateKey
}

// GetPrivateKey retrieves a private key from memory
func (m *MemoryKeyStore) GetPrivateKey(keyID uint8, scheme suciutil.SchemeID) (interface{}, error) {
	keyName := fmt.Sprintf("%d-%d", keyID, scheme)
	privateKey, exists := m.keys[keyName]
	if !exists {
		return nil, ErrKeyNotFound
	}
	return privateKey, nil
}

// EnvKeyStore implements KeyStore using environment variables
// Keys are expected in PEM format in environment variables
type EnvKeyStore struct {
	keyCache map[string]interface{}
}

// NewEnvKeyStore creates a new environment variable-based key store
func NewEnvKeyStore() *EnvKeyStore {
	return &EnvKeyStore{
		keyCache: make(map[string]interface{}),
	}
}

// GetPrivateKey retrieves a private key from environment variables
// Expected env var naming: HN_KEY_{keyID}_{PROFILE_A|PROFILE_B|PROFILE_C}
// Example: HN_KEY_101_PROFILE_A or HN_KEY_5_PROFILE_B or HN_KEY_0_PROFILE_C
func (e *EnvKeyStore) GetPrivateKey(keyID uint8, scheme suciutil.SchemeID) (interface{}, error) {
	// Special handling for composite profiles (D/E/F): expect two env vars containing PEMs
	if scheme == suciutil.SchemeProfileD || scheme == suciutil.SchemeProfileE || scheme == suciutil.SchemeProfileF {
		var profileLabel string
		switch scheme {
		case suciutil.SchemeProfileD:
			profileLabel = "D"
		case suciutil.SchemeProfileE:
			profileLabel = "E"
		case suciutil.SchemeProfileF:
			profileLabel = "F"
		}
		envML := fmt.Sprintf("HN_KEY_%d_PROFILE_%s_MLKEM", keyID, profileLabel)
		envX := fmt.Sprintf("HN_KEY_%d_PROFILE_%s_X25519", keyID, profileLabel)

		// Check cache
		if cachedKey, exists := e.keyCache[envML+"|"+envX]; exists {
			return cachedKey, nil
		}

		pemML := os.Getenv(envML)
		pemX := os.Getenv(envX)
		if pemML == "" || pemX == "" {
			return nil, ErrKeyNotFound
		}

		mlBlock, _ := pem.Decode([]byte(pemML))
		if mlBlock == nil {
			return nil, ErrInvalidKey
		}
		xBlock, _ := pem.Decode([]byte(pemX))
		if xBlock == nil {
			return nil, ErrInvalidKey
		}

		mlPriv, err := parseProfileCKey(mlBlock)
		if err != nil {
			return nil, err
		}
		xPriv, err := parseProfileAKey(xBlock)
		if err != nil {
			return nil, err
		}

		mlBytes, ok := mlPriv.([]byte)
		if !ok || (len(mlBytes) != suciutil.MLKEM768_PRIVATE_KEY_LEN && len(mlBytes) != suciutil.MLKEM1024_PRIVATE_KEY_LEN) {
			return nil, ErrInvalidKey
		}
		xBytes, ok := xPriv.([]byte)
		if !ok || len(xBytes) != 32 {
			return nil, ErrInvalidKey
		}

		composite := &suciutil.ProfileDPrivateKeys{MLKEMPrivate: mlBytes, X25519Private: xBytes}
		e.keyCache[envML+"|"+envX] = composite
		return composite, nil
	}

	var envVarName string
	switch scheme {
	case suciutil.SchemeProfileA:
		envVarName = fmt.Sprintf("HN_KEY_%d_PROFILE_A", keyID)
	case suciutil.SchemeProfileB:
		envVarName = fmt.Sprintf("HN_KEY_%d_PROFILE_B", keyID)
	case suciutil.SchemeProfileC:
		envVarName = fmt.Sprintf("HN_KEY_%d_PROFILE_C", keyID)
	default:
		return nil, ErrInvalidScheme
	}

	// Check cache first
	if cachedKey, exists := e.keyCache[envVarName]; exists {
		return cachedKey, nil
	}

	// Read from environment
	pemData := os.Getenv(envVarName)
	if pemData == "" {
		return nil, ErrKeyNotFound
	}

	// Decode PEM block
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, ErrInvalidKey
	}

	// Parse key based on scheme
	var privateKey interface{}
	var err error

	switch scheme {
	case suciutil.SchemeProfileA:
		privateKey, err = parseProfileAKey(block)
	case suciutil.SchemeProfileB:
		privateKey, err = parseProfileBKey(block)
	case suciutil.SchemeProfileC:
		privateKey, err = parseProfileCKey(block)
	default:
		return nil, ErrInvalidScheme
	}

	if err != nil {
		return nil, err
	}

	// Cache the key
	e.keyCache[envVarName] = privateKey

	return privateKey, nil
}
