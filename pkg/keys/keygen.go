package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
	"golang.org/x/crypto/curve25519"
)

// KeyPair represents a generated key pair with both private and public keys
type KeyPair struct {
	PrivateKey    interface{}       // Raw bytes for Profile A, *ecdsa.PrivateKey for Profile B
	PublicKey     interface{}       // Raw bytes for Profile A, *ecdsa.PublicKey for Profile B
	PrivateKeyPEM []byte            // PEM-encoded private key
	PublicKeyPEM  []byte            // PEM-encoded public key
	PrivateKeyDER []byte            // DER-encoded private key
	PublicKeyDER  []byte            // DER-encoded public key
	PrivateKeyHex string            // Hex-encoded raw private key
	PublicKeyHex  string            // Hex-encoded raw public key
	KeyID         uint8             // Key identifier (0-255)
	Scheme        suciutil.SchemeID // Profile A or Profile B
}

func mlkemGenerateRaw(level suciutil.MLKEMSecurityLevel) (pubBytes, privBytes []byte, err error) {
	switch suciutil.NormalizeMLKEMSecurityLevel(level) {
	case suciutil.MLKEMSecurityLevel5:
		pub, priv, e := mlkem1024.GenerateKeyPair(rand.Reader)
		if e != nil {
			return nil, nil, fmt.Errorf("failed to generate ML-KEM-1024 key pair: %w", e)
		}
		pubBytes, e = pub.MarshalBinary()
		if e != nil {
			return nil, nil, fmt.Errorf("failed to marshal ML-KEM-1024 public key: %w", e)
		}
		privBytes, e = priv.MarshalBinary()
		if e != nil {
			return nil, nil, fmt.Errorf("failed to marshal ML-KEM-1024 private key: %w", e)
		}
		return pubBytes, privBytes, nil
	default:
		pub, priv, e := mlkem768.GenerateKeyPair(rand.Reader)
		if e != nil {
			return nil, nil, fmt.Errorf("failed to generate ML-KEM-768 key pair: %w", e)
		}
		pubBytes, e = pub.MarshalBinary()
		if e != nil {
			return nil, nil, fmt.Errorf("failed to marshal ML-KEM public key: %w", e)
		}
		privBytes, e = priv.MarshalBinary()
		if e != nil {
			return nil, nil, fmt.Errorf("failed to marshal ML-KEM private key: %w", e)
		}
		return pubBytes, privBytes, nil
	}
}

func mlkemPEMTypesFromPrivLen(n int) (privType, pubType string) {
	switch n {
	case suciutil.MLKEM1024_PRIVATE_KEY_LEN:
		return "ML-KEM-1024 PRIVATE KEY", "ML-KEM-1024 PUBLIC KEY"
	default:
		return "ML-KEM-768 PRIVATE KEY", "ML-KEM-768 PUBLIC KEY"
	}
}

// GenerateKeyPair generates a new key pair for the specified scheme and key ID.
// Optional mlkemLevelOpt applies to profiles C–F (3 = ML-KEM-768 default, 5 = ML-KEM-1024); ignored for A/B.
func GenerateKeyPair(keyID uint8, scheme suciutil.SchemeID, mlkemLevelOpt ...suciutil.MLKEMSecurityLevel) (*KeyPair, error) {
	level := suciutil.MLKEMSecurityLevel3
	if len(mlkemLevelOpt) > 0 {
		level = suciutil.NormalizeMLKEMSecurityLevel(mlkemLevelOpt[0])
	}
	switch scheme {
	case suciutil.SchemeProfileA:
		return generateProfileAKey(keyID)
	case suciutil.SchemeProfileB:
		return generateProfileBKey(keyID)
	case suciutil.SchemeProfileC:
		return generateProfileCKey(keyID, level)
	case suciutil.SchemeProfileD:
		return generateProfileDKey(keyID, level)
	case suciutil.SchemeProfileE:
		return generateProfileEKey(keyID, level)
	case suciutil.SchemeProfileF:
		return generateProfileFKey(keyID, level)
	case suciutil.SchemeProfileG:
		return generateProfileGKey(keyID, level)
	default:
		return nil, ErrInvalidScheme
	}
}

// generateProfileAKey generates a Curve25519/X25519 key pair for Profile A
func generateProfileAKey(keyID uint8) (*KeyPair, error) {
	// Generate 32 random bytes for the private key
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Clamp the private key as per X25519 specification
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// Derive public key from private key
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Create PEM-encoded private key (PKCS#8 format)
	// For X25519, we use the raw 32-byte format wrapped in a simple PEM block
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X25519 PRIVATE KEY",
		Bytes: privateKey,
	})

	// Create PEM-encoded public key
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X25519 PUBLIC KEY",
		Bytes: publicKey,
	})

	return &KeyPair{
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  publicKeyPEM,
		PrivateKeyDER: privateKey, // For X25519, DER is just raw bytes
		PublicKeyDER:  publicKey,
		PrivateKeyHex: hex.EncodeToString(privateKey),
		PublicKeyHex:  hex.EncodeToString(publicKey),
		KeyID:         keyID,
		Scheme:        suciutil.SchemeProfileA,
	}, nil
}

// generateProfileBKey generates a P-256/secp256r1 key pair for Profile B
func generateProfileBKey(keyID uint8) (*KeyPair, error) {
	// Generate P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-256 key: %w", err)
	}

	// Create PEM-encoded private key (PKCS#8 format)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Create PEM-encoded public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Raw hex for private key (just the D value)
	privateKeyHex := hex.EncodeToString(privateKey.D.Bytes())

	// Raw hex for public key (uncompressed point)
	publicKeyRaw := elliptic.Marshal(privateKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	publicKeyHex := hex.EncodeToString(publicKeyRaw)

	return &KeyPair{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  publicKeyPEM,
		PrivateKeyDER: privateKeyBytes,
		PublicKeyDER:  publicKeyBytes,
		PrivateKeyHex: privateKeyHex,
		PublicKeyHex:  publicKeyHex,
		KeyID:         keyID,
		Scheme:        suciutil.SchemeProfileB,
	}, nil
}

// generateProfileCKey generates an ML-KEM key pair for PQC Profile C (768 or 1024 per level).
func generateProfileCKey(keyID uint8, level suciutil.MLKEMSecurityLevel) (*KeyPair, error) {
	level = suciutil.NormalizeMLKEMSecurityLevel(level)
	publicKeyBytes, privateKeyBytes, err := mlkemGenerateRaw(level)
	if err != nil {
		return nil, err
	}
	privType, pubType := mlkemPEMTypesFromPrivLen(len(privateKeyBytes))
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  privType,
		Bytes: privateKeyBytes,
	})
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  pubType,
		Bytes: publicKeyBytes,
	})

	return &KeyPair{
		PrivateKey:    privateKeyBytes,
		PublicKey:     publicKeyBytes,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  publicKeyPEM,
		PrivateKeyDER: privateKeyBytes, // DER is raw bytes for ML-KEM
		PublicKeyDER:  publicKeyBytes,
		PrivateKeyHex: hex.EncodeToString(privateKeyBytes),
		PublicKeyHex:  hex.EncodeToString(publicKeyBytes),
		KeyID:         keyID,
		Scheme:        suciutil.SchemeProfileC,
	}, nil
}

// generateProfileDKey generates hybrid Profile D key pair: ML-KEM + X25519.
func generateProfileDKey(keyID uint8, level suciutil.MLKEMSecurityLevel) (*KeyPair, error) {
	level = suciutil.NormalizeMLKEMSecurityLevel(level)
	mlkemPubBytes, mlkemPrivBytes, err := mlkemGenerateRaw(level)
	if err != nil {
		return nil, err
	}

	// X25519 key pair
	x25519Priv := make([]byte, 32)
	if _, err := rand.Read(x25519Priv); err != nil {
		return nil, fmt.Errorf("failed to generate X25519 private key: %w", err)
	}
	x25519Priv[0] &= 248
	x25519Priv[31] &= 127
	x25519Priv[31] |= 64
	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X25519 public key: %w", err)
	}

	compositePriv := &suciutil.ProfileDPrivateKeys{
		MLKEMPrivate:  mlkemPrivBytes,
		X25519Private: x25519Priv,
	}
	compositePub := &suciutil.ProfileDPublicKeys{
		MLKEMPublic:  mlkemPubBytes,
		X25519Public: x25519Pub,
	}

	privType, pubType := mlkemPEMTypesFromPrivLen(len(mlkemPrivBytes))
	mlkemPrivPEM := pem.EncodeToMemory(&pem.Block{Type: privType, Bytes: mlkemPrivBytes})
	mlkemPubPEM := pem.EncodeToMemory(&pem.Block{Type: pubType, Bytes: mlkemPubBytes})

	return &KeyPair{
		PrivateKey:    compositePriv,
		PublicKey:     compositePub,
		PrivateKeyPEM: mlkemPrivPEM, // first of two; SaveKeyPairWithFormat writes both
		PublicKeyPEM:  mlkemPubPEM,
		PrivateKeyDER: mlkemPrivBytes,
		PublicKeyDER:  mlkemPubBytes,
		PrivateKeyHex: hex.EncodeToString(mlkemPrivBytes) + "\n" + hex.EncodeToString(x25519Priv),
		PublicKeyHex:  hex.EncodeToString(mlkemPubBytes) + "\n" + hex.EncodeToString(x25519Pub),
		KeyID:         keyID,
		Scheme:        suciutil.SchemeProfileD,
	}, nil
}

// generateProfileEKey generates Nested Hybrid Profile E key pair: ML-KEM + X25519.
func generateProfileEKey(keyID uint8, level suciutil.MLKEMSecurityLevel) (*KeyPair, error) {
	level = suciutil.NormalizeMLKEMSecurityLevel(level)
	mlkemPubBytes, mlkemPrivBytes, err := mlkemGenerateRaw(level)
	if err != nil {
		return nil, err
	}

	x25519Priv := make([]byte, 32)
	if _, err := rand.Read(x25519Priv); err != nil {
		return nil, fmt.Errorf("failed to generate X25519 private key: %w", err)
	}
	x25519Priv[0] &= 248
	x25519Priv[31] &= 127
	x25519Priv[31] |= 64
	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X25519 public key: %w", err)
	}

	compositePriv := &suciutil.ProfileDPrivateKeys{
		MLKEMPrivate:  mlkemPrivBytes,
		X25519Private: x25519Priv,
	}
	compositePub := &suciutil.ProfileDPublicKeys{
		MLKEMPublic:  mlkemPubBytes,
		X25519Public: x25519Pub,
	}

	privTypeE, pubTypeE := mlkemPEMTypesFromPrivLen(len(mlkemPrivBytes))
	mlkemPrivPEM := pem.EncodeToMemory(&pem.Block{Type: privTypeE, Bytes: mlkemPrivBytes})
	mlkemPubPEM := pem.EncodeToMemory(&pem.Block{Type: pubTypeE, Bytes: mlkemPubBytes})

	return &KeyPair{
		PrivateKey:    compositePriv,
		PublicKey:     compositePub,
		PrivateKeyPEM: mlkemPrivPEM,
		PublicKeyPEM:  mlkemPubPEM,
		PrivateKeyDER: mlkemPrivBytes,
		PublicKeyDER:  mlkemPubBytes,
		PrivateKeyHex: hex.EncodeToString(mlkemPrivBytes) + "\n" + hex.EncodeToString(x25519Priv),
		PublicKeyHex:  hex.EncodeToString(mlkemPubBytes) + "\n" + hex.EncodeToString(x25519Pub),
		KeyID:         keyID,
		Scheme:        suciutil.SchemeProfileE,
	}, nil
}

// generateProfileFKey generates Wrapper Hybrid Profile F key pair: ML-KEM + X25519.
func generateProfileFKey(keyID uint8, level suciutil.MLKEMSecurityLevel) (*KeyPair, error) {
	level = suciutil.NormalizeMLKEMSecurityLevel(level)
	mlkemPubBytes, mlkemPrivBytes, err := mlkemGenerateRaw(level)
	if err != nil {
		return nil, err
	}

	x25519Priv := make([]byte, 32)
	if _, err := rand.Read(x25519Priv); err != nil {
		return nil, fmt.Errorf("failed to generate X25519 private key: %w", err)
	}
	x25519Priv[0] &= 248
	x25519Priv[31] &= 127
	x25519Priv[31] |= 64
	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X25519 public key: %w", err)
	}

	compositePriv := &suciutil.ProfileDPrivateKeys{
		MLKEMPrivate:  mlkemPrivBytes,
		X25519Private: x25519Priv,
	}
	compositePub := &suciutil.ProfileDPublicKeys{
		MLKEMPublic:  mlkemPubBytes,
		X25519Public: x25519Pub,
	}

	privTypeF, pubTypeF := mlkemPEMTypesFromPrivLen(len(mlkemPrivBytes))
	mlkemPrivPEM := pem.EncodeToMemory(&pem.Block{Type: privTypeF, Bytes: mlkemPrivBytes})
	mlkemPubPEM := pem.EncodeToMemory(&pem.Block{Type: pubTypeF, Bytes: mlkemPubBytes})

	return &KeyPair{
		PrivateKey:    compositePriv,
		PublicKey:     compositePub,
		PrivateKeyPEM: mlkemPrivPEM,
		PublicKeyPEM:  mlkemPubPEM,
		PrivateKeyDER: mlkemPrivBytes,
		PublicKeyDER:  mlkemPubBytes,
		PrivateKeyHex: hex.EncodeToString(mlkemPrivBytes) + "\n" + hex.EncodeToString(x25519Priv),
		PublicKeyHex:  hex.EncodeToString(mlkemPubBytes) + "\n" + hex.EncodeToString(x25519Pub),
		KeyID:         keyID,
		Scheme:        suciutil.SchemeProfileF,
	}, nil
}

type profileGGeneratedKeyFile struct {
	Profile           string `json:"profile"`
	SecurityLevel     int    `json:"security_level"`
	HNSymmetricKeyHex string `json:"hn_symmetric_key_hex"`
	WindowSizeSeconds int64  `json:"window_size_seconds"`
}

type profileGGeneratedSubscribersFile struct {
	Subscribers map[string]string `json:"subscribers"`
}

// generateProfileGKey generates symmetric Profile G key material.
func generateProfileGKey(keyID uint8, level suciutil.MLKEMSecurityLevel) (*KeyPair, error) {
	level = suciutil.NormalizeMLKEMSecurityLevel(level)
	keyLen := 16
	if level == suciutil.MLKEMSecurityLevel5 {
		keyLen = 32
	}
	hnKey := make([]byte, keyLen)
	if _, err := rand.Read(hnKey); err != nil {
		return nil, fmt.Errorf("failed to generate Profile G symmetric key: %w", err)
	}
	keyFile := profileGGeneratedKeyFile{
		Profile:           "g",
		SecurityLevel:     int(level),
		HNSymmetricKeyHex: hex.EncodeToString(hnKey),
		WindowSizeSeconds: suciutil.ProfileG_DefaultWindowSizeSeconds,
	}
	keyJSON, err := json.MarshalIndent(keyFile, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Profile G key file: %w", err)
	}
	template := profileGGeneratedSubscribersFile{
		Subscribers: map[string]string{
			"0011223344": "00112233445566778899aabbccddeeff",
		},
	}
	templateJSON, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Profile G subscriber template: %w", err)
	}
	return &KeyPair{
		PrivateKey: &suciutil.ProfileGKeyMaterial{
			HNKeyID:           keyID,
			SecurityLevel:     level,
			HNSymmetricKey:    hnKey,
			SubscriberKeys:    map[string][]byte{},
			WindowSizeSeconds: suciutil.ProfileG_DefaultWindowSizeSeconds,
		},
		PublicKey:     nil,
		PrivateKeyPEM: keyJSON,
		PublicKeyPEM:  templateJSON,
		PrivateKeyDER: keyJSON,
		PublicKeyDER:  templateJSON,
		PrivateKeyHex: hex.EncodeToString(hnKey),
		PublicKeyHex:  "",
		KeyID:         keyID,
		Scheme:        suciutil.SchemeProfileG,
	}, nil
}

// profileDPEMs holds the two PEM blobs for Profile D save.
type profileDPEMs struct {
	mlkemPrivPEM, mlkemPubPEM   []byte
	x25519PrivPEM, x25519PubPEM []byte
}

func getProfileDPEMs(keyPair *KeyPair) (profileDPEMs, error) {
	priv, ok := keyPair.PrivateKey.(*suciutil.ProfileDPrivateKeys)
	if !ok || priv == nil {
		return profileDPEMs{}, ErrInvalidScheme
	}
	pub, ok := keyPair.PublicKey.(*suciutil.ProfileDPublicKeys)
	if !ok || pub == nil {
		return profileDPEMs{}, ErrInvalidScheme
	}
	privType, pubType := mlkemPEMTypesFromPrivLen(len(priv.MLKEMPrivate))
	mlkemPrivPEM := pem.EncodeToMemory(&pem.Block{Type: privType, Bytes: priv.MLKEMPrivate})
	mlkemPubPEM := pem.EncodeToMemory(&pem.Block{Type: pubType, Bytes: pub.MLKEMPublic})
	x25519PrivPEM := pem.EncodeToMemory(&pem.Block{Type: "X25519 PRIVATE KEY", Bytes: priv.X25519Private})
	x25519PubPEM := pem.EncodeToMemory(&pem.Block{Type: "X25519 PUBLIC KEY", Bytes: pub.X25519Public})
	return profileDPEMs{
		mlkemPrivPEM: mlkemPrivPEM, mlkemPubPEM: mlkemPubPEM,
		x25519PrivPEM: x25519PrivPEM, x25519PubPEM: x25519PubPEM,
	}, nil
}

func saveCompositeKeyPair(keyPair *KeyPair, outputDir string, savePublic bool, format KeyFormat) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	if format != FormatPEM {
		return fmt.Errorf("composite profiles (D/E/F) only support PEM format for now")
	}
	pems, err := getProfileDPEMs(keyPair)
	if err != nil {
		return err
	}
	var profileSuffix string
	switch keyPair.Scheme {
	case suciutil.SchemeProfileD:
		profileSuffix = "profile-d"
	case suciutil.SchemeProfileE:
		profileSuffix = "profile-e"
	case suciutil.SchemeProfileF:
		profileSuffix = "profile-f"
	default:
		return ErrInvalidScheme
	}
	base := fmt.Sprintf("hn-key-%d-%s", keyPair.KeyID, profileSuffix)
	if err := os.WriteFile(filepath.Join(outputDir, base+"-mlkem.pem"), pems.mlkemPrivPEM, 0600); err != nil {
		return fmt.Errorf("failed to save ML-KEM private key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, base+"-x25519.pem"), pems.x25519PrivPEM, 0600); err != nil {
		return fmt.Errorf("failed to save X25519 private key: %w", err)
	}
	if savePublic {
		if err := os.WriteFile(filepath.Join(outputDir, base+"-mlkem.pub.pem"), pems.mlkemPubPEM, 0644); err != nil {
			return fmt.Errorf("failed to save ML-KEM public key: %w", err)
		}
		if err := os.WriteFile(filepath.Join(outputDir, base+"-x25519.pub.pem"), pems.x25519PubPEM, 0644); err != nil {
			return fmt.Errorf("failed to save X25519 public key: %w", err)
		}
	}
	return nil
}

func saveProfileGKeyPair(keyPair *KeyPair, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	mainPath := filepath.Join(outputDir, fmt.Sprintf("hn-key-%d-profile-g.json", keyPair.KeyID))
	if err := os.WriteFile(mainPath, keyPair.PrivateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save Profile G key file: %w", err)
	}
	templatePath := filepath.Join(outputDir, fmt.Sprintf("hn-key-%d-profile-g-subscribers.json", keyPair.KeyID))
	if err := os.WriteFile(templatePath, keyPair.PublicKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save Profile G subscriber template: %w", err)
	}
	return nil
}

// GenerateKeyPairBatch generates multiple key pairs for a range of key IDs.
func GenerateKeyPairBatch(startID, endID uint8, scheme suciutil.SchemeID, mlkemLevelOpt ...suciutil.MLKEMSecurityLevel) ([]*KeyPair, error) {
	if startID > endID {
		return nil, fmt.Errorf("start ID (%d) must be less than or equal to end ID (%d)", startID, endID)
	}

	var keyPairs []*KeyPair
	for keyID := startID; keyID <= endID; keyID++ {
		keyPair, err := GenerateKeyPair(keyID, scheme, mlkemLevelOpt...)
		if err != nil {
			return keyPairs, fmt.Errorf("failed to generate key for ID %d: %w", keyID, err)
		}
		keyPairs = append(keyPairs, keyPair)

		// Handle uint8 overflow at 255
		if keyID == 255 {
			break
		}
	}
	return keyPairs, nil
}

// SaveKeyPair saves a key pair to files in the specified directory
// Creates files: hn-key-{keyID}-profile-{a|b}.{ext} (private) and hn-key-{keyID}-profile-{a|b}.pub.{ext} (public)
func SaveKeyPair(keyPair *KeyPair, outputDir string, savePublic bool) error {
	return SaveKeyPairWithFormat(keyPair, outputDir, savePublic, FormatPEM)
}

// SaveKeyPairWithFormat saves a key pair in the specified format
func SaveKeyPairWithFormat(keyPair *KeyPair, outputDir string, savePublic bool, format KeyFormat) error {
	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Profile D/E/F writes two files per key (mlkem + x25519)
	if keyPair.Scheme == suciutil.SchemeProfileD || keyPair.Scheme == suciutil.SchemeProfileE || keyPair.Scheme == suciutil.SchemeProfileF {
		return saveCompositeKeyPair(keyPair, outputDir, savePublic, format)
	}
	if keyPair.Scheme == suciutil.SchemeProfileG {
		// Profile G always uses JSON files regardless of --format.
		return saveProfileGKeyPair(keyPair, outputDir)
	}

	// Determine profile suffix
	var profileSuffix string
	switch keyPair.Scheme {
	case suciutil.SchemeProfileA:
		profileSuffix = "profile-a"
	case suciutil.SchemeProfileB:
		profileSuffix = "profile-b"
	case suciutil.SchemeProfileC:
		profileSuffix = "profile-c"
	case suciutil.SchemeProfileG:
		profileSuffix = "profile-g"
	default:
		return ErrInvalidScheme
	}

	// Determine file extension and content based on format
	var ext string
	var privateKeyData, publicKeyData []byte

	switch format {
	case FormatPEM:
		ext = "pem"
		privateKeyData = keyPair.PrivateKeyPEM
		publicKeyData = keyPair.PublicKeyPEM

	case FormatDER:
		ext = "der"
		privateKeyData = keyPair.PrivateKeyDER
		publicKeyData = keyPair.PublicKeyDER

	case FormatHex:
		ext = "hex"
		privateKeyData = []byte(keyPair.PrivateKeyHex + "\n")
		publicKeyData = []byte(keyPair.PublicKeyHex + "\n")

	case FormatJWK:
		ext = "jwk"
		var err error
		privateKeyData, err = keyPairToJWK(keyPair, true)
		if err != nil {
			return fmt.Errorf("failed to create private JWK: %w", err)
		}
		publicKeyData, err = keyPairToJWK(keyPair, false)
		if err != nil {
			return fmt.Errorf("failed to create public JWK: %w", err)
		}

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	// Save private key
	privateKeyFile := filepath.Join(outputDir, fmt.Sprintf("hn-key-%d-%s.%s", keyPair.KeyID, profileSuffix, ext))
	if err := os.WriteFile(privateKeyFile, privateKeyData, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Optionally save public key
	if savePublic {
		publicKeyFile := filepath.Join(outputDir, fmt.Sprintf("hn-key-%d-%s.pub.%s", keyPair.KeyID, profileSuffix, ext))
		if err := os.WriteFile(publicKeyFile, publicKeyData, 0644); err != nil {
			return fmt.Errorf("failed to save public key: %w", err)
		}
	}

	return nil
}

// keyPairToJWK converts a key pair to JWK JSON format
func keyPairToJWK(keyPair *KeyPair, includePrivate bool) ([]byte, error) {
	jwk := make(map[string]interface{})

	switch keyPair.Scheme {
	case suciutil.SchemeProfileA:
		// X25519 uses OKP key type
		jwk["kty"] = "OKP"
		jwk["crv"] = "X25519"
		jwk["kid"] = fmt.Sprintf("hn-key-%d", keyPair.KeyID)

		if pubKey, ok := keyPair.PublicKey.([]byte); ok {
			jwk["x"] = base64URLEncode(pubKey)
		}

		if includePrivate {
			if privKey, ok := keyPair.PrivateKey.([]byte); ok {
				jwk["d"] = base64URLEncode(privKey)
			}
		}

	case suciutil.SchemeProfileB:
		// P-256 uses EC key type
		jwk["kty"] = "EC"
		jwk["crv"] = "P-256"
		jwk["kid"] = fmt.Sprintf("hn-key-%d", keyPair.KeyID)

		if ecdsaKey, ok := keyPair.PrivateKey.(*ecdsa.PrivateKey); ok {
			jwk["x"] = base64URLEncode(ecdsaKey.PublicKey.X.Bytes())
			jwk["y"] = base64URLEncode(ecdsaKey.PublicKey.Y.Bytes())

			if includePrivate {
				jwk["d"] = base64URLEncode(ecdsaKey.D.Bytes())
			}
		} else if ecdsaPubKey, ok := keyPair.PublicKey.(*ecdsa.PublicKey); ok {
			jwk["x"] = base64URLEncode(ecdsaPubKey.X.Bytes())
			jwk["y"] = base64URLEncode(ecdsaPubKey.Y.Bytes())
		}

	case suciutil.SchemeProfileC:
		jwk["kty"] = "KEM"
		jwk["kid"] = fmt.Sprintf("hn-key-%d", keyPair.KeyID)
		jwk["alg"] = "ML-KEM-768"
		if pubKey, ok := keyPair.PublicKey.([]byte); ok {
			if len(pubKey) == suciutil.MLKEM1024_PUBLIC_KEY_LEN {
				jwk["alg"] = "ML-KEM-1024"
			}
			jwk["pub"] = base64URLEncode(pubKey)
		}

		if includePrivate {
			if privKey, ok := keyPair.PrivateKey.([]byte); ok {
				jwk["priv"] = base64URLEncode(privKey)
			}
		}
	}

	return json.MarshalIndent(jwk, "", "  ")
}

// base64URLEncode encodes bytes as base64url without padding
func base64URLEncode(data []byte) string {
	// Standard base64 encoding
	encoded := make([]byte, (len(data)+2)/3*4)

	const encodeStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	const encodeURL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	// Simple implementation - use encoding/base64 in production
	di, si := 0, 0
	n := (len(data) / 3) * 3
	for si < n {
		val := uint(data[si])<<16 | uint(data[si+1])<<8 | uint(data[si+2])
		encoded[di] = encodeURL[val>>18&0x3F]
		encoded[di+1] = encodeURL[val>>12&0x3F]
		encoded[di+2] = encodeURL[val>>6&0x3F]
		encoded[di+3] = encodeURL[val&0x3F]
		si += 3
		di += 4
	}

	remain := len(data) - si
	if remain == 0 {
		return string(encoded[:di])
	}

	val := uint(data[si]) << 16
	if remain == 2 {
		val |= uint(data[si+1]) << 8
	}

	encoded[di] = encodeURL[val>>18&0x3F]
	encoded[di+1] = encodeURL[val>>12&0x3F]

	switch remain {
	case 2:
		encoded[di+2] = encodeURL[val>>6&0x3F]
		return string(encoded[:di+3]) // No padding
	case 1:
		return string(encoded[:di+2]) // No padding
	}

	return string(encoded[:di])
}

// SaveKeyPairBatch saves multiple key pairs to files
func SaveKeyPairBatch(keyPairs []*KeyPair, outputDir string, savePublic bool) error {
	return SaveKeyPairBatchWithFormat(keyPairs, outputDir, savePublic, FormatPEM)
}

// SaveKeyPairBatchWithFormat saves multiple key pairs in the specified format
func SaveKeyPairBatchWithFormat(keyPairs []*KeyPair, outputDir string, savePublic bool, format KeyFormat) error {
	for _, keyPair := range keyPairs {
		if err := SaveKeyPairWithFormat(keyPair, outputDir, savePublic, format); err != nil {
			return err
		}
	}
	return nil
}

// GetKeyFileName returns the expected filename for a key
func GetKeyFileName(keyID uint8, scheme suciutil.SchemeID, isPublic bool) string {
	return GetKeyFileNameWithFormat(keyID, scheme, isPublic, FormatPEM)
}

// GetKeyFileNameWithFormat returns the expected filename for a key in the specified format
func GetKeyFileNameWithFormat(keyID uint8, scheme suciutil.SchemeID, isPublic bool, format KeyFormat) string {
	var profileSuffix string
	switch scheme {
	case suciutil.SchemeProfileA:
		profileSuffix = "profile-a"
	case suciutil.SchemeProfileB:
		profileSuffix = "profile-b"
	case suciutil.SchemeProfileC:
		profileSuffix = "profile-c"
	case suciutil.SchemeProfileD:
		ext := string(format)
		if format == FormatAuto {
			ext = "pem"
		}
		if isPublic {
			// return both public filenames comma-separated
			return fmt.Sprintf("hn-key-%d-profile-d-mlkem.pub.%s,hn-key-%d-profile-d-x25519.pub.%s", keyID, ext, keyID, ext)
		}
		// return both private filenames comma-separated (primary reference is mlkem)
		return fmt.Sprintf("hn-key-%d-profile-d-mlkem.%s,hn-key-%d-profile-d-x25519.%s", keyID, ext, keyID, ext)

	default:
		return ""
	}

	ext := string(format)
	if format == FormatAuto {
		ext = "pem"
	}

	if isPublic {
		return fmt.Sprintf("hn-key-%d-%s.pub.%s", keyID, profileSuffix, ext)
	}
	return fmt.Sprintf("hn-key-%d-%s.%s", keyID, profileSuffix, ext)
}

// KeyGenConfig holds configuration for key generation
type KeyGenConfig struct {
	OutputDir    string            // Directory to save keys
	StartKeyID   uint8             // Starting key ID
	EndKeyID     uint8             // Ending key ID
	Scheme       suciutil.SchemeID // Profile A or Profile B or both (use 0 for both)
	SavePublic   bool              // Whether to save public keys
	Verbose      bool              // Enable verbose output
	GenerateBoth bool              // Generate both Profile A and Profile B
	Format       KeyFormat         // Output format: pem, der, hex, jwk
}

// GenerateAndSaveKeys generates and saves keys according to configuration
func GenerateAndSaveKeys(config *KeyGenConfig) (int, error) {
	var totalGenerated int

	// Default format to PEM
	format := config.Format
	if format == "" || format == FormatAuto {
		format = FormatPEM
	}

	schemes := []suciutil.SchemeID{}
	if config.GenerateBoth {
		schemes = append(schemes, suciutil.SchemeProfileA, suciutil.SchemeProfileB)
	} else if config.Scheme == suciutil.SchemeNullScheme {
		// Default to both if not specified
		schemes = append(schemes, suciutil.SchemeProfileA, suciutil.SchemeProfileB)
	} else {
		schemes = append(schemes, config.Scheme)
	}

	for _, scheme := range schemes {
		keyPairs, err := GenerateKeyPairBatch(config.StartKeyID, config.EndKeyID, scheme)
		if err != nil {
			return totalGenerated, err
		}

		if err := SaveKeyPairBatchWithFormat(keyPairs, config.OutputDir, config.SavePublic, format); err != nil {
			return totalGenerated, err
		}

		totalGenerated += len(keyPairs)
	}

	return totalGenerated, nil
}
