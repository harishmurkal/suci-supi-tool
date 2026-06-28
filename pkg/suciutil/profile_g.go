package suciutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// ProfileGConcealmentKeys contains inputs required for Profile-G concealment.
type ProfileGConcealmentKeys struct {
	SecurityLevel     MLKEMSecurityLevel
	HNSymmetricKey    []byte
	SubscriberKeyID   []byte
	Kmaster           []byte
	WindowSizeSeconds int64
}

// ProfileGKeyMaterial contains file-loaded key material for Profile-G deconcealment.
type ProfileGKeyMaterial struct {
	HNKeyID           uint8
	SecurityLevel     MLKEMSecurityLevel
	HNSymmetricKey    []byte
	SubscriberKeys    map[string][]byte // normalized lower-hex 10-char subscriber key ID -> 16-byte Kmaster
	WindowSizeSeconds int64
}

// NormalizeProfileGSubscriberKeyID normalizes a subscriber key ID to lower hex (5 bytes / 10 hex chars).
func NormalizeProfileGSubscriberKeyID(id string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(id))
	s = strings.TrimPrefix(s, "0x")
	if len(s) != ProfileG_KeyCipherTextLen*2 {
		return "", fmt.Errorf("subscriber key ID must be %d hex chars", ProfileG_KeyCipherTextLen*2)
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("subscriber key ID must be valid hex: %w", err)
	}
	return s, nil
}

func profileGParams(level MLKEMSecurityLevel) (rLen, macLen, keyLen int) {
	switch NormalizeMLKEMSecurityLevel(level) {
	case MLKEMSecurityLevel5:
		return ProfileG_Level5_RLen, ProfileG_Level5_MACLen, 32
	default:
		return ProfileG_Level3_RLen, ProfileG_Level3_MACLen, 16
	}
}

func profileGWindowSize(window int64) int64 {
	if window <= 0 {
		return ProfileG_DefaultWindowSizeSeconds
	}
	return window
}

func profileGWindowNow(windowSize int64, now time.Time) int64 {
	return now.Unix() / windowSize
}

func profileGWindowInfo(r []byte, window int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(window))
	out := make([]byte, 0, len(r)+len(b))
	out = append(out, r...)
	out = append(out, b...)
	return out
}

func profileGDeriveHKDFSHA256(ikm, info []byte, keyLen int) ([]byte, ErrorCode) {
	kdf := hkdf.New(sha256.New, ikm, nil, info)
	out := make([]byte, keyLen)
	if _, err := io.ReadFull(kdf, out); err != nil {
		return nil, E_ENCRYPTION_FAILED
	}
	return out, 0
}

func profileGDeriveSHA3256(ikm, info []byte, keyLen int) []byte {
	// ANSI X9.63-style expansion with SHA3-256: Hash(Z || Counter || Info)
	var result []byte
	counter := uint32(1)
	for len(result) < keyLen {
		h := sha3.New256()
		h.Write(ikm)
		cb := []byte{
			byte(counter >> 24),
			byte(counter >> 16),
			byte(counter >> 8),
			byte(counter),
		}
		h.Write(cb)
		h.Write(info)
		result = append(result, h.Sum(nil)...)
		counter++
	}
	return result[:keyLen]
}

func profileGAESCTR(input, key []byte) ([]byte, ErrorCode) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, E_ENCRYPTION_FAILED
	}
	iv := make([]byte, AES_IV_LEN)
	stream := cipher.NewCTR(block, iv)
	out := make([]byte, len(input))
	stream.XORKeyStream(out, input)
	return out, 0
}

func profileGHMACSHA256(data, key []byte, tagLen int) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	sum := m.Sum(nil)
	return sum[:tagLen]
}

func profileGKMAC256(data, key []byte, tagLen int) []byte {
	customString := []byte("SUCI-MAC")
	kmac := sha3.NewCShake256(nil, customString)
	encodedKey := encodeString(key)
	padded := bytepad(encodedKey, 136)
	kmac.Write(padded)
	kmac.Write(data)
	kmac.Write(rightEncode(uint64(tagLen * 8)))
	out := make([]byte, tagLen)
	kmac.Read(out)
	return out
}

func profileGVerifyMAC(expected, got []byte) bool {
	if len(expected) != len(got) {
		return false
	}
	return subtle.ConstantTimeCompare(expected, got) == 1
}

func profileGZeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func profileGDeriveKey(level MLKEMSecurityLevel, baseKey, info []byte, keyLen int) ([]byte, ErrorCode) {
	switch NormalizeMLKEMSecurityLevel(level) {
	case MLKEMSecurityLevel5:
		return profileGDeriveSHA3256(baseKey, info, keyLen), 0
	default:
		return profileGDeriveHKDFSHA256(baseKey, info, keyLen)
	}
}

func profileGComputeMAC(level MLKEMSecurityLevel, data, key []byte, macLen int) []byte {
	switch NormalizeMLKEMSecurityLevel(level) {
	case MLKEMSecurityLevel5:
		return profileGKMAC256(data, key, macLen)
	default:
		return profileGHMACSHA256(data, key, macLen)
	}
}

func profileGLookupKmaster(m map[string][]byte, subKey []byte) ([]byte, bool) {
	if len(subKey) != ProfileG_KeyCipherTextLen || m == nil {
		return nil, false
	}
	id := strings.ToLower(hex.EncodeToString(subKey))
	k, ok := m[id]
	if !ok || len(k) != 16 {
		return nil, false
	}
	out := make([]byte, len(k))
	copy(out, k)
	return out, true
}

// ParseProfileGCryptogram parses Profile G scheme output using Level 3 layout by default.
func ParseProfileGCryptogram(cryptogram []byte) (*ProfileGCryptogram, ErrorCode) {
	return ParseProfileGCryptogramForLevel(cryptogram, MLKEMSecurityLevel3)
}

// ParseProfileGCryptogramForLevel parses Profile G scheme output for the specified level.
func ParseProfileGCryptogramForLevel(cryptogram []byte, level MLKEMSecurityLevel) (*ProfileGCryptogram, ErrorCode) {
	rLen, macLen, _ := profileGParams(level)
	minLen := rLen + ProfileG_KeyCipherTextLen + macLen + macLen
	if len(cryptogram) < minLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}

	rEnd := rLen
	keyCipherEnd := rEnd + ProfileG_KeyCipherTextLen
	macKeyEnd := keyCipherEnd + macLen
	macMsinStart := len(cryptogram) - macLen
	if macMsinStart < macKeyEnd {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}

	r := make([]byte, rLen)
	copy(r, cryptogram[:rEnd])
	keyCipher := make([]byte, ProfileG_KeyCipherTextLen)
	copy(keyCipher, cryptogram[rEnd:keyCipherEnd])
	macKey := make([]byte, macLen)
	copy(macKey, cryptogram[keyCipherEnd:macKeyEnd])
	cipherText := make([]byte, macMsinStart-macKeyEnd)
	copy(cipherText, cryptogram[macKeyEnd:macMsinStart])
	macMsin := make([]byte, macLen)
	copy(macMsin, cryptogram[macMsinStart:])

	return &ProfileGCryptogram{
		R:             r,
		KeyCipherText: keyCipher,
		MACkey:        macKey,
		Ciphertext:    cipherText,
		MACmsin:       macMsin,
	}, 0
}

// EncryptProfileG builds a Profile-G scheme output from MSIN bytes.
func EncryptProfileG(msin []byte, keys *ProfileGConcealmentKeys) ([]byte, ErrorCode) {
	if keys == nil {
		return nil, E_INVALID_EC_KEY
	}
	level := NormalizeMLKEMSecurityLevel(keys.SecurityLevel)
	rLen, macLen, aesKeyLen := profileGParams(level)
	if len(keys.HNSymmetricKey) != aesKeyLen || len(keys.Kmaster) != 16 || len(keys.SubscriberKeyID) != ProfileG_KeyCipherTextLen {
		return nil, E_INVALID_EC_KEY
	}

	r := make([]byte, rLen)
	if _, err := rand.Read(r); err != nil {
		return nil, E_ENCRYPTION_FAILED
	}

	windowSize := profileGWindowSize(keys.WindowSizeSeconds)
	window := profileGWindowNow(windowSize, time.Now().UTC())
	info := profileGWindowInfo(r, window)

	kkey, errCode := profileGDeriveKey(level, keys.HNSymmetricKey, info, aesKeyLen)
	if errCode != 0 {
		return nil, errCode
	}
	defer profileGZeroize(kkey)

	ksuci, errCode := profileGDeriveKey(level, keys.Kmaster, info, aesKeyLen)
	if errCode != 0 {
		return nil, errCode
	}
	defer profileGZeroize(ksuci)

	keyCipherText, errCode := profileGAESCTR(keys.SubscriberKeyID, kkey)
	if errCode != 0 {
		return nil, errCode
	}
	cipherText, errCode := profileGAESCTR(msin, ksuci)
	if errCode != 0 {
		return nil, errCode
	}

	macKeyInput := make([]byte, 0, len(r)+len(keyCipherText))
	macKeyInput = append(macKeyInput, r...)
	macKeyInput = append(macKeyInput, keyCipherText...)
	macKey := profileGComputeMAC(level, macKeyInput, kkey, macLen)

	macMsinInput := make([]byte, 0, len(r)+len(cipherText))
	macMsinInput = append(macMsinInput, r...)
	macMsinInput = append(macMsinInput, cipherText...)
	macMsin := profileGComputeMAC(level, macMsinInput, ksuci, macLen)

	out := make([]byte, 0, len(r)+len(keyCipherText)+len(macKey)+len(cipherText)+len(macMsin))
	out = append(out, r...)
	out = append(out, keyCipherText...)
	out = append(out, macKey...)
	out = append(out, cipherText...)
	out = append(out, macMsin...)
	return out, 0
}

// DecryptProfileG verifies and decrypts a Profile-G cryptogram.
// It tries both current and previous time windows to tolerate UE/HN clock skew.
func DecryptProfileG(cryptogram *ProfileGCryptogram, material *ProfileGKeyMaterial) ([]byte, ErrorCode) {
	if cryptogram == nil || material == nil {
		return nil, E_INVALID_EC_KEY
	}
	level := NormalizeMLKEMSecurityLevel(material.SecurityLevel)
	rLen, macLen, aesKeyLen := profileGParams(level)
	if len(material.HNSymmetricKey) != aesKeyLen || len(cryptogram.R) != rLen || len(cryptogram.KeyCipherText) != ProfileG_KeyCipherTextLen || len(cryptogram.MACkey) != macLen || len(cryptogram.MACmsin) != macLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}

	windowSize := profileGWindowSize(material.WindowSizeSeconds)
	current := profileGWindowNow(windowSize, time.Now().UTC())
	candidates := []int64{current, current - 1}

	for _, window := range candidates {
		info := profileGWindowInfo(cryptogram.R, window)

		kkey, errCode := profileGDeriveKey(level, material.HNSymmetricKey, info, aesKeyLen)
		if errCode != 0 {
			return nil, errCode
		}

		macKeyInput := make([]byte, 0, len(cryptogram.R)+len(cryptogram.KeyCipherText))
		macKeyInput = append(macKeyInput, cryptogram.R...)
		macKeyInput = append(macKeyInput, cryptogram.KeyCipherText...)
		expectedMACKey := profileGComputeMAC(level, macKeyInput, kkey, macLen)
		if !profileGVerifyMAC(expectedMACKey, cryptogram.MACkey) {
			profileGZeroize(kkey)
			continue
		}

		subscriberKeyID, errCode := profileGAESCTR(cryptogram.KeyCipherText, kkey)
		profileGZeroize(kkey)
		if errCode != 0 {
			continue
		}

		kmaster, ok := profileGLookupKmaster(material.SubscriberKeys, subscriberKeyID)
		if !ok {
			continue
		}
		infoMsin := profileGWindowInfo(cryptogram.R, window)
		ksuci, errCode := profileGDeriveKey(level, kmaster, infoMsin, aesKeyLen)
		profileGZeroize(kmaster)
		if errCode != 0 {
			continue
		}

		macMsinInput := make([]byte, 0, len(cryptogram.R)+len(cryptogram.Ciphertext))
		macMsinInput = append(macMsinInput, cryptogram.R...)
		macMsinInput = append(macMsinInput, cryptogram.Ciphertext...)
		expectedMACmsin := profileGComputeMAC(level, macMsinInput, ksuci, macLen)
		if !profileGVerifyMAC(expectedMACmsin, cryptogram.MACmsin) {
			profileGZeroize(ksuci)
			continue
		}

		plain, decErr := profileGAESCTR(cryptogram.Ciphertext, ksuci)
		profileGZeroize(ksuci)
		if decErr != 0 {
			continue
		}
		return plain, 0
	}

	return nil, E_TAG_MISMATCH
}
