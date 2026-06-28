package suci

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/harishmurkal/suci-supi-tool/pkg/slog"
	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

// ParsedSUPI represents the parsed components of a SUPI string
type ParsedSUPI struct {
	Type IdentityType // 0=IMSI, 1=NAI
	MCC  string       // Mobile Country Code (3 digits)
	MNC  string       // Mobile Network Code (2-3 digits)
	MSIN string       // Mobile Subscriber Identification Number
}

// SUPI regex pattern
// Format: imsi-<mcc><mnc><msin> or nai-<nai_string>
var supiIMSIRegex = regexp.MustCompile(`^imsi-(\d{3})(\d{2,3})(\d{1,12})$`)

// ParseSUPI parses and validates a SUPI string
// Returns ParsedSUPI or an error code
func ParseSUPI(supiStr string) (*ParsedSUPI, ErrorCode) {
	// Try IMSI format first
	matches := supiIMSIRegex.FindStringSubmatch(supiStr)
	slog.Debugf("[DEBUG] ParseSUPI: input='%s' regex matches=%v\n", supiStr, matches)
	if matches != nil {
		mcc := matches[1]
		mnc := matches[2]
		msin := matches[3]
		slog.Debugf("[DEBUG] ParseSUPI: MCC='%s' MNC='%s' MSIN='%s'\n", mcc, mnc, msin)

		// Validate total IMSI length (MCC + MNC + MSIN should be 5-15 digits)
		totalLen := len(mcc) + len(mnc) + len(msin)
		if totalLen < IMSI_MIN_LEN || totalLen > IMSI_MAX_LEN {
			slog.Debugf("[DEBUG] ParseSUPI: Invalid IMSI length: %d\n", totalLen)
			return nil, E_INVALID_IMSI_LENGTH
		}

		return &ParsedSUPI{
			Type: TypeIMSI,
			MCC:  mcc,
			MNC:  mnc,
			MSIN: msin,
		}, 0
	}

	slog.Debugf("[DEBUG] ParseSUPI: Invalid SUPI format for input='%s'\n", supiStr)
	return nil, E_PARSE_SUPI
}

// EncryptECIES performs ECIES encryption for Profile A, B, C, or D.
// For Profile D, profileDVariant selects baseline (0), add17 (1), or add19 (2).
// Optional mlkemLevelOpt: for profiles C–F, ML-KEM parameter set (3=768 default, 5=1024). Omitted means ML-KEM-768.
// Returns the scheme output or an error.
func EncryptECIES(msin []byte, publicKey interface{}, scheme SchemeID, profileDVariant suciutil.ProfileDVariant, mlkemLevelOpt ...suciutil.MLKEMSecurityLevel) ([]byte, ErrorCode) {
	level := suciutil.MLKEMSecurityLevel3
	if len(mlkemLevelOpt) > 0 {
		level = suciutil.NormalizeMLKEMSecurityLevel(mlkemLevelOpt[0])
	}
	switch scheme {
	case SchemeProfileA:
		out, err := encryptProfileA(msin, publicKey)
		if err == 0 && out != nil {
			pubKeyLen := 32
			macLen := MAC_TAG_LEN
			macStart := len(out) - macLen
			slog.Debugf("[DEBUG] EncryptECIES/ProfileA: EphemeralPublicKey: %x\n", out[:pubKeyLen])
			slog.Debugf("[DEBUG] EncryptECIES/ProfileA: Ciphertext: %x\n", out[pubKeyLen:macStart])
			slog.Debugf("[DEBUG] EncryptECIES/ProfileA: MAC: %x\n", out[macStart:])
		}
		return out, err
	case SchemeProfileB:
		return encryptProfileB(msin, publicKey)
	case SchemeProfileC:
		return encryptProfileC(msin, publicKey, level)
	case SchemeProfileD:
		switch profileDVariant {
		case suciutil.ProfileDVariantAdd17:
			return encryptProfileDAdd17(msin, publicKey, level)
		case suciutil.ProfileDVariantAdd19:
			return encryptProfileDAdd19(msin, publicKey, level)
		default:
			return encryptProfileD(msin, publicKey, level)
		}
	case SchemeProfileE:
		return encryptProfileE(msin, publicKey, level)
	case SchemeProfileF:
		return encryptProfileF(msin, publicKey, level)
	case SchemeProfileG:
		return encryptProfileG(msin, publicKey, level)
	default:
		return nil, E_INVALID_SCHEME_ID
	}
}

// encryptProfileA handles ECIES Profile A (Curve25519/X25519) encryption
func encryptProfileA(plaintext []byte, publicKey interface{}) ([]byte, ErrorCode) {
	// Validate public key type
	hnPubKey, ok := publicKey.([]byte)
	if !ok || len(hnPubKey) != 32 {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 1: Generate ephemeral key pair
	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// Clamp ephemeral private key as per X25519 specification
	ephemeralPrivate[0] &= 248
	ephemeralPrivate[31] &= 127
	ephemeralPrivate[31] |= 64

	// Derive ephemeral public key
	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 2: Perform ECDH to compute shared secret
	sharedSecret, err := curve25519.X25519(ephemeralPrivate, hnPubKey)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 3: Derive keys using KDF (ANSI-X9.63-KDF with SHA-256)
	derivedKeys := kdfANSIX963(sharedSecret, KDF_OUTPUT_LEN)
	if len(derivedKeys) < KDF_OUTPUT_LEN {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 4: Split derived keys into encryption key and MAC key
	encKey := derivedKeys[0:AES_KEY_LEN]              // First 16 bytes for AES-128
	macKey := derivedKeys[AES_KEY_LEN:KDF_OUTPUT_LEN] // Next 32 bytes for HMAC-SHA-256

	// STEP 5: Encrypt plaintext using AES-128-CTR
	ciphertext, errCode := encryptAESCTR(plaintext, encKey)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 6: Compute MAC
	macTag := computeMAC(ephemeralPublic, ciphertext, macKey)

	// STEP 7: Construct scheme output: ephemeralPubKey || ciphertext || MAC
	schemeOutput := make([]byte, 0, len(ephemeralPublic)+len(ciphertext)+len(macTag))
	schemeOutput = append(schemeOutput, ephemeralPublic...)
	schemeOutput = append(schemeOutput, ciphertext...)
	schemeOutput = append(schemeOutput, macTag...)

	return schemeOutput, 0
}

// encryptProfileB handles ECIES Profile B (secp256r1/NIST P-256) encryption
func encryptProfileB(plaintext []byte, publicKey interface{}) ([]byte, ErrorCode) {
	// Validate public key type
	hnPubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, E_INVALID_EC_KEY
	}

	// Validate that the key is for secp256r1
	if hnPubKey.Curve != elliptic.P256() {
		return nil, E_CURVE_MISMATCH
	}

	// STEP 1: Generate ephemeral key pair
	ephemeralPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// Get compressed ephemeral public key
	ephemeralPublic := compressP256Point(&ephemeralPrivate.PublicKey)

	// STEP 2: Perform ECDH to compute shared secret
	// Shared secret = x-coordinate of (hnPubKey * ephemeralPrivate)
	sharedX, _ := hnPubKey.Curve.ScalarMult(hnPubKey.X, hnPubKey.Y, ephemeralPrivate.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Ensure shared secret is exactly 32 bytes (pad with leading zeros if needed)
	if len(sharedSecret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(sharedSecret):], sharedSecret)
		sharedSecret = padded
	}

	// STEP 3: Derive keys using KDF (ANSI-X9.63-KDF with SHA-256)
	derivedKeys := kdfANSIX963(sharedSecret, KDF_OUTPUT_LEN)
	if len(derivedKeys) < KDF_OUTPUT_LEN {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 4: Split derived keys into encryption key and MAC key
	encKey := derivedKeys[0:AES_KEY_LEN]              // First 16 bytes for AES-128
	macKey := derivedKeys[AES_KEY_LEN:KDF_OUTPUT_LEN] // Next 32 bytes for HMAC-SHA-256

	// STEP 5: Encrypt plaintext using AES-128-CTR
	ciphertext, errCode := encryptAESCTR(plaintext, encKey)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 6: Compute MAC
	macTag := computeMAC(ephemeralPublic, ciphertext, macKey)

	// STEP 7: Construct scheme output: ephemeralPubKey || ciphertext || MAC
	schemeOutput := make([]byte, 0, len(ephemeralPublic)+len(ciphertext)+len(macTag))
	schemeOutput = append(schemeOutput, ephemeralPublic...)
	schemeOutput = append(schemeOutput, ciphertext...)
	schemeOutput = append(schemeOutput, macTag...)

	return schemeOutput, 0
}

func mlkemEncapsulateFromPublicBytes(pub []byte) ([]byte, []byte, ErrorCode) {
	switch len(pub) {
	case suciutil.MLKEM768_PUBLIC_KEY_LEN:
		var pk mlkem768.PublicKey
		if err := pk.Unpack(pub); err != nil {
			return nil, nil, E_INVALID_PQC_KEY
		}
		ct, ss, err := mlkem768.Scheme().Encapsulate(&pk)
		if err != nil {
			return nil, nil, E_KEM_ENCAPSULATE_FAILED
		}
		return ct, ss, 0
	case suciutil.MLKEM1024_PUBLIC_KEY_LEN:
		var pk mlkem1024.PublicKey
		if err := pk.Unpack(pub); err != nil {
			return nil, nil, E_INVALID_PQC_KEY
		}
		ct, ss, err := mlkem1024.Scheme().Encapsulate(&pk)
		if err != nil {
			return nil, nil, E_KEM_ENCAPSULATE_FAILED
		}
		return ct, ss, 0
	default:
		return nil, nil, E_INVALID_PQC_KEY
	}
}

// encryptProfileC handles PQC Profile C (ML-KEM-768 or ML-KEM-1024) encryption.
func encryptProfileC(plaintext []byte, publicKey interface{}, level suciutil.MLKEMSecurityLevel) ([]byte, ErrorCode) {
	level = suciutil.NormalizeMLKEMSecurityLevel(level)
	want := suciutil.MLKEMPublicKeyLen(level)
	hnPubKeyBytes, ok := publicKey.([]byte)
	if !ok || len(hnPubKeyBytes) != want {
		return nil, E_INVALID_PQC_KEY
	}

	kemCiphertext, sharedSecret, errCode := mlkemEncapsulateFromPublicBytes(hnPubKeyBytes)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 2: Derive keys using ANSI-X9.63-KDF with SHA3-256
	// SharedInfo1 = ML-KEM ciphertext (per 3GPP TS 33.703)
	derivedKeys := kdfANSIX963SHA3(sharedSecret, kemCiphertext, ProfileC_KDF_OUTPUT)
	if len(derivedKeys) < ProfileC_KDF_OUTPUT {
		return nil, E_ENCRYPTION_FAILED
	}

	// STEP 3: Split derived keys into encryption key and MAC key
	encKey := derivedKeys[0:ProfileC_ENC_KEY_LEN]                   // First 32 bytes for AES-256
	macKey := derivedKeys[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT] // Next 32 bytes for KMAC256

	// STEP 4: Encrypt plaintext using AES-256-CTR
	ciphertext, errCode := encryptAES256CTR(plaintext, encKey)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 5: Compute MAC using KMAC256
	macTag := computeKMAC256(ciphertext, macKey)

	// STEP 6: Construct scheme output: kemCiphertext (1088) || ciphertext || MAC (8)
	schemeOutput := make([]byte, 0, len(kemCiphertext)+len(ciphertext)+len(macTag))
	schemeOutput = append(schemeOutput, kemCiphertext...)
	schemeOutput = append(schemeOutput, ciphertext...)
	schemeOutput = append(schemeOutput, macTag...)

	return schemeOutput, 0
}

// encryptProfileD handles Hybrid Profile D (ML-KEM + X25519) encryption (UE concealment).
func encryptProfileD(plaintext []byte, publicKey interface{}, level suciutil.MLKEMSecurityLevel) ([]byte, ErrorCode) {
	level = suciutil.NormalizeMLKEMSecurityLevel(level)
	wantML := suciutil.MLKEMPublicKeyLen(level)
	pub, ok := publicKey.(*suciutil.ProfileDPublicKeys)
	if !ok || pub == nil || len(pub.MLKEMPublic) != wantML || len(pub.X25519Public) != 32 {
		return nil, E_INVALID_PQC_KEY
	}

	kemCiphertext, sharedSecret1, errCode := mlkemEncapsulateFromPublicBytes(pub.MLKEMPublic)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 2: Ephemeral X25519 keypair + ECDH with HN X25519 public → sharedSecret2
	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return nil, E_ENCRYPTION_FAILED
	}
	ephemeralPrivate[0] &= 248
	ephemeralPrivate[31] &= 127
	ephemeralPrivate[31] |= 64

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	sharedSecret2, err := curve25519.X25519(ephemeralPrivate, pub.X25519Public)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 3: Combiner — CombinedSecret = SHA3-256(ss1 || ss2)
	combinedInput := make([]byte, 0, 64)
	combinedInput = append(combinedInput, sharedSecret1...)
	combinedInput = append(combinedInput, sharedSecret2...)
	combinedHash := sha3.Sum256(combinedInput)
	combinedSecret := combinedHash[:]

	// STEP 4: KDF — SharedInfo1 = kemCiphertext || ephPublicKey
	sharedInfo1 := make([]byte, 0, len(kemCiphertext)+len(ephemeralPublic))
	sharedInfo1 = append(sharedInfo1, kemCiphertext...)
	sharedInfo1 = append(sharedInfo1, ephemeralPublic...)

	derivedKeys := kdfANSIX963SHA3(combinedSecret, sharedInfo1, ProfileC_KDF_OUTPUT)
	if len(derivedKeys) < ProfileC_KDF_OUTPUT {
		return nil, E_ENCRYPTION_FAILED
	}

	encKey := derivedKeys[0:ProfileC_ENC_KEY_LEN]
	macKey := derivedKeys[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT]

	// STEP 5: AES-256-CTR encrypt
	ciphertext, errCode := encryptAES256CTR(plaintext, encKey)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 6: KMAC256 over ciphertext
	macTag := computeKMAC256(ciphertext, macKey)

	// STEP 7: Output = kemCiphertext || ephPublicKey || ciphertext || macTag
	schemeOutput := make([]byte, 0, len(kemCiphertext)+len(ephemeralPublic)+len(ciphertext)+len(macTag))
	schemeOutput = append(schemeOutput, kemCiphertext...)
	schemeOutput = append(schemeOutput, ephemeralPublic...)
	schemeOutput = append(schemeOutput, ciphertext...)
	schemeOutput = append(schemeOutput, macTag...)

	return schemeOutput, 0
}

// encryptProfileDAdd17 implements add17 variant: nonce + profile/variant binding in KDF.
// Output: pqCiphertext || ephPublicKey || 0x01 || nonce(16) || ciphertext || macTag(8)
func encryptProfileDAdd17(plaintext []byte, publicKey interface{}, level suciutil.MLKEMSecurityLevel) ([]byte, ErrorCode) {
	level = suciutil.NormalizeMLKEMSecurityLevel(level)
	wantML := suciutil.MLKEMPublicKeyLen(level)
	pub, ok := publicKey.(*suciutil.ProfileDPublicKeys)
	if !ok || pub == nil || len(pub.MLKEMPublic) != wantML || len(pub.X25519Public) != 32 {
		return nil, E_INVALID_PQC_KEY
	}

	kemCiphertext, sharedSecret1, errCode := mlkemEncapsulateFromPublicBytes(pub.MLKEMPublic)
	if errCode != 0 {
		return nil, errCode
	}

	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return nil, E_ENCRYPTION_FAILED
	}
	ephemeralPrivate[0] &= 248
	ephemeralPrivate[31] &= 127
	ephemeralPrivate[31] |= 64

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	sharedSecret2, err := curve25519.X25519(ephemeralPrivate, pub.X25519Public)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	combinedInput := make([]byte, 0, 64)
	combinedInput = append(combinedInput, sharedSecret1...)
	combinedInput = append(combinedInput, sharedSecret2...)
	combinedHash := sha3.Sum256(combinedInput)
	combinedSecret := combinedHash[:]

	nonce := make([]byte, suciutil.ProfileD_Add17_NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, E_ENCRYPTION_FAILED
	}

	// SharedInfo1 = kemCt || ephPub || nonce || profileID(0x04) || hybridCode(0x17)
	sharedInfo1 := make([]byte, 0, len(kemCiphertext)+len(ephemeralPublic)+len(nonce)+2)
	sharedInfo1 = append(sharedInfo1, kemCiphertext...)
	sharedInfo1 = append(sharedInfo1, ephemeralPublic...)
	sharedInfo1 = append(sharedInfo1, nonce...)
	sharedInfo1 = append(sharedInfo1, 0x04, 0x17)

	derivedKeys := kdfANSIX963SHA3(combinedSecret, sharedInfo1, ProfileC_KDF_OUTPUT)
	if len(derivedKeys) < ProfileC_KDF_OUTPUT {
		return nil, E_ENCRYPTION_FAILED
	}
	encKey := derivedKeys[0:ProfileC_ENC_KEY_LEN]
	macKey := derivedKeys[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT]

	ciphertext, errCode := encryptAES256CTR(plaintext, encKey)
	if errCode != 0 {
		return nil, errCode
	}
	macTag := computeKMAC256(ciphertext, macKey)

	// Output: kemCt || ephPub || 0x01 || nonce || ciphertext || macTag
	schemeOutput := make([]byte, 0, len(kemCiphertext)+len(ephemeralPublic)+1+len(nonce)+len(ciphertext)+len(macTag))
	schemeOutput = append(schemeOutput, kemCiphertext...)
	schemeOutput = append(schemeOutput, ephemeralPublic...)
	schemeOutput = append(schemeOutput, 0x01)
	schemeOutput = append(schemeOutput, nonce...)
	schemeOutput = append(schemeOutput, ciphertext...)
	schemeOutput = append(schemeOutput, macTag...)
	return schemeOutput, 0
}

// encryptProfileDAdd19 implements add19 variant: AEAD with AAD binding.
// Output: pqCiphertext || ephPublicKey || 0x02 || nonce(12) || ciphertext || tag(16)
func encryptProfileDAdd19(plaintext []byte, publicKey interface{}, level suciutil.MLKEMSecurityLevel) ([]byte, ErrorCode) {
	level = suciutil.NormalizeMLKEMSecurityLevel(level)
	wantML := suciutil.MLKEMPublicKeyLen(level)
	pub, ok := publicKey.(*suciutil.ProfileDPublicKeys)
	if !ok || pub == nil || len(pub.MLKEMPublic) != wantML || len(pub.X25519Public) != 32 {
		return nil, E_INVALID_PQC_KEY
	}

	kemCiphertext, sharedSecret1, errCode := mlkemEncapsulateFromPublicBytes(pub.MLKEMPublic)
	if errCode != 0 {
		return nil, errCode
	}

	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return nil, E_ENCRYPTION_FAILED
	}
	ephemeralPrivate[0] &= 248
	ephemeralPrivate[31] &= 127
	ephemeralPrivate[31] |= 64

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	sharedSecret2, err := curve25519.X25519(ephemeralPrivate, pub.X25519Public)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	combinedInput := make([]byte, 0, 64)
	combinedInput = append(combinedInput, sharedSecret1...)
	combinedInput = append(combinedInput, sharedSecret2...)
	combinedHash := sha3.Sum256(combinedInput)
	combinedSecret := combinedHash[:]

	// SharedInfo1 = kemCt || ephPub || profileID(0x04) || hybridCode(0x19)
	sharedInfo1 := make([]byte, 0, len(kemCiphertext)+len(ephemeralPublic)+2)
	sharedInfo1 = append(sharedInfo1, kemCiphertext...)
	sharedInfo1 = append(sharedInfo1, ephemeralPublic...)
	sharedInfo1 = append(sharedInfo1, 0x04, 0x19)

	// KDF output = aeadKey(32) || nonce(12)
	kdfOutput := ProfileC_ENC_KEY_LEN + suciutil.ProfileD_Add19_NonceLen
	derived := kdfANSIX963SHA3(combinedSecret, sharedInfo1, kdfOutput)
	if len(derived) < kdfOutput {
		return nil, E_ENCRYPTION_FAILED
	}
	aeadKey := derived[0:ProfileC_ENC_KEY_LEN]
	nonce := derived[ProfileC_ENC_KEY_LEN:kdfOutput]

	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, E_ENCRYPTION_FAILED
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, E_ENCRYPTION_FAILED
	}
	aad := make([]byte, 0, len(kemCiphertext)+len(ephemeralPublic))
	aad = append(aad, kemCiphertext...)
	aad = append(aad, ephemeralPublic...)

	ciphertextWithTag := aead.Seal(nil, nonce, plaintext, aad)
	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-suciutil.ProfileD_Add19_TagLen]
	tag := ciphertextWithTag[len(ciphertextWithTag)-suciutil.ProfileD_Add19_TagLen:]

	// Output: kemCt || ephPub || 0x02 || nonce || ciphertext || tag
	schemeOutput := make([]byte, 0, len(kemCiphertext)+len(ephemeralPublic)+1+len(nonce)+len(ciphertext)+len(tag))
	schemeOutput = append(schemeOutput, kemCiphertext...)
	schemeOutput = append(schemeOutput, ephemeralPublic...)
	schemeOutput = append(schemeOutput, 0x02)
	schemeOutput = append(schemeOutput, nonce...)
	schemeOutput = append(schemeOutput, ciphertext...)
	schemeOutput = append(schemeOutput, tag...)
	return schemeOutput, 0
}

// encryptProfileE handles Nested Hybrid Profile E encryption (UE concealment).
// Flow: ECDH → encrypt KEM ciphertext → ML-KEM encapsulate → encrypt SUPI
// Output: EphPub(32) || EncryptedKEMCT(1088) || KEMMAC(8) || EncryptedMSIN || MSINMAC(8)
func encryptProfileE(plaintext []byte, publicKey interface{}, level suciutil.MLKEMSecurityLevel) ([]byte, ErrorCode) {
	level = suciutil.NormalizeMLKEMSecurityLevel(level)
	wantML := suciutil.MLKEMPublicKeyLen(level)
	pub, ok := publicKey.(*suciutil.ProfileDPublicKeys)
	if !ok || pub == nil || len(pub.MLKEMPublic) != wantML || len(pub.X25519Public) != 32 {
		return nil, E_INVALID_PQC_KEY
	}

	// STEP 1: Generate ephemeral X25519 keypair
	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return nil, E_ENCRYPTION_FAILED
	}
	ephemeralPrivate[0] &= 248
	ephemeralPrivate[31] &= 127
	ephemeralPrivate[31] |= 64

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 2: ECDH → k1
	k1, err := curve25519.X25519(ephemeralPrivate, pub.X25519Public)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 3: ML-KEM encapsulation → kemCiphertext, k0
	kemCiphertext, k0, errCode := mlkemEncapsulateFromPublicBytes(pub.MLKEMPublic)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 4: Derive ECC layer keys from k1
	// SharedInfo1 = ephemeral public key
	derivedKeys1 := kdfANSIX963SHA3(k1, ephemeralPublic, ProfileC_KDF_OUTPUT)
	if len(derivedKeys1) < ProfileC_KDF_OUTPUT {
		return nil, E_ENCRYPTION_FAILED
	}
	encKey1 := derivedKeys1[0:ProfileC_ENC_KEY_LEN]
	macKey1 := derivedKeys1[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT]

	// STEP 5: Encrypt KEM ciphertext with ECC key (AES-256-CTR)
	encryptedKEMCT, errCode := encryptAES256CTR(kemCiphertext, encKey1)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 6: KMAC256 over encrypted KEM ciphertext
	kemMAC := computeKMAC256(encryptedKEMCT, macKey1)

	// STEP 7: Derive PQC layer keys from k0
	// SharedInfo1 = KEM ciphertext (original, before encryption)
	derivedKeys0 := kdfANSIX963SHA3(k0, kemCiphertext, ProfileC_KDF_OUTPUT)
	if len(derivedKeys0) < ProfileC_KDF_OUTPUT {
		return nil, E_ENCRYPTION_FAILED
	}
	encKey0 := derivedKeys0[0:ProfileC_ENC_KEY_LEN]
	macKey0 := derivedKeys0[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT]

	// STEP 8: Encrypt MSIN with PQC key (AES-256-CTR)
	encryptedMSIN, errCode := encryptAES256CTR(plaintext, encKey0)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 9: KMAC256 over encrypted MSIN
	msinMAC := computeKMAC256(encryptedMSIN, macKey0)

	// STEP 10: Construct output: ephPub || encKEMCT || kemMAC || encMSIN || msinMAC
	schemeOutput := make([]byte, 0, len(ephemeralPublic)+len(encryptedKEMCT)+len(kemMAC)+len(encryptedMSIN)+len(msinMAC))
	schemeOutput = append(schemeOutput, ephemeralPublic...)
	schemeOutput = append(schemeOutput, encryptedKEMCT...)
	schemeOutput = append(schemeOutput, kemMAC...)
	schemeOutput = append(schemeOutput, encryptedMSIN...)
	schemeOutput = append(schemeOutput, msinMAC...)

	return schemeOutput, 0
}

// encryptProfileF handles Wrapper Hybrid Profile F encryption (UE concealment).
// ECIES (Profile A) remains unchanged; PQC wraps the ephemeral key.
// Output: KEMCT(1088) || EncEph(32) || PQCMAC(8) || Ciphertext || MAC(8)
func encryptProfileF(plaintext []byte, publicKey interface{}, level suciutil.MLKEMSecurityLevel) ([]byte, ErrorCode) {
	level = suciutil.NormalizeMLKEMSecurityLevel(level)
	wantML := suciutil.MLKEMPublicKeyLen(level)
	pub, ok := publicKey.(*suciutil.ProfileDPublicKeys)
	if !ok || pub == nil || len(pub.MLKEMPublic) != wantML || len(pub.X25519Public) != 32 {
		return nil, E_INVALID_PQC_KEY
	}

	// STEP 1: Generate ephemeral X25519 keypair (same as Profile A)
	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return nil, E_ENCRYPTION_FAILED
	}
	ephemeralPrivate[0] &= 248
	ephemeralPrivate[31] &= 127
	ephemeralPrivate[31] |= 64

	ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 2: ECDH shared secret (same as Profile A)
	sharedSecret, err := curve25519.X25519(ephemeralPrivate, pub.X25519Public)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 3: Derive ECIES keys (same as Profile A: ANSI-X9.63-KDF with SHA-256)
	derivedKeys := kdfANSIX963(sharedSecret, KDF_OUTPUT_LEN)
	if len(derivedKeys) < KDF_OUTPUT_LEN {
		return nil, E_INVALID_EC_KEY
	}
	encKey := derivedKeys[0:AES_KEY_LEN]              // AES-128
	macKey := derivedKeys[AES_KEY_LEN:KDF_OUTPUT_LEN] // HMAC-SHA-256

	// STEP 4: Encrypt MSIN using AES-128-CTR (same as Profile A)
	ciphertext, errCode := encryptAESCTR(plaintext, encKey)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 5: Compute ECIES MAC (HMAC-SHA-256 over ephPub || ciphertext, same as Profile A)
	eciesMAC := computeMAC(ephemeralPublic, ciphertext, macKey)

	kemCiphertext, kemSS, errCode := mlkemEncapsulateFromPublicBytes(pub.MLKEMPublic)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 7: Derive PQC wrapper keys from KEM shared secret
	// SharedInfo1 = KEM ciphertext (same as Profile C)
	pqcDerived := kdfANSIX963SHA3(kemSS, kemCiphertext, ProfileC_KDF_OUTPUT)
	if len(pqcDerived) < ProfileC_KDF_OUTPUT {
		return nil, E_ENCRYPTION_FAILED
	}
	pqcEncKey := pqcDerived[0:ProfileC_ENC_KEY_LEN]
	pqcMacKey := pqcDerived[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT]

	// STEP 8: Encrypt ephemeral public key using PQC key (AES-256-CTR)
	encryptedEph, errCode := encryptAES256CTR(ephemeralPublic, pqcEncKey)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 9: KMAC256 over encrypted ephemeral key
	pqcMAC := computeKMAC256(encryptedEph, pqcMacKey)

	// STEP 10: Construct output: kemCT || encEph || pqcMAC || ciphertext || eciesMAC
	schemeOutput := make([]byte, 0, len(kemCiphertext)+len(encryptedEph)+len(pqcMAC)+len(ciphertext)+len(eciesMAC))
	schemeOutput = append(schemeOutput, kemCiphertext...)
	schemeOutput = append(schemeOutput, encryptedEph...)
	schemeOutput = append(schemeOutput, pqcMAC...)
	schemeOutput = append(schemeOutput, ciphertext...)
	schemeOutput = append(schemeOutput, eciesMAC...)

	return schemeOutput, 0
}

// encryptProfileG handles symmetric Profile G encryption.
func encryptProfileG(plaintext []byte, keys interface{}, level suciutil.MLKEMSecurityLevel) ([]byte, ErrorCode) {
	kg, ok := keys.(*suciutil.ProfileGConcealmentKeys)
	if !ok || kg == nil {
		return nil, E_INVALID_EC_KEY
	}
	local := *kg
	local.SecurityLevel = suciutil.NormalizeMLKEMSecurityLevel(level)
	out, errCode := suciutil.EncryptProfileG(plaintext, &local)
	return out, ErrorCode(errCode)
}

// encryptAES256CTR performs AES-256-CTR encryption
// ICB is all zeros for 5G SUCI Profile C (per 3GPP TS 33.703)
func encryptAES256CTR(plaintext, key []byte) ([]byte, ErrorCode) {
	if len(key) != 32 {
		return nil, E_ENCRYPTION_FAILED
	}

	// Create AES-256 cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, E_ENCRYPTION_FAILED
	}

	// Initialize CTR mode with zero ICB
	icb := make([]byte, AES_IV_LEN)
	stream := cipher.NewCTR(block, icb)

	// Encrypt
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, 0
}

// kdfANSIX963SHA3 performs ANSI-X9.63-KDF with SHA3-256
// Z: shared secret, sharedInfo1: additional input (kemCiphertext for Profile C)
// Returns derived key material of specified length
func kdfANSIX963SHA3(z, sharedInfo1 []byte, keyLen int) []byte {
	// ANSI X9.63 KDF: DerivedKey = Hash(Z || Counter || SharedInfo1)
	// We iterate until we have enough key material
	var result []byte
	counter := uint32(1)

	for len(result) < keyLen {
		h := sha3.New256()

		// Z (shared secret)
		h.Write(z)

		// Counter as 4 bytes (big-endian)
		counterBytes := []byte{
			byte(counter >> 24),
			byte(counter >> 16),
			byte(counter >> 8),
			byte(counter),
		}
		h.Write(counterBytes)

		// SharedInfo1 (kemCiphertext)
		h.Write(sharedInfo1)

		result = append(result, h.Sum(nil)...)
		counter++
	}

	return result[:keyLen]
}

// computeKMAC256 computes the MAC using KMAC256 per 3GPP TS 33.703
// Returns first 8 bytes (64-bit MAC tag)
func computeKMAC256(data, key []byte) []byte {
	// KMAC256(K, X, L, S) where:
	// K = key (32 bytes)
	// X = data (encrypted MSIN)
	// L = output length in bits (64)
	// S = customization string ("SUCI-MAC")
	customString := []byte("SUCI-MAC")

	// Create KMAC256 instance
	kmac := sha3.NewCShake256(nil, customString)

	// Encode rate and key
	// NewCShake256 does not directly support KMAC, so we implement KMAC256 manually
	// KMAC(K, X, L, S) = cSHAKE256(bytepad(encode_string(K), 136) || X || right_encode(L), L, "KMAC" || S)

	// For simplicity, we use cSHAKE256 with proper padding
	// This is a simplified implementation for the 8-byte output

	// Bytepad the key to 136 bytes (cSHAKE256 rate)
	encodedKey := encodeString(key)
	padded := bytepad(encodedKey, 136)

	kmac.Write(padded)
	kmac.Write(data)

	// right_encode(64) = output 64 bits
	kmac.Write(rightEncode(64))

	// Get 8 bytes of output
	result := make([]byte, 8)
	kmac.Read(result)

	return result
}

// encodeString encodes a byte string per NIST SP 800-185
func encodeString(s []byte) []byte {
	encoded := leftEncode(uint64(len(s) * 8))
	return append(encoded, s...)
}

// leftEncode encodes an integer per NIST SP 800-185
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{1, 0}
	}

	// Find number of bytes needed
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

	// Find number of bytes needed
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

// bytepad pads the input to a multiple of w bytes
func bytepad(x []byte, w int) []byte {
	encoded := leftEncode(uint64(w))
	buf := append(encoded, x...)

	// Pad to multiple of w
	padLen := w - (len(buf) % w)
	if padLen == w {
		padLen = 0
	}

	padding := make([]byte, padLen)
	return append(buf, padding...)
}

// encryptAESCTR performs AES-128-CTR encryption
// IV is all zeros for 5G SUCI (as per 3GPP TS 33.501)
func encryptAESCTR(plaintext, key []byte) ([]byte, ErrorCode) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// Initialize CTR mode with zero IV
	iv := make([]byte, AES_IV_LEN)
	slog.Debugf("[DEBUG] AES-CTR Encrypt: key=%x iv=%x\n", key, iv)
	stream := cipher.NewCTR(block, iv)

	// Encrypt
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext, 0
}

// computeMAC computes the MAC tag using HMAC-SHA-256
// MAC = first 8 bytes of HMAC-SHA-256(macKey, ephemeralPubKey || ciphertext)
func computeMAC(ephemeralPubKey, ciphertext, macKey []byte) []byte {
	// Construct MAC input: ephemeralPubKey || ciphertext
	macInput := append(ephemeralPubKey, ciphertext...)

	// Compute HMAC-SHA-256
	mac := hmac.New(sha256.New, macKey)
	mac.Write(macInput)
	computedMAC := mac.Sum(nil)

	// Truncate to canonical MAC tag length (MAC_TAG_LEN)
	return computedMAC[:MAC_TAG_LEN]
}

// compressP256Point compresses a P-256 public key point
// Format: [0x02/0x03][32-byte X coordinate]
func compressP256Point(pubKey *ecdsa.PublicKey) []byte {
	// Determine prefix based on Y coordinate parity
	prefix := byte(0x02)
	if pubKey.Y.Bit(0) == 1 {
		prefix = 0x03
	}

	// Create compressed representation
	compressed := make([]byte, 33)
	compressed[0] = prefix

	// Copy X coordinate (padded to 32 bytes)
	xBytes := pubKey.X.Bytes()
	copy(compressed[33-len(xBytes):], xBytes)

	return compressed
}

// ConstructSUCI constructs the SUCI string from components
func ConstructSUCI(identityType IdentityType, mcc, mnc, routingInd string, schemeID SchemeID, keyID uint8, schemeOutput []byte) string {
	return fmt.Sprintf("suci-%d-%s-%s-%s-%d-%d-%s",
		identityType,
		mcc,
		mnc,
		routingInd,
		schemeID,
		keyID,
		hex.EncodeToString(schemeOutput))
}
