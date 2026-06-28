package suci

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"math/big"

	"filippo.io/edwards25519/field"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

// DecryptECIES performs ECIES decryption for Profile A or Profile B
// Returns the decrypted plaintext (MSIN) or an error code
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
// Returns the decrypted plaintext (MSIN) or an error code
func DecryptPQC(pqcCryptogram *PQCCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	return decryptProfileC(pqcCryptogram, privateKey)
}

// DecryptHybrid performs hybrid decryption for Profile D (ML-KEM-768 + X25519)
// Returns the decrypted plaintext (MSIN) or an error code
func DecryptHybrid(hybridCryptogram *HybridCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	switch hybridCryptogram.Variant {
	case suciutil.ProfileDVariantAdd17:
		return decryptProfileDAdd17(hybridCryptogram, privateKey)
	case suciutil.ProfileDVariantAdd19:
		return decryptProfileDAdd19(hybridCryptogram, privateKey)
	default:
		return decryptProfileD(hybridCryptogram, privateKey)
	}
}

// DecryptNestedHybrid performs Profile E (Nested Hybrid) decryption
// Returns the decrypted plaintext (MSIN) or an error code
func DecryptNestedHybrid(cryptogram *ProfileECryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	return decryptProfileE(cryptogram, privateKey)
}

// DecryptWrapperHybrid performs Profile F (Wrapper Hybrid) decryption
// Returns the decrypted plaintext (MSIN) or an error code
func DecryptWrapperHybrid(cryptogram *ProfileFCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	return decryptProfileF(cryptogram, privateKey)
}

// DecryptSymmetric performs Profile G decryption.
func DecryptSymmetric(cryptogram *ProfileGCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	return decryptProfileG(cryptogram, privateKey)
}

// decryptProfileA handles ECIES Profile A (Curve25519/X25519)
func decryptProfileA(cryptogram *Cryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	// Validate private key type
	privKeyBytes, ok := privateKey.([]byte)
	if !ok || len(privKeyBytes) != 32 {
		return nil, E_INVALID_EC_KEY
	}

	// Validate ephemeral public key length
	if len(cryptogram.EphemeralPublicKey) != ProfileA_PubKeyLen {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 1: Perform ECDH to compute shared secret
	sharedSecret, err := curve25519.X25519(privKeyBytes, cryptogram.EphemeralPublicKey)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 2: Derive keys using KDF (ANSI-X9.63-KDF with SHA-256)
	derivedKeys := kdfANSIX963(sharedSecret, KDF_OUTPUT_LEN)
	if len(derivedKeys) < KDF_OUTPUT_LEN {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 3: Split derived keys into encryption key and MAC key
	encKey := derivedKeys[0:AES_KEY_LEN]              // First 16 bytes for AES-128
	macKey := derivedKeys[AES_KEY_LEN:KDF_OUTPUT_LEN] // Next 32 bytes for HMAC-SHA-256

	// STEP 4: Verify MAC
	if errCode := verifyMAC(cryptogram, macKey); errCode != 0 {
		return nil, errCode
	}

	// STEP 5: Decrypt ciphertext using AES-128-CTR
	plaintext, errCode := decryptAESCTR(cryptogram.Ciphertext, encKey)
	if errCode != 0 {
		return nil, errCode
	}

	return plaintext, 0
}

// decryptProfileB handles ECIES Profile B (secp256r1/NIST P-256)
func decryptProfileB(cryptogram *Cryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	// Validate private key type
	privKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, E_INVALID_EC_KEY
	}

	// Validate that the key is for secp256r1
	if privKey.Curve != elliptic.P256() {
		return nil, E_CURVE_MISMATCH
	}

	// Validate ephemeral public key length (compressed format)
	if len(cryptogram.EphemeralPublicKey) != ProfileB_PubKeyLen {
		return nil, E_INVALID_EC_KEY
	}

	// Decompress the ephemeral public key
	ephemeralPubKey, err := decompressP256Point(cryptogram.EphemeralPublicKey)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 1: Perform ECDH to compute shared secret
	// Shared secret = x-coordinate of (ephemeralPubKey * privateKey)
	sharedX, _ := privKey.Curve.ScalarMult(ephemeralPubKey.X, ephemeralPubKey.Y, privKey.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Ensure shared secret is exactly 32 bytes (pad with leading zeros if needed)
	if len(sharedSecret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(sharedSecret):], sharedSecret)
		sharedSecret = padded
	}

	// STEP 2: Derive keys using KDF (ANSI-X9.63-KDF with SHA-256)
	derivedKeys := kdfANSIX963(sharedSecret, KDF_OUTPUT_LEN)
	if len(derivedKeys) < KDF_OUTPUT_LEN {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 3: Split derived keys into encryption key and MAC key
	encKey := derivedKeys[0:AES_KEY_LEN]              // First 16 bytes for AES-128
	macKey := derivedKeys[AES_KEY_LEN:KDF_OUTPUT_LEN] // Next 32 bytes for HMAC-SHA-256

	// STEP 4: Verify MAC
	if errCode := verifyMAC(cryptogram, macKey); errCode != 0 {
		return nil, errCode
	}

	// STEP 5: Decrypt ciphertext using AES-128-CTR
	plaintext, errCode := decryptAESCTR(cryptogram.Ciphertext, encKey)
	if errCode != 0 {
		return nil, errCode
	}

	return plaintext, 0
}

// decryptProfileC handles PQC Profile C (ML-KEM-768 or ML-KEM-1024).
func decryptProfileC(pqcCryptogram *PQCCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	privKeyBytes, ok := privateKey.([]byte)
	if !ok {
		return nil, E_INVALID_PQC_KEY
	}
	switch len(pqcCryptogram.KEMCiphertext) {
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
	case suciutil.MLKEM1024_CIPHERTEXT_LEN:
		if len(privKeyBytes) != suciutil.MLKEM1024_PRIVATE_KEY_LEN {
			return nil, E_INVALID_PQC_KEY
		}
		var privKey mlkem1024.PrivateKey
		if err := privKey.Unpack(privKeyBytes); err != nil {
			return nil, E_INVALID_PQC_KEY
		}
		sharedSecret := make([]byte, suciutil.MLKEM1024_SHARED_SECRET)
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
	return decryptAES256CTR(pqcCryptogram.Ciphertext, encKey)
}

func mlkemDecapsulateSuci(mlkemPriv []byte, kemCiphertext []byte) ([]byte, ErrorCode) {
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
	case suciutil.MLKEM1024_CIPHERTEXT_LEN:
		if len(mlkemPriv) != suciutil.MLKEM1024_PRIVATE_KEY_LEN {
			return nil, E_INVALID_PQC_KEY
		}
		var pk mlkem1024.PrivateKey
		if err := pk.Unpack(mlkemPriv); err != nil {
			return nil, E_INVALID_PQC_KEY
		}
		ss := make([]byte, suciutil.MLKEM1024_SHARED_SECRET)
		pk.DecapsulateTo(ss, kemCiphertext)
		return ss, 0
	default:
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
}

// decryptProfileD handles Hybrid Profile D (ML-KEM + X25519).
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

	sharedSecret1, errCode := mlkemDecapsulateSuci(privKeys.MLKEMPrivate, hybridCryptogram.KEMCiphertext)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 2: X25519 ECDH to get sharedSecret2
	sharedSecret2, err := curve25519.X25519(privKeys.X25519Private, hybridCryptogram.EphemeralPublicKey)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 3: Combine shared secrets using SHA3-256
	// CombinedSecret = SHA3-256(sharedSecret1 || sharedSecret2)
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

	// STEP 5: Split derived keys into encryption key and MAC key
	encKey := derivedKeys[0:ProfileC_ENC_KEY_LEN]                   // First 32 bytes for AES-256
	macKey := derivedKeys[ProfileC_ENC_KEY_LEN:ProfileC_KDF_OUTPUT] // Next 32 bytes for KMAC256

	// STEP 6: Verify MAC using KMAC256
	if errCode := verifyKMAC256(hybridCryptogram.Ciphertext, hybridCryptogram.MACTag, macKey); errCode != 0 {
		return nil, errCode
	}

	// STEP 7: Decrypt ciphertext using AES-256-CTR
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
	if len(hybridCryptogram.Nonce) != suciutil.ProfileD_Add17_NonceLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
	if len(hybridCryptogram.EphemeralPublicKey) != ProfileD_EphPubKeyLen {
		return nil, E_INVALID_EC_KEY
	}

	sharedSecret1, errCode := mlkemDecapsulateSuci(privKeys.MLKEMPrivate, hybridCryptogram.KEMCiphertext)
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
	sharedInfo1 := make([]byte, 0, len(hybridCryptogram.KEMCiphertext)+len(hybridCryptogram.EphemeralPublicKey)+suciutil.ProfileD_Add17_NonceLen+2)
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
	if len(hybridCryptogram.Nonce) != suciutil.ProfileD_Add19_NonceLen || len(hybridCryptogram.MACTag) != suciutil.ProfileD_Add19_TagLen {
		return nil, E_SCHEME_OUTPUT_TOO_SHORT
	}
	if len(hybridCryptogram.EphemeralPublicKey) != ProfileD_EphPubKeyLen {
		return nil, E_INVALID_EC_KEY
	}

	sharedSecret1, errCode := mlkemDecapsulateSuci(privKeys.MLKEMPrivate, hybridCryptogram.KEMCiphertext)
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

	kdfOutput := ProfileC_ENC_KEY_LEN + suciutil.ProfileD_Add19_NonceLen
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

// decryptProfileE handles Nested Hybrid Profile E (ML-KEM-768 + X25519) decryption
// Flow: ECDH → decrypt KEM ciphertext → ML-KEM decapsulate → decrypt MSIN
func decryptProfileE(cryptogram *ProfileECryptogram, privateKey interface{}) ([]byte, ErrorCode) {
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

	// STEP 2: Derive ECC layer keys from k1 (SharedInfo1 = ephemeral public key)
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

	k0, errCode := mlkemDecapsulateSuci(privKeys.MLKEMPrivate, kemCT)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 6: Derive PQC layer keys from k0 (SharedInfo1 = original KEM ciphertext)
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

// decryptProfileF handles Wrapper Hybrid Profile F (ML-KEM-768 + X25519) decryption
// Flow: ML-KEM decapsulate → decrypt ephemeral key → ECDH → verify MAC → decrypt MSIN
func decryptProfileF(cryptogram *ProfileFCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	privKeys, ok := privateKey.(*ProfileDPrivateKeys)
	if !ok || privKeys == nil {
		return nil, E_INVALID_PQC_KEY
	}
	if len(privKeys.X25519Private) != 32 {
		return nil, E_INVALID_EC_KEY
	}

	kemSS, errCode := mlkemDecapsulateSuci(privKeys.MLKEMPrivate, cryptogram.KEMCiphertext)
	if errCode != 0 {
		return nil, errCode
	}

	// STEP 2: Derive PQC wrapper keys from KEM shared secret
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

	// STEP 5: ECDH (same as Profile A)
	sharedSecret, err := curve25519.X25519(privKeys.X25519Private, ephPub)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// STEP 6: Derive ECIES keys (same as Profile A)
	derivedKeys := kdfANSIX963(sharedSecret, KDF_OUTPUT_LEN)
	if len(derivedKeys) < KDF_OUTPUT_LEN {
		return nil, E_INVALID_EC_KEY
	}
	encKey := derivedKeys[0:AES_KEY_LEN]
	macKey := derivedKeys[AES_KEY_LEN:KDF_OUTPUT_LEN]

	// STEP 7: Verify ECIES MAC (HMAC-SHA-256 over ephPub || ciphertext)
	eciesCg := &Cryptogram{
		EphemeralPublicKey: ephPub,
		Ciphertext:         cryptogram.Ciphertext,
		MACTag:             cryptogram.MACTag,
	}
	if errCode := verifyMAC(eciesCg, macKey); errCode != 0 {
		return nil, errCode
	}

	// STEP 8: Decrypt MSIN using AES-128-CTR
	plaintext, errCode := decryptAESCTR(cryptogram.Ciphertext, encKey)
	if errCode != 0 {
		return nil, errCode
	}

	return plaintext, 0
}

// decryptProfileG handles symmetric Profile G decryption.
func decryptProfileG(cryptogram *ProfileGCryptogram, privateKey interface{}) ([]byte, ErrorCode) {
	kg, ok := privateKey.(*suciutil.ProfileGKeyMaterial)
	if !ok || kg == nil {
		return nil, E_INVALID_EC_KEY
	}
	out, errCode := suciutil.DecryptProfileG(&suciutil.ProfileGCryptogram{
		R:             cryptogram.R,
		KeyCipherText: cryptogram.KeyCipherText,
		MACkey:        cryptogram.MACkey,
		Ciphertext:    cryptogram.Ciphertext,
		MACmsin:       cryptogram.MACmsin,
	}, kg)
	return out, ErrorCode(errCode)
}

// kdfANSIX963SHA3Decrypt performs ANSI-X9.63-KDF with SHA3-256 for decryption
func kdfANSIX963SHA3Decrypt(z, sharedInfo1 []byte, keyLen int) []byte {
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

// verifyKMAC256 verifies the MAC using KMAC256 per 3GPP TS 33.703
func verifyKMAC256(data, expectedMAC, key []byte) ErrorCode {
	customString := []byte("SUCI-MAC")

	// Create KMAC256 instance using cSHAKE256
	kmac := sha3.NewCShake256(nil, customString)

	// Bytepad the key to 136 bytes (cSHAKE256 rate)
	encodedKey := encodeStringDecrypt(key)
	padded := bytepadDecrypt(encodedKey, 136)

	kmac.Write(padded)
	kmac.Write(data)
	kmac.Write(rightEncodeDecrypt(64))

	// Get 8 bytes of output
	computedMAC := make([]byte, 8)
	kmac.Read(computedMAC)

	// Constant-time comparison
	if subtle.ConstantTimeCompare(computedMAC, expectedMAC) != 1 {
		return E_TAG_MISMATCH
	}

	return 0
}

// decryptAES256CTR performs AES-256-CTR decryption
func decryptAES256CTR(ciphertext, key []byte) ([]byte, ErrorCode) {
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

	// Decrypt
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, 0
}

// Helper functions for KMAC256 (decryption side)
func encodeStringDecrypt(s []byte) []byte {
	encoded := leftEncodeDecrypt(uint64(len(s) * 8))
	return append(encoded, s...)
}

func leftEncodeDecrypt(x uint64) []byte {
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

func rightEncodeDecrypt(x uint64) []byte {
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

func bytepadDecrypt(x []byte, w int) []byte {
	encoded := leftEncodeDecrypt(uint64(w))
	buf := append(encoded, x...)
	padLen := w - (len(buf) % w)
	if padLen == w {
		padLen = 0
	}
	padding := make([]byte, padLen)
	return append(buf, padding...)
}

// kdfANSIX963 implements ANSI-X9.63-KDF with SHA-256
// Used to derive encryption and MAC keys from the shared secret
func kdfANSIX963(sharedSecret []byte, keyLen int) []byte {
	var counter uint32 = 1
	var derivedKey []byte
	hash := sha256.New()

	for len(derivedKey) < keyLen {
		hash.Reset()
		hash.Write(sharedSecret)

		// Write counter as 4-byte big-endian
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		hash.Write(counterBytes)

		derivedKey = append(derivedKey, hash.Sum(nil)...)
		counter++
	}

	return derivedKey[:keyLen]
}

// verifyMAC verifies the MAC tag using HMAC-SHA-256
// MAC = first 8 bytes of HMAC-SHA-256(macKey, ephemeralPubKey || ciphertext)
func verifyMAC(cryptogram *Cryptogram, macKey []byte) ErrorCode {
	// Construct MAC input: ephemeralPubKey || ciphertext
	macInput := append(cryptogram.EphemeralPublicKey, cryptogram.Ciphertext...)

	// Compute HMAC-SHA-256
	mac := hmac.New(sha256.New, macKey)
	mac.Write(macInput)
	computedMAC := mac.Sum(nil)

	// Compare first 8 bytes
	expectedMAC := computedMAC[:MAC_TAG_LEN]
	if !hmac.Equal(expectedMAC, cryptogram.MACTag) {
		return E_TAG_MISMATCH
	}

	return 0
}

// decryptAESCTR performs AES-128-CTR decryption
// IV is all zeros for 5G SUCI (as per 3GPP TS 33.501)
func decryptAESCTR(ciphertext, key []byte) ([]byte, ErrorCode) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, E_INVALID_EC_KEY
	}

	// Initialize CTR mode with zero IV
	iv := make([]byte, AES_IV_LEN)
	stream := cipher.NewCTR(block, iv)

	// Decrypt
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, 0
}

// decompressP256Point decompresses a compressed secp256r1 point
// Format: [0x02/0x03][32-byte X coordinate]
func decompressP256Point(compressed []byte) (*ecdsa.PublicKey, error) {
	if len(compressed) != 33 {
		return nil, E_INVALID_EC_KEY
	}

	curve := elliptic.P256()
	x := new(big.Int).SetBytes(compressed[1:33])

	// Compute y^2 = x^3 - 3x + b (mod p)
	// For P-256: y^2 = x^3 - 3x + b
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Mul(x, big.NewInt(3))
	x3.Sub(x3, threeX)
	x3.Add(x3, curve.Params().B)
	x3.Mod(x3, curve.Params().P)

	// Compute y = sqrt(y^2) mod p
	y := new(big.Int).ModSqrt(x3, curve.Params().P)
	if y == nil {
		return nil, E_INVALID_EC_KEY
	}

	// Choose correct y based on compressed point format
	// 0x02 = even y, 0x03 = odd y
	yIsOdd := y.Bit(0) == 1
	compressedYIsOdd := compressed[0] == 0x03

	if yIsOdd != compressedYIsOdd {
		y.Sub(curve.Params().P, y)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// Helper function to convert field element to bytes (for Curve25519)
func fieldElementToBytes(fe *field.Element) []byte {
	return fe.Bytes()
}
