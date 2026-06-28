package suci

import "github.com/harishmurkal/suci-supi-tool/pkg/suciutil"

// Compatibility wrappers forwarding to suciutil implementations and converting types.

func ParseSUCI(s string) (*ParsedSUCI, ErrorCode) {
	p, err := suciutil.ParseSUCI(s)
	if err != 0 {
		return nil, ErrorCode(err)
	}
	return &ParsedSUCI{
		Type:         IdentityType(p.Type),
		MCC:          p.MCC,
		MNC:          p.MNC,
		RoutingInd:   p.RoutingInd,
		SchemeID:     SchemeID(p.SchemeID),
		KeyID:        p.KeyID,
		SchemeOutput: p.SchemeOutput,
	}, 0
}

func ParseCryptogram(schemeOutput []byte, scheme SchemeID) (*Cryptogram, ErrorCode) {
	cg, err := suciutil.ParseCryptogram(schemeOutput, suciutil.SchemeID(scheme))
	if err != 0 {
		return nil, ErrorCode(err)
	}
	return &Cryptogram{
		EphemeralPublicKey: cg.EphemeralPublicKey,
		Ciphertext:         cg.Ciphertext,
		MACTag:             cg.MACTag,
	}, 0
}

func ParsePQCCryptogram(cryptogram []byte) (*PQCCryptogram, ErrorCode) {
	pqc, err := suciutil.ParsePQCCryptogram(cryptogram)
	if err != 0 {
		return nil, ErrorCode(err)
	}
	return &PQCCryptogram{
		KEMCiphertext: pqc.KEMCiphertext,
		Ciphertext:    pqc.Ciphertext,
		MACTag:        pqc.MACTag,
	}, 0
}

func ParseProfileDCryptogram(cryptogram []byte) (*HybridCryptogram, ErrorCode) {
	hc, err := suciutil.ParseProfileDCryptogram(cryptogram)
	if err != 0 {
		return nil, ErrorCode(err)
	}
	return &HybridCryptogram{
		KEMCiphertext:      hc.KEMCiphertext,
		EphemeralPublicKey: hc.EphemeralPublicKey,
		Variant:            hc.Variant,
		Nonce:              hc.Nonce,
		Ciphertext:         hc.Ciphertext,
		MACTag:             hc.MACTag,
	}, 0
}

func ParseProfileECryptogram(cryptogram []byte) (*ProfileECryptogram, ErrorCode) {
	ec, err := suciutil.ParseProfileECryptogram(cryptogram)
	if err != 0 {
		return nil, ErrorCode(err)
	}
	return &ProfileECryptogram{
		EphemeralPublicKey: ec.EphemeralPublicKey,
		EncryptedKEMCT:     ec.EncryptedKEMCT,
		KEMMACTag:          ec.KEMMACTag,
		Ciphertext:         ec.Ciphertext,
		MACTag:             ec.MACTag,
	}, 0
}

func ParseProfileFCryptogram(cryptogram []byte) (*ProfileFCryptogram, ErrorCode) {
	fc, err := suciutil.ParseProfileFCryptogram(cryptogram)
	if err != 0 {
		return nil, ErrorCode(err)
	}
	return &ProfileFCryptogram{
		KEMCiphertext:   fc.KEMCiphertext,
		EncryptedEphKey: fc.EncryptedEphKey,
		PQCMACTag:       fc.PQCMACTag,
		Ciphertext:      fc.Ciphertext,
		MACTag:          fc.MACTag,
	}, 0
}

func ParseProfileGCryptogram(cryptogram []byte) (*ProfileGCryptogram, ErrorCode) {
	gc, err := suciutil.ParseProfileGCryptogram(cryptogram)
	if err != 0 {
		return nil, ErrorCode(err)
	}
	return &ProfileGCryptogram{
		R:             gc.R,
		KeyCipherText: gc.KeyCipherText,
		MACkey:        gc.MACkey,
		Ciphertext:    gc.Ciphertext,
		MACmsin:       gc.MACmsin,
	}, 0
}

func ParsePQCCryptogramForLevel(cryptogram []byte, level suciutil.MLKEMSecurityLevel) (*PQCCryptogram, ErrorCode) {
	pqc, err := suciutil.ParsePQCCryptogramForLevel(cryptogram, level)
	if err != 0 {
		return nil, ErrorCode(err)
	}
	return &PQCCryptogram{
		KEMCiphertext: pqc.KEMCiphertext,
		Ciphertext:    pqc.Ciphertext,
		MACTag:        pqc.MACTag,
	}, 0
}

func ParseProfileDCryptogramForLevel(cryptogram []byte, level suciutil.MLKEMSecurityLevel) (*HybridCryptogram, ErrorCode) {
	hc, err := suciutil.ParseProfileDCryptogramForLevel(cryptogram, level)
	if err != 0 {
		return nil, ErrorCode(err)
	}
	return &HybridCryptogram{
		KEMCiphertext:      hc.KEMCiphertext,
		EphemeralPublicKey: hc.EphemeralPublicKey,
		Variant:            hc.Variant,
		Nonce:              hc.Nonce,
		Ciphertext:         hc.Ciphertext,
		MACTag:             hc.MACTag,
	}, 0
}

func ParseProfileECryptogramForLevel(cryptogram []byte, level suciutil.MLKEMSecurityLevel) (*ProfileECryptogram, ErrorCode) {
	ec, err := suciutil.ParseProfileECryptogramForLevel(cryptogram, level)
	if err != 0 {
		return nil, ErrorCode(err)
	}
	return &ProfileECryptogram{
		EphemeralPublicKey: ec.EphemeralPublicKey,
		EncryptedKEMCT:     ec.EncryptedKEMCT,
		KEMMACTag:          ec.KEMMACTag,
		Ciphertext:         ec.Ciphertext,
		MACTag:             ec.MACTag,
	}, 0
}

func ParseProfileFCryptogramForLevel(cryptogram []byte, level suciutil.MLKEMSecurityLevel) (*ProfileFCryptogram, ErrorCode) {
	fc, err := suciutil.ParseProfileFCryptogramForLevel(cryptogram, level)
	if err != 0 {
		return nil, ErrorCode(err)
	}
	return &ProfileFCryptogram{
		KEMCiphertext:   fc.KEMCiphertext,
		EncryptedEphKey: fc.EncryptedEphKey,
		PQCMACTag:       fc.PQCMACTag,
		Ciphertext:      fc.Ciphertext,
		MACTag:          fc.MACTag,
	}, 0
}

func ParseProfileGCryptogramForLevel(cryptogram []byte, level suciutil.MLKEMSecurityLevel) (*ProfileGCryptogram, ErrorCode) {
	gc, err := suciutil.ParseProfileGCryptogramForLevel(cryptogram, level)
	if err != 0 {
		return nil, ErrorCode(err)
	}
	return &ProfileGCryptogram{
		R:             gc.R,
		KeyCipherText: gc.KeyCipherText,
		MACkey:        gc.MACkey,
		Ciphertext:    gc.Ciphertext,
		MACmsin:       gc.MACmsin,
	}, 0
}

// EncodeMSIN_TBCD encodes MSIN digits as 3GPP TBCD (Telephony BCD).
func EncodeMSIN_TBCD(msin string) ([]byte, ErrorCode) {
	b, err := suciutil.EncodeMSIN_TBCDCode(msin)
	return b, ErrorCode(err)
}

// DecodeMSIN_TBCD decodes TBCD bytes to MSIN decimal digits.
func DecodeMSIN_TBCD(msinBytes []byte) (string, ErrorCode) {
	s, err := suciutil.DecodeMSIN_TBCDCode(msinBytes)
	return s, ErrorCode(err)
}

// ConstructSUPI wraps suciutil.ConstructSUPI
func ConstructSUPI(identityType IdentityType, mcc, mnc, msin string) (string, ErrorCode) {
	s, err := suciutil.ConstructSUPI(suciutil.IdentityType(identityType), mcc, mnc, msin)
	return s, ErrorCode(err)
}

// ValidateKeySchemeMatch wraps suciutil.ValidateKeySchemeMatch
func ValidateKeySchemeMatch(privateKey interface{}, scheme SchemeID) ErrorCode {
	return ErrorCode(suciutil.ValidateKeySchemeMatch(privateKey, suciutil.SchemeID(scheme)))
}

// Alias types from suciutil for tests that expect them in this package
type ConcealmentResult = suciutil.ConcealmentResult

// Alias Profile D types from suciutil for consistent type usage
type ProfileDPrivateKeys = suciutil.ProfileDPrivateKeys
type ProfileDPublicKeys = suciutil.ProfileDPublicKeys

// Profile E/F use the same key structure as Profile D
type ProfileEPrivateKeys = suciutil.ProfileDPrivateKeys
type ProfileEPublicKeys = suciutil.ProfileDPublicKeys
type ProfileFPrivateKeys = suciutil.ProfileDPrivateKeys
type ProfileFPublicKeys = suciutil.ProfileDPublicKeys
type ProfileGConcealmentKeys = suciutil.ProfileGConcealmentKeys
type ProfileGKeyMaterial = suciutil.ProfileGKeyMaterial
