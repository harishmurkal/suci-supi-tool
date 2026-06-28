package suci

import (
	"encoding/hex"
	"strings"

	"github.com/harishmurkal/suci-supi-tool/pkg/keys"
	"github.com/harishmurkal/suci-supi-tool/pkg/slog"
	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
)

// Converter orchestrates the SUCI to SUPI conversion process
type Converter struct {
	keyStore keys.KeyStore
}

// NewConverter creates a new SUCI to SUPI converter
func NewConverter(keyStore keys.KeyStore) *Converter {
	return &Converter{
		keyStore: keyStore,
	}
}

// DeconcealConfig optional settings for SUCI→SUPI conversion.
// MLKEMSecurityLevel unset (0): infer ML-KEM parameter set from the loaded HN private key (profiles C–F).
type DeconcealConfig struct {
	MLKEMSecurityLevel suciutil.MLKEMSecurityLevel
}

// ConvertSUCItoSUPI converts a SUCI string to SUPI (default deconceal: ML-KEM size inferred from key material).
func (c *Converter) ConvertSUCItoSUPI(suciStr string) suciutil.ConversionResult {
	return c.ConvertSUCItoSUPIWithConfig(suciStr, DeconcealConfig{})
}

// ConvertSUCItoSUPIWithConfig converts SUCI to SUPI with optional explicit ML-KEM security level for parsing.
func (c *Converter) ConvertSUCItoSUPIWithConfig(suciStr string, cfg DeconcealConfig) suciutil.ConversionResult {
	// STEP 1: Parse SUCI string
	parsed, errCode := suciutil.ParseSUCI(suciStr)
	if errCode != 0 {
		return suciutil.ConversionResult{Error: (*suciutil.ErrorCode)(&errCode)}
	}

	// Determine MSIN based on scheme
	var msin string
	var err suciutil.ErrorCode

	if parsed.SchemeID == suciutil.SchemeNullScheme {
		// NULL-SCHEME: Scheme output is plaintext MSIN (no decryption needed)
		msin, err = c.handleNullScheme(parsed)
	} else {
		// ECIES schemes: Decrypt the scheme output
		msin, err = c.handleEncryptedScheme(parsed, cfg)
	}

	if err != 0 {
		return suciutil.ConversionResult{Error: (*suciutil.ErrorCode)(&err)}
	}

	// STEP 8: Construct SUPI from MCC, MNC, and decrypted MSIN
	supi, errCode := suciutil.ConstructSUPI(suciutil.IdentityType(parsed.Type), parsed.MCC, parsed.MNC, msin)
	if errCode != 0 {
		return suciutil.ConversionResult{Error: (*suciutil.ErrorCode)(&errCode)}
	}

	return suciutil.ConversionResult{SUPI: supi}
}

// handleNullScheme processes NULL-SCHEME (no encryption)
func (c *Converter) handleNullScheme(parsed *suciutil.ParsedSUCI) (string, suciutil.ErrorCode) {
	// For NULL-SCHEME, the scheme output is plaintext MSIN encoded as 3GPP TBCD.
	msin, errCode := suciutil.DecodeMSIN_TBCDCode(parsed.SchemeOutput)
	if errCode != 0 {
		return "", errCode
	}
	return msin, 0
}

func resolveDeconcealMLKEMLevel(scheme suciutil.SchemeID, privateKey interface{}, explicit suciutil.MLKEMSecurityLevel) (suciutil.MLKEMSecurityLevel, suciutil.ErrorCode) {
	if !suciutil.SchemePQCUsesMLKEM(scheme) {
		return suciutil.MLKEMSecurityLevel3, 0
	}
	inferred, err := suciutil.InferMLKEMSecurityLevelFromPrivateKey(privateKey, scheme)
	if err != nil {
		return suciutil.MLKEMSecurityLevel3, suciutil.E_INVALID_PQC_KEY
	}
	if explicit == suciutil.MLKEMSecurityUnset {
		return inferred, 0
	}
	want := suciutil.NormalizeMLKEMSecurityLevel(explicit)
	if want != inferred {
		return suciutil.MLKEMSecurityLevel3, suciutil.E_INVALID_PQC_KEY
	}
	return want, 0
}

// handleEncryptedScheme processes ECIES encrypted schemes (Profile A, B) and PQC (Profile C)
func (c *Converter) handleEncryptedScheme(parsed *suciutil.ParsedSUCI, cfg DeconcealConfig) (string, suciutil.ErrorCode) {
	// STEP 3: Validate and retrieve private key from key store
	// Convert SchemeID to keys.SchemeID
	keyScheme := suciutil.SchemeID(parsed.SchemeID)
	privateKey, err := c.keyStore.GetPrivateKey(parsed.KeyID, keyScheme)
	if err != nil {
		// Map errors to error codes
		if err == keys.ErrKeyNotFound {
			return "", suciutil.E_UNKNOWN_KEY_ID
		}
		if err == keys.ErrInvalidScheme {
			return "", suciutil.E_INVALID_SCHEME_ID
		}
		if err == keys.ErrInvalidKey {
			return "", suciutil.E_INVALID_EC_KEY
		}
		return "", suciutil.E_UNKNOWN_KEY_ID
	}

	// STEP 4: Validate that key type matches the scheme
	if errCode := suciutil.ValidateKeySchemeMatch(privateKey, parsed.SchemeID); errCode != 0 {
		return "", errCode
	}

	var plaintextMSIN []byte
	var errCode suciutil.ErrorCode

	mlkemLevel, errCode := resolveDeconcealMLKEMLevel(parsed.SchemeID, privateKey, cfg.MLKEMSecurityLevel)
	if errCode != 0 {
		return "", errCode
	}

	if parsed.SchemeID == suciutil.SchemeProfileC {
		pqcCryptogram, errCode := suciutil.ParsePQCCryptogramForLevel(parsed.SchemeOutput, mlkemLevel)
		if errCode != 0 {
			return "", errCode
		}
		plaintextMSIN, errCode = suciutil.DecryptPQC(pqcCryptogram, privateKey)
		if errCode != 0 {
			return "", errCode
		}
	} else if parsed.SchemeID == suciutil.SchemeProfileD {
		hybridCryptogram, errCode := suciutil.ParseProfileDCryptogramForLevel(parsed.SchemeOutput, mlkemLevel)
		if errCode != 0 {
			return "", errCode
		}
		plaintextMSIN, errCode = suciutil.DecryptHybrid(hybridCryptogram, privateKey)
		if errCode != 0 {
			return "", errCode
		}
	} else if parsed.SchemeID == suciutil.SchemeProfileE {
		profileECryptogram, errCode := suciutil.ParseProfileECryptogramForLevel(parsed.SchemeOutput, mlkemLevel)
		if errCode != 0 {
			return "", errCode
		}
		plaintextMSIN, errCode = suciutil.DecryptNestedHybrid(profileECryptogram, privateKey)
		if errCode != 0 {
			return "", errCode
		}
	} else if parsed.SchemeID == suciutil.SchemeProfileF {
		profileFCryptogram, errCode := suciutil.ParseProfileFCryptogramForLevel(parsed.SchemeOutput, mlkemLevel)
		if errCode != 0 {
			return "", errCode
		}
		plaintextMSIN, errCode = suciutil.DecryptWrapperHybrid(profileFCryptogram, privateKey)
		if errCode != 0 {
			return "", errCode
		}
	} else if parsed.SchemeID == suciutil.SchemeProfileG {
		keyMaterial, ok := privateKey.(*suciutil.ProfileGKeyMaterial)
		if !ok || keyMaterial == nil {
			return "", suciutil.E_INVALID_EC_KEY
		}
		level := suciutil.NormalizeMLKEMSecurityLevel(keyMaterial.SecurityLevel)
		if cfg.MLKEMSecurityLevel != suciutil.MLKEMSecurityUnset {
			level = suciutil.NormalizeMLKEMSecurityLevel(cfg.MLKEMSecurityLevel)
		}
		profileGCryptogram, errCode := suciutil.ParseProfileGCryptogramForLevel(parsed.SchemeOutput, level)
		if errCode != 0 {
			return "", errCode
		}
		plaintextMSIN, errCode = suciutil.DecryptProfileG(profileGCryptogram, keyMaterial)
		if errCode != 0 {
			return "", errCode
		}
	} else {
		// ECIES Profiles A/B: Parse and decrypt
		cryptogram, errCode := suciutil.ParseCryptogram(parsed.SchemeOutput, parsed.SchemeID)
		if errCode != 0 {
			return "", errCode
		}
		plaintextMSIN, errCode = suciutil.DecryptECIES(cryptogram, privateKey, parsed.SchemeID)
		if errCode != 0 {
			return "", errCode
		}
	}

	// DEBUG: Print decrypted MSIN bytes and length
	slog.Debugf("[DEBUG] Decrypted MSIN bytes: %x\n", plaintextMSIN)
	slog.Debugf("[DEBUG] Decrypted MSIN length: %d\n", len(plaintextMSIN))

	msin, errCode := suciutil.DecodeMSIN_TBCDCode(plaintextMSIN)
	if errCode != 0 {
		slog.Debugf("[DEBUG] Decoded MSIN (TBCD) failed: err: %v\n", errCode)
		return "", errCode
	}
	slog.Debugf("[DEBUG] Decoded MSIN (TBCD): '%s'\n", msin)

	return msin, 0
}

// ConcealmentConfig holds configuration for SUPI to SUCI concealment
type ConcealmentConfig struct {
	SUPI            string
	SchemeID        suciutil.SchemeID
	ProfileDVariant suciutil.ProfileDVariant // Only used when SchemeID == ProfileD (0=baseline, 1=add17, 2=add19)
	KeyID           int
	// ProfileGSubscriberKeyID is a 5-byte subscriber key ID encoded as 10 hex characters.
	ProfileGSubscriberKeyID string
	RoutingInd              string
	KeyDirectory            string
	// MLKEMSecurityLevel: 0 or unset → ML-KEM-768 (NIST Level 3); 5 → ML-KEM-1024. Used for schemes C–F only.
	MLKEMSecurityLevel suciutil.MLKEMSecurityLevel
}

// ConvertSUPItoSUCI converts a SUPI to SUCI (concealment)
// This is the encryption side that happens at the UE
func (c *Converter) ConvertSUPItoSUCI(config ConcealmentConfig) suciutil.ConcealmentResult {
	// STEP 1: Parse SUPI string
	parsed, errCode := ParseSUPI(config.SUPI)
	if errCode != 0 {
		return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&errCode)}
	}

	// Set default routing indicator if not provided
	routingInd := config.RoutingInd
	if routingInd == "" {
		routingInd = "0000"
	}

	// Handle NULL-SCHEME separately
	if config.SchemeID == suciutil.SchemeNullScheme {
		msinBytes, encErr := suciutil.EncodeMSIN_TBCDCode(parsed.MSIN)
		if encErr != 0 {
			return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&encErr)}
		}
		suci := suciutil.ConstructSUCI(suciutil.IdentityType(parsed.Type), parsed.MCC, parsed.MNC, routingInd, suciutil.SchemeNullScheme, 0, msinBytes)
		return suciutil.ConcealmentResult{
			SUCI:     suci,
			KeyID:    0,
			SchemeID: suciutil.SchemeNullScheme,
		}
	}

	// STEP 2a: Early subscriber key ID validation for Profile G
	if config.SchemeID == suciutil.SchemeProfileG && strings.TrimSpace(config.ProfileGSubscriberKeyID) != "" {
		if _, err := suciutil.NormalizeProfileGSubscriberKeyID(config.ProfileGSubscriberKeyID); err != nil {
			errCode := suciutil.E_INVALID_SUBSCRIBER_KEY_ID
			return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&errCode)}
		}
	}

	// STEP 2b: Get or generate key
	keyID := uint8(config.KeyID)
	var privateKey, publicKey interface{}
	var err error

	if config.KeyID < 0 {
		// Auto-select: try to find any existing key in the keystore
		keyID, privateKey, err = c.findOrGenerateKey(config.SchemeID, config.KeyDirectory, config.MLKEMSecurityLevel)
		if err != nil {
			errCode := suciutil.E_UNKNOWN_KEY_ID
			return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&errCode)}
		}
	} else {
		// Specific key ID requested - retrieve from keystore
		keyScheme := suciutil.SchemeID(config.SchemeID)
		privateKey, err = c.keyStore.GetPrivateKey(keyID, keyScheme)
		if err != nil {
			errCode := suciutil.E_UNKNOWN_KEY_ID
			return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&errCode)}
		}
	}

	// STEP 3: Derive public key from private key (not used by Profile G)
	if config.SchemeID != suciutil.SchemeProfileG {
		publicKey, err = suciutil.GetPublicKeyFromPrivate(privateKey, config.SchemeID)
		if err != nil {
			errCode := suciutil.E_INVALID_EC_KEY
			return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&errCode)}
		}
	}

	msinBytes, encErr := suciutil.EncodeMSIN_TBCDCode(parsed.MSIN)
	if encErr != 0 {
		return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&encErr)}
	}
	slog.Debugf("[DEBUG] Conceal: MSIN bytes: %x\n", msinBytes)
	slog.Debugf("[DEBUG] Conceal: MSIN length: %d\n", len(msinBytes))

	if config.SchemeID == suciutil.SchemeProfileG {
		keyMaterial, ok := privateKey.(*suciutil.ProfileGKeyMaterial)
		if !ok || keyMaterial == nil {
			errCode := suciutil.E_INVALID_EC_KEY
			return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&errCode)}
		}

		normalizedSubID, err := suciutil.NormalizeProfileGSubscriberKeyID(config.ProfileGSubscriberKeyID)
		if err != nil {
			errCode := suciutil.E_INVALID_SUBSCRIBER_KEY_ID
			return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&errCode)}
		}
		subIDBytes, err := hex.DecodeString(normalizedSubID)
		if err != nil {
			errCode := suciutil.E_INVALID_SUBSCRIBER_KEY_ID
			return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&errCode)}
		}

		kmaster, ok := keyMaterial.SubscriberKeys[normalizedSubID]
		if !ok || len(kmaster) != 16 {
			errCode := suciutil.E_UNKNOWN_KEY_ID
			return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&errCode)}
		}

		level := suciutil.NormalizeMLKEMSecurityLevel(config.MLKEMSecurityLevel)
		gKeys := &suciutil.ProfileGConcealmentKeys{
			SecurityLevel:     level,
			HNSymmetricKey:    keyMaterial.HNSymmetricKey,
			SubscriberKeyID:   subIDBytes,
			Kmaster:           kmaster,
			WindowSizeSeconds: keyMaterial.WindowSizeSeconds,
		}
		schemeOutput, encErr := EncryptECIES(msinBytes, gKeys, SchemeID(config.SchemeID), config.ProfileDVariant, level)
		if encErr != 0 {
			return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&encErr)}
		}

		suci := suciutil.ConstructSUCI(suciutil.IdentityType(parsed.Type), parsed.MCC, parsed.MNC, routingInd, config.SchemeID, keyID, schemeOutput)
		return suciutil.ConcealmentResult{
			SUCI:     suci,
			KeyID:    keyID,
			SchemeID: config.SchemeID,
		}
	}

	var mlkemOpt []suciutil.MLKEMSecurityLevel
	if suciutil.SchemePQCUsesMLKEM(config.SchemeID) {
		mlkemOpt = append(mlkemOpt, suciutil.NormalizeMLKEMSecurityLevel(config.MLKEMSecurityLevel))
	}
	schemeOutput, errCode := EncryptECIES(msinBytes, publicKey, SchemeID(config.SchemeID), config.ProfileDVariant, mlkemOpt...)
	slog.Debugf("[DEBUG] Conceal: Encrypted scheme output: %x\n", schemeOutput)
	slog.Debugf("[DEBUG] Conceal: Encrypted scheme output length: %d\n", len(schemeOutput))
	if errCode != 0 {
		return suciutil.ConcealmentResult{Error: (*suciutil.ErrorCode)(&errCode)}
	}

	// STEP 6: Construct SUCI string
	suci := suciutil.ConstructSUCI(suciutil.IdentityType(parsed.Type), parsed.MCC, parsed.MNC, routingInd, config.SchemeID, keyID, schemeOutput)

	return suciutil.ConcealmentResult{
		SUCI:     suci,
		KeyID:    keyID,
		SchemeID: config.SchemeID,
	}
}

// findOrGenerateKey finds an existing key or generates a new one
func (c *Converter) findOrGenerateKey(scheme suciutil.SchemeID, keyDir string, mlkemLevel suciutil.MLKEMSecurityLevel) (uint8, interface{}, error) {
	keyScheme := suciutil.SchemeID(scheme)

	// Try to find an existing key (check IDs 0-255)
	for keyID := 0; keyID <= 255; keyID++ {
		id := uint8(keyID)
		privateKey, err := c.keyStore.GetPrivateKey(id, keyScheme)
		if err == nil {
			return id, privateKey, nil
		}
	}

	// Profile G key material must be provisioned via file-backed keystore.
	if scheme == suciutil.SchemeProfileG {
		return 0, nil, keys.ErrKeyNotFound
	}

	// No existing key found - generate a new one with key ID 0
	keyPair, err := keys.GenerateKeyPair(0, keyScheme, suciutil.NormalizeMLKEMSecurityLevel(mlkemLevel))
	if err != nil {
		return 0, nil, err
	}

	// Save the generated key if key directory is provided
	if keyDir != "" {
		if err := keys.SaveKeyPair(keyPair, keyDir, false); err != nil {
			// Continue anyway, just won't be persisted
		}
	}

	return 0, keyPair.PrivateKey, nil
}
