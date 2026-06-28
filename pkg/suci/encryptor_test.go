package suci

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/harishmurkal/suci-supi-tool/pkg/keys"
	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
	"golang.org/x/crypto/curve25519"
)

// Helper function to generate ML-KEM-768 key pair for tests
func mlkem768GenerateKeyPair() ([]byte, []byte, error) {
	pubKey, privKey, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubBytes, err := pubKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	privBytes, err := privKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return pubBytes, privBytes, nil
}

func mustEncodeMSINTBCD(t *testing.T, msin string) []byte {
	t.Helper()
	b, ec := suciutil.EncodeMSIN_TBCDCode(msin)
	if ec != 0 {
		t.Fatalf("EncodeMSIN_TBCDCode: %s", ec.Error())
	}
	return b
}

func assertMSINTBCDEquals(t *testing.T, tbcd []byte, want string) {
	t.Helper()
	got, ec := suciutil.DecodeMSIN_TBCDCode(tbcd)
	if ec != 0 {
		t.Fatalf("DecodeMSIN_TBCDCode: %s", ec.Error())
	}
	if got != want {
		t.Errorf("MSIN mismatch: want %q, got %q", want, got)
	}
}

// ============================================================================
// SUPI Parser Tests
// ============================================================================

func TestParseSUPI_ValidIMSI(t *testing.T) {
	testCases := []struct {
		name     string
		supi     string
		wantMCC  string
		wantMNC  string
		wantMSIN string
	}{
		{
			name:     "Standard 15-digit IMSI with 3-digit MNC (regex greedy)",
			supi:     "imsi-123450123456789",
			wantMCC:  "123",
			wantMNC:  "450", // Regex takes 3 digits for MNC when available
			wantMSIN: "123456789",
		},
		{
			name:     "15-digit IMSI with explicit 3-digit MNC",
			supi:     "imsi-123456012345678",
			wantMCC:  "123",
			wantMNC:  "456",
			wantMSIN: "012345678",
		},
		{
			name:     "IMSI with all zeros",
			supi:     "imsi-000000000000000",
			wantMCC:  "000",
			wantMNC:  "000",
			wantMSIN: "000000000",
		},
		{
			name:     "IMSI with all nines",
			supi:     "imsi-999999999999999",
			wantMCC:  "999",
			wantMNC:  "999",
			wantMSIN: "999999999",
		},
		{
			name:     "Minimum 6-digit IMSI (MCC + 2-digit MNC + 1 MSIN)",
			supi:     "imsi-123451",
			wantMCC:  "123",
			wantMNC:  "45", // Only 2 digits left for MNC after MCC
			wantMSIN: "1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, errCode := ParseSUPI(tc.supi)
			if errCode != 0 {
				t.Fatalf("Expected no error, got: %v", errCode)
			}

			if parsed.MCC != tc.wantMCC {
				t.Errorf("Expected MCC '%s', got: '%s'", tc.wantMCC, parsed.MCC)
			}
			if parsed.MNC != tc.wantMNC {
				t.Errorf("Expected MNC '%s', got: '%s'", tc.wantMNC, parsed.MNC)
			}
			if parsed.MSIN != tc.wantMSIN {
				t.Errorf("Expected MSIN '%s', got: '%s'", tc.wantMSIN, parsed.MSIN)
			}
			if parsed.Type != TypeIMSI {
				t.Errorf("Expected Type IMSI, got: %d", parsed.Type)
			}
		})
	}
}

func TestParseSUPI_InvalidFormat(t *testing.T) {
	invalidSUPIs := []struct {
		supi   string
		reason string
	}{
		{"", "empty string"},
		{"invalid", "no prefix"},
		{"supi-123450123456789", "wrong prefix"},
		{"imsi-12345012345678901", "too long (16 digits)"},
		{"imsi-1234", "too short (4 digits)"},
		{"imsi-12a450123456789", "non-numeric character"},
		{"imsi-", "empty after prefix"},
		{"IMSI-123450123456789", "uppercase prefix"},
	}

	for _, tc := range invalidSUPIs {
		t.Run(tc.reason, func(t *testing.T) {
			_, errCode := ParseSUPI(tc.supi)
			if errCode == 0 {
				t.Errorf("Expected error for invalid SUPI '%s' (%s)", tc.supi, tc.reason)
			}
		})
	}
}

// ============================================================================
// MSIN Encoding Tests
// ============================================================================

func TestEncodeMSIN_TBCD_Basic(t *testing.T) {
	testCases := []struct {
		name    string
		msin    string
		wantLen int
	}{
		{
			name:    "10-digit MSIN",
			msin:    "0123456789",
			wantLen: 5,
		},
		{
			name:    "5-digit MSIN",
			msin:    "12345",
			wantLen: 3,
		},
		{
			name:    "Empty MSIN",
			msin:    "",
			wantLen: 0,
		},
		{
			name:    "All zeros",
			msin:    "0000000000",
			wantLen: 5,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := suciutil.EncodeMSIN_TBCD(tc.msin)
			if err != nil {
				t.Fatalf("EncodeMSIN_TBCD: %v", err)
			}

			if len(encoded) != tc.wantLen {
				t.Errorf("Expected length %d, got %d", tc.wantLen, len(encoded))
			}

			decoded, err := suciutil.DecodeMSIN_TBCD(encoded)
			if err != nil {
				t.Fatalf("DecodeMSIN_TBCD: %v", err)
			}
			if decoded != tc.msin {
				t.Errorf("Round-trip expected '%s', got '%s'", tc.msin, decoded)
			}
		})
	}
}

// ============================================================================
// NULL Scheme Tests
// ============================================================================

func TestConstructSUCI_NullScheme(t *testing.T) {
	schemeOutput := mustEncodeMSINTBCD(t, "0123456789")

	suci := ConstructSUCI(TypeIMSI, "123", "45", "0000", SchemeNullScheme, 0, schemeOutput)

	// Verify format
	if !strings.HasPrefix(suci, "suci-0-123-45-") {
		t.Errorf("SUCI should start with 'suci-0-123-45-', got: %s", suci)
	}

	parts := strings.Split(suci, "-")
	if len(parts) != 8 {
		t.Errorf("SUCI should have 8 parts, got %d: %s", len(parts), suci)
	}

	// Check scheme ID is 0
	if parts[5] != "0" {
		t.Errorf("Expected scheme ID '0', got '%s'", parts[5])
	}
}

// ============================================================================
// GetPublicKeyFromPrivate Tests
// ============================================================================

func TestGetPublicKeyFromPrivate_ProfileA(t *testing.T) {
	// Generate a test private key (32 bytes for Profile A)
	privateKey := make([]byte, 32)
	for i := range privateKey {
		privateKey[i] = byte(i)
	}

	pubKey, err := suciutil.GetPublicKeyFromPrivate(privateKey, suciutil.SchemeProfileA)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Profile A public key should be 32 bytes
	pubKeyBytes, ok := pubKey.([]byte)
	if !ok {
		t.Fatalf("Expected []byte public key type")
	}
	if len(pubKeyBytes) != 32 {
		t.Errorf("Expected 32-byte public key, got %d bytes", len(pubKeyBytes))
	}
}

func TestGetPublicKeyFromPrivate_InvalidKey(t *testing.T) {
	// Too short private key for Profile A
	shortKey := make([]byte, 16)
	_, err := suciutil.GetPublicKeyFromPrivate(shortKey, suciutil.SchemeProfileA)
	if err == nil {
		t.Errorf("Expected error for short key")
	}
}

// ============================================================================
// ECIES Encryption Tests
// ============================================================================

func TestEncryptECIES_ProfileA_MinimalData(t *testing.T) {
	// Create a dummy public key (32 bytes for Profile A)
	publicKey := make([]byte, 32)
	for i := range publicKey {
		publicKey[i] = byte(i + 1)
	}

	msinBytes := []byte{0x01, 0x23, 0x45, 0x67, 0x89}

	ciphertext, errCode := EncryptECIES(msinBytes, publicKey, SchemeProfileA, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("Expected no error, got: %v", errCode)
	}

	// Profile A: 32 bytes ephemeral pubkey + encrypted data + 8 byte MAC
	expectedMinLen := 32 + len(msinBytes) + 8
	if len(ciphertext) < expectedMinLen {
		t.Errorf("Ciphertext too short: got %d, expected at least %d", len(ciphertext), expectedMinLen)
	}
}

func TestEncryptECIES_ProfileA_EmptyData(t *testing.T) {
	publicKey := make([]byte, 32)
	for i := range publicKey {
		publicKey[i] = byte(i + 1)
	}

	msinBytes := []byte{}

	ciphertext, errCode := EncryptECIES(msinBytes, publicKey, SchemeProfileA, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("Expected no error, got: %v", errCode)
	}

	// Profile A: 32 bytes ephemeral pubkey + 0 encrypted bytes + 8 byte MAC
	expectedLen := 32 + 8
	if len(ciphertext) != expectedLen {
		t.Errorf("Expected %d bytes, got %d", expectedLen, len(ciphertext))
	}
}

func TestEncryptECIES_InvalidPublicKey(t *testing.T) {
	// Invalid (short) public key
	invalidKey := make([]byte, 16)
	msinBytes := []byte{0x01, 0x23}

	_, errCode := EncryptECIES(msinBytes, invalidKey, SchemeProfileA, suciutil.ProfileDVariantBaseline)
	if errCode == 0 {
		t.Errorf("Expected error for invalid public key")
	}
}

// ============================================================================
// Integration Tests
// ============================================================================

func TestConcealmentResult_Methods(t *testing.T) {
	// Test successful result
	successResult := suciutil.ConcealmentResult{
		SUCI:     "suci-0-123-45-0000-0-0-abcd",
		KeyID:    5,
		SchemeID: suciutil.SchemeNullScheme,
		Error:    nil,
	}

	if !successResult.IsSuccess() {
		t.Errorf("Expected IsSuccess() to be true")
	}

	if successResult.GetErrorString() != "" {
		t.Errorf("Expected empty error string for success, got: %s", successResult.GetErrorString())
	}

	// Test failed result
	errCode := suciutil.ErrorCode(E_PARSE_SUPI)
	failResult := suciutil.ConcealmentResult{
		Error: &errCode,
	}

	if failResult.IsSuccess() {
		t.Errorf("Expected IsSuccess() to be false")
	}

	if failResult.GetErrorString() == "" {
		t.Errorf("Expected non-empty error string for failure")
	}
}

// ============================================================================
// Edge Case Tests
// ============================================================================

func TestParseSUPI_EdgeCases(t *testing.T) {
	// Test exactly 6 digits (minimum viable: MCC + 2-digit MNC + 1 MSIN)
	parsed, errCode := ParseSUPI("imsi-123451")
	if errCode != 0 {
		t.Fatalf("6-digit IMSI should be valid: %v", errCode)
	}
	if parsed.MSIN != "1" {
		t.Errorf("Expected MSIN '1' for 6-digit IMSI, got: '%s'", parsed.MSIN)
	}

	// Test exactly 15 digits (maximum)
	parsed, errCode = ParseSUPI("imsi-123456789012345")
	if errCode != 0 {
		t.Fatalf("15-digit IMSI should be valid: %v", errCode)
	}
	if len(parsed.MCC)+len(parsed.MNC)+len(parsed.MSIN) != 15 {
		t.Errorf("15-digit IMSI should parse to 15 total digits")
	}
}

func TestEncodeMSIN_TBCD_SingleDigit(t *testing.T) {
	encoded := mustEncodeMSINTBCD(t, "5")
	if len(encoded) != 1 {
		t.Errorf("Expected 1 byte, got %d", len(encoded))
	}
	if encoded[0] != 0xF5 {
		t.Errorf("Expected TBCD 0xF5, got 0x%02x", encoded[0])
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkParseSUPI(b *testing.B) {
	supi := "imsi-123450123456789"
	for i := 0; i < b.N; i++ {
		ParseSUPI(supi)
	}
}

func BenchmarkEncodeMSIN_TBCD(b *testing.B) {
	msin := "0123456789"
	for i := 0; i < b.N; i++ {
		_, _ = suciutil.EncodeMSIN_TBCD(msin)
	}
}

func BenchmarkEncryptECIES_ProfileA(b *testing.B) {
	publicKey := make([]byte, 32)
	for i := range publicKey {
		publicKey[i] = byte(i + 1)
	}
	msinBytes := []byte{0x01, 0x23, 0x45, 0x67, 0x89}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptECIES(msinBytes, publicKey, SchemeProfileA, suciutil.ProfileDVariantBaseline)
	}
}

// ============================================================================
// PQC Profile C Tests (ML-KEM-768)
// ============================================================================

func TestGetPublicKeyFromPrivate_ProfileC(t *testing.T) {
	// Generate a test ML-KEM-768 key pair
	keyPair, err := generateMLKEM768KeyPairForTest()
	if err != nil {
		t.Fatalf("Failed to generate ML-KEM-768 key pair: %v", err)
	}

	pubKey, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileC)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Profile C public key should be 1184 bytes
	pubKeyBytes, ok := pubKey.([]byte)
	if !ok {
		t.Fatalf("Expected []byte public key type")
	}
	if len(pubKeyBytes) != MLKEM768_PUBLIC_KEY_LEN {
		t.Errorf("Expected %d-byte public key, got %d bytes", MLKEM768_PUBLIC_KEY_LEN, len(pubKeyBytes))
	}
}

func TestEncryptECIES_ProfileC_RoundTrip(t *testing.T) {
	// Generate ML-KEM-768 key pair
	keyPair, err := generateMLKEM768KeyPairForTest()
	if err != nil {
		t.Fatalf("Failed to generate ML-KEM-768 key pair: %v", err)
	}

	originalMSIN := "1234567890"
	msinBytes := mustEncodeMSINTBCD(t, originalMSIN)

	// Encrypt using Profile C
	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileC, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("EncryptECIES Profile C failed: %v", errCode.Error())
	}

	// Verify minimum length: KEM ciphertext (1088) + encrypted MSIN + MAC (8)
	expectedMinLen := MLKEM768_CIPHERTEXT_LEN + len(msinBytes) + ProfileC_MAC_TAG_LEN
	if len(schemeOutput) < expectedMinLen {
		t.Errorf("Scheme output too short: got %d, expected at least %d", len(schemeOutput), expectedMinLen)
	}

	// Parse the PQC cryptogram
	pqcCryptogram, errCode := ParsePQCCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParsePQCCryptogram failed: %v", errCode.Error())
	}

	// Decrypt using Profile C
	decryptedMSIN, errCode := DecryptPQC(pqcCryptogram, keyPair.PrivateKey)
	if errCode != 0 {
		t.Fatalf("DecryptPQC failed: %v", errCode.Error())
	}

	// Verify round-trip
	assertMSINTBCDEquals(t, decryptedMSIN, originalMSIN)
}

func TestProfileC_Constants(t *testing.T) {
	// Verify constants match ML-KEM-768 specification
	if MLKEM768_PUBLIC_KEY_LEN != 1184 {
		t.Errorf("MLKEM768_PUBLIC_KEY_LEN should be 1184, got %d", MLKEM768_PUBLIC_KEY_LEN)
	}
	if MLKEM768_PRIVATE_KEY_LEN != 2400 {
		t.Errorf("MLKEM768_PRIVATE_KEY_LEN should be 2400, got %d", MLKEM768_PRIVATE_KEY_LEN)
	}
	if MLKEM768_CIPHERTEXT_LEN != 1088 {
		t.Errorf("MLKEM768_CIPHERTEXT_LEN should be 1088, got %d", MLKEM768_CIPHERTEXT_LEN)
	}
	if ProfileC_ENC_KEY_LEN != 32 {
		t.Errorf("ProfileC_ENC_KEY_LEN should be 32 (AES-256), got %d", ProfileC_ENC_KEY_LEN)
	}
	if ProfileC_MAC_KEY_LEN != 32 {
		t.Errorf("ProfileC_MAC_KEY_LEN should be 32, got %d", ProfileC_MAC_KEY_LEN)
	}
}

func TestSchemeID_ProfileC(t *testing.T) {
	scheme := SchemeProfileC

	if !scheme.IsValid() {
		t.Errorf("SchemeProfileC should be valid")
	}

	if !scheme.RequiresDecryption() {
		t.Errorf("SchemeProfileC should require decryption")
	}

	str := scheme.String()
	if !strings.Contains(str, "ML-KEM") {
		t.Errorf("SchemeProfileC string should mention ML-KEM, got: %s", str)
	}
}

func TestValidateKeySchemeMatch_ProfileC(t *testing.T) {
	// Valid Profile C key
	validKey := make([]byte, MLKEM768_PRIVATE_KEY_LEN)
	errCode := ValidateKeySchemeMatch(validKey, SchemeProfileC)
	if errCode != 0 {
		t.Errorf("Expected no error for valid Profile C key, got: %v", errCode)
	}

	// Invalid (wrong length) key
	invalidKey := make([]byte, 32) // Too short for ML-KEM
	errCode = ValidateKeySchemeMatch(invalidKey, SchemeProfileC)
	if errCode == 0 {
		t.Errorf("Expected error for invalid Profile C key length")
	}
}

func TestParsePQCCryptogram(t *testing.T) {
	// Create a minimal valid scheme output
	kemCiphertext := make([]byte, MLKEM768_CIPHERTEXT_LEN)
	encryptedMSIN := []byte("test1234")
	macTag := make([]byte, ProfileC_MAC_TAG_LEN)

	schemeOutput := append(kemCiphertext, encryptedMSIN...)
	schemeOutput = append(schemeOutput, macTag...)

	pqcCryptogram, errCode := ParsePQCCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParsePQCCryptogram failed: %v", errCode.Error())
	}

	if len(pqcCryptogram.KEMCiphertext) != MLKEM768_CIPHERTEXT_LEN {
		t.Errorf("KEMCiphertext should be %d bytes, got %d", MLKEM768_CIPHERTEXT_LEN, len(pqcCryptogram.KEMCiphertext))
	}

	if len(pqcCryptogram.MACTag) != ProfileC_MAC_TAG_LEN {
		t.Errorf("MACTag should be %d bytes, got %d", ProfileC_MAC_TAG_LEN, len(pqcCryptogram.MACTag))
	}
}

func TestParsePQCCryptogram_TooShort(t *testing.T) {
	// Too short - should fail
	shortOutput := make([]byte, ProfileC_MinLen-1)
	_, errCode := ParsePQCCryptogram(shortOutput)
	if errCode == 0 {
		t.Errorf("Expected error for too short scheme output")
	}
}

// Helper function to generate ML-KEM-768 key pair for testing
func generateMLKEM768KeyPairForTest() (*mlkem768TestKeyPair, error) {
	// Import the keys package to generate a real ML-KEM-768 key pair
	keyPair, err := generateProfileCKeyForTest()
	if err != nil {
		return nil, err
	}
	return keyPair, nil
}

type mlkem768TestKeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

func generateProfileCKeyForTest() (*mlkem768TestKeyPair, error) {
	// Use the circl library directly for testing
	pubKey, privKey, err := mlkem768GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &mlkem768TestKeyPair{
		PublicKey:  pubKey,
		PrivateKey: privKey,
	}, nil
}

// ============================================================================
// Hybrid Profile D Tests (ML-KEM-768 + X25519)
// ============================================================================

func TestSchemeID_ProfileD(t *testing.T) {
	scheme := SchemeProfileD

	if !scheme.IsValid() {
		t.Errorf("SchemeProfileD should be valid")
	}

	if !scheme.RequiresDecryption() {
		t.Errorf("SchemeProfileD should require decryption")
	}

	str := scheme.String()
	if !strings.Contains(str, "ML-KEM") || !strings.Contains(str, "X25519") {
		t.Errorf("SchemeProfileD string should mention ML-KEM and X25519, got: %s", str)
	}
}

func TestValidateKeySchemeMatch_ProfileD(t *testing.T) {
	// Valid Profile D key (composite key)
	validKey := &ProfileDPrivateKeys{
		MLKEMPrivate:  make([]byte, MLKEM768_PRIVATE_KEY_LEN),
		X25519Private: make([]byte, 32),
	}
	errCode := ValidateKeySchemeMatch(validKey, SchemeProfileD)
	if errCode != 0 {
		t.Errorf("Expected no error for valid Profile D key, got: %v", errCode)
	}

	// Invalid key (wrong type)
	invalidKey := make([]byte, 32)
	errCode = ValidateKeySchemeMatch(invalidKey, SchemeProfileD)
	if errCode == 0 {
		t.Errorf("Expected error for invalid Profile D key type")
	}

	// Invalid composite key (wrong ML-KEM length)
	invalidComposite := &ProfileDPrivateKeys{
		MLKEMPrivate:  make([]byte, 100), // Wrong length
		X25519Private: make([]byte, 32),
	}
	errCode = ValidateKeySchemeMatch(invalidComposite, SchemeProfileD)
	if errCode == 0 {
		t.Errorf("Expected error for invalid Profile D ML-KEM key length")
	}
}

func TestParseProfileDCryptogram(t *testing.T) {
	// Create a minimal valid scheme output for Profile D
	kemCiphertext := make([]byte, MLKEM768_CIPHERTEXT_LEN)
	ephemeralPubKey := make([]byte, ProfileD_EphPubKeyLen)
	encryptedMSIN := []byte("test1234")
	macTag := make([]byte, ProfileC_MAC_TAG_LEN)

	schemeOutput := append(kemCiphertext, ephemeralPubKey...)
	schemeOutput = append(schemeOutput, encryptedMSIN...)
	schemeOutput = append(schemeOutput, macTag...)

	hybridCryptogram, errCode := ParseProfileDCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileDCryptogram failed: %v", errCode.Error())
	}

	if len(hybridCryptogram.KEMCiphertext) != MLKEM768_CIPHERTEXT_LEN {
		t.Errorf("KEMCiphertext should be %d bytes, got %d", MLKEM768_CIPHERTEXT_LEN, len(hybridCryptogram.KEMCiphertext))
	}

	if len(hybridCryptogram.EphemeralPublicKey) != ProfileD_EphPubKeyLen {
		t.Errorf("EphemeralPublicKey should be %d bytes, got %d", ProfileD_EphPubKeyLen, len(hybridCryptogram.EphemeralPublicKey))
	}

	if len(hybridCryptogram.MACTag) != ProfileC_MAC_TAG_LEN {
		t.Errorf("MACTag should be %d bytes, got %d", ProfileC_MAC_TAG_LEN, len(hybridCryptogram.MACTag))
	}
}

func TestParseProfileDCryptogram_TooShort(t *testing.T) {
	// Too short - should fail
	shortOutput := make([]byte, ProfileD_MinLen-1)
	_, errCode := ParseProfileDCryptogram(shortOutput)
	if errCode == 0 {
		t.Errorf("Expected error for too short scheme output")
	}
}

func TestEncryptECIES_ProfileD_RoundTrip(t *testing.T) {
	// Generate Profile D key pair (ML-KEM + X25519)
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate Profile D key pair: %v", err)
	}

	originalMSIN := "1234567890"
	msinBytes := mustEncodeMSINTBCD(t, originalMSIN)

	// Encrypt using Profile D
	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileD, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("EncryptECIES Profile D failed: %v", errCode.Error())
	}

	// Verify minimum length: KEM ciphertext (1088) + ephemeral pub key (32) + encrypted MSIN + MAC (8)
	expectedMinLen := MLKEM768_CIPHERTEXT_LEN + ProfileD_EphPubKeyLen + len(msinBytes) + ProfileC_MAC_TAG_LEN
	if len(schemeOutput) < expectedMinLen {
		t.Errorf("Scheme output too short: got %d, expected at least %d", len(schemeOutput), expectedMinLen)
	}

	// Parse the Hybrid cryptogram
	hybridCryptogram, errCode := ParseProfileDCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileDCryptogram failed: %v", errCode.Error())
	}

	// Decrypt using Profile D
	decryptedMSIN, errCode := DecryptHybrid(hybridCryptogram, keyPair.PrivateKey)
	if errCode != 0 {
		t.Fatalf("DecryptHybrid failed: %v", errCode.Error())
	}

	// Verify round-trip
	assertMSINTBCDEquals(t, decryptedMSIN, originalMSIN)
}

func TestGetPublicKeyFromPrivate_ProfileD(t *testing.T) {
	// Generate a test Profile D key pair
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate Profile D key pair: %v", err)
	}

	pubKey, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileD)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Profile D public key should be *ProfileDPublicKeys
	pubKeyComposite, ok := pubKey.(*suciutil.ProfileDPublicKeys)
	if !ok {
		t.Fatalf("Expected *ProfileDPublicKeys type, got %T", pubKey)
	}
	if len(pubKeyComposite.MLKEMPublic) != MLKEM768_PUBLIC_KEY_LEN {
		t.Errorf("Expected %d-byte ML-KEM public key, got %d bytes", MLKEM768_PUBLIC_KEY_LEN, len(pubKeyComposite.MLKEMPublic))
	}
	if len(pubKeyComposite.X25519Public) != 32 {
		t.Errorf("Expected 32-byte X25519 public key, got %d bytes", len(pubKeyComposite.X25519Public))
	}
}

func TestProfileD_Constants(t *testing.T) {
	// Verify Profile D constants
	if ProfileD_EphPubKeyLen != 32 {
		t.Errorf("ProfileD_EphPubKeyLen should be 32 (X25519), got %d", ProfileD_EphPubKeyLen)
	}
	expectedMinLen := MLKEM768_CIPHERTEXT_LEN + ProfileD_EphPubKeyLen + ProfileC_MAC_TAG_LEN
	if ProfileD_MinLen != expectedMinLen {
		t.Errorf("ProfileD_MinLen should be %d, got %d", expectedMinLen, ProfileD_MinLen)
	}
}

// Helper structs and functions for Profile D testing
type profileDTestKeyPair struct {
	PublicKey  *ProfileDPublicKeys
	PrivateKey *ProfileDPrivateKeys
}

func generateProfileDKeyForTest() (*profileDTestKeyPair, error) {
	// Generate ML-KEM-768 key pair
	mlkemPub, mlkemPriv, err := mlkem768GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Generate X25519 key pair
	x25519Priv := make([]byte, 32)
	if _, err := rand.Read(x25519Priv); err != nil {
		return nil, err
	}

	// Derive X25519 public key from private key using basepoint multiplication
	basepoint := make([]byte, 32)
	basepoint[0] = 9
	x25519Pub, err := curve25519.X25519(x25519Priv, basepoint)
	if err != nil {
		return nil, err
	}

	return &profileDTestKeyPair{
		PublicKey: &ProfileDPublicKeys{
			MLKEMPublic:  mlkemPub,
			X25519Public: x25519Pub,
		},
		PrivateKey: &ProfileDPrivateKeys{
			MLKEMPrivate:  mlkemPriv,
			X25519Private: x25519Priv,
		},
	}, nil
}

// ============================================================================
// Profile D add17 / add19 Variant Round-Trip Tests
// ============================================================================

func TestEncryptECIES_ProfileD_Add17_RoundTrip(t *testing.T) {
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate Profile D key pair: %v", err)
	}

	originalMSIN := "1234567890"
	msinBytes := mustEncodeMSINTBCD(t, originalMSIN)

	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileD, suciutil.ProfileDVariantAdd17)
	if errCode != 0 {
		t.Fatalf("EncryptECIES Profile D add17 failed: %v", errCode.Error())
	}

	// add17 output: kemCt(1088) + ephPub(32) + variant(1) + nonce(16) + ciphertext + macTag(8)
	expectedMinLen := MLKEM768_CIPHERTEXT_LEN + ProfileD_EphPubKeyLen + 1 + suciutil.ProfileD_Add17_NonceLen + len(msinBytes) + ProfileC_MAC_TAG_LEN
	if len(schemeOutput) < expectedMinLen {
		t.Errorf("add17 scheme output too short: got %d, expected at least %d", len(schemeOutput), expectedMinLen)
	}

	// Verify variant byte
	variantOffset := MLKEM768_CIPHERTEXT_LEN + ProfileD_EphPubKeyLen
	if schemeOutput[variantOffset] != 0x01 {
		t.Errorf("Expected variant byte 0x01 at offset %d, got 0x%02x", variantOffset, schemeOutput[variantOffset])
	}

	hybridCryptogram, errCode := ParseProfileDCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileDCryptogram failed: %v", errCode.Error())
	}

	if hybridCryptogram.Variant != suciutil.ProfileDVariantAdd17 {
		t.Errorf("Expected variant add17 (1), got %d", hybridCryptogram.Variant)
	}
	if len(hybridCryptogram.Nonce) != suciutil.ProfileD_Add17_NonceLen {
		t.Errorf("Expected %d-byte nonce, got %d", suciutil.ProfileD_Add17_NonceLen, len(hybridCryptogram.Nonce))
	}

	decryptedMSIN, errCode := DecryptHybrid(hybridCryptogram, keyPair.PrivateKey)
	if errCode != 0 {
		t.Fatalf("DecryptHybrid add17 failed: %v", errCode.Error())
	}

	assertMSINTBCDEquals(t, decryptedMSIN, originalMSIN)
}

func TestEncryptECIES_ProfileD_Add19_RoundTrip(t *testing.T) {
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate Profile D key pair: %v", err)
	}

	originalMSIN := "1234567890"
	msinBytes := mustEncodeMSINTBCD(t, originalMSIN)

	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileD, suciutil.ProfileDVariantAdd19)
	if errCode != 0 {
		t.Fatalf("EncryptECIES Profile D add19 failed: %v", errCode.Error())
	}

	// add19 output: kemCt(1088) + ephPub(32) + variant(1) + nonce(12) + ciphertext + tag(16)
	expectedMinLen := MLKEM768_CIPHERTEXT_LEN + ProfileD_EphPubKeyLen + 1 + suciutil.ProfileD_Add19_NonceLen + len(msinBytes) + suciutil.ProfileD_Add19_TagLen
	if len(schemeOutput) < expectedMinLen {
		t.Errorf("add19 scheme output too short: got %d, expected at least %d", len(schemeOutput), expectedMinLen)
	}

	// Verify variant byte
	variantOffset := MLKEM768_CIPHERTEXT_LEN + ProfileD_EphPubKeyLen
	if schemeOutput[variantOffset] != 0x02 {
		t.Errorf("Expected variant byte 0x02 at offset %d, got 0x%02x", variantOffset, schemeOutput[variantOffset])
	}

	hybridCryptogram, errCode := ParseProfileDCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileDCryptogram failed: %v", errCode.Error())
	}

	if hybridCryptogram.Variant != suciutil.ProfileDVariantAdd19 {
		t.Errorf("Expected variant add19 (2), got %d", hybridCryptogram.Variant)
	}
	if len(hybridCryptogram.Nonce) != suciutil.ProfileD_Add19_NonceLen {
		t.Errorf("Expected %d-byte nonce, got %d", suciutil.ProfileD_Add19_NonceLen, len(hybridCryptogram.Nonce))
	}
	if len(hybridCryptogram.MACTag) != suciutil.ProfileD_Add19_TagLen {
		t.Errorf("Expected %d-byte AEAD tag, got %d", suciutil.ProfileD_Add19_TagLen, len(hybridCryptogram.MACTag))
	}

	decryptedMSIN, errCode := DecryptHybrid(hybridCryptogram, keyPair.PrivateKey)
	if errCode != 0 {
		t.Fatalf("DecryptHybrid add19 failed: %v", errCode.Error())
	}

	assertMSINTBCDEquals(t, decryptedMSIN, originalMSIN)
}

func TestProfileD_BaselineStillWorks(t *testing.T) {
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate Profile D key pair: %v", err)
	}

	originalMSIN := "9876543210"
	msinBytes := mustEncodeMSINTBCD(t, originalMSIN)

	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileD, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("EncryptECIES Profile D baseline failed: %v", errCode.Error())
	}

	hybridCryptogram, errCode := ParseProfileDCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileDCryptogram failed: %v", errCode.Error())
	}

	if hybridCryptogram.Variant != suciutil.ProfileDVariantBaseline {
		t.Errorf("Expected variant baseline (0), got %d", hybridCryptogram.Variant)
	}
	if hybridCryptogram.Nonce != nil {
		t.Errorf("Baseline should have nil nonce, got %d bytes", len(hybridCryptogram.Nonce))
	}

	decryptedMSIN, errCode := DecryptHybrid(hybridCryptogram, keyPair.PrivateKey)
	if errCode != 0 {
		t.Fatalf("DecryptHybrid baseline failed: %v", errCode.Error())
	}

	assertMSINTBCDEquals(t, decryptedMSIN, originalMSIN)
}

func TestProfileD_VariantIncompatibility(t *testing.T) {
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate Profile D key pair: %v", err)
	}

	msinBytes := mustEncodeMSINTBCD(t, "1234567890")

	// Encrypt with add17
	add17Output, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileD, suciutil.ProfileDVariantAdd17)
	if errCode != 0 {
		t.Fatalf("EncryptECIES add17 failed: %v", errCode.Error())
	}

	// Parse - should detect add17
	hc, errCode := ParseProfileDCryptogram(add17Output)
	if errCode != 0 {
		t.Fatalf("ParseProfileDCryptogram failed: %v", errCode.Error())
	}
	if hc.Variant != suciutil.ProfileDVariantAdd17 {
		t.Errorf("Expected add17 variant, got %v", hc.Variant)
	}

	// Encrypt with add19
	add19Output, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileD, suciutil.ProfileDVariantAdd19)
	if errCode != 0 {
		t.Fatalf("EncryptECIES add19 failed: %v", errCode.Error())
	}

	// Parse - should detect add19
	hc2, errCode := ParseProfileDCryptogram(add19Output)
	if errCode != 0 {
		t.Fatalf("ParseProfileDCryptogram failed: %v", errCode.Error())
	}
	if hc2.Variant != suciutil.ProfileDVariantAdd19 {
		t.Errorf("Expected add19 variant, got %v", hc2.Variant)
	}
}

func TestEncryptECIES_ProfileD_WrongKey(t *testing.T) {
	keyPair1, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}
	keyPair2, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	msinBytes := mustEncodeMSINTBCD(t, "1234567890")

	// Encrypt with key pair 1's public key
	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair1.PublicKey, SchemeProfileD, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("EncryptECIES failed: %v", errCode.Error())
	}

	// Try to decrypt with key pair 2's private key - should fail
	hybridCryptogram, errCode := ParseProfileDCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileDCryptogram failed: %v", errCode.Error())
	}

	_, errCode = DecryptHybrid(hybridCryptogram, keyPair2.PrivateKey)
	if errCode == 0 {
		t.Errorf("Expected decryption to fail with wrong key")
	}
}

func TestEncryptECIES_ProfileD_Add17_WrongKey(t *testing.T) {
	keyPair1, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}
	keyPair2, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	msinBytes := mustEncodeMSINTBCD(t, "1234567890")

	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair1.PublicKey, SchemeProfileD, suciutil.ProfileDVariantAdd17)
	if errCode != 0 {
		t.Fatalf("EncryptECIES add17 failed: %v", errCode.Error())
	}

	hybridCryptogram, errCode := ParseProfileDCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileDCryptogram failed: %v", errCode.Error())
	}

	_, errCode = DecryptHybrid(hybridCryptogram, keyPair2.PrivateKey)
	if errCode == 0 {
		t.Errorf("Expected add17 decryption to fail with wrong key")
	}
}

func TestEncryptECIES_ProfileD_Add19_WrongKey(t *testing.T) {
	keyPair1, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}
	keyPair2, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	msinBytes := mustEncodeMSINTBCD(t, "1234567890")

	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair1.PublicKey, SchemeProfileD, suciutil.ProfileDVariantAdd19)
	if errCode != 0 {
		t.Fatalf("EncryptECIES add19 failed: %v", errCode.Error())
	}

	hybridCryptogram, errCode := ParseProfileDCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileDCryptogram failed: %v", errCode.Error())
	}

	_, errCode = DecryptHybrid(hybridCryptogram, keyPair2.PrivateKey)
	if errCode == 0 {
		t.Errorf("Expected add19 decryption to fail with wrong key")
	}
}

// ============================================================================
// Profile E (Nested Hybrid) Tests
// ============================================================================

func TestSchemeID_ProfileE(t *testing.T) {
	scheme := SchemeProfileE
	if !scheme.IsValid() {
		t.Errorf("SchemeProfileE should be valid")
	}
	if !scheme.RequiresDecryption() {
		t.Errorf("SchemeProfileE should require decryption")
	}
	str := scheme.String()
	if !strings.Contains(str, "Nested") {
		t.Errorf("SchemeProfileE string should mention Nested, got: %s", str)
	}
}

func TestEncryptECIES_ProfileE_RoundTrip(t *testing.T) {
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	originalMSIN := "1234567890"
	msinBytes := mustEncodeMSINTBCD(t, originalMSIN)

	// Encrypt using Profile E
	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileE, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("EncryptECIES Profile E failed: %v", errCode.Error())
	}

	// Verify minimum length: EphPub(32) + EncKEMCT(1088) + KEMMAC(8) + EncMSIN + MSINMAC(8)
	expectedMinLen := ProfileE_EphPubKeyLen + MLKEM768_CIPHERTEXT_LEN + ProfileC_MAC_TAG_LEN + len(msinBytes) + ProfileC_MAC_TAG_LEN
	if len(schemeOutput) < expectedMinLen {
		t.Errorf("Scheme output too short: got %d, expected at least %d", len(schemeOutput), expectedMinLen)
	}

	// Parse the Profile E cryptogram
	profileECg, errCode := ParseProfileECryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileECryptogram failed: %v", errCode.Error())
	}

	// Verify parsed components
	if len(profileECg.EphemeralPublicKey) != ProfileE_EphPubKeyLen {
		t.Errorf("Expected %d-byte ephemeral key, got %d", ProfileE_EphPubKeyLen, len(profileECg.EphemeralPublicKey))
	}
	if len(profileECg.EncryptedKEMCT) != MLKEM768_CIPHERTEXT_LEN {
		t.Errorf("Expected %d-byte encrypted KEM CT, got %d", MLKEM768_CIPHERTEXT_LEN, len(profileECg.EncryptedKEMCT))
	}
	if len(profileECg.KEMMACTag) != ProfileC_MAC_TAG_LEN {
		t.Errorf("Expected %d-byte KEM MAC, got %d", ProfileC_MAC_TAG_LEN, len(profileECg.KEMMACTag))
	}
	if len(profileECg.MACTag) != ProfileC_MAC_TAG_LEN {
		t.Errorf("Expected %d-byte MSIN MAC, got %d", ProfileC_MAC_TAG_LEN, len(profileECg.MACTag))
	}

	// Decrypt using Profile E
	decryptedMSIN, errCode := DecryptNestedHybrid(profileECg, keyPair.PrivateKey)
	if errCode != 0 {
		t.Fatalf("DecryptNestedHybrid failed: %v", errCode.Error())
	}

	// Verify round-trip
	assertMSINTBCDEquals(t, decryptedMSIN, originalMSIN)
}

func TestEncryptECIES_ProfileE_EmptyMSIN(t *testing.T) {
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	msinBytes := []byte{}

	// Encrypt empty MSIN
	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileE, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("EncryptECIES Profile E failed with empty MSIN: %v", errCode.Error())
	}

	// Parse and decrypt
	profileECg, errCode := ParseProfileECryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileECryptogram failed: %v", errCode.Error())
	}

	decryptedMSIN, errCode := DecryptNestedHybrid(profileECg, keyPair.PrivateKey)
	if errCode != 0 {
		t.Fatalf("DecryptNestedHybrid failed: %v", errCode.Error())
	}

	if len(decryptedMSIN) != 0 {
		t.Errorf("Expected empty decrypted MSIN, got %d bytes", len(decryptedMSIN))
	}
}

func TestEncryptECIES_ProfileE_WrongKey(t *testing.T) {
	keyPair1, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}
	keyPair2, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	msinBytes := mustEncodeMSINTBCD(t, "1234567890")

	// Encrypt with key pair 1's public key
	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair1.PublicKey, SchemeProfileE, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("EncryptECIES failed: %v", errCode.Error())
	}

	// Try to decrypt with key pair 2's private key - should fail
	profileECg, errCode := ParseProfileECryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileECryptogram failed: %v", errCode.Error())
	}

	_, errCode = DecryptNestedHybrid(profileECg, keyPair2.PrivateKey)
	if errCode == 0 {
		t.Errorf("Expected decryption to fail with wrong key")
	}
}

func TestGetPublicKeyFromPrivate_ProfileE(t *testing.T) {
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	pubKey, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileE)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	pubKeyComposite, ok := pubKey.(*suciutil.ProfileDPublicKeys)
	if !ok {
		t.Fatalf("Expected *ProfileDPublicKeys type, got %T", pubKey)
	}
	if len(pubKeyComposite.MLKEMPublic) != MLKEM768_PUBLIC_KEY_LEN {
		t.Errorf("Expected %d-byte ML-KEM public key, got %d", MLKEM768_PUBLIC_KEY_LEN, len(pubKeyComposite.MLKEMPublic))
	}
	if len(pubKeyComposite.X25519Public) != 32 {
		t.Errorf("Expected 32-byte X25519 public key, got %d", len(pubKeyComposite.X25519Public))
	}
}

// ============================================================================
// Profile F (Wrapper Hybrid) Tests
// ============================================================================

func TestSchemeID_ProfileF(t *testing.T) {
	scheme := SchemeProfileF
	if !scheme.IsValid() {
		t.Errorf("SchemeProfileF should be valid")
	}
	if !scheme.RequiresDecryption() {
		t.Errorf("SchemeProfileF should require decryption")
	}
	str := scheme.String()
	if !strings.Contains(str, "Wrapper") {
		t.Errorf("SchemeProfileF string should mention Wrapper, got: %s", str)
	}
}

func TestEncryptECIES_ProfileF_RoundTrip(t *testing.T) {
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	originalMSIN := "1234567890"
	msinBytes := mustEncodeMSINTBCD(t, originalMSIN)

	// Encrypt using Profile F
	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileF, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("EncryptECIES Profile F failed: %v", errCode.Error())
	}

	// Verify minimum length: KEMCT(1088) + EncEph(32) + PQCMAC(8) + EncMSIN + MAC(8)
	expectedMinLen := MLKEM768_CIPHERTEXT_LEN + ProfileF_EncEphLen + ProfileC_MAC_TAG_LEN + len(msinBytes) + MAC_TAG_LEN
	if len(schemeOutput) < expectedMinLen {
		t.Errorf("Scheme output too short: got %d, expected at least %d", len(schemeOutput), expectedMinLen)
	}

	// Parse the Profile F cryptogram
	profileFCg, errCode := ParseProfileFCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileFCryptogram failed: %v", errCode.Error())
	}

	// Verify parsed components
	if len(profileFCg.KEMCiphertext) != MLKEM768_CIPHERTEXT_LEN {
		t.Errorf("Expected %d-byte KEM CT, got %d", MLKEM768_CIPHERTEXT_LEN, len(profileFCg.KEMCiphertext))
	}
	if len(profileFCg.EncryptedEphKey) != ProfileF_EncEphLen {
		t.Errorf("Expected %d-byte encrypted eph key, got %d", ProfileF_EncEphLen, len(profileFCg.EncryptedEphKey))
	}
	if len(profileFCg.PQCMACTag) != ProfileC_MAC_TAG_LEN {
		t.Errorf("Expected %d-byte PQC MAC, got %d", ProfileC_MAC_TAG_LEN, len(profileFCg.PQCMACTag))
	}
	if len(profileFCg.MACTag) != MAC_TAG_LEN {
		t.Errorf("Expected %d-byte ECIES MAC, got %d", MAC_TAG_LEN, len(profileFCg.MACTag))
	}

	// Decrypt using Profile F
	decryptedMSIN, errCode := DecryptWrapperHybrid(profileFCg, keyPair.PrivateKey)
	if errCode != 0 {
		t.Fatalf("DecryptWrapperHybrid failed: %v", errCode.Error())
	}

	// Verify round-trip
	assertMSINTBCDEquals(t, decryptedMSIN, originalMSIN)
}

func TestEncryptECIES_ProfileF_EmptyMSIN(t *testing.T) {
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	msinBytes := []byte{}

	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileF, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("EncryptECIES Profile F failed with empty MSIN: %v", errCode.Error())
	}

	profileFCg, errCode := ParseProfileFCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileFCryptogram failed: %v", errCode.Error())
	}

	decryptedMSIN, errCode := DecryptWrapperHybrid(profileFCg, keyPair.PrivateKey)
	if errCode != 0 {
		t.Fatalf("DecryptWrapperHybrid failed: %v", errCode.Error())
	}

	if len(decryptedMSIN) != 0 {
		t.Errorf("Expected empty decrypted MSIN, got %d bytes", len(decryptedMSIN))
	}
}

func TestEncryptECIES_ProfileF_WrongKey(t *testing.T) {
	keyPair1, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}
	keyPair2, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	msinBytes := mustEncodeMSINTBCD(t, "1234567890")

	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair1.PublicKey, SchemeProfileF, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("EncryptECIES failed: %v", errCode.Error())
	}

	profileFCg, errCode := ParseProfileFCryptogram(schemeOutput)
	if errCode != 0 {
		t.Fatalf("ParseProfileFCryptogram failed: %v", errCode.Error())
	}

	_, errCode = DecryptWrapperHybrid(profileFCg, keyPair2.PrivateKey)
	if errCode == 0 {
		t.Errorf("Expected decryption to fail with wrong key")
	}
}

func TestGetPublicKeyFromPrivate_ProfileF(t *testing.T) {
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	pubKey, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileF)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	pubKeyComposite, ok := pubKey.(*suciutil.ProfileDPublicKeys)
	if !ok {
		t.Fatalf("Expected *ProfileDPublicKeys type, got %T", pubKey)
	}
	if len(pubKeyComposite.MLKEMPublic) != MLKEM768_PUBLIC_KEY_LEN {
		t.Errorf("Expected %d-byte ML-KEM public key, got %d", MLKEM768_PUBLIC_KEY_LEN, len(pubKeyComposite.MLKEMPublic))
	}
	if len(pubKeyComposite.X25519Public) != 32 {
		t.Errorf("Expected 32-byte X25519 public key, got %d", len(pubKeyComposite.X25519Public))
	}
}

// ============================================================================
// Profile E/F End-to-End Converter Tests
// ============================================================================

func TestProfileE_EndToEnd_Converter(t *testing.T) {
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	originalMSIN := "0123456789"
	msinBytes := mustEncodeMSINTBCD(t, originalMSIN)

	// Encrypt
	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileE, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("Encrypt failed: %v", errCode.Error())
	}

	// Construct SUCI string
	suciStr := suciutil.ConstructSUCI(suciutil.TypeIMSI, "001", "01", "0000", suciutil.SchemeProfileE, 0, schemeOutput)

	// Parse SUCI
	parsed, parseErr := suciutil.ParseSUCI(suciStr)
	if parseErr != 0 {
		t.Fatalf("ParseSUCI failed: %v", parseErr.Error())
	}
	if parsed.SchemeID != suciutil.SchemeProfileE {
		t.Errorf("Expected scheme ID %d, got %d", suciutil.SchemeProfileE, parsed.SchemeID)
	}

	// Parse cryptogram and decrypt
	profileECg, parseErr := suciutil.ParseProfileECryptogram(parsed.SchemeOutput)
	if parseErr != 0 {
		t.Fatalf("ParseProfileECryptogram failed: %v", parseErr.Error())
	}
	decrypted, decErr := suciutil.DecryptNestedHybrid(profileECg, keyPair.PrivateKey)
	if decErr != 0 {
		t.Fatalf("DecryptNestedHybrid failed: %v", decErr.Error())
	}
	assertMSINTBCDEquals(t, decrypted, originalMSIN)
}

func TestProfileF_EndToEnd_Converter(t *testing.T) {
	keyPair, err := generateProfileDKeyForTest()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	originalMSIN := "0123456789"
	msinBytes := mustEncodeMSINTBCD(t, originalMSIN)

	// Encrypt
	schemeOutput, errCode := EncryptECIES(msinBytes, keyPair.PublicKey, SchemeProfileF, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		t.Fatalf("Encrypt failed: %v", errCode.Error())
	}

	// Construct SUCI string
	suciStr := suciutil.ConstructSUCI(suciutil.TypeIMSI, "001", "01", "0000", suciutil.SchemeProfileF, 0, schemeOutput)

	// Parse SUCI
	parsed, parseErr := suciutil.ParseSUCI(suciStr)
	if parseErr != 0 {
		t.Fatalf("ParseSUCI failed: %v", parseErr.Error())
	}
	if parsed.SchemeID != suciutil.SchemeProfileF {
		t.Errorf("Expected scheme ID %d, got %d", suciutil.SchemeProfileF, parsed.SchemeID)
	}

	// Parse cryptogram and decrypt
	profileFCg, parseErr := suciutil.ParseProfileFCryptogram(parsed.SchemeOutput)
	if parseErr != 0 {
		t.Fatalf("ParseProfileFCryptogram failed: %v", parseErr.Error())
	}
	decrypted, decErr := suciutil.DecryptWrapperHybrid(profileFCg, keyPair.PrivateKey)
	if decErr != 0 {
		t.Fatalf("DecryptWrapperHybrid failed: %v", decErr.Error())
	}
	assertMSINTBCDEquals(t, decrypted, originalMSIN)
}

func TestProfileE_Constants(t *testing.T) {
	if ProfileE_EphPubKeyLen != 32 {
		t.Errorf("ProfileE_EphPubKeyLen should be 32, got %d", ProfileE_EphPubKeyLen)
	}
	expectedMinLen := 32 + 1088 + 8 + 8
	if ProfileE_MinLen != expectedMinLen {
		t.Errorf("ProfileE_MinLen should be %d, got %d", expectedMinLen, ProfileE_MinLen)
	}
}

func TestProfileF_Constants(t *testing.T) {
	if ProfileF_EncEphLen != 32 {
		t.Errorf("ProfileF_EncEphLen should be 32, got %d", ProfileF_EncEphLen)
	}
	expectedMinLen := 1088 + 32 + 8 + 8
	if ProfileF_MinLen != expectedMinLen {
		t.Errorf("ProfileF_MinLen should be %d, got %d", expectedMinLen, ProfileF_MinLen)
	}
}

func TestParseProfileECryptogram_TooShort(t *testing.T) {
	shortOutput := make([]byte, ProfileE_MinLen-1)
	_, errCode := ParseProfileECryptogram(shortOutput)
	if errCode == 0 {
		t.Errorf("Expected error for too short Profile E scheme output")
	}
}

func TestParseProfileFCryptogram_TooShort(t *testing.T) {
	shortOutput := make([]byte, ProfileF_MinLen-1)
	_, errCode := ParseProfileFCryptogram(shortOutput)
	if errCode == 0 {
		t.Errorf("Expected error for too short Profile F scheme output")
	}
}

func makeProfileGTestMaterial(level suciutil.MLKEMSecurityLevel, windowSize int64) (*ProfileGConcealmentKeys, *ProfileGKeyMaterial, string) {
	level = suciutil.NormalizeMLKEMSecurityLevel(level)
	keyLen := 16
	if level == suciutil.MLKEMSecurityLevel5 {
		keyLen = 32
	}
	hnKey := make([]byte, keyLen)
	for i := range hnKey {
		hnKey[i] = byte(i + 1)
	}
	subID := []byte{0x00, 0x11, 0x22, 0x33, 0x44}
	subHex := hex.EncodeToString(subID)
	kmaster := []byte{
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f,
	}
	keys := &ProfileGConcealmentKeys{
		SecurityLevel:     level,
		HNSymmetricKey:    append([]byte(nil), hnKey...),
		SubscriberKeyID:   append([]byte(nil), subID...),
		Kmaster:           append([]byte(nil), kmaster...),
		WindowSizeSeconds: windowSize,
	}
	material := &ProfileGKeyMaterial{
		HNKeyID:           1,
		SecurityLevel:     level,
		HNSymmetricKey:    append([]byte(nil), hnKey...),
		SubscriberKeys:    map[string][]byte{subHex: append([]byte(nil), kmaster...)},
		WindowSizeSeconds: windowSize,
	}
	return keys, material, subHex
}

func cloneProfileGCryptogram(in *ProfileGCryptogram) *ProfileGCryptogram {
	if in == nil {
		return nil
	}
	return &ProfileGCryptogram{
		R:             append([]byte(nil), in.R...),
		KeyCipherText: append([]byte(nil), in.KeyCipherText...),
		MACkey:        append([]byte(nil), in.MACkey...),
		Ciphertext:    append([]byte(nil), in.Ciphertext...),
		MACmsin:       append([]byte(nil), in.MACmsin...),
	}
}

func TestProfileG_RoundTrip_BothSecurityLevelsAndVariableMSIN(t *testing.T) {
	levels := []suciutil.MLKEMSecurityLevel{suciutil.MLKEMSecurityLevel3, suciutil.MLKEMSecurityLevel5}
	msins := []string{"1", "12", "12345", "1234567890"}
	for _, lvl := range levels {
		for _, msin := range msins {
			keys, material, _ := makeProfileGTestMaterial(lvl, suciutil.ProfileG_DefaultWindowSizeSeconds)
			msinBytes := mustEncodeMSINTBCD(t, msin)
			out, ec := EncryptECIES(msinBytes, keys, SchemeProfileG, suciutil.ProfileDVariantBaseline, lvl)
			if ec != 0 {
				t.Fatalf("EncryptECIES Profile G failed (level=%d, msin=%s): %s", lvl, msin, ec.Error())
			}
			cg, ec := ParseProfileGCryptogramForLevel(out, lvl)
			if ec != 0 {
				t.Fatalf("ParseProfileGCryptogramForLevel failed (level=%d): %s", lvl, ec.Error())
			}
			plain, ec := DecryptSymmetric(cg, material)
			if ec != 0 {
				t.Fatalf("DecryptSymmetric failed (level=%d, msin=%s): %s", lvl, msin, ec.Error())
			}
			assertMSINTBCDEquals(t, plain, msin)
		}
	}
}

func TestProfileG_MACAndKeyRejections(t *testing.T) {
	keys, material, subHex := makeProfileGTestMaterial(suciutil.MLKEMSecurityLevel3, suciutil.ProfileG_DefaultWindowSizeSeconds)
	msinBytes := mustEncodeMSINTBCD(t, "1234567890")
	out, ec := EncryptECIES(msinBytes, keys, SchemeProfileG, suciutil.ProfileDVariantBaseline, suciutil.MLKEMSecurityLevel3)
	if ec != 0 {
		t.Fatalf("EncryptECIES Profile G failed: %s", ec.Error())
	}
	cg, ec := ParseProfileGCryptogramForLevel(out, suciutil.MLKEMSecurityLevel3)
	if ec != 0 {
		t.Fatalf("ParseProfileGCryptogramForLevel failed: %s", ec.Error())
	}

	macKeyBroken := cloneProfileGCryptogram(cg)
	macKeyBroken.MACkey[0] ^= 0x01
	if _, ec = DecryptSymmetric(macKeyBroken, material); ec != E_TAG_MISMATCH {
		t.Fatalf("expected E_TAG_MISMATCH for MACkey tamper, got %v", ec)
	}

	macMSINBroken := cloneProfileGCryptogram(cg)
	macMSINBroken.MACmsin[0] ^= 0x01
	if _, ec = DecryptSymmetric(macMSINBroken, material); ec != E_TAG_MISMATCH {
		t.Fatalf("expected E_TAG_MISMATCH for MACmsin tamper, got %v", ec)
	}

	wrongHN := &ProfileGKeyMaterial{
		HNKeyID:           material.HNKeyID,
		SecurityLevel:     material.SecurityLevel,
		HNSymmetricKey:    append([]byte(nil), material.HNSymmetricKey...),
		SubscriberKeys:    map[string][]byte{subHex: append([]byte(nil), material.SubscriberKeys[subHex]...)},
		WindowSizeSeconds: material.WindowSizeSeconds,
	}
	wrongHN.HNSymmetricKey[0] ^= 0x01
	if _, ec = DecryptSymmetric(cg, wrongHN); ec != E_TAG_MISMATCH {
		t.Fatalf("expected E_TAG_MISMATCH for wrong HN key, got %v", ec)
	}

	wrongKmaster := &ProfileGKeyMaterial{
		HNKeyID:           material.HNKeyID,
		SecurityLevel:     material.SecurityLevel,
		HNSymmetricKey:    append([]byte(nil), material.HNSymmetricKey...),
		SubscriberKeys:    map[string][]byte{subHex: append([]byte(nil), material.SubscriberKeys[subHex]...)},
		WindowSizeSeconds: material.WindowSizeSeconds,
	}
	wrongKmaster.SubscriberKeys[subHex][0] ^= 0x01
	if _, ec = DecryptSymmetric(cg, wrongKmaster); ec != E_TAG_MISMATCH {
		t.Fatalf("expected E_TAG_MISMATCH for wrong Kmaster, got %v", ec)
	}
}

func TestProfileG_InvalidSubscriberKeyIDReturnsSpecificError(t *testing.T) {
	ks := keys.NewMemoryKeyStore()
	conv := NewConverter(ks)

	badIDs := []string{"1", "zz", "00112233", "001122334455", ""}
	for _, badID := range badIDs {
		cfg := ConcealmentConfig{
			SUPI:                    "imsi-123456789012345",
			SchemeID:                suciutil.SchemeProfileG,
			KeyID:                   1,
			ProfileGSubscriberKeyID: badID,
			RoutingInd:              "0000",
			KeyDirectory:            ".",
			MLKEMSecurityLevel:      suciutil.MLKEMSecurityLevel3,
		}
		result := conv.ConvertSUPItoSUCI(cfg)
		if result.IsSuccess() {
			t.Fatalf("expected failure for subscriber-key-id=%q, got success", badID)
		}
		ec := *result.Error
		if badID == "" {
			continue
		}
		if ec != suciutil.E_INVALID_SUBSCRIBER_KEY_ID {
			t.Errorf("subscriber-key-id=%q: expected E_INVALID_SUBSCRIBER_KEY_ID (0x305), got %v", badID, ec)
		}
	}
}

func TestProfileG_TimeWindowFallbackAndReplay(t *testing.T) {
	keys, material, _ := makeProfileGTestMaterial(suciutil.MLKEMSecurityLevel3, 1)
	msinBytes := mustEncodeMSINTBCD(t, "1234567890")
	out, ec := EncryptECIES(msinBytes, keys, SchemeProfileG, suciutil.ProfileDVariantBaseline, suciutil.MLKEMSecurityLevel3)
	if ec != 0 {
		t.Fatalf("EncryptECIES Profile G failed: %s", ec.Error())
	}
	cg, ec := ParseProfileGCryptogramForLevel(out, suciutil.MLKEMSecurityLevel3)
	if ec != 0 {
		t.Fatalf("ParseProfileGCryptogramForLevel failed: %s", ec.Error())
	}

	createdSec := time.Now().Unix()
	for time.Now().Unix() == createdSec {
		time.Sleep(10 * time.Millisecond)
	}

	plain1, ec := DecryptSymmetric(cg, material)
	if ec != 0 {
		t.Fatalf("DecryptSymmetric should succeed via previous-window fallback: %s", ec.Error())
	}
	assertMSINTBCDEquals(t, plain1, "1234567890")

	plain2, ec := DecryptSymmetric(cg, material)
	if ec != 0 {
		t.Fatalf("DecryptSymmetric replay should still succeed: %s", ec.Error())
	}
	assertMSINTBCDEquals(t, plain2, "1234567890")
}
