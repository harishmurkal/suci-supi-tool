package suci

import (
	"encoding/hex"
	"testing"

	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
)

func TestParseSUCI_ValidIMSI(t *testing.T) {
	// NULL-SCHEME: MSIN 0123456789 as TBCD (5 bytes) -> hex 1032547698
	suci := "suci-0-123-45-012-0-0-1032547698"
	parsed, errCode := ParseSUCI(suci)

	if errCode != 0 {
		t.Fatalf("Expected no error, got: %v", errCode)
	}

	if parsed.Type != TypeIMSI {
		t.Errorf("Expected type IMSI (0), got: %d", parsed.Type)
	}
	if parsed.MCC != "123" {
		t.Errorf("Expected MCC '123', got: '%s'", parsed.MCC)
	}
	if parsed.MNC != "45" {
		t.Errorf("Expected MNC '45', got: '%s'", parsed.MNC)
	}
	if parsed.SchemeID != SchemeNullScheme {
		t.Errorf("Expected SchemeID 0, got: %d", parsed.SchemeID)
	}
}

func TestParseSUCI_InvalidFormat(t *testing.T) {
	invalidSUCIs := []string{
		"invalid-string",
		"suci-2-123-45-012-0-0-abc", // Invalid type
		"suci-0-12-45-012-0-0-abc",  // Invalid MCC (2 digits)
		"suci-0-123-4-012-0-0-abc",  // Invalid MNC (1 digit)
		"suci-0-123-45-012-3-0-abc", // Invalid scheme ID
		"suci-0-123-45-012-0-0-xyz", // Invalid hex
	}

	for _, suci := range invalidSUCIs {
		_, errCode := ParseSUCI(suci)
		if errCode == 0 {
			t.Errorf("Expected error for invalid SUCI: %s", suci)
		}
	}
}

func TestDecodeMSIN_TBCD(t *testing.T) {
	msinBytes := []byte{0x10, 0x32, 0x54, 0x76, 0x98}
	msin, errCode := DecodeMSIN_TBCD(msinBytes)
	if errCode != 0 {
		t.Fatalf("Expected no error, got: %v", errCode)
	}
	if msin != "0123456789" {
		t.Errorf("Expected '0123456789', got: '%s'", msin)
	}
}

func TestEncodeMSIN_TBCD_specExample(t *testing.T) {
	// 3GPP TBCD: "789012345" -> 87 09 21 43 F5
	b, err := suciutil.EncodeMSIN_TBCD("789012345")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x87, 0x09, 0x21, 0x43, 0xF5}
	if len(b) != len(want) {
		t.Fatalf("len %d, want %d", len(b), len(want))
	}
	for i := range want {
		if b[i] != want[i] {
			t.Errorf("byte[%d] got %02x want %02x", i, b[i], want[i])
		}
	}
}

func TestConstructSUPI_IMSI(t *testing.T) {
	supi, errCode := ConstructSUPI(TypeIMSI, "123", "45", "0123456789")

	if errCode != 0 {
		t.Fatalf("Expected no error, got: %v", errCode)
	}
	expected := "imsi-123450123456789"
	if supi != expected {
		t.Errorf("Expected '%s', got: '%s'", expected, supi)
	}
}

func TestConstructSUPI_InvalidIMSILength(t *testing.T) {
	// Too short (4 digits total)
	_, errCode := ConstructSUPI(TypeIMSI, "123", "4", "")
	if errCode != E_INVALID_IMSI_LENGTH {
		t.Errorf("Expected E_INVALID_IMSI_LENGTH for short IMSI")
	}

	// Too long (16 digits total)
	_, errCode = ConstructSUPI(TypeIMSI, "123", "45", "01234567890")
	if errCode != E_INVALID_IMSI_LENGTH {
		t.Errorf("Expected E_INVALID_IMSI_LENGTH for long IMSI")
	}
}

func TestParseCryptogram_ProfileA(t *testing.T) {
	// Profile A: 32 bytes pubkey + TBCD ciphertext (e.g. 5 bytes) + 8 bytes MAC = 45 bytes
	mockCryptogram := make([]byte, 45)
	for i := 0; i < 32; i++ {
		mockCryptogram[i] = byte(i) // Mock pubkey
	}
	for i := 32; i < 37; i++ {
		mockCryptogram[i] = byte(i) // Mock ciphertext
	}
	for i := 37; i < 45; i++ {
		mockCryptogram[i] = 0xFF // Mock MAC
	}

	parsed, errCode := ParseCryptogram(mockCryptogram, SchemeProfileA)
	if errCode != 0 {
		t.Fatalf("Expected no error, got: %v", errCode)
	}

	if len(parsed.EphemeralPublicKey) != 32 {
		t.Errorf("Expected 32-byte pubkey, got: %d", len(parsed.EphemeralPublicKey))
	}
	if len(parsed.Ciphertext) != 5 {
		t.Errorf("Expected 5-byte ciphertext, got: %d", len(parsed.Ciphertext))
	}
	if len(parsed.MACTag) != 8 {
		t.Errorf("Expected 8-byte MAC, got: %d", len(parsed.MACTag))
	}
}

func TestParseCryptogram_TooShort(t *testing.T) {
	// Profile A requires minimum 40 bytes
	shortCryptogram := make([]byte, 30)
	_, errCode := ParseCryptogram(shortCryptogram, SchemeProfileA)

	if errCode != E_SCHEME_OUTPUT_TOO_SHORT {
		t.Errorf("Expected E_SCHEME_OUTPUT_TOO_SHORT, got: %v", errCode)
	}
}

func TestErrorCode_String(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		expected string
	}{
		{E_PARSE_SUCI, "error-0101: Invalid SUCI format"},
		{E_TAG_MISMATCH, "error-0202: MAC verification failed"},
		{E_UNKNOWN_KEY_ID, "error-0304: Key ID not found in key store"},
	}

	for _, tt := range tests {
		result := tt.code.Error()
		if result != tt.expected {
			t.Errorf("Expected '%s', got: '%s'", tt.expected, result)
		}
	}
}

func TestSchemeID_String(t *testing.T) {
	tests := []struct {
		scheme   SchemeID
		expected string
	}{
		{SchemeNullScheme, "NULL-SCHEME"},
		{SchemeProfileA, "ECIES-Profile-A (Curve25519)"},
		{SchemeProfileB, "ECIES-Profile-B (secp256r1)"},
	}

	for _, tt := range tests {
		result := tt.scheme.String()
		if result != tt.expected {
			t.Errorf("Expected '%s', got: '%s'", tt.expected, result)
		}
	}
}

func TestSchemeID_IsValid(t *testing.T) {
	if !SchemeNullScheme.IsValid() {
		t.Error("SchemeNullScheme should be valid")
	}
	if !SchemeProfileA.IsValid() {
		t.Error("SchemeProfileA should be valid")
	}
	if !SchemeProfileB.IsValid() {
		t.Error("SchemeProfileB should be valid")
	}
	if SchemeID(99).IsValid() {
		t.Error("Scheme ID 99 should be invalid")
	}
}

// Benchmark tests
func BenchmarkParseSUCI(b *testing.B) {
	suci := "suci-0-123-45-012-2-101-0253fd4d2ccb9603c12dcfd179c2e71e"
	for i := 0; i < b.N; i++ {
		ParseSUCI(suci)
	}
}

func BenchmarkDecodeMSIN_TBCD(b *testing.B) {
	msinBytes := []byte{0x10, 0x32, 0x54, 0x76, 0x98}
	for i := 0; i < b.N; i++ {
		_, _ = DecodeMSIN_TBCD(msinBytes)
	}
}

func BenchmarkHexDecode(b *testing.B) {
	hexStr := "0253fd4d2ccb9603c12dcfd179c2e71e1234567890abcdef"
	for i := 0; i < b.N; i++ {
		hex.DecodeString(hexStr)
	}
}

func TestParseSUCI_ProfileG_Valid(t *testing.T) {
	schemeOutput := make([]byte, suciutil.ProfileG_Level3_MinLen)
	for i := range schemeOutput {
		schemeOutput[i] = byte(i + 1)
	}
	suci := "suci-0-001-01-0000-7-1-" + hex.EncodeToString(schemeOutput)
	parsed, errCode := ParseSUCI(suci)
	if errCode != 0 {
		t.Fatalf("expected Profile G SUCI parse success, got: %v", errCode)
	}
	if parsed.SchemeID != SchemeProfileG {
		t.Fatalf("expected SchemeProfileG, got %d", parsed.SchemeID)
	}
	if parsed.KeyID != 1 {
		t.Fatalf("expected key ID 1, got %d", parsed.KeyID)
	}
	if len(parsed.SchemeOutput) != suciutil.ProfileG_Level3_MinLen {
		t.Fatalf("expected scheme output len %d, got %d", suciutil.ProfileG_Level3_MinLen, len(parsed.SchemeOutput))
	}
}

func TestParseProfileGCryptogramForLevel_LengthChecks(t *testing.T) {
	short := make([]byte, suciutil.ProfileG_Level3_MinLen-1)
	if _, errCode := ParseProfileGCryptogramForLevel(short, suciutil.MLKEMSecurityLevel3); errCode != E_SCHEME_OUTPUT_TOO_SHORT {
		t.Fatalf("expected E_SCHEME_OUTPUT_TOO_SHORT for short Profile G L3, got %v", errCode)
	}
}

func TestParseProfileGCryptogramForLevel_Level5Layout(t *testing.T) {
	r := make([]byte, suciutil.ProfileG_Level5_RLen)
	keyCipher := make([]byte, suciutil.ProfileG_KeyCipherTextLen)
	macKey := make([]byte, suciutil.ProfileG_Level5_MACLen)
	cipherText := []byte{0x10, 0x20, 0x30, 0x40}
	macMSIN := make([]byte, suciutil.ProfileG_Level5_MACLen)
	for i := range r {
		r[i] = byte(0xA0 + i)
	}
	for i := range keyCipher {
		keyCipher[i] = byte(0xB0 + i)
	}
	out := append(append(append(append(append([]byte{}, r...), keyCipher...), macKey...), cipherText...), macMSIN...)

	cg, errCode := ParseProfileGCryptogramForLevel(out, suciutil.MLKEMSecurityLevel5)
	if errCode != 0 {
		t.Fatalf("ParseProfileGCryptogramForLevel L5 failed: %v", errCode)
	}
	if len(cg.R) != suciutil.ProfileG_Level5_RLen {
		t.Fatalf("unexpected R len: %d", len(cg.R))
	}
	if len(cg.KeyCipherText) != suciutil.ProfileG_KeyCipherTextLen {
		t.Fatalf("unexpected KeyCipherText len: %d", len(cg.KeyCipherText))
	}
	if len(cg.MACkey) != suciutil.ProfileG_Level5_MACLen {
		t.Fatalf("unexpected MACkey len: %d", len(cg.MACkey))
	}
	if len(cg.Ciphertext) != len(cipherText) {
		t.Fatalf("unexpected Ciphertext len: %d", len(cg.Ciphertext))
	}
	if len(cg.MACmsin) != suciutil.ProfileG_Level5_MACLen {
		t.Fatalf("unexpected MACmsin len: %d", len(cg.MACmsin))
	}
}
