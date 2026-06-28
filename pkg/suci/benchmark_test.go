package suci

import (
	"sync"
	"testing"

	"github.com/harishmurkal/suci-supi-tool/pkg/keys"
	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
)

const (
	benchMCC        = "001"
	benchMNC        = "01"
	benchRoutingInd = "0000"
	benchMSIN       = "1234567890" // 10 digits
	benchKeyID      = uint8(1)
)

type lockedKeyStore struct {
	mu   sync.RWMutex
	base *keys.MemoryKeyStore
}

func newLockedKeyStore() *lockedKeyStore {
	return &lockedKeyStore{base: keys.NewMemoryKeyStore()}
}

func (s *lockedKeyStore) AddKey(keyID uint8, scheme suciutil.SchemeID, privateKey interface{}) {
	s.mu.Lock()
	s.base.AddKey(keyID, scheme, privateKey)
	s.mu.Unlock()
}

func (s *lockedKeyStore) GetPrivateKey(keyID uint8, scheme suciutil.SchemeID) (interface{}, error) {
	s.mu.RLock()
	key, err := s.base.GetPrivateKey(keyID, scheme)
	s.mu.RUnlock()
	return key, err
}

func mustBenchmarkInput(b *testing.B, scheme SchemeID) (converter *Converter, suciStr string, parsed *ParsedSUCI, cryptogram *Cryptogram, privateKey interface{}) {
	b.Helper()

	ks := keys.NewMemoryKeyStore()

	var keyScheme suciutil.SchemeID
	switch scheme {
	case SchemeProfileA:
		keyScheme = suciutil.SchemeProfileA
	case SchemeProfileB:
		keyScheme = suciutil.SchemeProfileB
	case SchemeProfileC:
		keyScheme = suciutil.SchemeProfileC
	default:
		b.Fatalf("unsupported scheme: %d", scheme)
	}

	keyPair, err := keys.GenerateKeyPair(benchKeyID, keyScheme)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}
	ks.AddKey(benchKeyID, keyScheme, keyPair.PrivateKey)

	converter = NewConverter(ks)

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, keyScheme)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}
	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)
	schemeOutput, errCode := EncryptECIES(msinBytes, pub, scheme, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		b.Fatalf("EncryptECIES failed: %s", errCode.Error())
	}

	suciStr = ConstructSUCI(TypeIMSI, benchMCC, benchMNC, benchRoutingInd, scheme, benchKeyID, schemeOutput)

	parsedUtil, parseErr := suciutil.ParseSUCI(suciStr)
	if parseErr != 0 {
		b.Fatalf("ParseSUCI failed: %s", parseErr.Error())
	}

	cryptogramUtil, parseErr2 := suciutil.ParseCryptogram(parsedUtil.SchemeOutput, parsedUtil.SchemeID)
	if parseErr2 != 0 {
		b.Fatalf("ParseCryptogram failed: %s", parseErr2.Error())
	}

	// Convert suciutil types into local suci package types for benchmarks
	parsed = &ParsedSUCI{
		Type:         IdentityType(parsedUtil.Type),
		MCC:          parsedUtil.MCC,
		MNC:          parsedUtil.MNC,
		RoutingInd:   parsedUtil.RoutingInd,
		SchemeID:     SchemeID(parsedUtil.SchemeID),
		KeyID:        parsedUtil.KeyID,
		SchemeOutput: parsedUtil.SchemeOutput,
	}

	cryptogram = &Cryptogram{
		EphemeralPublicKey: cryptogramUtil.EphemeralPublicKey,
		Ciphertext:         cryptogramUtil.Ciphertext,
		MACTag:             cryptogramUtil.MACTag,
	}

	return converter, suciStr, parsed, cryptogram, keyPair.PrivateKey
}

func BenchmarkConvertSUCItoSUPI_NullScheme_EndToEnd(b *testing.B) {
	// NULL-SCHEME uses plaintext MSIN, no key store and no crypto.
	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)
	suciStr := ConstructSUCI(TypeIMSI, benchMCC, benchMNC, benchRoutingInd, SchemeNullScheme, 0, msinBytes)

	converter := NewConverter(keys.NewMemoryKeyStore())

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res := converter.ConvertSUCItoSUPI(suciStr)
		if !res.IsSuccess() {
			b.Fatalf("conversion failed: %s", res.GetErrorString())
		}
	}
}

func BenchmarkConvertSUCItoSUPI_ProfileA_EndToEnd(b *testing.B) {
	converter, suciStr, _, _, _ := mustBenchmarkInput(b, SchemeProfileA)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res := converter.ConvertSUCItoSUPI(suciStr)
		if !res.IsSuccess() {
			b.Fatalf("conversion failed: %s", res.GetErrorString())
		}
	}
}

func BenchmarkConvertSUCItoSUPI_ProfileB_EndToEnd(b *testing.B) {
	converter, suciStr, _, _, _ := mustBenchmarkInput(b, SchemeProfileB)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res := converter.ConvertSUCItoSUPI(suciStr)
		if !res.IsSuccess() {
			b.Fatalf("conversion failed: %s", res.GetErrorString())
		}
	}
}

// Decrypt-only benchmarks exclude regex parsing and SUCI construction.
// This approximates the crypto+decode cost per request when the caller already parsed the input.

func BenchmarkDeconceal_ProfileA_DecryptOnly(b *testing.B) {
	_, _, _, cryptogram, privateKey := mustBenchmarkInput(b, SchemeProfileA)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		plaintext, errCode := DecryptECIES(cryptogram, privateKey, SchemeProfileA)
		if errCode != 0 {
			b.Fatalf("DecryptECIES failed: %s", errCode.Error())
		}
		if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
			b.Fatalf("DecodeMSIN_TBCD failed: %s", errCode.Error())
		}
	}
}

func BenchmarkDeconceal_ProfileB_DecryptOnly(b *testing.B) {
	_, _, _, cryptogram, privateKey := mustBenchmarkInput(b, SchemeProfileB)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		plaintext, errCode := DecryptECIES(cryptogram, privateKey, SchemeProfileB)
		if errCode != 0 {
			b.Fatalf("DecryptECIES failed: %s", errCode.Error())
		}
		if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
			b.Fatalf("DecodeMSIN_TBCD failed: %s", errCode.Error())
		}
	}
}

func BenchmarkParseSUCI_ProfileA(b *testing.B) {
	_, suciStr, _, _, _ := mustBenchmarkInput(b, SchemeProfileA)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, errCode := suciutil.ParseSUCI(suciStr); errCode != 0 {
			b.Fatalf("ParseSUCI failed: %s", errCode.Error())
		}
	}
}

func BenchmarkParseSUCI_ProfileB(b *testing.B) {
	_, suciStr, _, _, _ := mustBenchmarkInput(b, SchemeProfileB)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, errCode := suciutil.ParseSUCI(suciStr); errCode != 0 {
			b.Fatalf("ParseSUCI failed: %s", errCode.Error())
		}
	}
}

// Parallel benchmark: measures crypto cost under concurrency without key-store contention.
// Each goroutine uses the same private key and cryptogram (read-only).
func BenchmarkDeconceal_ProfileA_DecryptOnly_Parallel(b *testing.B) {
	_, _, _, cryptogram, privateKey := mustBenchmarkInput(b, SchemeProfileA)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plaintext, errCode := DecryptECIES(cryptogram, privateKey, SchemeProfileA)
			if errCode != 0 {
				b.Fatalf("DecryptECIES failed: %s", errCode.Error())
			}
			if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
				b.Fatalf("DecodeMSIN_TBCD failed: %s", errCode.Error())
			}
		}
	})
}

// mustBenchmarkInputPQC creates test fixtures for PQC Profile C benchmarks.
// Profile C uses ML-KEM-768 (PQC) instead of ECIES.
func mustBenchmarkInputPQC(b *testing.B) (converter *Converter, suciStr string, parsed *ParsedSUCI, pqcCryptogram *PQCCryptogram, privateKey interface{}) {
	b.Helper()

	ks := keys.NewMemoryKeyStore()

	keyPair, err := keys.GenerateKeyPair(benchKeyID, suciutil.SchemeProfileC)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}
	ks.AddKey(benchKeyID, suciutil.SchemeProfileC, keyPair.PrivateKey)

	converter = NewConverter(ks)

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileC)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)
	schemeOutput, errCode := EncryptECIES(msinBytes, pub, SchemeProfileC, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		b.Fatalf("EncryptECIES (Profile C) failed: %s", errCode.Error())
	}

	suciStr = ConstructSUCI(TypeIMSI, benchMCC, benchMNC, benchRoutingInd, SchemeProfileC, benchKeyID, schemeOutput)

	parsedUtil, parseErr := suciutil.ParseSUCI(suciStr)
	if parseErr != 0 {
		b.Fatalf("ParseSUCI failed: %s", parseErr.Error())
	}

	pqcUtil, parseErr2 := suciutil.ParsePQCCryptogram(parsedUtil.SchemeOutput)
	if parseErr2 != 0 {
		b.Fatalf("ParsePQCCryptogram failed: %s", parseErr2.Error())
	}

	parsed = &ParsedSUCI{
		Type:         IdentityType(parsedUtil.Type),
		MCC:          parsedUtil.MCC,
		MNC:          parsedUtil.MNC,
		RoutingInd:   parsedUtil.RoutingInd,
		SchemeID:     SchemeID(parsedUtil.SchemeID),
		KeyID:        parsedUtil.KeyID,
		SchemeOutput: parsedUtil.SchemeOutput,
	}

	pqcCryptogram = &PQCCryptogram{
		KEMCiphertext: pqcUtil.KEMCiphertext,
		Ciphertext:    pqcUtil.Ciphertext,
		MACTag:        pqcUtil.MACTag,
	}

	return converter, suciStr, parsed, pqcCryptogram, keyPair.PrivateKey
}

// mustBenchmarkInputHybridVariant creates test fixtures for Hybrid Profile D benchmarks
// with a specific variant (baseline, add17, add19).
func mustBenchmarkInputHybridVariant(b *testing.B, variant suciutil.ProfileDVariant) (converter *Converter, suciStr string, parsed *ParsedSUCI, hybridCryptogram *HybridCryptogram, privateKey interface{}) {
	b.Helper()

	ks := keys.NewMemoryKeyStore()

	keyPair, err := keys.GenerateKeyPair(benchKeyID, suciutil.SchemeProfileD)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}
	ks.AddKey(benchKeyID, suciutil.SchemeProfileD, keyPair.PrivateKey)

	converter = NewConverter(ks)

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileD)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)
	schemeOutput, errCode := EncryptECIES(msinBytes, pub, SchemeProfileD, variant)
	if errCode != 0 {
		b.Fatalf("EncryptECIES (Profile D %s) failed: %s", variant, errCode.Error())
	}

	suciStr = ConstructSUCI(TypeIMSI, benchMCC, benchMNC, benchRoutingInd, SchemeProfileD, benchKeyID, schemeOutput)

	parsedUtil, parseErr := suciutil.ParseSUCI(suciStr)
	if parseErr != 0 {
		b.Fatalf("ParseSUCI failed: %s", parseErr.Error())
	}

	hgUtil, parseErr2 := suciutil.ParseProfileDCryptogram(parsedUtil.SchemeOutput)
	if parseErr2 != 0 {
		b.Fatalf("ParseProfileDCryptogram failed: %s", parseErr2.Error())
	}

	parsed = &ParsedSUCI{
		Type:         IdentityType(parsedUtil.Type),
		MCC:          parsedUtil.MCC,
		MNC:          parsedUtil.MNC,
		RoutingInd:   parsedUtil.RoutingInd,
		SchemeID:     SchemeID(parsedUtil.SchemeID),
		KeyID:        parsedUtil.KeyID,
		SchemeOutput: parsedUtil.SchemeOutput,
	}

	hybridCryptogram = &HybridCryptogram{
		KEMCiphertext:      hgUtil.KEMCiphertext,
		EphemeralPublicKey: hgUtil.EphemeralPublicKey,
		Variant:            hgUtil.Variant,
		Nonce:              hgUtil.Nonce,
		Ciphertext:         hgUtil.Ciphertext,
		MACTag:             hgUtil.MACTag,
	}

	return converter, suciStr, parsed, hybridCryptogram, keyPair.PrivateKey
}

// mustBenchmarkInputHybrid creates test fixtures for Hybrid Profile D benchmarks (baseline variant).
func mustBenchmarkInputHybrid(b *testing.B) (converter *Converter, suciStr string, parsed *ParsedSUCI, hybridCryptogram *HybridCryptogram, privateKey interface{}) {
	return mustBenchmarkInputHybridVariant(b, suciutil.ProfileDVariantBaseline)
}

// BenchmarkConvertSUCItoSUPI_ProfileD_EndToEnd benchmarks end-to-end SUCI->SUPI
// conversion with Hybrid Profile D (ML-KEM-768 + X25519).
func BenchmarkConvertSUCItoSUPI_ProfileD_EndToEnd(b *testing.B) {
	converter, suciStr, _, _, _ := mustBenchmarkInputHybrid(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res := converter.ConvertSUCItoSUPI(suciStr)
		if !res.IsSuccess() {
			b.Fatalf("ConvertSUCItoSUPI failed: %s", res.GetErrorString())
		}
	}
}

// BenchmarkDeconceal_ProfileD_DecryptOnly benchmarks Hybrid Profile D decryption
// (ML-KEM-768 decapsulation + X25519 ECDH + AES-256-CTR + KMAC256 verification).
func BenchmarkDeconceal_ProfileD_DecryptOnly(b *testing.B) {
	_, _, _, hybridCryptogram, privateKey := mustBenchmarkInputHybrid(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		plaintext, errCode := DecryptHybrid(hybridCryptogram, privateKey)
		if errCode != 0 {
			b.Fatalf("DecryptHybrid failed: %s", errCode.Error())
		}
		if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
			b.Fatalf("DecodeMSIN_TBCD failed: %s", errCode.Error())
		}
	}
}

// BenchmarkParseSUCI_ProfileD benchmarks SUCI parsing for Profile D.
func BenchmarkParseSUCI_ProfileD(b *testing.B) {
	_, suciStr, _, _, _ := mustBenchmarkInputHybrid(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, errCode := suciutil.ParseSUCI(suciStr); errCode != 0 {
			b.Fatalf("ParseSUCI failed: %s", errCode.Error())
		}
	}
}

// BenchmarkDeconceal_ProfileD_DecryptOnly_Parallel benchmarks hybrid decryption under concurrency.
func BenchmarkDeconceal_ProfileD_DecryptOnly_Parallel(b *testing.B) {
	_, _, _, hybridCryptogram, privateKey := mustBenchmarkInputHybrid(b)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plaintext, errCode := DecryptHybrid(hybridCryptogram, privateKey)
			if errCode != 0 {
				b.Fatalf("DecryptHybrid failed: %s", errCode.Error())
			}
			if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
				b.Fatalf("DecodeMSIN_TBCD failed: %s", errCode.Error())
			}
		}
	})
}

// BenchmarkEncrypt_ProfileD benchmarks hybrid encryption (ML-KEM-768 encapsulation + X25519 ephemeral + AES-256-CTR + KMAC256).
func BenchmarkEncrypt_ProfileD(b *testing.B) {
	keyPair, err := keys.GenerateKeyPair(benchKeyID, suciutil.SchemeProfileD)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileD)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, errCode := EncryptECIES(msinBytes, pub, SchemeProfileD, suciutil.ProfileDVariantBaseline)
		if errCode != 0 {
			b.Fatalf("EncryptECIES (Profile D) failed: %s", errCode.Error())
		}
	}
}

// BenchmarkConvertSUCItoSUPI_ProfileD_Add17_EndToEnd benchmarks end-to-end SUCI->SUPI
// conversion with Hybrid Profile D using the add17 variant (AES-256-CTR with 128-bit nonce).
func BenchmarkConvertSUCItoSUPI_ProfileD_Add17_EndToEnd(b *testing.B) {
	converter, suciStr, _, _, _ := mustBenchmarkInputHybridVariant(b, suciutil.ProfileDVariantAdd17)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res := converter.ConvertSUCItoSUPI(suciStr)
		if !res.IsSuccess() {
			b.Fatalf("ConvertSUCItoSUPI failed: %s", res.GetErrorString())
		}
	}
}

// BenchmarkConvertSUCItoSUPI_ProfileD_Add19_EndToEnd benchmarks end-to-end SUCI->SUPI
// conversion with Hybrid Profile D using the add19 variant (AES-256-GCM with 96-bit nonce).
func BenchmarkConvertSUCItoSUPI_ProfileD_Add19_EndToEnd(b *testing.B) {
	converter, suciStr, _, _, _ := mustBenchmarkInputHybridVariant(b, suciutil.ProfileDVariantAdd19)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res := converter.ConvertSUCItoSUPI(suciStr)
		if !res.IsSuccess() {
			b.Fatalf("ConvertSUCItoSUPI failed: %s", res.GetErrorString())
		}
	}
}

// BenchmarkDeconceal_ProfileD_Add17_DecryptOnly benchmarks Hybrid Profile D add17
// decryption (ML-KEM-768 + X25519 + AES-256-CTR with 128-bit nonce + KMAC256).
func BenchmarkDeconceal_ProfileD_Add17_DecryptOnly(b *testing.B) {
	_, _, _, hybridCryptogram, privateKey := mustBenchmarkInputHybridVariant(b, suciutil.ProfileDVariantAdd17)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		plaintext, errCode := DecryptHybrid(hybridCryptogram, privateKey)
		if errCode != 0 {
			b.Fatalf("DecryptHybrid failed: %s", errCode.Error())
		}
		if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
			b.Fatalf("DecodeMSIN_TBCD failed: %s", errCode.Error())
		}
	}
}

// BenchmarkDeconceal_ProfileD_Add19_DecryptOnly benchmarks Hybrid Profile D add19
// decryption (ML-KEM-768 + X25519 + AES-256-GCM with 96-bit nonce).
func BenchmarkDeconceal_ProfileD_Add19_DecryptOnly(b *testing.B) {
	_, _, _, hybridCryptogram, privateKey := mustBenchmarkInputHybridVariant(b, suciutil.ProfileDVariantAdd19)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		plaintext, errCode := DecryptHybrid(hybridCryptogram, privateKey)
		if errCode != 0 {
			b.Fatalf("DecryptHybrid failed: %s", errCode.Error())
		}
		if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
			b.Fatalf("DecodeMSIN_TBCD failed: %s", errCode.Error())
		}
	}
}

// BenchmarkDeconceal_ProfileD_Add17_DecryptOnly_Parallel benchmarks add17 hybrid decryption under concurrency.
func BenchmarkDeconceal_ProfileD_Add17_DecryptOnly_Parallel(b *testing.B) {
	_, _, _, hybridCryptogram, privateKey := mustBenchmarkInputHybridVariant(b, suciutil.ProfileDVariantAdd17)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plaintext, errCode := DecryptHybrid(hybridCryptogram, privateKey)
			if errCode != 0 {
				b.Fatalf("DecryptHybrid failed: %s", errCode.Error())
			}
			if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
				b.Fatalf("DecodeMSIN_TBCD failed: %s", errCode.Error())
			}
		}
	})
}

// BenchmarkDeconceal_ProfileD_Add19_DecryptOnly_Parallel benchmarks add19 hybrid decryption under concurrency.
func BenchmarkDeconceal_ProfileD_Add19_DecryptOnly_Parallel(b *testing.B) {
	_, _, _, hybridCryptogram, privateKey := mustBenchmarkInputHybridVariant(b, suciutil.ProfileDVariantAdd19)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plaintext, errCode := DecryptHybrid(hybridCryptogram, privateKey)
			if errCode != 0 {
				b.Fatalf("DecryptHybrid failed: %s", errCode.Error())
			}
			if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
				b.Fatalf("DecodeMSIN_TBCD failed: %s", errCode.Error())
			}
		}
	})
}

// BenchmarkEncrypt_ProfileD_Add17 benchmarks hybrid encryption with the add17 variant
// (ML-KEM-768 + X25519 + AES-256-CTR with 128-bit nonce + KMAC256).
func BenchmarkEncrypt_ProfileD_Add17(b *testing.B) {
	keyPair, err := keys.GenerateKeyPair(benchKeyID, suciutil.SchemeProfileD)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileD)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, errCode := EncryptECIES(msinBytes, pub, SchemeProfileD, suciutil.ProfileDVariantAdd17)
		if errCode != 0 {
			b.Fatalf("EncryptECIES (Profile D add17) failed: %s", errCode.Error())
		}
	}
}

// BenchmarkEncrypt_ProfileD_Add19 benchmarks hybrid encryption with the add19 variant
// (ML-KEM-768 + X25519 + AES-256-GCM with 96-bit nonce).
func BenchmarkEncrypt_ProfileD_Add19(b *testing.B) {
	keyPair, err := keys.GenerateKeyPair(benchKeyID, suciutil.SchemeProfileD)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileD)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, errCode := EncryptECIES(msinBytes, pub, SchemeProfileD, suciutil.ProfileDVariantAdd19)
		if errCode != 0 {
			b.Fatalf("EncryptECIES (Profile D add19) failed: %s", errCode.Error())
		}
	}
}

// BenchmarkConvertSUCItoSUPI_ProfileC_EndToEnd benchmarks end-to-end SUCI->SUPI
// conversion with PQC Profile C (ML-KEM-768).
func BenchmarkConvertSUCItoSUPI_ProfileC_EndToEnd(b *testing.B) {
	converter, suciStr, _, _, _ := mustBenchmarkInputPQC(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res := converter.ConvertSUCItoSUPI(suciStr)
		if !res.IsSuccess() {
			b.Fatalf("ConvertSUCItoSUPI failed: %s", res.GetErrorString())
		}
	}
}

// BenchmarkDeconceal_ProfileC_DecryptOnly benchmarks ML-KEM-768 decapsulation
// and AES-256-CTR decryption with KMAC256 verification.
func BenchmarkDeconceal_ProfileC_DecryptOnly(b *testing.B) {
	_, _, _, pqcCryptogram, privateKey := mustBenchmarkInputPQC(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		plaintext, errCode := DecryptPQC(pqcCryptogram, privateKey)
		if errCode != 0 {
			b.Fatalf("DecryptPQC failed: %s", errCode.Error())
		}
		if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
			b.Fatalf("DecodeMSIN_TBCD failed: %s", errCode.Error())
		}
	}
}

// BenchmarkParseSUCI_ProfileC benchmarks SUCI parsing for Profile C.
func BenchmarkParseSUCI_ProfileC(b *testing.B) {
	_, suciStr, _, _, _ := mustBenchmarkInputPQC(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, errCode := suciutil.ParseSUCI(suciStr); errCode != 0 {
			b.Fatalf("ParseSUCI failed: %s", errCode.Error())
		}
	}
}

// BenchmarkDeconceal_ProfileC_DecryptOnly_Parallel benchmarks PQC decryption
// under concurrency (ML-KEM-768 + AES-256-CTR + KMAC256).
func BenchmarkDeconceal_ProfileC_DecryptOnly_Parallel(b *testing.B) {
	_, _, _, pqcCryptogram, privateKey := mustBenchmarkInputPQC(b)

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plaintext, errCode := DecryptPQC(pqcCryptogram, privateKey)
			if errCode != 0 {
				b.Fatalf("DecryptPQC failed: %s", errCode.Error())
			}
			if _, errCode := suciutil.DecodeMSIN_TBCDCode(plaintext); errCode != 0 {
				b.Fatalf("DecodeMSIN_TBCD failed: %s", errCode.Error())
			}
		}
	})
}

func mustBenchmarkInputProfileG(b *testing.B, level suciutil.MLKEMSecurityLevel) (converter *Converter, suciStr string, cryptogram *ProfileGCryptogram, material *suciutil.ProfileGKeyMaterial) {
	b.Helper()
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
	kmaster := []byte{
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f,
	}
	subHex := "0011223344"
	material = &suciutil.ProfileGKeyMaterial{
		HNKeyID:           benchKeyID,
		SecurityLevel:     level,
		HNSymmetricKey:    hnKey,
		SubscriberKeys:    map[string][]byte{subHex: kmaster},
		WindowSizeSeconds: suciutil.ProfileG_DefaultWindowSizeSeconds,
	}

	ks := newLockedKeyStore()
	ks.AddKey(benchKeyID, suciutil.SchemeProfileG, material)
	converter = NewConverter(ks)

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)
	gKeys := &suciutil.ProfileGConcealmentKeys{
		SecurityLevel:     level,
		HNSymmetricKey:    hnKey,
		SubscriberKeyID:   subID,
		Kmaster:           kmaster,
		WindowSizeSeconds: suciutil.ProfileG_DefaultWindowSizeSeconds,
	}
	out, errCode := EncryptECIES(msinBytes, gKeys, SchemeProfileG, suciutil.ProfileDVariantBaseline, level)
	if errCode != 0 {
		b.Fatalf("EncryptECIES (Profile G) failed: %s", errCode.Error())
	}
	suciStr = ConstructSUCI(TypeIMSI, benchMCC, benchMNC, benchRoutingInd, SchemeProfileG, benchKeyID, out)
	cg, errCode := ParseProfileGCryptogramForLevel(out, level)
	if errCode != 0 {
		b.Fatalf("ParseProfileGCryptogramForLevel failed: %s", errCode.Error())
	}
	cryptogram = cg
	return converter, suciStr, cryptogram, material
}

func BenchmarkConvertSUCItoSUPI_ProfileG_EndToEnd_Level3(b *testing.B) {
	converter, suciStr, _, _ := mustBenchmarkInputProfileG(b, suciutil.MLKEMSecurityLevel3)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := converter.ConvertSUCItoSUPI(suciStr)
		if !res.IsSuccess() {
			b.Fatalf("ConvertSUCItoSUPI Profile G failed: %s", res.GetErrorString())
		}
	}
}

func BenchmarkConvertSUCItoSUPI_ProfileG_EndToEnd_Level5(b *testing.B) {
	converter, suciStr, _, _ := mustBenchmarkInputProfileG(b, suciutil.MLKEMSecurityLevel5)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := converter.ConvertSUCItoSUPIWithConfig(suciStr, DeconcealConfig{MLKEMSecurityLevel: suciutil.MLKEMSecurityLevel5})
		if !res.IsSuccess() {
			b.Fatalf("ConvertSUCItoSUPI Profile G L5 failed: %s", res.GetErrorString())
		}
	}
}

// BenchmarkEncrypt_ProfileC benchmarks ML-KEM-768 encapsulation with AES-256-CTR
// encryption and KMAC256 MAC computation.
func BenchmarkEncrypt_ProfileC(b *testing.B) {
	keyPair, err := keys.GenerateKeyPair(benchKeyID, suciutil.SchemeProfileC)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileC)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, errCode := EncryptECIES(msinBytes, pub, SchemeProfileC, suciutil.ProfileDVariantBaseline)
		if errCode != 0 {
			b.Fatalf("EncryptECIES (Profile C) failed: %s", errCode.Error())
		}
	}
}

// BenchmarkEncrypt_ProfileA benchmarks ECIES Profile A encryption for comparison.
func BenchmarkEncrypt_ProfileA(b *testing.B) {
	keyPair, err := keys.GenerateKeyPair(benchKeyID, suciutil.SchemeProfileA)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileA)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, errCode := EncryptECIES(msinBytes, pub, SchemeProfileA, suciutil.ProfileDVariantBaseline)
		if errCode != 0 {
			b.Fatalf("EncryptECIES (Profile A) failed: %s", errCode.Error())
		}
	}
}

// BenchmarkEncrypt_ProfileB benchmarks ECIES Profile B encryption for comparison.
func BenchmarkEncrypt_ProfileB(b *testing.B) {
	keyPair, err := keys.GenerateKeyPair(benchKeyID, suciutil.SchemeProfileB)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileB)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, errCode := EncryptECIES(msinBytes, pub, SchemeProfileB, suciutil.ProfileDVariantBaseline)
		if errCode != 0 {
			b.Fatalf("EncryptECIES (Profile B) failed: %s", errCode.Error())
		}
	}
}

// mustBenchmarkInputNestedHybrid creates test fixtures for Profile E benchmarks.
func mustBenchmarkInputNestedHybrid(b *testing.B) (converter *Converter, suciStr string, privateKey interface{}) {
	b.Helper()

	ks := keys.NewMemoryKeyStore()

	keyPair, err := keys.GenerateKeyPair(benchKeyID, suciutil.SchemeProfileE)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}
	ks.AddKey(benchKeyID, suciutil.SchemeProfileE, keyPair.PrivateKey)

	converter = NewConverter(ks)

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileE)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)
	schemeOutput, errCode := EncryptECIES(msinBytes, pub, SchemeProfileE, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		b.Fatalf("EncryptECIES (Profile E) failed: %s", errCode.Error())
	}

	suciStr = ConstructSUCI(TypeIMSI, benchMCC, benchMNC, benchRoutingInd, SchemeProfileE, benchKeyID, schemeOutput)

	return converter, suciStr, keyPair.PrivateKey
}

// mustBenchmarkInputWrapperHybrid creates test fixtures for Profile F benchmarks.
func mustBenchmarkInputWrapperHybrid(b *testing.B) (converter *Converter, suciStr string, privateKey interface{}) {
	b.Helper()

	ks := keys.NewMemoryKeyStore()

	keyPair, err := keys.GenerateKeyPair(benchKeyID, suciutil.SchemeProfileF)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}
	ks.AddKey(benchKeyID, suciutil.SchemeProfileF, keyPair.PrivateKey)

	converter = NewConverter(ks)

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileF)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)
	schemeOutput, errCode := EncryptECIES(msinBytes, pub, SchemeProfileF, suciutil.ProfileDVariantBaseline)
	if errCode != 0 {
		b.Fatalf("EncryptECIES (Profile F) failed: %s", errCode.Error())
	}

	suciStr = ConstructSUCI(TypeIMSI, benchMCC, benchMNC, benchRoutingInd, SchemeProfileF, benchKeyID, schemeOutput)

	return converter, suciStr, keyPair.PrivateKey
}

func BenchmarkConvertSUCItoSUPI_ProfileE_EndToEnd(b *testing.B) {
	converter, suciStr, _ := mustBenchmarkInputNestedHybrid(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res := converter.ConvertSUCItoSUPI(suciStr)
		if !res.IsSuccess() {
			b.Fatalf("ConvertSUCItoSUPI failed: %s", res.GetErrorString())
		}
	}
}

func BenchmarkConvertSUCItoSUPI_ProfileF_EndToEnd(b *testing.B) {
	converter, suciStr, _ := mustBenchmarkInputWrapperHybrid(b)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res := converter.ConvertSUCItoSUPI(suciStr)
		if !res.IsSuccess() {
			b.Fatalf("ConvertSUCItoSUPI failed: %s", res.GetErrorString())
		}
	}
}

func BenchmarkEncrypt_ProfileE(b *testing.B) {
	keyPair, err := keys.GenerateKeyPair(benchKeyID, suciutil.SchemeProfileE)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileE)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, errCode := EncryptECIES(msinBytes, pub, SchemeProfileE, suciutil.ProfileDVariantBaseline)
		if errCode != 0 {
			b.Fatalf("EncryptECIES (Profile E) failed: %s", errCode.Error())
		}
	}
}

func BenchmarkEncrypt_ProfileF(b *testing.B) {
	keyPair, err := keys.GenerateKeyPair(benchKeyID, suciutil.SchemeProfileF)
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pub, err := suciutil.GetPublicKeyFromPrivate(keyPair.PrivateKey, suciutil.SchemeProfileF)
	if err != nil {
		b.Fatalf("GetPublicKeyFromPrivate failed: %v", err)
	}

	msinBytes, _ := suciutil.EncodeMSIN_TBCDCode(benchMSIN)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, errCode := EncryptECIES(msinBytes, pub, SchemeProfileF, suciutil.ProfileDVariantBaseline)
		if errCode != 0 {
			b.Fatalf("EncryptECIES (Profile F) failed: %s", errCode.Error())
		}
	}
}
