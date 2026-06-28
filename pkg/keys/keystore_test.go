package keys

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
)

func makePEMBlock(t *testing.T, typ string, size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i % 256)
	}
	block := &pem.Block{Type: typ, Bytes: b}
	return pem.EncodeToMemory(block)
}

func TestEnvKeyStore_ProfileD(t *testing.T) {
	os.Setenv("HN_KEY_1_PROFILE_D_MLKEM", string(makePEMBlock(t, "ML-KEM-768 PRIVATE KEY", 2400)))
	os.Setenv("HN_KEY_1_PROFILE_D_X25519", string(makePEMBlock(t, "X25519 PRIVATE KEY", 32)))
	defer os.Unsetenv("HN_KEY_1_PROFILE_D_MLKEM")
	defer os.Unsetenv("HN_KEY_1_PROFILE_D_X25519")

	e := NewEnvKeyStore()
	key, err := e.GetPrivateKey(1, suciutil.SchemeProfileD)
	if err != nil {
		t.Fatalf("EnvKeyStore GetPrivateKey failed: %v", err)
	}
	pd, ok := key.(*suciutil.ProfileDPrivateKeys)
	if !ok {
		t.Fatalf("expected *ProfileDPrivateKeys, got %T", key)
	}
	if len(pd.MLKEMPrivate) != 2400 || len(pd.X25519Private) != 32 {
		t.Fatalf("unexpected key lengths: mlkem=%d x=%d", len(pd.MLKEMPrivate), len(pd.X25519Private))
	}
}

func TestFileKeyStore_SingleFile_ProfileD(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "hn-key-1-profile-d.pem")
	f, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("create file failed: %v", err)
	}
	defer f.Close()

	f.Write(makePEMBlock(t, "ML-KEM-768 PRIVATE KEY", 2400))
	f.Write(makePEMBlock(t, "X25519 PRIVATE KEY", 32))

	ks := NewFileKeyStore(tmpDir)
	key, err := ks.GetPrivateKey(1, suciutil.SchemeProfileD)
	if err != nil {
		t.Fatalf("FileKeyStore GetPrivateKey failed: %v", err)
	}
	pd, ok := key.(*suciutil.ProfileDPrivateKeys)
	if !ok {
		t.Fatalf("expected *ProfileDPrivateKeys, got %T", key)
	}
	if len(pd.MLKEMPrivate) != 2400 || len(pd.X25519Private) != 32 {
		t.Fatalf("unexpected key lengths: mlkem=%d x=%d", len(pd.MLKEMPrivate), len(pd.X25519Private))
	}
}

func TestEnvKeyStore_ProfileE(t *testing.T) {
	os.Setenv("HN_KEY_2_PROFILE_E_MLKEM", string(makePEMBlock(t, "ML-KEM-768 PRIVATE KEY", 2400)))
	os.Setenv("HN_KEY_2_PROFILE_E_X25519", string(makePEMBlock(t, "X25519 PRIVATE KEY", 32)))
	defer os.Unsetenv("HN_KEY_2_PROFILE_E_MLKEM")
	defer os.Unsetenv("HN_KEY_2_PROFILE_E_X25519")

	e := NewEnvKeyStore()
	key, err := e.GetPrivateKey(2, suciutil.SchemeProfileE)
	if err != nil {
		t.Fatalf("EnvKeyStore GetPrivateKey Profile E failed: %v", err)
	}
	pd, ok := key.(*suciutil.ProfileDPrivateKeys)
	if !ok {
		t.Fatalf("expected *ProfileDPrivateKeys, got %T", key)
	}
	if len(pd.MLKEMPrivate) != 2400 || len(pd.X25519Private) != 32 {
		t.Fatalf("unexpected key lengths: mlkem=%d x=%d", len(pd.MLKEMPrivate), len(pd.X25519Private))
	}
}

func TestEnvKeyStore_ProfileF(t *testing.T) {
	os.Setenv("HN_KEY_3_PROFILE_F_MLKEM", string(makePEMBlock(t, "ML-KEM-768 PRIVATE KEY", 2400)))
	os.Setenv("HN_KEY_3_PROFILE_F_X25519", string(makePEMBlock(t, "X25519 PRIVATE KEY", 32)))
	defer os.Unsetenv("HN_KEY_3_PROFILE_F_MLKEM")
	defer os.Unsetenv("HN_KEY_3_PROFILE_F_X25519")

	e := NewEnvKeyStore()
	key, err := e.GetPrivateKey(3, suciutil.SchemeProfileF)
	if err != nil {
		t.Fatalf("EnvKeyStore GetPrivateKey Profile F failed: %v", err)
	}
	pd, ok := key.(*suciutil.ProfileDPrivateKeys)
	if !ok {
		t.Fatalf("expected *ProfileDPrivateKeys, got %T", key)
	}
	if len(pd.MLKEMPrivate) != 2400 || len(pd.X25519Private) != 32 {
		t.Fatalf("unexpected key lengths: mlkem=%d x=%d", len(pd.MLKEMPrivate), len(pd.X25519Private))
	}
}

func TestFileKeyStore_SingleFile_ProfileE(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "hn-key-1-profile-e.pem")
	f, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("create file failed: %v", err)
	}
	defer f.Close()

	f.Write(makePEMBlock(t, "ML-KEM-768 PRIVATE KEY", 2400))
	f.Write(makePEMBlock(t, "X25519 PRIVATE KEY", 32))

	ks := NewFileKeyStore(tmpDir)
	key, err := ks.GetPrivateKey(1, suciutil.SchemeProfileE)
	if err != nil {
		t.Fatalf("FileKeyStore GetPrivateKey Profile E failed: %v", err)
	}
	pd, ok := key.(*suciutil.ProfileDPrivateKeys)
	if !ok {
		t.Fatalf("expected *ProfileDPrivateKeys, got %T", key)
	}
	if len(pd.MLKEMPrivate) != 2400 || len(pd.X25519Private) != 32 {
		t.Fatalf("unexpected key lengths: mlkem=%d x=%d", len(pd.MLKEMPrivate), len(pd.X25519Private))
	}
}

func TestFileKeyStore_SingleFile_ProfileF(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "hn-key-1-profile-f.pem")
	f, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("create file failed: %v", err)
	}
	defer f.Close()

	f.Write(makePEMBlock(t, "ML-KEM-768 PRIVATE KEY", 2400))
	f.Write(makePEMBlock(t, "X25519 PRIVATE KEY", 32))

	ks := NewFileKeyStore(tmpDir)
	key, err := ks.GetPrivateKey(1, suciutil.SchemeProfileF)
	if err != nil {
		t.Fatalf("FileKeyStore GetPrivateKey Profile F failed: %v", err)
	}
	pd, ok := key.(*suciutil.ProfileDPrivateKeys)
	if !ok {
		t.Fatalf("expected *ProfileDPrivateKeys, got %T", key)
	}
	if len(pd.MLKEMPrivate) != 2400 || len(pd.X25519Private) != 32 {
		t.Fatalf("unexpected key lengths: mlkem=%d x=%d", len(pd.MLKEMPrivate), len(pd.X25519Private))
	}
}

func TestFileKeyStore_ProfileG_LoadsMainAndSubscribers(t *testing.T) {
	tmpDir := t.TempDir()

	mainFile := filepath.Join(tmpDir, "hn-key-1-profile-g.json")
	mainObj := map[string]interface{}{
		"profile":              "g",
		"security_level":       3,
		"hn_symmetric_key_hex": "00112233445566778899aabbccddeeff",
		"window_size_seconds":  3600,
	}
	mainBytes, err := json.Marshal(mainObj)
	if err != nil {
		t.Fatalf("marshal main profile-g json: %v", err)
	}
	if err := os.WriteFile(mainFile, mainBytes, 0600); err != nil {
		t.Fatalf("write main profile-g json: %v", err)
	}

	subsFile := filepath.Join(tmpDir, "hn-key-1-profile-g-subscribers.json")
	subsObj := map[string]interface{}{
		"subscribers": map[string]string{
			"0011223344": "00112233445566778899aabbccddeeff",
		},
	}
	subsBytes, err := json.Marshal(subsObj)
	if err != nil {
		t.Fatalf("marshal subscribers profile-g json: %v", err)
	}
	if err := os.WriteFile(subsFile, subsBytes, 0600); err != nil {
		t.Fatalf("write subscribers profile-g json: %v", err)
	}

	ks := NewFileKeyStore(tmpDir)
	key, err := ks.GetPrivateKey(1, suciutil.SchemeProfileG)
	if err != nil {
		t.Fatalf("FileKeyStore GetPrivateKey Profile G failed: %v", err)
	}
	material, ok := key.(*suciutil.ProfileGKeyMaterial)
	if !ok {
		t.Fatalf("expected *ProfileGKeyMaterial, got %T", key)
	}
	if len(material.HNSymmetricKey) != 16 {
		t.Fatalf("unexpected HN symmetric key length: %d", len(material.HNSymmetricKey))
	}
	if material.SecurityLevel != suciutil.MLKEMSecurityLevel3 {
		t.Fatalf("unexpected security level: %d", material.SecurityLevel)
	}
	if len(material.SubscriberKeys) != 1 {
		t.Fatalf("expected 1 subscriber key mapping, got %d", len(material.SubscriberKeys))
	}
	if len(material.SubscriberKeys["0011223344"]) != 16 {
		t.Fatalf("expected 16-byte Kmaster for subscriber 0011223344")
	}
}

func TestSingleFileKeyStore_ProfileG_LoadsSubscribers(t *testing.T) {
	tmpDir := t.TempDir()
	mainFile := filepath.Join(tmpDir, "hn-key-1-profile-g.json")
	subsFile := filepath.Join(tmpDir, "hn-key-1-profile-g-subscribers.json")
	if err := os.WriteFile(mainFile, []byte(`{"profile":"g","security_level":3,"hn_symmetric_key_hex":"00112233445566778899aabbccddeeff","window_size_seconds":3600}`), 0600); err != nil {
		t.Fatalf("write main profile-g json: %v", err)
	}
	if err := os.WriteFile(subsFile, []byte(`{"subscribers":{"0011223344":"00112233445566778899aabbccddeeff"}}`), 0600); err != nil {
		t.Fatalf("write subscribers profile-g json: %v", err)
	}

	suciStr := "suci-0-001-01-0000-7-1-" + strings.Repeat("00", suciutil.ProfileG_Level3_MinLen)
	ks := NewSingleFileKeyStore(mainFile, suciStr)
	key, err := ks.GetPrivateKey(1, suciutil.SchemeProfileG)
	if err != nil {
		t.Fatalf("SingleFileKeyStore GetPrivateKey Profile G failed: %v", err)
	}
	material, ok := key.(*suciutil.ProfileGKeyMaterial)
	if !ok {
		t.Fatalf("expected *ProfileGKeyMaterial, got %T", key)
	}
	if len(material.SubscriberKeys) == 0 {
		t.Fatalf("expected subscriber key map to be loaded for Profile G single-file keystore")
	}
}
