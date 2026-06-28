package suci

import (
	"testing"

	"github.com/harishmurkal/suci-supi-tool/pkg/keys"
	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
)

func TestProfileC_MLKEM1024_EncryptDecryptRoundTrip(t *testing.T) {
	kp, err := keys.GenerateKeyPair(7, suciutil.SchemeProfileC, suciutil.MLKEMSecurityLevel5)
	if err != nil {
		t.Fatal(err)
	}
	msin, encErr := suciutil.EncodeMSIN_TBCDCode("1234567890")
	if encErr != 0 {
		t.Fatalf("EncodeMSIN: %v", encErr)
	}
	out, ecode := EncryptECIES(msin, kp.PublicKey, SchemeProfileC, suciutil.ProfileDVariantBaseline, suciutil.MLKEMSecurityLevel5)
	if ecode != 0 {
		t.Fatalf("EncryptECIES: %s", ecode.Error())
	}
	cg, perr := ParsePQCCryptogramForLevel(out, suciutil.MLKEMSecurityLevel5)
	if perr != 0 {
		t.Fatalf("ParsePQCCryptogramForLevel: %s", perr.Error())
	}
	pt, derr := DecryptPQC(cg, kp.PrivateKey)
	if derr != 0 {
		t.Fatalf("DecryptPQC: %s", derr.Error())
	}
	s, decErr := suciutil.DecodeMSIN_TBCDCode(pt)
	if decErr != 0 {
		t.Fatalf("DecodeMSIN: %v", decErr)
	}
	if s != "1234567890" {
		t.Fatalf("msin got %q", s)
	}
}

func TestProfileD_MLKEM1024_EncryptDecryptRoundTrip(t *testing.T) {
	kp, err := keys.GenerateKeyPair(8, suciutil.SchemeProfileD, suciutil.MLKEMSecurityLevel5)
	if err != nil {
		t.Fatal(err)
	}
	msin, encErr := suciutil.EncodeMSIN_TBCDCode("9876543210")
	if encErr != 0 {
		t.Fatalf("EncodeMSIN: %v", encErr)
	}
	out, ecode := EncryptECIES(msin, kp.PublicKey, SchemeProfileD, suciutil.ProfileDVariantBaseline, suciutil.MLKEMSecurityLevel5)
	if ecode != 0 {
		t.Fatalf("EncryptECIES: %s", ecode.Error())
	}
	hg, perr := ParseProfileDCryptogramForLevel(out, suciutil.MLKEMSecurityLevel5)
	if perr != 0 {
		t.Fatalf("ParseProfileDCryptogramForLevel: %s", perr.Error())
	}
	pt, derr := DecryptHybrid(hg, kp.PrivateKey)
	if derr != 0 {
		t.Fatalf("DecryptHybrid: %s", derr.Error())
	}
	s, decErr := suciutil.DecodeMSIN_TBCDCode(pt)
	if decErr != 0 {
		t.Fatalf("DecodeMSIN: %v", decErr)
	}
	if s != "9876543210" {
		t.Fatalf("msin got %q", s)
	}
}

func TestProfileC_DefaultLevelStill768(t *testing.T) {
	kp, err := keys.GenerateKeyPair(0, suciutil.SchemeProfileC)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := kp.PublicKey.([]byte)
	if !ok {
		t.Fatal("expected []byte public key")
	}
	priv, ok := kp.PrivateKey.([]byte)
	if !ok {
		t.Fatal("expected []byte private key")
	}
	msin, _ := suciutil.EncodeMSIN_TBCDCode("1111222233")
	out, ecode := EncryptECIES(msin, pub, SchemeProfileC, suciutil.ProfileDVariantBaseline)
	if ecode != 0 {
		t.Fatalf("EncryptECIES: %s", ecode.Error())
	}
	cg, perr := ParsePQCCryptogram(out)
	if perr != 0 {
		t.Fatalf("parse: %s", perr.Error())
	}
	pt, derr := DecryptPQC(cg, priv)
	if derr != 0 {
		t.Fatalf("decrypt: %s", derr.Error())
	}
	s, _ := suciutil.DecodeMSIN_TBCDCode(pt)
	if s != "1111222233" {
		t.Fatalf("got %q", s)
	}
}
