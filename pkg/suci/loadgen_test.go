package suci

import (
	"testing"

	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
)

func TestRunLoadGen_ProfileD_EndToEnd(t *testing.T) {
	cfg := LoadGenConfig{
		Mode:        LoadGenModeEndToEnd,
		Scheme:      suciutil.SchemeProfileD,
		N:           5,
		Concurrency: 1,
		Warmup:      0,
		MCC:         "001",
		MNC:         "01",
		RoutingInd:  "0000",
		MSIN:        "12345",
		KeyID:       1,
	}
	res, err := RunLoadGen(cfg)
	if err != nil {
		t.Fatalf("RunLoadGen end-to-end failed: %v", err)
	}
	if res.Errors != 0 {
		t.Fatalf("expected 0 errors, got %d", res.Errors)
	}
}

func TestRunLoadGen_ProfileD_DecryptOnly(t *testing.T) {
	cfg := LoadGenConfig{
		Mode:        LoadGenModeDecryptOnly,
		Scheme:      suciutil.SchemeProfileD,
		N:           5,
		Concurrency: 1,
		Warmup:      0,
		MCC:         "001",
		MNC:         "01",
		RoutingInd:  "0000",
		MSIN:        "12345",
		KeyID:       1,
	}
	res, err := RunLoadGen(cfg)
	if err != nil {
		t.Fatalf("RunLoadGen decrypt-only failed: %v", err)
	}
	if res.Errors != 0 {
		t.Fatalf("expected 0 errors, got %d", res.Errors)
	}
}

func TestRunLoadGen_ProfileE_EndToEnd(t *testing.T) {
	cfg := LoadGenConfig{
		Mode:        LoadGenModeEndToEnd,
		Scheme:      suciutil.SchemeProfileE,
		N:           5,
		Concurrency: 1,
		Warmup:      0,
		MCC:         "001",
		MNC:         "01",
		RoutingInd:  "0000",
		MSIN:        "12345",
		KeyID:       1,
	}
	res, err := RunLoadGen(cfg)
	if err != nil {
		t.Fatalf("RunLoadGen Profile E end-to-end failed: %v", err)
	}
	if res.Errors != 0 {
		t.Fatalf("expected 0 errors, got %d", res.Errors)
	}
}

func TestRunLoadGen_ProfileE_DecryptOnly(t *testing.T) {
	cfg := LoadGenConfig{
		Mode:        LoadGenModeDecryptOnly,
		Scheme:      suciutil.SchemeProfileE,
		N:           5,
		Concurrency: 1,
		Warmup:      0,
		MCC:         "001",
		MNC:         "01",
		RoutingInd:  "0000",
		MSIN:        "12345",
		KeyID:       1,
	}
	res, err := RunLoadGen(cfg)
	if err != nil {
		t.Fatalf("RunLoadGen Profile E decrypt-only failed: %v", err)
	}
	if res.Errors != 0 {
		t.Fatalf("expected 0 errors, got %d", res.Errors)
	}
}

func TestRunLoadGen_ProfileF_EndToEnd(t *testing.T) {
	cfg := LoadGenConfig{
		Mode:        LoadGenModeEndToEnd,
		Scheme:      suciutil.SchemeProfileF,
		N:           5,
		Concurrency: 1,
		Warmup:      0,
		MCC:         "001",
		MNC:         "01",
		RoutingInd:  "0000",
		MSIN:        "12345",
		KeyID:       1,
	}
	res, err := RunLoadGen(cfg)
	if err != nil {
		t.Fatalf("RunLoadGen Profile F end-to-end failed: %v", err)
	}
	if res.Errors != 0 {
		t.Fatalf("expected 0 errors, got %d", res.Errors)
	}
}

func TestRunLoadGen_ProfileF_DecryptOnly(t *testing.T) {
	cfg := LoadGenConfig{
		Mode:        LoadGenModeDecryptOnly,
		Scheme:      suciutil.SchemeProfileF,
		N:           5,
		Concurrency: 1,
		Warmup:      0,
		MCC:         "001",
		MNC:         "01",
		RoutingInd:  "0000",
		MSIN:        "12345",
		KeyID:       1,
	}
	res, err := RunLoadGen(cfg)
	if err != nil {
		t.Fatalf("RunLoadGen Profile F decrypt-only failed: %v", err)
	}
	if res.Errors != 0 {
		t.Fatalf("expected 0 errors, got %d", res.Errors)
	}
}

func TestRunLoadGen_ProfileG_EndToEnd(t *testing.T) {
	cfg := LoadGenConfig{
		Mode:                    LoadGenModeEndToEnd,
		Scheme:                  suciutil.SchemeProfileG,
		N:                       5,
		Concurrency:             1,
		Warmup:                  0,
		MCC:                     "001",
		MNC:                     "01",
		RoutingInd:              "0000",
		MSIN:                    "12345",
		KeyID:                   1,
		ProfileGSubscriberKeyID: "0011223344",
		MLKEMSecurityLevel:      suciutil.MLKEMSecurityLevel3,
	}
	res, err := RunLoadGen(cfg)
	if err != nil {
		t.Fatalf("RunLoadGen Profile G end-to-end failed: %v", err)
	}
	if res.Errors != 0 {
		t.Fatalf("expected 0 errors, got %d", res.Errors)
	}
}

func TestRunLoadGen_ProfileG_DecryptOnly(t *testing.T) {
	cfg := LoadGenConfig{
		Mode:                    LoadGenModeDecryptOnly,
		Scheme:                  suciutil.SchemeProfileG,
		N:                       5,
		Concurrency:             1,
		Warmup:                  0,
		MCC:                     "001",
		MNC:                     "01",
		RoutingInd:              "0000",
		MSIN:                    "12345",
		KeyID:                   1,
		ProfileGSubscriberKeyID: "0011223344",
		MLKEMSecurityLevel:      suciutil.MLKEMSecurityLevel3,
	}
	res, err := RunLoadGen(cfg)
	if err != nil {
		t.Fatalf("RunLoadGen Profile G decrypt-only failed: %v", err)
	}
	if res.Errors != 0 {
		t.Fatalf("expected 0 errors, got %d", res.Errors)
	}
}
