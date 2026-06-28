package suciutil

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeMSIN_TBCD_roundTrip(t *testing.T) {
	cases := []struct {
		msin string
		hex  string
	}{
		{"0123456789", "1032547698"},
		{"123456789", "21436587f9"},
		{"012345678901234", "10325476981032f4"},
		{"", ""},
		{"0", "f0"},
	}
	for _, tc := range cases {
		b, err := EncodeMSIN_TBCD(tc.msin)
		if err != nil {
			t.Fatalf("EncodeMSIN_TBCD(%q): %v", tc.msin, err)
		}
		if got := hexEncode(b); got != tc.hex {
			t.Fatalf("EncodeMSIN_TBCD(%q) hex got %q want %q", tc.msin, got, tc.hex)
		}
		s, err := DecodeMSIN_TBCD(b)
		if err != nil {
			t.Fatalf("DecodeMSIN_TBCD(%q): %v", tc.hex, err)
		}
		if s != tc.msin {
			t.Fatalf("round-trip %q: got %q", tc.msin, s)
		}
	}
}

func TestEncodeMSIN_TBCD_invalidDigit(t *testing.T) {
	_, err := EncodeMSIN_TBCD("12a4")
	if err != ErrInvalidMSINDigit {
		t.Fatalf("want ErrInvalidMSINDigit, got %v", err)
	}
}

func TestDecodeMSIN_TBCD_invalidNibble(t *testing.T) {
	_, err := DecodeMSIN_TBCD([]byte{0x1A})
	if err != ErrInvalidTBCDNibble {
		t.Fatalf("want ErrInvalidTBCDNibble, got %v", err)
	}
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	var buf bytes.Buffer
	for _, v := range b {
		buf.WriteByte(hexdigits[v>>4])
		buf.WriteByte(hexdigits[v&0x0f])
	}
	return buf.String()
}
