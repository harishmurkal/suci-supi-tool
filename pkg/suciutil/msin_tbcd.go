package suciutil

import (
	"errors"
	"strings"
)

var (
	// ErrInvalidMSINDigit is returned when MSIN contains a non-decimal digit.
	ErrInvalidMSINDigit = errors.New("msin: invalid digit (expected 0-9)")
	// ErrInvalidTBCDNibble is returned when TBCD data contains an invalid nibble.
	ErrInvalidTBCDNibble = errors.New("msin: invalid TBCD nibble")
)

// EncodeMSIN_TBCD encodes an MSIN as 3GPP-style TBCD: first digit in the low nibble,
// second in the high nibble; if the digit count is odd, the high nibble of the last byte is 0xF.
func EncodeMSIN_TBCD(msin string) ([]byte, error) {
	if msin == "" {
		return []byte{}, nil
	}
	n := len(msin)
	out := make([]byte, (n+1)/2)
	for i := 0; i < n; i += 2 {
		c := msin[i]
		if c < '0' || c > '9' {
			return nil, ErrInvalidMSINDigit
		}
		low := c - '0'
		var high byte = 0xF
		if i+1 < n {
			c2 := msin[i+1]
			if c2 < '0' || c2 > '9' {
				return nil, ErrInvalidMSINDigit
			}
			high = c2 - '0'
		}
		out[i/2] = low | (high << 4)
	}
	return out, nil
}

// DecodeMSIN_TBCD decodes TBCD bytes to decimal digits: low nibble first, then high;
// a high nibble of 0xF in the last byte is padding (odd digit count).
func DecodeMSIN_TBCD(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}
	var b strings.Builder
	last := len(data) - 1
	for i, v := range data {
		low := v & 0x0F
		high := (v >> 4) & 0x0F
		if low > 9 {
			return "", ErrInvalidTBCDNibble
		}
		b.WriteByte('0' + low)
		if i == last {
			if high == 0x0F {
				break
			}
			if high > 9 {
				return "", ErrInvalidTBCDNibble
			}
			b.WriteByte('0' + high)
			break
		}
		if high > 9 {
			return "", ErrInvalidTBCDNibble
		}
		b.WriteByte('0' + high)
	}
	return b.String(), nil
}

// EncodeMSIN_TBCDCode encodes MSIN as TBCD and maps errors to E_MSIN_ENCODING.
func EncodeMSIN_TBCDCode(msin string) ([]byte, ErrorCode) {
	b, err := EncodeMSIN_TBCD(msin)
	if err != nil {
		return nil, E_MSIN_ENCODING
	}
	return b, 0
}

// DecodeMSIN_TBCDCode decodes TBCD MSIN bytes and maps errors to E_MSIN_ENCODING.
func DecodeMSIN_TBCDCode(data []byte) (string, ErrorCode) {
	s, err := DecodeMSIN_TBCD(data)
	if err != nil {
		return "", E_MSIN_ENCODING
	}
	return s, 0
}
