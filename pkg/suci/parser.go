package suci

import (
	"regexp"
)

// SUCI regex pattern
// Format: suci-<type>-<mcc>-<mnc>-<routingInd>-<schemeId>-<keyId>-<schemeOutput>
// - type: 0 or 1
// - mcc: exactly 3 digits
// - mnc: 2 or 3 digits
// - routingInd: 1 to 4 digits
// - schemeId: 0..7
// - keyId: 0 to 255
// - schemeOutput: hex string
var suciRegex = regexp.MustCompile(`^suci-([01])-(\d{3})-(\d{2,3})-(\d{1,4})-([0-7])-(\d{1,3})-([0-9a-fA-F]+)$`)

// ParseSUCI parses and validates a SUCI string
// (moved to suciutil)

// (Functions moved to suciutil/parser.go)
// ParseCryptogram extracts the components from the scheme output
// Returns Cryptogram structure or error
// func ParseCryptogram(schemeOutput []byte, scheme SchemeID) (*Cryptogram, ErrorCode)

// ParsePQCCryptogram extracts the components from the PQC Profile C scheme output
// Structure: KEMCiphertext (1088) || EncryptedMSIN || MACTag (8)
// func ParsePQCCryptogram(schemeOutput []byte) (*PQCCryptogram, ErrorCode)

// MSIN is encoded as TBCD only; see compat.go EncodeMSIN_TBCD / DecodeMSIN_TBCD.

// ConstructSUPI constructs the final SUPI from MCC, MNC, and MSIN
// func ConstructSUPI(identityType IdentityType, mcc, mnc, msin string) (string, ErrorCode)
