package keys

import (
	"fmt"

	"github.com/harishmurkal/suci-supi-tool/pkg/suciutil"
)

// SingleFileKeyStore implements KeyStore for a single PEM file, mapped to the keyID and scheme in the SUCI string.
type SingleFileKeyStore struct {
	keyFile string
	keyID   uint8
	scheme  suciutil.SchemeID
	key     interface{}
	loaded  bool
}

// NewSingleFileKeyStore creates a KeyStore that loads the keyFile and maps it to the keyID/scheme in the SUCI string.
func NewSingleFileKeyStore(keyFile string, suciStr string) *SingleFileKeyStore {
	parsed, errCode := suciutil.ParseSUCI(suciStr)
	if errCode != 0 {
		return &SingleFileKeyStore{keyFile: keyFile, loaded: false}
	}
	return &SingleFileKeyStore{
		keyFile: keyFile,
		keyID:   parsed.KeyID,
		scheme:  parsed.SchemeID,
		loaded:  false,
	}
}

// GetPrivateKey returns the loaded key only if keyID and scheme match
func (s *SingleFileKeyStore) GetPrivateKey(keyID uint8, scheme suciutil.SchemeID) (interface{}, error) {
	if !s.loaded {
		key, err := loadPrivateKeyFromFile(s.keyFile, scheme)
		if err != nil {
			return nil, err
		}
		s.key = key
		s.loaded = true
	}
	if keyID == s.keyID && scheme == s.scheme {
		return s.key, nil
	}
	return nil, fmt.Errorf("key not found for keyID=%d scheme=%d", keyID, scheme)
}
