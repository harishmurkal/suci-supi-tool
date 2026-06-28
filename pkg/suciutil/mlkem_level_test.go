package suciutil

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func TestMLKEM1024MarshalLengthsMatchConstants(t *testing.T) {
	pub768, priv768, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pb768, err := pub768.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sk768, err := priv768.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(pb768) != MLKEM768_PUBLIC_KEY_LEN || len(sk768) != MLKEM768_PRIVATE_KEY_LEN {
		t.Fatalf("768: got pk=%d sk=%d want %d/%d", len(pb768), len(sk768), MLKEM768_PUBLIC_KEY_LEN, MLKEM768_PRIVATE_KEY_LEN)
	}

	pub1024, priv1024, err := mlkem1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pb1024, err := pub1024.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sk1024, err := priv1024.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(pb1024) != MLKEM1024_PUBLIC_KEY_LEN || len(sk1024) != MLKEM1024_PRIVATE_KEY_LEN {
		t.Fatalf("1024: got pk=%d sk=%d want %d/%d", len(pb1024), len(sk1024), MLKEM1024_PUBLIC_KEY_LEN, MLKEM1024_PRIVATE_KEY_LEN)
	}
	ct, _, err := mlkem1024.Scheme().Encapsulate(pub1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) != MLKEM1024_CIPHERTEXT_LEN {
		t.Fatalf("1024 ct len %d want %d", len(ct), MLKEM1024_CIPHERTEXT_LEN)
	}
}
