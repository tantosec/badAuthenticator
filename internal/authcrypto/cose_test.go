package authcrypto

import "testing"

func TestGetAlgorithmByNameIsCaseInsensitive(t *testing.T) {
	tests := map[string]int64{
		"ES256": COSEAlgorithmES256,
		"es384": COSEAlgorithmES384,
		"Rs256": COSEAlgorithmRS256,
		"ps256": COSEAlgorithmPS256,
		"PS384": COSEAlgorithmPS384,
		"ps512": COSEAlgorithmPS512,
		"EdDSA": COSEAlgorithmEdDSA,
		"eddsa": COSEAlgorithmEdDSA,
	}

	for name, want := range tests {
		got, ok := GetAlgorithmByName(name)
		if !ok {
			t.Fatalf("GetAlgorithmByName(%q) returned ok=false", name)
		}
		if got != want {
			t.Fatalf("GetAlgorithmByName(%q) = %d, want %d", name, got, want)
		}
	}
}
