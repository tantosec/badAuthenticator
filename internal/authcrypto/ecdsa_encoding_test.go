package authcrypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestECDSAPublicKeyEncodingPreservesLeadingZeros(t *testing.T) {
	tests := []struct {
		name           string
		provider       CryptographyProvider
		curve          ecdh.Curve
		ecdsaCurve     elliptic.Curve
		coordinateSize int
		scalar         int
		zeroOffset     int
	}{
		{"ES256 X", &EcdsaProvider{}, ecdh.P256(), elliptic.P256(), 32, 379, 1},
		{"ES256 Y", &EcdsaProvider{}, ecdh.P256(), elliptic.P256(), 32, 43, 33},
		{"ES384 X", &EcdsaP384Provider{}, ecdh.P384(), elliptic.P384(), 48, 197, 1},
		{"ES384 Y", &EcdsaP384Provider{}, ecdh.P384(), elliptic.P384(), 48, 176, 49},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scalar := make([]byte, tc.coordinateSize)
			scalar[len(scalar)-2] = byte(tc.scalar >> 8)
			scalar[len(scalar)-1] = byte(tc.scalar)
			privateKey, err := tc.curve.NewPrivateKey(scalar)
			if err != nil {
				t.Fatal(err)
			}
			point := privateKey.PublicKey().Bytes()
			if point[tc.zeroOffset] != 0 {
				t.Fatal("test key does not have a leading-zero coordinate")
			}
			publicKey, err := ecdsa.ParseUncompressedPublicKey(tc.ecdsaCurve, point)
			if err != nil {
				t.Fatal(err)
			}

			encoded, err := tc.provider.PublicKeyToCoseCbor(publicKey)
			if err != nil {
				t.Fatal(err)
			}
			var cose map[int]any
			if err := cbor.Unmarshal(encoded, &cose); err != nil {
				t.Fatal(err)
			}
			for _, coordinate := range []struct {
				label int
				want  []byte
			}{
				{COSEXLabel, point[1 : 1+tc.coordinateSize]},
				{COSEYLabel, point[1+tc.coordinateSize:]},
			} {
				got, ok := cose[coordinate.label].([]byte)
				if !ok || !bytes.Equal(got, coordinate.want) {
					t.Fatalf("COSE coordinate %d = %x, want %x", coordinate.label, got, coordinate.want)
				}
			}

			gotHex, err := tc.provider.PublicKeyToHex(publicKey)
			if err != nil {
				t.Fatal(err)
			}
			if want := hex.EncodeToString(point); gotHex != want {
				t.Fatalf("public key hex = %s, want %s", gotHex, want)
			}
		})
	}
}
