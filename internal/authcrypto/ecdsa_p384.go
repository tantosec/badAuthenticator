package authcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// EcdsaP384Provider uses P-384 and SHA-384 (ES384).
type EcdsaP384Provider struct{}

func (p *EcdsaP384Provider) GenerateKey(r io.Reader) (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), r)
}

func (p *EcdsaP384Provider) Sign(r io.Reader, priv crypto.PrivateKey, data []byte) ([]byte, error) {
	key, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("algorithm ES384 requires an ECDSA P-384 key, but got %T", priv)
	}

	digest := sha512.Sum384(data)
	rVal, sVal, err := ecdsa.Sign(r, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign assertion data with ECDSA P-384: %w", err)
	}

	return asn1.Marshal(ecdsaSignature{R: rVal, S: sVal})
}

func (p *EcdsaP384Provider) PublicKeyToCoseCbor(pub crypto.PublicKey) ([]byte, error) {
	ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not of type *ecdsa.PublicKey")
	}

	if ecdsaPubKey.Curve != elliptic.P384() {
		return nil, errors.New("ecdsa public key is not on P-384 curve")
	}
	point, err := ecdsaPubKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to encode P-384 public key: %w", err)
	}

	coseKeyMap := map[int]interface{}{
		COSEKtyLabel: COSEKtyEC2,
		COSEAlgLabel: COSEAlgorithmES384,
		COSECrvLabel: COSEEllipticCurveP384,
		COSEXLabel:   point[1:49],
		COSEYLabel:   point[49:],
	}

	return cbor.Marshal(coseKeyMap)
}

func (p *EcdsaP384Provider) PublicKeyToHex(pub crypto.PublicKey) (string, error) {
	ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("public key is not of type *ecdsa.PublicKey for hex conversion")
	}
	point, err := ecdsaPubKey.Bytes()
	if err != nil {
		return "", fmt.Errorf("failed to encode ECDSA public key: %w", err)
	}
	return hex.EncodeToString(point), nil
}
