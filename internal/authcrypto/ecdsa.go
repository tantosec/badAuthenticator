package authcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

type ecdsaSignature struct {
	R, S *big.Int
}

// EcdsaProvider uses P-256 and SHA-256 (ES256).
type EcdsaProvider struct{}

func (p *EcdsaProvider) GenerateKey(r io.Reader) (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), r)
}

func (p *EcdsaProvider) Sign(r io.Reader, priv crypto.PrivateKey, data []byte) ([]byte, error) {
	key, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("algorithm ES256 requires an ECDSA P-256 key, but got %T", priv)
	}

	digest := sha256.Sum256(data)
	rVal, sVal, err := ecdsa.Sign(r, key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign assertion data with ECDSA: %w", err)
	}

	return asn1.Marshal(ecdsaSignature{R: rVal, S: sVal})
}

func (p *EcdsaProvider) PublicKeyToCoseCbor(pub crypto.PublicKey) ([]byte, error) {
	ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not of type *ecdsa.PublicKey")
	}

	if ecdsaPubKey.Curve != elliptic.P256() {
		return nil, errors.New("ecdsa public key is not on P-256 curve")
	}
	point, err := ecdsaPubKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("failed to encode P-256 public key: %w", err)
	}

	coseKeyMap := map[int]any{
		COSEKtyLabel: COSEKtyEC2,
		COSEAlgLabel: COSEAlgorithmES256,
		COSECrvLabel: COSEEllipticCurveP256,
		COSEXLabel:   point[1:33],
		COSEYLabel:   point[33:],
	}

	return cbor.Marshal(coseKeyMap)
}

func (p *EcdsaProvider) PublicKeyToHex(pub crypto.PublicKey) (string, error) {
	ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("public key is not of type *ecdsa.PublicKey for hex conversion")
	}
	point, err := ecdsaPubKey.Bytes()
	if err != nil {
		return "", fmt.Errorf("failed to encode ECDSA public key: %w", err)
	}
	return hex.EncodeToString(point), nil
}
