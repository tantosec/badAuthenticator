package authcrypto

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/tantosec/badAuthenticator/internal/config"
)

// RsaProvider uses PKCS#1 v1.5 padding and SHA-256 (RS256).
type RsaProvider struct{}

func (p *RsaProvider) GenerateKey(r io.Reader) (crypto.PrivateKey, error) {
	return rsa.GenerateKey(r, config.DefaultRSAPrivateKeyBitLength)
}

func (p *RsaProvider) Sign(r io.Reader, priv crypto.PrivateKey, data []byte) ([]byte, error) {
	key, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("algorithm RS256 requires an RSA key, but got %T", priv)
	}

	digest := sha256.Sum256(data)
	return rsa.SignPKCS1v15(r, key, crypto.SHA256, digest[:])
}

func (p *RsaProvider) PublicKeyToCoseCbor(pub crypto.PublicKey) ([]byte, error) {
	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not of type *rsa.PublicKey")
	}

	coseKeyMap := map[int]any{
		COSEKtyLabel: COSEKtyRSA,
		COSEAlgLabel: COSEAlgorithmRS256,
		COSENLabel:   rsaPubKey.N.Bytes(),
		COSEELabel:   big.NewInt(int64(rsaPubKey.E)).Bytes(),
	}

	return cbor.Marshal(coseKeyMap)
}

func (p *RsaProvider) PublicKeyToHex(pub crypto.PublicKey) (string, error) {
	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("public key is not of type *rsa.PublicKey for hex conversion")
	}
	return hex.EncodeToString(rsaPubKey.N.Bytes()), nil
}
