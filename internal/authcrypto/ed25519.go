package authcrypto

import (
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

type Ed25519Provider struct{}

func (p *Ed25519Provider) GenerateKey(r io.Reader) (crypto.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(r)
	return priv, err
}

func (p *Ed25519Provider) Sign(r io.Reader, priv crypto.PrivateKey, data []byte) ([]byte, error) {
	key, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("algorithm EdDSA requires an Ed25519 key, but got %T", priv)
	}

	// Ed25519 takes the message directly, without a separate hashing step.
	return ed25519.Sign(key, data), nil
}

func (p *Ed25519Provider) PublicKeyToCoseCbor(pub crypto.PublicKey) ([]byte, error) {
	edPubKey, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not of type ed25519.PublicKey")
	}

	coseKeyMap := map[int]interface{}{
		COSEKtyLabel: COSEKtyOKP,
		COSEAlgLabel: COSEAlgorithmEdDSA,
		COSECrvLabel: COSEEllipticCurveEd25519,
		COSEXLabel:   edPubKey,
	}

	return cbor.Marshal(coseKeyMap)
}

func (p *Ed25519Provider) PublicKeyToHex(pub crypto.PublicKey) (string, error) {
	edPubKey, ok := pub.(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("public key is not of type ed25519.PublicKey for hex conversion")
	}
	return hex.EncodeToString(edPubKey), nil
}
