package authcrypto

import (
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/tantosec/badAuthenticator/internal/config"
)

// RsaPssProvider shares RSA-PSS signing across the PS256, PS384 and PS512 hashes.
type RsaPssProvider struct {
	hash      crypto.Hash
	coseAlgId int64
}

func (p *RsaPssProvider) GenerateKey(r io.Reader) (crypto.PrivateKey, error) {
	return rsa.GenerateKey(r, config.DefaultRSAPrivateKeyBitLength)
}

func (p *RsaPssProvider) Sign(r io.Reader, priv crypto.PrivateKey, data []byte) ([]byte, error) {
	key, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("algorithm PS256/384/512 requires an RSA key, but got %T", priv)
	}

	hasher := p.hash.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       p.hash,
	}

	return rsa.SignPSS(r, key, p.hash, digest, opts)
}

func (p *RsaPssProvider) PublicKeyToCoseCbor(pub crypto.PublicKey) ([]byte, error) {
	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not of type *rsa.PublicKey")
	}

	coseKeyMap := map[int]interface{}{
		COSEKtyLabel: COSEKtyRSA,
		COSEAlgLabel: p.coseAlgId,
		COSENLabel:   rsaPubKey.N.Bytes(),
		COSEELabel:   big.NewInt(int64(rsaPubKey.E)).Bytes(),
	}

	return cbor.Marshal(coseKeyMap)
}

func (p *RsaPssProvider) PublicKeyToHex(pub crypto.PublicKey) (string, error) {
	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("public key is not of type *rsa.PublicKey for hex conversion")
	}
	return hex.EncodeToString(rsaPubKey.N.Bytes()), nil
}
