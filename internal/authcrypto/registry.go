package authcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
)

// Registration follows the RP's algorithm order, regardless of this list's order.
var preferredAlgs = []int64{
	COSEAlgorithmEdDSA,
	COSEAlgorithmES384,
	COSEAlgorithmES256,
	COSEAlgorithmPS512,
	COSEAlgorithmPS384,
	COSEAlgorithmPS256,
	COSEAlgorithmRS256,
}

var providers = map[int64]CryptographyProvider{
	COSEAlgorithmES256: &EcdsaProvider{},
	COSEAlgorithmRS256: &RsaProvider{},
	COSEAlgorithmEdDSA: &Ed25519Provider{},
	COSEAlgorithmES384: &EcdsaP384Provider{},
	COSEAlgorithmPS256: &RsaPssProvider{hash: crypto.SHA256, coseAlgId: COSEAlgorithmPS256},
	COSEAlgorithmPS384: &RsaPssProvider{hash: crypto.SHA384, coseAlgId: COSEAlgorithmPS384},
	COSEAlgorithmPS512: &RsaPssProvider{hash: crypto.SHA512, coseAlgId: COSEAlgorithmPS512},
}

func GetSupportedAlgorithms() []int64 {
	return preferredAlgs
}

func GetProvider(alg int64) (CryptographyProvider, error) {
	provider, ok := providers[alg]
	if !ok {
		return nil, fmt.Errorf("no crypto provider found for algorithm: %d", alg)
	}
	return provider, nil
}

// GetProviderFromKey infers the algorithm from the key type and curve.
// RSA keys do not identify the signing scheme, so imports default to RS256.
func GetProviderFromKey(priv crypto.PrivateKey) (CryptographyProvider, int64, error) {
	switch key := priv.(type) {
	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P256():
			return providers[COSEAlgorithmES256], COSEAlgorithmES256, nil
		case elliptic.P384():
			return providers[COSEAlgorithmES384], COSEAlgorithmES384, nil
		default:
			return nil, 0, fmt.Errorf("unsupported ECDSA curve")
		}
	case *rsa.PrivateKey:
		return providers[COSEAlgorithmRS256], COSEAlgorithmRS256, nil
	case ed25519.PrivateKey:
		return providers[COSEAlgorithmEdDSA], COSEAlgorithmEdDSA, nil
	default:
		return nil, 0, fmt.Errorf("unsupported private key type: %T", priv)
	}
}
