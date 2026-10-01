package authcrypto

import (
	"crypto"
	"io"
)

// CryptographyProvider supplies signing and key encoding for one COSE algorithm.
type CryptographyProvider interface {
	GenerateKey(rand io.Reader) (crypto.PrivateKey, error)

	// Sign takes message bytes and performs any algorithm-specific hashing.
	Sign(rand io.Reader, priv crypto.PrivateKey, data []byte) ([]byte, error)

	PublicKeyToCoseCbor(pub crypto.PublicKey) ([]byte, error)

	// PublicKeyToHex returns the provider-specific representation stored in metadata.
	PublicKeyToHex(pub crypto.PublicKey) (string, error)
}
