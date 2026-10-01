package authcrypto

import (
	"strings"
)

// Common COSE key labels (RFC 9052, section 7).
const (
	COSEKtyLabel = 1 // Key type
	COSEAlgLabel = 3 // Algorithm
)

// COSE key type values (RFC 9052, section 7.1.1).
const (
	COSEKtyOKP = 1 // Octet key pair
	COSEKtyEC2 = 2 // Elliptic curve key with x and y coordinates
	COSEKtyRSA = 3 // RSA key
)

// IDs from the IANA COSE Algorithms registry.
const (
	COSEAlgorithmEdDSA  = -8   // EdDSA
	COSEAlgorithmES256  = -7   // ECDSA w/ SHA-256
	COSEAlgorithmES384  = -35  // ECDSA w/ SHA-384
	COSEAlgorithmES256K = -47  // ECDSA w/ secp256k1 curve + SHA-256
	COSEAlgorithmPS256  = -37  // RSASSA-PSS w/ SHA-256
	COSEAlgorithmPS384  = -38  // RSASSA-PSS w/ SHA-384
	COSEAlgorithmPS512  = -39  // RSASSA-PSS w/ SHA-512
	COSEAlgorithmRS256  = -257 // RSASSA-PKCS1-v1_5 w/ SHA-256
)

// IDs from the IANA COSE Elliptic Curves registry.
const (
	COSEEllipticCurveP256      = 1 // P-256
	COSEEllipticCurveP384      = 2 // P-384
	COSEEllipticCurveEd25519   = 6 // Ed25519
	COSEEllipticCurveSecp256k1 = 8 // secp256k1
)

// EC2 key labels.
const (
	COSECrvLabel = -1 // Curve
	COSEXLabel   = -2 // X-coordinate
	COSEYLabel   = -3 // Y-coordinate
)

// RSA key labels.
const (
	COSENLabel = -1 // Modulus
	COSEELabel = -2 // Exponent
)

var AlgorithmNames = map[string]int64{
	"ES256": COSEAlgorithmES256,
	"ES384": COSEAlgorithmES384,
	"RS256": COSEAlgorithmRS256,
	"PS256": COSEAlgorithmPS256,
	"PS384": COSEAlgorithmPS384,
	"PS512": COSEAlgorithmPS512,
	"EDDSA": COSEAlgorithmEdDSA,
}

// GetAlgorithmByName ignores case and returns (0, false) for unknown names.
func GetAlgorithmByName(name string) (int64, bool) {
	alg, ok := AlgorithmNames[strings.ToUpper(name)]
	return alg, ok
}
