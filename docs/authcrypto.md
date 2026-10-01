# Cryptographic providers

`internal/authcrypto` implements key generation, signing and public key
encoding through `CryptographyProvider` in `provider.go`.

| Algorithm | COSE ID | Key | Signing |
|---|---|---|---|
| ES256 | -7 | ECDSA P-256 | SHA-256, ASN.1 DER signature |
| ES384 | -35 | ECDSA P-384 | SHA-384, ASN.1 DER signature |
| RS256 | -257 | RSA | SHA-256, PKCS#1 v1.5 padding |
| PS256 | -37 | RSA | SHA-256, PSS padding |
| PS384 | -38 | RSA | SHA-384, PSS padding |
| PS512 | -39 | RSA | SHA-512, PSS padding |
| EdDSA | -8 | Ed25519 | Signs the message directly |

RSA keys are 2048 bits. PSS uses Go's automatic salt-length selection. Ceremony
code passes `crypto/rand.Reader` for key generation and signing.

`Sign` takes the message bytes. Providers perform any algorithm-specific
hashing themselves. `PublicKeyToCoseCbor` encodes a COSE key for authenticator
data. `PublicKeyToHex` supplies the keystore's public key representation.

## Algorithm selection

`registry.go` maps COSE IDs to providers. `GetSupportedAlgorithms` returns
EdDSA, ES384, ES256, PS512, PS384, PS256 and RS256 in that order, but attestation
negotiation follows the RP's `pubKeyCredParams` order. `--alg` bypasses
negotiation.

`GetProviderFromKey`, used during import, selects by key type and EC curve.
RSA keys do not identify their signing scheme, so imports default to RS256.
The import path currently ignores the transfer object's `coseAlgorithm` field.
