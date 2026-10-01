package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const BitUP byte = 0x01 // User present
const BitUV byte = 0x04 // User verified
const BitBE byte = 0x08 // Backup eligible
const BitBS byte = 0x10 // Backup state
const BitAT byte = 0x40 // Attested credential data
const BitED byte = 0x80 // Extension data

func AssembleFlags(up, uv, be, bs, at, ed bool) byte {
	var flags byte
	if up {
		flags |= BitUP
	}
	if uv {
		flags |= BitUV
	}
	if be {
		flags |= BitBE
	}
	if bs {
		flags |= BitBS
	}
	if at {
		flags |= BitAT
	}
	if ed {
		flags |= BitED
	}
	return flags
}

// DeriveRPIDHash returns SHA-256 of the RP ID for discovery and storage.
func DeriveRPIDHash(relyingPartyID string) []byte {
	digest := sha256.Sum256([]byte(relyingPartyID))
	hash := digest[:]
	if len(hash) != sha256.Size {
		panic(fmt.Sprintf("webauthn: derived rpIdHash for %q is %d bytes, want %d", relyingPartyID, len(hash), sha256.Size))
	}
	return hash
}

// AuthenticatorDataParams holds fields for binary serialisation.
// Nil fields are omitted without padding.
type AuthenticatorDataParams struct {
	RPIDHash  []byte
	Flags     *byte
	SignCount *uint32

	// AttestedData is written only when AT is set.
	AttestedData *AttestedCredentialData

	ExtensionsCbor []byte
}

// BuildAuthenticatorData writes fields without validating lengths or flag/payload
// consistency. ValidateAuthenticatorData checks the resulting bytes separately.
func BuildAuthenticatorData(params AuthenticatorDataParams) ([]byte, error) {
	var authDataBuffer bytes.Buffer

	if _, err := authDataBuffer.Write(params.RPIDHash); err != nil {
		return nil, fmt.Errorf("webauthn: failed to write rpIdHash to buffer: %w", err)
	}

	flags := byte(0)
	if params.Flags != nil {
		flags = *params.Flags
		if err := authDataBuffer.WriteByte(flags); err != nil {
			return nil, fmt.Errorf("webauthn: failed to write flags to buffer: %w", err)
		}
	}

	if params.SignCount != nil {
		if err := binary.Write(&authDataBuffer, binary.BigEndian, *params.SignCount); err != nil {
			return nil, fmt.Errorf("webauthn: failed to write signCount to buffer: %w", err)
		}
	}

	if (flags&BitAT) == BitAT && params.AttestedData != nil {
		attestedData := params.AttestedData

		if _, err := authDataBuffer.Write(attestedData.AAGUID); err != nil {
			return nil, fmt.Errorf("webauthn: failed to write AAGUID to buffer: %w", err)
		}

		// Keep the supplied length even if it disagrees with CredentialID.
		if err := binary.Write(&authDataBuffer, binary.BigEndian, attestedData.CredentialIDLength); err != nil {
			return nil, fmt.Errorf("webauthn: failed to write CredentialIDLength to buffer: %w", err)
		}

		if _, err := authDataBuffer.Write(attestedData.CredentialID); err != nil {
			return nil, fmt.Errorf("webauthn: failed to write CredentialID to buffer: %w", err)
		}

		if _, err := authDataBuffer.Write(attestedData.CredentialPublicKey); err != nil {
			return nil, fmt.Errorf("webauthn: failed to write CredentialPublicKey to buffer: %w", err)
		}
	}

	if (flags&BitED) == BitED && params.ExtensionsCbor != nil {
		if _, err := authDataBuffer.Write(params.ExtensionsCbor); err != nil {
			return nil, fmt.Errorf("webauthn: failed to write extensionsCbor to buffer: %w", err)
		}
	}

	return authDataBuffer.Bytes(), nil
}
