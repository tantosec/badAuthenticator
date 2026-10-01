package handlers

import (
	"database/sql"
	"fmt"

	"github.com/tantosec/badAuthenticator/internal/webauthn"
)

func HandleAttestation(db *sql.DB, optionsJsonBytes []byte, overrides *webauthn.AttestationOverrides) (*webauthn.PublicKeyCredential[webauthn.AuthenticatorAttestationResponse], error) {
	attestationResponse, err := webauthn.Attestation(db, optionsJsonBytes, overrides)
	if err != nil {
		return nil, fmt.Errorf("attestation processing failed: %w", err)
	}

	return attestationResponse, nil
}
