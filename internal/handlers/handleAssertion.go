package handlers

import (
	"database/sql"
	"fmt"

	"github.com/tantosec/badAuthenticator/internal/webauthn"
)

func HandleAssertion(db *sql.DB, optionsJsonBytes []byte, overrides *webauthn.AssertionOverrides) (*webauthn.PublicKeyCredential[webauthn.AuthenticatorAssertionResponse], error) {
	assertionResponse, err := webauthn.Assertion(db, optionsJsonBytes, overrides)
	if err != nil {
		return nil, fmt.Errorf("assertion processing failed: %w", err)
	}

	return assertionResponse, nil
}
