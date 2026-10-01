package webauthn

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

// Assertion accepts bare request options or a ceremony envelope.
// Direct overrides take precedence over envelope and profile values.
func Assertion(db *sql.DB, requestBytes []byte, overrides *AssertionOverrides) (*PublicKeyCredential[AuthenticatorAssertionResponse], error) {

	request, err := ParseCeremonyRequest(requestBytes)
	if err != nil {
		return nil, err
	}

	var requestOptions PublicKeyCredentialRequestOptions
	if err := json.Unmarshal(request.Options, &requestOptions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal assertion options: %w", err)
	}

	mergedOverrides := AssertionOverrides{}
	if overrides != nil {
		mergedOverrides = *overrides
	}
	mergedOverrides.CeremonyOverrides = request.CeremonyOverrides.Layer(mergedOverrides.CeremonyOverrides)

	assertionResponse, err := CreateAssertionResponseJSON(db, requestOptions, &mergedOverrides)
	if err != nil {
		return nil, fmt.Errorf("assertion processing failed: %w", err)
	}

	return assertionResponse, nil
}
