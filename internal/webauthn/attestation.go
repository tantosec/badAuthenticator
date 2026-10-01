package webauthn

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/tantosec/badAuthenticator/internal/authcrypto"
	"github.com/tantosec/badAuthenticator/internal/keystore"
)

// Attestation accepts bare creation options or a ceremony envelope.
// Direct overrides take precedence over envelope and profile values.
func Attestation(db *sql.DB, requestBytes []byte, overrides *AttestationOverrides) (*PublicKeyCredential[AuthenticatorAttestationResponse], error) {
	return AttestationWithStore(func(entry keystore.CredentialEntry) error {
		return keystore.AddCredentialEntryMetadata(db, entry)
	}, requestBytes, overrides)
}

// AttestationWithStore lets callers save metadata in a transaction.
func AttestationWithStore(store func(keystore.CredentialEntry) error, requestBytes []byte, overrides *AttestationOverrides) (*PublicKeyCredential[AuthenticatorAttestationResponse], error) {
	request, err := ParseCeremonyRequest(requestBytes)
	if err != nil {
		return nil, err
	}

	var creationOptions PublicKeyCredentialCreationOptions
	if err := json.Unmarshal(request.Options, &creationOptions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation options JSON from stdin: %w", err)
	}

	mergedOverrides := AttestationOverrides{}
	if overrides != nil {
		mergedOverrides = *overrides
	}
	mergedOverrides.CeremonyOverrides = request.CeremonyOverrides.Layer(mergedOverrides.CeremonyOverrides)

	profile, err := GetProfile(mergedOverrides.Profile)
	if err != nil {
		return nil, err
	}
	warnOnRawOverrides("attestation", mergedOverrides.CeremonyOverrides)

	userHandleBytes, err := base64.RawURLEncoding.DecodeString(creationOptions.User.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode user.id from attestation options: %w", err)
	}

	var selectedAlg int64
	supportedAlgs := make(map[int64]bool)
	for _, alg := range authcrypto.GetSupportedAlgorithms() {
		supportedAlgs[alg] = true
	}

	if mergedOverrides.AlgOverride != nil {
		selectedAlg = *mergedOverrides.AlgOverride
	} else {
		for _, rpParam := range creationOptions.PubKeyCredParams {
			if _, ok := supportedAlgs[rpParam.Alg]; ok {
				selectedAlg = rpParam.Alg
				break
			}
		}
	}

	if selectedAlg == 0 {
		return nil, fmt.Errorf("no mutually supported algorithm found in RP's pubKeyCredParams")
	}

	clientDataOverrides := profile.ClientData.Layer(mergedOverrides.ClientData)

	var clientDataJsonBytes []byte
	switch {
	case mergedOverrides.ClientDataRaw != nil:
		clientDataJsonBytes = *mergedOverrides.ClientDataRaw
	case profile.NoAssembly:
		clientDataJsonBytes = []byte{}
	default:
		clientDataJsonBytes, err = buildClientDataJSON(clientDataDefaults{
			Type:      "webauthn.create",
			Challenge: creationOptions.Challenge,
			Origin:    "https://" + creationOptions.RP.ID,
		}, clientDataOverrides, resolveFieldOrder(profile, clientDataOverrides))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal clientDataJSON for attestation response: %w", err)
		}
	}
	clientDataJSONHash := sha256.Sum256(clientDataJsonBytes)

	config := AttestationConfig{
		storeCredential:    store,
		RelyingPartyID:     creationOptions.RP.ID,
		UserHandle:         userHandleBytes,
		Alg:                selectedAlg,
		ClientDataJSONHash: clientDataJSONHash[:],
		AuthData:           mergedOverrides.AuthenticatorData,
		ProfileAAGUID:      profile.AAGUID,
		AttestationFormat:  profile.AttestationFormat,
		AttestationType:    profile.AttestationType,
		CredentialIDLength: mergedOverrides.CredentialIDLength,
	}
	if mergedOverrides.AuthenticatorDataRaw != nil {
		config.AuthDataRaw = *mergedOverrides.AuthenticatorDataRaw
	} else if profile.NoAssembly {
		config.AuthDataRaw = []byte{}
	}
	if mergedOverrides.AttestationFormat != nil {
		config.AttestationFormat = *mergedOverrides.AttestationFormat
	}
	if mergedOverrides.AttestationType != nil {
		config.AttestationType = *mergedOverrides.AttestationType
	}

	// Store explicit values only. Profile defaults are resolved again on assertion.
	config.StoredProfile = profile.Name
	if mergedOverrides.ClientData != nil {
		if mergedOverrides.ClientData.Origin.HasValue() {
			config.StoredOrigin = mergedOverrides.ClientData.Origin.Value
		}
		if mergedOverrides.ClientData.AndroidPackageName.HasValue() {
			config.StoredAndroidPackageName = mergedOverrides.ClientData.AndroidPackageName.Value
		}
	}

	attestationObjectCbor, newRawCredentialID, err := CreateNewAttestation(config)
	if err != nil {
		return nil, fmt.Errorf("createNewAttestation failed: %w", err)
	}

	if mergedOverrides.Validate {
		authData, err := attestationAuthData(attestationObjectCbor)
		if err != nil {
			return nil, fmt.Errorf("strict validation failed: %w", err)
		}
		if err := ValidateCeremonyOutput(CeremonyExpectation{
			Type:           "webauthn.create",
			Challenge:      creationOptions.Challenge,
			RelyingPartyID: creationOptions.RP.ID,
			ExpectAT:       true,
		}, clientDataJsonBytes, authData); err != nil {
			return nil, fmt.Errorf("strict validation failed: %w", err)
		}
	}

	idForJson := base64.RawURLEncoding.EncodeToString(newRawCredentialID)
	attestationObjectForJson := base64.RawURLEncoding.EncodeToString(attestationObjectCbor)
	clientDataJsonForJsonResponse := base64.RawURLEncoding.EncodeToString(clientDataJsonBytes)

	attestationResponse := AuthenticatorAttestationResponse{
		ClientDataJSON:    clientDataJsonForJsonResponse,
		AttestationObject: attestationObjectForJson,
		Transports:        profile.Transports,
	}

	finalResponse := &PublicKeyCredential[AuthenticatorAttestationResponse]{
		ID:                     idForJson,
		RawID:                  idForJson,
		Type:                   "public-key",
		ClientExtensionResults: make(map[string]any),
		Response:               attestationResponse,
	}

	return finalResponse, nil
}
