package webauthn

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/tantosec/badAuthenticator/internal/authcrypto"
	appconfig "github.com/tantosec/badAuthenticator/internal/config"
	"github.com/tantosec/badAuthenticator/internal/keystore"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

type AttestationConfig struct {
	storeCredential func(keystore.CredentialEntry) error

	DB             *sql.DB
	RelyingPartyID string
	UserHandle     []byte
	Alg            int64

	AuthData *AuthenticatorDataOverrides

	// ProfileAAGUID is used unless AuthData overrides it.
	ProfileAAGUID []byte

	// AuthDataRaw bypasses assembly when non-nil, including an empty slice.
	AuthDataRaw []byte

	CredentialIDLength *uint16
	AttestationFormat  AttestationFormat

	AttestationType AttestationType

	ClientDataJSONHash []byte

	// Saved with the credential for later assertions.
	StoredOrigin             string
	StoredAndroidPackageName string
	StoredProfile            string
}

// AttestationOverrides takes precedence over values in the request envelope.
type AttestationOverrides struct {
	CeremonyOverrides

	CredentialIDLength *uint16
	AlgOverride        *int64 // Bypasses RP algorithm negotiation.
	AttestationFormat  *AttestationFormat
	AttestationType    *AttestationType
}

type AttestationFormat string

const (
	AttestationFormatNone   AttestationFormat = "none"
	AttestationFormatPacked AttestationFormat = "packed"
)

// AttestationType selects how a packed attestation statement is signed.
type AttestationType string

const (
	AttestationTypeSelf AttestationType = "self"

	AttestationTypeFull AttestationType = "full"
)

func CreateNewAttestation(config AttestationConfig) (
	attestationObjectCbor []byte,
	newRawCredentialID []byte,
	err error,
) {

	attestationFormat := config.AttestationFormat
	if attestationFormat == "" {
		attestationFormat = AttestationFormatNone
	}
	switch attestationFormat {
	case AttestationFormatNone:
	case AttestationFormatPacked:
		if len(config.ClientDataJSONHash) != sha256.Size {
			return nil, nil, fmt.Errorf("packed attestation requires a %d-byte clientDataJSON hash", sha256.Size)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported attestation format: %s", attestationFormat)
	}

	if config.AttestationType == AttestationTypeFull && attestationFormat != AttestationFormatPacked {
		return nil, nil, fmt.Errorf("full attestation requires packed format, got %q; select a packed profile", attestationFormat)
	}

	cryptoProvider, err := authcrypto.GetProvider(config.Alg)
	if err != nil {
		return nil, nil, err
	}

	privateKey, genKeyErr := cryptoProvider.GenerateKey(rand.Reader)
	if genKeyErr != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", genKeyErr)
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("private key of type %T does not implement crypto.Signer", privateKey)
	}
	publicKey := signer.Public()

	credIDLen := appconfig.DefaultCredentialIDLength
	if config.CredentialIDLength != nil {
		credIDLen = *config.CredentialIDLength
	}
	newRawCredentialID = make([]byte, credIDLen)
	_, err = rand.Read(newRawCredentialID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate new raw credential ID: %w", err)
	}

	credentialIDString := base64.RawURLEncoding.EncodeToString(newRawCredentialID)

	// Store the real hash for discovery, even when output overrides it.
	rpIdHash := DeriveRPIDHash(config.RelyingPartyID)

	params := resolveAuthenticatorDataParams(config.AuthData, authenticatorDataDefaults{
		RPIDHash:  rpIdHash,
		UP:        true,
		UV:        true,
		AT:        true,
		SignCount: 0,
	})

	// Use the resolved counter as the starting point for future assertions.
	storedSignCount := uint32(0)
	if params.SignCount != nil {
		storedSignCount = *params.SignCount
	}

	publicKeyHex, err := cryptoProvider.PublicKeyToHex(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get hex for public key: %w", err)
	}

	cosePublicKeyCbor, err := cryptoProvider.PublicKeyToCoseCbor(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create COSE public key CBOR: %w", err)
	}

	// SetNull clears Value, so an explicit null omits the AAGUID bytes.
	aaguid := config.ProfileAAGUID
	if config.AuthData != nil && config.AuthData.AAGUID.Present {
		aaguid = config.AuthData.AAGUID.Value
	}
	params.AttestedData = &AttestedCredentialData{
		AAGUID:              aaguid,
		CredentialIDLength:  uint16(len(newRawCredentialID)),
		CredentialID:        newRawCredentialID,
		CredentialPublicKey: cosePublicKeyCbor,
	}

	var authDataBytes []byte
	if config.AuthDataRaw != nil {
		authDataBytes = config.AuthDataRaw
	} else {
		authDataBytes, err = BuildAuthenticatorData(params)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to build authenticator data: %w", err)
		}
	}

	attStmt := make(map[string]any)

	switch attestationFormat {
	case AttestationFormatNone:
	case AttestationFormatPacked:
		dataToSign := make([]byte, 0, len(authDataBytes)+len(config.ClientDataJSONHash))
		dataToSign = append(dataToSign, authDataBytes...)
		dataToSign = append(dataToSign, config.ClientDataJSONHash...)

		switch config.AttestationType {
		case AttestationTypeFull:
			chain, err := synthesizePackedChain(aaguid)
			if err != nil {
				return nil, nil, err
			}
			leafProvider, err := authcrypto.GetProvider(authcrypto.COSEAlgorithmES256)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to load ES256 provider for full attestation: %w", err)
			}
			signatureBytes, err := leafProvider.Sign(rand.Reader, chain.LeafSigner, dataToSign)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to sign packed full-attestation data: %w", err)
			}
			attStmt["alg"] = int64(authcrypto.COSEAlgorithmES256)
			attStmt["sig"] = signatureBytes
			attStmt["x5c"] = chain.X5C
		default:
			signatureBytes, err := cryptoProvider.Sign(rand.Reader, privateKey, dataToSign)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to sign packed self-attestation data: %w", err)
			}
			attStmt["alg"] = config.Alg
			attStmt["sig"] = signatureBytes
		}
	}

	attestationObj := AttestationObject{
		AuthData: authDataBytes,
		Format:   string(attestationFormat),
		AttStmt:  attStmt,
	}

	attestationObjectCbor, err = cbor.Marshal(attestationObj)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal attestation object to CBOR: %w", err)
	}

	privateKeyFilePath, err := keystore.StorePrivateKeyToPEM(credentialIDString, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to store private key file: %w", err)
	}

	keystoreEntry := keystore.CredentialEntry{
		CredentialID:       credentialIDString,
		PrivateKeyFilePath: privateKeyFilePath,
		PublicKeyBytesHex:  publicKeyHex,
		UserHandle:         base64.RawURLEncoding.EncodeToString(config.UserHandle),
		SignCount:          int(storedSignCount),
		RPIDHash:           hex.EncodeToString(rpIdHash),
		CreationDate:       time.Now().UTC().Format(time.RFC3339),
		RPID:               config.RelyingPartyID,
		CoseAlgorithm:      config.Alg,
		Origin:             config.StoredOrigin,
		AndroidPackageName: config.StoredAndroidPackageName,
		Profile:            config.StoredProfile,
	}

	store := config.storeCredential
	if store == nil {
		store = func(entry keystore.CredentialEntry) error {
			return keystore.AddCredentialEntryMetadata(config.DB, entry)
		}
	}
	if err := store(keystoreEntry); err != nil {
		if cleanupErr := os.Remove(privateKeyFilePath); cleanupErr != nil && !os.IsNotExist(cleanupErr) {
			return nil, nil, fmt.Errorf("failed to add credential entry to keystore: %w (also failed to remove private key file %q: %v)", err, privateKeyFilePath, cleanupErr)
		}
		return nil, nil, fmt.Errorf("failed to add credential entry to keystore: %w", err)
	}

	return attestationObjectCbor, newRawCredentialID, nil
}

// CreateNewAttestationNone creates a credential with "none" attestation.
func CreateNewAttestationNone(config AttestationConfig) (
	attestationObjectCbor []byte,
	newRawCredentialID []byte,
	err error,
) {
	config.AttestationFormat = AttestationFormatNone
	return CreateNewAttestation(config)
}

type AssertionConfig struct {
	DB                 *sql.DB
	RelyingPartyID     string
	ClientDataJSONHash []byte // SHA-256 of clientDataJSON.
	AllowCredentials   []PublicKeyCredentialDescriptor

	UserVerificationRequired bool
	// CredentialOverride skips discovery and loads the key from its stored path.
	CredentialOverride *keystore.CredentialEntry

	// A supplied SignCount leaves the stored counter unchanged.
	AuthData *AuthenticatorDataOverrides

	// AuthDataRaw bypasses assembly when non-nil, including an empty slice.
	AuthDataRaw []byte

	// AlgOverride replaces the credential's stored algorithm.
	AlgOverride *int64
}

// AssertionOverrides takes precedence over values in the request envelope.
type AssertionOverrides struct {
	CeremonyOverrides

	CredentialOverride *keystore.CredentialEntry
	AlgOverride        *int64
}

// FindAssertionCredential returns the first allowed credential, or the newest
// credential for the RP when no allow list is supplied. No match returns (nil, nil).
// A non-nil override is returned without a lookup.
func FindAssertionCredential(
	db *sql.DB,
	relyingPartyID string,
	allowCredentials []PublicKeyCredentialDescriptor,
	override *keystore.CredentialEntry,
) (*keystore.CredentialEntry, error) {
	logger := logging.GetLogger()

	if override != nil {
		return override, nil
	}

	rpIdHash := sha256.Sum256([]byte(relyingPartyID))
	rpidHashHexString := hex.EncodeToString(rpIdHash[:])

	if len(allowCredentials) > 0 {
		logger.Debug("allowCredentials provided, performing non-discoverable lookup.")
		for _, allowedCredential := range allowCredentials {
			cred, getErr := keystore.GetMetadataCredentialEntry(db, allowedCredential.ID, rpidHashHexString)
			if getErr != nil {
				return nil, fmt.Errorf("failed to fetch keystore entry for %s: %w", allowedCredential.ID, getErr)
			}
			if cred != nil {
				logger.Debug("Found matching non-discoverable credential", "id", cred.CredentialID)
				return cred, nil
			}
		}
		return nil, nil
	}

	logger.Debug("No allowCredentials provided, attempting discoverable credential lookup", "rpId", relyingPartyID)
	allRPcreds, listErr := keystore.ListCredentialsByRPIDHash(db, rpidHashHexString)
	if listErr != nil {
		return nil, fmt.Errorf("failed to search for discoverable credentials: %w", listErr)
	}
	if len(allRPcreds) == 0 {
		return nil, nil
	}

	chosen := &allRPcreds[0]
	logger.Debug("Found discoverable credential", "id", chosen.CredentialID, "userHandle", chosen.UserHandle)
	return chosen, nil
}

// CreateAssertion signs authenticator data with the selected credential.
// It returns raw bytes. Authenticator data uses the binary layout, not CBOR.
func CreateAssertion(config AssertionConfig) (
	rawIdUsed []byte,
	authDataCbor []byte,
	signature []byte,
	userHandleUsed []byte,
	err error,
) {
	rpIdHash := DeriveRPIDHash(config.RelyingPartyID)

	chosenCredential, err := FindAssertionCredential(config.DB, config.RelyingPartyID, config.AllowCredentials, config.CredentialOverride)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if chosenCredential == nil {
		return nil, nil, nil, nil, fmt.Errorf("no matching credential found for rpId: %s", config.RelyingPartyID)
	}

	algorithmToUse := chosenCredential.CoseAlgorithm
	if config.AlgOverride != nil {
		algorithmToUse = *config.AlgOverride
	}

	provider, err := authcrypto.GetProvider(algorithmToUse)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	privateKey, err := keystore.LoadPrivateKeyFromPEM(chosenCredential.PrivateKeyFilePath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to load private key for credential %s: %w", chosenCredential.CredentialID, err)
	}

	// Any supplied counter, including null, skips the stored counter update.
	var newSignCount uint32
	overridesSignCount := config.AuthData != nil && config.AuthData.SignCount.Present
	if !overridesSignCount {
		sc, err := keystore.IncrementMetadataCredentialEntrySignCount(config.DB, chosenCredential.CredentialID)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to increment sign count for credential %s: %w", chosenCredential.CredentialID, err)
		}
		newSignCount = uint32(sc)
	}

	rawIdUsed, err = base64.RawURLEncoding.DecodeString(chosenCredential.CredentialID)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to decode chosen credential ID '%s': %w", chosenCredential.CredentialID, err)
	}

	params := resolveAuthenticatorDataParams(config.AuthData, authenticatorDataDefaults{
		RPIDHash:  rpIdHash,
		UP:        true,
		UV:        config.UserVerificationRequired,
		SignCount: newSignCount,
	})

	var currentAuthDataBytes []byte
	if config.AuthDataRaw != nil {
		currentAuthDataBytes = config.AuthDataRaw
	} else {
		currentAuthDataBytes, err = BuildAuthenticatorData(params)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to build authenticator data for assertion: %w", err)
		}
	}

	dataToSign := append(currentAuthDataBytes, config.ClientDataJSONHash...)

	finalSignatureBytes, err := provider.Sign(rand.Reader, privateKey, dataToSign)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to sign assertion data: %w", err)
	}

	userHandleUsed, err = base64.RawURLEncoding.DecodeString(chosenCredential.UserHandle)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to decode stored user handle for credential %s: %w", chosenCredential.CredentialID, err)
	}

	return rawIdUsed, currentAuthDataBytes, finalSignatureBytes, userHandleUsed, nil
}

func CreateAssertionResponseJSON(
	db *sql.DB,
	requestOptions PublicKeyCredentialRequestOptions,
	overrides *AssertionOverrides,
) (
	*PublicKeyCredential[AuthenticatorAssertionResponse], error,
) {
	logger := logging.GetLogger()

	if overrides == nil {
		overrides = &AssertionOverrides{}
	}

	warnOnRawOverrides("assertion", overrides.CeremonyOverrides)

	// Resolve the credential before building clientDataJSON to use its saved defaults.
	chosenCredential, err := FindAssertionCredential(db, requestOptions.RpId, requestOptions.AllowCredentials, overrides.CredentialOverride)
	if err != nil {
		return nil, err
	}

	profileName := overrides.Profile
	if profileName == "" && chosenCredential != nil {
		profileName = chosenCredential.Profile
	}
	profile, err := GetProfile(profileName)
	if err != nil {
		return nil, err
	}

	clientDataOverrides := profile.ClientData.Layer(overrides.ClientData)
	if chosenCredential != nil {
		// Apply stored values after the profile, then apply request overrides.
		stored := &ClientDataOverrides{}
		if chosenCredential.Origin != "" {
			stored.Origin.SetValue(chosenCredential.Origin)
		}
		if chosenCredential.AndroidPackageName != "" {
			stored.AndroidPackageName.SetValue(chosenCredential.AndroidPackageName)
		}
		clientDataOverrides = profile.ClientData.Layer(stored).Layer(overrides.ClientData)
	}

	var clientDataJsonBytes []byte
	switch {
	case overrides.ClientDataRaw != nil:
		clientDataJsonBytes = *overrides.ClientDataRaw
	case profile.NoAssembly:
		clientDataJsonBytes = []byte{}
	default:
		clientDataJsonBytes, err = buildClientDataJSON(clientDataDefaults{
			Type:      "webauthn.get",
			Challenge: requestOptions.Challenge,
			Origin:    "https://" + requestOptions.RpId,
		}, clientDataOverrides, resolveFieldOrder(profile, clientDataOverrides))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal clientData for assertion: %w", err)
		}
	}

	clientDataJSONHash := sha256.Sum256(clientDataJsonBytes)

	userVerificationActuallyPerformed := false
	if requestOptions.UserVerification == "required" {
		logger.Debug("UserVerification 'required' by RP, setting UV flag to true.")
		userVerificationActuallyPerformed = true
	}

	config := AssertionConfig{
		DB:                       db,
		RelyingPartyID:           requestOptions.RpId,
		ClientDataJSONHash:       clientDataJSONHash[:],
		AllowCredentials:         requestOptions.AllowCredentials,
		UserVerificationRequired: userVerificationActuallyPerformed,
		CredentialOverride:       chosenCredential,
		AuthData:                 overrides.AuthenticatorData,
		AlgOverride:              overrides.AlgOverride,
	}
	if overrides.AuthenticatorDataRaw != nil {
		config.AuthDataRaw = *overrides.AuthenticatorDataRaw
	} else if profile.NoAssembly {
		config.AuthDataRaw = []byte{}
	}

	rawIdUsed, authDataBytes, signatureBytes, userHandleBytesUsed, err := CreateAssertion(config)
	if err != nil {
		return nil, fmt.Errorf("core CreateAssertion failed: %w", err)
	}

	if overrides.Validate {
		if err := ValidateCeremonyOutput(CeremonyExpectation{
			Type:           "webauthn.get",
			Challenge:      requestOptions.Challenge,
			RelyingPartyID: requestOptions.RpId,
			ExpectAT:       false,
		}, clientDataJsonBytes, authDataBytes); err != nil {
			return nil, fmt.Errorf("strict validation failed: %w", err)
		}
	}

	idForJsonResponse := base64.RawURLEncoding.EncodeToString(rawIdUsed)
	clientDataJSONForResponse := base64.RawURLEncoding.EncodeToString(clientDataJsonBytes)
	authenticatorDataForResponse := base64.RawURLEncoding.EncodeToString(authDataBytes)
	signatureForResponse := base64.RawURLEncoding.EncodeToString(signatureBytes)

	assertionResponse := AuthenticatorAssertionResponse{
		ClientDataJSON:    clientDataJSONForResponse,
		AuthenticatorData: authenticatorDataForResponse,
		Signature:         signatureForResponse,
	}
	if len(userHandleBytesUsed) > 0 {
		assertionResponse.UserHandle = base64.RawURLEncoding.EncodeToString(userHandleBytesUsed)
	}

	finalResponse := PublicKeyCredential[AuthenticatorAssertionResponse]{
		ID:                     idForJsonResponse,
		RawID:                  idForJsonResponse,
		Type:                   "public-key",
		ClientExtensionResults: make(map[string]any),
		Response:               assertionResponse,
	}

	return &finalResponse, nil
}

func warnOnRawOverrides(ceremony string, overrides CeremonyOverrides) {
	logger := logging.GetLogger()

	if overrides.ClientDataRaw != nil {
		logger.Warn("clientDataJSON supplied verbatim; not assembled or validated",
			"ceremony", ceremony, "bytes", len(*overrides.ClientDataRaw))
	}
	if overrides.AuthenticatorDataRaw != nil {
		logger.Warn("authenticatorData supplied verbatim; not assembled or validated",
			"ceremony", ceremony, "bytes", len(*overrides.AuthenticatorDataRaw))
	}
}

// attestationAuthData extracts the bytes used by output validation.
func attestationAuthData(attestationObjectCbor []byte) ([]byte, error) {
	var attestationObject AttestationObject
	if err := cbor.Unmarshal(attestationObjectCbor, &attestationObject); err != nil {
		return nil, fmt.Errorf("failed to unmarshal the attestation object just built: %w", err)
	}
	return attestationObject.AuthData, nil
}
