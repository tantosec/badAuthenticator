package webauthn

// COSEKey stores the CBOR fields of an EC public key.
type COSEKey struct {
	Kty int64  `cbor:"1,keyasint"`            // Key type (e.g., 2 for EC2)
	Alg int64  `cbor:"3,keyasint,omitempty"`  // Algorithm (e.g., -7 for ES256)
	Crv int64  `cbor:"-1,keyasint,omitempty"` // Curve (e.g., 1 for P-256), for EC2 keys
	X   []byte `cbor:"-2,keyasint,omitempty"` // X-coordinate, for EC2 keys
	Y   []byte `cbor:"-3,keyasint,omitempty"` // Y-coordinate, for EC2 keys
}

// AttestedCredentialData is part of AuthenticatorData during registration.
//
// The builder preserves supplied AAGUID bytes and CredentialIDLength, including
// invalid lengths, so callers can test malformed responses.
type AttestedCredentialData struct {
	AAGUID              []byte // Authenticator Attestation Globally Unique Identifier
	CredentialIDLength  uint16 // Length prefix written for the CredentialID
	CredentialID        []byte
	CredentialPublicKey []byte // CBOR-encoded COSE key
}

// AttestationObject contains the CBOR fields sent to the relying party.
type AttestationObject struct {
	AuthData []byte         `cbor:"authData"` // Binary output of BuildAuthenticatorData
	Format   string         `cbor:"fmt"`      // Attestation format (e.g., "none")
	AttStmt  map[string]any `cbor:"attStmt"`  // Attestation statement (format-specific)
}

// PublicKeyCredentialRpEntity describes the Relying Party.
type PublicKeyCredentialRpEntity struct {
	Name string `json:"name,omitempty"`
	ID   string `json:"id"` // Required: The RP ID
}

// PublicKeyCredentialUserEntity describes the user.
type PublicKeyCredentialUserEntity struct {
	ID          string `json:"id"` // Required: Base64url-encoded user handle (opaque to authenticator)
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// PublicKeyCredentialParameters specifies a public key algorithm and type.
type PublicKeyCredentialParameters struct {
	Type string `json:"type"` // e.g., "public-key"
	Alg  int64  `json:"alg"`  // COSE algorithm ID (e.g., -7 for ES256)
}

// AuthenticatorSelectionCriteria guides authenticator selection.
type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"` // "platform" or "cross-platform"
	RequireResidentKey      *bool  `json:"requireResidentKey,omitempty"`      // Nil when omitted
	ResidentKey             string `json:"residentKey,omitempty"`             // "discouraged", "preferred", "required"
	UserVerification        string `json:"userVerification,omitempty"`        // "required", "preferred", "discouraged"
}

// PublicKeyCredentialDescriptor describes an existing credential.
// Used in `allowCredentials` for assertions and `excludeCredentials` for attestations.
type PublicKeyCredentialDescriptor struct {
	Type       string   `json:"type"`                 // e.g., "public-key"
	ID         string   `json:"id"`                   // Required: Base64url-encoded raw credential ID
	Transports []string `json:"transports,omitempty"` // e.g., "internal", "usb", "nfc", "ble"
}

// PublicKeyCredentialCreationOptions contains the relying party's registration options.
type PublicKeyCredentialCreationOptions struct {
	Challenge              string                          `json:"challenge"`        // Required: Base64url-encoded challenge
	RP                     PublicKeyCredentialRpEntity     `json:"rp"`               // Required
	User                   PublicKeyCredentialUserEntity   `json:"user"`             // Required
	PubKeyCredParams       []PublicKeyCredentialParameters `json:"pubKeyCredParams"` // Required
	Timeout                uint64                          `json:"timeout,omitempty"`
	ExcludeCredentials     []PublicKeyCredentialDescriptor `json:"excludeCredentials,omitempty"` // List of credentials to exclude
	Attestation            string                          `json:"attestation,omitempty"`        // e.g., "none", "indirect", "direct"
	AuthenticatorSelection AuthenticatorSelectionCriteria  `json:"authenticatorSelection,omitempty"`
	Extensions             map[string]any                  `json:"extensions,omitempty"`
}

// PublicKeyCredentialRequestOptions contains the relying party's authentication options.
type PublicKeyCredentialRequestOptions struct {
	Challenge        string                          `json:"challenge"` // Required: Base64url-encoded
	Timeout          uint64                          `json:"timeout,omitempty"`
	RpId             string                          `json:"rpId,omitempty"`             // Optional: RP ID, should match credential's RP ID
	AllowCredentials []PublicKeyCredentialDescriptor `json:"allowCredentials,omitempty"` // Can be empty if RP supports discoverable credentials
	UserVerification string                          `json:"userVerification,omitempty"` // "required", "preferred", "discouraged"
	Extensions       map[string]any                  `json:"extensions,omitempty"`
}

// ClientData is used to decode clientDataJSON. Output is built field by field
// in clientdata.go to preserve the key order chosen by the profile or request.
type ClientData struct {
	Type               string `json:"type"`                         // "webauthn.create" or "webauthn.get"
	Challenge          string `json:"challenge"`                    // Base64url-encoded challenge (must match input challenge)
	Origin             string `json:"origin"`                       // Origin of the RP
	AndroidPackageName string `json:"androidPackageName,omitempty"` // Native Android flows only
	CrossOrigin        *bool  `json:"crossOrigin,omitempty"`        // Nil when omitted
	TopOrigin          string `json:"topOrigin,omitempty"`          // Optional, cross-origin ceremonies only
}

// AuthenticatorAttestationResponse contains the registration response fields.
type AuthenticatorAttestationResponse struct {
	ClientDataJSON    string   `json:"clientDataJSON"`       // Base64URL(clientDataJSON_bytes)
	AttestationObject string   `json:"attestationObject"`    // Base64URL(attestationObject_CBOR_bytes)
	Transports        []string `json:"transports,omitempty"` // Transports from the selected profile
}

// AuthenticatorAssertionResponse contains the authentication response fields.
type AuthenticatorAssertionResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`       // Base64URL(clientDataJSON_bytes)
	AuthenticatorData string `json:"authenticatorData"`    // Base64URL(authenticatorData_raw_bytes)
	Signature         string `json:"signature"`            // Base64URL(signature_raw_bytes)
	UserHandle        string `json:"userHandle,omitempty"` // Base64URL(userHandle_raw_bytes), present if available and resident key was used
}

// PublicKeyCredential wraps a registration or authentication response.
type PublicKeyCredential[T AuthenticatorAttestationResponse | AuthenticatorAssertionResponse] struct {
	ID                     string         `json:"id"`    // Base64URL(rawId of the credential)
	RawID                  string         `json:"rawId"` // Base64URL(rawId of the credential)
	Type                   string         `json:"type"`  // Should always be "public-key"
	ClientExtensionResults map[string]any `json:"clientExtensionResults,omitempty"`
	Response               T              `json:"response"`
}
