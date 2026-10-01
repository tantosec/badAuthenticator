package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Opt distinguishes an absent field (use the default), null (omit the field),
// and a supplied value. Pointer fields cannot distinguish absent from null.
// Individual flag bits treat null as absent because a bit cannot be omitted.
type Opt[T any] struct {
	Present bool
	Null    bool
	Value   T
}

func (o Opt[T]) HasValue() bool { return o.Present && !o.Null }

func (o *Opt[T]) SetValue(v T) {
	o.Present = true
	o.Null = false
	o.Value = v
}

func (o *Opt[T]) SetNull() {
	o.Present = true
	o.Null = true
	var zero T
	o.Value = zero
}

// Or uses fallback only when o is absent. An explicit null takes precedence.
func (o Opt[T]) Or(fallback Opt[T]) Opt[T] {
	if o.Present {
		return o
	}
	return fallback
}

// UnmarshalJSON is called for explicit nulls, but not for absent keys.
func (o *Opt[T]) UnmarshalJSON(data []byte) error {
	o.Present = true

	var zero T
	if string(bytes.TrimSpace(data)) == "null" {
		o.Null = true
		o.Value = zero
		return nil
	}

	o.Null = false
	return json.Unmarshal(data, &o.Value)
}

// MarshalJSON encodes both absent and null fields as JSON null.
func (o Opt[T]) MarshalJSON() ([]byte, error) {
	if !o.Present || o.Null {
		return []byte("null"), nil
	}
	return json.Marshal(o.Value)
}

// ClientDataOverrides replaces profile and ceremony defaults for clientDataJSON.
type ClientDataOverrides struct {
	Type               Opt[string] `json:"type"`
	Challenge          Opt[string] `json:"challenge"`
	Origin             Opt[string] `json:"origin"`
	AndroidPackageName Opt[string] `json:"androidPackageName"`
	CrossOrigin        Opt[bool]   `json:"crossOrigin"`
	TopOrigin          Opt[string] `json:"topOrigin"`

	// FieldOrder replaces the profile's order and allows repeated keys.
	// Unknown names and fields without values are skipped.
	FieldOrder []string `json:"fieldOrder,omitempty"`
}

// Layer merges overrides with higher taking precedence. Either side may be nil.
func (c *ClientDataOverrides) Layer(higher *ClientDataOverrides) *ClientDataOverrides {
	if higher == nil {
		return c
	}
	if c == nil {
		return higher
	}

	merged := ClientDataOverrides{
		Type:               higher.Type.Or(c.Type),
		Challenge:          higher.Challenge.Or(c.Challenge),
		Origin:             higher.Origin.Or(c.Origin),
		AndroidPackageName: higher.AndroidPackageName.Or(c.AndroidPackageName),
		CrossOrigin:        higher.CrossOrigin.Or(c.CrossOrigin),
		TopOrigin:          higher.TopOrigin.Or(c.TopOrigin),
		FieldOrder:         higher.FieldOrder,
	}
	if merged.FieldOrder == nil {
		merged.FieldOrder = c.FieldOrder
	}
	return &merged
}

// AuthenticatorDataOverrides replaces fields before serialisation.
// Flags takes precedence over individual bits, including when set to null.
type AuthenticatorDataOverrides struct {
	Flags Opt[uint8] `json:"flags"`
	UP    Opt[bool]  `json:"up"`
	UV    Opt[bool]  `json:"uv"`
	BE    Opt[bool]  `json:"be"`
	BS    Opt[bool]  `json:"bs"`
	AT    Opt[bool]  `json:"at"`
	ED    Opt[bool]  `json:"ed"`

	SignCount Opt[uint32]      `json:"signCount"`
	RPIDHash  Opt[Base64Bytes] `json:"rpIdHash"`

	// AAGUID is only used during attestation.
	AAGUID Opt[AAGUIDValue] `json:"aaguid"`
}

// Layer merges overrides with higher taking precedence. Either side may be nil.
func (a *AuthenticatorDataOverrides) Layer(higher *AuthenticatorDataOverrides) *AuthenticatorDataOverrides {
	if higher == nil {
		return a
	}
	if a == nil {
		return higher
	}

	merged := AuthenticatorDataOverrides{
		Flags:     higher.Flags.Or(a.Flags),
		UP:        higher.UP.Or(a.UP),
		UV:        higher.UV.Or(a.UV),
		BE:        higher.BE.Or(a.BE),
		BS:        higher.BS.Or(a.BS),
		AT:        higher.AT.Or(a.AT),
		ED:        higher.ED.Or(a.ED),
		SignCount: higher.SignCount.Or(a.SignCount),
		RPIDHash:  higher.RPIDHash.Or(a.RPIDHash),
		AAGUID:    higher.AAGUID.Or(a.AAGUID),
	}
	return &merged
}

// Base64Bytes accepts either base64 alphabet, with or without padding.
// JSON output uses unpadded base64url.
type Base64Bytes []byte

func (b *Base64Bytes) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("expected a base64url string: %w", err)
	}

	decoded, err := DecodeBase64Permissive(encoded)
	if err != nil {
		return err
	}
	*b = decoded
	return nil
}

func (b Base64Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// DecodeBase64Permissive accepts either base64 alphabet and optional padding.
func DecodeBase64Permissive(encoded string) ([]byte, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(encoded), "=")

	if decoded, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil {
		return decoded, nil
	}

	decoded, err := base64.RawStdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 value %q: %w", encoded, err)
	}
	return decoded, nil
}

// CeremonyOverrides is shared by the request envelope and CLI flags.
type CeremonyOverrides struct {
	// An empty Profile uses the stored credential profile, or the default.
	Profile string `json:"profile,omitempty"`

	// Validate checks output before returning it. Storage changes are not undone.
	Validate bool `json:"validate,omitempty"`

	ClientData        *ClientDataOverrides        `json:"clientData,omitempty"`
	AuthenticatorData *AuthenticatorDataOverrides `json:"authenticatorData,omitempty"`

	// A nil pointer uses the builder. A supplied value replaces its output,
	// even when empty. Validate still checks the resulting bytes.
	ClientDataRaw        *Base64Bytes `json:"clientDataRaw,omitempty"`
	AuthenticatorDataRaw *Base64Bytes `json:"authenticatorDataRaw,omitempty"`
}

// Layer gives higher precedence, but keeps validation enabled if either sets it.
func (o CeremonyOverrides) Layer(higher CeremonyOverrides) CeremonyOverrides {
	merged := CeremonyOverrides{
		Profile:              o.Profile,
		Validate:             o.Validate || higher.Validate,
		ClientData:           o.ClientData.Layer(higher.ClientData),
		AuthenticatorData:    o.AuthenticatorData.Layer(higher.AuthenticatorData),
		ClientDataRaw:        o.ClientDataRaw,
		AuthenticatorDataRaw: o.AuthenticatorDataRaw,
	}
	if higher.Profile != "" {
		merged.Profile = higher.Profile
	}
	if higher.ClientDataRaw != nil {
		merged.ClientDataRaw = higher.ClientDataRaw
	}
	if higher.AuthenticatorDataRaw != nil {
		merged.AuthenticatorDataRaw = higher.AuthenticatorDataRaw
	}
	return merged
}

// CeremonyRequest combines WebAuthn options with output overrides.
type CeremonyRequest struct {
	CeremonyOverrides

	Options json.RawMessage `json:"options"`
}

// ParseCeremonyRequest recognises an envelope by its top-level "options" key.
// Other input is passed through as bare WebAuthn options.
func ParseCeremonyRequest(requestBytes []byte) (*CeremonyRequest, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(requestBytes, &probe); err != nil {
		// Let the ceremony's options parser report malformed input.
		return &CeremonyRequest{Options: requestBytes}, nil
	}

	if _, isEnvelope := probe["options"]; !isEnvelope {
		return &CeremonyRequest{Options: requestBytes}, nil
	}

	var envelope CeremonyRequest
	if err := json.Unmarshal(requestBytes, &envelope); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ceremony request envelope: %w", err)
	}
	if len(envelope.Options) == 0 {
		return nil, fmt.Errorf("ceremony request envelope has no options object")
	}
	return &envelope, nil
}
