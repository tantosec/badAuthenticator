package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

type ParsedAuthenticatorData struct {
	RPIDHash               string                        `json:"rpidHash"` // Hex.
	Flags                  uint8                         `json:"flags"`
	FlagsDecoded           string                        `json:"flagsDecoded"`
	SignCount              uint32                        `json:"signCount"`
	AttestedCredentialData *ParsedAttestedCredentialData `json:"attestedCredentialData,omitempty"`
	Extensions             string                        `json:"extensions,omitempty"` // Placeholder until extension decoding is implemented.
}

type ParsedAttestedCredentialData struct {
	AAGUID             string `json:"aaguid"` // Hex.
	CredentialIDLength uint16 `json:"credentialIDLength"`
	CredentialID       string `json:"credentialID"` // Hex.
	PublicKey          string `json:"publicKey"`    // Text representation of the decoded COSE key.
}

func StructToJSON(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("error marshalling to JSON: %v", err)
	}
	return string(b)
}

func ParseAuthenticatorData(authData []byte) (*ParsedAuthenticatorData, error) {
	if len(authData) < 37 {
		return nil, fmt.Errorf("authenticator data too short: %d bytes (min 37)", len(authData))
	}

	reader := bytes.NewReader(authData)

	rpIDHash := make([]byte, 32)
	reader.Read(rpIDHash)

	flags, _ := reader.ReadByte()

	var signCount uint32
	binary.Read(reader, binary.BigEndian, &signCount)

	parsed := &ParsedAuthenticatorData{
		RPIDHash:  hex.EncodeToString(rpIDHash),
		Flags:     flags,
		SignCount: signCount,
	}

	var flagStrs []string
	if flags&BitUP != 0 {
		flagStrs = append(flagStrs, "UP")
	}
	if flags&BitUV != 0 {
		flagStrs = append(flagStrs, "UV")
	}
	if flags&BitBE != 0 {
		flagStrs = append(flagStrs, "BE")
	}
	if flags&BitBS != 0 {
		flagStrs = append(flagStrs, "BS")
	}
	if flags&BitAT != 0 {
		flagStrs = append(flagStrs, "AT")
	}
	if flags&BitED != 0 {
		flagStrs = append(flagStrs, "ED")
	}
	b, _ := json.Marshal(flagStrs)
	parsed.FlagsDecoded = string(b)

	if flags&BitAT != 0 {
		aaguid := make([]byte, 16)
		reader.Read(aaguid)

		var credIDLen uint16
		binary.Read(reader, binary.BigEndian, &credIDLen)

		credID := make([]byte, credIDLen)
		reader.Read(credID)

		currPos, _ := reader.Seek(0, 1)
		remaining := authData[currPos:]

		var coseKey any
		dec := cbor.NewDecoder(bytes.NewReader(remaining))
		// Keep displaying what we can decode. Strict validation happens in validate.go.
		_ = dec.Decode(&coseKey)

		parsed.AttestedCredentialData = &ParsedAttestedCredentialData{
			AAGUID:             hex.EncodeToString(aaguid),
			CredentialIDLength: credIDLen,
			CredentialID:       hex.EncodeToString(credID),
			PublicKey:          fmt.Sprintf("%v", coseKey),
		}
	}

	if flags&BitED != 0 {
		parsed.Extensions = "Extensions present (parsing not fully implemented)"
	}

	return parsed, nil
}

type HumanReadablePublicKeyCredential[T any] struct {
	ID                     string         `json:"id"`
	RawID                  string         `json:"rawId"`
	Type                   string         `json:"type"`
	ClientExtensionResults map[string]any `json:"clientExtensionResults,omitempty"`
	Response               T              `json:"response"`
}

// HumanReadableAttestationResponse uses decoded values or error strings.
type HumanReadableAttestationResponse struct {
	ClientDataJSON    any      `json:"clientDataJSON"`
	AttestationObject any      `json:"attestationObject"`
	Transports        []string `json:"transports,omitempty"`
}

// HumanReadableAssertionResponse uses decoded values or error strings.
type HumanReadableAssertionResponse struct {
	ClientDataJSON    any    `json:"clientDataJSON"`
	AuthenticatorData any    `json:"authenticatorData"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"userHandle,omitempty"`
}

type ParsedAttestationObject struct {
	AuthData any            `json:"authData"` // Decoded data or an error string.
	Format   string         `json:"fmt"`
	AttStmt  map[string]any `json:"attStmt"`
}

func ParseClientData(clientDataJSONBase64 string) (any, error) {
	data, err := base64.RawURLEncoding.DecodeString(clientDataJSONBase64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("json unmarshal failed: %w", err)
	}
	return m, nil
}
