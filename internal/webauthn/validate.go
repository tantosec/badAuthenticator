package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// CeremonyExpectation supplies the expected values for output validation.
type CeremonyExpectation struct {
	Type           string
	Challenge      string
	RelyingPartyID string
	ExpectAT       bool
}

// ValidateCeremonyOutput checks output structure and ceremony values, including
// raw overrides. It does not verify signatures, origin binding or counter history.
func ValidateCeremonyOutput(expectation CeremonyExpectation, clientDataJSON, authData []byte) error {
	var problems []error

	if err := validateClientDataJSON(expectation, clientDataJSON); err != nil {
		problems = append(problems, err)
	}
	if err := ValidateAuthenticatorData(expectation, authData); err != nil {
		problems = append(problems, err)
	}

	return errors.Join(problems...)
}

func validateClientDataJSON(expectation CeremonyExpectation, clientDataJSON []byte) error {
	var problems []error

	keys, err := clientDataJSONKeys(clientDataJSON)
	if err != nil {
		return fmt.Errorf("clientDataJSON: %w", err)
	}
	seen := make(map[string]bool, len(keys))
	for _, key := range keys {
		if seen[key] {
			problems = append(problems, fmt.Errorf("clientDataJSON: duplicate key %q", key))
		}
		seen[key] = true
	}

	var fields struct {
		Type      *string `json:"type"`
		Challenge *string `json:"challenge"`
		Origin    *string `json:"origin"`
	}
	if err := json.Unmarshal(clientDataJSON, &fields); err != nil {
		return errors.Join(append(problems, fmt.Errorf("clientDataJSON: %w", err))...)
	}

	switch {
	case fields.Type == nil:
		problems = append(problems, errors.New(`clientDataJSON: missing "type"`))
	case *fields.Type != expectation.Type:
		problems = append(problems, fmt.Errorf("clientDataJSON: type is %q, want %q for this ceremony", *fields.Type, expectation.Type))
	}

	switch {
	case fields.Challenge == nil:
		problems = append(problems, errors.New(`clientDataJSON: missing "challenge"`))
	case *fields.Challenge != expectation.Challenge:
		problems = append(problems, fmt.Errorf("clientDataJSON: challenge %q does not match the challenge in options", *fields.Challenge))
	}

	switch {
	case fields.Origin == nil:
		problems = append(problems, errors.New(`clientDataJSON: missing "origin"`))
	case *fields.Origin == "":
		problems = append(problems, errors.New(`clientDataJSON: "origin" is empty`))
	}

	return errors.Join(problems...)
}

// clientDataJSONKeys preserves duplicate keys that decoding into a map would lose.
func clientDataJSONKeys(clientDataJSON []byte) ([]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(clientDataJSON))

	openingToken, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if delimiter, ok := openingToken.(json.Delim); !ok || delimiter != '{' {
		return nil, errors.New("not a JSON object")
	}

	var keys []string
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("not valid JSON: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, errors.New("not a JSON object")
		}
		keys = append(keys, key)

		var discarded json.RawMessage
		if err := decoder.Decode(&discarded); err != nil {
			return nil, fmt.Errorf("not valid JSON: %w", err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing bytes after the JSON object")
	}

	return keys, nil
}

// ValidateAuthenticatorData checks the RP ID hash, flags and binary layout.
func ValidateAuthenticatorData(expectation CeremonyExpectation, authData []byte) error {
	const headerLength = sha256.Size + 1 + 4

	if len(authData) < headerLength {
		return fmt.Errorf("authenticatorData: %d bytes, want at least %d", len(authData), headerLength)
	}

	var problems []error

	rpIDHash := authData[:sha256.Size]
	if expectation.RelyingPartyID != "" {
		if want := DeriveRPIDHash(expectation.RelyingPartyID); !bytes.Equal(rpIDHash, want) {
			problems = append(problems, fmt.Errorf("authenticatorData: rpIdHash %x does not match SHA-256(%q)", rpIDHash, expectation.RelyingPartyID))
		}
	}

	flags := authData[sha256.Size]
	if flags&BitUP == 0 {
		problems = append(problems, errors.New("authenticatorData: UP flag is clear"))
	}
	if flags&BitBS != 0 && flags&BitBE == 0 {
		problems = append(problems, errors.New("authenticatorData: BS is set without BE"))
	}
	if hasAT := flags&BitAT != 0; hasAT != expectation.ExpectAT {
		problems = append(problems, fmt.Errorf("authenticatorData: AT flag is %v, want %v for this ceremony", hasAT, expectation.ExpectAT))
	}

	remaining := authData[headerLength:]
	if flags&BitAT != 0 {
		rest, err := validateAttestedCredentialData(remaining)
		if err != nil {
			problems = append(problems, err)
			remaining = nil
		} else {
			remaining = rest
		}
	}

	if flags&BitED != 0 {
		if len(remaining) == 0 {
			problems = append(problems, errors.New("authenticatorData: ED flag is set but no extension data follows"))
		} else {
			var extensions any
			if err := cbor.Unmarshal(remaining, &extensions); err != nil {
				problems = append(problems, fmt.Errorf("authenticatorData: extension data is not valid CBOR: %w", err))
			}
			remaining = nil
		}
	}

	if len(remaining) != 0 {
		problems = append(problems, fmt.Errorf("authenticatorData: %d trailing bytes", len(remaining)))
	}

	return errors.Join(problems...)
}

// validateAttestedCredentialData returns the bytes after the credential public key.
func validateAttestedCredentialData(data []byte) ([]byte, error) {
	const aaguidLength = 16

	if len(data) < aaguidLength+2 {
		return nil, fmt.Errorf("authenticatorData: attested credential data is %d bytes, too short for an AAGUID and length prefix", len(data))
	}

	credentialIDLength := int(binary.BigEndian.Uint16(data[aaguidLength : aaguidLength+2]))
	rest := data[aaguidLength+2:]
	if credentialIDLength > len(rest) {
		return nil, fmt.Errorf("authenticatorData: credential ID length prefix is %d but only %d bytes follow", credentialIDLength, len(rest))
	}
	if credentialIDLength == 0 {
		return nil, errors.New("authenticatorData: credential ID length prefix is zero")
	}
	rest = rest[credentialIDLength:]

	// Decode one CBOR item to find where any extension data begins.
	decoder := cbor.NewDecoder(bytes.NewReader(rest))
	var coseKey map[int]any
	if err := decoder.Decode(&coseKey); err != nil {
		return nil, fmt.Errorf("authenticatorData: credential public key is not valid COSE CBOR: %w", err)
	}
	return rest[decoder.NumBytesRead():], nil
}
