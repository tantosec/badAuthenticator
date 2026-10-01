package webauthn

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/tantosec/badAuthenticator/internal/keystore"
)

func TestProfileAttestationFormat(t *testing.T) {
	none := AttestationFormatNone
	for _, tc := range []struct {
		name       string
		profile    string
		definition string
		override   *AttestationFormat
		want       AttestationFormat
	}{
		{name: "default", want: AttestationFormatNone},
		{name: "web", profile: ProfileWeb, want: AttestationFormatNone},
		{name: "android", profile: ProfileAndroid, want: AttestationFormatNone},
		{name: "windows", profile: ProfileWindowsHelloSoftware, want: AttestationFormatPacked},
		{name: "custom omitted", profile: "custom", definition: `{}`, want: AttestationFormatNone},
		{name: "custom none", profile: "custom", definition: `{"attestationFormat":"none"}`, want: AttestationFormatNone},
		{name: "custom packed", profile: "custom", definition: `{"attestationFormat":"packed"}`, want: AttestationFormatPacked},
		{name: "direct override", profile: ProfileWindowsHelloSoftware, override: &none, want: AttestationFormatNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openTestDB(t)
			if _, err := GetProfile(ProfileWeb); err != nil {
				t.Fatal(err)
			}
			if tc.definition != "" {
				loadTestProfile(t, tc.profile, tc.definition)
			}
			request := `{"options":` + testAttestationOptions + `,"profile":"` + tc.profile + `"}`
			response, err := Attestation(db, []byte(request), &AttestationOverrides{AttestationFormat: tc.override})
			if err != nil {
				t.Fatal(err)
			}
			var obj AttestationObject
			if err := cbor.Unmarshal(decodeBase64URL(t, response.Response.AttestationObject), &obj); err != nil {
				t.Fatal(err)
			}
			if obj.Format != string(tc.want) {
				t.Fatalf("format = %q, want %q", obj.Format, tc.want)
			}
			if tc.want == AttestationFormatNone {
				if len(obj.AttStmt) != 0 {
					t.Fatal("none attestation contains a statement")
				}
				return
			}
			signature, ok := obj.AttStmt["sig"].([]byte)
			if !ok {
				t.Fatal("packed attestation has no signature")
			}
			if _, ok := obj.AttStmt["x5c"]; ok {
				t.Fatal("self-attestation contains a certificate chain")
			}
			entry, err := keystore.GetCredentialByID(db, response.ID)
			if err != nil || entry == nil {
				t.Fatalf("stored credential missing: %v", err)
			}
			key, err := keystore.LoadPrivateKeyFromPEM(entry.PrivateKeyFilePath)
			if err != nil {
				t.Fatal(err)
			}
			clientHash := sha256.Sum256(decodeBase64URL(t, response.Response.ClientDataJSON))
			digest := sha256.Sum256(append(obj.AuthData, clientHash[:]...))
			if !ecdsa.VerifyASN1(&key.(*ecdsa.PrivateKey).PublicKey, digest[:], signature) {
				t.Fatal("packed signature does not verify over the returned response")
			}
		})
	}
}

func TestWindowsHelloProfilePersistsForAssertions(t *testing.T) {
	db := openTestDB(t)
	request := `{"options":` + testAttestationOptions + `,"profile":"windows-hello-software","validate":true}`
	response, err := Attestation(db, []byte(request), nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseAttestationAuthData(t, response.Response.AttestationObject)
	if parsed.AttestedCredentialData == nil || parsed.AttestedCredentialData.AAGUID != "6028b017b1d44c02b4b3afcdafc96bb2" {
		t.Fatalf("unexpected Windows Hello AAGUID: %+v", parsed.AttestedCredentialData)
	}
	if len(response.Response.Transports) != 1 || response.Response.Transports[0] != "internal" {
		t.Fatalf("transports = %v", response.Response.Transports)
	}
	entry, err := keystore.GetCredentialByID(db, response.ID)
	if err != nil || entry == nil || entry.Profile != ProfileWindowsHelloSoftware {
		t.Fatalf("profile was not stored: %+v, %v", entry, err)
	}
	assertion, err := Assertion(db, []byte(testAssertionOptions), nil)
	if err != nil {
		t.Fatal(err)
	}
	if assertion.ID != response.ID {
		t.Fatal("assertion selected a different credential")
	}
	var clientData map[string]any
	if err := json.Unmarshal(decodeBase64URL(t, assertion.Response.ClientDataJSON), &clientData); err != nil {
		t.Fatal(err)
	}
	if clientData["crossOrigin"] != false || clientData["type"] != "webauthn.get" {
		t.Fatalf("unexpected assertion client data: %v", clientData)
	}
	verifyAssertionSignature(t, db, assertion)
}

func TestWindowsHelloProfileAllowsAAGUIDOverride(t *testing.T) {
	db := openTestDB(t)
	response, err := Attestation(db, []byte(`{"options":`+testAttestationOptions+`,"profile":"windows-hello-software","authenticatorData":{"aaguid":"00000000-0000-0000-0000-000000000000"}}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed := parseAttestationAuthData(t, response.Response.AttestationObject)
	if parsed.AttestedCredentialData == nil || parsed.AttestedCredentialData.AAGUID != strings.Repeat("0", 32) {
		t.Fatalf("explicit AAGUID did not override profile: %+v", parsed.AttestedCredentialData)
	}
}

func TestProfileRejectsUnsupportedAttestationFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(path, []byte(`{"custom":{"attestationFormat":"typo"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := LoadProfiles(path); err == nil || !strings.Contains(err.Error(), `unsupported attestation format "typo"`) {
		t.Fatalf("LoadProfiles error = %v", err)
	}
}
