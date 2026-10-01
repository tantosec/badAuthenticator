package webauthn

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/tantosec/badAuthenticator/internal/keystore"
)

const (
	testAttestationOptions = `{"rp":{"id":"example.com","name":"Example"},` +
		`"user":{"id":"dXNlcg","name":"u","displayName":"U"},` +
		`"challenge":"Y2hhbGxlbmdl",` +
		`"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`

	testAssertionOptions = `{"challenge":"YXNzZXJ0","rpId":"example.com"}`

	androidOrigin = "android:apk-key-hash:qz7fNlJErX_Gi-GXFgi60o7uP_ByiGFuP_OouU-M8Hc"
	androidPackge = "com.example.app"
)

func TestBothCeremoniesSerializeIdentically(t *testing.T) {
	db := openTestDB(t)

	attestation, err := Attestation(db, []byte(testAttestationOptions), nil)
	if err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}
	const wantAttestation = `{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com","crossOrigin":false}`
	if got := decodeClientDataJSON(t, attestation.Response.ClientDataJSON); got != wantAttestation {
		t.Fatalf("attestation clientDataJSON =\n%s\nwant\n%s", got, wantAttestation)
	}

	assertion, err := Assertion(db, []byte(testAssertionOptions), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}
	const wantAssertion = `{"type":"webauthn.get","challenge":"YXNzZXJ0","origin":"https://example.com","crossOrigin":false}`
	if got := decodeClientDataJSON(t, assertion.Response.ClientDataJSON); got != wantAssertion {
		t.Fatalf("assertion clientDataJSON =\n%s\nwant\n%s", got, wantAssertion)
	}
}

func TestSettingOriginDoesNotReorderOtherFields(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}
	assertion, err := Assertion(db, []byte(`{
		"options": `+testAssertionOptions+`,
		"clientData": {"origin": "`+androidOrigin+`"}
	}`), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}

	want := `{"type":"webauthn.get","challenge":"YXNzZXJ0","origin":"` + androidOrigin + `","crossOrigin":false}`
	if got := decodeClientDataJSON(t, assertion.Response.ClientDataJSON); got != want {
		t.Fatalf("clientDataJSON =\n%s\nwant\n%s", got, want)
	}
}

func TestAndroidProfileAloneProducesTheAndroidShape(t *testing.T) {
	db := openTestDB(t)

	attestation, err := Attestation(db, []byte(`{"profile":"android","options":`+testAttestationOptions+`}`), nil)
	if err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}

	const wantClientData = `{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl",` +
		`"origin":"https://example.com","androidPackageName":"com.google.android.gms"}`
	if got := decodeClientDataJSON(t, attestation.Response.ClientDataJSON); got != wantClientData {
		t.Fatalf("clientDataJSON =\n%s\nwant\n%s", got, wantClientData)
	}

	parsed := parseAttestationAuthData(t, attestation.Response.AttestationObject)
	const wantAAGUID = "ea9b8d664d011d213ce4b6b48cb575d4"
	if parsed.AttestedCredentialData == nil || parsed.AttestedCredentialData.AAGUID != wantAAGUID {
		t.Fatalf("aaguid = %+v, want %s", parsed.AttestedCredentialData, wantAAGUID)
	}
}

func TestWebProfileEmitsZeroAAGUID(t *testing.T) {
	db := openTestDB(t)

	attestation, err := Attestation(db, []byte(testAttestationOptions), nil)
	if err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}

	parsed := parseAttestationAuthData(t, attestation.Response.AttestationObject)
	if parsed.AttestedCredentialData == nil || parsed.AttestedCredentialData.AAGUID != strings.Repeat("0", 32) {
		t.Fatalf("aaguid = %+v, want all zero", parsed.AttestedCredentialData)
	}
}

func TestAndroidProfilePersistsAcrossAssertions(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(`{
		"profile":"android",
		"options": `+testAttestationOptions+`,
		"clientData": {"origin": "`+androidOrigin+`", "androidPackageName": "`+androidPackge+`"}
	}`), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}

	assertion, err := Assertion(db, []byte(testAssertionOptions), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}

	want := `{"type":"webauthn.get","challenge":"YXNzZXJ0","origin":"` + androidOrigin +
		`","androidPackageName":"` + androidPackge + `"}`
	if got := decodeClientDataJSON(t, assertion.Response.ClientDataJSON); got != want {
		t.Fatalf("clientDataJSON =\n%s\nwant\n%s", got, want)
	}
	verifyAssertionSignature(t, db, assertion)
}

func TestProfileDefaultsAreNotFrozenIntoTheCredential(t *testing.T) {
	db := openTestDB(t)

	attestation, err := Attestation(db, []byte(`{"profile":"android","options":`+testAttestationOptions+`}`), nil)
	if err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}

	entry, err := keystore.GetCredentialByID(db, attestation.ID)
	if err != nil {
		t.Fatalf("GetCredentialByID failed: %v", err)
	}
	if entry.Profile != "android" {
		t.Fatalf("stored profile = %q, want %q", entry.Profile, "android")
	}
	if entry.AndroidPackageName != "" {
		t.Fatalf("stored androidPackageName = %q, want the profile default not to be copied", entry.AndroidPackageName)
	}

	assertion, err := Assertion(db, []byte(`{"profile":"web","options":`+testAssertionOptions+`}`), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}
	const want = `{"type":"webauthn.get","challenge":"YXNzZXJ0","origin":"https://example.com","crossOrigin":false}`
	if got := decodeClientDataJSON(t, assertion.Response.ClientDataJSON); got != want {
		t.Fatalf("clientDataJSON =\n%s\nwant\n%s", got, want)
	}
}

func TestExplicitOverrideForcesCrossOriginBackOnUnderAndroid(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}
	assertion, err := Assertion(db, []byte(`{
		"profile":"android",
		"options": `+testAssertionOptions+`,
		"clientData": {"crossOrigin": false}
	}`), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}

	const want = `{"type":"webauthn.get","challenge":"YXNzZXJ0","origin":"https://example.com",` +
		`"androidPackageName":"com.google.android.gms","crossOrigin":false}`
	if got := decodeClientDataJSON(t, assertion.Response.ClientDataJSON); got != want {
		t.Fatalf("clientDataJSON =\n%s\nwant\n%s", got, want)
	}
	verifyAssertionSignature(t, db, assertion)
}

func TestExplicitNullTurnsOffAProfileDefault(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}
	assertion, err := Assertion(db, []byte(`{
		"options": `+testAssertionOptions+`,
		"clientData": {"androidPackageName": "`+androidPackge+`", "crossOrigin": null}
	}`), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}

	const want = `{"type":"webauthn.get","challenge":"YXNzZXJ0","origin":"https://example.com",` +
		`"androidPackageName":"` + androidPackge + `"}`
	if got := decodeClientDataJSON(t, assertion.Response.ClientDataJSON); got != want {
		t.Fatalf("clientDataJSON =\n%s\nwant\n%s", got, want)
	}
}

func TestExplicitAAGUIDBeatsProfile(t *testing.T) {
	db := openTestDB(t)

	attestation, err := Attestation(db, []byte(`{
		"profile":"android",
		"options": `+testAttestationOptions+`,
		"authenticatorData": {"aaguid": "6028b017-b1d4-4c02-b4b3-afcdafc96bb2"}
	}`), nil)
	if err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}

	parsed := parseAttestationAuthData(t, attestation.Response.AttestationObject)
	const want = "6028b017b1d44c02b4b3afcdafc96bb2"
	if parsed.AttestedCredentialData == nil || parsed.AttestedCredentialData.AAGUID != want {
		t.Fatalf("aaguid = %+v, want %s", parsed.AttestedCredentialData, want)
	}
}

func TestClientDataRawIsSignedAndEmittedVerbatim(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}

	// Deliberately malformed JSON.
	rawClientData := []byte(`{"type":"webauthn.get","type":"webauthn.create","challenge":` + "\x00\xff" + `trailing`)
	encoded := base64.RawURLEncoding.EncodeToString(rawClientData)

	assertion, err := Assertion(db, []byte(`{
		"options": `+testAssertionOptions+`,
		"clientDataRaw": "`+encoded+`"
	}`), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}

	emitted := decodeBase64URL(t, assertion.Response.ClientDataJSON)
	if string(emitted) != string(rawClientData) {
		t.Fatalf("emitted clientDataJSON = %q, want %q", emitted, rawClientData)
	}
	verifyAssertionSignatureBytes(t, db, assertion)
}

func TestAuthenticatorDataRawIsSignedAndEmittedVerbatim(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}

	// The AT flag is set but the attested credential data is truncated.
	rawAuthData := append(make([]byte, 32), 0x45, 0x00, 0x00, 0x00, 0x09, 0xde, 0xad)
	encoded := base64.RawURLEncoding.EncodeToString(rawAuthData)

	assertion, err := Assertion(db, []byte(`{
		"options": `+testAssertionOptions+`,
		"authenticatorDataRaw": "`+encoded+`"
	}`), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}

	emitted := decodeBase64URL(t, assertion.Response.AuthenticatorData)
	if string(emitted) != string(rawAuthData) {
		t.Fatalf("emitted authenticatorData = %x, want %x", emitted, rawAuthData)
	}
	verifyAssertionSignatureBytes(t, db, assertion)
}

func TestRawProfileAssemblesNothing(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}
	assertion, err := Assertion(db, []byte(`{"profile":"raw","options":`+testAssertionOptions+`}`), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}

	if got := decodeBase64URL(t, assertion.Response.ClientDataJSON); len(got) != 0 {
		t.Fatalf("clientDataJSON = %q, want empty", got)
	}
	if got := decodeBase64URL(t, assertion.Response.AuthenticatorData); len(got) != 0 {
		t.Fatalf("authenticatorData = %x, want empty", got)
	}
	verifyAssertionSignatureBytes(t, db, assertion)
}

func TestFieldOrderIsHonouredVerbatimIncludingDuplicates(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}
	assertion, err := Assertion(db, []byte(`{
		"options": `+testAssertionOptions+`,
		"clientData": {"fieldOrder": ["challenge", "type", "origin", "challenge", "notAField"]}
	}`), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}

	const want = `{"challenge":"YXNzZXJ0","type":"webauthn.get","origin":"https://example.com","challenge":"YXNzZXJ0"}`
	if got := decodeClientDataJSON(t, assertion.Response.ClientDataJSON); got != want {
		t.Fatalf("clientDataJSON =\n%s\nwant\n%s", got, want)
	}
	verifyAssertionSignatureBytes(t, db, assertion)
}

func TestTriStateProducesThreeDistinctOutputs(t *testing.T) {
	db := openTestDB(t)
	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}

	// Give every field a default so absent and null produce different output.
	loadTestProfile(t, "tristate", `{
		"fieldOrder": ["type", "challenge", "origin", "androidPackageName", "crossOrigin", "topOrigin"],
		"clientData": {
			"androidPackageName": "com.profile.default",
			"crossOrigin": false,
			"topOrigin": "https://profile.example"
		},
		"aaguid": "00000000-0000-0000-0000-000000000000",
		"transports": ["internal"]
	}`)

	// Flag bits are excluded because null and absent have the same meaning.
	cases := []struct {
		field   string
		section string
		value   string
		project func(*testing.T, *PublicKeyCredential[AuthenticatorAssertionResponse]) string
	}{
		{field: "type", section: "clientData", value: `"webauthn.create"`, project: projectClientData},
		{field: "challenge", section: "clientData", value: `"other"`, project: projectClientData},
		{field: "origin", section: "clientData", value: `"https://other.example"`, project: projectClientData},
		{field: "androidPackageName", section: "clientData", value: `"com.other"`, project: projectClientData},
		{field: "crossOrigin", section: "clientData", value: `true`, project: projectClientData},
		{field: "topOrigin", section: "clientData", value: `"https://top.example"`, project: projectClientData},
		{field: "flags", section: "authenticatorData", value: `255`, project: projectAuthDataWithoutCounter},
		{field: "rpIdHash", section: "authenticatorData", value: `"AAAA"`, project: projectAuthDataWithoutCounter},
		{field: "signCount", section: "authenticatorData", value: `4096`, project: projectSignCount},
	}

	for _, testCase := range cases {
		t.Run(testCase.field, func(t *testing.T) {
			outputs := map[string]string{}
			for _, variant := range []struct{ name, fragment string }{
				{"absent", ``},
				{"null", `,"` + testCase.section + `":{"` + testCase.field + `":null}`},
				{"value", `,"` + testCase.section + `":{"` + testCase.field + `":` + testCase.value + `}`},
			} {
				request := `{"profile":"tristate","options":` + testAssertionOptions + variant.fragment + `}`
				assertion, err := Assertion(db, []byte(request), nil)
				if err != nil {
					t.Fatalf("%s: Assertion failed: %v", variant.name, err)
				}
				outputs[variant.name] = testCase.project(t, assertion)
			}

			if outputs["absent"] == outputs["null"] {
				t.Fatalf("absent and null produced the same output: %s", outputs["absent"])
			}
			if outputs["absent"] == outputs["value"] {
				t.Fatalf("absent and an explicit value produced the same output: %s", outputs["absent"])
			}
			if outputs["null"] == outputs["value"] {
				t.Fatalf("null and an explicit value produced the same output: %s", outputs["null"])
			}
		})
	}
}

func TestAAGUIDTriStateOnAttestation(t *testing.T) {
	db := openTestDB(t)

	outputs := map[string]string{}
	for name, fragment := range map[string]string{
		"absent": ``,
		"null":   `,"authenticatorData":{"aaguid":null}`,
		"value":  `,"authenticatorData":{"aaguid":"6028b017-b1d4-4c02-b4b3-afcdafc96bb2"}`,
	} {
		attestation, err := Attestation(db, []byte(`{"profile":"android","options":`+testAttestationOptions+fragment+`}`), nil)
		if err != nil {
			t.Fatalf("%s: Attestation failed: %v", name, err)
		}
		authData := attestationAuthDataBytes(t, attestation.Response.AttestationObject)
		// The AAGUID starts after the 37-byte header.
		outputs[name] = hex.EncodeToString(authData[37:53])
	}

	if outputs["absent"] == outputs["null"] || outputs["absent"] == outputs["value"] || outputs["null"] == outputs["value"] {
		t.Fatalf("aaguid tri-state collapsed: %+v", outputs)
	}
}

func TestCallerSuppliedShortRPIDHashIsEmitted(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}
	// "AAAAAAAAAA" decodes to seven bytes.
	assertion, err := Assertion(db, []byte(`{
		"options": `+testAssertionOptions+`,
		"authenticatorData": {"rpIdHash": "AAAAAAAAAA"}
	}`), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}

	authData := decodeBase64URL(t, assertion.Response.AuthenticatorData)
	if len(authData) != 7+1+4 {
		t.Fatalf("authenticatorData length = %d, want 12", len(authData))
	}
	verifyAssertionSignatureBytes(t, db, assertion)
}

func TestDeriveRPIDHashPanicsOnAWrongLengthResult(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("expected a panic from a wrong-length self-derived rpIdHash")
		}
	}()
	assertDerivedRPIDHashLength([]byte("too short"), "example.com")
}

func TestDeriveRPIDHashReturnsTheRealHash(t *testing.T) {
	want := sha256.Sum256([]byte("example.com"))
	if got := DeriveRPIDHash("example.com"); string(got) != string(want[:]) {
		t.Fatalf("DeriveRPIDHash = %x, want %x", got, want)
	}
}

func TestStrictRejectsWhatTheDefaultPathEmits(t *testing.T) {
	db := openTestDB(t)
	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}

	cases := []struct {
		name      string
		overrides string
		wantError string
	}{
		{"mismatched rpIdHash", `"authenticatorData":{"rpIdHash":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo"}`, "does not match"},
		{"short rpIdHash", `"authenticatorData":{"rpIdHash":"AAAA"}`, "want at least"},
		{"UP cleared", `"authenticatorData":{"up":false}`, "UP flag is clear"},
		{"BS without BE", `"authenticatorData":{"bs":true}`, "BS is set without BE"},
		{"contradictory type", `"clientData":{"type":"webauthn.create"}`, "want \"webauthn.get\""},
		{"wrong challenge", `"clientData":{"challenge":"bm90LXRoZS1jaGFsbGVuZ2U"}`, "does not match the challenge"},
		{"missing origin", `"clientData":{"origin":null}`, `missing "origin"`},
		{"duplicate key", `"clientData":{"fieldOrder":["type","challenge","origin","challenge"]}`, "duplicate key"},
		{"not JSON at all", `"clientDataRaw":"bm90LWpzb24"`, "not valid JSON"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := `{"options":` + testAssertionOptions + `,` + testCase.overrides + `}`

			if _, err := Assertion(db, []byte(request), nil); err != nil {
				t.Fatalf("default path rejected the input: %v", err)
			}

			strictRequest := `{"validate":true,"options":` + testAssertionOptions + `,` + testCase.overrides + `}`
			err := mustAssertionError(t, db, strictRequest)
			if !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("strict error = %v, want it to mention %q", err, testCase.wantError)
			}
		})
	}
}

func TestStrictAcceptsConformantOutput(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(`{"validate":true,"options":`+testAttestationOptions+`}`), nil); err != nil {
		t.Fatalf("strict attestation rejected conformant output: %v", err)
	}
	if _, err := Assertion(db, []byte(`{"validate":true,"options":`+testAssertionOptions+`}`), nil); err != nil {
		t.Fatalf("strict assertion rejected conformant output: %v", err)
	}
	if _, err := Assertion(db, []byte(`{"validate":true,"profile":"android","options":`+testAssertionOptions+`}`), nil); err != nil {
		t.Fatalf("strict assertion rejected the android profile: %v", err)
	}
}

func TestDirectOverrideBeatsEnvelope(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}

	flagOrigin := ClientDataOverrides{}
	flagOrigin.Origin.SetValue("https://from-flag.example")

	assertion, err := Assertion(db, []byte(`{
		"options": `+testAssertionOptions+`,
		"clientData": {"origin": "https://from-envelope.example", "topOrigin": "https://kept.example"}
	}`), &AssertionOverrides{CeremonyOverrides: CeremonyOverrides{ClientData: &flagOrigin}})
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}

	clientData := decodeClientDataJSON(t, assertion.Response.ClientDataJSON)
	if !strings.Contains(clientData, `"origin":"https://from-flag.example"`) {
		t.Fatalf("clientDataJSON %s did not take the flag origin", clientData)
	}
	if !strings.Contains(clientData, `"topOrigin":"https://kept.example"`) {
		t.Fatalf("clientDataJSON %s dropped the envelope topOrigin", clientData)
	}
}

func TestUnknownProfileIsRejected(t *testing.T) {
	db := openTestDB(t)

	_, err := Attestation(db, []byte(`{"profile":"nosuch","options":`+testAttestationOptions+`}`), nil)
	if err == nil || !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("error = %v, want it to mention an unknown profile", err)
	}
}

func TestSignCountOverrideIsEmittedVerbatim(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}
	for range 3 {
		if _, err := Assertion(db, []byte(testAssertionOptions), nil); err != nil {
			t.Fatalf("Assertion failed: %v", err)
		}
	}

	assertion, err := Assertion(db, []byte(`{
		"options": `+testAssertionOptions+`,
		"authenticatorData": {"signCount": 0}
	}`), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}

	parsed, err := ParseAuthenticatorData(decodeBase64URL(t, assertion.Response.AuthenticatorData))
	if err != nil {
		t.Fatalf("ParseAuthenticatorData failed: %v", err)
	}
	if parsed.SignCount != 0 {
		t.Fatalf("signCount = %d, want 0", parsed.SignCount)
	}
	verifyAssertionSignature(t, db, assertion)
}

func TestUVFalseClearsBitAndStillVerifies(t *testing.T) {
	db := openTestDB(t)

	if _, err := Attestation(db, []byte(testAttestationOptions), nil); err != nil {
		t.Fatalf("Attestation failed: %v", err)
	}
	assertion, err := Assertion(db, []byte(`{
		"options": {"challenge":"YXNzZXJ0","rpId":"example.com","userVerification":"required"},
		"authenticatorData": {"uv": false}
	}`), nil)
	if err != nil {
		t.Fatalf("Assertion failed: %v", err)
	}

	authData := decodeBase64URL(t, assertion.Response.AuthenticatorData)
	if authData[32]&BitUV != 0 {
		t.Fatalf("UV bit set in flags 0x%02x, want clear", authData[32])
	}
	verifyAssertionSignature(t, db, assertion)
}

func assertDerivedRPIDHashLength(hash []byte, relyingPartyID string) {
	if len(hash) != sha256.Size {
		panic("webauthn: derived rpIdHash for " + relyingPartyID + " is the wrong length")
	}
}

func mustAssertionError(t *testing.T, db *sql.DB, request string) error {
	t.Helper()

	_, err := Assertion(db, []byte(request), nil)
	if err == nil {
		t.Fatal("expected strict validation to reject this output")
	}
	return err
}

func projectClientData(t *testing.T, assertion *PublicKeyCredential[AuthenticatorAssertionResponse]) string {
	t.Helper()
	return decodeClientDataJSON(t, assertion.Response.ClientDataJSON)
}

// Ignore the counter so successive assertions can be compared.
func projectAuthDataWithoutCounter(t *testing.T, assertion *PublicKeyCredential[AuthenticatorAssertionResponse]) string {
	t.Helper()

	authData := decodeBase64URL(t, assertion.Response.AuthenticatorData)
	if len(authData) < 37 {
		return hex.EncodeToString(authData)
	}
	return hex.EncodeToString(authData[:33]) + "|" + hex.EncodeToString(authData[37:])
}

func projectSignCount(t *testing.T, assertion *PublicKeyCredential[AuthenticatorAssertionResponse]) string {
	t.Helper()

	authData := decodeBase64URL(t, assertion.Response.AuthenticatorData)
	if len(authData) < 37 {
		return "omitted"
	}
	return hex.EncodeToString(authData[33:37])
}

func loadTestProfile(t *testing.T, name, definition string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(path, []byte(`{"`+name+`":`+definition+`}`), 0o600); err != nil {
		t.Fatalf("failed to write profiles file: %v", err)
	}
	if err := LoadProfiles(path); err != nil {
		t.Fatalf("LoadProfiles failed: %v", err)
	}
	t.Cleanup(func() {
		if err := LoadProfiles(""); err != nil {
			t.Fatalf("failed to restore the built-in profiles: %v", err)
		}
	})
}

func decodeBase64URL(t *testing.T, encoded string) []byte {
	t.Helper()

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("failed to base64url decode %q: %v", encoded, err)
	}
	return decoded
}

func decodeClientDataJSON(t *testing.T, encoded string) string {
	t.Helper()
	return string(decodeBase64URL(t, encoded))
}

func attestationAuthDataBytes(t *testing.T, attestationObject string) []byte {
	t.Helper()

	var attObj AttestationObject
	if err := cbor.Unmarshal(decodeBase64URL(t, attestationObject), &attObj); err != nil {
		t.Fatalf("failed to unmarshal attestation object: %v", err)
	}
	return attObj.AuthData
}

func parseAttestationAuthData(t *testing.T, attestationObject string) *ParsedAuthenticatorData {
	t.Helper()

	parsed, err := ParseAuthenticatorData(attestationAuthDataBytes(t, attestationObject))
	if err != nil {
		t.Fatalf("ParseAuthenticatorData failed: %v", err)
	}
	return parsed
}

func verifyAssertionSignature(t *testing.T, db *sql.DB, assertion *PublicKeyCredential[AuthenticatorAssertionResponse]) {
	t.Helper()

	verifyAssertionSignatureBytes(t, db, assertion)

	clientDataJSON := decodeBase64URL(t, assertion.Response.ClientDataJSON)
	var probe map[string]any
	if err := json.Unmarshal(clientDataJSON, &probe); err != nil {
		t.Fatalf("emitted clientDataJSON is not valid JSON: %v", err)
	}
}

// Verify against the emitted bytes to catch overrides applied after signing.
func verifyAssertionSignatureBytes(t *testing.T, db *sql.DB, assertion *PublicKeyCredential[AuthenticatorAssertionResponse]) {
	t.Helper()

	entry, err := keystore.GetCredentialByID(db, assertion.ID)
	if err != nil {
		t.Fatalf("GetCredentialByID failed: %v", err)
	}
	if entry == nil {
		t.Fatalf("credential %s not found in keystore", assertion.ID)
	}

	privateKey, err := keystore.LoadPrivateKeyFromPEM(entry.PrivateKeyFilePath)
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromPEM failed: %v", err)
	}
	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("stored key is %T, want *ecdsa.PrivateKey", privateKey)
	}

	authData := decodeBase64URL(t, assertion.Response.AuthenticatorData)
	clientDataJSON := decodeBase64URL(t, assertion.Response.ClientDataJSON)
	clientDataHash := sha256.Sum256(clientDataJSON)

	signedData := make([]byte, 0, len(authData)+len(clientDataHash))
	signedData = append(signedData, authData...)
	signedData = append(signedData, clientDataHash[:]...)
	digest := sha256.Sum256(signedData)

	signature := decodeBase64URL(t, assertion.Response.Signature)
	if !ecdsa.VerifyASN1(&ecdsaKey.PublicKey, digest[:], signature) {
		t.Fatal("signature does not verify over the emitted authenticatorData || SHA256(clientDataJSON)")
	}
}
