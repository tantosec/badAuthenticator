package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/tantosec/badAuthenticator/internal/config"
	"github.com/tantosec/badAuthenticator/internal/keystore"
	"github.com/tantosec/badAuthenticator/internal/types"
	"github.com/tantosec/badAuthenticator/internal/webauthn"
)

const (
	attestationOptions = `{"rp":{"id":"example.com","name":"Example"},` +
		`"user":{"id":"dXNlcg","name":"u","displayName":"U"},` +
		`"challenge":"Y2hhbGxlbmdl",` +
		`"pubKeyCredParams":[{"type":"public-key","alg":-7}]}`

	androidOrigin      = "android:apk-key-hash:qz7fNlJErX_Gi-GXFgi60o7uP_ByiGFuP_OouU-M8Hc"
	androidPackageName = "com.example.app"
)

func TestAttestationAPIHandlerAppliesEnvelopeOverrides(t *testing.T) {
	db := openTestKeystore(t)

	body := `{"profile":"android","options":` + attestationOptions +
		`,"clientData":{"origin":"` + androidOrigin + `","androidPackageName":"` + androidPackageName + `"}` +
		`,"authenticatorData":{"uv":false}}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/attest", strings.NewReader(body))
	rec := httptest.NewRecorder()
	AttestationAPIHandler(db, true).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	clientData := decodeResponseClientData(t, rec.Body.Bytes())
	want := `{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"` + androidOrigin +
		`","androidPackageName":"` + androidPackageName + `"}`
	if clientData != want {
		t.Fatalf("clientDataJSON =\n%s\nwant\n%s", clientData, want)
	}
}

func TestAttestationAPIHandlerWithoutOverridesUsesWebProfile(t *testing.T) {
	db := openTestKeystore(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/attest", strings.NewReader(`{"options":`+attestationOptions+`}`))
	rec := httptest.NewRecorder()
	AttestationAPIHandler(db, true).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	const want = `{"type":"webauthn.create","challenge":"Y2hhbGxlbmdl","origin":"https://example.com","crossOrigin":false}`
	if got := decodeResponseClientData(t, rec.Body.Bytes()); got != want {
		t.Fatalf("clientDataJSON =\n%s\nwant\n%s", got, want)
	}
}

func TestAttestationAPIHandlerGETAcceptsEnvelope(t *testing.T) {
	db := openTestKeystore(t)

	envelope := `{"options":` + attestationOptions + `,"clientData":{"origin":"` + androidOrigin + `"}}`
	encoded := base64.RawURLEncoding.EncodeToString([]byte(envelope))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attest?options="+encoded, nil)
	rec := httptest.NewRecorder()
	AttestationAPIHandler(db, true).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := decodeResponseClientData(t, rec.Body.Bytes()); !strings.Contains(got, `"origin":"`+androidOrigin+`"`) {
		t.Fatalf("clientDataJSON %s did not use the envelope origin", got)
	}
}

func TestExportImportRoundTripsStoredOrigin(t *testing.T) {
	db := openTestKeystore(t)

	body := `{"profile":"android","options":` + attestationOptions +
		`,"clientData":{"origin":"` + androidOrigin + `","androidPackageName":"` + androidPackageName + `"}}`
	response, err := HandleAttestation(db, []byte(body), nil)
	if err != nil {
		t.Fatalf("HandleAttestation failed: %v", err)
	}

	exported, err := HandleExportKey(db, response.ID)
	if err != nil {
		t.Fatalf("HandleExportKey failed: %v", err)
	}
	if exported.Origin != androidOrigin || exported.AndroidPackageName != androidPackageName {
		t.Fatalf("exported origin/package = %q/%q, want %q/%q",
			exported.Origin, exported.AndroidPackageName, androidOrigin, androidPackageName)
	}
	if exported.Profile != "android" {
		t.Fatalf("exported profile = %q, want %q", exported.Profile, "android")
	}

	reimported := *exported
	reimported.CredentialID = base64.RawURLEncoding.EncodeToString([]byte("reimported-credential"))
	if err := keystore.ImportCredential(db, types.CredentialTransfer(reimported)); err != nil {
		t.Fatalf("ImportCredential failed: %v", err)
	}

	entry, err := keystore.GetCredentialByID(db, reimported.CredentialID)
	if err != nil {
		t.Fatalf("GetCredentialByID failed: %v", err)
	}
	if entry == nil {
		t.Fatal("re-imported credential not found")
	}
	if entry.Origin != androidOrigin || entry.AndroidPackageName != androidPackageName {
		t.Fatalf("imported origin/package = %q/%q, want %q/%q",
			entry.Origin, entry.AndroidPackageName, androidOrigin, androidPackageName)
	}
	if entry.Profile != "android" {
		t.Fatalf("imported profile = %q, want %q", entry.Profile, "android")
	}

	if err := keystore.UpdateCredentialByID(db, reimported.CredentialID, "Origin", "https://edited.example"); err != nil {
		t.Fatalf("UpdateCredentialByID failed: %v", err)
	}
	updated, err := keystore.GetCredentialByID(db, reimported.CredentialID)
	if err != nil {
		t.Fatalf("GetCredentialByID failed: %v", err)
	}
	if updated.Origin != "https://edited.example" {
		t.Fatalf("updated origin = %q, want %q", updated.Origin, "https://edited.example")
	}
}

func decodeResponseClientData(t *testing.T, responseBody []byte) string {
	t.Helper()

	var response webauthn.PublicKeyCredential[webauthn.AuthenticatorAttestationResponse]
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("failed to unmarshal handler response: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(response.Response.ClientDataJSON)
	if err != nil {
		t.Fatalf("failed to decode clientDataJSON: %v", err)
	}
	return string(decoded)
}

func openTestKeystore(t *testing.T) *sql.DB {
	t.Helper()

	oldKeystoreDir := config.KeystoreDir
	oldKeyFileDir := config.KeyFileDir
	keystoreDir := filepath.Join(t.TempDir(), "keystore")
	config.KeystoreDir = keystoreDir
	config.KeyFileDir = filepath.Join(keystoreDir, "keys")
	t.Cleanup(func() {
		config.KeystoreDir = oldKeystoreDir
		config.KeyFileDir = oldKeyFileDir
	})

	db, err := keystore.OpenAndVerifyDB()
	if err != nil {
		t.Fatalf("OpenAndVerifyDB failed: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil && err != sql.ErrConnDone {
			t.Fatalf("db.Close failed: %v", err)
		}
	})
	return db
}

func TestAttestationAPIWindowsHelloProfile(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			db := openTestKeystore(t)
			body := `{"options":` + attestationOptions + `,"profile":"windows-hello-software"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/attest", strings.NewReader(body))
			if method == http.MethodGet {
				req = httptest.NewRequest(method, "/api/v1/attest?options="+base64.RawURLEncoding.EncodeToString([]byte(body)), nil)
			}
			rec := httptest.NewRecorder()
			AttestationAPIHandler(db, true).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
			}
			var response webauthn.PublicKeyCredential[webauthn.AuthenticatorAttestationResponse]
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			raw, err := base64.RawURLEncoding.DecodeString(response.Response.AttestationObject)
			if err != nil {
				t.Fatal(err)
			}
			var obj webauthn.AttestationObject
			if err := cbor.Unmarshal(raw, &obj); err != nil {
				t.Fatal(err)
			}
			if obj.Format != "packed" {
				t.Fatalf("format = %q", obj.Format)
			}
			parsed, err := webauthn.ParseAuthenticatorData(obj.AuthData)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.AttestedCredentialData == nil || parsed.AttestedCredentialData.AAGUID != "6028b017b1d44c02b4b3afcdafc96bb2" {
				t.Fatalf("unexpected AAGUID: %+v", parsed.AttestedCredentialData)
			}
			entry, err := keystore.GetCredentialByID(db, response.ID)
			if err != nil || entry == nil || entry.Profile != webauthn.ProfileWindowsHelloSoftware {
				t.Fatalf("profile was not stored: %+v, %v", entry, err)
			}
		})
	}
}
