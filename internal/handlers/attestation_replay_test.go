package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/tantosec/badAuthenticator/internal/config"
	"github.com/tantosec/badAuthenticator/internal/keystore"
)

func requestAttestation(handler http.Handler, method, options string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1/attest", strings.NewReader(`{"options":`+options+`}`))
	if method == http.MethodGet {
		req = httptest.NewRequest(method, "/api/v1/attest?options="+base64.RawURLEncoding.EncodeToString([]byte(options)), nil)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func requireAttestation(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ID == "" {
		t.Fatal("missing credential ID")
	}
	return response.ID
}

func requireCredentialCount(t *testing.T, db *sql.DB, want int) {
	t.Helper()
	entries, err := keystore.ListAllCredentialEntries(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != want {
		t.Fatalf("credentials = %d, want %d", len(entries), want)
	}
	keys, err := filepath.Glob(filepath.Join(config.KeyFileDir, "*.key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != want {
		t.Fatalf("private keys = %d, want %d", len(keys), want)
	}
}

func TestAttestationGETOptIn(t *testing.T) {
	db := openTestKeystore(t)
	for _, enabled := range []bool{false, true} {
		handler := AttestationAPIHandler(db, enabled)
		allowed := "POST"
		if enabled {
			allowed = "GET, POST"
		}
		for _, method := range []string{http.MethodHead, http.MethodPut, http.MethodDelete} {
			rec := requestAttestation(handler, method, attestationOptions)
			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != allowed {
				t.Fatalf("enabled=%t method=%s: status=%d Allow=%q", enabled, method, rec.Code, rec.Header().Get("Allow"))
			}
		}
		rec := requestAttestation(handler, http.MethodGet, attestationOptions)
		if enabled {
			requireAttestation(t, rec)
		} else {
			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
				t.Fatalf("GET: %d %v", rec.Code, rec.Header())
			}
			requireCredentialCount(t, db, 0)
		}
	}
	requireCredentialCount(t, db, 1)
}

func TestAttestationPOSTAllowsDuplicates(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "GET enabled"}[enabled], func(t *testing.T) {
			db := openTestKeystore(t)
			handler := AttestationAPIHandler(db, enabled)
			first := requireAttestation(t, requestAttestation(handler, http.MethodPost, attestationOptions))
			second := requireAttestation(t, requestAttestation(handler, http.MethodPost, attestationOptions))
			if first == second {
				t.Fatal("duplicate POST reused a credential")
			}
			if enabled {
				getID := requireAttestation(t, requestAttestation(handler, http.MethodGet, attestationOptions))
				if getID == first || getID == second {
					t.Fatal("GET reused a POST credential")
				}
				third := requireAttestation(t, requestAttestation(handler, http.MethodPost, attestationOptions))
				if third == getID {
					t.Fatal("POST reused a GET credential")
				}
				requireCredentialCount(t, db, 4)
			} else {
				requireCredentialCount(t, db, 2)
			}
		})
	}
}

func TestAttestationGETReplaySurvivesReopen(t *testing.T) {
	db := openTestKeystore(t)
	handler := AttestationAPIHandler(db, true)
	original := requestAttestation(handler, http.MethodGet, attestationOptions)
	id := requireAttestation(t, original)
	if err := keystore.UpdateCredentialByID(db, id, "SignCount", "7"); err != nil {
		t.Fatal(err)
	}
	before, err := keystore.GetCredentialByID(db, id)
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(before.PrivateKeyFilePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := keystore.OpenAndVerifyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	handler = AttestationAPIHandler(reopened, true)
	// Formatting, display names and overrides are not part of the tuple.
	envelope := `{"profile":"windows-hello-software", "options":` + strings.ReplaceAll(attestationOptions, `"name":"u"`, `"name":"renamed"`) + `}`
	replay := requestAttestation(handler, http.MethodGet, envelope)
	requireAttestation(t, replay)
	if replay.Body.String() != original.Body.String() {
		t.Fatal("replay response changed")
	}
	after, err := keystore.GetCredentialByID(reopened, id)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("metadata changed: %+v -> %+v", before, after)
	}
	keyAfter, err := os.ReadFile(after.PrivateKeyFilePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(keyBefore) != string(keyAfter) {
		t.Fatal("private key changed")
	}
	requireCredentialCount(t, reopened, 1)
}

func TestAttestationGETTuple(t *testing.T) {
	db := openTestKeystore(t)
	handler := AttestationAPIHandler(db, true)
	seen := map[string]bool{}
	for _, options := range []string{
		attestationOptions,
		strings.ReplaceAll(attestationOptions, "example.com", "other.example"),
		strings.ReplaceAll(attestationOptions, "dXNlcg", "b3RoZXI"),
		strings.ReplaceAll(attestationOptions, "Y2hhbGxlbmdl", "bmV3"),
	} {
		first := requestAttestation(handler, http.MethodGet, options)
		id := requireAttestation(t, first)
		if seen[id] {
			t.Fatal("different tuple reused a credential")
		}
		seen[id] = true
		second := requestAttestation(handler, http.MethodGet, options)
		requireAttestation(t, second)
		if first.Body.String() != second.Body.String() {
			t.Fatal("tuple replay changed response")
		}
	}
	requireCredentialCount(t, db, 4)
}

func TestAttestationGETConcurrentReplay(t *testing.T) {
	db := openTestKeystore(t)
	otherDB, err := keystore.OpenAndVerifyDB()
	if err != nil {
		t.Fatal(err)
	}
	defer otherDB.Close()
	handlers := []http.Handler{AttestationAPIHandler(db, true), AttestationAPIHandler(otherDB, true)}
	const count = 12
	results := make([]*httptest.ResponseRecorder, count)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range results {
		wg.Go(func() {
			<-start
			results[i] = requestAttestation(handlers[i%len(handlers)], http.MethodGet, attestationOptions)
		})
	}
	close(start)
	wg.Wait()
	for _, rec := range results {
		requireAttestation(t, rec)
		if rec.Body.String() != results[0].Body.String() {
			t.Fatal("concurrent replay created a different response")
		}
	}
	requireCredentialCount(t, db, 1)
}

func TestAttestationGETFailuresCanBeRetried(t *testing.T) {
	db := openTestKeystore(t)
	handler := AttestationAPIHandler(db, true)
	for _, options := range []string{
		strings.ReplaceAll(attestationOptions, `"id":"example.com"`, `"id":""`),
		strings.ReplaceAll(attestationOptions, `"id":"dXNlcg"`, `"id":""`),
		strings.ReplaceAll(attestationOptions, `"challenge":"Y2hhbGxlbmdl"`, `"challenge":""`),
		strings.ReplaceAll(attestationOptions, `"alg":-7`, `"alg":0`),
		`{"options":` + attestationOptions + `,"validate":true,"clientData":{"type":"wrong"}}`,
	} {
		rec := requestAttestation(handler, http.MethodGet, options)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		requireCredentialCount(t, db, 0)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_replay BEFORE UPDATE ON attestation_replays
        BEGIN SELECT RAISE(ABORT, 'test storage failure'); END`); err != nil {
		t.Fatal(err)
	}
	failed := requestAttestation(handler, http.MethodGet, attestationOptions)
	if failed.Code != http.StatusInternalServerError {
		t.Fatalf("storage failure status=%d: %s", failed.Code, failed.Body.String())
	}
	requireCredentialCount(t, db, 0)
	var cached int
	if err := db.QueryRow("SELECT COUNT(*) FROM attestation_replays").Scan(&cached); err != nil {
		t.Fatal(err)
	}
	if cached != 0 {
		t.Fatalf("failed requests cached %d results", cached)
	}
	if _, err := db.Exec("DROP TRIGGER fail_replay"); err != nil {
		t.Fatal(err)
	}
	requireAttestation(t, requestAttestation(handler, http.MethodGet, attestationOptions))
	requireCredentialCount(t, db, 1)
}

func TestAttestationGETJSONAndBase64ShareReplay(t *testing.T) {
	db := openTestKeystore(t)
	handler := AttestationAPIHandler(db, true)
	body := `{"options":` + attestationOptions + `,"clientData":{"origin":"https://example.com/a+b?x=1&y=2"}}`
	var original string
	for _, payload := range []string{body, " \n" + body, base64.RawURLEncoding.EncodeToString([]byte(body))} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/attest?options="+url.QueryEscape(payload), nil))
		requireAttestation(t, rec)
		if original == "" {
			original = rec.Body.String()
		}
		if rec.Body.String() != original {
			t.Fatal("encoding changed replay identity")
		}
		var clientData struct {
			Origin string `json:"origin"`
		}
		if err := json.Unmarshal([]byte(decodeResponseClientData(t, rec.Body.Bytes())), &clientData); err != nil {
			t.Fatal(err)
		}
		if clientData.Origin != "https://example.com/a+b?x=1&y=2" {
			t.Fatalf("URL decoding changed origin: %q", clientData.Origin)
		}
	}
	requireCredentialCount(t, db, 1)
	for _, payload := range []string{`{"options":`, "%%%"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/attest?options="+url.QueryEscape(payload), nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("malformed options: %d", rec.Code)
		}
	}
	requireCredentialCount(t, db, 1)
}
