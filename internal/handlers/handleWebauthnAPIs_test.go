package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/tantosec/badAuthenticator/internal/keystore"
)

func TestListCredsAPIHandlerRequiresRPID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/listCredentials", nil)
	rec := httptest.NewRecorder()

	ListCredsAPIHandler(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	assertAPIError(t, rec.Body.String(), "missing_rpid", "Missing rpid query parameter")
}

func TestWebAuthnAPIHandlerDoesNotExposeRawLogicError(t *testing.T) {
	handler := WebAuthnAPIHandler(nil, func(db *sql.DB, jsonBytes []byte) (any, error) {
		return nil, errors.New("secret internal detail")
	}, "test operation", true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/assert", strings.NewReader(`{"options":{"challenge":"abc"}}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	assertAPIError(t, rec.Body.String(), "operation_failed", "test operation failed")
	if strings.Contains(rec.Body.String(), "secret internal detail") {
		t.Fatalf("response leaked internal error detail: %s", rec.Body.String())
	}
}

func assertAPIError(t *testing.T, body string, wantCode string, wantError string) {
	t.Helper()

	var got map[string]string
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("failed to unmarshal API error body %q: %v", body, err)
	}
	if got["code"] != wantCode {
		t.Fatalf("code = %q, want %q", got["code"], wantCode)
	}
	if got["error"] != wantError {
		t.Fatalf("error = %q, want %q", got["error"], wantError)
	}
}

func TestWebAuthnAPIHandlerBodySize(t *testing.T) {
	const limit = 10 << 20
	const prefix = `{"options":{}}`
	for _, tc := range []struct {
		name       string
		size       int
		wantStatus int
	}{
		{"below limit", limit - 1, http.StatusOK},
		{"at limit", limit, http.StatusOK},
		{"over limit", limit + 1, http.StatusRequestEntityTooLarge},
	} {
		for _, length := range []string{"known length", "streamed"} {
			t.Run(tc.name+"/"+length, func(t *testing.T) {
				called := false
				handler := WebAuthnAPIHandler(nil, func(_ *sql.DB, body []byte) (any, error) {
					called = true
					if len(body) != tc.size {
						t.Fatalf("body length = %d, want %d", len(body), tc.size)
					}
					return map[string]bool{"ok": true}, nil
				}, "test", true)
				body := prefix + strings.Repeat(" ", tc.size-len(prefix))
				req := httptest.NewRequest(http.MethodPost, "/api/v1/attest", strings.NewReader(body))
				if length == "streamed" {
					req.ContentLength = -1
					req.TransferEncoding = []string{"chunked"}
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != tc.wantStatus {
					t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
				}
				if called != (tc.wantStatus == http.StatusOK) {
					t.Fatalf("ceremony called = %v for status %d", called, rec.Code)
				}
				if tc.wantStatus == http.StatusRequestEntityTooLarge {
					assertAPIError(t, rec.Body.String(), "request_body_too_large", "Request body exceeds 10 MiB")
				}
			})
		}
	}
}

func TestListCredsFiltersRPBeforeReadingRows(t *testing.T) {
	db := openTestKeystore(t)
	for _, rpid := range []string{"example.com", "other.example"} {
		body := strings.ReplaceAll(attestationOptions, "example.com", rpid)
		if _, err := HandleAttestation(db, []byte(body), nil); err != nil {
			t.Fatal(err)
		}
	}
	// A malformed row for another RP must not be scanned or decoded.
	if _, err := db.Exec(`UPDATE credentials SET SignCount = 'invalid', UserHandle = '%' WHERE RPID = ?`, "other.example"); err != nil {
		t.Fatal(err)
	}
	for _, rpid := range []string{"example.com", "missing.example", "example.com' OR 1=1 --"} {
		rec := httptest.NewRecorder()
		ListCredsAPIHandler(db).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/listCredentials?rpid="+url.QueryEscape(rpid), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		var response CredentialListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		want := 0
		if rpid == "example.com" {
			want = 1
		}
		if len(response.Credentials) != want {
			t.Fatalf("credentials = %d, want %d", len(response.Credentials), want)
		}
		if want == 0 && response.Credentials == nil {
			t.Fatal("empty result should be an array")
		}
	}
	entries, err := keystore.ListCredentialsByRPID(db, "example.com")
	if err != nil || len(entries) != 1 {
		t.Fatalf("RP query: %v, %v", entries, err)
	}
}
