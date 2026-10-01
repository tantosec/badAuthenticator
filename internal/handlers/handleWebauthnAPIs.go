package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/tantosec/badAuthenticator/internal/keystore"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

type CredentialListResponse struct {
	Credentials []ListEntryJSON `json:"credentials"`
}

func AttestationAPIHandler(db *sql.DB, allowGET bool) http.HandlerFunc {
	logicFunc := func(db *sql.DB, jsonBytes []byte) (any, error) {
		attestationResponse, err := HandleAttestation(db, jsonBytes, nil)
		return attestationResponse, err
	}
	postHandler := WebAuthnAPIHandler(db, logicFunc, "attestation", !allowGET)
	if !allowGET {
		return postHandler
	}
	getHandler := WebAuthnAPIHandler(db, replayAttestation, "attestation", false)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getHandler(w, r)
			return
		}
		postHandler(w, r)
	}
}

func AssertionAPIHandler(db *sql.DB) http.HandlerFunc {
	logicFunc := func(db *sql.DB, jsonBytes []byte) (any, error) {
		assertionResponse, err := HandleAssertion(db, jsonBytes, nil)
		return assertionResponse, err
	}
	return WebAuthnAPIHandler(db, logicFunc, "assertion", true)
}

func ListCredsAPIHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := logging.GetLogger()
		logger.Debug("ListCredsAPIHandler called")

		switch r.Method {
		case http.MethodGet:
			rpid := r.URL.Query().Get("rpid")
			if rpid == "" {
				writeAPIError(w, newAPIError(http.StatusBadRequest, "missing_rpid", "Missing rpid query parameter", nil))
				return
			}

			entries, err := keystore.ListCredentialsByRPID(db, rpid)
			if err != nil {
				logger.Error("Failed to list credentials", "error", err)
				writeAPIError(w, newAPIError(http.StatusInternalServerError, "list_credentials_failed", "Failed to list credentials", err))
				return
			}

			entriesForRP := []ListEntryJSON{}
			for _, entry := range entries {

				decodedUserHandle, err := base64.RawURLEncoding.DecodeString(entry.UserHandle)
				if err != nil {
					logger.Error("Failed to decode userHandle for a credential", "credentialID", entry.CredentialID, "error", err)
					continue
				}

				jsonOutput := ListEntryJSON{
					CredentialID: entry.CredentialID,
					RPID:         entry.RPID,
					UserHandle:   string(decodedUserHandle),
					SignCount:    entry.SignCount,
					CreationDate: entry.CreationDate,

					Origin:             entry.Origin,
					AndroidPackageName: entry.AndroidPackageName,
					Profile:            entry.Profile,
				}

				entriesForRP = append(entriesForRP, jsonOutput)
			}

			responsePayload := CredentialListResponse{
				Credentials: entriesForRP,
			}

			jsonResponse, err := json.Marshal(responsePayload)
			if err != nil {
				writeAPIError(w, newAPIError(http.StatusInternalServerError, "response_marshal_failed", "Failed to create JSON response", err))
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(jsonResponse)

		default:
			writeAPIError(w, newAPIError(http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed", nil))
			return
		}

	}
}
