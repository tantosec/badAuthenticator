package handlers

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/tantosec/badAuthenticator/pkg/logging"
)

const maxRequestBodyBytes = 10 << 20

type webAuthnLogicFunc func(db *sql.DB, jsonBytes []byte) (response any, err error)

// The full request body is forwarded so overrides alongside options are preserved.
type apiRequestPayload struct {
	Options json.RawMessage `json:"options"`
}

func WebAuthnAPIHandler(db *sql.DB, logicFunc webAuthnLogicFunc, operationName string, postOnly bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := logging.GetLogger()
		var jsonBytes []byte
		var optionsBytes []byte
		var err error

		switch r.Method {
		case http.MethodPost:
			bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
			if err != nil {
				var sizeError *http.MaxBytesError
				if errors.As(err, &sizeError) {
					writeAPIError(w, newAPIError(http.StatusRequestEntityTooLarge, "request_body_too_large", "Request body exceeds 10 MiB", err))
					return
				}
				logger.Error("Failed to read request body", "error", err)
				writeAPIError(w, newAPIError(http.StatusInternalServerError, "request_body_read_failed", "Cannot read request body", err))
				return
			}

			var payload apiRequestPayload
			if err := json.Unmarshal(bodyBytes, &payload); err != nil {
				logger.Error("Failed to unmarshal request payload", "error", err)
				writeAPIError(w, newAPIError(http.StatusBadRequest, "invalid_json", "Invalid JSON payload structure", err))
				return
			}
			optionsBytes = payload.Options
			jsonBytes = bodyBytes

		case http.MethodGet:

			if postOnly {
				w.Header().Set("Allow", http.MethodPost)
				writeAPIError(w, newAPIError(http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed", nil))
				return
			}
			encodedData := r.URL.Query().Get("options")
			if encodedData == "" {
				writeAPIError(w, newAPIError(http.StatusBadRequest, "missing_options", "Missing options payload in request", nil))
				return
			}
			if strings.HasPrefix(strings.TrimSpace(encodedData), "{") {
				jsonBytes = []byte(encodedData)
			} else {
				jsonBytes, err = base64.RawURLEncoding.DecodeString(encodedData)
				if err != nil {
					logger.Error("Failed to decode base64url payload", "error", err)
					writeAPIError(w, newAPIError(http.StatusBadRequest, "invalid_base64url_options", "Options must be JSON or unpadded base64url JSON", err))
					return
				}
			}
			optionsBytes = jsonBytes

		default:
			allowed := "GET, POST"
			if postOnly {
				allowed = http.MethodPost
			}
			w.Header().Set("Allow", allowed)
			writeAPIError(w, newAPIError(http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed", nil))
			return
		}

		if len(optionsBytes) == 0 {
			writeAPIError(w, newAPIError(http.StatusBadRequest, "missing_data", "Missing data payload in request", nil))
			return
		}

		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, jsonBytes, "", "  "); err != nil {
			logger.Debug("Received and decoded (malformed) options", "operation", operationName, "body", string(jsonBytes))
		} else {
			logger.Debug("Received and decoded options", "operation", operationName, "body", "\n"+prettyJSON.String())
		}

		responseObject, err := logicFunc(db, jsonBytes)
		if err != nil {
			logger.Error("Handler logic failed", "operation", operationName, "error", err)
			writeAPIError(w, apiErrorFrom(err, operationName+" failed"))
			return
		}

		jsonResponseBytes, err := json.Marshal(responseObject)
		if err != nil {
			logger.Error("Failed to marshal response for API", "operation", operationName, "error", err)
			writeAPIError(w, newAPIError(http.StatusInternalServerError, "response_marshal_failed", "Internal Server Error", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(jsonResponseBytes)
	}
}
