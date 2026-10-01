package middleware

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
)

func BearerTokenAuthMiddleware(next http.Handler, validTokens []string) http.Handler {
	var tokens []string
	for _, token := range validTokens {
		if token != "" {
			tokens = append(tokens, token)
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(tokens) == 0 {
			writeJSONError(w, http.StatusUnauthorized, "auth_not_configured", "Unauthorized")
			return
		}

		authHeader := r.Header.Get("Authorization")

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			writeJSONError(w, http.StatusUnauthorized, "missing_bearer_token", "Unauthorized")
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		if token == "" {
			writeJSONError(w, http.StatusUnauthorized, "empty_bearer_token", "Unauthorized")
			return
		}

		// Compare equal-length tokens in constant time.
		valid := false
		for _, validToken := range tokens {
			if subtle.ConstantTimeCompare([]byte(token), []byte(validToken)) == 1 {
				valid = true
				break
			}
		}

		if !valid {
			writeJSONError(w, http.StatusUnauthorized, "invalid_bearer_token", "Unauthorized")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeJSONError(w http.ResponseWriter, status int, code string, message string) {
	responseBytes, err := json.Marshal(map[string]string{
		"code":  code,
		"error": message,
	})
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(responseBytes)
}
