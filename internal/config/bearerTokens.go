package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/tantosec/badAuthenticator/pkg/logging"
)

func generateSecureToken() (string, error) {
	bytes := make([]byte, GeneratedBearerTokenBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// LoadBearerTokens reads comma-separated tokens from the environment.
// If unset, it generates a token and logs it once at startup.
func LoadBearerTokens() ([]string, error) {
	logger := logging.GetLogger()
	var validTokens []string

	tokensStr := os.Getenv("BAD_AUTHENTICATOR_BEARER_TOKENS")

	if tokensStr == "" {
		logger.Warn("BAD_AUTHENTICATOR_BEARER_TOKENS is not set.")
		newToken, err := generateSecureToken()
		if err != nil {
			return nil, fmt.Errorf("could not generate a secure bearer token: %w", err)
		}

		logger.Warnf("A new bearer token has been generated. Please set this in your extension and environment: %s", newToken)
		validTokens = append(validTokens, newToken)

	} else {
		tokens := strings.Split(tokensStr, ",")
		for _, token := range tokens {
			trimmedToken := strings.TrimSpace(token)
			if trimmedToken == "" {
				continue
			}

			if len(trimmedToken) < MinBearerTokenLength {
				return nil, fmt.Errorf("a configured bearer token is shorter than the required minimum of %d characters", MinBearerTokenLength)
			}
			validTokens = append(validTokens, trimmedToken)
		}
	}

	if len(validTokens) == 0 {
		return nil, fmt.Errorf("no valid bearer tokens were loaded or generated")
	}

	logger.Infof("Loaded %d bearer token(s)", len(validTokens))
	return validTokens, nil
}
