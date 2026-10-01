package handlers

import (
	"database/sql"
	"fmt"

	"github.com/tantosec/badAuthenticator/internal/keystore"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

type ListEntryJSON struct {
	CredentialID string `json:"credentialId"`
	RPID         string `json:"rpid"`
	UserHandle   string `json:"userHandle"`
	SignCount    int    `json:"signCount"`
	CreationDate string `json:"creationDate"`

	Origin             string `json:"origin,omitempty"`
	AndroidPackageName string `json:"androidPackageName,omitempty"`
	Profile            string `json:"profile,omitempty"`
}

func HandleListKeys(db *sql.DB) ([]keystore.CredentialEntry, error) {
	logger := logging.GetLogger()
	logger.Debug("Handling list keys request")

	entries, err := keystore.ListAllCredentialEntries(db)
	if err != nil {
		return nil, fmt.Errorf("failed to list credential entries from keystore: %w", err)
	}

	logger.Debug("Retrieved credential entries", "count", len(entries))
	return entries, nil
}
