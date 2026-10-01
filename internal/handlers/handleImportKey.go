package handlers

import (
	"database/sql"
	"fmt"

	"github.com/tantosec/badAuthenticator/internal/keystore"
	"github.com/tantosec/badAuthenticator/internal/types"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

func HandleImportKey(db *sql.DB, data types.CredentialTransfer) error {

	logger := logging.GetLogger()
	logger.Debug("Handling key import", "id", data.CredentialID)

	if data.CredentialID == "" || data.RPID == "" || data.PrivateKeyPEM == "" {
		return fmt.Errorf("import JSON is missing required fields: credentialId, rpid, and privateKeyPem must be set")
	}

	err := keystore.ImportCredential(db, data)
	if err != nil {
		return fmt.Errorf("failed to import credential from keystore: %w", err)
	}

	logger.Info("Imported credential", "id", data.CredentialID)
	return nil
}
