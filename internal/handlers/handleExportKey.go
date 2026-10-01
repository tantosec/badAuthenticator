package handlers

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/tantosec/badAuthenticator/internal/keystore"
	"github.com/tantosec/badAuthenticator/internal/types"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

func HandleExportKey(db *sql.DB, credID string) (*types.CredentialTransfer, error) {
	logger := logging.GetLogger()

	entry, err := keystore.GetCredentialByID(db, credID)
	if err != nil {
		return nil, fmt.Errorf("could not get credential metadata: %w", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("no credential found with ID: %s", credID)
	}
	logger.Debug("Found metadata for credential", "id", credID)

	pemData, err := os.ReadFile(entry.PrivateKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not read private key file '%s': %w", entry.PrivateKeyFilePath, err)
	}
	logger.Debug("Read private key", "path", entry.PrivateKeyFilePath)

	transferData := &types.CredentialTransfer{
		CredentialID:  entry.CredentialID,
		PrivateKeyPEM: string(pemData),
		RPID:          entry.RPID,
		UserHandle:    entry.UserHandle,
		SignCount:     entry.SignCount,
		CoseAlgorithm: entry.CoseAlgorithm,

		Origin:             entry.Origin,
		AndroidPackageName: entry.AndroidPackageName,
		Profile:            entry.Profile,
	}

	return transferData, nil
}
