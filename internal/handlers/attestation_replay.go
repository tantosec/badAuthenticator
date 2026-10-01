package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"

	"github.com/tantosec/badAuthenticator/internal/keystore"
	"github.com/tantosec/badAuthenticator/internal/webauthn"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

func replayAttestation(db *sql.DB, jsonBytes []byte) (any, error) {
	request, err := webauthn.ParseCeremonyRequest(jsonBytes)
	if err != nil {
		return nil, err
	}
	var options webauthn.PublicKeyCredentialCreationOptions
	if err := json.Unmarshal(request.Options, &options); err != nil {
		return nil, err
	}
	if options.RP.ID == "" || options.User.ID == "" || options.Challenge == "" {
		return nil, newAPIError(http.StatusBadRequest, "missing_replay_key", "GET attestation requires rp.id, user.id and challenge", nil)
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, replayStorageError(err)
	}
	var keyPath string
	committed := false
	defer func() {
		tx.Rollback()
		if !committed && keyPath != "" {
			if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
				logging.GetLogger().Warn("Failed to remove uncommitted private key", "error", err)
			}
		}
	}()

	// Reserve the tuple before reading, so concurrent requests wait for its result.
	_, err = tx.Exec(`INSERT INTO attestation_replays (rp, user_id, challenge)
        VALUES (?, ?, ?) ON CONFLICT DO NOTHING`, options.RP.ID, options.User.ID, options.Challenge)
	if err != nil {
		return nil, replayStorageError(err)
	}
	var response []byte
	err = tx.QueryRow(`SELECT response FROM attestation_replays
        WHERE rp = ? AND user_id = ? AND challenge = ?`, options.RP.ID, options.User.ID, options.Challenge).Scan(&response)
	if err != nil {
		return nil, replayStorageError(err)
	}
	if response != nil {
		return json.RawMessage(response), nil
	}

	credential, err := webauthn.AttestationWithStore(func(entry keystore.CredentialEntry) error {
		if err := keystore.AddCredentialEntryMetadata(tx, entry); err != nil {
			return replayStorageError(err)
		}
		keyPath = entry.PrivateKeyFilePath
		return nil
	}, jsonBytes, nil)
	if err != nil {
		return nil, err
	}
	response, err = json.Marshal(credential)
	if err != nil {
		return nil, replayStorageError(err)
	}
	_, err = tx.Exec(`UPDATE attestation_replays SET response = ?
        WHERE rp = ? AND user_id = ? AND challenge = ?`, response, options.RP.ID, options.User.ID, options.Challenge)
	if err != nil {
		return nil, replayStorageError(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, replayStorageError(err)
	}
	committed = true
	return json.RawMessage(response), nil
}

func replayStorageError(err error) *APIError {
	return newAPIError(http.StatusInternalServerError, "attestation_storage_failed", "Failed to store attestation result", err)
}
