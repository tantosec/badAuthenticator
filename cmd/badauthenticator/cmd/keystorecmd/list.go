package keystorecmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tantosec/badAuthenticator/internal/handlers"
	"github.com/tantosec/badAuthenticator/pkg/cmdutil"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List stored credentials as JSONL.",
	Long:    `Write each stored credential as a JSON object on its own line.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := logging.GetLogger()
		logger.Debug("Executing 'list' command")

		db, err := cmdutil.GetDBFromCmd(cmd)
		if err != nil {
			return err
		}

		entries, err := handlers.HandleListKeys(db)
		if err != nil {
			return err
		}

		if len(entries) == 0 {
			logger.Info("No credentials found in the keystore.")
			return nil
		}

		for _, entry := range entries {

			decodedUserHandle, err := base64.RawURLEncoding.DecodeString(entry.UserHandle)
			if err != nil {
				logger.Warnf("Could not decode userHandle for credential %s: %v", entry.CredentialID, err)
				continue
			}

			jsonOutput := handlers.ListEntryJSON{
				CredentialID: entry.CredentialID,
				RPID:         entry.RPID,
				UserHandle:   string(decodedUserHandle),
				SignCount:    entry.SignCount,
				CreationDate: entry.CreationDate,

				Origin:             entry.Origin,
				AndroidPackageName: entry.AndroidPackageName,
				Profile:            entry.Profile,
			}

			jsonBytes, err := json.Marshal(jsonOutput)
			if err != nil {
				return fmt.Errorf("failed to process entry %s: %w", entry.CredentialID, err)
			}

			fmt.Println(string(jsonBytes))
		}

		return nil
	},
}
