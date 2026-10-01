package keystorecmd

import (
	"encoding/base64"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tantosec/badAuthenticator/internal/keystore"
	"github.com/tantosec/badAuthenticator/pkg/cmdutil"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

var updateCmd = &cobra.Command{
	Use:   "update [credentialID] [fieldName] [newValue]",
	Short: "Update one field of a stored credential.",
	Long: `Updates a single field for a credential identified by its ID.
Valid fields are: PrivateKeyFilePath, PublicKeyBytesHex, UserHandle, SignCount, RPIDHash, CreationDate, RPID, CoseAlgorithm, Origin, AndroidPackageName, Profile.

Assertions reuse Profile, Origin and AndroidPackageName unless the request
overrides them. An empty Origin uses the profile default, or https://<RPID>
when the profile has no origin.`,
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := logging.GetLogger()
		credentialID := args[0]
		fieldName := args[1]
		valueToSet := args[2]

		logger.Debugf("Executing 'update' command for credential '%s'", credentialID)

		if strings.EqualFold(fieldName, "UserHandle") {
			valueToSet = base64.RawURLEncoding.EncodeToString([]byte(valueToSet))
		}

		db, err := cmdutil.GetDBFromCmd(cmd)
		if err != nil {
			return err
		}

		err = keystore.UpdateCredentialByID(db, credentialID, fieldName, valueToSet)
		if err != nil {
			return err
		}

		logger.Infof("Updated %s for credential %s", fieldName, credentialID)
		return nil
	},
}
