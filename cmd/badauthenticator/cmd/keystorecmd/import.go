package keystorecmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/tantosec/badAuthenticator/internal/handlers"
	"github.com/tantosec/badAuthenticator/internal/types"
	"github.com/tantosec/badAuthenticator/pkg/cmdutil"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a credential from JSON.",
	Long: `Read credential metadata and a PEM private key from a file or stdin.
Save the key in the keystore and the metadata in SQLite.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := logging.GetLogger()
		logger.Debug("Executing 'import' command")

		db, err := cmdutil.GetDBFromCmd(cmd)
		if err != nil {
			return err
		}

		filePath, _ := cmd.Flags().GetString("from-file")
		var inputBytes []byte

		if filePath != "" {
			logger.Debug("Reading import data from file", "path", filePath)
			inputBytes, err = os.ReadFile(filePath)
			if err != nil {
				return fmt.Errorf("failed to read import file '%s': %w", filePath, err)
			}
		} else {
			logger.Debug("Reading import data from stdin")
			inputBytes, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read from stdin: %w", err)
			}
		}

		var credTransfer types.CredentialTransfer
		if err := json.Unmarshal(inputBytes, &credTransfer); err != nil {
			return fmt.Errorf("failed to unmarshal import JSON: %w", err)
		}

		logger.Debug("Parsed import JSON")
		return handlers.HandleImportKey(db, credTransfer)
	},
}

func init() {
	importCmd.Flags().String("from-file", "", "Path to the JSON file to import from (default: stdin)")
}
