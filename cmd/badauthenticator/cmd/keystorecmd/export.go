package keystorecmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tantosec/badAuthenticator/internal/handlers"
	"github.com/tantosec/badAuthenticator/pkg/cmdutil"
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export a credential as JSON.",
	Long:  `Write the credential metadata and PEM private key to stdout.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		credID, _ := cmd.Flags().GetString("id")

		db, err := cmdutil.GetDBFromCmd(cmd)
		if err != nil {
			return err
		}

		credTransfer, err := handlers.HandleExportKey(db, credID)
		if err != nil {
			return err
		}

		jsonBytes, err := json.MarshalIndent(credTransfer, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal export data to JSON: %w", err)
		}

		fmt.Println(string(jsonBytes))
		return nil
	},
}

func init() {
	exportCmd.Flags().String("id", "", "Base64URL Credential ID to export")
	exportCmd.MarkFlagRequired("id")
}
