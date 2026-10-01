package keystorecmd

import (
	"github.com/spf13/cobra"
	"github.com/tantosec/badAuthenticator/internal/handlers"
)

var clearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Delete all credentials and keys from the keystore.",
	Long: `Permanently deletes all stored credentials, private keys, and the database.
This also removes profiles.json from the keystore. Deletion cannot be undone.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		return handlers.HandleClearKeystore(force)
	},
}

func init() {
	clearCmd.Flags().Bool("force", false, "Delete without asking for confirmation")
}
