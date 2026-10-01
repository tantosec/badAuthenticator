package keystorecmd

import (
	"github.com/spf13/cobra"
)

var KeystoreCmd = &cobra.Command{
	Use:     "keystore",
	Aliases: []string{"ks"},
	Short:   "Manage the credential keystore.",
	Long:    "Manage the credential keystore.",
}

func Register(root *cobra.Command) {
	KeystoreCmd.AddCommand(listCmd)
	KeystoreCmd.AddCommand(importCmd)
	KeystoreCmd.AddCommand(exportCmd)
	KeystoreCmd.AddCommand(clearCmd)
	KeystoreCmd.AddCommand(updateCmd)

	root.AddCommand(KeystoreCmd)
}
