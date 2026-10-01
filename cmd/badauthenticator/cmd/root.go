package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tantosec/badAuthenticator/cmd/badauthenticator/cmd/keystorecmd"
	"github.com/tantosec/badAuthenticator/internal/config"
	"github.com/tantosec/badAuthenticator/internal/keystore"
	"github.com/tantosec/badAuthenticator/pkg/contextkeys"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

var rootCmd = &cobra.Command{
	Use:   "badauthenticator",
	Short: "A software WebAuthn authenticator for testing.",
	Long: `badAuthenticator creates credentials and signs assertions from WebAuthn options.
Use the CLI with JSON on stdin, or run the HTTP API with serve.`,
	SilenceUsage:  true,
	SilenceErrors: true,

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		verbose, _ := cmd.Flags().GetCount("verbose")
		logging.InitLogger(verbose)

		directory, _ := cmd.Flags().GetString("keystore-dir")
		if strings.TrimSpace(directory) == "" {
			return fmt.Errorf("--keystore-dir is required")
		}
		directory, err := filepath.Abs(directory)
		if err != nil {
			return fmt.Errorf("cannot resolve keystore directory: %w", err)
		}
		config.KeystoreDir = directory
		config.KeyFileDir = filepath.Join(directory, "keys")

		db, err := keystore.OpenAndVerifyDB()
		if err != nil {
			return fmt.Errorf("failed to initialize database: %w", err)
		}

		ctx := context.WithValue(cmd.Context(), contextkeys.DBKey{}, db)
		cmd.SetContext(ctx)

		return nil
	},

	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if db, ok := cmd.Context().Value(contextkeys.DBKey{}).(*sql.DB); ok && db != nil {
			_ = db.Close()
		}
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().String("keystore-dir", "", "Directory for credential metadata, keys and profiles (required)")
	rootCmd.PersistentFlags().CountP("verbose", "v", "Enable verbose (debug) logging")
	keystorecmd.Register(rootCmd)
}
