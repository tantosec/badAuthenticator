package cmdutil

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/tantosec/badAuthenticator/pkg/contextkeys"
)

// ReadStdin rejects empty input and returns the original bytes.
func ReadStdin() ([]byte, error) {
	stdinBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read from stdin: %w", err)
	}

	if len(bytes.TrimSpace(stdinBytes)) == 0 {
		return nil, fmt.Errorf("no data received from stdin")
	}

	return stdinBytes, nil
}

func GetDBFromCmd(cmd *cobra.Command) (*sql.DB, error) {
	db, ok := cmd.Context().Value(contextkeys.DBKey{}).(*sql.DB)
	if !ok || db == nil {
		return nil, fmt.Errorf("database connection not found in command context")
	}
	return db, nil
}
