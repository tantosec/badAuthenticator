package handlers

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/tantosec/badAuthenticator/internal/keystore"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

// HandleClearKeystore prompts before deletion unless force is set.
func HandleClearKeystore(force bool) error {
	logger := logging.GetLogger()

	if !force {
		fmt.Println("This will permanently delete the entire keystore, including all private keys and the database.")
		fmt.Print("Are you sure you want to continue? (y/N): ")

		reader := bufio.NewReader(os.Stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read user confirmation: %w", err)
		}

		if strings.ToLower(strings.TrimSpace(response)) != "y" && strings.ToLower(strings.TrimSpace(response)) != "yes" {
			fmt.Println("Operation cancelled.")
			return nil
		}
	}

	logger.Warn("Clearing the entire keystore...")

	if err := keystore.ClearAll(); err != nil {
		return fmt.Errorf("failed to clear keystore: %w", err)
	}

	logger.Info("Keystore cleared")
	return nil
}
