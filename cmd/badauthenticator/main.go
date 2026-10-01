package main

import (
	"os"

	"github.com/tantosec/badAuthenticator/cmd/badauthenticator/cmd"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

func main() {
	if err := cmd.Execute(); err != nil {
		logger := logging.GetLogger()
		logger.Error("Command failed", "error", err)

		os.Exit(1)
	}
}
