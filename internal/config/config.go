package config

import "path/filepath"

var (
	KeystoreDir = "badauthenticator-keystore"

	KeyFileDir = filepath.Join(KeystoreDir, "keys")
)
