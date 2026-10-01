package keystore

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tantosec/badAuthenticator/internal/authcrypto"
	"github.com/tantosec/badAuthenticator/internal/config"
	"github.com/tantosec/badAuthenticator/internal/types"
)

type CredentialEntry struct {
	CredentialID       string
	PrivateKeyFilePath string
	PublicKeyBytesHex  string
	UserHandle         string
	SignCount          int
	RPIDHash           string
	CreationDate       string // UTC RFC 3339.
	RPID               string
	CoseAlgorithm      int64

	// Explicit registration values reused by assertions. Empty values fall back
	// to profile and ceremony defaults.
	Origin             string
	AndroidPackageName string

	// Profile is reused unless an assertion selects another one.
	Profile string
}

func StorePrivateKeyToPEM(credentialID string, privateKey crypto.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	return writePrivateKeyFile(credentialID, pemBytes)
}

func writePrivateKeyFile(credentialID string, pemBytes []byte) (string, error) {
	rawID, err := base64.RawURLEncoding.DecodeString(credentialID)
	if err != nil || len(rawID) == 0 || base64.RawURLEncoding.EncodeToString(rawID) != credentialID {
		return "", fmt.Errorf("credential ID must be unpadded base64url")
	}

	if err := os.MkdirAll(config.KeyFileDir, config.DefaultDirectoryPermissions); err != nil {
		return "", fmt.Errorf("failed to create key directory %s: %w", config.KeyFileDir, err)
	}
	root, err := os.OpenRoot(config.KeyFileDir)
	if err != nil {
		return "", fmt.Errorf("failed to open key directory: %w", err)
	}
	defer root.Close()

	name := credentialID + ".key.pem"
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, config.PrivateKeyFilePermissions)
	if err != nil {
		return "", fmt.Errorf("failed to create private key file: %w", err)
	}
	_, writeErr := file.Write(pemBytes)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		root.Remove(name)
		return "", fmt.Errorf("failed to write private key file: %w", errors.Join(writeErr, closeErr))
	}
	return filepath.Join(config.KeyFileDir, name), nil
}

func LoadPrivateKeyFromPEM(filename string) (crypto.PrivateKey, error) {

	pemBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file '%s': %w", filename, err)
	}

	return parsePrivateKeyPEM(pemBytes)
}

func parsePrivateKeyPEM(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	return privateKey, nil
}

func ImportCredential(db *sql.DB, data types.CredentialTransfer) error {

	existing, err := GetCredentialByID(db, data.CredentialID)
	if err != nil {
		return fmt.Errorf("failed to check for existing credential: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("credential with ID '%s' already exists", data.CredentialID)
	}

	privateKey, err := parsePrivateKeyPEM([]byte(data.PrivateKeyPEM))
	if err != nil {
		return fmt.Errorf("imported PEM data is invalid: %w", err)
	}

	provider, alg, err := authcrypto.GetProviderFromKey(privateKey)
	if err != nil {
		return err
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("imported key of type %T does not implement crypto.Signer", privateKey)
	}
	publicKey := signer.Public()
	publicKeyHex, err := provider.PublicKeyToHex(publicKey)
	if err != nil {
		return fmt.Errorf("failed to get hex for public key: %w", err)
	}
	privateKeyStoragePath, err := writePrivateKeyFile(data.CredentialID, []byte(data.PrivateKeyPEM))
	if err != nil {
		return err
	}

	rpIdHashBytes := sha256.Sum256([]byte(data.RPID))
	rpIdHashHex := hex.EncodeToString(rpIdHashBytes[:])
	creationDate := time.Now().UTC().Format(time.RFC3339)

	newEntry := CredentialEntry{
		CredentialID:       data.CredentialID,
		PrivateKeyFilePath: privateKeyStoragePath,
		PublicKeyBytesHex:  publicKeyHex,
		UserHandle:         data.UserHandle,
		SignCount:          data.SignCount,
		RPIDHash:           rpIdHashHex,
		CreationDate:       creationDate,
		RPID:               data.RPID,
		CoseAlgorithm:      alg,
		Origin:             data.Origin,
		AndroidPackageName: data.AndroidPackageName,
		Profile:            data.Profile,
	}

	if err := AddCredentialEntryMetadata(db, newEntry); err != nil {
		os.Remove(privateKeyStoragePath)
		return fmt.Errorf("failed to add credential entry to database: %w", err)
	}

	return nil
}

func ClearAll() error {
	if err := os.RemoveAll(config.KeystoreDir); err != nil {
		return fmt.Errorf("failed to remove keystore directory '%s': %w", config.KeystoreDir, err)
	}
	return nil
}
