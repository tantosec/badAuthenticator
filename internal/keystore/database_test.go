package keystore

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/tantosec/badAuthenticator/internal/authcrypto"
	"github.com/tantosec/badAuthenticator/internal/config"
)

func TestUpdateCredentialByIDCoseAlgorithmMapsToSchemaColumn(t *testing.T) {
	db := openTempKeystoreDB(t)

	entry := CredentialEntry{
		CredentialID:       "credential-1",
		PrivateKeyFilePath: "keystore/keys/credential-1.key.pem",
		PublicKeyBytesHex:  "00",
		UserHandle:         "user-1",
		SignCount:          0,
		RPIDHash:           "hash",
		CreationDate:       time.Now().UTC().Format(time.RFC3339),
		RPID:               "example.com",
		CoseAlgorithm:      authcrypto.COSEAlgorithmES256,
	}
	if err := AddCredentialEntryMetadata(db, entry); err != nil {
		t.Fatalf("AddCredentialEntryMetadata failed: %v", err)
	}

	if err := UpdateCredentialByID(db, entry.CredentialID, "CoseAlgorithm", "-8"); err != nil {
		t.Fatalf("UpdateCredentialByID failed: %v", err)
	}

	got, err := GetCredentialByID(db, entry.CredentialID)
	if err != nil {
		t.Fatalf("GetCredentialByID failed: %v", err)
	}
	if got == nil {
		t.Fatal("credential not found after update")
	}
	if got.CoseAlgorithm != authcrypto.COSEAlgorithmEdDSA {
		t.Fatalf("CoseAlgorithm = %d, want %d", got.CoseAlgorithm, authcrypto.COSEAlgorithmEdDSA)
	}
}

func openTempKeystoreDB(t *testing.T) *sql.DB {
	t.Helper()

	oldKeystoreDir := config.KeystoreDir
	oldKeyFileDir := config.KeyFileDir
	keystoreDir := filepath.Join(t.TempDir(), "keystore")
	config.KeystoreDir = keystoreDir
	config.KeyFileDir = filepath.Join(keystoreDir, "keys")
	t.Cleanup(func() {
		config.KeystoreDir = oldKeystoreDir
		config.KeyFileDir = oldKeyFileDir
	})

	db, err := OpenAndVerifyDB()
	if err != nil {
		t.Fatalf("OpenAndVerifyDB failed: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("db.Close failed: %v", err)
		}
	})
	return db
}

func TestConcurrentCredentialWrites(t *testing.T) {
	db := openTempKeystoreDB(t)
	const writers = 8
	start := make(chan struct{})
	results := make(chan error, writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			<-start
			results <- AddCredentialEntryMetadata(db, CredentialEntry{
				CredentialID:  fmt.Sprintf("concurrent-%d", i),
				CreationDate:  time.Now().UTC().Format(time.RFC3339),
				RPID:          "example.com",
				CoseAlgorithm: authcrypto.COSEAlgorithmES256,
			})
		}(i)
	}
	close(start)
	for i := 0; i < writers; i++ {
		if err := <-results; err != nil {
			t.Errorf("concurrent insert failed: %v", err)
		}
	}
	for i := 0; i < writers; i++ {
		entry, err := GetCredentialByID(db, fmt.Sprintf("concurrent-%d", i))
		if err != nil || entry == nil {
			t.Errorf("credential %d missing: %v", i, err)
		}
	}
}
