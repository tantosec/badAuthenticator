package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/tantosec/badAuthenticator/internal/config"
	"github.com/tantosec/badAuthenticator/internal/types"
)

func TestImportCredentialDoesNotWriteOutsideKeystore(t *testing.T) {
	db := openTempKeystoreDB(t)
	victim := filepath.Join(filepath.Dir(config.KeystoreDir), "victim.key.pem")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	t.Run("traversal", func(t *testing.T) {
		err := ImportCredential(db, types.CredentialTransfer{
			CredentialID: "../../victim", RPID: "example.com", PrivateKeyPEM: privateKeyPEM,
		})
		if err == nil {
			t.Fatal("import accepted a credential ID containing path traversal")
		}
	})

	t.Run("existing symlink", func(t *testing.T) {
		if err := os.MkdirAll(config.KeyFileDir, 0o755); err != nil {
			t.Fatal(err)
		}
		credentialID := base64.RawURLEncoding.EncodeToString([]byte("credential"))
		link := filepath.Join(config.KeyFileDir, credentialID+".key.pem")
		if err := os.Symlink(victim, link); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		err := ImportCredential(db, types.CredentialTransfer{
			CredentialID: credentialID, RPID: "example.com", PrivateKeyPEM: privateKeyPEM,
		})
		if err == nil {
			t.Fatal("import followed an existing symlink")
		}
	})

	content, err := os.ReadFile(victim)
	if err != nil || string(content) != "keep" {
		t.Fatalf("file outside keystore changed: %q, %v", content, err)
	}
}
