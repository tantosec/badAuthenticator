package webauthn

import (
	"crypto/sha256"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/tantosec/badAuthenticator/internal/authcrypto"
	"github.com/tantosec/badAuthenticator/internal/config"
	"github.com/tantosec/badAuthenticator/internal/keystore"
)

func TestCreateNewAttestationDefaultsToNone(t *testing.T) {
	db := openTestDB(t)

	attObj := createTestAttestationObject(t, AttestationConfig{
		DB:             db,
		RelyingPartyID: "example.com",
		UserHandle:     []byte("user-1"),
		Alg:            authcrypto.COSEAlgorithmES256,
	})

	if attObj.Format != string(AttestationFormatNone) {
		t.Fatalf("format = %q, want %q", attObj.Format, AttestationFormatNone)
	}
	if len(attObj.AttStmt) != 0 {
		t.Fatalf("attStmt length = %d, want 0", len(attObj.AttStmt))
	}
}

func TestCreateNewAttestationPackedSelfAttestation(t *testing.T) {
	db := openTestDB(t)
	clientDataHash := sha256.Sum256([]byte(`{"type":"webauthn.create","challenge":"test"}`))
	aaguid := mustAAGUID(t, "6028b017-b1d4-4c02-b4b3-afcdafc96bb2")

	attObj := createTestAttestationObject(t, AttestationConfig{
		DB:                 db,
		RelyingPartyID:     "example.com",
		UserHandle:         []byte("user-1"),
		Alg:                authcrypto.COSEAlgorithmES256,
		ProfileAAGUID:      aaguid,
		AttestationFormat:  AttestationFormatPacked,
		ClientDataJSONHash: clientDataHash[:],
	})

	if attObj.Format != string(AttestationFormatPacked) {
		t.Fatalf("format = %q, want %q", attObj.Format, AttestationFormatPacked)
	}
	if got := attStmtAlg(t, attObj.AttStmt); got != authcrypto.COSEAlgorithmES256 {
		t.Fatalf("attStmt alg = %d, want %d", got, authcrypto.COSEAlgorithmES256)
	}
	if sig, ok := attObj.AttStmt["sig"].([]byte); !ok || len(sig) == 0 {
		t.Fatalf("attStmt sig = %T length %d, want non-empty []byte", attObj.AttStmt["sig"], len(sig))
	}
	if _, ok := attObj.AttStmt["x5c"]; ok {
		t.Fatal("attStmt unexpectedly includes x5c")
	}

	parsedAuthData, err := ParseAuthenticatorData(attObj.AuthData)
	if err != nil {
		t.Fatalf("ParseAuthenticatorData failed: %v", err)
	}
	if parsedAuthData.AttestedCredentialData == nil {
		t.Fatal("attested credential data is nil")
	}
	if parsedAuthData.AttestedCredentialData.AAGUID != "6028b017b1d44c02b4b3afcdafc96bb2" {
		t.Fatalf("AAGUID = %q, want Windows Hello Software AAGUID", parsedAuthData.AttestedCredentialData.AAGUID)
	}
}

func TestCreateNewAttestationPackedRequiresClientDataHash(t *testing.T) {
	db := openTestDB(t)

	_, _, err := CreateNewAttestation(AttestationConfig{
		DB:                db,
		RelyingPartyID:    "example.com",
		UserHandle:        []byte("user-1"),
		Alg:               authcrypto.COSEAlgorithmES256,
		AttestationFormat: AttestationFormatPacked,
	})
	if err == nil {
		t.Fatal("CreateNewAttestation succeeded without clientDataJSON hash")
	}
}

func TestCreateNewAttestationRemovesPrivateKeyIfMetadataInsertFails(t *testing.T) {
	db := openTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close failed: %v", err)
	}

	_, _, err := CreateNewAttestation(AttestationConfig{
		DB:             db,
		RelyingPartyID: "example.com",
		UserHandle:     []byte("user-1"),
		Alg:            authcrypto.COSEAlgorithmES256,
	})
	if err == nil {
		t.Fatal("CreateNewAttestation succeeded with closed database")
	}

	keyFiles, readDirErr := os.ReadDir(config.KeyFileDir)
	if readDirErr != nil && !os.IsNotExist(readDirErr) {
		t.Fatalf("ReadDir(%q) failed: %v", config.KeyFileDir, readDirErr)
	}
	if len(keyFiles) != 0 {
		t.Fatalf("key directory contains %d file(s), want 0 after rollback", len(keyFiles))
	}
}

func openTestDB(t *testing.T) *sql.DB {
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

	db, err := keystore.OpenAndVerifyDB()
	if err != nil {
		t.Fatalf("OpenAndVerifyDB failed: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil && err != sql.ErrConnDone {
			t.Fatalf("db.Close failed: %v", err)
		}
	})
	return db
}

func createTestAttestationObject(t *testing.T, cfg AttestationConfig) AttestationObject {
	t.Helper()

	attestationObjectCbor, _, err := CreateNewAttestation(cfg)
	if err != nil {
		t.Fatalf("CreateNewAttestation failed: %v", err)
	}
	var attObj AttestationObject
	if err := cbor.Unmarshal(attestationObjectCbor, &attObj); err != nil {
		t.Fatalf("failed to unmarshal attestation object CBOR: %v", err)
	}
	return attObj
}

func mustAAGUID(t *testing.T, s string) []byte {
	t.Helper()

	aaguid, err := ParseAAGUID(s)
	if err != nil {
		t.Fatalf("failed to decode AAGUID: %v", err)
	}
	if len(aaguid) != 16 {
		t.Fatalf("AAGUID length = %d, want 16", len(aaguid))
	}
	return aaguid
}

func attStmtAlg(t *testing.T, attStmt map[string]any) int64 {
	t.Helper()

	switch alg := attStmt["alg"].(type) {
	case int64:
		return alg
	case int:
		return int64(alg)
	default:
		t.Fatalf("attStmt alg has type %T, want integer", attStmt["alg"])
		return 0
	}
}
