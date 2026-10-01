package webauthn

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/tantosec/badAuthenticator/internal/authcrypto"
)

func TestCreateNewAttestationPackedFullAttestation(t *testing.T) {
	db := openTestDB(t)
	clientDataHash := sha256.Sum256([]byte(`{"type":"webauthn.create","challenge":"full"}`))
	aaguid := mustAAGUID(t, "ee882879-721c-4913-9775-3dfcce97072a")

	attestationObjectCbor, _, err := CreateNewAttestation(AttestationConfig{
		DB:                 db,
		RelyingPartyID:     "example.com",
		UserHandle:         []byte("user-1"),
		Alg:                authcrypto.COSEAlgorithmES256,
		ProfileAAGUID:      aaguid,
		AttestationFormat:  AttestationFormatPacked,
		AttestationType:    AttestationTypeFull,
		ClientDataJSONHash: clientDataHash[:],
	})
	if err != nil {
		t.Fatalf("CreateNewAttestation failed: %v", err)
	}

	var attObj AttestationObject
	if err := cbor.Unmarshal(attestationObjectCbor, &attObj); err != nil {
		t.Fatalf("failed to unmarshal attestation object CBOR: %v", err)
	}
	if attObj.Format != string(AttestationFormatPacked) {
		t.Fatalf("format = %q, want %q", attObj.Format, AttestationFormatPacked)
	}
	if got := attStmtAlg(t, attObj.AttStmt); got != authcrypto.COSEAlgorithmES256 {
		t.Fatalf("attStmt alg = %d, want %d", got, authcrypto.COSEAlgorithmES256)
	}

	rawChain, ok := attObj.AttStmt["x5c"].([]any)
	if !ok {
		t.Fatalf("attStmt x5c = %T, want []any", attObj.AttStmt["x5c"])
	}
	if len(rawChain) != 2 {
		t.Fatalf("x5c length = %d, want 2 (leaf, root)", len(rawChain))
	}
	leafDER := certBytes(t, rawChain[0])
	rootDER := certBytes(t, rawChain[1])

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("failed to parse root certificate: %v", err)
	}

	if err := root.CheckSignatureFrom(root); err != nil {
		t.Fatalf("root is not self-signed: %v", err)
	}
	if err := leaf.CheckSignatureFrom(root); err != nil {
		t.Fatalf("leaf is not signed by root: %v", err)
	}

	sig, ok := attObj.AttStmt["sig"].([]byte)
	if !ok || len(sig) == 0 {
		t.Fatalf("attStmt sig = %T length %d, want non-empty []byte", attObj.AttStmt["sig"], len(sig))
	}
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("leaf public key = %T, want *ecdsa.PublicKey", leaf.PublicKey)
	}
	signed := append(append([]byte{}, attObj.AuthData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	if !ecdsa.VerifyASN1(leafPub, digest[:], sig) {
		t.Fatal("attestation signature does not verify under the leaf certificate")
	}

	assertSubjectUTF8(t, leaf)

	certAAGUID := leafAAGUIDExtension(t, leaf)
	parsedAuthData, err := ParseAuthenticatorData(attObj.AuthData)
	if err != nil {
		t.Fatalf("ParseAuthenticatorData failed: %v", err)
	}
	if parsedAuthData.AttestedCredentialData == nil {
		t.Fatal("attested credential data is nil")
	}
	if certAAGUID != parsedAuthData.AttestedCredentialData.AAGUID {
		t.Fatalf("certificate AAGUID = %q, authData AAGUID = %q, want equal", certAAGUID, parsedAuthData.AttestedCredentialData.AAGUID)
	}
}

func TestCreateNewAttestationFullRequiresPackedFormat(t *testing.T) {
	db := openTestDB(t)
	clientDataHash := sha256.Sum256([]byte(`{}`))

	_, _, err := CreateNewAttestation(AttestationConfig{
		DB:                 db,
		RelyingPartyID:     "example.com",
		UserHandle:         []byte("user-1"),
		Alg:                authcrypto.COSEAlgorithmES256,
		AttestationFormat:  AttestationFormatNone,
		AttestationType:    AttestationTypeFull,
		ClientDataJSONHash: clientDataHash[:],
	})
	if err == nil {
		t.Fatal("CreateNewAttestation accepted full attestation with the none format")
	}
}

func assertSubjectUTF8(t *testing.T, leaf *x509.Certificate) {
	t.Helper()

	type attributeTypeAndValue struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	var relativeDNs []asn1.RawValue
	if _, err := asn1.Unmarshal(leaf.RawSubject, &relativeDNs); err != nil {
		t.Fatalf("failed to parse leaf subject: %v", err)
	}

	mustBeUTF8 := map[string]asn1.ObjectIdentifier{
		"O":  oidOrganization,
		"OU": oidOrganizationalUnit,
		"CN": oidCommonName,
	}
	seen := map[string]bool{}
	for _, rdn := range relativeDNs {
		rest := rdn.Bytes
		for len(rest) > 0 {
			var attr attributeTypeAndValue
			var err error
			rest, err = asn1.Unmarshal(rest, &attr)
			if err != nil {
				t.Fatalf("failed to parse subject attribute: %v", err)
			}
			for label, oid := range mustBeUTF8 {
				if attr.Type.Equal(oid) {
					seen[label] = true
					if attr.Value.Tag != asn1.TagUTF8String {
						t.Errorf("subject %s tag = %d, want UTF8String (%d)", label, attr.Value.Tag, asn1.TagUTF8String)
					}
				}
			}
		}
	}
	for label := range mustBeUTF8 {
		if !seen[label] {
			t.Errorf("subject is missing the %s attribute", label)
		}
	}
}

func certBytes(t *testing.T, entry any) []byte {
	t.Helper()
	der, ok := entry.([]byte)
	if !ok {
		t.Fatalf("x5c entry = %T, want []byte", entry)
	}
	return der
}

func leafAAGUIDExtension(t *testing.T, leaf *x509.Certificate) string {
	t.Helper()
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(oidFidoGenCeAAGUID) {
			continue
		}
		var inner []byte
		if _, err := asn1.Unmarshal(ext.Value, &inner); err != nil {
			t.Fatalf("failed to decode AAGUID extension: %v", err)
		}
		return hex.EncodeToString(inner)
	}
	t.Fatal("leaf certificate is missing the id-fido-gen-ce-aaguid extension")
	return ""
}
