package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

var oidFidoGenCeAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

var (
	oidCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
)

func subjectAttr(oid asn1.ObjectIdentifier, tag int, value string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{
		Type:  oid,
		Value: asn1.RawValue{Tag: tag, Bytes: []byte(value)},
	}
}

type attestationChain struct {
	LeafSigner crypto.Signer
	X5C        [][]byte
}

// synthesizePackedChain returns a leaf and an untrusted self-signed root.
func synthesizePackedChain(aaguid []byte) (*attestationChain, error) {
	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour)

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation root key: %w", err)
	}
	rootSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName:   "badAuthenticator Attestation Root CA",
			Organization: []string{"badAuthenticator"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation root certificate: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation root certificate: %w", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation leaf key: %w", err)
	}
	leafSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	var extraExtensions []pkix.Extension
	if len(aaguid) == 16 {
		// x509 wraps this inner OCTET STRING in the extension's outer OCTET STRING.
		aaguidValue, err := asn1.Marshal(aaguid)
		if err != nil {
			return nil, fmt.Errorf("failed to encode AAGUID certificate extension: %w", err)
		}
		extraExtensions = append(extraExtensions, pkix.Extension{
			Id:       oidFidoGenCeAAGUID,
			Critical: false,
			Value:    aaguidValue,
		})
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		// Packed attestation requires UTF8String for O, OU and CN.
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				subjectAttr(oidCountry, asn1.TagPrintableString, "US"),
				subjectAttr(oidOrganization, asn1.TagUTF8String, "badAuthenticator"),
				subjectAttr(oidOrganizationalUnit, asn1.TagUTF8String, "Authenticator Attestation"),
				subjectAttr(oidCommonName, asn1.TagUTF8String, "badAuthenticator Attestation Leaf"),
			},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtraExtensions:       extraExtensions,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation leaf certificate: %w", err)
	}

	return &attestationChain{
		LeafSigner: leafKey,
		X5C:        [][]byte{leafDER, rootDER},
	}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate serial number: %w", err)
	}
	return serial, nil
}
