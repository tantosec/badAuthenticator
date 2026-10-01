package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/spf13/cobra"
	"github.com/tantosec/badAuthenticator/internal/authcrypto"
	"github.com/tantosec/badAuthenticator/internal/handlers"
	"github.com/tantosec/badAuthenticator/internal/webauthn"
	"github.com/tantosec/badAuthenticator/pkg/cmdutil"
)

var attestCmd = &cobra.Command{
	Use:   "attest",
	Short: "Create and store a WebAuthn credential.",
	Long:  `Read registration options from stdin and write the credential response as JSON.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := cmdutil.GetDBFromCmd(cmd)
		if err != nil {
			return err
		}

		stdinBytes, err := cmdutil.ReadStdin()
		if err != nil {
			return err
		}

		var overrides webauthn.AttestationOverrides

		overrides.CeremonyOverrides, err = parseCeremonyOverrideFlags(cmd)
		if err != nil {
			return err
		}

		if cmd.Flags().Changed("cred-id-len") {
			l, _ := cmd.Flags().GetUint16("cred-id-len")
			overrides.CredentialIDLength = &l
		}
		if cmd.Flags().Changed("alg") {
			algName, _ := cmd.Flags().GetString("alg")
			algID, ok := authcrypto.GetAlgorithmByName(algName)
			if !ok {
				return fmt.Errorf("unknown algorithm: %s (valid: ES256, ES384, RS256, PS256, PS384, PS512, EdDSA)", algName)
			}
			overrides.AlgOverride = &algID
		}
		if cmd.Flags().Changed("attestation-type") {
			value, _ := cmd.Flags().GetString("attestation-type")
			attestationType := webauthn.AttestationType(value)
			switch attestationType {
			case webauthn.AttestationTypeSelf, webauthn.AttestationTypeFull:
			default:
				return fmt.Errorf("unknown attestation type: %s (valid: self, full)", value)
			}
			overrides.AttestationType = &attestationType
		}

		attestationResponse, err := handlers.HandleAttestation(db, stdinBytes, &overrides)
		if err != nil {
			return err
		}

		return writeCommandOutput(cmd, attestationResponse, humanReadableAttestation(attestationResponse))
	},
}

func init() {
	rootCmd.AddCommand(attestCmd)

	addCeremonyOverrideFlags(attestCmd, true, true)
	attestCmd.Flags().Uint16("cred-id-len", 0, "Override Credential ID length")
	addOutputFlags(attestCmd)
	attestCmd.Flags().String("alg", "", "Force algorithm (ES256, ES384, RS256, PS256, PS384, PS512, EdDSA)")
	attestCmd.Flags().String("attestation-type", "", "Packed attestation type: self or full (requires a packed profile)")
}

func humanReadableAttestation(attestationResponse *webauthn.PublicKeyCredential[webauthn.AuthenticatorAttestationResponse]) webauthn.HumanReadablePublicKeyCredential[webauthn.HumanReadableAttestationResponse] {
	readableResponse := webauthn.HumanReadableAttestationResponse{
		Transports: attestationResponse.Response.Transports,
	}

	if parsedClientData, err := webauthn.ParseClientData(attestationResponse.Response.ClientDataJSON); err == nil {
		readableResponse.ClientDataJSON = parsedClientData
	} else {
		readableResponse.ClientDataJSON = fmt.Sprintf("Error parsing: %v", err)
	}

	attObjBytes, err := base64.RawURLEncoding.DecodeString(attestationResponse.Response.AttestationObject)
	if err != nil {
		readableResponse.AttestationObject = fmt.Sprintf("Error decoding base64: %v", err)
	} else {
		var attObj webauthn.AttestationObject
		if err := cbor.Unmarshal(attObjBytes, &attObj); err != nil {
			readableResponse.AttestationObject = fmt.Sprintf("Error unmarshalling CBOR: %v", err)
		} else {
			parsedAttObj := webauthn.ParsedAttestationObject{
				Format:  attObj.Format,
				AttStmt: attObj.AttStmt,
			}
			if parsedAuthData, err := webauthn.ParseAuthenticatorData(attObj.AuthData); err == nil {
				parsedAttObj.AuthData = parsedAuthData
			} else {
				parsedAttObj.AuthData = fmt.Sprintf("Error parsing authData: %v", err)
			}
			readableResponse.AttestationObject = parsedAttObj
		}
	}

	return webauthn.HumanReadablePublicKeyCredential[webauthn.HumanReadableAttestationResponse]{
		ID:                     attestationResponse.ID,
		RawID:                  attestationResponse.RawID,
		Type:                   attestationResponse.Type,
		ClientExtensionResults: attestationResponse.ClientExtensionResults,
		Response:               readableResponse,
	}
}
