package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/tantosec/badAuthenticator/internal/authcrypto"
	"github.com/tantosec/badAuthenticator/internal/handlers"
	"github.com/tantosec/badAuthenticator/internal/keystore"
	"github.com/tantosec/badAuthenticator/internal/webauthn"
	"github.com/tantosec/badAuthenticator/pkg/cmdutil"
)

var assertCmd = &cobra.Command{
	Use:   "assert",
	Short: "Sign a WebAuthn assertion with a stored credential.",
	Long:  `Read authentication options from stdin and write the assertion response as JSON.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := cmdutil.GetDBFromCmd(cmd)
		if err != nil {
			return err
		}

		stdinBytes, err := cmdutil.ReadStdin()
		if err != nil {
			return err
		}

		var overrides webauthn.AssertionOverrides

		overrides.CeremonyOverrides, err = parseCeremonyOverrideFlags(cmd)
		if err != nil {
			return err
		}

		if cmd.Flags().Changed("cred-id") {
			credID, _ := cmd.Flags().GetString("cred-id")
			cred, err := keystore.GetCredentialByID(db, credID)
			if err != nil {
				return fmt.Errorf("failed to lookup credential override ID '%s': %w", credID, err)
			}
			if cred == nil {
				return fmt.Errorf("credential override ID '%s' not found", credID)
			}
			overrides.CredentialOverride = cred
		}
		if cmd.Flags().Changed("alg") {
			algName, _ := cmd.Flags().GetString("alg")
			algID, ok := authcrypto.GetAlgorithmByName(algName)
			if !ok {
				return fmt.Errorf("unknown algorithm: %s (valid: ES256, ES384, RS256, PS256, PS384, PS512, EdDSA)", algName)
			}
			overrides.AlgOverride = &algID
		}

		assertionResponse, err := handlers.HandleAssertion(db, stdinBytes, &overrides)
		if err != nil {
			return err
		}

		return writeCommandOutput(cmd, assertionResponse, humanReadableAssertion(assertionResponse))
	},
}

func init() {
	rootCmd.AddCommand(assertCmd)

	addCeremonyOverrideFlags(assertCmd, false, false)
	assertCmd.Flags().String("cred-id", "", "Override credential ID to use (base64url encoded string)")
	addOutputFlags(assertCmd)
	assertCmd.Flags().String("alg", "", "Force signing algorithm (ES256, ES384, RS256, PS256, PS384, PS512, EdDSA)")
}

func humanReadableAssertion(assertionResponse *webauthn.PublicKeyCredential[webauthn.AuthenticatorAssertionResponse]) webauthn.HumanReadablePublicKeyCredential[webauthn.HumanReadableAssertionResponse] {
	readableResponse := webauthn.HumanReadableAssertionResponse{
		Signature:  assertionResponse.Response.Signature,
		UserHandle: assertionResponse.Response.UserHandle,
	}

	if parsedClientData, err := webauthn.ParseClientData(assertionResponse.Response.ClientDataJSON); err == nil {
		readableResponse.ClientDataJSON = parsedClientData
	} else {
		readableResponse.ClientDataJSON = fmt.Sprintf("Error parsing: %v", err)
	}

	authDataBytes, err := base64.RawURLEncoding.DecodeString(assertionResponse.Response.AuthenticatorData)
	if err != nil {
		readableResponse.AuthenticatorData = fmt.Sprintf("Error decoding base64: %v", err)
	} else {
		if parsedAuthData, err := webauthn.ParseAuthenticatorData(authDataBytes); err == nil {
			readableResponse.AuthenticatorData = parsedAuthData
		} else {
			readableResponse.AuthenticatorData = fmt.Sprintf("Error parsing auth data: %v", err)
		}
	}

	return webauthn.HumanReadablePublicKeyCredential[webauthn.HumanReadableAssertionResponse]{
		ID:                     assertionResponse.ID,
		RawID:                  assertionResponse.RawID,
		Type:                   assertionResponse.Type,
		ClientExtensionResults: assertionResponse.ClientExtensionResults,
		Response:               readableResponse,
	}
}
