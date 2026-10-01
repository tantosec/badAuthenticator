package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tantosec/badAuthenticator/internal/webauthn"
)

// Only explicitly set flags affect the ceremony.
func addCeremonyOverrideFlags(cmd *cobra.Command, defaultUV, defaultAT bool) {
	flags := cmd.Flags()

	flags.String("profile", "", fmt.Sprintf("Authenticator profile (default %q)", webauthn.DefaultProfile))
	flags.String("profiles-file", "", "Path to a JSON file of user-defined profiles")
	flags.Bool("strict", false, "Check response structure and ceremony fields before returning output")

	flags.Uint8("flags", 0, "Override the whole authenticator data flags byte (integer)")
	flags.Bool("up", true, "Override User Present (UP) flag (use --up=false to disable)")
	flags.Bool("uv", defaultUV, fmt.Sprintf("Override User Verified (UV) flag (use --uv=%t to invert)", !defaultUV))
	flags.Bool("be", false, "Override Backup Eligible (BE) flag")
	flags.Bool("bs", false, "Override Backup State (BS) flag")
	flags.Bool("at", defaultAT, fmt.Sprintf("Override Attested Credential Data (AT) flag (use --at=%t to invert)", !defaultAT))
	flags.Bool("ed", false, "Override Extension Data (ED) flag without writing extension data")
	flags.Uint32("sign-count", 0, "Override the signature counter, including backwards")
	flags.String("rp-id-hash", "", "Override the RP ID hash in authenticator data (base64url, any length)")
	flags.String("aaguid", "", "Override the attestation AAGUID (UUID or hex, any length)")

	flags.String("client-data-type", "", `Override clientDataJSON "type"`)
	flags.String("origin", "", `Override clientDataJSON "origin" (e.g. android:apk-key-hash:...)`)
	flags.String("android-package", "", `Override clientDataJSON "androidPackageName"`)
	flags.Bool("cross-origin", false, `Override clientDataJSON "crossOrigin"`)
	flags.String("top-origin", "", `Emit clientDataJSON "topOrigin"`)
	flags.StringSlice("field-order", nil, "Set clientDataJSON key order, including repeated keys")
	flags.StringSlice("null-field", nil, "Omit an output field (repeatable)")

	flags.String("client-data-raw", "", "Supply base64url clientDataJSON bytes to sign and emit")
	flags.String("authenticator-data-raw", "", "Supply base64url authenticatorData bytes to sign and emit")
}

// --null-field accepts whole fields because individual bits cannot be omitted.
var nullableFields = map[string]func(*webauthn.ClientDataOverrides, *webauthn.AuthenticatorDataOverrides){
	webauthn.FieldType:      func(c *webauthn.ClientDataOverrides, _ *webauthn.AuthenticatorDataOverrides) { c.Type.SetNull() },
	webauthn.FieldChallenge: func(c *webauthn.ClientDataOverrides, _ *webauthn.AuthenticatorDataOverrides) { c.Challenge.SetNull() },
	webauthn.FieldOrigin:    func(c *webauthn.ClientDataOverrides, _ *webauthn.AuthenticatorDataOverrides) { c.Origin.SetNull() },
	webauthn.FieldAndroidPackageName: func(c *webauthn.ClientDataOverrides, _ *webauthn.AuthenticatorDataOverrides) {
		c.AndroidPackageName.SetNull()
	},
	webauthn.FieldCrossOrigin: func(c *webauthn.ClientDataOverrides, _ *webauthn.AuthenticatorDataOverrides) { c.CrossOrigin.SetNull() },
	webauthn.FieldTopOrigin:   func(c *webauthn.ClientDataOverrides, _ *webauthn.AuthenticatorDataOverrides) { c.TopOrigin.SetNull() },
	"flags":                   func(_ *webauthn.ClientDataOverrides, a *webauthn.AuthenticatorDataOverrides) { a.Flags.SetNull() },
	"signCount":               func(_ *webauthn.ClientDataOverrides, a *webauthn.AuthenticatorDataOverrides) { a.SignCount.SetNull() },
	"rpIdHash":                func(_ *webauthn.ClientDataOverrides, a *webauthn.AuthenticatorDataOverrides) { a.RPIDHash.SetNull() },
	"aaguid":                  func(_ *webauthn.ClientDataOverrides, a *webauthn.AuthenticatorDataOverrides) { a.AAGUID.SetNull() },
}

// parseCeremonyOverrideFlags reads explicitly set flags into envelope overrides.
// It checks encodings and types, leaving output validation to --strict.
func parseCeremonyOverrideFlags(cmd *cobra.Command) (webauthn.CeremonyOverrides, error) {
	flags := cmd.Flags()
	var overrides webauthn.CeremonyOverrides

	if flags.Changed("profiles-file") {
		path, _ := flags.GetString("profiles-file")
		if err := webauthn.LoadProfiles(path); err != nil {
			return overrides, err
		}
	}
	if flags.Changed("profile") {
		overrides.Profile, _ = flags.GetString("profile")
	}
	if flags.Changed("strict") {
		overrides.Validate, _ = flags.GetBool("strict")
	}

	var clientData *webauthn.ClientDataOverrides
	ensureClientData := func() *webauthn.ClientDataOverrides {
		if clientData == nil {
			clientData = &webauthn.ClientDataOverrides{}
		}
		return clientData
	}

	if flags.Changed("client-data-type") {
		value, _ := flags.GetString("client-data-type")
		ensureClientData().Type.SetValue(value)
	}
	if flags.Changed("origin") {
		value, _ := flags.GetString("origin")
		ensureClientData().Origin.SetValue(value)
	}
	if flags.Changed("android-package") {
		value, _ := flags.GetString("android-package")
		ensureClientData().AndroidPackageName.SetValue(value)
	}
	if flags.Changed("cross-origin") {
		value, _ := flags.GetBool("cross-origin")
		ensureClientData().CrossOrigin.SetValue(value)
	}
	if flags.Changed("top-origin") {
		value, _ := flags.GetString("top-origin")
		ensureClientData().TopOrigin.SetValue(value)
	}
	if flags.Changed("field-order") {
		value, _ := flags.GetStringSlice("field-order")
		ensureClientData().FieldOrder = value
	}

	var authData *webauthn.AuthenticatorDataOverrides
	ensureAuthData := func() *webauthn.AuthenticatorDataOverrides {
		if authData == nil {
			authData = &webauthn.AuthenticatorDataOverrides{}
		}
		return authData
	}

	if flags.Changed("flags") {
		value, _ := flags.GetUint8("flags")
		ensureAuthData().Flags.SetValue(value)
	}
	for _, bit := range []struct {
		name   string
		assign func(*webauthn.AuthenticatorDataOverrides, bool)
	}{
		{"up", func(o *webauthn.AuthenticatorDataOverrides, v bool) { o.UP.SetValue(v) }},
		{"uv", func(o *webauthn.AuthenticatorDataOverrides, v bool) { o.UV.SetValue(v) }},
		{"be", func(o *webauthn.AuthenticatorDataOverrides, v bool) { o.BE.SetValue(v) }},
		{"bs", func(o *webauthn.AuthenticatorDataOverrides, v bool) { o.BS.SetValue(v) }},
		{"at", func(o *webauthn.AuthenticatorDataOverrides, v bool) { o.AT.SetValue(v) }},
		{"ed", func(o *webauthn.AuthenticatorDataOverrides, v bool) { o.ED.SetValue(v) }},
	} {
		if !flags.Changed(bit.name) {
			continue
		}
		value, _ := flags.GetBool(bit.name)
		bit.assign(ensureAuthData(), value)
	}
	if flags.Changed("sign-count") {
		value, _ := flags.GetUint32("sign-count")
		ensureAuthData().SignCount.SetValue(value)
	}
	if flags.Changed("rp-id-hash") {
		value, _ := flags.GetString("rp-id-hash")
		decoded, err := webauthn.DecodeBase64Permissive(value)
		if err != nil {
			return overrides, fmt.Errorf("invalid --rp-id-hash: %w", err)
		}
		ensureAuthData().RPIDHash.SetValue(webauthn.Base64Bytes(decoded))
	}
	if flags.Changed("aaguid") {
		value, _ := flags.GetString("aaguid")
		decoded, err := webauthn.ParseAAGUID(value)
		if err != nil {
			return overrides, err
		}
		ensureAuthData().AAGUID.SetValue(webauthn.AAGUIDValue(decoded))
	}

	if flags.Changed("null-field") {
		names, _ := flags.GetStringSlice("null-field")
		for _, name := range names {
			setNull, ok := nullableFields[name]
			if !ok {
				return overrides, fmt.Errorf("--null-field %q is not a field that can be omitted (try one of: %s)",
					name, strings.Join(nullableFieldNames(), ", "))
			}
			setNull(ensureClientData(), ensureAuthData())
		}
	}

	if flags.Changed("client-data-raw") {
		value, _ := flags.GetString("client-data-raw")
		decoded, err := webauthn.DecodeBase64Permissive(value)
		if err != nil {
			return overrides, fmt.Errorf("invalid --client-data-raw: %w", err)
		}
		raw := webauthn.Base64Bytes(decoded)
		overrides.ClientDataRaw = &raw
	}
	if flags.Changed("authenticator-data-raw") {
		value, _ := flags.GetString("authenticator-data-raw")
		decoded, err := webauthn.DecodeBase64Permissive(value)
		if err != nil {
			return overrides, fmt.Errorf("invalid --authenticator-data-raw: %w", err)
		}
		raw := webauthn.Base64Bytes(decoded)
		overrides.AuthenticatorDataRaw = &raw
	}

	overrides.ClientData = clientData
	overrides.AuthenticatorData = authData
	return overrides, nil
}

func nullableFieldNames() []string {
	names := make([]string, 0, len(nullableFields))
	for name := range nullableFields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
