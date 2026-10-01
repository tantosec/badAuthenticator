package webauthn

type authenticatorDataDefaults struct {
	RPIDHash  []byte
	UP        bool
	UV        bool
	BE        bool
	BS        bool
	AT        bool
	ED        bool
	SignCount uint32
}

// resolveAuthenticatorDataParams applies overrides and converts null fields to
// nil builder parameters. Null flag bits keep their defaults.
func resolveAuthenticatorDataParams(overrides *AuthenticatorDataOverrides, defaults authenticatorDataDefaults) AuthenticatorDataParams {
	flags := AssembleFlags(defaults.UP, defaults.UV, defaults.BE, defaults.BS, defaults.AT, defaults.ED)
	signCount := defaults.SignCount

	params := AuthenticatorDataParams{
		RPIDHash:  defaults.RPIDHash,
		Flags:     &flags,
		SignCount: &signCount,
	}

	if overrides == nil {
		return params
	}

	if overrides.RPIDHash.Present {
		if overrides.RPIDHash.Null {
			params.RPIDHash = nil
		} else {
			params.RPIDHash = overrides.RPIDHash.Value
		}
	}

	switch {
	case overrides.Flags.Null:
		params.Flags = nil
	case overrides.Flags.Present:
		flags = overrides.Flags.Value
	default:
		up := boolOr(overrides.UP, defaults.UP)
		uv := boolOr(overrides.UV, defaults.UV)
		be := boolOr(overrides.BE, defaults.BE)
		bs := boolOr(overrides.BS, defaults.BS)
		at := boolOr(overrides.AT, defaults.AT)
		ed := boolOr(overrides.ED, defaults.ED)
		flags = AssembleFlags(up, uv, be, bs, at, ed)
	}

	if overrides.SignCount.Present {
		if overrides.SignCount.Null {
			params.SignCount = nil
		} else {
			signCount = overrides.SignCount.Value
		}
	}

	return params
}

// A null bit keeps its default. False clears it.
func boolOr(override Opt[bool], fallback bool) bool {
	if override.HasValue() {
		return override.Value
	}
	return fallback
}
