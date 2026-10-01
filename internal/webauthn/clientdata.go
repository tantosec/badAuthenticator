package webauthn

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// clientDataDefaults applies where neither the profile nor request sets a value.
type clientDataDefaults struct {
	Type      string
	Challenge string
	Origin    string
}

// buildClientDataJSON writes fields in the requested order, preserving repeats.
// Unknown names and fields without values are skipped.
func buildClientDataJSON(defaults clientDataDefaults, overrides *ClientDataOverrides, fieldOrder []string) ([]byte, error) {
	if overrides == nil {
		overrides = &ClientDataOverrides{}
	}

	// Fill absent fields without overwriting explicit nulls.
	resolved := *overrides
	if !resolved.Type.Present {
		resolved.Type.SetValue(defaults.Type)
	}
	if !resolved.Challenge.Present {
		resolved.Challenge.SetValue(defaults.Challenge)
	}
	if !resolved.Origin.Present {
		resolved.Origin.SetValue(defaults.Origin)
	}

	var buffer bytes.Buffer
	buffer.WriteByte('{')

	fieldsWritten := 0
	writeField := func(key string, value any) error {
		encodedValue, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal clientData field %q: %w", key, err)
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			return fmt.Errorf("failed to marshal clientData key %q: %w", key, err)
		}

		if fieldsWritten > 0 {
			buffer.WriteByte(',')
		}
		fieldsWritten++
		buffer.Write(encodedKey)
		buffer.WriteByte(':')
		buffer.Write(encodedValue)
		return nil
	}

	for _, fieldName := range fieldOrder {
		switch fieldName {
		case FieldType:
			if resolved.Type.HasValue() {
				if err := writeField(fieldName, resolved.Type.Value); err != nil {
					return nil, err
				}
			}
		case FieldChallenge:
			if resolved.Challenge.HasValue() {
				if err := writeField(fieldName, resolved.Challenge.Value); err != nil {
					return nil, err
				}
			}
		case FieldOrigin:
			if resolved.Origin.HasValue() {
				if err := writeField(fieldName, resolved.Origin.Value); err != nil {
					return nil, err
				}
			}
		case FieldAndroidPackageName:
			if resolved.AndroidPackageName.HasValue() {
				if err := writeField(fieldName, resolved.AndroidPackageName.Value); err != nil {
					return nil, err
				}
			}
		case FieldCrossOrigin:
			if resolved.CrossOrigin.HasValue() {
				if err := writeField(fieldName, resolved.CrossOrigin.Value); err != nil {
					return nil, err
				}
			}
		case FieldTopOrigin:
			if resolved.TopOrigin.HasValue() {
				if err := writeField(fieldName, resolved.TopOrigin.Value); err != nil {
					return nil, err
				}
			}
		default:
			// Unknown fields have no value to emit.
		}
	}

	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}

// resolveFieldOrder prefers the request, then the profile, then the web order.
func resolveFieldOrder(profile *Profile, overrides *ClientDataOverrides) []string {
	if overrides != nil && overrides.FieldOrder != nil {
		return overrides.FieldOrder
	}
	if profile != nil && profile.FieldOrder != nil {
		return profile.FieldOrder
	}
	return specFieldOrder
}
