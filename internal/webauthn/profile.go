package webauthn

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/tantosec/badAuthenticator/internal/config"
)

// Profile holds client data, AAGUID, transport and attestation defaults for a ceremony.
type Profile struct {
	// Name comes from the key in the profiles file.
	Name string `json:"-"`

	// FieldOrder controls JSON key order. Fields without values are skipped.
	FieldOrder []string `json:"fieldOrder,omitempty"`

	ClientData ClientDataOverrides `json:"clientData,omitempty"`

	// AAGUID accepts UUID or hex strings in JSON.
	AAGUID AAGUIDValue `json:"aaguid,omitempty"`

	// Transports appears only in attestation responses.
	Transports []string `json:"transports,omitempty"`

	// AttestationFormat applies to registration only. Empty defaults to none.
	AttestationFormat AttestationFormat `json:"attestationFormat,omitempty"`

	AttestationType AttestationType `json:"attestationType,omitempty"`

	// NoAssembly uses raw overrides only, emitting empty bytes when absent.
	NoAssembly bool `json:"noAssembly,omitempty"`
}

const (
	FieldType               = "type"
	FieldChallenge          = "challenge"
	FieldOrigin             = "origin"
	FieldAndroidPackageName = "androidPackageName"
	FieldCrossOrigin        = "crossOrigin"
	FieldTopOrigin          = "topOrigin"
)

const (
	ProfileWeb                  = "web"
	ProfileAndroid              = "android"
	ProfileRaw                  = "raw"
	ProfileWindowsHelloSoftware = "windows-hello-software"
)

const DefaultProfile = ProfileWeb

// AAGUID source: https://github.com/passkeydeveloper/passkey-authenticator-aaguids.
const googlePasswordManagerAAGUID = "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4"
const windowsHelloSoftwareAAGUID = "6028b017-b1d4-4c02-b4b3-afcdafc96bb2"

const androidPackageNameDefault = "com.google.android.gms"

// Include normally absent fields at the end so explicit overrides have a position.
var specFieldOrder = []string{FieldType, FieldChallenge, FieldOrigin, FieldCrossOrigin, FieldTopOrigin, FieldAndroidPackageName}

var androidFieldOrder = []string{FieldType, FieldChallenge, FieldOrigin, FieldAndroidPackageName, FieldCrossOrigin, FieldTopOrigin}

func builtinProfiles() map[string]*Profile {
	// The web default writes 16 zero bytes. A null AAGUID writes none.
	web := &Profile{
		Name:       ProfileWeb,
		FieldOrder: specFieldOrder,
		AAGUID:     make(AAGUIDValue, 16),
		Transports: []string{"internal"},
	}
	web.ClientData.CrossOrigin.SetValue(false)

	android := &Profile{
		Name:       ProfileAndroid,
		FieldOrder: androidFieldOrder,
		AAGUID:     mustParseAAGUID(googlePasswordManagerAAGUID),
		Transports: []string{"internal"},
	}
	android.ClientData.AndroidPackageName.SetValue(androidPackageNameDefault)

	windowsHello := &Profile{
		Name:              ProfileWindowsHelloSoftware,
		FieldOrder:        specFieldOrder,
		AAGUID:            mustParseAAGUID(windowsHelloSoftwareAAGUID),
		Transports:        []string{"internal"},
		AttestationFormat: AttestationFormatPacked,
	}
	windowsHello.ClientData.CrossOrigin.SetValue(false)

	raw := &Profile{
		Name:       ProfileRaw,
		NoAssembly: true,
	}

	return map[string]*Profile{
		ProfileWeb:                  web,
		ProfileAndroid:              android,
		ProfileRaw:                  raw,
		ProfileWindowsHelloSoftware: windowsHello,
	}
}

var (
	profilesOnce  sync.Once
	profilesMutex sync.RWMutex
	profiles      map[string]*Profile
	profilesErr   error
)

const ProfilesFileEnvVar = "BAD_AUTHENTICATOR_PROFILES"

const DefaultProfilesFileName = "profiles.json"

// LoadProfiles resets the built-ins and loads custom profiles, replacing any
// matching names. Path falls back to the environment, then the keystore.
// An explicit path must exist. Only a missing default file is ignored.
func LoadProfiles(path string) error {
	table := builtinProfiles()

	resolvedPath := path
	if resolvedPath == "" {
		resolvedPath = os.Getenv(ProfilesFileEnvVar)
	}
	explicit := resolvedPath != ""
	if resolvedPath == "" {
		resolvedPath = filepath.Join(config.KeystoreDir, DefaultProfilesFileName)
	}

	fileBytes, err := os.ReadFile(resolvedPath)
	switch {
	case err == nil:
		var userProfiles map[string]*Profile
		if err := json.Unmarshal(fileBytes, &userProfiles); err != nil {
			return fmt.Errorf("failed to parse profiles file %q: %w", resolvedPath, err)
		}
		for name, profile := range userProfiles {
			if profile == nil {
				continue
			}
			switch profile.AttestationFormat {
			case "", AttestationFormatNone, AttestationFormatPacked:
			default:
				return fmt.Errorf("profile %q: unsupported attestation format %q", name, profile.AttestationFormat)
			}
			switch profile.AttestationType {
			case "", AttestationTypeSelf, AttestationTypeFull:
			default:
				return fmt.Errorf("profile %q: unsupported attestation type %q", name, profile.AttestationType)
			}
			if profile.AttestationType == AttestationTypeFull && profile.AttestationFormat != AttestationFormatPacked {
				return fmt.Errorf("profile %q: attestationType %q requires attestationFormat %q", name, AttestationTypeFull, AttestationFormatPacked)
			}
			profile.Name = name
			table[name] = profile
		}
	case os.IsNotExist(err) && !explicit:
		// The default profiles file is optional.
	default:
		return fmt.Errorf("failed to read profiles file %q: %w", resolvedPath, err)
	}

	profilesMutex.Lock()
	profiles = table
	profilesErr = nil
	profilesMutex.Unlock()
	return nil
}

func profileTable() (map[string]*Profile, error) {
	profilesOnce.Do(func() {
		profilesMutex.RLock()
		loaded := profiles != nil
		profilesMutex.RUnlock()
		if loaded {
			return
		}
		if err := LoadProfiles(""); err != nil {
			profilesMutex.Lock()
			profiles = builtinProfiles()
			profilesErr = err
			profilesMutex.Unlock()
		}
	})

	profilesMutex.RLock()
	defer profilesMutex.RUnlock()
	return profiles, profilesErr
}

// GetProfile uses DefaultProfile when name is empty.
func GetProfile(name string) (*Profile, error) {
	table, err := profileTable()
	if err != nil {
		return nil, err
	}

	if name == "" {
		name = DefaultProfile
	}
	profile, ok := table[name]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q (available: %s)", name, strings.Join(profileNames(table), ", "))
	}
	return profile, nil
}

// ProfileNames returns available names in sorted order.
func ProfileNames() []string {
	table, _ := profileTable()
	return profileNames(table)
}

func profileNames(table map[string]*Profile) []string {
	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// AAGUIDValue encodes 16 bytes as a UUID and other lengths as hex.
type AAGUIDValue []byte

func (a *AAGUIDValue) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("expected an AAGUID string: %w", err)
	}

	parsed, err := ParseAAGUID(encoded)
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

func (a AAGUIDValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

func (a AAGUIDValue) String() string {
	if len(a) != 16 {
		return hex.EncodeToString(a)
	}
	encoded := hex.EncodeToString(a)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32])
}

// ParseAAGUID accepts UUID or hex strings without checking the decoded length.
func ParseAAGUID(value string) ([]byte, error) {
	stripped := strings.ReplaceAll(strings.TrimSpace(value), "-", "")
	decoded, err := hex.DecodeString(stripped)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string for aaguid %q: %w", value, err)
	}
	return decoded, nil
}

func mustParseAAGUID(value string) AAGUIDValue {
	parsed, err := ParseAAGUID(value)
	if err != nil {
		panic(fmt.Sprintf("webauthn: built-in AAGUID %q is invalid: %v", value, err))
	}
	return parsed
}
