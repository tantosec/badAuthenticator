package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAttestProfileCLI(t *testing.T) {
	const windowsAAGUID = "6028b017b1d44c02b4b3afcdafc96bb2"
	const zeroAAGUID = "00000000000000000000000000000000"
	for _, tc := range []struct {
		name       string
		flags      []string
		wantFormat string
		wantAAGUID string
		profiles   string
	}{
		{name: "default", wantFormat: "none", wantAAGUID: zeroAAGUID},
		{name: "profile", flags: []string{"--profile", "windows-hello-software"}, wantFormat: "packed", wantAAGUID: windowsAAGUID},
		{name: "explicit AAGUID", flags: []string{"--profile", "windows-hello-software", "--aaguid", zeroAAGUID}, wantFormat: "packed", wantAAGUID: zeroAAGUID},
		{name: "custom profile", flags: []string{"--profile", "custom"}, profiles: `{"custom":{"attestationFormat":"packed","aaguid":"00000000000000000000000000000000"}}`, wantFormat: "packed", wantAAGUID: zeroAAGUID},
		{name: "profile file override", flags: []string{"--profile", "windows-hello-software"}, profiles: `{"windows-hello-software":{"attestationFormat":"none","aaguid":"00000000000000000000000000000000"}}`, wantFormat: "none", wantAAGUID: zeroAAGUID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			args := append([]string{"-test.run=^TestAttestCLIProcess$", "--", "attest", "--keystore-dir", filepath.Join(dir, "badauthenticator-keystore"), "--format", "decoded"}, tc.flags...)
			if tc.profiles != "" {
				path := filepath.Join(dir, "profiles.json")
				if err := os.WriteFile(path, []byte(tc.profiles), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--profiles-file", path)
			}
			cmd := exec.Command(os.Args[0], args...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "BAD_AUTHENTICATOR_TEST_CLI=1", "BAD_AUTHENTICATOR_PROFILES=")
			cmd.Stdin = strings.NewReader(`{"rp":{"id":"example.com","name":"Example"},"user":{"id":"dXNlcg","name":"user","displayName":"User"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-7}]}`)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("CLI failed: %v\n%s", err, &stderr)
			}
			var response struct {
				Response struct {
					AttestationObject struct {
						Format   string `json:"fmt"`
						AuthData struct {
							AttestedCredentialData struct {
								AAGUID string `json:"aaguid"`
							} `json:"attestedCredentialData"`
						} `json:"authData"`
					} `json:"attestationObject"`
				} `json:"response"`
			}
			if err := json.Unmarshal(output, &response); err != nil {
				t.Fatalf("invalid CLI output: %v\n%s", err, output)
			}
			obj := response.Response.AttestationObject
			if obj.Format != tc.wantFormat || obj.AuthData.AttestedCredentialData.AAGUID != tc.wantAAGUID {
				t.Fatalf("format/AAGUID = %q/%q, want %q/%q", obj.Format, obj.AuthData.AttestedCredentialData.AAGUID, tc.wantFormat, tc.wantAAGUID)
			}
		})
	}
}

// Run each CLI invocation in its own process so Cobra flags and the keystore are isolated.
func TestAttestCLIProcess(t *testing.T) {
	if os.Getenv("BAD_AUTHENTICATOR_TEST_CLI") != "1" {
		return
	}
	rootCmd.SetArgs(os.Args[3:])
	if err := Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
