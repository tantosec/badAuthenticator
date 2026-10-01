package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeystoreDirectoryCLI(t *testing.T) {
	for _, name := range []string{"named", "relative", "absolute"} {
		t.Run(name, func(t *testing.T) {
			cwd := t.TempDir()
			directory := "badauthenticator-keystore"
			args := []string{"-test.run=^TestAttestCLIProcess$", "--", "attest"}
			switch name {
			case "relative":
				directory = "custom-store"
			case "absolute":
				directory = filepath.Join(t.TempDir(), "custom-store")
			}
			args = append(args, "--keystore-dir", directory)
			target := directory
			if !filepath.IsAbs(target) {
				target = filepath.Join(cwd, target)
			}
			if err := os.MkdirAll(target, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, "profiles.json"), []byte(`{"custom":{"attestationFormat":"none"}}`), 0600); err != nil {
				t.Fatal(err)
			}
			args = append(args, "--profile", "custom")
			cmd := exec.Command(os.Args[0], args...)
			cmd.Dir = cwd
			cmd.Env = append(os.Environ(), "BAD_AUTHENTICATOR_TEST_CLI=1", "BAD_AUTHENTICATOR_PROFILES=")
			cmd.Stdin = strings.NewReader(`{"rp":{"id":"example.com"},"user":{"id":"dXNlcg"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-7}]}`)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("CLI: %v: %s", err, output)
			}
			var response struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(output, &response); err != nil {
				t.Fatalf("response: %v: %s", err, output)
			}
			for _, path := range []string{"metadata.db", filepath.Join("keys", response.ID+".key.pem")} {
				if _, err := os.Stat(filepath.Join(target, path)); err != nil {
					t.Fatal(err)
				}
			}
			assertion := exec.Command(os.Args[0], "-test.run=^TestAttestCLIProcess$", "--", "assert", "--keystore-dir", target)
			assertion.Dir = t.TempDir()
			assertion.Env = cmd.Env
			assertion.Stdin = strings.NewReader(`{"rpId":"example.com","challenge":"bmV3","allowCredentials":[{"type":"public-key","id":"` + response.ID + `"}]}`)
			if output, err := assertion.CombinedOutput(); err != nil {
				t.Fatalf("assert from another directory: %v: %s", err, output)
			}
			if name != "named" {
				if _, err := os.Stat(filepath.Join(cwd, "badauthenticator-keystore")); !os.IsNotExist(err) {
					t.Fatal("custom directory created another keystore")
				}
			}
		})
	}
}

func TestKeystoreDirectoryRequired(t *testing.T) {
	for _, args := range [][]string{{"attest"}, {"assert"}, {"keystore", "list"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cwd := t.TempDir()
			cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestAttestCLIProcess$", "--"}, args...)...)
			cmd.Dir = cwd
			cmd.Env = append(os.Environ(), "BAD_AUTHENTICATOR_TEST_CLI=1")
			output, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "--keystore-dir is required") {
				t.Fatalf("missing keystore directory: %v: %s", err, output)
			}
			if _, err := os.Stat(filepath.Join(cwd, "badauthenticator-keystore")); !os.IsNotExist(err) {
				t.Fatal("created a keystore without --keystore-dir")
			}
		})
	}
}

func TestKeystoreListCreatesDirectory(t *testing.T) {
	cwd := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestAttestCLIProcess$", "--", "keystore", "list", "--keystore-dir", "badauthenticator-keystore")
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "BAD_AUTHENTICATOR_TEST_CLI=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("keystore list: %v: %s", err, output)
	}
	if _, err := os.Stat(filepath.Join(cwd, "badauthenticator-keystore", "metadata.db")); err != nil {
		t.Fatal(err)
	}
}
