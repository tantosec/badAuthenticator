# CLI reference

Commands use Cobra under `cmd/badauthenticator/cmd`. The root command initialises
logging and opens the keystore, then passes the database through command context.
`-v` enables debug logging. Pass `--keystore-dir <PATH>` with `attest`, `assert`,
`serve` and every `keystore` subcommand. The directory is created if needed.

## Ceremonies

`attest` and `assert` read JSON from stdin: bare WebAuthn options, or an envelope
with an `options` field and overrides. Both call the shared handlers and write
the response to stdout. Explicit flags take precedence over envelope values.

| Output flag | Result |
|---|---|
| `--format json` | WebAuthn response JSON on stdout (default) |
| `--format decoded` | Decoded response JSON on stdout |
| `--human-readable` | Decoded details on stderr while stdout stays JSON (ignored with `--format decoded`) |

`ceremonyflags.go` registers the shared override flags:

| Flags | Purpose |
|---|---|
| `--profile`, `--profiles-file` | Select a profile or load custom profiles |
| `--strict` | Check output before returning it |
| `--origin`, `--android-package`, `--client-data-type` | Set client data fields |
| `--cross-origin`, `--top-origin`, `--field-order` | Set cross-origin fields and JSON key order |
| `--flags` | Replace the whole flags byte, taking precedence over individual bits |
| `--up`, `--uv`, `--be`, `--bs`, `--at`, `--ed` | Set individual flag bits |
| `--sign-count`, `--rp-id-hash` | Set the counter or emitted RP ID hash |
| `--aaguid` | Set the attestation AAGUID |
| `--client-data-raw`, `--authenticator-data-raw` | Supply base64-encoded output bytes |
| `--null-field` | Omit a field (repeatable) |
| `--alg` | Select an algorithm explicitly |

`attest` also accepts `--cred-id-len`, and `assert` accepts `--cred-id` to select
a stored credential. Use `--help` with either command for its accepted values.
See [WebAuthn](webauthn.md) for override rules and how `--strict` affects storage.

## Server

`serve` starts the [HTTP API](http.md). Static files are served only when
`--public-dir` is supplied, and that directory must already exist.

| Flag | Default |
|---|---|
| `-p`, `--port` | `8080` |
| `--bind-address` | `127.0.0.1` |
| `--public-dir` | Disabled |
| `--allow-unauthenticated-attestation` | `false` |
| `--allow-get-attestation` | `false` |
| `--read-timeout` | `10s` |
| `--read-header-timeout` | `5s` |
| `--write-timeout` | `30s` |
| `--idle-timeout` | `120s` |
| `--shutdown-timeout` | `10s` |

Bearer tokens come from `BAD_AUTHENTICATOR_BEARER_TOKENS`, separated by commas,
with a minimum length of 24 characters. If unset, the server generates a token
and logs it at startup.

## Keystore

Run each subcommand after `badauthenticator --keystore-dir <PATH> keystore`.
For example:

```sh
badauthenticator --keystore-dir ./badauthenticator-keystore keystore list
```

| Subcommand | Result |
|---|---|
| `list` | One credential per line as JSON |
| `export --id <id>` | Credential JSON, including the PEM private key |
| `import [--from-file <path>]` | Import from a file or stdin |
| `update <id> <field> <value>` | Update one metadata field |
| `clear [--force]` | Delete the keystore after confirmation, unless forced |

See [Keystore](keystore.md) for fields and import behaviour.
