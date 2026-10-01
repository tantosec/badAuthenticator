# HTTP API

`internal/handlers` passes HTTP requests to the ceremony functions used by the CLI.
`cmd/badauthenticator/cmd/serve.go` registers routes and middleware.

| Route | Methods | Authentication |
|---|---|---|
| `/api/v1/attest` | POST (GET opt-in) | Bearer by default |
| `/api/v1/assert` | POST | Bearer |
| `/api/v1/listCredentials` | GET | Bearer |
| `/` (with `--public-dir`) | GET | None (static files) |

`--allow-unauthenticated-attestation` removes authentication from the first
route only.

## Ceremony requests

`WebAuthnAPIHandler` reads POST bodies as JSON envelopes containing `options`.
GET attestation requires `--allow-get-attestation`. Its `options` query parameter
accepts URL-encoded JSON or unpadded base64url JSON, as bare options or an envelope.
The required `(rp.id, user.id, challenge)` tuple identifies the first successful
response, saved in SQLite with its credential. Replays, including concurrent
requests and requests after a restart, return that response without changing the
credential. Other options do not affect this lookup. Failed requests can be retried.
POST requests do not use this lookup and always create a new credential.

The handler passes the whole envelope to `HandleAttestation` or
`HandleAssertion`. Those functions call the WebAuthn package to parse options
and resolve overrides. See [WebAuthn](webauthn.md) for the envelope fields.

POST bodies are limited to 10 MiB, including streamed requests with no declared
length. Larger bodies receive `413 request_body_too_large`. The handler does not
check Content-Type.

## Credential listing

`GET /api/v1/listCredentials?rpid=example.com` returns a `credentials` array with
`credentialId`, `rpid`, `userHandle`, `signCount` and `creationDate` fields.
The response also includes non-empty `origin`, `androidPackageName` and
`profile` values. An RP with no matching credentials gets an empty array.

## Errors

Errors use `code` and `error` fields. Internal error details go to the server
log.

```json
{"code": "missing_rpid", "error": "Missing rpid query parameter"}
```

| Status | Examples |
|---|---|
| 400 | `invalid_json`, `missing_options`, `invalid_base64url_options`, `missing_data`, `missing_rpid`, `missing_replay_key`, `operation_failed` |
| 405 | `method_not_allowed` |
| 413 | `request_body_too_large` |
| 500 | `attestation_storage_failed` |

Untyped ceremony errors become `400 operation_failed`. Request-body read failures
and response encoding failures return 500.
