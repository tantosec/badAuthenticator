# WebAuthn

`internal/webauthn` builds registration and assertion responses. `attestation.go`
and `assertion.go` parse requests. `webauthn.go` creates credentials and signs
responses. Both ceremonies share the client data and authenticator data builders.

## Profiles

Profiles in `profile.go` supply defaults for client data, AAGUID, transports
and attestation format. The built-ins are:

| Profile | `crossOrigin` | `androidPackageName` | AAGUID | Transports |
|---|---|---|---|---|
| `web` | `false` | Omitted | 16 zero bytes | `["internal"]` |
| `android` | Omitted | `com.google.android.gms` | `ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4` | `["internal"]` |
| `windows-hello-software` | `false` | Omitted | `6028b017-b1d4-4c02-b4b3-afcdafc96bb2` | `["internal"]` |
| `raw` | No assembly | No assembly | No assembly | Omitted |

The `web` field order is `type`, `challenge`, `origin`, `crossOrigin`, `topOrigin`,
`androidPackageName`. The `android` order moves `androidPackageName` immediately
after `origin`. Fields without a value are skipped.

The tool loads custom profiles from `--profiles-file`, `BAD_AUTHENTICATOR_PROFILES`,
or `profiles.json` inside the selected keystore, in that order. A missing default
file is fine. An explicit path must exist. Entries replace built-ins with the same name.

```json
{
  "ios": {
    "fieldOrder": ["type", "challenge", "origin", "crossOrigin", "topOrigin"],
    "clientData": {"crossOrigin": false},
    "aaguid": "fbfc3007-154e-4ecc-8c0b-6e020557d7bd",
    "transports": ["internal"]
  }
}
```

A credential stores its registration profile name and any explicit origin or
Android package value. Assertions reuse these unless the request overrides
them. Defaults are read from the profile at use time, so editing a profile
affects existing credentials too.

## Request fields

The CLI accepts bare WebAuthn options or an envelope. HTTP POST requires the
envelope. GET attestation accepts either. A top-level `options` key identifies
an envelope.

| Envelope field | Value |
|---|---|
| `options` | WebAuthn creation or request options |
| `profile` | Profile name (defaults to `web`, or the stored profile for assertions) |
| `validate` | Enable output validation |
| `clientData` | Structured client data overrides |
| `authenticatorData` | Structured authenticator data overrides |
| `clientDataRaw` | Base64-encoded client data bytes |
| `authenticatorDataRaw` | Base64-encoded authenticator data bytes |

Client data fields are `type`, `challenge`, `origin`, `androidPackageName`,
`crossOrigin`, `topOrigin` and `fieldOrder`. Authenticator data fields are
`flags`, `up`, `uv`, `be`, `bs`, `at`, `ed`, `signCount`, `rpIdHash` and `aaguid`.

`rpIdHash` and raw byte fields accept standard or URL-safe base64, with or
without padding. AAGUIDs accept UUID or hex strings. Their decoded length is
not checked during parsing.

## Override rules

The tool applies values in this order, with later values taking precedence:
ceremony defaults, profile values, stored client data for assertions, envelope
overrides, and explicit CLI flags.

Raw bytes replace the corresponding assembled output. Validation stays enabled
if either the envelope or CLI enables it.

For fields represented by `Opt[T]`:

| Input | Result |
|---|---|
| Absent | Use the resolved default |
| `null` | Omit the field |
| Value | Use the supplied value |

`--null-field` supplies an explicit null from the CLI. Individual flag bits treat
null as absent. Use `false` to clear a bit. A whole-byte `flags` override takes
precedence over the individual bits.

A supplied `fieldOrder` replaces the profile's order. Repeated names repeat the
JSON key. The builder skips unknown names and fields without values. An empty
list emits `{}`. Omitted or null `fieldOrder` uses the profile's order.

Raw overrides are emitted byte for byte and logged to stderr. The `raw` profile
skips both builders, producing empty byte strings wherever no raw value is
supplied. Validation, when enabled, also checks raw output.

## Authenticator data and signatures

The normal binary layout is:

| Length | Field |
|---|---|
| 32 bytes | SHA-256 of the RP ID |
| 1 byte | Flags: UP `0x01`, UV `0x04`, BE `0x08`, BS `0x10`, AT `0x40`, ED `0x80` |
| 4 bytes | Big-endian signature counter |
| Variable | Attested credential data, if AT is set |
| Variable | CBOR extension data, if ED is set |

Attested credential data contains a 16-byte AAGUID, a two-byte credential ID
length, the credential ID, and a CBOR COSE public key. Authenticator data itself
is not CBOR. The builder writes supplied lengths and values without validation
and skips nil fields.

Attestation defaults to UP, UV and AT set, a counter of zero and a random
16-byte credential ID. Assertions set UP and set UV when `userVerification` is
`required`. These flags describe the generated response. No physical presence
or verification takes place.

Assertions and packed self-attestation sign
`authenticatorData || SHA256(clientDataJSON)`. The selected crypto provider
performs any further hashing required by its algorithm. Overrides are applied
before signing.

An RP ID hash override affects only output. Credential discovery and storage
use the actual RP ID hash. An attestation counter override sets the initial
stored counter. An assertion counter override leaves the stored counter
unchanged. Otherwise the counter advances before signing.

## Validation and limits

`--strict` or `"validate": true` enables these output checks:

- Client data is one JSON object with unique keys and no trailing data.
- Type and challenge match the ceremony options.
- Origin is present and non-empty.
- Authenticator data has a complete header and the expected RP ID hash.
- UP is set, BS implies BE, and AT matches the ceremony.
- Attested credential data and extension CBOR parse without trailing bytes.

This does not verify origin syntax or binding, counter monotonicity, signatures,
or every WebAuthn requirement. Validation runs after credential creation or
counter updates and does not roll them back on failure. GET attestation is an
exception: its transaction rolls back a failed request and removes the new key.

The profile field `attestationFormat` accepts `none` (the default when omitted) or
`packed`. The `windows-hello-software` profile selects `packed`.

Direct Go attestation overrides take precedence over the profile. Assertions do
not use this field. Other formats are unsupported, as are caller-supplied client
data hashes.

For `packed`, `attestationType` is `self` (default) or `full`. Self-attestation
signs with the credential key. Full attestation signs with a new ES256 leaf key and
emits `x5c = [leaf, self-signed root]`. The leaf's AAGUID extension matches the
authenticator data; the root is untrusted. `full` requires a packed profile.
The CLI flag `--attestation-type` overrides the profile's type.

Setting ED through structured overrides adds no extension payload. Set transports
in a profile; requests cannot override them.
