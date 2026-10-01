# Keystore

`internal/keystore` stores metadata in `<PATH>/metadata.db` and private keys in
`<PATH>/keys/<credential-id>.key.pem`, where `<PATH>` is the required
`--keystore-dir` value. Keys use unencrypted PKCS#8 PEM, with `0600` permissions
when created. The directory also holds the default `profiles.json`.

Pass `--keystore-dir <PATH>` with each CLI command. For example:

```sh
badauthenticator --keystore-dir ./badauthenticator-keystore keystore list
```

## Metadata

| Field | Stored value |
|---|---|
| `CredentialID` | Base64url credential ID used as the primary key |
| `PrivateKeyFilePath` | Path to the PEM file |
| `PublicKeyBytesHex` | Provider-specific public key representation |
| `UserHandle` | Base64url user ID |
| `SignCount` | Signature counter |
| `RPIDHash` | Hex SHA-256 of the RP ID |
| `CreationDate` | UTC RFC 3339 timestamp |
| `RPID` | RP ID string |
| `CoseAlgorithm` | COSE algorithm ID, stored in the `cose_algorithm` column |
| `Origin`, `AndroidPackageName` | Explicit client data values saved at registration |
| `Profile` | Registration profile name |

Assertions reuse the stored profile, origin and package unless overridden.
Each assertion reads the profile defaults, so profile edits affect existing
credentials. Empty origin or package values use the profile and ceremony defaults.

`OpenAndVerifyDB` creates the schema or adds missing columns through
`MigrateSchema`. Reads use an explicit column list and treat null values in the
added columns as empty strings.

The `attestation_replays` table saves successful GET attestation responses by
`(rp.id, user.id, challenge)`. Clearing the keystore also clears these responses.

## Import, export and updates

`CredentialTransfer` in `internal/types/types.go` defines the JSON format. An
export contains the credential ID, PEM private key, RP ID, base64url user handle,
counter, algorithm, and any stored client data values or profile.

Import requires an unpadded base64url credential ID, rejects duplicate IDs and
existing key files, parses the PEM key and derives the public key, RP ID hash
and algorithm. It preserves the counter and client data metadata, but
sets a new creation timestamp. Algorithm detection uses the key type. RSA
imports become RS256 even if the transfer JSON specifies PSS.

`UpdateCredentialByID` accepts the metadata fields above except `CredentialID`.
Field names are case-insensitive. Both `CoseAlgorithm` and `cose_algorithm` are
accepted. Column names come from a fixed allow list and values use SQL
parameters. Updates affect one field at a time and do not recompute related
fields. The CLI accepts plain text for `UserHandle` and base64url-encodes it.

`ClearAll` removes the entire keystore directory, including `profiles.json` if
stored there. The CLI asks for confirmation unless `--force` is set.
