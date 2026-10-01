package types

// CredentialTransfer is the import/export format, including the private key.
type CredentialTransfer struct {
	CredentialID  string `json:"credentialId"`
	PrivateKeyPEM string `json:"privateKeyPem"`
	RPID          string `json:"rpid"`
	UserHandle    string `json:"userHandle"`
	SignCount     int    `json:"signCount"`
	CoseAlgorithm int64  `json:"coseAlgorithm,omitempty"`

	Origin             string `json:"origin,omitempty"`
	AndroidPackageName string `json:"androidPackageName,omitempty"`
	Profile            string `json:"profile,omitempty"`
}
