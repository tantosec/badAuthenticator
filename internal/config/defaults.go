package config

import "time"

const (
	DefaultHTTPPort              = 8080
	DefaultHTTPReadTimeout       = 10 * time.Second
	DefaultHTTPReadHeaderTimeout = 5 * time.Second
	DefaultHTTPWriteTimeout      = 30 * time.Second
	DefaultHTTPIdleTimeout       = 120 * time.Second
	DefaultHTTPShutdownTimeout   = 10 * time.Second
	DefaultHTTPBindAddress       = "127.0.0.1"

	DefaultDirectoryPermissions   = 0o755
	PrivateKeyFilePermissions     = 0o600
	MinBearerTokenLength          = 24
	GeneratedBearerTokenBytes     = 32
	DefaultCredentialIDLength     = uint16(16)
	DefaultRSAPrivateKeyBitLength = 2048
)
