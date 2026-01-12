package jwt

import (
	"time"
)

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	AccessExpiry time.Time `json:"access_expiry"`
	TokenType    string    `json:"token_type"`
}

// TokenType represents different token types
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

type SecurityMode int

const (
	ModeIssuer    SecurityMode = 0
	ModeValidator SecurityMode = 1
	ModeBoth      SecurityMode = 2
)

// SigningMethod defines the supported signing algorithms
type SigningMethod string

const (
	RS256 SigningMethod = "RS256"
	RS384 SigningMethod = "RS384"
	RS512 SigningMethod = "RS512"
	HS256 SigningMethod = "HS256"
	HS384 SigningMethod = "HS384"
	HS512 SigningMethod = "HS512"
	ES256 SigningMethod = "ES256"
	ES384 SigningMethod = "ES384"
	ES512 SigningMethod = "ES512"
)

// KeySource defines where the key is loaded from
type KeySource int

const (
	KeySourceRaw KeySource = iota
	KeySourceFile
	KeySourcePEM
)

// KeyConfig holds configuration for cryptographic keys
type KeyConfig struct {
	// For HMAC (symmetric)
	HMACKey       []byte
	HMACKeyPath   string
	HMACKeySource KeySource

	// For RSA/ECDSA (asymmetric)
	PrivateKeyData   []byte
	PublicKeyData    []byte
	PrivateKeyPath   string
	PublicKeyPath    string
	PrivateKeySource KeySource
	PublicKeySource  KeySource

	// Algorithm configuration
	SigningMethod SigningMethod
}

// Config holds JWT manager configuration
type Config struct {
	Mode          SecurityMode
	Issuer        string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration

	// Key configurations
	KeyConfig *KeyConfig

	Algorithm string
}
