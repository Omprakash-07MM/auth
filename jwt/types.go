package jwt

import (
	"time"
)

// Config holds JWT configuration
type Config struct {
	Mode          SecurityMode  // Required: issuer, validator, or both
	PrivateKeyPEM []byte        // Private key content (PEM encoded) - only for issuer/both
	PublicKeyPEM  []byte        // Public key content (PEM encoded) - always required
	AccessExpiry  time.Duration // Access token expiry
	RefreshExpiry time.Duration // Refresh token expiry
	Issuer        string        // Token issuer name
}

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

type SecurityMode string

const (
	ModeIssuer    SecurityMode = "issuer"    // Auth Service: Generate tokens only
	ModeValidator SecurityMode = "validator" // Other Services: Validate tokens only
)
