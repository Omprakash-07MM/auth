package jwt

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager manages JWT operations
type JWTManager struct {
	mode          SecurityMode
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	signingMethod jwt.SigningMethod
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	issuer        string
}

// NewJWTManager creates a new JWT manager with RSA keys

func NewJWTManager(config *Config) (*JWTManager, error) {
	if config.Mode == ModeIssuer {
		return NewJWTIssuer(config.PrivateKeyPEM, config.PublicKeyPEM, config.Issuer)
	} else {
		return NewJWTValidator(config.PublicKeyPEM, config.Issuer)
	}
}

// NewJWTIssuer creates a JWT manager that can issue tokens (Auth Service)
func NewJWTIssuer(privateKeyPEM, publicKeyPEM []byte, issuer string) (*JWTManager, error) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &JWTManager{
		mode:          ModeIssuer,
		privateKey:    privateKey,
		publicKey:     publicKey,
		signingMethod: jwt.SigningMethodRS256,
		accessExpiry:  15 * time.Minute,
		refreshExpiry: 7 * 24 * time.Hour,
		issuer:        issuer,
	}, nil
}

func NewJWTValidator(publicKeyPEM []byte, issuer string) (*JWTManager, error) {

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &JWTManager{
		mode:       ModeValidator,
		privateKey: nil, // No private key!
		publicKey:  publicKey,
		// ... other config
	}, nil
}

// ValidateToken validates and parses a JWT token
func (jm *JWTManager) ValidateToken(tokenString string) (*CustomClaims, error) {
	token, err := jm.ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		if err := claims.Validate(); err != nil {
			return nil, err
		}
		return claims, nil
	}

	return nil, ErrInvalidToken
}

// ParseToken parses a JWT token without validating custom claims
func (jm *JWTManager) ParseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// IMPORTANT: Validate the algorithm to prevent algorithm confusion attacks
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, ErrInvalidSigningMethod
		}
		return jm.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	return token, nil
}

// GetAccessExpiry returns access token expiry duration
func (jm *JWTManager) GetAccessExpiry() time.Duration {
	return jm.accessExpiry
}

// GetRefreshExpiry returns refresh token expiry duration
func (jm *JWTManager) GetRefreshExpiry() time.Duration {
	return jm.refreshExpiry
}
