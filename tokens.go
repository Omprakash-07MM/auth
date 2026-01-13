package jwt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenIssuer interface {
	GenerateAccessToken(userID string) (string, time.Time, error)
	GenerateRefreshToken(userID string) (string, time.Time, error)
	GenerateTokenPair(userID string) (*TokenPair, error)
	RefreshToken(refreshToken string) (*TokenPair, error)
}

// TokenManager handles token operations
type TokenValidator interface {
	ValidateToken(tokenString string) (*CustomClaims, error)
	ParseToken(tokenString string) (*jwt.Token, error)
	GetTokenHash(token string) string
}

// GenerateAccessToken creates a new access token
func (jm *JWTManager) GenerateAccessToken(userID string, opts ...Options) (string, time.Time, error) {
	expirationTime := time.Now().Add(jm.accessExpiry)

	options := &options{}
	for _, opt := range opts {
		opt(options)
	}

	claims := &CustomClaims{
		UserID:    userID,
		TokenType: AccessToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    jm.issuer,
			Subject:   userID,
		},
	}

	if options.tokenVersion != nil {
		claims.TokenVersion = *options.tokenVersion
	}

	if err := claims.Validate(); err != nil {
		return "", time.Time{}, fmt.Errorf("%w: %v", ErrInvalidClaims, err)
	}

	token := jwt.NewWithClaims(jm.signingMethod, claims)
	tokenString, err := token.SignedString(jm.signingKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("%w: %v", ErrTokenGeneration, err)
	}

	return tokenString, expirationTime, nil
}

// GenerateRefreshToken creates a new refresh
func (jm *JWTManager) GenerateRefreshToken(userID string, opts ...Options) (string, time.Time, error) {
	expirationTime := time.Now().Add(jm.refreshExpiry)

	options := &options{}
	for _, opt := range opts {
		opt(options)
	}

	var err error
	claims := &CustomClaims{
		UserID:    userID,
		TokenType: RefreshToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    jm.issuer,
			Subject:   userID,
		},
	}

	if options.tokenVersion != nil {
		claims.TokenVersion = *options.tokenVersion
	}

	if err := claims.Validate(); err != nil {
		return "", time.Time{}, fmt.Errorf("%w: %v", ErrInvalidClaims, err)
	}

	token := jwt.NewWithClaims(jm.signingMethod, claims)
	tokenString, err := token.SignedString(jm.signingKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("%w: %v", ErrTokenGeneration, err)
	}

	return tokenString, expirationTime, nil
}

// GenerateTokenPair generates both access and refresh tokens
func (jm *JWTManager) GenerateTokenPair(userID string, opts ...Options) (*TokenPair, error) {

	accessToken, accessExpiry, err := jm.GenerateAccessToken(userID, opts...)
	if err != nil {
		return nil, err
	}

	refreshToken, _, err := jm.GenerateRefreshToken(userID)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessExpiry: accessExpiry,
		TokenType:    "Bearer",
	}, nil
}

// GetTokenHash creates a hash of the token for storage
func (jm *JWTManager) GetTokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (jm *JWTManager) RefreshToken(refreshToken string) (*TokenPair, error) {
	// Parse and validate the refresh token
	claims, err := jm.ValidateToken(refreshToken, RefreshToken)
	if err != nil {
		return nil, err
	}
	// Generate new token pair
	return jm.GenerateTokenPair(claims.UserID)
}
