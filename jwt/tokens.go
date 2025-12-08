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
}

// TokenManager handles token operations
type TokenValidator interface {
	ValidateToken(tokenString string) (*CustomClaims, error)
	ParseToken(tokenString string) (*jwt.Token, error)
	GetTokenHash(token string) string
}

// GenerateAccessToken creates a new access token
func (jm *JWTManager) GenerateAccessToken(userID string) (string, time.Time, error) {
	expirationTime := time.Now().Add(jm.accessExpiry)

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

// GenerateRefreshToken creates a new refresh token
func (jm *JWTManager) GenerateRefreshToken(userID string) (string, time.Time, error) {
	expirationTime := time.Now().Add(jm.refreshExpiry)

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
func (jm *JWTManager) GenerateTokenPair(userID string) (*TokenPair, error) {
	accessToken, accessExpiry, err := jm.GenerateAccessToken(userID)
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
