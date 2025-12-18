package jwt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenIssuer interface {
	GenerateAccessToken(ctx context.Context, userID string) (string, time.Time, error)
	GenerateRefreshToken(ctx context.Context, userID string) (string, time.Time, error)
	GenerateTokenPair(ctx context.Context, userID string) (*TokenPair, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
}

// TokenManager handles token operations
type TokenValidator interface {
	ValidateToken(ctx context.Context, tokenString string) (*CustomClaims, error)
	ParseToken(tokenString string) (*jwt.Token, error)
	GetTokenHash(token string) string
}

// GenerateAccessToken creates a new access token
func (jm *JWTManager) GenerateAccessToken(ctx context.Context, userID string) (string, time.Time, error) {
	expirationTime := time.Now().Add(jm.accessExpiry)

	var tv int64
	var err error
	if jm.tokenStore != nil && jm.tokenStore.Client != nil {
		tv, err = jm.tokenStore.StoreTokenVersion(ctx, AccessToken, userID, jm.accessExpiry)
		if err != nil {
			return "", time.Time{}, err
		}
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

	if tv > 0 {
		claims.TokenVersion = tv
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
func (jm *JWTManager) GenerateRefreshToken(ctx context.Context, userID string) (string, time.Time, error) {
	expirationTime := time.Now().Add(jm.refreshExpiry)

	var tv int64
	var err error
	if jm.tokenStore != nil && jm.tokenStore.Client != nil {
		tv, err = jm.tokenStore.StoreTokenVersion(ctx, RefreshToken, userID, jm.refreshExpiry)
		if err != nil {
			return "", time.Time{}, err
		}
	}

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

	if tv > 0 {
		claims.TokenVersion = tv
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
func (jm *JWTManager) GenerateTokenPair(ctx context.Context, userID string) (*TokenPair, error) {

	if jm.tokenStore != nil && jm.tokenStore.Client != nil {
		accessKey := jm.tokenStore.AccessPrefix + userID
		refreshKey := jm.tokenStore.RefreshPrefix + userID
		refreshCount, _ := jm.tokenStore.Client.Get(ctx, refreshKey).Int64()

		if refreshCount > 500 {
			jm.tokenStore.Client.Del(ctx, accessKey)
			jm.tokenStore.Client.Del(ctx, refreshKey)
		}

	}

	accessToken, accessExpiry, err := jm.GenerateAccessToken(ctx, userID)
	if err != nil {
		return nil, err
	}

	refreshToken, _, err := jm.GenerateRefreshToken(ctx, userID)
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

func (jm *JWTManager) RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error) {
	// Parse and validate the refresh token
	claims, err := jm.ValidateToken(ctx, refreshToken, RefreshToken)
	if err != nil {
		return nil, err
	}
	// Generate new token pair
	return jm.GenerateTokenPair(ctx, claims.UserID)
}
