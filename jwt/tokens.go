package jwt

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
func (jm *JWTManager) GenerateAccessToken(userID string) (string, time.Time, error) {
	expirationTime := time.Now().Add(jm.accessExpiry)

	var tv int64 = 0
	var err error

	if jm.redisClient != nil {
		key := "tv:" + userID

		tv, err = jm.redisClient.Incr(jm.ctx, key).Result()
		if err != nil {
			return "", time.Time{}, err
		}

		jm.redisClient.Expire(jm.ctx, key, jm.accessExpiry+time.Minute*2)
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
func (jm *JWTManager) GenerateRefreshToken(userID string) (string, time.Time, error) {
	expirationTime := time.Now().Add(jm.refreshExpiry)

	var rv int64 = 0
	var err error

	if jm.redisClient != nil {
		key := "rv:" + userID

		rv, err = jm.redisClient.Incr(jm.ctx, key).Result()
		if err != nil {
			return "", time.Time{}, err
		}

		jm.redisClient.Expire(jm.ctx, key, jm.refreshExpiry+time.Minute*2)
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

	if rv > 0 {
		claims.TokenVersion = rv
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

	if jm.redisClient != nil {
		accessKey := "tv:" + userID
		refreshKey := "rv:" + userID
		refreshCount, _ := jm.redisClient.Get(jm.ctx, refreshKey).Int64()

		if refreshCount > 500 {
			jm.redisClient.Del(jm.ctx, accessKey)
			jm.redisClient.Del(jm.ctx, refreshKey)
		}

	}

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

func (j *JWTManager) RefreshToken(refreshToken string) (*TokenPair, error) {
	// Parse and validate the refresh token
	claims, err := j.ValidateToken(refreshToken)
	if err != nil {
		return nil, err
	}

	// Ensure it's a refresh token
	if claims.TokenType != RefreshToken {
		return nil, errors.New("invalid token type for refresh")
	}

	// Generate new token pair
	return j.GenerateTokenPair(claims.UserID)
}
