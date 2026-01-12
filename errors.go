package jwt

import "errors"

var (
	ErrInvalidToken         = errors.New("invalid token")
	ErrExpiredToken         = errors.New("token has expired")
	ErrInvalidSigningMethod = errors.New("invalid signing method")
	ErrInvalidClaims        = errors.New("invalid claims")
	ErrTokenGeneration      = errors.New("failed to generate token")
	ErrInvalidUserID        = errors.New("invalid user ID")
	ErrInvalidTokenType     = errors.New("invalid token type")
	ErrKeyNotFound          = errors.New("key not found")
	ErrInvalidIssuer        = errors.New("invalid token issuer")
)
