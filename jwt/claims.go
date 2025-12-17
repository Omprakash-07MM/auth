// pkg/jwt/claims.go
package jwt

import (
	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims contains custom JWT claims
type CustomClaims struct {
	UserID       string    `json:"user_id"`
	TokenType    TokenType `json:"token_type"`
	TokenVersion int64     `json:"token_version,omitempty"`
	jwt.RegisteredClaims
}

// Validate validates the claims
func (c *CustomClaims) Validate() error {

	if c.UserID == "" {
		return ErrInvalidUserID
	}
	if c.TokenType == "" {
		return ErrInvalidTokenType
	}
	return nil
}
