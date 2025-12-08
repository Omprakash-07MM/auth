package jwt

import (
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager manages JWT operations
type JWTManager struct {
	mode          SecurityMode
	signingKey    interface{} // Could be *rsa.PrivateKey, *ecdsa.PrivateKey, []byte for HMAC
	verifyingKey  interface{} // Could be *rsa.PublicKey, *ecdsa.PublicKey, []byte for HMAC
	signingMethod jwt.SigningMethod
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	issuer        string
}

// NewJWTManager creates a new JWT manager with RSA keys

func NewJWTManager(config *Config) (*JWTManager, error) {
	if config.Mode == ModeIssuer {
		return NewJWTIssuer(config)
	} else {
		return NewJWTValidator(config)
	}
}

// NewJWTIssuer creates a JWT manager that can issue tokens (Auth Service)
func NewJWTIssuer(config *Config) (*JWTManager, error) {
	// Resolve keys from config
	signingKey, verifyingKey, signingMethod, err := resolveKeys(config, true)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve keys: %w", err)
	}

	// Set default expiry if not provided
	accessExpiry := config.AccessExpiry
	if accessExpiry == 0 {
		accessExpiry = 15 * time.Minute
	}

	refreshExpiry := config.RefreshExpiry
	if refreshExpiry == 0 {
		refreshExpiry = 7 * 24 * time.Hour
	}

	return &JWTManager{
		mode:          ModeIssuer,
		signingKey:    signingKey,
		verifyingKey:  verifyingKey,
		signingMethod: signingMethod,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
		issuer:        config.Issuer,
	}, nil
}

func NewJWTValidator(config *Config) (*JWTManager, error) {
	// For validator, we only need verifying key
	_, verifyingKey, signingMethod, err := resolveKeys(config, false)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve verifying key: %w", err)
	}

	return &JWTManager{
		mode:          ModeValidator,
		signingKey:    nil,
		verifyingKey:  verifyingKey,
		signingMethod: signingMethod,
		accessExpiry:  config.AccessExpiry,
		refreshExpiry: config.RefreshExpiry,
		issuer:        config.Issuer,
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
// ParseToken parses a JWT token without validating custom claims
func (jm *JWTManager) ParseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, jm.keyFunc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	return token, nil
}

// keyFunc provides the key for token validation
func (jm *JWTManager) keyFunc(token *jwt.Token) (interface{}, error) {
	// Validate the algorithm matches
	expectedAlg := jm.signingMethod.Alg()
	if token.Header["alg"] != expectedAlg {
		return nil, fmt.Errorf("unexpected signing method: %v, expected: %s",
			token.Header["alg"], expectedAlg)
	}

	return jm.verifyingKey, nil
}

// GetAccessExpiry returns access token expiry duration
func (jm *JWTManager) GetAccessExpiry() time.Duration {
	return jm.accessExpiry
}

// GetRefreshExpiry returns refresh token expiry duration
func (jm *JWTManager) GetRefreshExpiry() time.Duration {
	return jm.refreshExpiry
}

// resolveKeys handles key loading from various sources
func resolveKeys(config *Config, needSigningKey bool) (signingKey, verifyingKey interface{}, method jwt.SigningMethod, err error) {
	// Determine algorithm and method
	method, err = getSigningMethod(config)
	if err != nil {
		return nil, nil, nil, err
	}

	// Use KeyConfig if provided
	if config.KeyConfig != nil {
		return resolveKeyConfig(config.KeyConfig, method, needSigningKey)
	}

	return nil, nil, nil, fmt.Errorf("no key configuration provided")
}

// getSigningMethod determines the JWT signing method from config
func getSigningMethod(config *Config) (jwt.SigningMethod, error) {
	var algorithm string

	// Check KeyConfig first
	if config.KeyConfig != nil && config.KeyConfig.SigningMethod != "" {
		algorithm = string(config.KeyConfig.SigningMethod)
	} else if config.Algorithm != "" {
		algorithm = config.Algorithm
	} else {
		// Default to RS256
		algorithm = string(RS256)
	}

	switch SigningMethod(algorithm) {
	case RS256:
		return jwt.SigningMethodRS256, nil
	case RS384:
		return jwt.SigningMethodRS384, nil
	case RS512:
		return jwt.SigningMethodRS512, nil
	case HS256:
		return jwt.SigningMethodHS256, nil
	case HS384:
		return jwt.SigningMethodHS384, nil
	case HS512:
		return jwt.SigningMethodHS512, nil
	case ES256:
		return jwt.SigningMethodES256, nil
	case ES384:
		return jwt.SigningMethodES384, nil
	case ES512:
		return jwt.SigningMethodES512, nil
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", algorithm)
	}
}

// resolveKeyConfig handles keys from KeyConfig structure
func resolveKeyConfig(keyConfig *KeyConfig, method jwt.SigningMethod, needSigningKey bool) (signingKey, verifyingKey interface{}, _ jwt.SigningMethod, err error) {
	// Load private key if needed
	if needSigningKey {
		signingKey, err = loadKey(keyConfig.PrivateKeySource, keyConfig.PrivateKeyPath, keyConfig.PrivateKeyData, true, method)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to load signing key: %w", err)
		}
	}

	// Load verifying key
	verifyingKey, err = loadKey(keyConfig.PublicKeySource, keyConfig.PublicKeyPath, keyConfig.PublicKeyData, false, method)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load verifying key: %w", err)
	}

	// For HMAC, use HMAC key if provided
	if _, ok := method.(*jwt.SigningMethodHMAC); ok {
		if len(keyConfig.HMACKey) > 0 {
			return keyConfig.HMACKey, keyConfig.HMACKey, method, nil
		}
		// If HMAC but no HMAC key, try to use private key data
		if keyConfig.PrivateKeyData != nil {
			return keyConfig.PrivateKeyData, keyConfig.PrivateKeyData, method, nil
		}
	}

	return signingKey, verifyingKey, method, nil
}

// loadKey loads a key from various sources
func loadKey(source KeySource, path string, data []byte, isPrivate bool, method jwt.SigningMethod) (interface{}, error) {
	var keyData []byte

	switch source {
	case KeySourceFile:
		if path == "" {
			return nil, fmt.Errorf("key path is required for file source")
		}
		var err error
		keyData, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %s: %w", path, err)
		}
	case KeySourcePEM:
		// Extract PEM data from byte array
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM data")
		}
		keyData = block.Bytes
	case KeySourceRaw:
		keyData = data
	default:
		return nil, fmt.Errorf("unsupported key source: %v", source)
	}

	// Parse key based on algorithm type
	switch method.(type) {
	case *jwt.SigningMethodRSA:
		if isPrivate {
			return jwt.ParseRSAPrivateKeyFromPEM(keyData)
		} else {
			return jwt.ParseRSAPublicKeyFromPEM(keyData)
		}
	case *jwt.SigningMethodECDSA:
		if isPrivate {
			return jwt.ParseECPrivateKeyFromPEM(keyData)
		} else {
			return jwt.ParseECPublicKeyFromPEM(keyData)
		}
	case *jwt.SigningMethodHMAC:
		return keyData, nil
	default:
		return nil, fmt.Errorf("unsupported signing method for key loading")
	}
}
