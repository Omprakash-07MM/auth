package jwt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
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
	redisClient   *redis.Client
	ctx           context.Context
}

// NewJWTManager creates a new JWT manager with RSA keys

func NewJWTManager(config *Config, redisCli *redis.Client) (*JWTManager, error) {
	if config.Mode == ModeIssuer {
		return NewJWTIssuer(config, redisCli)
	} else {
		return NewJWTValidator(config, redisCli)
	}
}

// NewJWTIssuer creates a JWT manager that can issue tokens (Auth Service)
func NewJWTIssuer(config *Config, redisCli *redis.Client) (*JWTManager, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.KeyConfig == nil {
		return nil, fmt.Errorf("key config cannot be nil")
	}

	// Get signing method from algorithm
	signingMethod, err := getSigningMethod(config)
	if err != nil {
		return nil, err
	}

	// Resolve keys based on algorithm type
	signingKey, verifyingKey, err := resolveKeys(config.KeyConfig, signingMethod, config.Mode == ModeIssuer)
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

func NewJWTValidator(config *Config, redisCli *redis.Client) (*JWTManager, error) {
	// For validator, we only need verifying key

	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.KeyConfig == nil {
		return nil, fmt.Errorf("key config cannot be nil")
	}

	// Get signing method from algorithm
	signingMethod, err := getSigningMethod(config)
	if err != nil {
		return nil, err
	}

	// Resolve keys based on algorithm type
	_, verifyingKey, err := resolveKeys(config.KeyConfig, signingMethod, config.Mode == ModeIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve keys: %w", err)
	}

	return &JWTManager{
		mode:          ModeValidator,
		signingKey:    nil,
		verifyingKey:  verifyingKey,
		signingMethod: signingMethod,
		accessExpiry:  config.AccessExpiry,
		refreshExpiry: config.RefreshExpiry,
		issuer:        config.Issuer,
		redisClient:   redisCli,
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

		if claims.Issuer != jm.issuer {
			return nil, ErrInvalidIssuer
		}
		key := "tv" + claims.UserID

		currentTV, err := jm.redisClient.Get(jm.ctx, key).Int64()
		if err != nil {
			if err == redis.Nil {
				return nil, errors.New("invalid token: no session found")
			}

			return nil, err
		}

		if claims.TokenVersion != currentTV {
			return nil, errors.New("invalid token: token revoked")
		}

		return claims, nil
	}

	return nil, ErrInvalidToken
}

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

// resolveKeys resolves keys based on algorithm type
func resolveKeys(keyConfig *KeyConfig, method jwt.SigningMethod, needSigningKey bool) (signingKey, verifyingKey interface{}, err error) {
	// Determine algorithm type and route to appropriate resolver
	switch method.(type) {
	case *jwt.SigningMethodHMAC:
		return resolveHMACKey(keyConfig)
	default:
		return resolveAsymmetricKey(keyConfig, method, needSigningKey)
	}
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

// resolveHMACKey resolves HMAC key (symmetric)
func resolveHMACKey(keyConfig *KeyConfig) (signingKey, verifyingKey interface{}, err error) {
	var hmacKey []byte

	// Priority 1: Direct HMAC key
	if len(keyConfig.HMACKey) > 0 {
		hmacKey = keyConfig.HMACKey
	} else if keyConfig.HMACKeySource == KeySourceFile && keyConfig.HMACKeyPath != "" {
		data, err := os.ReadFile(keyConfig.HMACKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read HMAC key file: %w", err)
		}
		hmacKey = data
	} else if len(keyConfig.PrivateKeyData) > 0 {
		hmacKey = keyConfig.PrivateKeyData
	} else if len(keyConfig.PublicKeyData) > 0 {
		hmacKey = keyConfig.PublicKeyData
	}

	if len(hmacKey) == 0 {
		return nil, nil, fmt.Errorf("HMAC key not provided. Please provide HMACKey or HMACKeyPath")
	}

	// For HMAC, same key is used for signing and verification
	return hmacKey, hmacKey, nil
}

func resolveAsymmetricKey(keyConfig *KeyConfig, method jwt.SigningMethod, needSigningKey bool) (signingKey, verifyingKey interface{}, err error) {
	var signKey interface{}

	// Load private key if needed (for issuer mode)
	if needSigningKey {
		signKey, err = loadAsymmetricKey(
			keyConfig.PrivateKeySource,
			keyConfig.PrivateKeyPath,
			keyConfig.PrivateKeyData,
			true,
			method,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load private key: %w", err)
		}
	}

	// Load public key (always needed for verification)
	verifyKey, err := loadAsymmetricKey(
		keyConfig.PublicKeySource,
		keyConfig.PublicKeyPath,
		keyConfig.PublicKeyData,
		false,
		method,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load public key: %w", err)
	}

	return signKey, verifyKey, nil
}

func loadAsymmetricKey(source KeySource, path string, data []byte, isPrivate bool, method jwt.SigningMethod) (interface{}, error) {
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
		// Already PEM formatted
		keyStr := string(data)
		keyStr = strings.ReplaceAll(keyStr, "\\n", "\n")
		keyData = []byte(keyStr)
	case KeySourceRaw:
		// Convert raw key to PEM if needed
		keyData = data
	default:
		// If source is not specified but data exists, assume it's PEM
		if len(data) > 0 {
			keyData = data
		} else {
			return nil, fmt.Errorf("no key data provided")
		}
	}

	if len(keyData) == 0 {
		return nil, fmt.Errorf("no key data available")
	}

	// Parse based on algorithm type
	switch m := method.(type) {
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
	default:
		return nil, fmt.Errorf("unsupported signing method: %v", m.Alg())
	}
}
