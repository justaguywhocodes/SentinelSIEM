package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// AccessTokenExpiry is the lifetime of an access token.
	AccessTokenExpiry = 15 * time.Minute

	// RefreshTokenExpiry is the lifetime of a refresh token.
	RefreshTokenExpiry = 7 * 24 * time.Hour
)

// Claims are the JWT claims embedded in access tokens.
type Claims struct {
	jwt.RegisteredClaims
	UserID   string `json:"uid"`
	Username string `json:"usr"`
	Role     Role   `json:"role"`
}

// JWTManager handles JWT creation and validation.
type JWTManager struct {
	signingKey []byte
	issuer     string
}

// NewJWTManager creates a new JWTManager with the given HMAC-SHA256 signing key.
func NewJWTManager(signingKey []byte) *JWTManager {
	return &JWTManager{
		signingKey: signingKey,
		issuer:     "sentinel-siem",
	}
}

// GenerateAccessToken creates a signed JWT access token for the given user.
func (m *JWTManager) GenerateAccessToken(user *User) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(AccessTokenExpiry)),
		},
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.signingKey)
	if err != nil {
		return "", fmt.Errorf("signing access token: %w", err)
	}
	return signed, nil
}

// ValidateAccessToken parses and validates a JWT access token.
// Returns the claims if valid, or an error.
func (m *JWTManager) ValidateAccessToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.signingKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// GenerateRefreshToken creates a random refresh token string.
func GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating refresh token: %w", err)
	}
	return "rt_" + hex.EncodeToString(b), nil
}
