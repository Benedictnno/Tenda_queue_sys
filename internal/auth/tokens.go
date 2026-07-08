// Package auth — tokens.go
//
// All JWT generation and validation lives here.  Nothing else in the codebase
// should import golang-jwt directly; go through these helpers.
//
// Access token claims shape (as consumed by the Python FastAPI service):
//
//	{
//	  "sub":        "uuid-of-user",
//	  "identifier": "CSC/2023/045",
//	  "role":       "student",
//	  "department": "Computer Science",
//	  "iat":        1719000000,
//	  "exp":        1719000900
//	}
//
// Do NOT change this shape without coordinating with the Python team.
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tennda/auth/internal/models"
)

// ─── Sentinel errors ─────────────────────────────────────────────────────────

// ErrTokenExpired is returned when a token is syntactically valid but past its
// expiry time.  Callers should map this to a TOKEN_EXPIRED API error.
var ErrTokenExpired = errors.New("token has expired")

// ErrTokenInvalid is returned for any other validation failure (bad signature,
// malformed, wrong algorithm, etc.).
var ErrTokenInvalid = errors.New("token is invalid")

// ─── Claims ──────────────────────────────────────────────────────────────────

// Claims is the JWT payload for Tennda access tokens.
// The shape is fixed — the Python FastAPI service depends on it exactly.
type Claims struct {
	Identifier string `json:"identifier"`
	Role       string `json:"role"`
	Department string `json:"department"`
	jwt.RegisteredClaims
}

// ─── Access token ────────────────────────────────────────────────────────────

// GenerateAccessToken creates a signed HS256 JWT for the given user.
// The token embeds: sub, identifier, role, department, iat, exp.
func GenerateAccessToken(user *models.User, secret string, expiry time.Duration) (string, error) {
	now := time.Now()

	claims := Claims{
		Identifier: user.Identifier,
		Role:       user.Role,
		Department: user.Department,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("tokens: sign access token: %w", err)
	}
	return signed, nil
}

// ─── Refresh token ───────────────────────────────────────────────────────────

// GenerateRefreshToken creates a signed HS256 JWT used as a refresh token.
// Only sub (userID) and expiry are embedded — refresh tokens carry no role
// claims so they cannot be misused as access tokens.
func GenerateRefreshToken(userID string, secret string, expiry time.Duration) (string, error) {
	now := time.Now()

	claims := jwt.RegisteredClaims{
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("tokens: sign refresh token: %w", err)
	}
	return signed, nil
}

// ─── Validation ──────────────────────────────────────────────────────────────

// ValidateAccessToken parses and validates an access token string.
// Returns the Claims on success, or one of ErrTokenExpired / ErrTokenInvalid.
func ValidateAccessToken(tokenString, secret string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		keyFunc(secret),
		// Enforce HS256 — reject tokens signed with any other algorithm.
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil {
		// Distinguish expired from other errors so the API can return the
		// correct error code (TOKEN_EXPIRED vs TOKEN_INVALID).
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrTokenInvalid
	}

	if !token.Valid {
		return nil, ErrTokenInvalid
	}

	return claims, nil
}

// ValidateRefreshTokenClaims parses a refresh token and returns only the
// subject (userID).  Used internally during the refresh flow.
func ValidateRefreshTokenClaims(tokenString, secret string) (string, error) {
	claims := &jwt.RegisteredClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		keyFunc(secret),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", ErrTokenExpired
		}
		return "", ErrTokenInvalid
	}

	if !token.Valid {
		return "", ErrTokenInvalid
	}

	return claims.Subject, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// HashToken returns the SHA256 hex digest of a raw token string.
// Refresh tokens are stored only as their hash — the raw value is never
// persisted to the database.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// keyFunc returns a jwt.Keyfunc that validates the signing method and provides
// the HMAC secret.
func keyFunc(secret string) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("tokens: unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	}
}
