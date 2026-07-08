// Package auth — middleware.go
//
// Gin middleware for JWT authentication and role-based access control.
// Attach JWTMiddleware to any route that requires an authenticated user.
// Wrap specific routes with RoleGuard to restrict access by role.
package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tennda/auth/config"
	"github.com/tennda/auth/pkg/response"
)

// ─── JWT Middleware ───────────────────────────────────────────────────────────

// JWTMiddleware validates the Bearer token in the Authorization header and
// injects the parsed claims into the Gin context.
//
// Context keys set on success:
//   - "userID"  — the subject claim (UUID string)
//   - "claims"  — the full *Claims struct
//
// Error codes returned:
//   - TOKEN_MISSING  — no Authorization header present
//   - TOKEN_EXPIRED  — token signature is valid but the token has expired
//   - TOKEN_INVALID  — token is malformed or has an invalid signature
func JWTMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			response.Error(c, http.StatusUnauthorized, "TOKEN_MISSING",
				"Authorization header is required")
			return
		}

		// Expect "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			response.Error(c, http.StatusUnauthorized, "TOKEN_INVALID",
				"Authorization header format must be: Bearer <token>")
			return
		}

		rawToken := parts[1]
		claims, err := ValidateAccessToken(rawToken, cfg.JWTSecret)
		if err != nil {
			if errors.Is(err, ErrTokenExpired) {
				response.Error(c, http.StatusUnauthorized, "TOKEN_EXPIRED",
					"Token has expired — please refresh")
				return
			}
			response.Error(c, http.StatusUnauthorized, "TOKEN_INVALID",
				"Token is invalid or malformed")
			return
		}

		// Inject into context for downstream handlers and middleware.
		c.Set(contextKeyUserID, claims.Subject)
		c.Set(contextKeyClaims, claims)

		c.Next()
	}
}

// ─── Role Guard Middleware ────────────────────────────────────────────────────

// RoleGuard returns a Gin middleware that allows only the specified roles to
// proceed.  Must be used AFTER JWTMiddleware, which populates the claims.
//
// Usage:
//
//	router.POST("/sessions", auth.JWTMiddleware(cfg), auth.RoleGuard("lecturer", "admin"), handler.CreateSession)
//
// Returns 403 FORBIDDEN if the authenticated user's role is not in the allowed
// list.
func RoleGuard(allowedRoles ...string) gin.HandlerFunc {
	// Build a lookup set for O(1) role checks.
	allowed := make(map[string]bool, len(allowedRoles))
	for _, r := range allowedRoles {
		allowed[r] = true
	}

	return func(c *gin.Context) {
		raw, exists := c.Get(contextKeyClaims)
		if !exists {
			// JWTMiddleware must run before RoleGuard.
			response.Error(c, http.StatusUnauthorized, "TOKEN_MISSING",
				"Authorization token is required")
			return
		}

		claims, ok := raw.(*Claims)
		if !ok {
			response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR",
				"An unexpected error occurred")
			return
		}

		if !allowed[claims.Role] {
			response.Error(c, http.StatusForbidden, "FORBIDDEN",
				"You do not have permission to access this resource")
			return
		}

		c.Next()
	}
}
