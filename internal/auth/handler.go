// Package auth — handler.go
//
// HTTP handlers for all auth endpoints.  Handlers are thin: decode request →
// call service → map service error to HTTP response.  No business logic here.
package auth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tennda/auth/pkg/response"
)

// contextKeyUserID is the key used to store the authenticated user's ID in the
// Gin context after JWT middleware validation.
const contextKeyUserID = "userID"

// contextKeyClaims is the key used to store the full JWT claims.
const contextKeyClaims = "claims"

// Handler holds a reference to the auth service and exposes HTTP handler funcs.
type Handler struct {
	svc *Service
}

// NewHandler creates a Handler backed by the given Service.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// ─── POST /api/v1/auth/login ──────────────────────────────────────────────────

// HandleLogin authenticates a user and returns access + refresh tokens.
//
// Rate limited to 5 requests per IP per minute (enforced at router level).
func (h *Handler) HandleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	resp, err := h.svc.Login(c.Request.Context(), req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, resp)
}

// ─── POST /api/v1/auth/refresh ────────────────────────────────────────────────

// HandleRefresh exchanges a valid refresh token for a new access token.
func (h *Handler) HandleRefresh(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Error(c, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	resp, err := h.svc.Refresh(c.Request.Context(), body.RefreshToken)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, resp)
}

// ─── POST /api/v1/auth/logout ─────────────────────────────────────────────────

// HandleLogout revokes all refresh tokens for the authenticated user.
// Requires a valid JWT in the Authorization header (enforced by JWTMiddleware).
func (h *Handler) HandleLogout(c *gin.Context) {
	// userID is placed into context by JWTMiddleware.
	userID, ok := c.Get(contextKeyUserID)
	if !ok {
		response.Error(c, http.StatusUnauthorized, "TOKEN_MISSING",
			"Authorization token is required")
		return
	}

	if err := h.svc.Logout(c.Request.Context(), userID.(string)); err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// ─── POST /api/v1/auth/verify ─────────────────────────────────────────────────

// HandleVerify validates an access token and returns the embedded user claims.
//
// This endpoint is called by the Python FastAPI attendance service — it must
// remain fast (no DB hit) and must be deployed on an INTERNAL network only.
// Do NOT expose this endpoint to the public internet.
//
// No rate limiting is applied here by design — the Python service calls this
// on every inbound request and must not be throttled.
func (h *Handler) HandleVerify(c *gin.Context) {
	var body struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Error(c, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	resp, err := h.svc.VerifyToken(body.Token)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, resp)
}

// ─── POST /api/v1/auth/verify-device ─────────────────────────────────────────

// HandleVerifyDevice authenticates a hardware QR scanner by its device key.
//
// This endpoint must be deployed on an INTERNAL network only.
// Do NOT expose it to the public internet.
func (h *Handler) HandleVerifyDevice(c *gin.Context) {
	var body struct {
		DeviceID  string `json:"device_id"  binding:"required"`
		DeviceKey string `json:"device_key" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		response.Error(c, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	resp, err := h.svc.VerifyDevice(c.Request.Context(), body.DeviceID, body.DeviceKey)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, resp)
}

// ─── Error mapping ────────────────────────────────────────────────────────────

// handleServiceError converts a ServiceError into the appropriate HTTP response.
// Unknown errors are treated as internal server errors.
func handleServiceError(c *gin.Context, err error) {
	var svcErr *ServiceError
	if errors.As(err, &svcErr) {
		response.Error(c, svcErr.StatusCode, svcErr.Code, svcErr.Message)
		return
	}
	// Unexpected internal error — do not expose details.
	response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR",
		"An unexpected error occurred")
}
