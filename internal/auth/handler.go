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

// ─── Swagger Documentation Wrappers ───────────────────────────────────────────

type docsLoginResponse struct {
	Success bool          `json:"success" example:"true"`
	Data    LoginResponse `json:"data"`
}

type docsRefreshResponse struct {
	Success bool            `json:"success" example:"true"`
	Data    RefreshResponse `json:"data"`
}

type docsLogoutResponse struct {
	Success bool `json:"success" example:"true"`
	Data    struct {
		Message string `json:"message" example:"Logged out successfully"`
	} `json:"data"`
}

type docsVerifyResponse struct {
	Success bool           `json:"success" example:"true"`
	Data    VerifyResponse `json:"data"`
}

type docsVerifyDeviceResponse struct {
	Success bool                 `json:"success" example:"true"`
	Data    DeviceVerifyResponse `json:"data"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required" example:"eyJhbG..."`
}

type VerifyRequest struct {
	Token string `json:"token" binding:"required" example:"eyJhbG..."`
}

type VerifyDeviceRequest struct {
	DeviceID  string `json:"device_id"  binding:"required" example:"SCANNER-01"`
	DeviceKey string `json:"device_key" binding:"required" example:"raw-key-here"`
}

// ─── POST /api/v1/auth/login ──────────────────────────────────────────────────

// HandleLogin authenticates a user and returns access + refresh tokens.
//
// @Summary Login a user
// @Description Authenticates a user using identifier and password, returning access and refresh tokens.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} docsLoginResponse
// @Failure 400 {object} response.ErrorBody
// @Failure 401 {object} response.ErrorBody
// @Failure 403 {object} response.ErrorBody
// @Router /auth/login [post]
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
//
// @Summary Refresh access token
// @Description Exchanges a valid refresh token for a new access token.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RefreshRequest true "Refresh Token"
// @Success 200 {object} docsRefreshResponse
// @Failure 400 {object} response.ErrorBody
// @Failure 401 {object} response.ErrorBody
// @Failure 403 {object} response.ErrorBody
// @Router /auth/refresh [post]
func (h *Handler) HandleRefresh(c *gin.Context) {
	var body RefreshRequest
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
//
// @Summary Logout user
// @Description Revokes all refresh tokens for the authenticated user. Requires Bearer token.
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} docsLogoutResponse
// @Failure 401 {object} response.ErrorBody
// @Failure 500 {object} response.ErrorBody
// @Router /auth/logout [post]
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
//
// @Summary Verify access token (Internal)
// @Description Validates an access token and returns the embedded user claims. For internal service use only.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body VerifyRequest true "Access Token"
// @Success 200 {object} docsVerifyResponse
// @Failure 400 {object} response.ErrorBody
// @Failure 401 {object} response.ErrorBody
// @Router /auth/verify [post]
func (h *Handler) HandleVerify(c *gin.Context) {
	var body VerifyRequest
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
//
// @Summary Verify hardware scanner (Internal)
// @Description Authenticates a hardware QR scanner by its device ID and key. For internal network use only.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body VerifyDeviceRequest true "Device Credentials"
// @Success 200 {object} docsVerifyDeviceResponse
// @Failure 400 {object} response.ErrorBody
// @Failure 401 {object} response.ErrorBody
// @Failure 403 {object} response.ErrorBody
// @Router /auth/verify-device [post]
func (h *Handler) HandleVerifyDevice(c *gin.Context) {
	var body VerifyDeviceRequest
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
