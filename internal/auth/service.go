// Package auth — service.go
//
// Business logic layer.  Handlers call the Service; the Service calls the
// Repository.  No SQL here, no HTTP concepts — pure domain logic.
package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/tennda/auth/config"
	"github.com/tennda/auth/internal/models"
)

// ─── Request / Response DTOs ─────────────────────────────────────────────────

// RegisterRequest is the decoded body of POST /auth/register and POST /auth/admin/register.
type RegisterRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password"   binding:"required,min=6"`
	FullName   string `json:"full_name"  binding:"required"`
	Role       string `json:"role"`
	Department string `json:"department"`
}

// LoginRequest is the decoded body of POST /auth/login.
type LoginRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password"   binding:"required"`
	Role       string `json:"role"       binding:"required"`
	DeviceInfo string `json:"device_info"`
}

// LoginResponse is returned on a successful login.
type LoginResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int      `json:"expires_in"` // seconds
	User         UserInfo `json:"user"`
}

// RefreshResponse is returned when a refresh token is exchanged for a new
// access token.
type RefreshResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// VerifyResponse is returned by /auth/verify for the Python FastAPI service.
type VerifyResponse struct {
	Valid bool     `json:"valid"`
	User UserInfo `json:"user"`
}

// DeviceVerifyResponse is returned by /auth/verify-device.
type DeviceVerifyResponse struct {
	Valid    bool   `json:"valid"`
	DeviceID string `json:"device_id"`
	Location string `json:"location"`
}

// UserInfo is the public user representation embedded in responses.
type UserInfo struct {
	ID         string `json:"id"`
	Identifier string `json:"identifier"`
	FullName   string `json:"full_name,omitempty"`
	Role       string `json:"role"`
	Department string `json:"department"`
}

// ─── Service errors ──────────────────────────────────────────────────────────

// ServiceError carries an HTTP status code alongside a machine code and message.
// Handlers convert these directly into API error responses.
type ServiceError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *ServiceError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func serviceErr(statusCode int, code, message string) *ServiceError {
	return &ServiceError{StatusCode: statusCode, Code: code, Message: message}
}

// ─── Service ─────────────────────────────────────────────────────────────────

// Service implements the auth business logic.
type Service struct {
	repo *Repository
	cfg  *config.Config
}

// NewService creates an auth Service with the given repository and config.
func NewService(repo *Repository, cfg *config.Config) *Service {
	return &Service{repo: repo, cfg: cfg}
}

// Login authenticates a user and returns access + refresh tokens.
//
// Flow:
//  1. Look up user by identifier.
//  2. Check account is active (not suspended).
//  3. Verify bcrypt password hash.
//  4. Generate access token (short-lived) and refresh token (long-lived).
//  5. Hash refresh token with SHA256 and persist to DB.
//  6. Return both tokens to the caller.
func (s *Service) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	// 1. Look up user.
	user, err := s.repo.GetUserByIdentifier(ctx, req.Identifier)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, serviceErr(http.StatusUnauthorized, "INVALID_CREDENTIALS",
				"Identifier or password is incorrect")
		}
		return nil, fmt.Errorf("service: Login: %w", err)
	}

	// 2. Check account status.
	if !user.IsActive() {
		return nil, serviceErr(http.StatusForbidden, "ACCOUNT_SUSPENDED",
			"This account has been suspended")
	}

	// 3. Verify password.
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, serviceErr(http.StatusUnauthorized, "INVALID_CREDENTIALS",
			"Identifier or password is incorrect")
	}

	// 4a. Generate access token.
	accessToken, err := GenerateAccessToken(user, s.cfg.JWTSecret, s.cfg.JWTAccessExpiry)
	if err != nil {
		return nil, fmt.Errorf("service: Login: generate access token: %w", err)
	}

	// 4b. Generate refresh token.
	refreshToken, err := GenerateRefreshToken(user.ID, s.cfg.JWTSecret, s.cfg.JWTRefreshExpiry)
	if err != nil {
		return nil, fmt.Errorf("service: Login: generate refresh token: %w", err)
	}

	// 5. Store hashed refresh token.
	tokenHash := HashToken(refreshToken)
	expiresAt := time.Now().Add(s.cfg.JWTRefreshExpiry)

	if err := s.repo.CreateRefreshToken(ctx, user.ID, tokenHash, req.DeviceInfo, expiresAt); err != nil {
		return nil, fmt.Errorf("service: Login: store refresh token: %w", err)
	}

	// 6. Build response.
	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(s.cfg.JWTAccessExpiry.Seconds()),
		User: UserInfo{
			ID:         user.ID,
			Identifier: user.Identifier,
			FullName:   user.FullName,
			Role:       user.Role,
			Department: user.Department,
		},
	}, nil
}

// Refresh exchanges a valid refresh token for a new access token.
//
// Flow:
//  1. Hash the incoming refresh token and look it up in the DB.
//  2. Check it is not revoked and not expired.
//  3. Load the user record.
//  4. Generate a new access token.
//  5. Return it — the refresh token stays unchanged.
func (s *Service) Refresh(ctx context.Context, rawRefreshToken string) (*RefreshResponse, error) {
	// 1. Hash and look up.
	tokenHash := HashToken(rawRefreshToken)
	rt, err := s.repo.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, serviceErr(http.StatusUnauthorized, "TOKEN_INVALID",
				"Refresh token is invalid")
		}
		return nil, fmt.Errorf("service: Refresh: %w", err)
	}

	// 2. Validate.
	if !rt.IsValid() {
		return nil, serviceErr(http.StatusUnauthorized, "TOKEN_INVALID",
			"Refresh token has expired or been revoked")
	}

	// 3. Load user.
	user, err := s.repo.GetUserByID(ctx, rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("service: Refresh: load user: %w", err)
	}

	if !user.IsActive() {
		return nil, serviceErr(http.StatusForbidden, "ACCOUNT_SUSPENDED",
			"This account has been suspended")
	}

	// 4. New access token.
	accessToken, err := GenerateAccessToken(user, s.cfg.JWTSecret, s.cfg.JWTAccessExpiry)
	if err != nil {
		return nil, fmt.Errorf("service: Refresh: generate access token: %w", err)
	}

	return &RefreshResponse{
		AccessToken: accessToken,
		ExpiresIn:   int(s.cfg.JWTAccessExpiry.Seconds()),
	}, nil
}

// Logout revokes all refresh tokens for the authenticated user.
func (s *Service) Logout(ctx context.Context, userID string) error {
	if err := s.repo.RevokeUserTokens(ctx, userID); err != nil {
		return fmt.Errorf("service: Logout: %w", err)
	}
	return nil
}

// VerifyToken validates an access token string without touching the database.
// This is the hot path called by the Python FastAPI service — keep it fast.
//
// SECURITY NOTE: /auth/verify must be deployed on an internal network only.
// It must NOT be reachable from the public internet.
func (s *Service) VerifyToken(tokenString string) (*VerifyResponse, error) {
	claims, err := ValidateAccessToken(tokenString, s.cfg.JWTSecret)
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			return nil, serviceErr(http.StatusUnauthorized, "TOKEN_EXPIRED",
				"Token has expired")
		}
		return nil, serviceErr(http.StatusUnauthorized, "TOKEN_INVALID",
			"Token is invalid or expired")
	}

	return &VerifyResponse{
		Valid: true,
		User: UserInfo{
			ID:         claims.Subject,
			Identifier: claims.Identifier,
			Role:       claims.Role,
			Department: claims.Department,
		},
	}, nil
}

// VerifyDevice authenticates a hardware scanner by checking its device key.
//
// Flow:
//  1. Look up device_id in device_keys table.
//  2. SHA256-hash the incoming raw key and compare to stored hash.
//  3. Confirm device status is active.
//
// SECURITY NOTE: /auth/verify-device must be deployed on an internal network.
// It must NOT be reachable from the public internet.
func (s *Service) VerifyDevice(ctx context.Context, deviceID, rawKey string) (*DeviceVerifyResponse, error) {
	dk, err := s.repo.GetDeviceKey(ctx, deviceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, serviceErr(http.StatusUnauthorized, "DEVICE_INVALID",
				"Device not found or key is incorrect")
		}
		return nil, fmt.Errorf("service: VerifyDevice: %w", err)
	}

	// Compare hashes — never compare raw keys.
	if HashToken(rawKey) != dk.KeyHash {
		return nil, serviceErr(http.StatusUnauthorized, "DEVICE_INVALID",
			"Device not found or key is incorrect")
	}

	if !dk.IsActive() {
		return nil, serviceErr(http.StatusForbidden, "DEVICE_REVOKED",
			"This device has been revoked")
	}

	return &DeviceVerifyResponse{
		Valid:    true,
		DeviceID: dk.DeviceID,
		Location: dk.Location,
	}, nil
}

// Register creates a new user record.
//
// If isPublic is true (POST /auth/register):
// - Default role is "user" if not specified.
// - Self-registration as "admin" or "super_admin" is forbidden.
//
// If isPublic is false (POST /auth/admin/register):
// - Default role is "user" if not specified.
// - super_admin caller can create any valid role.
// - admin caller can create user, student, staff, lecturer (cannot create admin or super_admin).
func (s *Service) Register(ctx context.Context, req RegisterRequest, callerRole string, isPublic bool) (*UserInfo, error) {
	targetRole := req.Role
	if targetRole == "" {
		targetRole = models.RoleUser
	}

	// 1. Validate role is known.
	if !models.ValidRoles[targetRole] {
		return nil, serviceErr(http.StatusBadRequest, "INVALID_ROLE",
			fmt.Sprintf("Role '%s' is invalid", targetRole))
	}

	// 2. Permission checks.
	if isPublic {
		if targetRole == models.RoleAdmin || targetRole == models.RoleSuperAdmin {
			return nil, serviceErr(http.StatusForbidden, "FORBIDDEN_ROLE",
				"Cannot self-register with administrative privileges")
		}
	} else {
		switch callerRole {
		case models.RoleSuperAdmin:
			// Super admin can assign any valid role.
		case models.RoleAdmin:
			if targetRole == models.RoleSuperAdmin || targetRole == models.RoleAdmin {
				return nil, serviceErr(http.StatusForbidden, "FORBIDDEN_ROLE",
					"Admins cannot assign admin or super_admin roles")
			}
		default:
			return nil, serviceErr(http.StatusForbidden, "FORBIDDEN",
				"Insufficient permissions to register users")
		}
	}

	// 3. Hash password.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("service: Register: hash password: %w", err)
	}

	// 4. Generate user ID.
	userID, err := generateUUID()
	if err != nil {
		return nil, fmt.Errorf("service: Register: generate uuid: %w", err)
	}

	now := time.Now()
	user := &models.User{
		ID:           userID,
		Identifier:   req.Identifier,
		PasswordHash: string(hashedPassword),
		FullName:     req.FullName,
		Role:         targetRole,
		Department:   req.Department,
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// 5. Persist to DB.
	if err := s.repo.CreateUser(ctx, user); err != nil {
		if errors.Is(err, ErrUserExists) {
			return nil, serviceErr(http.StatusConflict, "USER_EXISTS",
				"A user with this identifier already exists")
		}
		return nil, fmt.Errorf("service: Register: %w", err)
	}

	return &UserInfo{
		ID:         user.ID,
		Identifier: user.Identifier,
		FullName:   user.FullName,
		Role:       user.Role,
		Department: user.Department,
	}, nil
}

// generateUUID returns a cryptographically secure RFC 4122 v4 UUID string.
func generateUUID() (string, error) {
	var uuid [16]byte
	_, err := rand.Read(uuid[:])
	if err != nil {
		return "", err
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}


