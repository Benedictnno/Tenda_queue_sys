// Package models defines the core domain structs and constants shared across
// the Tennda auth service.
package models

import (
	"time"
)

// ─── Role constants ───────────────────────────────────────────────────────────

const (
	RoleStudent  = "student"
	RoleStaff    = "staff"
	RoleLecturer = "lecturer"
	RoleAdmin    = "admin"
)

// ValidRoles is the exhaustive set of allowed user roles.  Any value outside
// this set must be rejected at the API boundary.
var ValidRoles = map[string]bool{
	RoleStudent:  true,
	RoleStaff:    true,
	RoleLecturer: true,
	RoleAdmin:    true,
}

// ─── User ─────────────────────────────────────────────────────────────────────

// User represents a row in the `users` table.
type User struct {
	ID           string    `db:"id"            json:"id"`
	Identifier   string    `db:"identifier"    json:"identifier"` // matric_no or staff_id
	PasswordHash string    `db:"password_hash" json:"-"`          // never serialise
	FullName     string    `db:"full_name"     json:"full_name"`
	Role         string    `db:"role"          json:"role"`
	Department   string    `db:"department"    json:"department"`
	Status       string    `db:"status"        json:"status"`
	CreatedAt    time.Time `db:"created_at"    json:"created_at"`
	UpdatedAt    time.Time `db:"updated_at"    json:"updated_at"`
}

// IsActive returns true when the user account is not suspended.
func (u *User) IsActive() bool {
	return u.Status == "active"
}

// ─── RefreshToken ─────────────────────────────────────────────────────────────

// RefreshToken represents a row in the `refresh_tokens` table.
// The raw token is never stored — only its SHA256 hex digest (TokenHash).
type RefreshToken struct {
	ID         string    `db:"id"`
	UserID     string    `db:"user_id"`
	TokenHash  string    `db:"token_hash"`
	DeviceInfo string    `db:"device_info"`
	ExpiresAt  time.Time `db:"expires_at"`
	CreatedAt  time.Time `db:"created_at"`
	Revoked    bool      `db:"revoked"`
}

// IsValid returns true when the token is not revoked and has not expired.
func (rt *RefreshToken) IsValid() bool {
	return !rt.Revoked && time.Now().Before(rt.ExpiresAt)
}

// ─── DeviceKey ───────────────────────────────────────────────────────────────

// DeviceKey represents a row in the `device_keys` table.
// Used exclusively by hardware QR scanners — not user-facing.
type DeviceKey struct {
	ID        string    `db:"id"`
	DeviceID  string    `db:"device_id"`
	KeyHash   string    `db:"key_hash"`
	Location  string    `db:"location"`
	Status    string    `db:"status"`
	CreatedAt time.Time `db:"created_at"`
}

// IsActive returns true when the device has not been revoked.
func (dk *DeviceKey) IsActive() bool {
	return dk.Status == "active"
}
