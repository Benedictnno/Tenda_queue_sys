// Package auth — repository.go
//
// Pure database access layer.  No business logic lives here — only raw SQL
// queries wrapped in typed Go functions.  All queries use the pgxpool.Pool
// acquired at startup.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tennda/auth/internal/models"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("record not found")

// ErrUserExists is returned when a user with the same identifier already exists.
var ErrUserExists = errors.New("user already exists")

// Repository handles all database interactions for the auth domain.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository creates a Repository backed by the given connection pool.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// CreateUser inserts a new user record into the database.
func (r *Repository) CreateUser(ctx context.Context, u *models.User) error {
	const q = `
		INSERT INTO users (id, identifier, password_hash, full_name, role, department, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.Exec(ctx, q,
		u.ID, u.Identifier, u.PasswordHash, u.FullName,
		u.Role, u.Department, u.Status, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrUserExists
		}
		return fmt.Errorf("repository: CreateUser: %w", err)
	}

	return nil
}

// ─── User queries ─────────────────────────────────────────────────────────────

// GetUserByIdentifier fetches a user row by their matric number or staff ID.
// Returns ErrNotFound when no matching row exists.
func (r *Repository) GetUserByIdentifier(ctx context.Context, identifier string) (*models.User, error) {
	const q = `
		SELECT id, identifier, password_hash, full_name, role, department, status,
		       created_at, updated_at
		FROM   users
		WHERE  identifier = $1
		LIMIT  1
	`

	row := r.db.QueryRow(ctx, q, identifier)
	u := &models.User{}

	err := row.Scan(
		&u.ID, &u.Identifier, &u.PasswordHash, &u.FullName,
		&u.Role, &u.Department, &u.Status, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repository: GetUserByIdentifier: %w", err)
	}

	return u, nil
}

// GetUserByID fetches a user by their UUID primary key.
// Returns ErrNotFound when no matching row exists.
func (r *Repository) GetUserByID(ctx context.Context, userID string) (*models.User, error) {
	const q = `
		SELECT id, identifier, password_hash, full_name, role, department, status,
		       created_at, updated_at
		FROM   users
		WHERE  id = $1
		LIMIT  1
	`

	row := r.db.QueryRow(ctx, q, userID)
	u := &models.User{}

	err := row.Scan(
		&u.ID, &u.Identifier, &u.PasswordHash, &u.FullName,
		&u.Role, &u.Department, &u.Status, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repository: GetUserByID: %w", err)
	}

	return u, nil
}

// ─── Refresh token queries ────────────────────────────────────────────────────

// CreateRefreshToken inserts a new refresh token record.
// tokenHash must be the SHA256 digest of the raw token — never the raw value.
func (r *Repository) CreateRefreshToken(
	ctx context.Context,
	userID, tokenHash, deviceInfo string,
	expiresAt time.Time,
) error {
	const q = `
		INSERT INTO refresh_tokens (user_id, token_hash, device_info, expires_at)
		VALUES ($1, $2, $3, $4)
	`

	_, err := r.db.Exec(ctx, q, userID, tokenHash, deviceInfo, expiresAt)
	if err != nil {
		return fmt.Errorf("repository: CreateRefreshToken: %w", err)
	}
	return nil
}

// GetRefreshToken fetches a refresh token record by its hash.
// Returns ErrNotFound when no matching row exists.
func (r *Repository) GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	const q = `
		SELECT id, user_id, token_hash, device_info, expires_at, created_at, revoked
		FROM   refresh_tokens
		WHERE  token_hash = $1
		LIMIT  1
	`

	row := r.db.QueryRow(ctx, q, tokenHash)
	rt := &models.RefreshToken{}

	err := row.Scan(
		&rt.ID, &rt.UserID, &rt.TokenHash, &rt.DeviceInfo,
		&rt.ExpiresAt, &rt.CreatedAt, &rt.Revoked,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repository: GetRefreshToken: %w", err)
	}

	return rt, nil
}

// RevokeUserTokens sets revoked=true for every active refresh token belonging
// to the given user.  Called during logout.
func (r *Repository) RevokeUserTokens(ctx context.Context, userID string) error {
	const q = `
		UPDATE refresh_tokens
		SET    revoked = TRUE
		WHERE  user_id = $1
		  AND  revoked = FALSE
	`

	_, err := r.db.Exec(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("repository: RevokeUserTokens: %w", err)
	}
	return nil
}

// ─── Device key queries ───────────────────────────────────────────────────────

// GetDeviceKey fetches a device_keys row by its device_id string.
// Returns ErrNotFound when no matching row exists.
func (r *Repository) GetDeviceKey(ctx context.Context, deviceID string) (*models.DeviceKey, error) {
	const q = `
		SELECT id, device_id, key_hash, location, status, created_at
		FROM   device_keys
		WHERE  device_id = $1
		LIMIT  1
	`

	row := r.db.QueryRow(ctx, q, deviceID)
	dk := &models.DeviceKey{}

	err := row.Scan(
		&dk.ID, &dk.DeviceID, &dk.KeyHash, &dk.Location, &dk.Status, &dk.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repository: GetDeviceKey: %w", err)
	}

	return dk, nil
}
