// Package database manages the PostgreSQL connection pool for the Tennda
// auth service.  All DB access goes through the single pool returned by
// Connect() — never open per-request connections.
package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Connect opens a pgxpool connection pool using the provided DATABASE_URL and
// returns it.  The caller is responsible for calling pool.Close() on shutdown.
func Connect(databaseURL string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("database: parse config: %w", err)
	}

	// Conservative pool settings — tune for your deployment.
	cfg.MaxConns = 25
	cfg.MinConns = 5
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("database: open pool: %w", err)
	}

	// Verify connectivity before the server starts accepting requests.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("database: ping failed: %w", err)
	}

	log.Println("database: connected to PostgreSQL")
	return pool, nil
}

// MigrationSQL contains the DDL to create the tables required by the
// Tennda service.  Run this once against your database before starting the
// service.  In production, use a proper migration tool (goose, atlas, etc.)
// instead of executing this directly.
const MigrationSQL = `
-- Enable the pgcrypto extension for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier    VARCHAR(50)  UNIQUE NOT NULL,   -- matric_no or staff_id
    password_hash VARCHAR(255) NOT NULL,
    full_name     VARCHAR(100) NOT NULL,
    role          VARCHAR(20)  NOT NULL,           -- student | staff | lecturer | admin
    department    VARCHAR(100),
    status        VARCHAR(20)  DEFAULT 'active',   -- active | suspended
    created_at    TIMESTAMP    DEFAULT NOW(),
    updated_at    TIMESTAMP    DEFAULT NOW()
);

-- ─── refresh_tokens ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(255) UNIQUE NOT NULL,
    device_info VARCHAR(255),
    expires_at  TIMESTAMP NOT NULL,
    created_at  TIMESTAMP DEFAULT NOW(),
    revoked     BOOLEAN   DEFAULT FALSE
);

-- ─── device_keys ─────────────────────────────────────────────────────────────
-- NOTE: This table is for hardware QR scanners only.
-- The /auth/verify-device endpoint MUST be on an internal network in production
-- and MUST NOT be exposed to the public internet.
CREATE TABLE IF NOT EXISTS device_keys (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(100) UNIQUE NOT NULL,   -- e.g. SCANNER-LT1-01
    key_hash  VARCHAR(255) NOT NULL,
    location  VARCHAR(100),
    status    VARCHAR(20)  DEFAULT 'active',  -- active | revoked
    created_at TIMESTAMP   DEFAULT NOW()
);

-- ─── queues ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS queues (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title         VARCHAR(150) NOT NULL,
    description   TEXT,
    owner_id      UUID REFERENCES users(id) ON DELETE CASCADE,
    department    VARCHAR(100),
    location      VARCHAR(150),
    max_size      INT DEFAULT 0,               -- daily capacity (0 = unlimited)
    max_rejoins   INT DEFAULT 3,               -- max times a user can rejoin this queue per day
    status        VARCHAR(20) DEFAULT 'open',  -- open | closed | paused
    created_at    TIMESTAMP DEFAULT NOW(),
    updated_at    TIMESTAMP DEFAULT NOW()
);

-- ─── queue_entries ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS queue_entries (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    queue_id    UUID REFERENCES queues(id) ON DELETE CASCADE,
    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
    position    INT NOT NULL,
    status      VARCHAR(20) DEFAULT 'waiting',  -- waiting | serving | served | left
    joined_at   TIMESTAMP DEFAULT NOW(),
    served_at   TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_queue_entries_queue_status
    ON queue_entries(queue_id, status, position);
CREATE INDEX IF NOT EXISTS idx_queue_entries_queue_user
    ON queue_entries(queue_id, user_id);
`
