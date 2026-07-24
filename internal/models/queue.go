// Package models — queue.go
//
// Domain structs and constants for the queue system.
package models

import (
	"time"
)

// ─── Queue status constants ──────────────────────────────────────────────────

const (
	QueueStatusOpen   = "open"
	QueueStatusClosed = "closed"
	QueueStatusPaused = "paused"
)

// ─── Queue entry status constants ────────────────────────────────────────────

const (
	EntryStatusWaiting = "waiting"
	EntryStatusServing = "serving"
	EntryStatusServed  = "served"
	EntryStatusLeft    = "left"
)

// ─── Queue ───────────────────────────────────────────────────────────────────

// Queue represents a row in the `queues` table.
type Queue struct {
	ID          string    `db:"id"           json:"id"`
	Title       string    `db:"title"        json:"title"`
	Description string    `db:"description"  json:"description,omitempty"`
	OwnerID     string    `db:"owner_id"     json:"owner_id"`
	Department  string    `db:"department"   json:"department,omitempty"`
	Location    string    `db:"location"     json:"location,omitempty"`
	MaxSize     int       `db:"max_size"     json:"max_size"`      // daily capacity; 0 = unlimited
	MaxRejoins  int       `db:"max_rejoins"  json:"max_rejoins"`   // max rejoins per user per day
	Status      string    `db:"status"       json:"status"`
	CreatedAt   time.Time `db:"created_at"   json:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"   json:"updated_at"`
}

// IsOpen returns true when the queue is accepting new entries.
func (q *Queue) IsOpen() bool {
	return q.Status == QueueStatusOpen
}

// ─── QueueEntry ──────────────────────────────────────────────────────────────

// QueueEntry represents a row in the `queue_entries` table.
type QueueEntry struct {
	ID       string     `db:"id"        json:"id"`
	QueueID  string     `db:"queue_id"  json:"queue_id"`
	UserID   string     `db:"user_id"   json:"user_id"`
	Position int        `db:"position"  json:"position"`
	Status   string     `db:"status"    json:"status"`
	JoinedAt time.Time  `db:"joined_at" json:"joined_at"`
	ServedAt *time.Time `db:"served_at" json:"served_at,omitempty"`
}

// IsActive returns true when the entry is either waiting or currently being served.
func (e *QueueEntry) IsActive() bool {
	return e.Status == EntryStatusWaiting || e.Status == EntryStatusServing
}
