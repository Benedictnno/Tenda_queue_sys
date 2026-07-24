// Package queue — repository.go
//
// Pure database access layer for the queue domain.  No business logic — only
// raw SQL queries wrapped in typed Go functions.
package queue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tennda/auth/internal/models"
)

// Sentinel errors for the queue domain.
var (
	ErrNotFound     = errors.New("record not found")
	ErrQueueFull    = errors.New("queue is at daily capacity")
	ErrAlreadyInQueue = errors.New("user already has an active entry in this queue")
)

// Repository handles all database interactions for the queue domain.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository creates a Repository backed by the given connection pool.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// ─── Queue queries ───────────────────────────────────────────────────────────

// CreateQueue inserts a new queue row.
func (r *Repository) CreateQueue(ctx context.Context, q *models.Queue) error {
	const query = `
		INSERT INTO queues (id, title, description, owner_id, department, location, max_size, max_rejoins, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := r.db.Exec(ctx, query,
		q.ID, q.Title, q.Description, q.OwnerID, q.Department,
		q.Location, q.MaxSize, q.MaxRejoins, q.Status, q.CreatedAt, q.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("repository: CreateQueue: %w", err)
	}
	return nil
}

// GetQueueByID fetches a queue by its UUID.
func (r *Repository) GetQueueByID(ctx context.Context, queueID string) (*models.Queue, error) {
	const query = `
		SELECT id, title, description, owner_id, department, location,
		       max_size, max_rejoins, status, created_at, updated_at
		FROM   queues
		WHERE  id = $1
		LIMIT  1
	`

	row := r.db.QueryRow(ctx, query, queueID)
	q := &models.Queue{}

	err := row.Scan(
		&q.ID, &q.Title, &q.Description, &q.OwnerID, &q.Department,
		&q.Location, &q.MaxSize, &q.MaxRejoins, &q.Status, &q.CreatedAt, &q.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repository: GetQueueByID: %w", err)
	}
	return q, nil
}

// ListQueues returns queues with optional status filter and pagination.
func (r *Repository) ListQueues(ctx context.Context, status string, limit, offset int) ([]*models.Queue, int, error) {
	var countQ, listQ string
	var args []any

	if status != "" {
		countQ = `SELECT COUNT(*) FROM queues WHERE status = $1`
		listQ = `
			SELECT id, title, description, owner_id, department, location,
			       max_size, max_rejoins, status, created_at, updated_at
			FROM   queues
			WHERE  status = $1
			ORDER BY created_at DESC
			LIMIT  $2 OFFSET $3
		`
		args = []any{status, limit, offset}
	} else {
		countQ = `SELECT COUNT(*) FROM queues`
		listQ = `
			SELECT id, title, description, owner_id, department, location,
			       max_size, max_rejoins, status, created_at, updated_at
			FROM   queues
			ORDER BY created_at DESC
			LIMIT  $1 OFFSET $2
		`
		args = []any{limit, offset}
	}

	// Get total count.
	var total int
	countArgs := args[:0:0]
	if status != "" {
		countArgs = []any{status}
	}
	if err := r.db.QueryRow(ctx, countQ, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("repository: ListQueues count: %w", err)
	}

	rows, err := r.db.Query(ctx, listQ, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("repository: ListQueues: %w", err)
	}
	defer rows.Close()

	var queues []*models.Queue
	for rows.Next() {
		q := &models.Queue{}
		if err := rows.Scan(
			&q.ID, &q.Title, &q.Description, &q.OwnerID, &q.Department,
			&q.Location, &q.MaxSize, &q.MaxRejoins, &q.Status, &q.CreatedAt, &q.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("repository: ListQueues scan: %w", err)
		}
		queues = append(queues, q)
	}

	return queues, total, nil
}

// UpdateQueueStatus sets the status of a queue and updates updated_at.
func (r *Repository) UpdateQueueStatus(ctx context.Context, queueID, status string) error {
	const query = `
		UPDATE queues
		SET    status = $1, updated_at = $2
		WHERE  id = $3
	`

	tag, err := r.db.Exec(ctx, query, status, time.Now(), queueID)
	if err != nil {
		return fmt.Errorf("repository: UpdateQueueStatus: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── Queue entry queries ─────────────────────────────────────────────────────

// CreateEntry inserts a queue entry.
func (r *Repository) CreateEntry(ctx context.Context, e *models.QueueEntry) error {
	const query = `
		INSERT INTO queue_entries (id, queue_id, user_id, position, status, joined_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.Exec(ctx, query,
		e.ID, e.QueueID, e.UserID, e.Position, e.Status, e.JoinedAt,
	)
	if err != nil {
		return fmt.Errorf("repository: CreateEntry: %w", err)
	}
	return nil
}

// GetActiveEntryByQueueAndUser checks if a user has a waiting or serving entry.
func (r *Repository) GetActiveEntryByQueueAndUser(ctx context.Context, queueID, userID string) (*models.QueueEntry, error) {
	const query = `
		SELECT id, queue_id, user_id, position, status, joined_at, served_at
		FROM   queue_entries
		WHERE  queue_id = $1 AND user_id = $2 AND status IN ('waiting', 'serving')
		LIMIT  1
	`

	row := r.db.QueryRow(ctx, query, queueID, userID)
	e := &models.QueueEntry{}

	err := row.Scan(&e.ID, &e.QueueID, &e.UserID, &e.Position, &e.Status, &e.JoinedAt, &e.ServedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repository: GetActiveEntryByQueueAndUser: %w", err)
	}
	return e, nil
}

// CountUserRejoinsToday counts how many times a user has joined this queue today
// (entries with status served or left, created today).
func (r *Repository) CountUserRejoinsToday(ctx context.Context, queueID, userID string) (int, error) {
	const query = `
		SELECT COUNT(*)
		FROM   queue_entries
		WHERE  queue_id = $1
		  AND  user_id = $2
		  AND  status IN ('served', 'left')
		  AND  joined_at >= $3
	`

	startOfDay := startOfToday()
	var count int
	err := r.db.QueryRow(ctx, query, queueID, userID, startOfDay).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("repository: CountUserRejoinsToday: %w", err)
	}
	return count, nil
}

// CountServedToday counts entries served in this queue today (for daily capacity).
func (r *Repository) CountServedToday(ctx context.Context, queueID string) (int, error) {
	const query = `
		SELECT COUNT(*)
		FROM   queue_entries
		WHERE  queue_id = $1
		  AND  status = 'served'
		  AND  served_at >= $2
	`

	startOfDay := startOfToday()
	var count int
	err := r.db.QueryRow(ctx, query, queueID, startOfDay).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("repository: CountServedToday: %w", err)
	}
	return count, nil
}

// CountWaiting counts entries with status 'waiting' in a queue.
func (r *Repository) CountWaiting(ctx context.Context, queueID string) (int, error) {
	const query = `
		SELECT COUNT(*)
		FROM   queue_entries
		WHERE  queue_id = $1 AND status = 'waiting'
	`

	var count int
	err := r.db.QueryRow(ctx, query, queueID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("repository: CountWaiting: %w", err)
	}
	return count, nil
}

// GetNextPosition returns the next position number for a queue.
func (r *Repository) GetNextPosition(ctx context.Context, queueID string) (int, error) {
	const query = `
		SELECT COALESCE(MAX(position), 0) + 1
		FROM   queue_entries
		WHERE  queue_id = $1
	`

	var pos int
	err := r.db.QueryRow(ctx, query, queueID).Scan(&pos)
	if err != nil {
		return 0, fmt.Errorf("repository: GetNextPosition: %w", err)
	}
	return pos, nil
}

// GetNextWaiting fetches the lowest-position waiting entry in a queue.
func (r *Repository) GetNextWaiting(ctx context.Context, queueID string) (*models.QueueEntry, error) {
	const query = `
		SELECT id, queue_id, user_id, position, status, joined_at, served_at
		FROM   queue_entries
		WHERE  queue_id = $1 AND status = 'waiting'
		ORDER BY position ASC
		LIMIT  1
	`

	row := r.db.QueryRow(ctx, query, queueID)
	e := &models.QueueEntry{}

	err := row.Scan(&e.ID, &e.QueueID, &e.UserID, &e.Position, &e.Status, &e.JoinedAt, &e.ServedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repository: GetNextWaiting: %w", err)
	}
	return e, nil
}

// GetCurrentlyServing fetches the entry with status 'serving' in a queue.
func (r *Repository) GetCurrentlyServing(ctx context.Context, queueID string) (*models.QueueEntry, error) {
	const query = `
		SELECT id, queue_id, user_id, position, status, joined_at, served_at
		FROM   queue_entries
		WHERE  queue_id = $1 AND status = 'serving'
		LIMIT  1
	`

	row := r.db.QueryRow(ctx, query, queueID)
	e := &models.QueueEntry{}

	err := row.Scan(&e.ID, &e.QueueID, &e.UserID, &e.Position, &e.Status, &e.JoinedAt, &e.ServedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repository: GetCurrentlyServing: %w", err)
	}
	return e, nil
}

// UpdateEntryStatus transitions an entry's status.
func (r *Repository) UpdateEntryStatus(ctx context.Context, entryID, status string) error {
	const query = `
		UPDATE queue_entries
		SET    status = $1
		WHERE  id = $2
	`

	tag, err := r.db.Exec(ctx, query, status, entryID)
	if err != nil {
		return fmt.Errorf("repository: UpdateEntryStatus: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateEntryServed marks an entry as served with a timestamp.
func (r *Repository) UpdateEntryServed(ctx context.Context, entryID string) error {
	const query = `
		UPDATE queue_entries
		SET    status = 'served', served_at = $1
		WHERE  id = $2
	`

	now := time.Now()
	tag, err := r.db.Exec(ctx, query, now, entryID)
	if err != nil {
		return fmt.Errorf("repository: UpdateEntryServed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetUserPosition returns how many people are ahead of the user in the queue.
func (r *Repository) GetUserPosition(ctx context.Context, queueID, userID string) (*models.QueueEntry, int, error) {
	// First get the user's active entry.
	entry, err := r.GetActiveEntryByQueueAndUser(ctx, queueID, userID)
	if err != nil {
		return nil, 0, err
	}

	// Count waiting entries with a lower position number.
	const query = `
		SELECT COUNT(*)
		FROM   queue_entries
		WHERE  queue_id = $1 AND status = 'waiting' AND position < $2
	`

	var ahead int
	err = r.db.QueryRow(ctx, query, queueID, entry.Position).Scan(&ahead)
	if err != nil {
		return nil, 0, fmt.Errorf("repository: GetUserPosition: %w", err)
	}

	return entry, ahead, nil
}

// ListEntries returns entries for a queue, optionally filtered by status.
func (r *Repository) ListEntries(ctx context.Context, queueID, status string) ([]*models.QueueEntry, error) {
	var query string
	var args []any

	if status != "" {
		query = `
			SELECT id, queue_id, user_id, position, status, joined_at, served_at
			FROM   queue_entries
			WHERE  queue_id = $1 AND status = $2
			ORDER BY position ASC
		`
		args = []any{queueID, status}
	} else {
		query = `
			SELECT id, queue_id, user_id, position, status, joined_at, served_at
			FROM   queue_entries
			WHERE  queue_id = $1
			ORDER BY position ASC
		`
		args = []any{queueID}
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("repository: ListEntries: %w", err)
	}
	defer rows.Close()

	var entries []*models.QueueEntry
	for rows.Next() {
		e := &models.QueueEntry{}
		if err := rows.Scan(
			&e.ID, &e.QueueID, &e.UserID, &e.Position, &e.Status, &e.JoinedAt, &e.ServedAt,
		); err != nil {
			return nil, fmt.Errorf("repository: ListEntries scan: %w", err)
		}
		entries = append(entries, e)
	}

	return entries, nil
}

// BulkLeaveWaiting sets all 'waiting' entries in a queue to 'left'.
// Called when a queue is closed.
func (r *Repository) BulkLeaveWaiting(ctx context.Context, queueID string) error {
	const query = `
		UPDATE queue_entries
		SET    status = 'left'
		WHERE  queue_id = $1 AND status = 'waiting'
	`

	_, err := r.db.Exec(ctx, query, queueID)
	if err != nil {
		return fmt.Errorf("repository: BulkLeaveWaiting: %w", err)
	}
	return nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// startOfToday returns midnight of the current day (server-local time).
func startOfToday() time.Time {
	now := time.Now()
	return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
}
