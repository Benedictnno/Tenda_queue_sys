// Package queue — service.go
//
// Business logic layer for queue management.  Handlers call the Service;
// the Service calls the Repository.  No SQL here, no HTTP concepts.
package queue

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/tennda/auth/internal/models"
)

// ─── Request / Response DTOs ─────────────────────────────────────────────────

// CreateQueueRequest is the decoded body of POST /queues.
type CreateQueueRequest struct {
	Title       string `json:"title"       binding:"required"`
	Description string `json:"description"`
	Department  string `json:"department"`
	Location    string `json:"location"`
	MaxSize     int    `json:"max_size"`     // daily capacity; 0 = unlimited
	MaxRejoins  int    `json:"max_rejoins"`  // max rejoins per user per day; 0 = use default (3)
}

// QueueResponse is the public representation of a queue.
type QueueResponse struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Description  string    `json:"description,omitempty"`
	OwnerID      string    `json:"owner_id"`
	Department   string    `json:"department,omitempty"`
	Location     string    `json:"location,omitempty"`
	MaxSize      int       `json:"max_size"`
	MaxRejoins   int       `json:"max_rejoins"`
	Status       string    `json:"status"`
	WaitingCount int       `json:"waiting_count"`
	ServedToday  int       `json:"served_today"`
	CreatedAt    time.Time `json:"created_at"`
}

// QueueListResponse wraps a paginated list of queues.
type QueueListResponse struct {
	Queues     []*QueueResponse `json:"queues"`
	Total      int              `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
}

// EntryResponse is the public representation of a queue entry.
type EntryResponse struct {
	ID       string     `json:"id"`
	QueueID  string     `json:"queue_id"`
	UserID   string     `json:"user_id"`
	Position int        `json:"position"`
	Status   string     `json:"status"`
	JoinedAt time.Time  `json:"joined_at"`
	ServedAt *time.Time `json:"served_at,omitempty"`
}

// PositionResponse tells the user where they are in line.
type PositionResponse struct {
	QueueID     string `json:"queue_id"`
	Position    int    `json:"position"`
	PeopleAhead int    `json:"people_ahead"`
	Status      string `json:"status"`
}

// ServeNextResponse is returned after advancing the queue.
type ServeNextResponse struct {
	PreviouslyServing *EntryResponse `json:"previously_serving,omitempty"`
	NowServing        *EntryResponse `json:"now_serving,omitempty"`
	Message           string         `json:"message"`
}

// ─── Service errors ──────────────────────────────────────────────────────────

// ServiceError carries an HTTP status code alongside a machine code and message.
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

// Service implements the queue business logic.
type Service struct {
	repo *Repository
}

// NewService creates a queue Service with the given repository.
func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

// CreateQueue creates a new queue owned by the caller.
func (s *Service) CreateQueue(ctx context.Context, req CreateQueueRequest, ownerID string) (*QueueResponse, error) {
	id, err := generateUUID()
	if err != nil {
		return nil, fmt.Errorf("service: CreateQueue: uuid: %w", err)
	}

	maxRejoins := req.MaxRejoins
	if maxRejoins <= 0 {
		maxRejoins = 3 // sensible default
	}

	now := time.Now()
	q := &models.Queue{
		ID:          id,
		Title:       req.Title,
		Description: req.Description,
		OwnerID:     ownerID,
		Department:  req.Department,
		Location:    req.Location,
		MaxSize:     req.MaxSize,
		MaxRejoins:  maxRejoins,
		Status:      models.QueueStatusOpen,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.repo.CreateQueue(ctx, q); err != nil {
		return nil, fmt.Errorf("service: CreateQueue: %w", err)
	}

	return &QueueResponse{
		ID:           q.ID,
		Title:        q.Title,
		Description:  q.Description,
		OwnerID:      q.OwnerID,
		Department:   q.Department,
		Location:     q.Location,
		MaxSize:      q.MaxSize,
		MaxRejoins:   q.MaxRejoins,
		Status:       q.Status,
		WaitingCount: 0,
		ServedToday:  0,
		CreatedAt:    q.CreatedAt,
	}, nil
}

// GetQueue returns queue details with live waiting count and daily served count.
func (s *Service) GetQueue(ctx context.Context, queueID string) (*QueueResponse, error) {
	q, err := s.repo.GetQueueByID(ctx, queueID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, serviceErr(http.StatusNotFound, "QUEUE_NOT_FOUND", "Queue not found")
		}
		return nil, fmt.Errorf("service: GetQueue: %w", err)
	}

	waiting, err := s.repo.CountWaiting(ctx, queueID)
	if err != nil {
		return nil, fmt.Errorf("service: GetQueue: count waiting: %w", err)
	}

	served, err := s.repo.CountServedToday(ctx, queueID)
	if err != nil {
		return nil, fmt.Errorf("service: GetQueue: count served: %w", err)
	}

	return &QueueResponse{
		ID:           q.ID,
		Title:        q.Title,
		Description:  q.Description,
		OwnerID:      q.OwnerID,
		Department:   q.Department,
		Location:     q.Location,
		MaxSize:      q.MaxSize,
		MaxRejoins:   q.MaxRejoins,
		Status:       q.Status,
		WaitingCount: waiting,
		ServedToday:  served,
		CreatedAt:    q.CreatedAt,
	}, nil
}

// ListQueues returns a paginated list of queues.
func (s *Service) ListQueues(ctx context.Context, status string, page, pageSize int) (*QueueListResponse, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 50 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	queues, total, err := s.repo.ListQueues(ctx, status, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("service: ListQueues: %w", err)
	}

	var results []*QueueResponse
	for _, q := range queues {
		waiting, _ := s.repo.CountWaiting(ctx, q.ID)
		served, _ := s.repo.CountServedToday(ctx, q.ID)

		results = append(results, &QueueResponse{
			ID:           q.ID,
			Title:        q.Title,
			Description:  q.Description,
			OwnerID:      q.OwnerID,
			Department:   q.Department,
			Location:     q.Location,
			MaxSize:      q.MaxSize,
			MaxRejoins:   q.MaxRejoins,
			Status:       q.Status,
			WaitingCount: waiting,
			ServedToday:  served,
			CreatedAt:    q.CreatedAt,
		})
	}

	return &QueueListResponse{
		Queues:   results,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// JoinQueue adds the user to the queue.
//
// Validations:
//  1. Queue exists and is open.
//  2. User does not already have an active (waiting/serving) entry.
//  3. Daily capacity not exceeded (if max_size > 0).
//  4. User has not exceeded max rejoins for the day.
func (s *Service) JoinQueue(ctx context.Context, queueID, userID string) (*EntryResponse, error) {
	q, err := s.repo.GetQueueByID(ctx, queueID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, serviceErr(http.StatusNotFound, "QUEUE_NOT_FOUND", "Queue not found")
		}
		return nil, fmt.Errorf("service: JoinQueue: %w", err)
	}

	if !q.IsOpen() {
		return nil, serviceErr(http.StatusConflict, "QUEUE_NOT_OPEN",
			fmt.Sprintf("Queue is currently %s", q.Status))
	}

	// Check for existing active entry.
	_, err = s.repo.GetActiveEntryByQueueAndUser(ctx, queueID, userID)
	if err == nil {
		return nil, serviceErr(http.StatusConflict, "ALREADY_IN_QUEUE",
			"You already have an active entry in this queue")
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("service: JoinQueue: check active: %w", err)
	}

	// Check daily capacity.
	if q.MaxSize > 0 {
		served, err := s.repo.CountServedToday(ctx, queueID)
		if err != nil {
			return nil, fmt.Errorf("service: JoinQueue: count served: %w", err)
		}
		waiting, err := s.repo.CountWaiting(ctx, queueID)
		if err != nil {
			return nil, fmt.Errorf("service: JoinQueue: count waiting: %w", err)
		}
		if served+waiting >= q.MaxSize {
			return nil, serviceErr(http.StatusConflict, "QUEUE_FULL",
				"Queue has reached its daily capacity")
		}
	}

	// Check rejoin limit.
	rejoins, err := s.repo.CountUserRejoinsToday(ctx, queueID, userID)
	if err != nil {
		return nil, fmt.Errorf("service: JoinQueue: count rejoins: %w", err)
	}
	if rejoins >= q.MaxRejoins {
		return nil, serviceErr(http.StatusConflict, "REJOIN_LIMIT",
			fmt.Sprintf("You have reached the maximum of %d joins for this queue today", q.MaxRejoins))
	}

	// Get next position.
	pos, err := s.repo.GetNextPosition(ctx, queueID)
	if err != nil {
		return nil, fmt.Errorf("service: JoinQueue: next position: %w", err)
	}

	entryID, err := generateUUID()
	if err != nil {
		return nil, fmt.Errorf("service: JoinQueue: uuid: %w", err)
	}

	entry := &models.QueueEntry{
		ID:       entryID,
		QueueID:  queueID,
		UserID:   userID,
		Position: pos,
		Status:   models.EntryStatusWaiting,
		JoinedAt: time.Now(),
	}

	if err := s.repo.CreateEntry(ctx, entry); err != nil {
		return nil, fmt.Errorf("service: JoinQueue: %w", err)
	}

	return toEntryResponse(entry), nil
}

// LeaveQueue lets a user voluntarily leave the queue.
func (s *Service) LeaveQueue(ctx context.Context, queueID, userID string) error {
	entry, err := s.repo.GetActiveEntryByQueueAndUser(ctx, queueID, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return serviceErr(http.StatusNotFound, "NOT_IN_QUEUE",
				"You do not have an active entry in this queue")
		}
		return fmt.Errorf("service: LeaveQueue: %w", err)
	}

	if err := s.repo.UpdateEntryStatus(ctx, entry.ID, models.EntryStatusLeft); err != nil {
		return fmt.Errorf("service: LeaveQueue: %w", err)
	}
	return nil
}

// GetPosition returns the user's current position and how many people are ahead.
func (s *Service) GetPosition(ctx context.Context, queueID, userID string) (*PositionResponse, error) {
	entry, ahead, err := s.repo.GetUserPosition(ctx, queueID, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, serviceErr(http.StatusNotFound, "NOT_IN_QUEUE",
				"You do not have an active entry in this queue")
		}
		return nil, fmt.Errorf("service: GetPosition: %w", err)
	}

	return &PositionResponse{
		QueueID:     queueID,
		Position:    entry.Position,
		PeopleAhead: ahead,
		Status:      entry.Status,
	}, nil
}

// ServeNext advances the queue: marks current serving entry as served, promotes
// the next waiting entry to serving.
//
// Only the queue owner or an admin/super_admin can call this.
func (s *Service) ServeNext(ctx context.Context, queueID, callerID, callerRole string) (*ServeNextResponse, error) {
	q, err := s.repo.GetQueueByID(ctx, queueID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, serviceErr(http.StatusNotFound, "QUEUE_NOT_FOUND", "Queue not found")
		}
		return nil, fmt.Errorf("service: ServeNext: %w", err)
	}

	if !s.isOwnerOrAdmin(q, callerID, callerRole) {
		return nil, serviceErr(http.StatusForbidden, "FORBIDDEN",
			"Only the queue owner or an admin can serve the queue")
	}

	resp := &ServeNextResponse{}

	// Mark current serving entry as served (if any).
	current, err := s.repo.GetCurrentlyServing(ctx, queueID)
	if err == nil {
		if err := s.repo.UpdateEntryServed(ctx, current.ID); err != nil {
			return nil, fmt.Errorf("service: ServeNext: mark served: %w", err)
		}
		current.Status = models.EntryStatusServed
		resp.PreviouslyServing = toEntryResponse(current)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("service: ServeNext: get current: %w", err)
	}

	// Promote next waiting entry.
	next, err := s.repo.GetNextWaiting(ctx, queueID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			resp.Message = "No one is waiting in the queue"
			return resp, nil
		}
		return nil, fmt.Errorf("service: ServeNext: get next: %w", err)
	}

	if err := s.repo.UpdateEntryStatus(ctx, next.ID, models.EntryStatusServing); err != nil {
		return nil, fmt.Errorf("service: ServeNext: promote: %w", err)
	}
	next.Status = models.EntryStatusServing
	resp.NowServing = toEntryResponse(next)
	resp.Message = "Next person is now being served"

	return resp, nil
}

// CloseQueue sets queue status to closed and marks all waiting entries as left.
func (s *Service) CloseQueue(ctx context.Context, queueID, callerID, callerRole string) error {
	q, err := s.repo.GetQueueByID(ctx, queueID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return serviceErr(http.StatusNotFound, "QUEUE_NOT_FOUND", "Queue not found")
		}
		return fmt.Errorf("service: CloseQueue: %w", err)
	}

	if !s.isOwnerOrAdmin(q, callerID, callerRole) {
		return serviceErr(http.StatusForbidden, "FORBIDDEN",
			"Only the queue owner or an admin can close the queue")
	}

	// Mark all waiting entries as left.
	if err := s.repo.BulkLeaveWaiting(ctx, queueID); err != nil {
		return fmt.Errorf("service: CloseQueue: bulk leave: %w", err)
	}

	if err := s.repo.UpdateQueueStatus(ctx, queueID, models.QueueStatusClosed); err != nil {
		return fmt.Errorf("service: CloseQueue: %w", err)
	}
	return nil
}

// PauseQueue sets queue status to paused (no new joins allowed).
func (s *Service) PauseQueue(ctx context.Context, queueID, callerID, callerRole string) error {
	q, err := s.repo.GetQueueByID(ctx, queueID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return serviceErr(http.StatusNotFound, "QUEUE_NOT_FOUND", "Queue not found")
		}
		return fmt.Errorf("service: PauseQueue: %w", err)
	}

	if !s.isOwnerOrAdmin(q, callerID, callerRole) {
		return serviceErr(http.StatusForbidden, "FORBIDDEN",
			"Only the queue owner or an admin can pause the queue")
	}

	if err := s.repo.UpdateQueueStatus(ctx, queueID, models.QueueStatusPaused); err != nil {
		return fmt.Errorf("service: PauseQueue: %w", err)
	}
	return nil
}

// ResumeQueue sets queue status back to open.
func (s *Service) ResumeQueue(ctx context.Context, queueID, callerID, callerRole string) error {
	q, err := s.repo.GetQueueByID(ctx, queueID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return serviceErr(http.StatusNotFound, "QUEUE_NOT_FOUND", "Queue not found")
		}
		return fmt.Errorf("service: ResumeQueue: %w", err)
	}

	if !s.isOwnerOrAdmin(q, callerID, callerRole) {
		return serviceErr(http.StatusForbidden, "FORBIDDEN",
			"Only the queue owner or an admin can resume the queue")
	}

	if err := s.repo.UpdateQueueStatus(ctx, queueID, models.QueueStatusOpen); err != nil {
		return fmt.Errorf("service: ResumeQueue: %w", err)
	}
	return nil
}

// ListEntries returns all entries for a queue, optionally filtered by status.
func (s *Service) ListEntries(ctx context.Context, queueID, callerID, callerRole, status string) ([]*EntryResponse, error) {
	q, err := s.repo.GetQueueByID(ctx, queueID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, serviceErr(http.StatusNotFound, "QUEUE_NOT_FOUND", "Queue not found")
		}
		return nil, fmt.Errorf("service: ListEntries: %w", err)
	}

	if !s.isOwnerOrAdmin(q, callerID, callerRole) {
		return nil, serviceErr(http.StatusForbidden, "FORBIDDEN",
			"Only the queue owner or an admin can view entries")
	}

	entries, err := s.repo.ListEntries(ctx, queueID, status)
	if err != nil {
		return nil, fmt.Errorf("service: ListEntries: %w", err)
	}

	var results []*EntryResponse
	for _, e := range entries {
		results = append(results, toEntryResponse(e))
	}
	return results, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// isOwnerOrAdmin returns true if the caller owns the queue or has an admin role.
func (s *Service) isOwnerOrAdmin(q *models.Queue, callerID, callerRole string) bool {
	if q.OwnerID == callerID {
		return true
	}
	return callerRole == models.RoleAdmin || callerRole == models.RoleSuperAdmin
}

// toEntryResponse maps a domain QueueEntry to an API EntryResponse.
func toEntryResponse(e *models.QueueEntry) *EntryResponse {
	return &EntryResponse{
		ID:       e.ID,
		QueueID:  e.QueueID,
		UserID:   e.UserID,
		Position: e.Position,
		Status:   e.Status,
		JoinedAt: e.JoinedAt,
		ServedAt: e.ServedAt,
	}
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
