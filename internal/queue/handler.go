// Package queue — handler.go
//
// HTTP handlers for all queue endpoints.  Handlers are thin: decode request →
// call service → map service error to HTTP response.  No business logic here.
package queue

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/tennda/auth/internal/auth"
	"github.com/tennda/auth/pkg/response"
)

// Handler holds a reference to the queue service and exposes HTTP handler funcs.
type Handler struct {
	svc *Service
}

// NewHandler creates a Handler backed by the given Service.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// ─── Swagger Documentation Wrappers ──────────────────────────────────────────

type docsQueueResponse struct {
	Success bool          `json:"success" example:"true"`
	Data    QueueResponse `json:"data"`
}

type docsQueueListResponse struct {
	Success bool              `json:"success" example:"true"`
	Data    QueueListResponse `json:"data"`
}

type docsEntryResponse struct {
	Success bool          `json:"success" example:"true"`
	Data    EntryResponse `json:"data"`
}

type docsPositionResponse struct {
	Success bool             `json:"success" example:"true"`
	Data    PositionResponse `json:"data"`
}

type docsServeNextResponse struct {
	Success bool              `json:"success" example:"true"`
	Data    ServeNextResponse `json:"data"`
}

type docsEntriesListResponse struct {
	Success bool             `json:"success" example:"true"`
	Data    []*EntryResponse `json:"data"`
}

// ─── POST /api/v1/queues ─────────────────────────────────────────────────────

// HandleCreateQueue creates a new queue.
//
// @Summary Create a queue
// @Description Creates a new queue owned by the authenticated user.
// @Tags queues
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateQueueRequest true "Queue details"
// @Success 201 {object} docsQueueResponse
// @Failure 400 {object} response.ErrorBody
// @Failure 401 {object} response.ErrorBody
// @Failure 403 {object} response.ErrorBody
// @Router /queues [post]
func (h *Handler) HandleCreateQueue(c *gin.Context) {
	var req CreateQueueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "BAD_REQUEST", err.Error())
		return
	}

	ownerID := getUserID(c)

	resp, err := h.svc.CreateQueue(c.Request.Context(), req, ownerID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusCreated, resp)
}

// ─── GET /api/v1/queues ──────────────────────────────────────────────────────

// HandleListQueues returns a paginated list of queues.
//
// @Summary List queues
// @Description Returns a paginated list of queues, optionally filtered by status.
// @Tags queues
// @Produce json
// @Security BearerAuth
// @Param status query string false "Filter by status (open, closed, paused)"
// @Param page query int false "Page number (default 1)"
// @Param page_size query int false "Page size (default 20, max 50)"
// @Success 200 {object} docsQueueListResponse
// @Failure 401 {object} response.ErrorBody
// @Router /queues [get]
func (h *Handler) HandleListQueues(c *gin.Context) {
	status := c.Query("status")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "20"))

	resp, err := h.svc.ListQueues(c.Request.Context(), status, page, pageSize)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, resp)
}

// ─── GET /api/v1/queues/:id ──────────────────────────────────────────────────

// HandleGetQueue returns details for a single queue.
//
// @Summary Get queue details
// @Description Returns queue details including waiting count and daily served count.
// @Tags queues
// @Produce json
// @Security BearerAuth
// @Param id path string true "Queue UUID"
// @Success 200 {object} docsQueueResponse
// @Failure 401 {object} response.ErrorBody
// @Failure 404 {object} response.ErrorBody
// @Router /queues/{id} [get]
func (h *Handler) HandleGetQueue(c *gin.Context) {
	queueID := c.Param("id")

	resp, err := h.svc.GetQueue(c.Request.Context(), queueID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, resp)
}

// ─── POST /api/v1/queues/:id/join ────────────────────────────────────────────

// HandleJoinQueue adds the authenticated user to the queue.
//
// @Summary Join a queue
// @Description Adds the authenticated user to the specified queue. Users can rejoin after leaving/being served, up to the queue's rejoin limit.
// @Tags queues
// @Produce json
// @Security BearerAuth
// @Param id path string true "Queue UUID"
// @Success 201 {object} docsEntryResponse
// @Failure 401 {object} response.ErrorBody
// @Failure 404 {object} response.ErrorBody
// @Failure 409 {object} response.ErrorBody
// @Router /queues/{id}/join [post]
func (h *Handler) HandleJoinQueue(c *gin.Context) {
	queueID := c.Param("id")
	userID := getUserID(c)

	resp, err := h.svc.JoinQueue(c.Request.Context(), queueID, userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusCreated, resp)
}

// ─── POST /api/v1/queues/:id/leave ───────────────────────────────────────────

// HandleLeaveQueue removes the authenticated user from the queue.
//
// @Summary Leave a queue
// @Description Allows the authenticated user to voluntarily leave the queue.
// @Tags queues
// @Produce json
// @Security BearerAuth
// @Param id path string true "Queue UUID"
// @Success 200 {object} response.SuccessBody
// @Failure 401 {object} response.ErrorBody
// @Failure 404 {object} response.ErrorBody
// @Router /queues/{id}/leave [post]
func (h *Handler) HandleLeaveQueue(c *gin.Context) {
	queueID := c.Param("id")
	userID := getUserID(c)

	if err := h.svc.LeaveQueue(c.Request.Context(), queueID, userID); err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, gin.H{"message": "You have left the queue"})
}

// ─── GET /api/v1/queues/:id/position ─────────────────────────────────────────

// HandleGetPosition returns the user's position in the queue.
//
// @Summary Get queue position
// @Description Returns the authenticated user's position and number of people ahead.
// @Tags queues
// @Produce json
// @Security BearerAuth
// @Param id path string true "Queue UUID"
// @Success 200 {object} docsPositionResponse
// @Failure 401 {object} response.ErrorBody
// @Failure 404 {object} response.ErrorBody
// @Router /queues/{id}/position [get]
func (h *Handler) HandleGetPosition(c *gin.Context) {
	queueID := c.Param("id")
	userID := getUserID(c)

	resp, err := h.svc.GetPosition(c.Request.Context(), queueID, userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, resp)
}

// ─── POST /api/v1/queues/:id/serve-next ──────────────────────────────────────

// HandleServeNext advances the queue to the next person.
//
// @Summary Serve next person
// @Description Marks the currently serving person as served and promotes the next waiting person. Only the queue owner or admins can call this.
// @Tags queues
// @Produce json
// @Security BearerAuth
// @Param id path string true "Queue UUID"
// @Success 200 {object} docsServeNextResponse
// @Failure 401 {object} response.ErrorBody
// @Failure 403 {object} response.ErrorBody
// @Failure 404 {object} response.ErrorBody
// @Router /queues/{id}/serve-next [post]
func (h *Handler) HandleServeNext(c *gin.Context) {
	queueID := c.Param("id")
	callerID := getUserID(c)
	callerRole := getUserRole(c)

	resp, err := h.svc.ServeNext(c.Request.Context(), queueID, callerID, callerRole)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, resp)
}

// ─── POST /api/v1/queues/:id/close ───────────────────────────────────────────

// HandleCloseQueue closes the queue and removes all waiting entries.
//
// @Summary Close a queue
// @Description Closes the queue, marking all waiting entries as left. Only the queue owner or admins can call this.
// @Tags queues
// @Produce json
// @Security BearerAuth
// @Param id path string true "Queue UUID"
// @Success 200 {object} response.SuccessBody
// @Failure 401 {object} response.ErrorBody
// @Failure 403 {object} response.ErrorBody
// @Failure 404 {object} response.ErrorBody
// @Router /queues/{id}/close [post]
func (h *Handler) HandleCloseQueue(c *gin.Context) {
	queueID := c.Param("id")
	callerID := getUserID(c)
	callerRole := getUserRole(c)

	if err := h.svc.CloseQueue(c.Request.Context(), queueID, callerID, callerRole); err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, gin.H{"message": "Queue closed"})
}

// ─── POST /api/v1/queues/:id/pause ───────────────────────────────────────────

// HandlePauseQueue pauses the queue (no new joins allowed).
//
// @Summary Pause a queue
// @Description Pauses the queue so no new users can join. Existing entries remain. Only the queue owner or admins can call this.
// @Tags queues
// @Produce json
// @Security BearerAuth
// @Param id path string true "Queue UUID"
// @Success 200 {object} response.SuccessBody
// @Failure 401 {object} response.ErrorBody
// @Failure 403 {object} response.ErrorBody
// @Failure 404 {object} response.ErrorBody
// @Router /queues/{id}/pause [post]
func (h *Handler) HandlePauseQueue(c *gin.Context) {
	queueID := c.Param("id")
	callerID := getUserID(c)
	callerRole := getUserRole(c)

	if err := h.svc.PauseQueue(c.Request.Context(), queueID, callerID, callerRole); err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, gin.H{"message": "Queue paused"})
}

// ─── POST /api/v1/queues/:id/resume ──────────────────────────────────────────

// HandleResumeQueue resumes a paused queue.
//
// @Summary Resume a queue
// @Description Resumes a paused queue, allowing new users to join again. Only the queue owner or admins can call this.
// @Tags queues
// @Produce json
// @Security BearerAuth
// @Param id path string true "Queue UUID"
// @Success 200 {object} response.SuccessBody
// @Failure 401 {object} response.ErrorBody
// @Failure 403 {object} response.ErrorBody
// @Failure 404 {object} response.ErrorBody
// @Router /queues/{id}/resume [post]
func (h *Handler) HandleResumeQueue(c *gin.Context) {
	queueID := c.Param("id")
	callerID := getUserID(c)
	callerRole := getUserRole(c)

	if err := h.svc.ResumeQueue(c.Request.Context(), queueID, callerID, callerRole); err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, gin.H{"message": "Queue resumed"})
}

// ─── GET /api/v1/queues/:id/entries ──────────────────────────────────────────

// HandleListEntries returns all entries for a queue.
//
// @Summary List queue entries
// @Description Returns all entries for a queue, optionally filtered by status. Only the queue owner or admins can view entries.
// @Tags queues
// @Produce json
// @Security BearerAuth
// @Param id path string true "Queue UUID"
// @Param status query string false "Filter by entry status (waiting, serving, served, left)"
// @Success 200 {object} docsEntriesListResponse
// @Failure 401 {object} response.ErrorBody
// @Failure 403 {object} response.ErrorBody
// @Failure 404 {object} response.ErrorBody
// @Router /queues/{id}/entries [get]
func (h *Handler) HandleListEntries(c *gin.Context) {
	queueID := c.Param("id")
	status := c.Query("status")
	callerID := getUserID(c)
	callerRole := getUserRole(c)

	entries, err := h.svc.ListEntries(c.Request.Context(), queueID, callerID, callerRole, status)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	response.Success(c, http.StatusOK, entries)
}

// ─── Context helpers ─────────────────────────────────────────────────────────

// getUserID extracts the authenticated user's ID from the Gin context.
func getUserID(c *gin.Context) string {
	uid, _ := c.Get("userID")
	return uid.(string)
}

// getUserRole extracts the authenticated user's role from the Gin context.
func getUserRole(c *gin.Context) string {
	raw, exists := c.Get("claims")
	if !exists {
		return ""
	}
	claims, ok := raw.(*auth.Claims)
	if !ok {
		return ""
	}
	return claims.Role
}

// ─── Error mapping ───────────────────────────────────────────────────────────

// handleServiceError converts a ServiceError into the appropriate HTTP response.
func handleServiceError(c *gin.Context, err error) {
	var svcErr *ServiceError
	if errors.As(err, &svcErr) {
		response.Error(c, svcErr.StatusCode, svcErr.Code, svcErr.Message)
		return
	}
	response.Error(c, http.StatusInternalServerError, "INTERNAL_ERROR",
		"An unexpected error occurred")
}
