// Package response provides standardised JSON response helpers used by all
// HTTP handlers in the Tennda auth service.
//
// Every response conforms to one of two shapes:
//
//	Success: { "success": true,  "data": <any> }
//	Error:   { "success": false, "error": { "code": "...", "message": "..." } }
//
// The Python FastAPI attendance service and React frontend both depend on this
// contract — do not change the top-level field names.
package response

import (
	"github.com/gin-gonic/gin"
)

// successBody is the envelope for successful responses.
type successBody struct {
	Success bool `json:"success"`
	Data    any  `json:"data"`
}

// errorDetail carries a machine-readable code alongside a human message.
type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// errorBody is the envelope for error responses.
type errorBody struct {
	Success bool        `json:"success"`
	Error   errorDetail `json:"error"`
}

// Success writes a standardised success JSON response.
//
//	response.Success(c, http.StatusOK, gin.H{"message": "ok"})
func Success(c *gin.Context, statusCode int, data any) {
	c.JSON(statusCode, successBody{
		Success: true,
		Data:    data,
	})
}

// Error writes a standardised error JSON response.
//
//	response.Error(c, http.StatusUnauthorized, "TOKEN_INVALID", "Token is invalid or expired")
func Error(c *gin.Context, statusCode int, code, message string) {
	c.AbortWithStatusJSON(statusCode, errorBody{
		Success: false,
		Error: errorDetail{
			Code:    code,
			Message: message,
		},
	})
}
