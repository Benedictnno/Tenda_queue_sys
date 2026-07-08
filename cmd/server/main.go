// Package main — cmd/server/main.go
//
// Entry point for the Tennda auth service.
// Wires together config → database → repository → service → handler → router.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	ginlimiter "github.com/ulule/limiter/v3/drivers/middleware/gin"
	"github.com/ulule/limiter/v3/drivers/store/memory"

	"github.com/tennda/auth/config"
	"github.com/tennda/auth/internal/auth"
	"github.com/tennda/auth/internal/database"
)

func main() {
	// ── 1. Load configuration ──────────────────────────────────────────────
	cfg := config.Load()

	// ── 2. Connect to PostgreSQL ───────────────────────────────────────────
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("main: database connection failed: %v", err)
	}
	defer db.Close()

	// ── 3. Wire dependencies ───────────────────────────────────────────────
	repo := auth.NewRepository(db)
	svc := auth.NewService(repo, cfg)
	h := auth.NewHandler(svc)

	// ── 4. Rate limiter — 5 requests per IP per minute on /login ──────────
	rate := limiter.Rate{
		Period: 1 * time.Minute,
		Limit:  5,
	}
	store := memory.NewStore()
	loginLimiter := ginlimiter.NewMiddleware(limiter.New(store, rate))

	// ── 5. Router setup ────────────────────────────────────────────────────
	// Use gin.New() instead of gin.Default() so we control which middleware
	// is applied globally.
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Health check — useful for load balancers and k8s probes.
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "tennda-auth"})
	})

	// ── 6. Route groups ────────────────────────────────────────────────────
	v1 := router.Group("/api/v1")
	authGroup := v1.Group("/auth")
	{
		// Public endpoints — no JWT required.
		authGroup.POST("/login", loginLimiter, h.HandleLogin)
		authGroup.POST("/refresh", h.HandleRefresh)

		// Protected endpoint — JWT required.
		authGroup.POST(
			"/logout",
			auth.JWTMiddleware(cfg),
			h.HandleLogout,
		)

		// ── Internal-only endpoints ──────────────────────────────────────
		//
		// SECURITY: /auth/verify and /auth/verify-device MUST be placed
		// behind an internal network boundary (VPC, private subnet, or
		// network policy) in production.  They MUST NOT be reachable from
		// the public internet.
		//
		// The Python FastAPI attendance service calls /auth/verify on every
		// inbound request — no rate limit is applied here intentionally.
		authGroup.POST("/verify", h.HandleVerify)
		authGroup.POST("/verify-device", h.HandleVerifyDevice)
	}

	// ── 7. Example of RoleGuard usage (for reference) ─────────────────────
	//
	// When other services extend this router, protect routes like this:
	//
	//   v1.POST("/sessions",
	//       auth.JWTMiddleware(cfg),
	//       auth.RoleGuard("lecturer", "admin"),
	//       sessionHandler.Create,
	//   )

	// ── 8. Start server with graceful shutdown ─────────────────────────────
	addr := fmt.Sprintf(":%s", cfg.AppPort)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start in a goroutine so we can listen for shutdown signals.
	go func() {
		log.Printf("main: Tennda auth service listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("main: ListenAndServe: %v", err)
		}
	}()

	// Block until SIGINT or SIGTERM is received.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("main: shutdown signal received — draining connections...")

	// Give in-flight requests 10 seconds to complete.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("main: forced shutdown: %v", err)
	}

	log.Println("main: Tennda auth service stopped cleanly")
}
