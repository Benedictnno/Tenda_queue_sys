// Package config loads all required environment variables at startup.
// The application panics on startup if any required variable is missing,
// preventing silent misconfiguration in production.
package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config holds the full runtime configuration for the auth service.
type Config struct {
	DatabaseURL      string
	JWTSecret        string
	JWTAccessExpiry  time.Duration
	JWTRefreshExpiry time.Duration
	AppPort          string
	BcryptCost       int
}

// Load reads environment variables (from .env if present) and returns a Config.
// It panics if any required variable is absent or malformed.
func Load() *Config {
	// Load .env file if it exists — silently ignore if not found (production
	// environments inject vars directly).
	_ = godotenv.Load()

	cfg := &Config{
		DatabaseURL: requireEnv("DATABASE_URL"),
		JWTSecret:   requireEnv("JWT_SECRET"),
		AppPort:     getEnvOrDefault("APP_PORT", "8080"),
	}

	// Parse JWT access token expiry (e.g. "15m")
	accessExpiry, err := time.ParseDuration(requireEnv("JWT_ACCESS_EXPIRY"))
	if err != nil {
		log.Fatalf("config: invalid JWT_ACCESS_EXPIRY: %v", err)
	}
	cfg.JWTAccessExpiry = accessExpiry

	// Parse JWT refresh token expiry (e.g. "168h" for 7 days)
	refreshExpiry, err := time.ParseDuration(requireEnv("JWT_REFRESH_EXPIRY"))
	if err != nil {
		log.Fatalf("config: invalid JWT_REFRESH_EXPIRY: %v", err)
	}
	cfg.JWTRefreshExpiry = refreshExpiry

	// Parse bcrypt cost factor
	cost, err := strconv.Atoi(getEnvOrDefault("BCRYPT_COST", "12"))
	if err != nil || cost < 4 || cost > 31 {
		log.Fatalf("config: BCRYPT_COST must be an integer between 4 and 31, got: %s", os.Getenv("BCRYPT_COST"))
	}
	cfg.BcryptCost = cost

	return cfg
}

// requireEnv returns the value of an environment variable or panics.
func requireEnv(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("config: required environment variable %q is not set", key)
	}
	return val
}

// getEnvOrDefault returns the value of an env var or a fallback default.
func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
