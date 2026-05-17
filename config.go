package main

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	Port              string
	DataDir           string
	DownloadsDir      string
	AdminPass         string
	LinkSecret        []byte
	MaxUploadBytes    int64
	MaxFetchBytes     int64
	QuotaBytes        int64
	MaxSessionsPerUser int
	CookieSecure      bool
	WebhookURL        string
	RegistrationOpen  bool
}

func LoadConfig() *Config {
	dataDir := envStr("DATA_DIR", "data")
	downloadsDir := envStr("DOWNLOADS_DIR", filepath.Join(dataDir, "files"))

	secret := envStr("LINK_SECRET", "")
	if secret == "" {
		b := make([]byte, 32)
		rand.Read(b)
		secret = hex.EncodeToString(b)
		slog.Warn("LINK_SECRET not set; using ephemeral random secret — signed URLs will break on restart")
	}

	cfg := &Config{
		Port:              envStr("PORT", "8080"),
		DataDir:           dataDir,
		DownloadsDir:      downloadsDir,
		AdminPass:         envStr("ADMIN_PASS", ""),
		LinkSecret:        []byte(secret),
		MaxUploadBytes:    int64(envInt("MAX_UPLOAD_MB", 2048)) * 1024 * 1024,
		MaxFetchBytes:     int64(envInt("MAX_FETCH_MB", 4096)) * 1024 * 1024,
		QuotaBytes:        int64(envInt("QUOTA_MB", 0)) * 1024 * 1024,
		MaxSessionsPerUser: envInt("MAX_SESSIONS_PER_USER", 10),
		CookieSecure:      envBool("COOKIE_SECURE", false),
		WebhookURL:        envStr("WEBHOOK_URL", ""),
		RegistrationOpen:  envBool("REGISTRATION_OPEN", true),
	}

	// Ensure required directories exist.
	for _, dir := range []string{cfg.DataDir, cfg.DownloadsDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			slog.Error("cannot create directory", "path", dir, "err", err)
			os.Exit(1)
		}
	}

	if cfg.AdminPass == "" {
		slog.Warn("ADMIN_PASS not set; admin account will not be created")
	}

	return cfg
}

func envStr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}
