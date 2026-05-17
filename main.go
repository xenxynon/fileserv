package main

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

//go:embed static
var staticFS embed.FS

// appFS is the sub-filesystem for embedded static assets.
var appFS, _ = fs.Sub(staticFS, "static")

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg := LoadConfig()

	db, err := NewDB(cfg.DataDir)
	if err != nil {
		slog.Error("database init failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	// Prune stale sessions on startup
	db.PruneExpiredSessions()

	store := NewStorage(cfg.DownloadsDir)
	hub := NewHub()
	go hub.Run()

	h := NewHandlers(cfg, db, store, hub)
	r := buildRouter(h)

	srv := &http.Server{
		Addr:         "0.0.0.0:" + cfg.Port,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // 0 = no write timeout; needed for streaming downloads
		IdleTimeout:  120 * time.Second,
	}

	slog.Info("fileserv ready",
		"addr", "http://localhost:"+cfg.Port,
		"downloads", cfg.DownloadsDir,
		"data", cfg.DataDir,
	)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server crashed", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down…")
	srv.Close()
	slog.Info("goodbye")
}

func buildRouter(h *Handlers) http.Handler {
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(SecurityHeaders)
	r.Use(RateLimit)

	// Public routes
	r.Get("/", h.ServeApp)
	r.Handle("/static/*", http.FileServer(http.FS(appFS)))

	// Public share access
	r.Get("/s/{token}", h.ShareDownload)
	r.Post("/s/{token}", h.ShareDownload)

	// Auth (rate-limited via middleware above)
	r.Post("/api/auth/login", h.Login)
	r.Post("/api/auth/register", h.Register)
	r.Post("/api/auth/logout", h.Logout)
	r.Get("/api/auth/session", h.Session)

	// All routes below require a valid session or API key
	r.Group(func(r chi.Router) {
		r.Use(h.AuthMiddleware)

		// Health
		r.Get("/api/health", h.Health)

		// File browser
		r.Get("/api/files", h.ListFiles)
		r.Post("/api/files/upload", h.Upload)
		r.Delete("/api/files/*", h.DeleteFile)
		r.Post("/api/files/rename", h.Rename)
		r.Post("/api/files/mkdir", h.Mkdir)
		r.Post("/api/files/move", h.Move)
		r.Post("/api/files/bulk", h.Bulk)
		r.Get("/api/files/search", h.Search)
		r.Get("/api/files/zip", h.ZipFolder)
		r.Get("/api/files/zip-inspect", h.ZipInspect)
		r.Get("/api/files/edit/*", h.EditGet)
		r.Put("/api/files/edit/*", h.EditPut)
		r.Get("/api/files/token/*", h.MakeToken)

		// Downloads
		r.Get("/dl/*", h.Download)
		r.Get("/preview/*", h.Preview)
		r.Get("/t/{token}/*", h.TokenDownload)

		// Remote URL fetch
		r.Post("/api/fetch", h.FetchURL)
		r.Get("/api/fetch", h.FetchProgress)
		r.Delete("/api/fetch/{id}", h.FetchCancel)
		r.Post("/api/fetch/{id}/retry", h.FetchRetry)

		// Share links
		r.Post("/api/share", h.ShareCreate)
		r.Get("/api/share", h.ShareList)
		r.Delete("/api/share/{token}", h.ShareDelete)

		// API keys
		r.Post("/api/keys", h.KeyCreate)
		r.Get("/api/keys", h.KeyList)
		r.Delete("/api/keys/{prefix}", h.KeyDelete)

		// WebSocket event stream
		r.Get("/ws", h.WebSocket)

		// Admin-only routes
		r.Group(func(r chi.Router) {
			r.Use(h.AdminOnly)
			r.Get("/api/admin/users", h.AdminListUsers)
			r.Patch("/api/admin/users/{username}", h.AdminUpdateUser)
			r.Delete("/api/admin/users/{username}", h.AdminDeleteUser)
			r.Post("/api/admin/users/{username}/sessions/revoke", h.AdminRevokeSession)
			r.Get("/api/admin/stats", h.AdminStats)
			r.Get("/api/admin/audit", h.AdminAudit)
			r.Get("/api/flags", h.FlagsGet)
			r.Post("/api/flags", h.FlagsSet)
			r.Post("/api/torrent", h.Torrent)
			r.Get("/api/torrent", h.TorrentProgress)
			r.Delete("/api/torrent/{pid}", h.TorrentCancel)
		})
	})

	return r
}
