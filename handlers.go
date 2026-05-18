package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// Handlers holds all shared dependencies for HTTP handlers.
type Handlers struct {
	cfg   *Config
	db    *DB
	store *Storage
	hub   *Hub

	fetchMu   sync.Mutex
	fetchJobs map[string]*FetchJob

	torrentMu   sync.Mutex
	torrentJobs map[int]*TorrentJob
}

func NewHandlers(cfg *Config, db *DB, store *Storage, hub *Hub) *Handlers {
	h := &Handlers{
		cfg:         cfg,
		db:          db,
		store:       store,
		hub:         hub,
		fetchJobs:   map[string]*FetchJob{},
		torrentJobs: map[int]*TorrentJob{},
	}
	// Bootstrap admin account
	if cfg.AdminPass != "" {
		h.ensureAdmin()
	}
	return h
}

func (h *Handlers) ensureAdmin() {
	existing, _ := h.db.GetUser("admin")
	hash, _ := HashPassword(h.cfg.AdminPass)
	if existing == nil {
		h.db.CreateUser(User{
			Username:  "admin",
			PwHash:    hash,
			Role:      RoleAdmin,
			CreatedAt: time.Now(),
		})
	} else if !CheckPassword(h.cfg.AdminPass, existing.PwHash) {
		h.db.UpdateUser("admin", map[string]any{"pw_hash": hash, "role": "admin"})
	}
}

// ─── Static ───────────────────────────────────────────────────────────────────

func (h *Handlers) ServeApp(w http.ResponseWriter, r *http.Request) {
	f, err := staticFS.Open("static/app.html")
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 500)
		return
	}
	defer f.Close()
	data, _ := io.ReadAll(f)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid request")
		return
	}
	body.Username = strings.TrimSpace(body.Username)

	user, _ := h.db.GetUser(body.Username)
	if user == nil || user.Disabled || !CheckPassword(body.Password, user.PwHash) {
		h.db.Audit("login_fail", body.Username, "", clientIP(r))
		jsonErr(w, 401, "invalid credentials")
		return
	}

	// Enforce max sessions
	count, _ := h.db.CountUserSessions(body.Username)
	for count >= h.cfg.MaxSessionsPerUser {
		h.db.EvictOldestSession(body.Username)
		count--
	}

	tok := NewToken()
	sess := Session{
		Token:     tok,
		Username:  user.Username,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(sessionTTL),
	}
	h.db.CreateSession(sess)
	h.setSessionCookie(w, tok)
	h.db.Audit("login", user.Username, "", clientIP(r))
	jsonOK(w, map[string]any{"username": user.Username, "role": user.Role})
}

func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.RegistrationOpen {
		jsonErr(w, 403, "registration is closed")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid request")
		return
	}
	body.Username = regexp.MustCompile(`[^\w.\-]`).ReplaceAllString(strings.TrimSpace(body.Username), "")
	if body.Username == "" || len(body.Password) < 6 {
		jsonErr(w, 400, "username required; password must be ≥ 6 chars")
		return
	}
	existing, _ := h.db.GetUser(body.Username)
	if existing != nil {
		jsonErr(w, 409, "username already taken")
		return
	}
	hash, err := HashPassword(body.Password)
	if err != nil {
		jsonErr(w, 500, "internal error")
		return
	}
	h.db.CreateUser(User{Username: body.Username, PwHash: hash, Role: RoleUser, CreatedAt: time.Now()})
	h.db.Audit("register", body.Username, "", clientIP(r))

	tok := NewToken()
	h.db.CreateSession(Session{Token: tok, Username: body.Username, Role: RoleUser, ExpiresAt: time.Now().Add(sessionTTL)})
	h.setSessionCookie(w, tok)
	jsonOK(w, map[string]any{"username": body.Username, "role": "user"})
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		h.db.DeleteSession(c.Value)
	}
	h.clearSessionCookie(w)
	jsonOK(w, nil)
}

func (h *Handlers) Session(w http.ResponseWriter, r *http.Request) {
	s := h.resolveSession(r)
	if s == nil {
		jsonOK(w, map[string]any{
			"authenticated":     false,
			"registration_open": h.cfg.RegistrationOpen,
		})
		return
	}
	user, _ := h.db.GetUser(s.Username)
	avatar := ""
	if user != nil {
		avatar = user.Avatar
	}
	var quotaUsed int64
	if h.cfg.QuotaBytes > 0 {
		paths, _ := h.db.GetFileMetaForUser(s.Username)
		quotaUsed = h.store.DiskUsageForPaths(paths)
	}
	jsonOK(w, map[string]any{
		"authenticated":     true,
		"username":          s.Username,
		"role":              s.Role,
		"avatar":            avatar,
		"quota_bytes":       h.cfg.QuotaBytes,
		"quota_used":        quotaUsed,
		"registration_open": h.cfg.RegistrationOpen,
	})
}

// ─── Files ────────────────────────────────────────────────────────────────────

func (h *Handlers) ListFiles(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	rel := r.URL.Query().Get("path")
	entries, err := h.store.List(rel)
	if err != nil {
		jsonErr(w, 404, "directory not found")
		return
	}

	var files, dirs []FileEntry
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if e.IsDir() {
			dirs = append(dirs, FileEntry{
				Name:      e.Name(),
				Type:      "dir",
				Mtime:     fi.ModTime().Unix(),
				CanModify: s.IsAdmin(),
			})
		} else {
			entryRel := e.Name()
			if rel != "" {
				entryRel = rel + "/" + e.Name()
			}
			owner, _ := h.db.GetFileMeta(entryRel)
			files = append(files, FileEntry{
				Name:      e.Name(),
				Rel:       entryRel,
				Type:      "file",
				Size:      fi.Size(),
				Mtime:     fi.ModTime().Unix(),
				Owner:     owner,
				CanModify: s.IsAdmin() || owner == s.Username,
				Category:  CategoryFromExt(e.Name()),
				MimeType:  GuessMime(e.Name()),
			})
		}
	}
	jsonOK(w, map[string]any{"path": rel, "dirs": dirs, "files": files})
}

func (h *Handlers) Upload(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	r.Body = http.MaxBytesReader(w, r.Body, h.cfg.MaxUploadBytes+65536)

	folderRel := r.URL.Query().Get("path")
	if _, err := h.store.ResolveDir(folderRel); err != nil {
		jsonErr(w, 400, "invalid upload path")
		return
	}

	// Quota check
	if h.cfg.QuotaBytes > 0 {
		paths, _ := h.db.GetFileMetaForUser(s.Username)
		used := h.store.DiskUsageForPaths(paths)
		if used >= h.cfg.QuotaBytes {
			jsonErr(w, 413, fmt.Sprintf("quota exceeded (%s limit)", fmtBytes(h.cfg.QuotaBytes)))
			return
		}
	}

	mr, err := r.MultipartReader()
	if err != nil {
		jsonErr(w, 400, "expected multipart/form-data")
		return
	}

	var uploaded []string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			jsonErr(w, 400, "multipart error: "+err.Error())
			return
		}
		if part.FormName() != "file" {
			part.Close()
			continue
		}
		name := SanitizeFilename(part.FileName())
		destRel := name
		if folderRel != "" {
			destRel = folderRel + "/" + name
		}
		n, err := h.store.WriteFile(destRel, part, h.cfg.MaxUploadBytes)
		part.Close()
		if err != nil {
			jsonErr(w, 413, "upload failed: "+err.Error())
			return
		}
		h.db.SetFileMeta(destRel, s.Username)
		h.db.Audit("upload", s.Username, fmt.Sprintf("file=%s size=%d", destRel, n), clientIP(r))
		uploaded = append(uploaded, name)
		h.hub.Broadcast("files.changed", map[string]any{"path": folderRel})
	}
	jsonOK(w, map[string]any{"uploaded": uploaded})
}

func (h *Handlers) DeleteFile(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")

	// Check ownership
	if !s.IsAdmin() {
		owner, _ := h.db.GetFileMeta(rel)
		if owner != s.Username {
			jsonErr(w, 403, "you don't own this file")
			return
		}
	}

	if err := h.store.Delete(rel); err != nil {
		jsonErr(w, 404, "not found")
		return
	}
	h.db.DeleteFileMeta(rel)
	h.db.Audit("delete", s.Username, "path="+rel, clientIP(r))
	h.hub.Broadcast("files.changed", map[string]any{"path": filepath.Dir(rel)})
	jsonOK(w, nil)
}

func (h *Handlers) Rename(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	var body struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid request")
		return
	}
	body.Old = strings.TrimPrefix(body.Old, "/")
	newName := SanitizeFilename(body.New)

	if !s.IsAdmin() {
		owner, _ := h.db.GetFileMeta(body.Old)
		if owner != s.Username {
			jsonErr(w, 403, "forbidden")
			return
		}
	}

	newRel, err := h.store.Rename(body.Old, newName)
	if err != nil {
		httpErrFromErr(w, err)
		return
	}
	h.db.RenameFileMeta(body.Old, newRel)
	h.db.Audit("rename", s.Username, fmt.Sprintf("old=%s new=%s", body.Old, newRel), clientIP(r))
	h.hub.Broadcast("files.changed", map[string]any{"path": filepath.Dir(body.Old)})
	jsonOK(w, map[string]any{"name": newName, "rel": newRel})
}

func (h *Handlers) Mkdir(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	var body struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid request")
		return
	}
	name := SanitizeFilename(body.Name)
	if name == "" {
		jsonErr(w, 400, "invalid folder name")
		return
	}
	if err := h.store.Mkdir(strings.TrimPrefix(body.Path, "/"), name); err != nil {
		httpErrFromErr(w, err)
		return
	}
	h.db.Audit("mkdir", s.Username, "name="+name, clientIP(r))
	h.hub.Broadcast("files.changed", map[string]any{"path": body.Path})
	jsonOK(w, map[string]any{"name": name})
}

func (h *Handlers) Move(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	var body struct {
		Src    string `json:"src"`
		DstDir string `json:"dst_dir"`
		Copy   bool   `json:"copy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid request")
		return
	}
	body.Src = strings.TrimPrefix(body.Src, "/")

	if !body.Copy && !s.IsAdmin() {
		owner, _ := h.db.GetFileMeta(body.Src)
		if owner != s.Username {
			jsonErr(w, 403, "forbidden")
			return
		}
	}

	if err := h.store.Move(body.Src, strings.TrimPrefix(body.DstDir, "/"), body.Copy); err != nil {
		httpErrFromErr(w, err)
		return
	}
	action := "move"
	if body.Copy {
		action = "copy"
	}
	h.db.Audit(action, s.Username, fmt.Sprintf("src=%s dst=%s", body.Src, body.DstDir), clientIP(r))
	h.hub.Broadcast("files.changed", map[string]any{"path": body.DstDir})
	jsonOK(w, nil)
}

func (h *Handlers) Bulk(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	var body struct {
		Action string   `json:"action"`
		Files  []string `json:"files"`
		DstDir string   `json:"dst_dir,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid request")
		return
	}

	switch body.Action {
	case "delete":
		var deleted int
		var errs []string
		for _, rel := range body.Files {
			rel = strings.TrimPrefix(rel, "/")
			if !s.IsAdmin() {
				owner, _ := h.db.GetFileMeta(rel)
				if owner != s.Username {
					errs = append(errs, rel+": forbidden")
					continue
				}
			}
			if err := h.store.Delete(rel); err != nil {
				errs = append(errs, rel+": "+err.Error())
				continue
			}
			h.db.DeleteFileMeta(rel)
			deleted++
		}
		h.db.Audit("bulk_delete", s.Username, fmt.Sprintf("count=%d", deleted), clientIP(r))
		h.hub.Broadcast("files.changed", nil)
		jsonOK(w, map[string]any{"deleted": deleted, "errors": errs})

	case "zip":
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		var added int
		for _, rel := range body.Files {
			rel = strings.TrimPrefix(rel, "/")
			abs, err := h.store.ResolveFile(rel)
			if err != nil {
				continue
			}
			fw, err := zw.Create(filepath.Base(abs))
			if err != nil {
				continue
			}
			f, err := os.Open(abs)
			if err != nil {
				continue
			}
			io.Copy(fw, f)
			f.Close()
			added++
		}
		zw.Close()
		if added == 0 {
			jsonErr(w, 400, "no valid files")
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="selection.zip"`)
		w.Header().Set("Content-Type", "application/zip")
		w.Write(buf.Bytes())

	default:
		jsonErr(w, 400, "unknown action: "+body.Action)
	}
}

func (h *Handlers) Search(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	pathRel := r.URL.Query().Get("path")
	typeFilter := r.URL.Query().Get("type")
	if q == "" {
		jsonErr(w, 400, "q required")
		return
	}

	baseDir, err := h.store.ResolveDir(pathRel)
	if err != nil {
		jsonErr(w, 400, "invalid path")
		return
	}

	var results []FileEntry
	filepath.WalkDir(baseDir, func(abs string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() || len(results) >= 200 {
			return nil
		}
		if !strings.Contains(strings.ToLower(de.Name()), q) {
			return nil
		}
		cat := CategoryFromExt(de.Name())
		if typeFilter != "" && cat != typeFilter {
			return nil
		}
		rel := h.store.RelPath(abs)
		fi, _ := de.Info()
		var size int64
		var mtime int64
		if fi != nil {
			size = fi.Size()
			mtime = fi.ModTime().Unix()
		}
		owner, _ := h.db.GetFileMeta(rel)
		results = append(results, FileEntry{
			Name:      de.Name(),
			Rel:       rel,
			Type:      "file",
			Size:      size,
			Mtime:     mtime,
			Owner:     owner,
			CanModify: s.IsAdmin() || owner == s.Username,
			Category:  cat,
		})
		return nil
	})

	jsonOK(w, map[string]any{"results": results, "q": q, "total": len(results)})
}

// ─── Downloads & Preview ──────────────────────────────────────────────────────

func (h *Handlers) Download(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	abs, err := h.store.ResolveFile(rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	streamFile(w, r, abs, filepath.Base(abs), false)
}

func (h *Handlers) Preview(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	abs, err := h.store.ResolveFile(rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	streamFile(w, r, abs, filepath.Base(abs), true)
}

func (h *Handlers) TokenDownload(w http.ResponseWriter, r *http.Request) {
	tok := chi.URLParam(r, "token")
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	if !VerifySignedToken(h.cfg.LinkSecret, tok, rel) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	abs, err := h.store.ResolveFile(rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	streamFile(w, r, abs, filepath.Base(abs), false)
}

func (h *Handlers) MakeToken(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	if _, err := h.store.ResolveFile(rel); err != nil {
		http.NotFound(w, r)
		return
	}
	tok := SignToken(h.cfg.LinkSecret, rel)
	encoded := url.PathEscape(rel)
	jsonOK(w, map[string]any{"url": "/t/" + tok + "/" + encoded, "token": tok})
}

func (h *Handlers) ZipFolder(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Query().Get("path"), "/")
	if rel == "" {
		jsonErr(w, 400, "path required")
		return
	}
	abs, err := h.store.ResolveDir(rel)
	if err != nil || abs == h.store.Root() {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zip"`, filepath.Base(abs)))

	zw := zip.NewWriter(w)
	defer zw.Close()
	filepath.WalkDir(abs, func(path string, de os.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(abs, path)
		fw, err := zw.Create(rel)
		if err != nil {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		io.Copy(fw, f)
		return nil
	})
}

func (h *Handlers) ZipInspect(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Query().Get("path"), "/")
	abs, err := h.store.ResolveFile(rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !strings.EqualFold(filepath.Ext(abs), ".zip") {
		jsonErr(w, 400, "only .zip files supported")
		return
	}
	zr, err := zip.OpenReader(abs)
	if err != nil {
		jsonErr(w, 400, "not a valid zip: "+err.Error())
		return
	}
	defer zr.Close()
	type entry struct {
		Name       string `json:"name"`
		Size       uint64 `json:"size"`
		Compressed uint64 `json:"compressed"`
		IsDir      bool   `json:"is_dir"`
	}
	var entries []entry
	for _, f := range zr.File {
		entries = append(entries, entry{
			Name:       f.Name,
			Size:       f.UncompressedSize64,
			Compressed: f.CompressedSize64,
			IsDir:      f.FileInfo().IsDir(),
		})
	}
	jsonOK(w, map[string]any{"path": rel, "entries": entries, "count": len(entries)})
}

// ─── Text editor ─────────────────────────────────────────────────────────────

const maxEditBytes = 2 * 1024 * 1024

func (h *Handlers) EditGet(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	abs, err := h.store.ResolveFile(rel)
	if err != nil {
		jsonErr(w, 404, "not found")
		return
	}
	if !IsEditable(filepath.Base(abs)) {
		jsonErr(w, 400, "file type not editable")
		return
	}
	fi, _ := os.Stat(abs)
	if fi != nil && fi.Size() > maxEditBytes {
		jsonErr(w, 413, fmt.Sprintf("file too large (%s)", fmtBytes(fi.Size())))
		return
	}
	content, err := os.ReadFile(abs)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOK(w, map[string]any{
		"rel":     rel,
		"name":    filepath.Base(abs),
		"content": string(content),
		"size":    len(content),
	})
}

func (h *Handlers) EditPut(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	rel := strings.TrimPrefix(chi.URLParam(r, "*"), "/")
	abs, err := h.store.ResolveFile(rel)
	if err != nil {
		jsonErr(w, 404, "not found")
		return
	}
	if !s.IsAdmin() {
		owner, _ := h.db.GetFileMeta(rel)
		if owner != s.Username {
			jsonErr(w, 403, "forbidden")
			return
		}
	}
	if !IsEditable(filepath.Base(abs)) {
		jsonErr(w, 400, "file type not editable")
		return
	}
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid request")
		return
	}
	if int64(len(body.Content)) > maxEditBytes {
		jsonErr(w, 413, "content too large")
		return
	}
	tmp := abs + ".tmp"
	if err := os.WriteFile(tmp, []byte(body.Content), 0o640); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if err := os.Rename(tmp, abs); err != nil {
		os.Remove(tmp)
		jsonErr(w, 500, err.Error())
		return
	}
	h.db.Audit("edit", s.Username, "file="+rel, clientIP(r))
	jsonOK(w, map[string]any{"size": len(body.Content)})
}

// ─── Share links ──────────────────────────────────────────────────────────────

func (h *Handlers) ShareCreate(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	var body struct {
		Rel      string  `json:"rel"`
		TTLHours float64 `json:"ttl_hours"`
		Password string  `json:"password"`
		MaxHits  *int    `json:"max_hits"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid request")
		return
	}
	rel := strings.TrimPrefix(body.Rel, "/")
	if _, err := h.store.ResolveFile(rel); err != nil {
		jsonErr(w, 404, "file not found")
		return
	}
	if body.TTLHours <= 0 {
		body.TTLHours = 168
	}

	var pwHash string
	if body.Password != "" {
		h, _ := HashPassword(body.Password)
		pwHash = h
	}

	tok := NewToken()[:32]
	share := ShareLink{
		Token:    tok,
		RelPath:  rel,
		Owner:    s.Username,
		PwHash:   pwHash,
		MaxHits:  body.MaxHits,
		ExpiresAt: time.Now().Add(time.Duration(body.TTLHours * float64(time.Hour))),
	}
	if err := h.db.CreateShare(share); err != nil {
		jsonErr(w, 500, "failed to create share")
		return
	}
	h.db.Audit("share_create", s.Username, "rel="+rel, clientIP(r))
	jsonOK(w, map[string]any{"token": tok, "url": "/s/" + tok})
}

func (h *Handlers) ShareList(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	shares, err := h.db.ListShares(s.Username, s.IsAdmin())
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	type shareOut struct {
		Token     string    `json:"token"`
		RelPath   string    `json:"rel"`
		Owner     string    `json:"owner"`
		Hits      int       `json:"hits"`
		MaxHits   *int      `json:"max_hits,omitempty"`
		Protected bool      `json:"protected"`
		ExpiresAt time.Time `json:"expires_at"`
		Expired   bool      `json:"expired"`
	}
	var out []shareOut
	now := time.Now()
	for _, s := range shares {
		out = append(out, shareOut{
			Token:     s.Token,
			RelPath:   s.RelPath,
			Owner:     s.Owner,
			Hits:      s.Hits,
			MaxHits:   s.MaxHits,
			Protected: s.PwHash != "",
			ExpiresAt: s.ExpiresAt,
			Expired:   now.After(s.ExpiresAt),
		})
	}
	jsonOK(w, out)
}

func (h *Handlers) ShareDelete(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	tok := chi.URLParam(r, "token")
	share, _ := h.db.GetShare(tok)
	if share == nil {
		jsonErr(w, 404, "not found")
		return
	}
	if !s.IsAdmin() && share.Owner != s.Username {
		jsonErr(w, 403, "forbidden")
		return
	}
	h.db.DeleteShare(tok)
	jsonOK(w, nil)
}

func (h *Handlers) ShareDownload(w http.ResponseWriter, r *http.Request) {
	tok := chi.URLParam(r, "token")
	share, _ := h.db.GetShare(tok)
	if share == nil || time.Now().After(share.ExpiresAt) {
		http.Error(w, "share link expired or not found", http.StatusGone)
		return
	}
	if share.MaxHits != nil && share.Hits >= *share.MaxHits {
		http.Error(w, "download limit reached", http.StatusGone)
		return
	}
	if share.PwHash != "" {
		pw := r.FormValue("password")
		if pw == "" {
			renderShareGate(w, false)
			return
		}
		if !CheckPassword(pw, share.PwHash) {
			renderShareGate(w, true)
			return
		}
	}
	abs, err := h.store.ResolveFile(share.RelPath)
	if err != nil {
		http.Error(w, "file no longer exists", http.StatusNotFound)
		return
	}
	h.db.IncrementShareHits(tok)
	h.db.Audit("share_download", share.Owner, "token="+tok, clientIP(r))
	streamFile(w, r, abs, filepath.Base(abs), false)
}

// ─── Remote URL fetch ─────────────────────────────────────────────────────────

func (h *Handlers) FetchURL(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid request")
		return
	}
	u, err := url.Parse(strings.TrimSpace(body.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		jsonErr(w, 400, "only http/https URLs supported")
		return
	}
	if isPrivateIP(u.Hostname()) {
		jsonErr(w, 400, "requests to private network addresses are not allowed")
		return
	}

	name := SanitizeFilename(filepath.Base(u.Path))
	if name == "" || name == "upload" {
		name = "download"
	}

	h.fetchMu.Lock()
	// Check for active duplicate
	for _, j := range h.fetchJobs {
		if j.Name == name && j.Status != "done" && j.Status != "failed" && j.Status != "cancelled" {
			h.fetchMu.Unlock()
			jsonErr(w, 409, "already downloading: "+name)
			return
		}
	}
	id := NewToken()[:16]
	ctx, cancel := context.WithCancel(context.Background())
	job := &FetchJob{
		ID:       id,
		Name:     name,
		URL:      body.URL,
		Owner:    s.Username,
		Status:   "starting",
		Category: CategoryFromExt(name),
		cancel:   cancel,
	}
	h.fetchJobs[id] = job
	h.fetchMu.Unlock()

	go h.runFetch(ctx, job)
	h.db.Audit("fetch_start", s.Username, "url="+body.URL, clientIP(r))
	jsonOK(w, map[string]any{"id": id, "name": name})
}

func (h *Handlers) runFetch(ctx context.Context, job *FetchJob) {
	client := &http.Client{Timeout: 0}
	req, _ := http.NewRequestWithContext(ctx, "GET", job.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		h.setJobStatus(job, "failed", err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		h.setJobStatus(job, "failed", fmt.Sprintf("HTTP %d", resp.StatusCode))
		return
	}
	job.Total = resp.ContentLength
	job.Status = "downloading"

	rel := job.Name
	done, err := h.store.WriteFile(rel, &fetchReader{job: job, r: resp.Body}, h.cfg.MaxFetchBytes)
	if err != nil {
		if ctx.Err() != nil {
			h.setJobStatus(job, "cancelled", "")
		} else {
			h.setJobStatus(job, "failed", err.Error())
		}
		return
	}
	h.db.SetFileMeta(rel, job.Owner)
	job.Done = done
	job.Progress = 100
	h.setJobStatus(job, "done", "")
	h.hub.Broadcast("files.changed", nil)
	h.hub.Broadcast("fetch.done", map[string]any{"id": job.ID, "name": job.Name})
}

type fetchReader struct {
	job  *FetchJob
	r    io.Reader
	last time.Time
}

func (fr *fetchReader) Read(p []byte) (int, error) {
	n, err := fr.r.Read(p)
	fr.job.Done += int64(n)
	now := time.Now()
	if now.Sub(fr.last) >= 500*time.Millisecond {
		if fr.job.Total > 0 {
			fr.job.Progress = int(fr.job.Done * 100 / fr.job.Total)
		}
		fr.last = now
	}
	return n, err
}

func (h *Handlers) setJobStatus(job *FetchJob, status, errMsg string) {
	h.fetchMu.Lock()
	defer h.fetchMu.Unlock()
	job.Status = status
	if errMsg != "" {
		job.Error = errMsg
	}
}

func (h *Handlers) FetchProgress(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	h.fetchMu.Lock()
	defer h.fetchMu.Unlock()
	out := map[string]*FetchJob{}
	for id, j := range h.fetchJobs {
		if s.IsAdmin() || j.Owner == s.Username {
			out[id] = j
		}
	}
	jsonOK(w, out)
}

func (h *Handlers) FetchCancel(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	id := chi.URLParam(r, "id")
	h.fetchMu.Lock()
	defer h.fetchMu.Unlock()
	job, ok := h.fetchJobs[id]
	if !ok {
		jsonErr(w, 404, "not found")
		return
	}
	if !s.IsAdmin() && job.Owner != s.Username {
		jsonErr(w, 403, "forbidden")
		return
	}
	job.cancel()
	job.Status = "cancelled"
	jsonOK(w, nil)
}

func (h *Handlers) FetchRetry(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	id := chi.URLParam(r, "id")
	h.fetchMu.Lock()
	old, ok := h.fetchJobs[id]
	h.fetchMu.Unlock()
	if !ok || (old.Status != "failed" && old.Status != "cancelled") {
		jsonErr(w, 400, "job not retryable")
		return
	}
	if !s.IsAdmin() && old.Owner != s.Username {
		jsonErr(w, 403, "forbidden")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	newID := NewToken()[:16]
	job := &FetchJob{
		ID:     newID,
		Name:   old.Name,
		URL:    old.URL,
		Owner:  s.Username,
		Status: "starting",
		cancel: cancel,
	}
	h.fetchMu.Lock()
	h.fetchJobs[newID] = job
	h.fetchMu.Unlock()
	go h.runFetch(ctx, job)
	jsonOK(w, map[string]any{"id": newID})
}

// ─── Torrent ──────────────────────────────────────────────────────────────────

func (h *Handlers) Torrent(w http.ResponseWriter, r *http.Request) {
	// Torrent support requires aria2c in PATH
	jsonErr(w, 501, "torrent support not yet implemented in this build")
}

func (h *Handlers) TorrentProgress(w http.ResponseWriter, r *http.Request) {
	h.torrentMu.Lock()
	defer h.torrentMu.Unlock()
	jsonOK(w, h.torrentJobs)
}

func (h *Handlers) TorrentCancel(w http.ResponseWriter, r *http.Request) {
	jsonErr(w, 501, "not implemented")
}

// ─── API Keys ─────────────────────────────────────────────────────────────────

func (h *Handlers) KeyCreate(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	var body struct {
		Label string `json:"label"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	raw := NewToken()
	key := APIKey{
		Hash:      HashAPIKey(raw),
		Label:     body.Label,
		Username:  s.Username,
		Role:      s.Role,
		CreatedAt: time.Now(),
	}
	h.db.CreateAPIKey(key)
	h.db.Audit("apikey_create", s.Username, "label="+body.Label, clientIP(r))
	jsonOK(w, map[string]any{
		"key":   raw,
		"label": body.Label,
		"note":  "Save this key — it will not be shown again.",
	})
}

func (h *Handlers) KeyList(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	keys, _ := h.db.ListAPIKeys(s.Username, s.IsAdmin())
	type out struct {
		Prefix    string    `json:"prefix"`
		Label     string    `json:"label"`
		Username  string    `json:"user"`
		CreatedAt time.Time `json:"created_at"`
	}
	var result []out
	for _, k := range keys {
		prefix := k.Hash
		if len(prefix) > 12 {
			prefix = prefix[:12] + "…"
		}
		result = append(result, out{Prefix: prefix, Label: k.Label, Username: k.Username, CreatedAt: k.CreatedAt})
	}
	jsonOK(w, result)
}

func (h *Handlers) KeyDelete(w http.ResponseWriter, r *http.Request) {
	s := SessionFrom(r)
	prefix := chi.URLParam(r, "prefix")
	n, err := h.db.DeleteAPIKeyByPrefix(prefix, s.Username, s.IsAdmin())
	if err != nil || n == 0 {
		jsonErr(w, 404, "not found")
		return
	}
	h.db.Audit("apikey_delete", s.Username, "prefix="+prefix, clientIP(r))
	jsonOK(w, map[string]any{"deleted": n})
}

// ─── Admin ────────────────────────────────────────────────────────────────────

func (h *Handlers) AdminListUsers(w http.ResponseWriter, r *http.Request) {
	users, _ := h.db.ListUsers()
	type userOut struct {
		Username  string    `json:"username"`
		Role      Role      `json:"role"`
		Disabled  bool      `json:"disabled"`
		CreatedAt time.Time `json:"created_at"`
	}
	var out []userOut
	for _, u := range users {
		out = append(out, userOut{u.Username, u.Role, u.Disabled, u.CreatedAt})
	}
	jsonOK(w, out)
}

func (h *Handlers) AdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	actor := SessionFrom(r)
	username := chi.URLParam(r, "username")
	if username == actor.Username {
		jsonErr(w, 400, "cannot modify yourself this way")
		return
	}
	existing, _ := h.db.GetUser(username)
	if existing == nil {
		jsonErr(w, 404, "user not found")
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid request")
		return
	}
	updates := map[string]any{}
	if pw, ok := body["password"].(string); ok {
		if len(pw) < 6 {
			jsonErr(w, 400, "password must be ≥ 6 chars")
			return
		}
		hash, _ := HashPassword(pw)
		updates["pw_hash"] = hash
	}
	if disabled, ok := body["disabled"].(bool); ok {
		updates["disabled"] = boolInt(disabled)
	}
	if role, ok := body["role"].(string); ok {
		if role != "user" && role != "admin" {
			jsonErr(w, 400, "invalid role")
			return
		}
		if role == "user" && existing.Role == RoleAdmin {
			admins, _ := h.db.CountAdmins()
			if admins <= 1 {
				jsonErr(w, 400, "cannot demote the last admin")
				return
			}
		}
		updates["role"] = role
	}
	if len(updates) == 0 {
		jsonErr(w, 400, "nothing to update")
		return
	}
	h.db.UpdateUser(username, updates)
	h.db.DeleteUserSessions(username)
	h.db.Audit("user_update", actor.Username, "target="+username, clientIP(r))
	jsonOK(w, nil)
}

func (h *Handlers) AdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	actor := SessionFrom(r)
	username := chi.URLParam(r, "username")
	if username == actor.Username {
		jsonErr(w, 400, "cannot delete yourself")
		return
	}
	existing, _ := h.db.GetUser(username)
	if existing == nil || existing.Role == RoleAdmin {
		jsonErr(w, 404, "not found or protected")
		return
	}
	h.db.DeleteUser(username)
	h.db.Audit("user_delete", actor.Username, "target="+username, clientIP(r))
	jsonOK(w, nil)
}

func (h *Handlers) AdminRevokeSession(w http.ResponseWriter, r *http.Request) {
	actor := SessionFrom(r)
	username := chi.URLParam(r, "username")
	n, _ := h.db.DeleteUserSessions(username)
	h.db.Audit("session_revoke", actor.Username, fmt.Sprintf("target=%s killed=%d", username, n), clientIP(r))
	jsonOK(w, map[string]any{"killed": n})
}

func (h *Handlers) AdminStats(w http.ResponseWriter, r *http.Request) {
	users, _ := h.db.ListUsers()
	var totalSize int64
	var fileCount int
	filepath.WalkDir(h.store.Root(), func(_ string, de os.DirEntry, err error) error {
		if err == nil && !de.IsDir() {
			fileCount++
			fi, _ := de.Info()
			if fi != nil {
				totalSize += fi.Size()
			}
		}
		return nil
	})

	var adminCount, disabledCount int
	for _, u := range users {
		if u.Role == RoleAdmin {
			adminCount++
		}
		if u.Disabled {
			disabledCount++
		}
	}

	jsonOK(w, map[string]any{
		"files":   map[string]any{"count": fileCount, "size_bytes": totalSize},
		"users":   map[string]any{"total": len(users), "admins": adminCount, "disabled": disabledCount},
		"storage": map[string]any{"downloads_dir": h.store.Root()},
	})
}

func (h *Handlers) AdminAudit(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("n")); err == nil && n > 0 {
		if n > 2000 {
			n = 2000
		}
		limit = n
	}
	entries, _ := h.db.GetAuditLog(limit)
	jsonOK(w, entries)
}

func (h *Handlers) FlagsGet(w http.ResponseWriter, r *http.Request) {
	flags, _ := h.db.GetFlags()
	jsonOK(w, flags)
}

func (h *Handlers) FlagsSet(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, 400, "invalid request")
		return
	}
	for k, v := range body {
		h.db.SetFlag(k, v)
	}
	flags, _ := h.db.GetFlags()
	jsonOK(w, flags)
}

func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{"status": "ok", "time": time.Now().Unix()})
}

// ─── File streaming ───────────────────────────────────────────────────────────

func streamFile(w http.ResponseWriter, r *http.Request, abs, name string, inline bool) {
	f, err := os.Open(abs)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		http.Error(w, "stat error", 500)
		return
	}
	disp := "attachment"
	if inline {
		disp = "inline"
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`%s; filename="%s"`, disp, name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

// ─── Share gate HTML ──────────────────────────────────────────────────────────

func renderShareGate(w http.ResponseWriter, wrongPassword bool) {
	errMsg := ""
	if wrongPassword {
		errMsg = `<p style="color:#f87171">Incorrect password.</p>`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset=utf-8><title>Protected Download</title>
<style>body{font-family:system-ui;max-width:360px;margin:80px auto;padding:1rem;background:#0c0e14;color:#e8eaf2}
input{width:100%%;padding:.5rem;margin:.5rem 0;box-sizing:border-box;background:#191d28;border:1px solid #252a38;color:#e8eaf2;border-radius:4px}
button{padding:.6rem 1.4rem;background:#4a9eff;color:#fff;border:none;border-radius:4px;cursor:pointer}</style></head>
<body><h2>🔒 Password required</h2>%s
<form method=post><input type=password name=password placeholder="Enter password" autofocus>
<button type=submit>Download</button></form></body></html>`, errMsg)
}

// ─── Response helpers ─────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	if data == nil {
		w.Write([]byte(`{"ok":true}`))
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": data})
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}

func httpErrFromErr(w http.ResponseWriter, err error) {
	type statusCoder interface{ StatusCode() int }
	if sc, ok := err.(statusCoder); ok {
		jsonErr(w, sc.StatusCode(), err.Error())
		return
	}
	if os.IsNotExist(err) {
		jsonErr(w, 404, "not found")
		return
	}
	slog.Error("handler error", "err", err)
	jsonErr(w, 500, err.Error())
}

func fmtBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// multipart helper – needed because chi eats the wildcard
func getMultipartReader(r *http.Request, maxSize int64) (*multipart.Reader, error) {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/") {
		return nil, fmt.Errorf("expected multipart content-type")
	}
	return r.MultipartReader()
}
