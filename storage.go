package main

import (
	"io"
	"mime"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Storage provides a safe, sandboxed view of the downloads directory.
// All paths are validated to prevent traversal attacks.
type Storage struct {
	root string
}

// NewStorage creates a Storage rooted at dir.
func NewStorage(dir string) *Storage {
	abs, _ := filepath.Abs(dir)
	return &Storage{root: abs}
}

// Root returns the absolute root path.
func (s *Storage) Root() string { return s.root }

// Resolve returns the absolute path for a relative path within the storage root,
// or an error if the path escapes the root.
func (s *Storage) Resolve(rel string) (string, error) {
	rel = strings.TrimPrefix(rel, "/")
	abs := filepath.Join(s.root, filepath.FromSlash(rel))
	abs, err := filepath.Abs(abs)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(abs, s.root+string(os.PathSeparator)) && abs != s.root {
		return "", &PathError{Rel: rel, Msg: "path outside storage root"}
	}
	return abs, nil
}

// ResolveFile returns the absolute path only if it resolves to an existing regular file.
func (s *Storage) ResolveFile(rel string) (string, error) {
	abs, err := s.Resolve(rel)
	if err != nil {
		return "", err
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", &PathError{Rel: rel, Msg: "not a regular file"}
	}
	return abs, nil
}

// ResolveDir returns the absolute path only if it resolves to an existing directory.
func (s *Storage) ResolveDir(rel string) (string, error) {
	if rel == "" || rel == "." || rel == "/" {
		return s.root, nil
	}
	abs, err := s.Resolve(rel)
	if err != nil {
		return "", err
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", &PathError{Rel: rel, Msg: "not a directory"}
	}
	return abs, nil
}

// List returns the entries of a directory.
func (s *Storage) List(rel string) ([]os.DirEntry, error) {
	abs, err := s.ResolveDir(rel)
	if err != nil {
		return nil, err
	}
	return os.ReadDir(abs)
}

// WriteFile atomically writes data to rel path, stripping execute bits.
func (s *Storage) WriteFile(rel string, r io.Reader, maxBytes int64) (int64, error) {
	abs, err := s.Resolve(rel)
	if err != nil {
		return 0, err
	}
	tmp := abs + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, io.LimitReader(r, maxBytes+1))
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return 0, err
	}
	if n > maxBytes {
		os.Remove(tmp)
		return 0, ErrFileTooLarge
	}
	if err := os.Rename(tmp, abs); err != nil {
		os.Remove(tmp)
		return 0, err
	}
	os.Chmod(abs, 0o640)
	return n, nil
}

// Delete removes a file or directory.
func (s *Storage) Delete(rel string) error {
	abs, err := s.Resolve(rel)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return os.RemoveAll(abs)
	}
	return os.Remove(abs)
}

// Rename renames src to a new name within the same parent directory.
func (s *Storage) Rename(srcRel, newName string) (string, error) {
	srcAbs, err := s.Resolve(srcRel)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(srcAbs); err != nil {
		return "", err
	}
	dir := filepath.Dir(srcAbs)
	dstAbs := filepath.Join(dir, newName)
	if !strings.HasPrefix(dstAbs, s.root) {
		return "", &PathError{Rel: newName, Msg: "invalid destination"}
	}
	if _, err := os.Lstat(dstAbs); err == nil {
		return "", ErrAlreadyExists
	}
	if err := os.Rename(srcAbs, dstAbs); err != nil {
		return "", err
	}
	dstRel, _ := filepath.Rel(s.root, dstAbs)
	return filepath.ToSlash(dstRel), nil
}

// Move moves or copies src into dstDir.
func (s *Storage) Move(srcRel, dstDirRel string, copy bool) error {
	srcAbs, err := s.Resolve(srcRel)
	if err != nil {
		return err
	}
	dstDirAbs, err := s.ResolveDir(dstDirRel)
	if err != nil {
		return err
	}
	name := filepath.Base(srcAbs)
	dstAbs := filepath.Join(dstDirAbs, name)
	if _, err := os.Lstat(dstAbs); err == nil {
		return ErrAlreadyExists
	}
	if copy {
		return copyPath(srcAbs, dstAbs)
	}
	return os.Rename(srcAbs, dstAbs)
}

// Mkdir creates a new directory at rel path.
func (s *Storage) Mkdir(parentRel, name string) error {
	parentAbs, err := s.ResolveDir(parentRel)
	if err != nil {
		return err
	}
	newDir := filepath.Join(parentAbs, name)
	if !strings.HasPrefix(newDir, s.root) {
		return &PathError{Rel: name, Msg: "invalid directory name"}
	}
	if _, err := os.Lstat(newDir); err == nil {
		return ErrAlreadyExists
	}
	return os.Mkdir(newDir, 0o750)
}

// RelPath converts an absolute path back to a root-relative slash path.
func (s *Storage) RelPath(abs string) string {
	rel, _ := filepath.Rel(s.root, abs)
	return filepath.ToSlash(rel)
}

// DiskUsageForPaths returns the total size of a list of root-relative paths.
func (s *Storage) DiskUsageForPaths(rels []string) int64 {
	var total int64
	for _, rel := range rels {
		abs, err := s.Resolve(rel)
		if err != nil {
			continue
		}
		fi, err := os.Lstat(abs)
		if err == nil && fi.Mode().IsRegular() {
			total += fi.Size()
		}
	}
	return total
}

// ─── Filename sanitization ───────────────────────────────────────────────────

var (
	safeNameRe  = regexp.MustCompile(`[^\w.\-+ ]`)
	doubleDotRe = regexp.MustCompile(`\.{2,}`)
)

// SanitizeFilename returns a safe filename, stripping path components and unsafe chars.
func SanitizeFilename(name string) string {
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "\x00", "")
	name = safeNameRe.ReplaceAllString(name, "_")
	name = doubleDotRe.ReplaceAllString(name, ".")
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return "upload"
	}
	return name
}

// ─── MIME / category helpers ─────────────────────────────────────────────────

var extCategories = map[string]string{
	"zip": "archive", "gz": "archive", "xz": "archive", "zst": "archive",
	"tar": "archive", "7z": "archive", "bz2": "archive", "rar": "archive",
	"jpg": "image", "jpeg": "image", "png": "image", "gif": "image",
	"webp": "image", "svg": "image", "avif": "image", "ico": "image", "bmp": "image",
	"mp4": "video", "mkv": "video", "avi": "video", "mov": "video",
	"webm": "video", "flv": "video", "m4v": "video", "ts": "video",
	"mp3": "audio", "flac": "audio", "aac": "audio", "wav": "audio",
	"ogg": "audio", "m4a": "audio", "opus": "audio",
	"txt": "doc", "md": "doc", "log": "doc", "json": "doc", "xml": "doc",
	"yaml": "doc", "yml": "doc", "toml": "doc", "cfg": "doc", "py": "doc",
	"js": "doc", "html": "doc", "css": "doc", "pdf": "doc",
	"csv": "doc", "sh": "doc", "go": "doc", "rs": "doc",
}

var editableExts = map[string]bool{
	"txt": true, "md": true, "log": true, "json": true, "yaml": true,
	"yml": true, "toml": true, "cfg": true, "ini": true, "conf": true,
	"py": true, "js": true, "ts": true, "html": true, "css": true,
	"xml": true, "csv": true, "env": true, "sh": true, "go": true,
	"rs": true, "gitignore": true,
}

func CategoryFromExt(name string) string {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	if c, ok := extCategories[ext]; ok {
		return c
	}
	return "other"
}

func IsEditable(name string) bool {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	return editableExts[ext]
}

func GuessMime(name string) string {
	ct := mime.TypeByExtension(filepath.Ext(name))
	if ct == "" {
		return "application/octet-stream"
	}
	return ct
}

// ─── File copy helper ────────────────────────────────────────────────────────

func copyPath(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return copyDir(src, dst)
	}
	return copyFile(src, dst)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o750); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		if err := copyPath(s, d); err != nil {
			return err
		}
	}
	return nil
}

// ─── Errors ───────────────────────────────────────────────────────────────────

type PathError struct {
	Rel string
	Msg string
}

func (e *PathError) Error() string { return e.Msg + ": " + e.Rel }

var (
	ErrFileTooLarge = &appError{code: 413, msg: "file too large"}
	ErrAlreadyExists = &appError{code: 409, msg: "name already exists"}
	ErrNotFound      = &appError{code: 404, msg: "not found"}
	ErrForbidden     = &appError{code: 403, msg: "forbidden"}
)

type appError struct {
	code int
	msg  string
}

func (e *appError) Error() string { return e.msg }
func (e *appError) StatusCode() int { return e.code }
