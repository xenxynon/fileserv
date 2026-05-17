package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "fsid"
	sessionTTL        = 24 * time.Hour
)

// ─── Password ────────────────────────────────────────────────────────────────

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func CheckPassword(pw, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// ─── Session tokens ──────────────────────────────────────────────────────────

func NewToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ─── Signed download tokens ──────────────────────────────────────────────────

func SignToken(secret []byte, rel string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(rel))
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifySignedToken(secret []byte, tok, rel string) bool {
	expected := SignToken(secret, rel)
	return hmac.Equal([]byte(tok), []byte(expected))
}

// ─── API key hashing ─────────────────────────────────────────────────────────

func HashAPIKey(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// ─── Auth context ────────────────────────────────────────────────────────────

type ctxKey int

const sessionKey ctxKey = 0

func SessionFrom(r *http.Request) *Session {
	if v := r.Context().Value(sessionKey); v != nil {
		return v.(*Session)
	}
	return nil
}

// ─── Middleware ──────────────────────────────────────────────────────────────

func (h *Handlers) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := h.resolveSession(r)
		if s == nil {
			if isAPIPath(r.URL.Path) {
				jsonErr(w, http.StatusUnauthorized, "unauthorized")
			} else {
				http.Redirect(w, r, "/", http.StatusFound)
			}
			return
		}
		ctx := r.Context()
		ctx = setContext(ctx, sessionKey, s)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *Handlers) AdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := SessionFrom(r)
		if s == nil || !s.IsAdmin() {
			jsonErr(w, http.StatusForbidden, "admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// resolveSession checks cookie and Bearer token, returning the validated session.
func (h *Handlers) resolveSession(r *http.Request) *Session {
	// Cookie session
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if s, err := h.db.GetSession(cookie.Value); err == nil && s != nil {
			return s
		}
	}

	// Bearer token (API key)
	raw := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		raw = strings.TrimSpace(auth[7:])
	}
	if raw == "" {
		raw = r.URL.Query().Get("api_key")
	}
	if raw != "" {
		if k, err := h.db.GetAPIKey(HashAPIKey(raw)); err == nil && k != nil {
			return &Session{
				Token:     raw,
				Username:  k.Username,
				Role:      k.Role,
				ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
			}
		}
	}
	return nil
}

func (h *Handlers) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handlers) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ─── Security headers ─────────────────────────────────────────────────────────

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// ─── Rate limiter (per-IP token bucket) ──────────────────────────────────────

type rateBucket struct {
	mu      sync.Mutex
	buckets map[string]*ipBucket
}

type ipBucket struct {
	hits []time.Time
}

var globalRateLimiter = &rateBucket{buckets: map[string]*ipBucket{}}

const (
	rateLimitWindow   = 60 * time.Second
	rateLimitMaxLogin = 10  // login attempts per window
	rateLimitMaxAPI   = 300 // general API calls per window
)

func RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/auth/") {
			next.ServeHTTP(w, r)
			return
		}
		ip := clientIP(r)
		if !globalRateLimiter.allow(ip, rateLimitMaxLogin) {
			jsonErr(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rb *rateBucket) allow(ip string, max int) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	now := time.Now()
	b, ok := rb.buckets[ip]
	if !ok {
		b = &ipBucket{}
		rb.buckets[ip] = b
	}
	cutoff := now.Add(-rateLimitWindow)
	valid := b.hits[:0]
	for _, t := range b.hits {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	b.hits = valid
	if len(b.hits) >= max {
		return false
	}
	b.hits = append(b.hits, now)
	return true
}

// ─── SSRF protection ─────────────────────────────────────────────────────────

var privateNets = func() []*net.IPNet {
	cidrs := []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10", "0.0.0.0/8",
	}
	var out []*net.IPNet
	for _, cidr := range cidrs {
		_, n, _ := net.ParseCIDR(cidr)
		out = append(out, n)
	}
	return out
}()

func isPrivateIP(host string) bool {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return true // treat resolution failures as unsafe
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return true
		}
		for _, net := range privateNets {
			if net.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.SplitN(fwd, ",", 2)[0]
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func isAPIPath(path string) bool {
	return strings.HasPrefix(path, "/api/") ||
		strings.HasPrefix(path, "/dl/") ||
		strings.HasPrefix(path, "/preview/") ||
		strings.HasPrefix(path, "/ws")
}
