# fileserv

A ground-up rewrite of the original Python/aiohttp file server.
Clean Go backend, modern single-file SPA frontend, zero external runtime dependencies.

---

## What changed

| Old | New |
|---|---|
| Python + aiohttp | Go 1.22 + chi router |
| JSON flat-files | SQLite via `modernc.org/sqlite` (pure Go, no CGO) |
| In-memory sessions (dict) | SQLite-backed sessions with automatic expiry |
| Raw HTML templates | Reactive SPA (vanilla JS, no build step) |
| Orange accent, dense rows | Cobalt + Graphite design, sidebar layout |
| Monolithic `web.py` | Split: `main`, `config`, `models`, `auth`, `db`, `storage`, `handlers`, `ws` |
| URL-edit navigation | Breadcrumb + left folder tree |
| No drag-drop from anywhere | Global drag-drop landing zone |
| Polling for progress | WebSocket events + polling hybrid |
| Ad-hoc MIME handling | Clean abstraction with path traversal prevention |
| No signed tokens | HMAC-SHA256 signed download URLs |
| bcrypt sessions | bcrypt passwords + HMAC session tokens in httpOnly cookies |
| No rate limiting | Per-IP token bucket for auth endpoints |
| Shell dependencies | Pure Go (no subprocess calls) |

---

## Stack

```
backend   Go 1.22 · chi · modernc.org/sqlite · golang.org/x/crypto
frontend  Vanilla JS SPA (Syne + JetBrains Mono fonts via Google Fonts)
database  SQLite (single file, WAL mode)
deploy    Docker + optional Caddy or Nginx
```

---

## Quick start

### Binary (local dev)

```bash
# 1. Clone / unzip the project
cd fileserv-rewrite

# 2. Pull dependencies and generate go.sum
go mod tidy

# 3. Copy and edit config
cp .env.example .env
# At minimum set ADMIN_PASS and LINK_SECRET

# 4. Run
source .env   # or export vars manually
go run .

# Server starts on http://localhost:8080
# Login with: admin / <your ADMIN_PASS>
```

### Docker (recommended for production)

```bash
cp .env.example .env
# Edit .env: set ADMIN_PASS, LINK_SECRET, COOKIE_SECURE=true

# Plain HTTP (e.g. behind existing proxy)
docker compose up -d

# With Caddy (auto-HTTPS) — edit Caddyfile domain first
docker compose --profile caddy up -d
```

### Build binary only

```bash
go mod tidy
go build -ldflags="-s -w" -o fileserv .
./fileserv
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Listen port |
| `DATA_DIR` | `./data` | SQLite DB and metadata root |
| `DOWNLOADS_DIR` | `./data/files` | Root of served files |
| `ADMIN_PASS` | *(empty)* | Bootstrap admin password. If empty, no admin is created. |
| `LINK_SECRET` | *(random)* | HMAC secret for signed URLs. **Set this** — random means tokens break on restart. |
| `MAX_UPLOAD_MB` | `2048` | Max single upload size |
| `MAX_FETCH_MB` | `4096` | Max remote fetch size |
| `QUOTA_MB` | `0` | Per-user quota in MB (0 = unlimited) |
| `MAX_SESSIONS_PER_USER` | `10` | Oldest session evicted when exceeded |
| `COOKIE_SECURE` | `false` | Set `true` when behind HTTPS |
| `REGISTRATION_OPEN` | `true` | Allow self-registration |
| `WEBHOOK_URL` | *(empty)* | Optional webhook for events |

---

## API overview

All endpoints under `/api/*` return `{ "ok": true, "data": … }` or
`{ "ok": false, "error": "…" }`.

Authentication: session cookie **or** `Authorization: Bearer <api_key>` header
**or** `?api_key=<key>` query param.

### Auth
```
POST  /api/auth/login          { username, password }
POST  /api/auth/register       { username, password }
POST  /api/auth/logout
GET   /api/auth/session
```

### Files
```
GET   /api/files?path=         List directory
POST  /api/files/upload        multipart/form-data, ?path= for target dir
DELETE /api/files/*rel         Delete file or directory
POST  /api/files/rename        { old, new }
POST  /api/files/mkdir         { path, name }
POST  /api/files/move          { src, dst_dir, copy? }
POST  /api/files/bulk          { action: "delete"|"zip", files: [...] }
GET   /api/files/search?q=     Full-tree filename search
GET   /api/files/zip?path=     Download directory as ZIP
GET   /api/files/zip-inspect?path=  List ZIP contents
GET   /api/files/edit/*rel     Get file content (text files only)
PUT   /api/files/edit/*rel     { content } Save file
GET   /api/files/token/*rel    Generate signed download token
```

### Downloads
```
GET   /dl/*rel                 Attachment download (requires auth)
GET   /preview/*rel            Inline preview (requires auth)
GET   /t/{token}/*rel          Signed token download (no auth needed)
```

### Remote fetch
```
POST  /api/fetch               { url }  Start background download
GET   /api/fetch               List all jobs
DELETE /api/fetch/{id}         Cancel job
POST  /api/fetch/{id}/retry    Retry failed/cancelled job
```

### Share links
```
POST  /api/share               { rel, ttl_hours, password?, max_hits? }
GET   /api/share               List my shares (admin sees all)
DELETE /api/share/{token}      Delete share
GET   /s/{token}               Public share download (may prompt for password)
POST  /s/{token}               Password submit for protected share
```

### API keys
```
POST  /api/keys                { label? }  Create key (shown once)
GET   /api/keys                List keys (hashed prefixes only)
DELETE /api/keys/{prefix}      Delete by hash prefix
```

### Admin
```
GET   /api/admin/users
PATCH /api/admin/users/{u}     { password?, role?, disabled? }
DELETE /api/admin/users/{u}
POST  /api/admin/users/{u}/sessions/revoke
GET   /api/admin/stats
GET   /api/admin/audit?n=200
GET   /api/flags
POST  /api/flags               { key: value, … }
```

### WebSocket
```
GET   /ws                      Event stream (requires auth)
```

Event types broadcast over WebSocket:
- `connected` — on handshake
- `files.changed` — any upload/delete/move
- `fetch.done` — remote download complete
- `fetch.progress` — periodic progress (optional future use)

---

## Keyboard shortcuts

| Key | Action |
|---|---|
| `⌘/Ctrl+K` | Open command palette |
| `Esc` | Close modal / palette / preview |
| `R` | Refresh |
| `/` or `F` | Focus search |
| `U` | Open upload panel |
| `N` | New folder |

---

## Project structure

```
fileserv-rewrite/
├── main.go          router wiring, server lifecycle, embed
├── config.go        env-based configuration
├── models.go        all data types
├── auth.go          bcrypt, HMAC tokens, session middleware, rate limiter, SSRF guard
├── db.go            SQLite schema + typed query methods
├── storage.go       path-safe filesystem abstraction, MIME helpers
├── handlers.go      all HTTP handler implementations
├── ws.go            WebSocket hub (broadcast to all clients)
├── wscodec.go       minimal WebSocket frame codec (no external dep)
├── ctx.go           context helper
├── static/
│   └── app.html     complete SPA: login, file browser, preview, upload, palette
├── Dockerfile
├── docker-compose.yml
├── Caddyfile
├── nginx.conf
├── go.mod
├── .env.example
└── README.md
```

---

## Security model

- **Passwords** — bcrypt (cost 10)
- **Sessions** — 256-bit random tokens in httpOnly, SameSite=Strict cookies; stored in SQLite; TTL 24h; evicts oldest when per-user cap exceeded
- **Signed URLs** — HMAC-SHA256 over relative path using `LINK_SECRET`
- **API keys** — SHA-256 hashed at rest; only prefix shown in listings
- **Path traversal** — `storage.Resolve()` validates every path stays under root using `filepath.Abs` comparison
- **SSRF** — Remote fetch resolves hostnames and rejects RFC-1918 / loopback addresses before connecting
- **Rate limiting** — Per-IP token bucket on `/api/auth/*` (10 req/min)
- **Headers** — `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` on every response
- **Upload sandboxing** — filenames sanitized; temp `.part` files used for atomic writes; execute bits stripped
- **Audit log** — every login, upload, delete, rename, share create/download recorded to SQLite

---

## Extending

### Add virus scanning hook
In `handlers.go → Upload()`, after `h.store.WriteFile(...)` succeeds, call your scanner:
```go
if err := scanFile(abs); err != nil {
    h.store.Delete(destRel)
    jsonErr(w, 422, "file rejected by scanner: "+err.Error())
    return
}
```

### Add S3/object-storage backend
Replace `storage.WriteFile` / `storage.List` / `storage.Delete` with calls to your S3 client.
The `Storage` interface surface is deliberately small — everything funnels through `Resolve()`.

### Add webhook notifications
In `handlers.go`, after any mutating operation:
```go
if h.cfg.WebhookURL != "" {
    go sendWebhook(h.cfg.WebhookURL, "upload", map[string]any{
        "user": s.Username, "file": destRel, "size": n,
    })
}
```

---

## License

MIT
