package main

import "time"

// Role is an authenticated user's privilege level.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// User represents a registered account.
type User struct {
	Username  string    `json:"username"`
	PwHash    string    `json:"-"`
	Role      Role      `json:"role"`
	Disabled  bool      `json:"disabled"`
	Avatar    string    `json:"avatar,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Session is a validated authentication context attached to a request.
type Session struct {
	Token     string
	Username  string
	Role      Role
	ExpiresAt time.Time
}

func (s *Session) IsAdmin() bool { return s.Role == RoleAdmin }

// FileMeta holds server-side metadata for a stored file.
type FileMeta struct {
	RelPath   string    `json:"rel"`
	Owner     string    `json:"owner"`
	CreatedAt time.Time `json:"created_at"`
}

// ShareLink is a time-limited, optionally protected public download link.
type ShareLink struct {
	Token    string    `json:"token"`
	RelPath  string    `json:"rel"`
	Owner    string    `json:"owner"`
	PwHash   string    `json:"-"`
	Hits     int       `json:"hits"`
	MaxHits  *int      `json:"max_hits,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// APIKey is a bearer token for programmatic access.
type APIKey struct {
	Hash      string    `json:"-"`
	Label     string    `json:"label"`
	Username  string    `json:"user"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditEntry is a structured audit log record.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	User   string    `json:"user"`
	Detail string    `json:"detail,omitempty"`
	IP     string    `json:"ip,omitempty"`
}

// FileEntry is a directory listing entry returned to the client.
type FileEntry struct {
	Name      string `json:"name"`
	Rel       string `json:"rel"`
	Type      string `json:"type"` // "file" | "dir"
	Size      int64  `json:"size"`
	Mtime     int64  `json:"mtime"`
	Owner     string `json:"owner,omitempty"`
	CanModify bool   `json:"can_modify"`
	Category  string `json:"category"`
	MimeType  string `json:"mime,omitempty"`
}

// FetchJob tracks an asynchronous remote URL download.
type FetchJob struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Owner    string `json:"owner"`
	Status   string `json:"status"` // starting|downloading|done|failed|cancelled
	Progress int    `json:"progress"`
	Done     int64  `json:"done"`
	Total    int64  `json:"total"`
	Speed    int64  `json:"speed"`
	ETA      int    `json:"eta"`
	Error    string `json:"error,omitempty"`
	Category string `json:"category"`

	cancel func()
}

// TorrentJob tracks a torrent or magnet download via aria2c.
type TorrentJob struct {
	PID      int    `json:"pid"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Progress int    `json:"progress"`
	SpeedStr string `json:"speed_str,omitempty"`
	ETAStr   string `json:"eta_str,omitempty"`
	Log      string `json:"log,omitempty"`
	Error    string `json:"error,omitempty"`
}

// WSMessage is a WebSocket event envelope sent to connected clients.
type WSMessage struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}
