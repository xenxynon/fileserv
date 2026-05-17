package main

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite connection and provides typed query methods.
type DB struct {
	sql *sql.DB
}

const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS users (
	username    TEXT PRIMARY KEY,
	pw_hash     TEXT NOT NULL,
	role        TEXT NOT NULL DEFAULT 'user',
	disabled    INTEGER NOT NULL DEFAULT 0,
	avatar      TEXT,
	created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
	token       TEXT PRIMARY KEY,
	username    TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
	expires_at  INTEGER NOT NULL,
	created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS file_meta (
	rel_path    TEXT PRIMARY KEY,
	owner       TEXT NOT NULL,
	created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS share_links (
	token       TEXT PRIMARY KEY,
	rel_path    TEXT NOT NULL,
	owner       TEXT NOT NULL,
	pw_hash     TEXT,
	hits        INTEGER NOT NULL DEFAULT 0,
	max_hits    INTEGER,
	expires_at  INTEGER NOT NULL,
	created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
	hash        TEXT PRIMARY KEY,
	label       TEXT NOT NULL DEFAULT '',
	username    TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
	role        TEXT NOT NULL DEFAULT 'user',
	created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	time        INTEGER NOT NULL,
	action      TEXT NOT NULL,
	username    TEXT,
	detail      TEXT,
	ip          TEXT
);

CREATE TABLE IF NOT EXISTS flags (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_expires  ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_time        ON audit_log(time DESC);
CREATE INDEX IF NOT EXISTS idx_share_owner       ON share_links(owner);
`

// NewDB opens (or creates) the SQLite database at dataDir/fileserv.db.
func NewDB(dataDir string) (*DB, error) {
	path := filepath.Join(dataDir, "fileserv.db")
	sql, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	sql.SetMaxOpenConns(1) // SQLite serializes writes
	if _, err := sql.Exec(schema); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &DB{sql: sql}, nil
}

func (d *DB) Close() error { return d.sql.Close() }

// ─── Users ──────────────────────────────────────────────────────────────────

func (d *DB) CreateUser(u User) error {
	_, err := d.sql.Exec(
		`INSERT INTO users (username,pw_hash,role,disabled,avatar,created_at)
		 VALUES (?,?,?,?,?,?)`,
		u.Username, u.PwHash, string(u.Role), boolInt(u.Disabled), u.Avatar, u.CreatedAt.Unix(),
	)
	return err
}

func (d *DB) GetUser(username string) (*User, error) {
	row := d.sql.QueryRow(
		`SELECT username,pw_hash,role,disabled,avatar,created_at FROM users WHERE username=?`,
		username,
	)
	var u User
	var disabled int
	var avatar sql.NullString
	var ts int64
	if err := row.Scan(&u.Username, &u.PwHash, &u.Role, &disabled, &avatar, &ts); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	u.Disabled = disabled != 0
	u.Avatar = avatar.String
	u.CreatedAt = time.Unix(ts, 0)
	return &u, nil
}

func (d *DB) UpdateUser(username string, updates map[string]any) error {
	for k, v := range updates {
		if _, err := d.sql.Exec(
			fmt.Sprintf(`UPDATE users SET %s=? WHERE username=?`, k), v, username,
		); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) DeleteUser(username string) error {
	_, err := d.sql.Exec(`DELETE FROM users WHERE username=?`, username)
	return err
}

func (d *DB) ListUsers() ([]User, error) {
	rows, err := d.sql.Query(
		`SELECT username,role,disabled,avatar,created_at FROM users ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var disabled int
		var avatar sql.NullString
		var ts int64
		if err := rows.Scan(&u.Username, &u.Role, &disabled, &avatar, &ts); err != nil {
			continue
		}
		u.Disabled = disabled != 0
		u.Avatar = avatar.String
		u.CreatedAt = time.Unix(ts, 0)
		out = append(out, u)
	}
	return out, rows.Err()
}

func (d *DB) CountAdmins() (int, error) {
	var n int
	err := d.sql.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&n)
	return n, err
}

// ─── Sessions ────────────────────────────────────────────────────────────────

func (d *DB) CreateSession(s Session) error {
	_, err := d.sql.Exec(
		`INSERT INTO sessions (token,username,expires_at,created_at) VALUES (?,?,?,?)`,
		s.Token, s.Username, s.ExpiresAt.Unix(), time.Now().Unix(),
	)
	return err
}

func (d *DB) GetSession(token string) (*Session, error) {
	row := d.sql.QueryRow(
		`SELECT s.token,s.username,u.role,s.expires_at
		 FROM sessions s JOIN users u USING(username)
		 WHERE s.token=? AND s.expires_at>? AND u.disabled=0`,
		token, time.Now().Unix(),
	)
	var s Session
	var exp int64
	if err := row.Scan(&s.Token, &s.Username, &s.Role, &exp); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	s.ExpiresAt = time.Unix(exp, 0)
	return &s, nil
}

func (d *DB) DeleteSession(token string) error {
	_, err := d.sql.Exec(`DELETE FROM sessions WHERE token=?`, token)
	return err
}

func (d *DB) DeleteUserSessions(username string) (int64, error) {
	res, err := d.sql.Exec(`DELETE FROM sessions WHERE username=?`, username)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) CountUserSessions(username string) (int, error) {
	var n int
	err := d.sql.QueryRow(
		`SELECT COUNT(*) FROM sessions WHERE username=? AND expires_at>?`,
		username, time.Now().Unix(),
	).Scan(&n)
	return n, err
}

func (d *DB) EvictOldestSession(username string) error {
	_, err := d.sql.Exec(
		`DELETE FROM sessions WHERE token=(
			SELECT token FROM sessions WHERE username=? ORDER BY created_at ASC LIMIT 1
		)`, username,
	)
	return err
}

func (d *DB) PruneExpiredSessions() error {
	_, err := d.sql.Exec(`DELETE FROM sessions WHERE expires_at<?`, time.Now().Unix())
	return err
}

// ─── File metadata ───────────────────────────────────────────────────────────

func (d *DB) SetFileMeta(rel, owner string) error {
	_, err := d.sql.Exec(
		`INSERT OR REPLACE INTO file_meta (rel_path,owner,created_at) VALUES (?,?,?)`,
		rel, owner, time.Now().Unix(),
	)
	return err
}

func (d *DB) GetFileMeta(rel string) (string, error) {
	var owner string
	err := d.sql.QueryRow(`SELECT owner FROM file_meta WHERE rel_path=?`, rel).Scan(&owner)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return owner, err
}

func (d *DB) DeleteFileMeta(rel string) error {
	_, err := d.sql.Exec(`DELETE FROM file_meta WHERE rel_path=?`, rel)
	return err
}

func (d *DB) RenameFileMeta(oldRel, newRel string) error {
	_, err := d.sql.Exec(
		`UPDATE file_meta SET rel_path=? WHERE rel_path=?`, newRel, oldRel,
	)
	return err
}

func (d *DB) GetUserDiskUsage(username string) (int64, error) {
	rows, err := d.sql.Query(`SELECT rel_path FROM file_meta WHERE owner=?`, username)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var paths []string
	for rows.Next() {
		var p string
		rows.Scan(&p)
		paths = append(paths, p)
	}
	return 0, rows.Err() // Caller resolves actual disk usage
}

func (d *DB) GetFileMetaForUser(username string) ([]string, error) {
	rows, err := d.sql.Query(`SELECT rel_path FROM file_meta WHERE owner=?`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		rows.Scan(&p)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ─── Share links ─────────────────────────────────────────────────────────────

func (d *DB) CreateShare(s ShareLink) error {
	var maxHits *int64
	if s.MaxHits != nil {
		v := int64(*s.MaxHits)
		maxHits = &v
	}
	_, err := d.sql.Exec(
		`INSERT INTO share_links (token,rel_path,owner,pw_hash,hits,max_hits,expires_at,created_at)
		 VALUES (?,?,?,?,0,?,?,?)`,
		s.Token, s.RelPath, s.Owner, nullStr(s.PwHash), maxHits, s.ExpiresAt.Unix(), time.Now().Unix(),
	)
	return err
}

func (d *DB) GetShare(token string) (*ShareLink, error) {
	row := d.sql.QueryRow(
		`SELECT token,rel_path,owner,pw_hash,hits,max_hits,expires_at
		 FROM share_links WHERE token=?`, token,
	)
	var s ShareLink
	var pw sql.NullString
	var maxHits sql.NullInt64
	var exp int64
	if err := row.Scan(&s.Token, &s.RelPath, &s.Owner, &pw, &s.Hits, &maxHits, &exp); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	s.PwHash = pw.String
	if maxHits.Valid {
		v := int(maxHits.Int64)
		s.MaxHits = &v
	}
	s.ExpiresAt = time.Unix(exp, 0)
	return &s, nil
}

func (d *DB) IncrementShareHits(token string) error {
	_, err := d.sql.Exec(`UPDATE share_links SET hits=hits+1 WHERE token=?`, token)
	return err
}

func (d *DB) DeleteShare(token string) error {
	_, err := d.sql.Exec(`DELETE FROM share_links WHERE token=?`, token)
	return err
}

func (d *DB) ListShares(username string, isAdmin bool) ([]ShareLink, error) {
	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = d.sql.Query(
			`SELECT token,rel_path,owner,pw_hash,hits,max_hits,expires_at FROM share_links ORDER BY created_at DESC`,
		)
	} else {
		rows, err = d.sql.Query(
			`SELECT token,rel_path,owner,pw_hash,hits,max_hits,expires_at FROM share_links WHERE owner=? ORDER BY created_at DESC`,
			username,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ShareLink
	for rows.Next() {
		var s ShareLink
		var pw sql.NullString
		var maxHits sql.NullInt64
		var exp int64
		if err := rows.Scan(&s.Token, &s.RelPath, &s.Owner, &pw, &s.Hits, &maxHits, &exp); err != nil {
			continue
		}
		s.PwHash = pw.String
		if maxHits.Valid {
			v := int(maxHits.Int64)
			s.MaxHits = &v
		}
		s.ExpiresAt = time.Unix(exp, 0)
		out = append(out, s)
	}
	return out, rows.Err()
}

// ─── API Keys ────────────────────────────────────────────────────────────────

func (d *DB) CreateAPIKey(k APIKey) error {
	_, err := d.sql.Exec(
		`INSERT INTO api_keys (hash,label,username,role,created_at) VALUES (?,?,?,?,?)`,
		k.Hash, k.Label, k.Username, string(k.Role), time.Now().Unix(),
	)
	return err
}

func (d *DB) GetAPIKey(hash string) (*APIKey, error) {
	row := d.sql.QueryRow(
		`SELECT hash,label,k.username,k.role,k.created_at
		 FROM api_keys k JOIN users u ON k.username=u.username
		 WHERE k.hash=? AND u.disabled=0`, hash,
	)
	var k APIKey
	var ts int64
	if err := row.Scan(&k.Hash, &k.Label, &k.Username, &k.Role, &ts); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	k.CreatedAt = time.Unix(ts, 0)
	return &k, nil
}

func (d *DB) ListAPIKeys(username string, isAdmin bool) ([]APIKey, error) {
	var rows *sql.Rows
	var err error
	if isAdmin {
		rows, err = d.sql.Query(
			`SELECT hash,label,username,role,created_at FROM api_keys ORDER BY created_at DESC`,
		)
	} else {
		rows, err = d.sql.Query(
			`SELECT hash,label,username,role,created_at FROM api_keys WHERE username=? ORDER BY created_at DESC`,
			username,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		var ts int64
		if err := rows.Scan(&k.Hash, &k.Label, &k.Username, &k.Role, &ts); err != nil {
			continue
		}
		k.CreatedAt = time.Unix(ts, 0)
		out = append(out, k)
	}
	return out, rows.Err()
}

func (d *DB) DeleteAPIKeyByPrefix(prefix, username string, isAdmin bool) (int64, error) {
	var res sql.Result
	var err error
	if isAdmin {
		res, err = d.sql.Exec(`DELETE FROM api_keys WHERE hash LIKE ?`, prefix+"%")
	} else {
		res, err = d.sql.Exec(
			`DELETE FROM api_keys WHERE hash LIKE ? AND username=?`, prefix+"%", username,
		)
	}
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ─── Audit log ───────────────────────────────────────────────────────────────

func (d *DB) Audit(action, username, detail, ip string) {
	d.sql.ExecContext(context.Background(),
		`INSERT INTO audit_log (time,action,username,detail,ip) VALUES (?,?,?,?,?)`,
		time.Now().Unix(), action, username, detail, ip,
	)
}

func (d *DB) GetAuditLog(limit int) ([]AuditEntry, error) {
	rows, err := d.sql.Query(
		`SELECT time,action,username,detail,ip FROM audit_log ORDER BY time DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		var username, detail, ip sql.NullString
		if err := rows.Scan(&ts, &e.Action, &username, &detail, &ip); err != nil {
			continue
		}
		e.Time = time.Unix(ts, 0)
		e.User = username.String
		e.Detail = detail.String
		e.IP = ip.String
		out = append(out, e)
	}
	return out, rows.Err()
}

// ─── Flags ───────────────────────────────────────────────────────────────────

func (d *DB) GetFlags() (map[string]string, error) {
	rows, err := d.sql.Query(`SELECT key,value FROM flags`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		m[k] = v
	}
	return m, rows.Err()
}

func (d *DB) SetFlag(key, value string) error {
	_, err := d.sql.Exec(`INSERT OR REPLACE INTO flags (key,value) VALUES (?,?)`, key, value)
	return err
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullStr(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
