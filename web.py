import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import socket
import tempfile
import time
import urllib.parse
import zipfile
from pathlib import Path

from aiohttp import web, ClientSession, ClientTimeout
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fileserv")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

WEB_PORT       = int(os.environ.get("WEB_PORT", 8080))
WEB_ADMIN_PASS = os.environ.get("WEB_ADMIN_PASS", "")
LINK_SECRET    = os.environ.get("LINK_SECRET", secrets.token_hex(32))
DOWNLOADS_DIR  = Path(os.environ.get("DOWNLOADS_DIR",
    Path(__file__).parent / "downloads")).resolve()
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
os.chmod(DOWNLOADS_DIR, 0o750)

_HERE         = Path(__file__).parent
HTML_DIR      = _HERE / "html"
STATIC_DIR    = _HERE / "static"
FLAGS_FILE    = _HERE / "flags.json"
USERS_FILE    = _HERE / "users.json"
META_FILE     = _HERE / "file_meta.json"
AUDIT_FILE    = _HERE / "audit.log"
SHARES_FILE   = _HERE / "share_links.json"
API_KEYS_FILE = _HERE / "api_keys.json"

SESSION_TTL           = 86400
COOKIE_NAME           = "fsid"
MAX_UPLOAD_BYTES      = int(os.environ.get("MAX_UPLOAD_MB",  2048)) * 1024 * 1024
MAX_FETCH_BYTES       = int(os.environ.get("MAX_FETCH_MB",   4096)) * 1024 * 1024
RATE_LIMIT_WINDOW     = 60
RATE_LIMIT_MAX        = 30
MAX_SESSIONS_PER_USER = int(os.environ.get("MAX_SESSIONS_PER_USER", 10))
USER_QUOTA_BYTES      = int(os.environ.get("QUOTA_MB", 0)) * 1024 * 1024
MAX_EDIT_BYTES        = 2 * 1024 * 1024

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# No file type blocking – all file types are accepted.
# Instead, every file written to disk gets 0o640 permissions (no execute bits).
BLOCKED_EXTS: set = set()  # kept for API compat but always empty

EDITABLE_EXTS = {
    "txt","md","log","json","yaml","yml","toml","cfg","ini","conf",
    "py","js","ts","html","css","xml","csv","env","gitignore",
}

EXT_CATS = {
    **{e: "archive" for e in "zip gz xz zst tar 7z bz2 lz4 br rar".split()},
    **{e: "image"   for e in "jpg jpeg png gif webp svg bmp avif ico".split()},
    **{e: "video"   for e in "mp4 mkv avi mov webm flv m4v ts".split()},
    **{e: "audio"   for e in "mp3 flac aac wav ogg m4a opus".split()},
    **{e: "doc"     for e in "txt log md json xml yaml toml cfg py js ts html css pdf doc docx xls xlsx csv".split()},
}

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

_sessions:     dict = {}
_rate:         dict = {}
_torrent_jobs: dict = {}
_fetch_jobs:   dict = {}
_flags_cache:  dict = {}

# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def _audit(action, user, detail=""):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = f"{ts} [{action}] user={user or '-'} {detail}\n"
    try:
        with open(AUDIT_FILE, "a") as f:
            f.write(line)
    except Exception as e:
        log.warning("audit write failed: %s", e)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _atomic_write(path, text):
    tmp = str(path) + ".tmp"
    try:
        with open(tmp, "w") as f:
            f.write(text)
        os.replace(tmp, str(path))
    except Exception as e:
        log.warning("write %s: %s", path, e)

def _pw_hash(pw):
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + pw).encode()).hexdigest()
    return f"sha256${salt}${digest}"

def _pw_verify(pw, stored):
    if stored.startswith("sha256$"):
        _, salt, digest = stored.split("$", 2)
        expected = hashlib.sha256((salt + pw).encode()).hexdigest()
        return secrets.compare_digest(expected, digest)
    return secrets.compare_digest(hashlib.sha256(pw.encode()).hexdigest(), stored)

def _sanitize_filename(name):
    name = Path(name).name
    name = name.replace("\x00", "")
    name = re.sub(r"[^\w.\-+ ]", "_", name).strip()
    name = re.sub(r"\.{2,}", ".", name)
    return name if name and name not in (".", "..") else "upload"

def _sanitize_dirname(name):
    name = Path(name).name
    name = name.replace("\x00", "")
    name = re.sub(r"[^\w.\-+ ]", "_", name).strip()
    name = re.sub(r"\.{2,}", ".", name)
    return name if name and name not in (".", "..") else None

def _is_blocked(name):
    return any(p in BLOCKED_EXTS for p in name.lower().split(".")[1:])

def _rate_ok(ip):
    now = time.time()
    bucket = _rate.setdefault(ip, [])
    _rate[ip] = [t for t in bucket if now - t < RATE_LIMIT_WINDOW]
    if len(_rate[ip]) >= RATE_LIMIT_MAX:
        return False
    _rate[ip].append(now)
    return True

def _cat_from_ext(name):
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return EXT_CATS.get(ext, "other")

def _cat_from_mime(mime):
    if not mime: return "other"
    m = mime.lower()
    if m.startswith("image/"): return "image"
    if m.startswith("video/"): return "video"
    if m.startswith("audio/"): return "audio"
    if m in ("application/pdf", "text/plain", "text/html", "text/csv"): return "doc"
    if any(x in m for x in ("zip", "tar", "compress", "7z")): return "archive"
    return "other"

def _is_private_ip(host):
    try:
        for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
            ip = ipaddress.ip_address(info[4][0])
            if any(ip in net for net in _PRIVATE_NETS):
                return True
        return False
    except Exception:
        return True

def _user_disk_usage(username):
    """Count bytes owned by username across all files (root and subdirs)."""
    meta = _load_meta()
    total = 0
    for rel_path, owner in meta.items():
        if owner != username: continue
        p = DOWNLOADS_DIR / rel_path
        if p.is_file():
            try: total += p.stat().st_size
            except Exception: pass
    return total

def _inside_downloads(p):
    sp = str(p.resolve())
    return sp == str(DOWNLOADS_DIR) or sp.startswith(str(DOWNLOADS_DIR) + os.sep)

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

def _load_flags():
    global _flags_cache
    try: _flags_cache = json.loads(FLAGS_FILE.read_text())
    except Exception: _flags_cache = {}

def get_flag(k, default=False):
    return _flags_cache.get(k, default)

def set_flag(k, v):
    _flags_cache[k] = v
    _atomic_write(FLAGS_FILE, json.dumps(_flags_cache))

_load_flags()

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def _load_users():
    try: return json.loads(USERS_FILE.read_text())
    except Exception: return {"users": {}}

def _save_users(db):
    _atomic_write(USERS_FILE, json.dumps(db))

def _ensure_admin():
    if not WEB_ADMIN_PASS: return
    db = _load_users()
    existing = db["users"].get("admin")
    if existing is None:
        db["users"]["admin"] = {"pw_hash": _pw_hash(WEB_ADMIN_PASS), "role": "admin"}
        _save_users(db)
    elif not _pw_verify(WEB_ADMIN_PASS, existing["pw_hash"]):
        existing["pw_hash"] = _pw_hash(WEB_ADMIN_PASS)
        existing["role"] = "admin"
        db["users"]["admin"] = existing
        _save_users(db)
        log.info("admin password hash resynced from WEB_ADMIN_PASS")

_ensure_admin()

# ---------------------------------------------------------------------------
# File metadata
# ---------------------------------------------------------------------------

def _load_meta():
    try: return json.loads(META_FILE.read_text())
    except Exception: return {}

def _save_meta(m): _atomic_write(META_FILE, json.dumps(m))
def _set_owner(name, username): m = _load_meta(); m[name] = username; _save_meta(m)
def _get_owner(name): return _load_meta().get(name)

def _noexec(path):
    """Strip all execute bits from a file – files should never be directly executable."""
    try: os.chmod(path, 0o640)
    except Exception: pass

# ---------------------------------------------------------------------------
# Sessions + API keys
# ---------------------------------------------------------------------------

def _load_api_keys():
    try: return json.loads(API_KEYS_FILE.read_text())
    except Exception: return {}

def _save_api_keys(d): _atomic_write(API_KEYS_FILE, json.dumps(d))
def _hash_api_key(raw): return hashlib.sha256(raw.encode()).hexdigest()

def _new_session(username, role):
    existing = [tok for tok, s in list(_sessions.items()) if s.get("user") == username]
    if len(existing) >= MAX_SESSIONS_PER_USER:
        for tok in sorted(existing, key=lambda t: _sessions[t].get("exp", 0))[: len(existing) - MAX_SESSIONS_PER_USER + 1]:
            _sessions.pop(tok, None)
    tok = secrets.token_hex(32)
    _sessions[tok] = {"exp": time.time() + SESSION_TTL, "user": username, "role": role}
    return tok

def _get_session(req):
    tok = req.cookies.get(COOKIE_NAME)
    if not tok: return None
    s = _sessions.get(tok)
    if not s or time.time() > s["exp"]:
        _sessions.pop(tok, None); return None
    return s

def _get_session_or_apikey(req):
    s = _get_session(req)
    if s: return s
    raw = None
    auth = req.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "): raw = auth[7:].strip()
    if not raw: raw = req.rel_url.query.get("api_key", "").strip()
    if not raw: return None
    entry = _load_api_keys().get(_hash_api_key(raw))
    if not entry: return None
    return {"user": entry["user"], "role": entry["role"], "exp": float("inf")}

def _check(req):    return _get_session_or_apikey(req) is not None
def _is_admin(req): s = _get_session_or_apikey(req); return bool(s and s.get("role") == "admin")
def _who(req):      s = _get_session_or_apikey(req); return s.get("user") if s else None

def _can_modify(req, name):
    if _is_admin(req): return True
    u = _who(req); return u is not None and _get_owner(name) == u

def _set_cookie(resp, tok):
    use_secure = os.environ.get("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")
    resp.set_cookie(COOKIE_NAME, tok, max_age=SESSION_TTL,
                    httponly=True, samesite="Strict", secure=use_secure)

# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

def _safe(rel_path):
    try:
        p = (DOWNLOADS_DIR / rel_path.lstrip("/")).resolve()
        if _inside_downloads(p) and p.is_file(): return p
    except Exception: pass
    return None

def _safe_dir(rel):
    try:
        if rel in ("", ".", "/"): return DOWNLOADS_DIR
        p = (DOWNLOADS_DIR / Path(rel)).resolve()
        if p == DOWNLOADS_DIR or _inside_downloads(p): return p
    except Exception: pass
    return None

# ---------------------------------------------------------------------------
# Share links
# ---------------------------------------------------------------------------

def _load_shares():
    try: return json.loads(SHARES_FILE.read_text())
    except Exception: return {}

def _save_shares(d): _atomic_write(SHARES_FILE, json.dumps(d))

_SHARE_GATE_HTML = """<!doctype html><html><head><meta charset=utf-8>
<title>Protected Download</title>
<style>body{{font-family:sans-serif;max-width:360px;margin:80px auto;padding:1rem}}
input{{width:100%;padding:.5rem;margin:.5rem 0;box-sizing:border-box}}
button{{padding:.5rem 1.2rem}}.err{{color:red}}</style></head><body>
<h2>&#128274; Password required</h2><p class=err>{error}</p>
<form method=post><input type=password name=password placeholder="Enter password" autofocus>
<button type=submit>Download</button></form></body></html>"""

# ---------------------------------------------------------------------------
# Permanent share tokens
# ---------------------------------------------------------------------------

def make_dl_token(name):
    return hmac.new(LINK_SECRET.encode(), name.encode(), "sha256").hexdigest()

def verify_dl_token(tok, name):
    return hmac.compare_digest(tok, make_dl_token(name))

# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------

async def _fire_webhook(event, payload):
    url = get_flag("webhook_url", "")
    if not url: return
    if event not in get_flag("webhook_events", ["upload", "delete", "fetch_done"]): return
    try:
        data = json.dumps({"event": event, "ts": time.time(), **payload})
        async with ClientSession(timeout=ClientTimeout(total=5)) as s:
            await s.post(url, data=data, headers={"Content-Type": "application/json"})
    except Exception as ex:
        log.warning("webhook %s: %s", event, ex)

# ---------------------------------------------------------------------------
# Template + streaming
# ---------------------------------------------------------------------------

def _tpl(name, **ctx):
    text = (HTML_DIR / name).read_text()
    for k, v in ctx.items(): text = text.replace(f"{{{{{k}}}}}", v)
    return text

async def _stream(req, path, name, inline=False):
    ct, _ = mimetypes.guess_type(str(path))
    ct = ct or "application/octet-stream"
    size = path.stat().st_size
    disp = f'{"inline" if inline else "attachment"}; filename="{name}"'

    range_hdr = req.headers.get("Range")
    if range_hdr:
        try:
            spec = range_hdr.strip()[len("bytes="):]
            s_str, e_str = spec.split("-", 1)
            start = int(s_str) if s_str else 0
            end   = int(e_str) if e_str else size - 1
            end   = min(end, size - 1)
        except Exception:
            return web.Response(status=416, headers={"Content-Range": f"bytes */{size}"})
        if start > end or start >= size:
            return web.Response(status=416, headers={"Content-Range": f"bytes */{size}"})
        length = end - start + 1
        resp = web.StreamResponse(status=206, headers={
            "Content-Disposition": disp,
            "Content-Type":        ct,
            "Content-Length":      str(length),
            "Content-Range":       f"bytes {start}-{end}/{size}",
            "Accept-Ranges":       "bytes",
        })
        await resp.prepare(req)
        try:
            with open(path, "rb") as f:
                f.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = f.read(min(65536, remaining))
                    if not chunk: break
                    await resp.write(chunk)
                    remaining -= len(chunk)
        except (ConnectionError, ConnectionResetError): pass
        return resp

    resp = web.StreamResponse(headers={
        "Content-Disposition": disp,
        "Content-Type":        ct,
        "Content-Length":      str(size),
        "Accept-Ranges":       "bytes",
        "X-Content-Type-Options": "nosniff",
    })
    await resp.prepare(req)
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536): await resp.write(chunk)
    except (ConnectionError, ConnectionResetError): pass
    return resp

# ---------------------------------------------------------------------------
# Background: URL fetch
# ---------------------------------------------------------------------------

async def _run_fetch(job_id, url, dest_name, username):
    job = _fetch_jobs[job_id]
    tmp = DOWNLOADS_DIR / (dest_name + ".part")
    try:
        async with ClientSession(timeout=ClientTimeout(total=None, connect=15, sock_read=60)) as sess:
            async with sess.get(url, allow_redirects=True, max_redirects=10) as resp:
                if resp.status >= 400:
                    job["status"] = "failed"; job["error"] = f"HTTP {resp.status}"; return
                total = int(resp.headers.get("Content-Length", 0))
                job["total"] = total
                if total > MAX_FETCH_BYTES:
                    job["status"] = "failed"; job["error"] = f"Remote file too large"; return
                job["category"] = _cat_from_mime(resp.content_type or "") or _cat_from_ext(dest_name)
                job["status"] = "downloading"
                done = 0; last_time = time.monotonic(); last_done = 0
                with open(tmp, "wb") as f:
                    async for chunk in resp.content.iter_chunked(65536):
                        if job.get("cancelled"):
                            job["status"] = "cancelled"; tmp.unlink(missing_ok=True); return
                        f.write(chunk); done += len(chunk); job["done"] = done
                        now = time.monotonic(); dt = now - last_time
                        if dt >= 0.5:
                            speed = (done - last_done) / dt; job["speed"] = int(speed)
                            if total > 0:
                                job["progress"] = min(99, int(done / total * 100))
                                job["eta"] = int((total - done) / speed) if speed > 0 else -1
                            last_time = now; last_done = done
                        if done > MAX_FETCH_BYTES:
                            job["status"] = "failed"; job["error"] = "File exceeded size limit"
                            tmp.unlink(missing_ok=True); return
        dest_p = DOWNLOADS_DIR / dest_name
        dest_p.write_bytes(tmp.read_bytes()); tmp.unlink(missing_ok=True)
        _noexec(dest_p)
        _set_owner(dest_name, username)
        _audit("fetch_done", username, f"file={dest_name}")
        job["status"] = "done"; job["progress"] = 100; job["done"] = done; job["total"] = done
        asyncio.create_task(_fire_webhook("fetch_done", {"user": username, "file": dest_name}))
    except asyncio.CancelledError:
        job["status"] = "cancelled"; tmp.unlink(missing_ok=True)
    except Exception as ex:
        log.error("fetch %s: %s", dest_name, ex)
        job["status"] = "failed"; job["error"] = str(ex); tmp.unlink(missing_ok=True)

# ---------------------------------------------------------------------------
# Background: torrent via async subprocess
# ---------------------------------------------------------------------------

async def _watch_torrent(pid, proc):
    job = _torrent_jobs.get(pid)
    if not job: return
    log_buf = ""
    try:
        async for line in proc.stdout:
            text = line.decode(errors="replace").rstrip()
            log_buf += text + "\n"; job["log"] = log_buf[-3000:]
            if m := re.search(r"\((\d+)%\)", text):
                job["progress"] = int(m.group(1)); job["status"] = "downloading"
            if m := re.search(r"DL:([\d.]+\s*\w+)", text): job["speed_str"] = m.group(1).replace(" ","")
            if m := re.search(r"ETA:(\S+)", text): job["eta_str"] = m.group(1)
            if m := re.search(r"([\d.]+\s*\w+)/([\d.]+\s*\w+)\(", text):
                job["done_str"] = m.group(1).strip(); job["total_str"] = m.group(2).strip()
    except Exception: pass
    ret = await proc.wait()
    if job["status"] != "cancelled":
        job["status"] = "done" if ret == 0 else "failed"
        if ret == 0: job["progress"] = 100
        elif not job.get("error"): job["error"] = log_buf[-400:] or f"aria2c exit {ret}"

# ===========================================================================
# Route handlers
# ===========================================================================

async def handle_root(req):
    if _check(req): return web.Response(text=_tpl("explorer.html"), content_type="text/html")
    return web.Response(text=_tpl("login.html", error=""), content_type="text/html")

async def handle_health(req):
    disk = shutil.disk_usage(str(DOWNLOADS_DIR))
    return web.json_response({"status": "ok",
        "disk_free_gb": round(disk.free / 1024**3, 2),
        "disk_used_gb": round(disk.used / 1024**3, 2),
        "active_sessions": len(_sessions)})

async def handle_login(req):
    if not _rate_ok(req.remote): return web.Response(status=429, text="Too many requests")
    data = await req.post()
    username = (data.get("username") or "").strip(); password = data.get("pass", "")
    db = _load_users(); user = db["users"].get(username)
    if not user or user.get("disabled") or not _pw_verify(password, user["pw_hash"]):
        _audit("login_fail", username)
        return web.Response(text=_tpl("login.html", error='<p class="error">Wrong credentials.</p>'),
                            content_type="text/html", status=401)
    if not user["pw_hash"].startswith("sha256$"):
        user["pw_hash"] = _pw_hash(password); db["users"][username] = user; _save_users(db)
    tok = _new_session(username, user["role"]); resp = web.HTTPFound("/")
    _set_cookie(resp, tok); _audit("login", username); return resp

async def handle_register(req):
    if not get_flag("registration_open", True):
        return web.Response(text=_tpl("login.html", error='<p class="error">Registration is closed.</p>'),
                            content_type="text/html", status=403)
    if not _rate_ok(req.remote): return web.Response(status=429, text="Too many requests")
    data = await req.post()
    username = re.sub(r"[^\w.\-]", "", (data.get("username") or "")).strip()
    password = data.get("pass", "")
    if not username or len(password) < 6:
        return web.Response(text=_tpl("login.html",
            error='<p class="error">Username required; password must be &ge; 6 chars.</p>'),
            content_type="text/html", status=400)
    db = _load_users()
    if username in db["users"]:
        return web.Response(text=_tpl("login.html", error='<p class="error">Username already taken.</p>'),
                            content_type="text/html", status=409)
    db["users"][username] = {"pw_hash": _pw_hash(password), "role": "user"}
    _save_users(db); _audit("register", username)
    tok = _new_session(username, "user"); resp = web.HTTPFound("/")
    _set_cookie(resp, tok); return resp

async def handle_logout(req):
    _sessions.pop(req.cookies.get(COOKIE_NAME), None)
    _audit("logout", _who(req))
    resp = web.HTTPFound("/"); resp.del_cookie(COOKIE_NAME); return resp

async def handle_session(req):
    if not _check(req):
        return web.json_response({"admin": False, "can_write": False, "torrent_enabled": False,
                                  "username": None, "registration_open": get_flag("registration_open", True)})
    user = _who(req); is_admin = _is_admin(req)
    db = _load_users(); avatar = db["users"].get(user, {}).get("avatar")
    quota_used = _user_disk_usage(user) if USER_QUOTA_BYTES > 0 else 0
    return web.json_response({"admin": is_admin, "can_write": True,
        "torrent_enabled": is_admin and get_flag("torrent_enabled", False),
        "username": user, "avatar": avatar,
        "registration_open": get_flag("registration_open", True),
        "quota_bytes": USER_QUOTA_BYTES, "quota_used": quota_used})

async def handle_files(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel = req.rel_url.query.get("path", ""); base = _safe_dir(rel)
    if base is None or not base.exists(): return web.json_response({"error": "not found"}, status=404)
    user = _who(req); is_admin = _is_admin(req); meta = _load_meta()
    files, dirs = [], []
    try:
        for e in os.scandir(base):
            st = e.stat(follow_symlinks=False)
            if e.is_dir(follow_symlinks=False):
                dirs.append({"name": e.name, "type": "dir", "size": 0, "mtime": int(st.st_mtime)})
            elif e.is_file(follow_symlinks=False):
                rp = str(Path(e.path).relative_to(DOWNLOADS_DIR))
                owner = meta.get(e.name)
                files.append({"name": e.name, "rel": rp, "type": "file",
                    "size": st.st_size, "mtime": int(st.st_mtime), "owner": owner,
                    "can_modify": is_admin or owner == user, "category": _cat_from_ext(e.name)})
    except Exception as ex:
        log.error("scandir %s: %s", base, ex)
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"dirs": dirs, "files": files, "path": rel})

async def handle_upload(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    username = _who(req)
    folder_rel = req.rel_url.query.get("path", "").lstrip("/")
    dest_dir = _safe_dir(folder_rel) if folder_rel else DOWNLOADS_DIR
    if dest_dir is None or not dest_dir.is_dir():
        return web.json_response({"error": "invalid upload path"}, status=400)
    quota_remaining = None
    if USER_QUOTA_BYTES > 0:
        used = _user_disk_usage(username)
        if used >= USER_QUOTA_BYTES:
            return web.json_response({"error": f"Quota exceeded ({USER_QUOTA_BYTES//1024//1024} MB limit)"}, status=413)
        quota_remaining = USER_QUOTA_BYTES - used
    try:
        reader = await req.multipart(); field = await reader.next()
        if field is None or field.name != "file": raise web.HTTPBadRequest()
        filename = _sanitize_filename(field.filename or "upload")
        # (all file types accepted)
        dest = dest_dir / filename; tmp = dest.with_suffix(dest.suffix + ".part")
        received = 0
        try:
            with open(tmp, "wb") as f:
                while chunk := await field.read_chunk(65536):
                    received += len(chunk)
                    if received > MAX_UPLOAD_BYTES:
                        tmp.unlink(missing_ok=True)
                        return web.json_response({"error": "file too large"}, status=413)
                    if quota_remaining is not None and received > quota_remaining:
                        tmp.unlink(missing_ok=True)
                        return web.json_response({"error": "quota exceeded"}, status=413)
                    f.write(chunk)
            tmp.rename(dest); _noexec(dest); _set_owner(filename, username)
            _audit("upload", username, f"file={filename} size={received}")
            asyncio.create_task(_fire_webhook("upload", {"user": username, "file": filename}))
        except Exception: tmp.unlink(missing_ok=True); raise
    except web.HTTPException: raise
    except Exception as ex:
        log.error("upload: %s", ex)
        return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True, "name": filename})

async def handle_delete(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel = req.match_info["tail"].lstrip("/"); fname = Path(rel).name
    if not _can_modify(req, fname): return web.json_response({"error": "forbidden — not your file"}, status=403)
    path = _safe(rel)
    if path is None:
        if not _is_admin(req): return web.json_response({"error": "only admins can delete folders"}, status=403)
        d = _safe_dir(rel)
        if d is None or d == DOWNLOADS_DIR or not d.is_dir(): raise web.HTTPNotFound()
        try: shutil.rmtree(str(d))
        except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
        _audit("delete_dir", _who(req), f"dir={rel}"); return web.json_response({"ok": True})
    try:
        path.unlink(); m = _load_meta(); m.pop(fname, None); _save_meta(m)
        _audit("delete", _who(req), f"file={rel}")
        asyncio.create_task(_fire_webhook("delete", {"user": _who(req), "path": rel}))
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True})

async def handle_rename(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body = await req.json()
        old_rel = body.get("old", "").lstrip("/"); new_name = _sanitize_filename(body.get("new", ""))
        if not old_rel or not new_name: raise ValueError
    except Exception: return web.json_response({"error": "bad request"}, status=400)
    old_name = Path(old_rel).name
    if not _can_modify(req, old_name): return web.json_response({"error": "forbidden — not your file"}, status=403)
    # (all file types accepted)
    src = _safe(old_rel); is_dir = False
    if src is None:
        src_dir = _safe_dir(old_rel)
        if src_dir is None or src_dir == DOWNLOADS_DIR or not src_dir.is_dir(): raise web.HTTPNotFound()
        src = src_dir; is_dir = True
    dst = src.parent / new_name
    if not _inside_downloads(dst): return web.json_response({"error": "invalid path"}, status=400)
    if dst.exists(): return web.json_response({"error": "name already taken"}, status=409)
    try:
        src.rename(dst)
        if not is_dir:
            m = _load_meta()
            if old_name in m: m[new_name] = m.pop(old_name); _save_meta(m)
        _audit("rename", _who(req), f"old={old_rel} new={new_name}")
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True, "name": new_name})

async def handle_mkdir(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body = await req.json()
        parent_rel = body.get("path", "").lstrip("/"); folder_name = _sanitize_dirname(body.get("name", ""))
    except Exception: return web.json_response({"error": "bad request"}, status=400)
    if not folder_name: return web.json_response({"error": "invalid folder name"}, status=400)
    parent = _safe_dir(parent_rel)
    if parent is None: return web.json_response({"error": "invalid parent path"}, status=400)
    new_dir = parent / folder_name
    if not _inside_downloads(new_dir): return web.json_response({"error": "invalid path"}, status=400)
    if new_dir.exists(): return web.json_response({"error": "already exists"}, status=409)
    try: new_dir.mkdir(parents=False)
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
    _audit("mkdir", _who(req), f"dir={folder_name}")
    return web.json_response({"ok": True, "name": folder_name})

async def handle_preview(req):
    if not _check(req): raise web.HTTPFound("/")
    rel = req.match_info["tail"].lstrip("/"); path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    ct, _ = mimetypes.guess_type(str(path)); ct = ct or "application/octet-stream"
    if not any(ct.startswith(p) for p in ("image/","video/","audio/","text/","application/pdf")):
        raise web.HTTPFound(f"/dl/{rel}")
    return await _stream(req, path, path.name, inline=True)

async def handle_download(req):
    if not _check(req): raise web.HTTPFound("/")
    rel = req.match_info["tail"].lstrip("/"); path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    return await _stream(req, path, path.name)

async def handle_token_download(req):
    tok = req.match_info["token"]; rel = req.match_info["tail"].lstrip("/")
    if not verify_dl_token(tok, rel): raise web.HTTPForbidden()
    path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    return await _stream(req, path, path.name)

async def handle_make_token(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel = req.match_info["tail"].lstrip("/")
    if _safe(rel) is None: raise web.HTTPNotFound()
    encoded_rel = "/".join(urllib.parse.quote(seg, safe="") for seg in rel.split("/"))
    return web.json_response({"url": f"/get/{make_dl_token(rel)}/{encoded_rel}"})

async def handle_zip_folder(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel = req.rel_url.query.get("path", "").lstrip("/")
    if not rel: return web.json_response({"error": "path required"}, status=400)
    folder = _safe_dir(rel)
    if folder is None or not folder.is_dir() or folder == DOWNLOADS_DIR: raise web.HTTPNotFound()
    zip_name = urllib.parse.quote(folder.name + ".zip", safe="")
    resp = web.StreamResponse(headers={
        "Content-Disposition": f"attachment; filename*=UTF-8''{zip_name}",
        "Content-Type": "application/zip"})
    await resp.prepare(req)
    try:
        import io; buf = io.BytesIO()
        def _build():
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                for item in sorted(folder.rglob("*")):
                    if item.is_file(follow_symlinks=False): zf.write(item, item.relative_to(folder))
            return buf.getvalue()
        await resp.write(await asyncio.to_thread(_build))
    except (ConnectionError, ConnectionResetError): pass
    return resp

async def handle_fetch_url(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body = await req.json(); url = (body.get("url") or "").strip()
        if not url: raise ValueError("missing url")
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return web.json_response({"error": "only http/https URLs supported"}, status=400)
        host = parsed.hostname or ""
        if not host: return web.json_response({"error": "invalid URL"}, status=400)
        if _is_private_ip(host):
            return web.json_response({"error": "requests to private network addresses are not allowed"}, status=400)
    except web.HTTPException: raise
    except Exception as ex: return web.json_response({"error": str(ex)}, status=400)
    filename = _sanitize_filename(urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1] or "download"))
    # (all file types accepted)
    dest = DOWNLOADS_DIR / filename
    if dest.exists():
        for jid, j in _fetch_jobs.items():
            if j.get("name") == filename and j["status"] not in ("done","failed","cancelled"):
                return web.json_response({"error": "already downloading", "job_id": jid}, status=409)
        return web.json_response({"error": f'"{filename}" already exists.', "duplicate": True}, status=409)
    try:
        async with ClientSession(timeout=ClientTimeout(connect=10, total=15)) as sess:
            async with sess.head(url, allow_redirects=True) as hr:
                cl = int(hr.headers.get("Content-Length", 0))
                if cl > MAX_FETCH_BYTES:
                    return web.json_response({"error": f"File too large (>{MAX_FETCH_BYTES//1024//1024} MB)"}, status=413)
    except Exception: pass
    job_id = secrets.token_hex(8); username = _who(req)
    _fetch_jobs[job_id] = {"status": "starting", "progress": 0, "speed": 0, "eta": -1,
        "total": 0, "done": 0, "name": filename, "url": url,
        "started": time.time(), "error": None, "category": _cat_from_ext(filename), "owner": username}
    _audit("fetch_start", username, f"url={url} file={filename}")
    asyncio.create_task(_run_fetch(job_id, url, filename, username))
    return web.json_response({"ok": True, "job_id": job_id, "name": filename})

async def handle_fetch_progress(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    if _is_admin(req): return web.json_response(dict(_fetch_jobs))
    user = _who(req)
    return web.json_response({jid: j for jid, j in _fetch_jobs.items() if j.get("owner") == user})

async def handle_fetch_cancel(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    job_id = req.match_info["job_id"]; job = _fetch_jobs.get(job_id)
    if not job: return web.json_response({"error": "not found"}, status=404)
    if not _is_admin(req) and job.get("owner") != _who(req):
        return web.json_response({"error": "forbidden"}, status=403)
    job["cancelled"] = True; job["status"] = "cancelled"
    return web.json_response({"ok": True})

async def handle_fetch_retry(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    job_id = req.match_info["job_id"]; old = _fetch_jobs.get(job_id)
    if not old or old["status"] not in ("failed","cancelled"):
        return web.json_response({"error": "job not retryable"}, status=400)
    username = _who(req)
    if not _is_admin(req) and old.get("owner") != username:
        return web.json_response({"error": "forbidden"}, status=403)
    new_id = secrets.token_hex(8)
    _fetch_jobs[new_id] = {"status": "starting", "progress": 0, "speed": 0, "eta": -1,
        "total": 0, "done": 0, "name": old["name"], "url": old["url"],
        "started": time.time(), "error": None, "category": old.get("category","other"), "owner": username}
    asyncio.create_task(_run_fetch(new_id, old["url"], old["name"], username))
    return web.json_response({"ok": True, "job_id": new_id})

async def handle_torrent(req):
    if not _check(req) or not _is_admin(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    if not get_flag("torrent_enabled", False):
        return web.json_response({"error": "torrent downloads are disabled"}, status=403)
    ct = req.content_type or ""
    if "multipart" in ct:
        try:
            reader = await req.multipart(); field = await reader.next()
            if field is None or field.name != "file": raise ValueError("missing file field")
            data = await field.read(decode=True)
            if not data: raise ValueError("empty file")
        except Exception as ex: return web.json_response({"error": str(ex)}, status=400)
        fd, tmp_path = tempfile.mkstemp(suffix=".torrent")
        try:
            with os.fdopen(fd, "wb") as f: f.write(data)
            proc = await asyncio.create_subprocess_exec(
                "aria2c","--dir",str(DOWNLOADS_DIR),"--daemon=false",
                "--max-connection-per-server=4","--split=4","--seed-time=0",tmp_path,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        except FileNotFoundError: return web.json_response({"error": "aria2c not found"}, status=500)
        except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
        finally:
            try: os.unlink(tmp_path)
            except Exception: pass
    else:
        try:
            body = await req.json(); uri = (body.get("uri") or "").strip()
            if not uri: raise ValueError
        except Exception: return web.json_response({"error": "bad request"}, status=400)
        if not (uri.lower().startswith("magnet:") or uri.lower().endswith(".torrent")):
            return web.json_response({"error": "not a magnet link or .torrent URL"}, status=400)
        name = uri
        if "dn=" in uri:
            if m := re.search(r"dn=([^&]+)", uri): name = urllib.parse.unquote_plus(m.group(1))
        elif "/" in uri: name = uri.rsplit("/", 1)[-1]
        try:
            proc = await asyncio.create_subprocess_exec(
                "aria2c","--dir",str(DOWNLOADS_DIR),"--daemon=false",
                "--max-connection-per-server=4","--split=4","--seed-time=0",uri,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        except FileNotFoundError: return web.json_response({"error": "aria2c not found"}, status=500)
        except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
        _torrent_jobs[proc.pid] = {"status": "starting", "progress": 0, "speed": 0, "eta": -1,
            "total": 0, "done": 0, "name": name[:120] if "uri" in dir() else "torrent",
            "started": time.time(), "log": ""}
        asyncio.create_task(_watch_torrent(proc.pid, proc))
        return web.json_response({"ok": True, "pid": proc.pid})
    _torrent_jobs[proc.pid] = {"status": "starting", "progress": 0, "speed": 0, "eta": -1,
        "total": 0, "done": 0, "name": "torrent file", "started": time.time(), "log": ""}
    asyncio.create_task(_watch_torrent(proc.pid, proc))
    return web.json_response({"ok": True, "pid": proc.pid})

async def handle_torrent_progress(req):
    if not _check(req) or not _is_admin(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    return web.json_response(dict(_torrent_jobs))

async def handle_torrent_cancel(req):
    if not _check(req) or not _is_admin(req):
        return web.json_response({"error": "unauthorized"}, status=401)
    try: pid = int(req.match_info["pid"])
    except Exception: return web.json_response({"error": "bad pid"}, status=400)
    job = _torrent_jobs.get(pid)
    if not job: return web.json_response({"error": "not found"}, status=404)
    try: os.kill(pid, 15)
    except Exception: pass
    job["status"] = "cancelled"
    return web.json_response({"ok": True})

async def handle_move(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body = await req.json()
        src_rel = body.get("src","").lstrip("/"); dst_rel = body.get("dst_dir","").lstrip("/")
        do_copy = bool(body.get("copy", False))
        if not src_rel: raise ValueError("src required")
    except Exception as ex: return web.json_response({"error": str(ex)}, status=400)
    dst_dir = _safe_dir(dst_rel)
    if dst_dir is None or not dst_dir.is_dir(): return web.json_response({"error": "destination not found"}, status=404)
    src = _safe(src_rel); src_is_dir = False
    if src is None:
        src = _safe_dir(src_rel)
        if src is None or src == DOWNLOADS_DIR or not src.is_dir(): raise web.HTTPNotFound()
        src_is_dir = True
    if not do_copy and not _can_modify(req, src.name):
        return web.json_response({"error": "forbidden — not your file"}, status=403)
    dst = dst_dir / src.name
    if dst.exists(): return web.json_response({"error": f'"{src.name}" already exists in destination'}, status=409)
    try:
        if do_copy:
            await asyncio.to_thread(shutil.copytree if src_is_dir else shutil.copy2, str(src), str(dst))
            if not src_is_dir: m = _load_meta(); m[src.name] = _who(req); _save_meta(m)
        else:
            await asyncio.to_thread(shutil.move, str(src), str(dst))
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
    _audit("copy" if do_copy else "move", _who(req), f"src={src_rel} dst={dst_rel}")
    return web.json_response({"ok": True, "name": src.name})

async def handle_bulk(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body = await req.json(); action = body.get("action","")
        rels = [r.lstrip("/") for r in (body.get("files") or []) if r]
        if not action or not rels: raise ValueError("action and files required")
    except Exception as ex: return web.json_response({"error": str(ex)}, status=400)
    if action == "delete":
        errors = []; deleted = 0
        for rel in rels:
            fname = Path(rel).name
            if not _can_modify(req, fname): errors.append(f"{rel}: forbidden"); continue
            p = _safe(rel)
            if p is None: errors.append(f"{rel}: not found"); continue
            try: p.unlink(); m = _load_meta(); m.pop(fname,None); _save_meta(m); deleted += 1
            except Exception as ex: errors.append(f"{rel}: {ex}")
        _audit("bulk_delete", _who(req), f"count={deleted}")
        return web.json_response({"ok": True, "deleted": deleted, "errors": errors})
    elif action == "move":
        dst_rel = body.get("dst_dir","").lstrip("/"); dst_dir = _safe_dir(dst_rel)
        if dst_dir is None or not dst_dir.is_dir(): return web.json_response({"error": "destination not found"}, status=404)
        errors = []; moved = 0
        for rel in rels:
            fname = Path(rel).name
            if not _can_modify(req, fname): errors.append(f"{rel}: forbidden"); continue
            p = _safe(rel)
            if p is None: errors.append(f"{rel}: not found"); continue
            dst = dst_dir / fname
            if dst.exists(): errors.append(f"{rel}: already exists"); continue
            try: shutil.move(str(p), str(dst)); moved += 1
            except Exception as ex: errors.append(f"{rel}: {ex}")
        _audit("bulk_move", _who(req), f"count={moved} dst={dst_rel}")
        return web.json_response({"ok": True, "moved": moved, "errors": errors})
    elif action == "zip":
        import io; buf = io.BytesIO(); added = 0
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for rel in rels:
                p = _safe(rel)
                if p: zf.write(p, p.name); added += 1
        if not added: return web.json_response({"error": "no valid files"}, status=400)
        _audit("bulk_zip", _who(req), f"count={added}")
        return web.Response(body=buf.getvalue(),
            headers={"Content-Disposition": 'attachment; filename="selection.zip"',
                     "Content-Type": "application/zip"})
    return web.json_response({"error": f"unknown action: {action}"}, status=400)

async def handle_search(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    q = req.rel_url.query.get("q","").strip().lower()
    path_rel = req.rel_url.query.get("path","").strip()
    type_f = req.rel_url.query.get("type","").strip().lower()
    if not q: return web.json_response({"error": "q required"}, status=400)
    base = _safe_dir(path_rel) if path_rel else DOWNLOADS_DIR
    if base is None: return web.json_response({"error": "invalid path"}, status=400)
    user = _who(req); is_admin = _is_admin(req); meta = _load_meta(); results = []
    try:
        for item in base.rglob("*"):
            if not item.is_file(follow_symlinks=False): continue
            if q not in item.name.lower(): continue
            if type_f and _cat_from_ext(item.name) != type_f: continue
            rel = str(item.relative_to(DOWNLOADS_DIR)); owner = meta.get(item.name)
            try: st = item.stat(); size, mtime = st.st_size, int(st.st_mtime)
            except Exception: size, mtime = 0, 0
            results.append({"name": item.name, "rel": rel, "size": size, "mtime": mtime,
                "owner": owner, "can_modify": is_admin or owner == user, "category": _cat_from_ext(item.name)})
            if len(results) >= 200: break
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"results": results, "q": q, "total": len(results)})

async def handle_zip_inspect(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel = req.rel_url.query.get("path","").lstrip("/"); path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    if path.suffix.lower() != ".zip": return web.json_response({"error": "only .zip files supported"}, status=400)
    try:
        entries = []
        with zipfile.ZipFile(str(path), "r") as zf:
            for info in zf.infolist():
                entries.append({"name": info.filename, "size": info.file_size,
                    "compressed": info.compress_size, "is_dir": info.filename.endswith("/"),
                    "mtime": int(time.mktime(info.date_time+(0,0,-1))) if info.date_time[0]>1980 else 0})
        return web.json_response({"path": rel, "entries": entries, "count": len(entries)})
    except zipfile.BadZipFile: return web.json_response({"error": "not a valid zip"}, status=400)
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)

async def handle_edit_get(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel = req.match_info["tail"].lstrip("/"); path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    if path.suffix.lower().lstrip(".") not in EDITABLE_EXTS:
        return web.json_response({"error": "file type not editable"}, status=400)
    try:
        size = path.stat().st_size
        if size > MAX_EDIT_BYTES: return web.json_response({"error": f"file too large ({size//1024} KB)"}, status=413)
        return web.json_response({"rel": rel, "name": path.name, "content": path.read_text(errors="replace"), "size": size})
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)

async def handle_edit_put(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    rel = req.match_info["tail"].lstrip("/"); path = _safe(rel)
    if path is None: raise web.HTTPNotFound()
    if not _can_modify(req, path.name): return web.json_response({"error": "forbidden"}, status=403)
    if path.suffix.lower().lstrip(".") not in EDITABLE_EXTS:
        return web.json_response({"error": "file type not editable"}, status=400)
    try:
        body = await req.json(); content = body.get("content","")
        if not isinstance(content, str): raise ValueError("content must be a string")
        if len(content.encode()) > MAX_EDIT_BYTES: return web.json_response({"error": "content too large"}, status=413)
    except Exception as ex: return web.json_response({"error": str(ex)}, status=400)
    try:
        tmp = path.with_suffix(path.suffix + ".tmp"); tmp.write_text(content); tmp.rename(path)
        _audit("edit_save", _who(req), f"file={rel}")
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)
    return web.json_response({"ok": True, "size": len(content.encode())})

async def handle_share_create(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try:
        body = await req.json(); rel = body.get("rel","").lstrip("/")
        if not rel: raise ValueError("rel required")
    except Exception as ex: return web.json_response({"error": str(ex)}, status=400)
    if _safe(rel) is None: raise web.HTTPNotFound()
    ttl_h = float(body.get("ttl_hours", 168)); password = body.get("password") or None
    max_hits = body.get("max_hits"); tok = secrets.token_urlsafe(24)
    shares = _load_shares()
    shares[tok] = {"rel": rel, "exp": time.time() + ttl_h*3600,
        "pw_hash": _pw_hash(password) if password else None,
        "hits": 0, "max_hits": int(max_hits) if max_hits is not None else None, "owner": _who(req)}
    _save_shares(shares); _audit("share_create", _who(req), f"rel={rel}")
    return web.json_response({"token": tok, "url": f"/s/{tok}"})

async def handle_share_download(req):
    tok = req.match_info["token"]; shares = _load_shares(); entry = shares.get(tok)
    if not entry or time.time() > entry["exp"]: return web.Response(text="Share link expired or not found.", status=410)
    if entry["max_hits"] is not None and entry["hits"] >= entry["max_hits"]:
        return web.Response(text="Download limit reached.", status=410)
    if entry["pw_hash"]:
        if req.method == "POST":
            data = await req.post(); pw = data.get("password","")
            if not _pw_verify(pw, entry["pw_hash"]):
                return web.Response(text=_SHARE_GATE_HTML.format(token=tok, error="Wrong password."),
                                    content_type="text/html", status=401)
        else:
            return web.Response(text=_SHARE_GATE_HTML.format(token=tok, error=""), content_type="text/html")
    path = _safe(entry["rel"])
    if path is None: return web.Response(text="File no longer exists.", status=404)
    entry["hits"] += 1; _save_shares(shares)
    _audit("share_download", entry.get("owner"), f"token={tok}")
    return await _stream(req, path, path.name)

async def handle_share_list(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    user = _who(req); is_admin = _is_admin(req); shares = _load_shares(); now = time.time()
    return web.json_response({tok: {"rel": e["rel"], "exp": e["exp"], "hits": e["hits"],
        "max_hits": e["max_hits"], "protected": bool(e["pw_hash"]),
        "owner": e.get("owner"), "expired": now > e["exp"]}
        for tok, e in shares.items() if is_admin or e.get("owner") == user})

async def handle_share_delete(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    tok = req.match_info["token"]; shares = _load_shares(); entry = shares.get(tok)
    if not entry: return web.json_response({"error": "not found"}, status=404)
    if not _is_admin(req) and entry.get("owner") != _who(req):
        return web.json_response({"error": "forbidden"}, status=403)
    shares.pop(tok); _save_shares(shares)
    return web.json_response({"ok": True})

async def handle_flag_get(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    return web.json_response(dict(_flags_cache))

async def handle_flag_set(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    try:
        body = await req.json()
        if not isinstance(body, dict): raise ValueError
    except Exception: return web.json_response({"error": "bad request"}, status=400)
    for k, v in body.items(): set_flag(str(k), v)
    return web.json_response({"ok": True, "flags": dict(_flags_cache)})

async def handle_admin_users(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    db = _load_users()
    return web.json_response({u: {"role": d["role"], "avatar": d.get("avatar"), "disabled": d.get("disabled",False)}
                               for u, d in db["users"].items()})

async def handle_admin_user_delete(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    username = req.match_info["username"]
    if username == _who(req): return web.json_response({"error": "cannot delete yourself"}, status=400)
    db = _load_users()
    if username not in db["users"] or db["users"][username].get("role") == "admin":
        return web.json_response({"error": "not found or protected"}, status=404)
    db["users"].pop(username); _save_users(db); _audit("user_delete", _who(req), f"target={username}")
    return web.json_response({"ok": True})

async def handle_admin_user_update(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    username = req.match_info["username"]
    if username == _who(req): return web.json_response({"error": "cannot modify yourself this way"}, status=400)
    try: body = await req.json()
    except Exception: return web.json_response({"error": "bad request"}, status=400)
    db = _load_users()
    if username not in db["users"]: return web.json_response({"error": "user not found"}, status=404)
    user = db["users"][username]; changed = False
    if "password" in body:
        pw = str(body["password"])
        if len(pw) < 6: return web.json_response({"error": "password must be >= 6 chars"}, status=400)
        user["pw_hash"] = _pw_hash(pw); changed = True
    if "disabled" in body: user["disabled"] = bool(body["disabled"]); changed = True
    if "role" in body:
        role = body["role"]
        if role not in ("user","admin"): return web.json_response({"error": "invalid role"}, status=400)
        if role == "user" and user.get("role") == "admin":
            if sum(1 for d in db["users"].values() if d.get("role")=="admin") <= 1:
                return web.json_response({"error": "cannot demote the last admin"}, status=400)
        user["role"] = role; changed = True
    if not changed: return web.json_response({"error": "nothing to update"}, status=400)
    db["users"][username] = user; _save_users(db); _audit("user_update", _who(req), f"target={username}")
    if body.get("disabled") or "password" in body:
        for tok in [t for t, s in list(_sessions.items()) if s.get("user") == username]: _sessions.pop(tok, None)
    return web.json_response({"ok": True})

async def handle_admin_session_reset(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    username = req.match_info.get("username","")
    to_kill = [tok for tok, s in list(_sessions.items())
               if (s.get("user") == username if username else s.get("role") != "admin")]
    for tok in to_kill: _sessions.pop(tok, None)
    _audit("session_reset", _who(req), f"target={username or '*'}")
    return web.json_response({"ok": True, "killed": len(to_kill)})

async def handle_admin_stats(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    disk = shutil.disk_usage(str(DOWNLOADS_DIR)); db = _load_users()
    file_count = files_size = 0
    for p in DOWNLOADS_DIR.rglob("*"):
        if p.is_file(follow_symlinks=False):
            file_count += 1
            try: files_size += p.stat().st_size
            except Exception: pass
    return web.json_response({
        "disk": {"total_gb": round(disk.total/1024**3,2), "used_gb": round(disk.used/1024**3,2), "free_gb": round(disk.free/1024**3,2)},
        "files": {"count": file_count, "size_mb": round(files_size/1024**2,2)},
        "users": {"total": len(db["users"]),
                  "admin": sum(1 for d in db["users"].values() if d.get("role")=="admin"),
                  "disabled": sum(1 for d in db["users"].values() if d.get("disabled"))},
        "sessions": {"active": len(_sessions)},
        "jobs": {"fetch_active": sum(1 for j in _fetch_jobs.values() if j["status"] not in ("done","failed","cancelled")),
                 "torrent_active": sum(1 for j in _torrent_jobs.values() if j["status"] not in ("done","failed","cancelled"))},
        "quota_mb": USER_QUOTA_BYTES//1024//1024 if USER_QUOTA_BYTES > 0 else 0})

async def handle_admin_audit(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    try: lines_n = min(int(req.rel_url.query.get("n", 200)), 2000)
    except Exception: lines_n = 200
    try:
        text = AUDIT_FILE.read_text() if AUDIT_FILE.exists() else ""
        return web.json_response({"lines": text.splitlines()[-lines_n:]})
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)

async def handle_avatar_upload(req):
    if not _is_admin(req): return web.json_response({"error": "forbidden"}, status=403)
    username = _who(req)
    try:
        reader = await req.multipart(); field = await reader.next()
        if field is None or field.name != "file": raise web.HTTPBadRequest()
        data = await field.read(decode=True)
        if len(data) > 2*1024*1024: return web.json_response({"error": "avatar too large (max 2 MB)"}, status=413)
        ext = Path(field.filename or "avatar.png").suffix.lower().lstrip(".")
        if ext not in ("jpg","jpeg","png","gif","webp"): return web.json_response({"error": "image files only"}, status=400)
        mime = {"jpg":"image/jpeg","jpeg":"image/jpeg","png":"image/png","gif":"image/gif","webp":"image/webp"}.get(ext,"image/png")
        data_url = f"data:{mime};base64,{base64.b64encode(data).decode()}"
        db = _load_users(); db["users"][username]["avatar"] = data_url; _save_users(db)
        return web.json_response({"ok": True, "avatar": data_url})
    except web.HTTPException: raise
    except Exception as ex: return web.json_response({"error": str(ex)}, status=500)

async def handle_apikey_create(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    try: body = await req.json(); label = str(body.get("label",""))[:80]
    except Exception: label = ""
    user = _who(req); s = _get_session_or_apikey(req); role = s["role"] if s else "user"
    raw = secrets.token_urlsafe(32); h = _hash_api_key(raw)
    keys = _load_api_keys(); keys[h] = {"user": user, "role": role, "label": label, "created": time.time()}
    _save_api_keys(keys); _audit("apikey_create", user, f"label={label}")
    return web.json_response({"key": raw, "label": label, "note": "Save this key — it will not be shown again."})

async def handle_apikey_list(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    user = _who(req); is_admin = _is_admin(req); keys = _load_api_keys()
    return web.json_response([{"hash": h[:12]+"…","label": e["label"],"created": e["created"],"user": e["user"]}
                               for h, e in keys.items() if is_admin or e["user"] == user])

async def handle_apikey_delete(req):
    if not _check(req): return web.json_response({"error": "unauthorized"}, status=401)
    prefix = req.match_info["prefix"]; user = _who(req); is_admin = _is_admin(req)
    keys = _load_api_keys()
    to_del = [h for h in keys if h.startswith(prefix) and (is_admin or keys[h]["user"] == user)]
    if not to_del: return web.json_response({"error": "not found"}, status=404)
    for h in to_del: keys.pop(h)
    _save_api_keys(keys); _audit("apikey_delete", user, f"prefix={prefix}")
    return web.json_response({"ok": True, "deleted": len(to_del)})

async def handle_static(req):
    name = req.match_info["name"]; path = (STATIC_DIR / name).resolve()
    if not str(path).startswith(str(STATIC_DIR)) or not path.is_file(): raise web.HTTPNotFound()
    ct, _ = mimetypes.guess_type(str(path))
    return web.Response(body=path.read_bytes(), content_type=ct or "application/octet-stream")

# ===========================================================================
# App wiring
# ===========================================================================

def create_app():
    app = web.Application(client_max_size=MAX_UPLOAD_BYTES + 65536)
    r = app.router
    r.add_get   ("/",                              handle_root)
    r.add_get   ("/health",                        handle_health)
    r.add_post  ("/login",                         handle_login)
    r.add_post  ("/register",                      handle_register)
    r.add_post  ("/logout",                        handle_logout)
    r.add_get   ("/session",                       handle_session)
    r.add_get   ("/files",                         handle_files)
    r.add_route ("DELETE", "/files/{tail:.*}",     handle_delete)
    r.add_post  ("/rename",                        handle_rename)
    r.add_post  ("/mkdir",                         handle_mkdir)
    r.add_get   ("/zip",                           handle_zip_folder)
    r.add_post  ("/upload",                        handle_upload)
    r.add_get   ("/preview/{tail:.*}",             handle_preview)
    r.add_get   ("/dl/{tail:.*}",                  handle_download)
    r.add_get   ("/token/{tail:.*}",               handle_make_token)
    r.add_get   ("/get/{token}/{tail:.*}",         handle_token_download)
    r.add_post  ("/move",                          handle_move)
    r.add_post  ("/bulk",                          handle_bulk)
    r.add_get   ("/search",                        handle_search)
    r.add_get   ("/zip-inspect",                   handle_zip_inspect)
    r.add_get   ("/edit/{tail:.*}",                handle_edit_get)
    r.add_put   ("/edit/{tail:.*}",                handle_edit_put)
    r.add_post  ("/share",                         handle_share_create)
    r.add_get   ("/share",                         handle_share_list)
    r.add_delete("/share/{token}",                 handle_share_delete)
    r.add_get   ("/s/{token}",                     handle_share_download)
    r.add_post  ("/s/{token}",                     handle_share_download)
    r.add_post  ("/fetch",                         handle_fetch_url)
    r.add_get   ("/fetch/progress",                handle_fetch_progress)
    r.add_post  ("/fetch/{job_id}/cancel",         handle_fetch_cancel)
    r.add_post  ("/fetch/{job_id}/retry",          handle_fetch_retry)
    r.add_post  ("/torrent",                       handle_torrent)
    r.add_get   ("/torrent/progress",              handle_torrent_progress)
    r.add_post  ("/torrent/{pid}/cancel",          handle_torrent_cancel)
    r.add_get   ("/flags",                         handle_flag_get)
    r.add_post  ("/flags",                         handle_flag_set)
    r.add_get   ("/admin/users",                   handle_admin_users)
    r.add_delete("/admin/users/{username}",        handle_admin_user_delete)
    r.add_patch ("/admin/users/{username}",        handle_admin_user_update)
    r.add_post  ("/admin/users/{username}/reset",  handle_admin_session_reset)
    r.add_post  ("/admin/avatar",                  handle_avatar_upload)
    r.add_get   ("/admin/stats",                   handle_admin_stats)
    r.add_get   ("/admin/audit",                   handle_admin_audit)
    r.add_post  ("/apikeys",                       handle_apikey_create)
    r.add_get   ("/apikeys",                       handle_apikey_list)
    r.add_delete("/apikeys/{prefix}",              handle_apikey_delete)
    r.add_get   ("/static/{name}",                 handle_static)
    return app

async def start_web():
    runner = web.AppRunner(create_app())
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", WEB_PORT).start()
    base = os.environ.get("WEB_BASE", f"http://localhost:{WEB_PORT}")
    log.info("web: %s", base)

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    loop.run_until_complete(start_web())
    loop.run_forever()
