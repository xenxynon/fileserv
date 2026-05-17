# file.serv

A self-hosted file server with a web UI. Upload, download, preview, and share files from anywhere.

## Features

- **File browser** — list, sort, filter by type, search
- **Upload** — drag-and-drop, multi-file, progress bar with speed/ETA
- **Preview** — images, video, audio, PDFs, text/code
- **Download** — direct download, copy permanent link
- **Remote fetch** — download a file from any HTTP/HTTPS URL into the server
- **Folders** — create, rename, move/copy files between folders, download folder as ZIP
- **Bulk ops** — select multiple files to delete, move, or zip
- **Text editor** — edit text/code files in-browser
- **Share links** — time-limited, optionally password-protected, hit-limited
- **Torrent** — download via magnet link or .torrent file (admin only, requires `aria2c`)
- **API keys** — bearer token auth for automation
- **Admin** — user management, audit log, session control, feature flags

## Video Playback Note

Browsers can only decode certain audio codecs. **MKV, TS, and AVI** files frequently carry AC3, EAC3, or DTS audio which no browser supports natively — you'll hear only background audio (effects track) or silence. This is a browser limitation, not a server bug.

**Fix:** Download the file and watch in [VLC](https://www.videolan.org/vlc/). The video player shows a warning banner with a **Download** button and an **Open in VLC** button (works on Android if VLC is installed).

## Security

- Files are written with `0o640` permissions — no execute bits, ever
- All responses include `X-Content-Type-Options: nosniff`
- Sessions use HTTP-only, SameSite=Strict cookies; expire after 24 hours
- Rate limiting on login/register endpoints
- Path traversal protection on all file operations
- Private/LAN network URLs blocked in remote fetch

## Setup

```bash
pip install aiohttp python-dotenv
cp .env.example .env
# Edit .env — set WEB_ADMIN_PASS at minimum
python web.py
```

Open `http://localhost:8080`. Log in as `admin` with your chosen password.

## Configuration (`.env`)

| Variable | Default | Description |
|---|---|---|
| `WEB_PORT` | `8080` | Port to listen on |
| `WEB_ADMIN_PASS` | — | Admin password (required) |
| `DOWNLOADS_DIR` | `./downloads` | Where files are stored |
| `MAX_UPLOAD_MB` | `2048` | Max single upload size |
| `MAX_FETCH_MB` | `4096` | Max remote-fetch file size |
| `QUOTA_MB` | `0` (unlimited) | Per-user storage quota |
| `LINK_SECRET` | random | HMAC secret for permanent links |
| `COOKIE_SECURE` | `false` | Set `true` when serving over HTTPS |
| `MAX_SESSIONS_PER_USER` | `10` | Max concurrent sessions per user |

## Tunneling (quick public URL)

```bash
# Cloudflare Tunnel — no account needed, generates temporary URL
cloudflared tunnel --url http://localhost:8080
```

## Telegram Bot

Set `BOT_TOKEN` and `ALLOWED_USERS` in `.env`, then run `bot.py` alongside `web.py`. Lets you upload/download files directly from a Telegram chat.
