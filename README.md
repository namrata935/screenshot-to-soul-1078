# Screenshot To Soul

Implement exactly the screenshot and nothing else

This project was built with [Lovable](https://lovable.dev).

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/4d81d035-096b-4c96-8035-5fedd9f82795).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```

Visual threat inference (existing Flask server, unchanged):

```sh
npm run model:serve
```

## Cybersecurity analytics (platform monitoring)

This service watches the VMS itself (logins, video access, camera heartbeats). It does **not** replace the CNN-LSTM Flask model or the React dashboard.

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | SQLAlchemy URL (PostgreSQL). Default in Compose: `postgresql+psycopg://vms:vms@postgres:5432/cyber_analytics` |
| `CYBER_HMAC_SECRET` | HMAC key used to pseudonymize IP addresses in `security_events` |
| `CYBER_ADMIN_API_KEY` | Sent as `X-Admin-Key` for admin-only reads |
| `RULE_BRUTE_FORCE_THRESHOLD` | Max failed logins before alerting (default: `5`) |
| `RULE_BRUTE_FORCE_WINDOW_SECONDS` | Sliding window for brute force detection in seconds (default: `60`) |
| `RULE_CREDENTIAL_STUFFING_THRESHOLD_USERNAMES` | Distinct accounts targeted before alerting (default: `3`) |
| `RULE_CREDENTIAL_STUFFING_WINDOW_SECONDS` | Sliding window for credential stuffing in seconds (default: `120`) |
| `RULE_IMPOSSIBLE_ACCESS_WINDOW_SECONDS` | Window for concurrent logins from different IPs in seconds (default: `300`) |
| `RULE_MASS_EXPORT_THRESHOLD` | Video views/downloads threshold before alerting (default: `10`) |
| `RULE_MASS_EXPORT_WINDOW_SECONDS` | Sliding window for mass export in seconds (default: `600`) |
| `RULE_PRIVILEGE_ABUSE_THRESHOLD` | Repeated permission denied responses before alerting (default: `3`) |
| `RULE_PRIVILEGE_ABUSE_WINDOW_SECONDS` | Sliding window for privilege abuse in seconds (default: `300`) |
| `RULE_CAMERA_HEARTBEAT_TIMEOUT_SECONDS` | Maximum allowed silence before camera tampering alert (default: `180`) |

```sh
docker compose up --build
# API: http://localhost:8001  (Postgres: localhost:5432)

cd cyber_analytics
python -m pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8001
python -m pytest
```

Ingest an event from another service: `POST /api/v1/security-events`. Auth/video/camera hook routes under `/api/v1/auth`, `/api/v1/videos`, `/api/v1/cameras` are logged automatically by middleware.
