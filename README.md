# Virtual Queue App

MVP virtual clinic queue system featuring:
* Patient queue management (position tracking)
* In-app notification center
* Optional push notifications (Firebase Cloud Messaging)
* AI medication info assistant (guardrailed)
* Basic visit logging & extensible architecture

## Notifications Overview

The app now supports two channels:

1. Push Notifications (account registration events) via **Firebase Cloud Messaging (FCM)** using `pyfcm`.
2. In-App Notifications (queue position updates + a copy of registration) stored in-memory.

### Deployment (Render) Quick Guide

1. Create a new Web Service in Render, connect this repo.
2. Environment
	- Runtime: Python
	- Build Command: (leave blank – Render will install `backend/requirements.txt` automatically)
	- Start Command: Procfile is present (`web: gunicorn backend.wsgi:app ...`). Render will honor it.
3. Add Environment Variables:
	- `SECRET_KEY` = long random string
4. (Optional) Add a Persistent Disk if you need durable SQLite storage. Mount it at `/data` and set `DB_PATH` env var consumed by future refactor.
5. (Optional) Deploy frontend separately as a Static Site pointing to the backend API.

### Local Dev
```
pip install -r backend/requirements.txt
export SECRET_KEY=dev-secret
python -m backend.security  # or: gunicorn backend.wsgi:app
```

### Notes
Two database layers currently exist (`database.py` legacy and `db_manager.py` new). Prefer `db_manager.py` for user & queue operations. Plan a consolidation pass before production hardening.

## Patient UI Overview

The patient interface (`frontend/patient_ui/`) provides:

* Combined Login / Registration card (tabbed) hitting `/login` and `/register`.
* Optional auto-join to queue during registration (checkbox sets `auto_join`).
* Queue ticket view hitting `/queue/me` every few seconds (manual refresh button also available).
* Join form to call `/queue/join` with a chosen visit type.
* Medication Info Assistant (AI): toggle panel that posts questions to `/ai/advice` (must be authenticated). The backend module applies safety filters (no dosing / diagnosis) and appends a disclaimer.

### Recent Additions
* Persistent patient JWT (localStorage key: `patient_jwt_token`).
* `/queue/leave` endpoint to cancel a waiting ticket (cannot cancel once serving).
* Advice panel now keeps a rolling transcript (last ~30 Q/A turns stored client-side only).
* Persistent AI Advice logging (`ai_advice_logs` table) capturing question, answer, llm_used, model.
* `/ai/history` endpoint (GET, auth) returns recent advice interactions for the authenticated user.
* Unified database path support via `DB_PATH` env and WAL mode for improved SQLite concurrency.
* OpenAI model usage now recorded when LLM path is taken.

To point the frontend at a different backend origin, set a global before scripts:
```html
<script>window.API_BASE = 'https://your-backend.example.com';</script>
<script src="queue_status.js" defer></script>
```

### Planned Enhancements (not yet implemented)
* Leave queue endpoint & button enablement
* LocalStorage token persistence for session resume
* Display of historical AI advice turns
* Urgency-based priority highlighting (integrate `urgency_detector`)

## AI Advice Persistence & OpenAI Integration

The medication info assistant stores interactions in `ai_advice_logs` (created automatically):

Columns: `id, user_id, question, answer, llm_used (0/1), model, created_at`.

### Enabling OpenAI
Set the following environment variables:

Required to activate LLM path (otherwise local structured fallback only):
* `OPENAI_API_KEY` – Your OpenAI API key.
* `MED_CHAT_USE_LLM=1` – Feature flag to allow LLM requests.

Optional tweaks:
* `MED_CHAT_MODEL` (default: `gpt-4.1-mini`) – Model name.
* `MED_CHAT_DEBUG=1` – Include internal metrics in `/ai/advice` response (debug only).

Safety rules enforced server-side block dosing, diagnosis, emergencies. Fallback answers use curated structured medication JSON.

### Fetching User History
`GET /ai/history?limit=25` (Authorization: Bearer <token>)
Returns: `{ "items": [ { id, question, answer, llm_used, model, created_at }, ...], count }`

### Database Consolidation
Set `DB_PATH` env var (e.g. `/data/app.db`) to use a single SQLite database for all tables. WAL mode and `foreign_keys=ON` are applied at connection time in `db_manager.py`.

If deploying on Render with a persistent disk mounted at `/data`:
```
DB_PATH=/data/app.db
```

## Minimal Environment Variables

For basic operation (no LLM):
```
SECRET_KEY=change-me
DB_PATH=/data/app.db            # if using a mounted volume
MED_CHAT_USE_LLM=0              # explicit off (default off if unset)
```

For OpenAI-enabled advice:
```
SECRET_KEY=change-me
DB_PATH=/data/app.db
OPENAI_API_KEY=sk-...
MED_CHAT_USE_LLM=1
MED_CHAT_MODEL=gpt-4.1-mini     # optional
```


# Virtual Queue App

MVP virtual clinic queue system featuring:
* Patient queue management (position tracking)
* In-app notification center
* Optional push notifications (Firebase Cloud Messaging)
* AI medication info assistant (guardrailed)
* Basic visit logging & extensible architecture

## Notifications Overview

The app now supports two channels:

1. Push Notifications (account registration events) via **Firebase Cloud Messaging (FCM)** using `pyfcm`.
2. In-App Notifications (queue position updates + a copy of registration) stored in-memory.
