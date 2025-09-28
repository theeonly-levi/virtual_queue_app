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
