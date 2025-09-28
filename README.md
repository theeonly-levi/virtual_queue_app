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

Queue position changes are NOT pushed to FCM (to reduce noise) but are available through the in-app list. You can extend this to push a notification when a patient is near the front (e.g., position <= 2).

### Environment Variables

```
FCM_SERVER_KEY=<your FCM legacy server key>
TWILIO_SID=...(optional legacy SMS)
TWILIO_AUTH_TOKEN=...(optional)
TWILIO_NUMBER=...(optional)
OPENAI_API_KEY=...(optional for AI advice LLM mode)
MED_CHAT_USE_LLM=1 (enable LLM mode if OpenAI key present)
```

If `FCM_SERVER_KEY` is absent or invalid, push notifications are silently skipped (in-app still works).

### Device Token Flow (Client Responsibility)
1. Client (web/mobile) obtains device token using Firebase SDK.
2. Client sends token to backend (you need to implement an endpoint to store tokens per user ID; not included in this MVP).
3. When you create a user account, call:
	 ```python
	 from backend.notifications import notification_service
	 notification_service.send_account_registration(user_id, device_tokens=[...], user_name="Alice")
	 ```
4. For queue updates, the `QueueManager` automatically records position changes in the in-app store.

### Retrieving In-App Notifications
```python
from backend.notifications import notification_service
notes = notification_service.get_user_notifications(user_id)
```
Returns a list like:
```json
[
	{"type": "account_registration", "payload": {"message": "Welcome Alice!"}},
	{"type": "queue_position", "payload": {"position": 3, "visit_type": "consultation"}}
]
```

### Extending Persistence
Currently notifications are in-memory. For production replace `AppNotificationCenter` with a database or Redis implementation. Keep the same interface (`add`, `list`).

### Optional Future Enhancements
* Push "you're next" events when position == 1.
* WebSocket or Server-Sent Events stream for live queue updates.
* Deduplicate or update (instead of append) queue position changes.
* Add expiry / pruning policy for notifications.

## Development

Install backend dependencies:
```bash
pip install -r backend/requirements.txt
```

## AI Medication Assistant
Guardrails prevent dosing, diagnosis, and emergency advice. See `backend/ai_advice.py` for logic and structured medication data handling.

---
Hackathon-grade code; contributions welcome.