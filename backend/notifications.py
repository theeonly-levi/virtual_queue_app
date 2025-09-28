"""Notification services: FCM Push + In-App notifications.

Environment variables:
  FCM_SERVER_KEY        (required for real push; if missing push disabled)
  TWILIO_SID            (optional legacy SMS)
  TWILIO_AUTH_TOKEN     (optional legacy SMS)
  TWILIO_NUMBER         (optional legacy SMS)

Usage patterns:
  - Register device tokens per user elsewhere (persist them) then call
      notification_service.send_account_registration(user_id, tokens, name)
  - Queue updates: queue manager calls notification_service.record_queue_position(...)
  - Retrieve in-app notifications: notification_service.get_user_notifications(user_id)

The in-app notification center is in-memory; replace with persistent storage
for production (e.g., Redis, DB). All operations are best-effort; push is skipped
when not configured or library unavailable.
"""

from __future__ import annotations

import os
from typing import List, Dict, Optional

# Optional Twilio (kept for backwards compatibility) -------------------------
try:  # pragma: no cover - optional dependency
    from twilio.rest import Client as _TwilioClient  # type: ignore
except Exception:  # pragma: no cover - don't crash if absent
    _TwilioClient = None


def _init_twilio():  # pragma: no cover - light helper
    sid = os.getenv("TWILIO_SID")
    token = os.getenv("TWILIO_AUTH_TOKEN")
    number = os.getenv("TWILIO_NUMBER")
    if not (sid and token and number and _TwilioClient):
        return None, None
    try:
        return _TwilioClient(sid, token), number
    except Exception:
        return None, None


_twilio_client, _twilio_number = _init_twilio()


def send_sms(to_number: str, message: str) -> Optional[str]:  # legacy
    """Send an SMS if Twilio configured; return message SID or None.
    Provided for backward compatibility. Prefer push or in-app notifications.
    """
    if not (_twilio_client and _twilio_number):
        return None
    try:  # pragma: no cover
        msg = _twilio_client.messages.create(
            body=message,
            from_=_twilio_number,
            to=to_number
        )
        return getattr(msg, "sid", None)
    except Exception:
        return None


# FCM Push ------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from pyfcm import FCMNotification  # type: ignore
except Exception:  # pragma: no cover
    FCMNotification = None


class PushNotifier:
    """Wrap FCM push logic. Disabled if no API key or library missing."""

    def __init__(self, api_key: Optional[str]):
        self.enabled = bool(api_key and FCMNotification)
        self._api_key = api_key
        self._client = FCMNotification(api_key=api_key) if self.enabled else None

    def send(self, tokens: List[str], title: str, body: str, data: Optional[Dict] = None) -> Dict:
        if not (self.enabled and tokens):
            return {"status": "skipped"}
        try:
            result = self._client.notify_multiple_devices(
                registration_ids=tokens,
                message_title=title,
                message_body=body,
                data_message=data or {},
            )
            return {"status": "ok", "response": result}
        except Exception as e:  # pragma: no cover
            return {"status": "error", "error": str(e)}

    def send_registration(self, tokens: List[str], user_id: int, user_name: str):
        title = "Account Created"
        body = f"Welcome {user_name}! Your account has been registered."
        return self.send(tokens, title, body, data={"event": "account_registration", "user_id": user_id})


# In-App Notification Center -------------------------------------------------
class AppNotificationCenter:
    """In-memory notification storage (non-persistent)."""

    def __init__(self):
        self._store: Dict[int, List[Dict]] = {}

    def add(self, user_id: int, type_: str, payload: Dict):
        note = {"type": type_, "payload": payload}
        self._store.setdefault(user_id, []).append(note)
        return note

    def list(self, user_id: int) -> List[Dict]:
        return self._store.get(user_id, [])


class NotificationService:
    """High-level facade for push + in-app notifications."""

    def __init__(self, push_notifier: PushNotifier, app_center: AppNotificationCenter):
        self.push = push_notifier
        self.app = app_center

    # Account registration ---------------------------------------------------
    def send_account_registration(self, user_id: int, device_tokens: List[str], user_name: str):
        self.push.send_registration(device_tokens, user_id, user_name)
        self.app.add(user_id, "account_registration", {"message": f"Welcome {user_name}!"})

    # Queue position updates -------------------------------------------------
    def record_queue_position(self, user_id: int, position: int, visit_type: str):
        self.app.add(user_id, "queue_position", {"position": position, "visit_type": visit_type})

    # Retrieval ---------------------------------------------------------------
    def get_user_notifications(self, user_id: int):
        return self.app.list(user_id)


# Global singleton-style instances -------------------------------------------
push_api_key = os.getenv("FCM_SERVER_KEY")
push_notifier = PushNotifier(push_api_key)
app_notification_center = AppNotificationCenter()
notification_service = NotificationService(push_notifier, app_notification_center)

__all__ = [
    "send_sms",
    "PushNotifier",
    "AppNotificationCenter",
    "NotificationService",
    "push_notifier",
    "app_notification_center",
    "notification_service",
]
