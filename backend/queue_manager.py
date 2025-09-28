"""Queue manager now backed by persistent DB layer (db_manager).

Provides a thin façade so other modules can remain agnostic of storage changes.
Notification hooks still supported.
"""
from .notifications import notification_service
from . import db_manager


class QueueManager:
    def __init__(self, notifier=notification_service):
        self.notifier = notifier

    def add_patient(self, user_id: int, name: str, visit_type: str):
        ok, entry_id, err = db_manager.join_queue(user_id=user_id, name=name, visit_type=visit_type)
        if not ok:
            return None, err
        position = db_manager.get_position(user_id)
        if self.notifier and position is not None:
            self.notifier.record_queue_position(user_id=user_id, position=position, visit_type=visit_type)
        return entry_id, None

    def list_waiting(self):
        return db_manager.list_queue(include_serving=True)

    def advance(self):
        nxt = db_manager.next_patient()
        if nxt and self.notifier:
            # After advancing, recompute & publish positions for remaining waiting
            remaining = db_manager.list_queue()
            for idx, row in enumerate([r for r in remaining if r['status'] == 'waiting'], start=1):
                self.notifier.record_queue_position(user_id=row['user_id'], position=idx, visit_type=row['visit_type'])
        return nxt

    def mark_done(self, entry_id: int):
        return db_manager.mark_done(entry_id)

    def user_position(self, user_id: int):
        return db_manager.get_position(user_id)


queue_manager = QueueManager()

__all__ = ["QueueManager", "queue_manager"]
