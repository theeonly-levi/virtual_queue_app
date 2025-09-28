from .notifications import notification_service


class QueueManager:
    def __init__(self, notifier=notification_service):
        self.queue = []
        self.next_number = 1
        self.notifier = notifier

    def add_patient(self, name, visit_type, user_id=None):
        """Add a patient and record their initial queue position.

        Parameters:
            name: Patient name
            visit_type: Reason / category of visit
            user_id: Optional external user identifier (defaults to assigned patient id)
        """
        patient = {
            'id': self.next_number,
            'name': name,
            'visit_type': visit_type,
            'status': 'waiting'
        }
        self.queue.append(patient)
        self.next_number += 1

        position = len(self.queue)
        if user_id is None:
            user_id = patient['id']
        if self.notifier:
            self.notifier.record_queue_position(user_id=user_id, position=position, visit_type=visit_type)
        return patient['id']

    def get_queue_status(self):
        return [{'id': p['id'], 'status': p['status'], 'visit_type': p['visit_type']} for p in self.queue]

    def recompute_positions(self):
        """Re-publish queue positions (e.g., after a removal or status change)."""
        if not self.notifier:
            return
        for idx, patient in enumerate(self.queue):
            self.notifier.record_queue_position(
                user_id=patient['id'],
                position=idx + 1,
                visit_type=patient['visit_type']
            )
