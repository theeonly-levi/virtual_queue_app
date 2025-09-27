class QueueManager:
    def __init__(self):
        self.queue = []
        self.next_number = 1

    def add_patient(self, name, visit_type):
        patient = {
            'id': self.next_number,
            'name': name,
            'visit_type': visit_type,
            'status': 'waiting'
        }
        self.queue.append(patient)
        self.next_number += 1
        return patient['id']

    def get_queue_status(self):
        return [{'id': p['id'], 'status': p['status'], 'visit_type': p['visit_type']} for p in self.queue]
