visits = []

def log_visit(patient_id, visit_type):
    visit_record = {'id': patient_id, 'visit_type': visit_type}
    visits.append(visit_record)
    return visit_record
