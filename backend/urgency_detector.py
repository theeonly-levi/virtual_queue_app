def check_urgency(visit_description):
    emergency_keywords = ['severe', 'urgent', 'chest pain', 'bleeding']
    for word in emergency_keywords:
        if word in visit_description.lower():
            return True
    return False
