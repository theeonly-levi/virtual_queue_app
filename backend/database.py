import sqlite3

conn = sqlite3.connect('clinic_queue.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        visit_type TEXT NOT NULL,
        status TEXT DEFAULT 'waiting'
    )
''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS visits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER NOT NULL,
        visit_type TEXT NOT NULL,
        advice TEXT,
        FOREIGN KEY(patient_id) REFERENCES patients(id)
    )
''')
conn.commit()

def add_patient(name, visit_type):
    cursor.execute('INSERT INTO patients (name, visit_type) VALUES (?, ?)', (name, visit_type))
    conn.commit()
    return cursor.lastrowid

def log_visit(patient_id, visit_type, advice):
    cursor.execute('INSERT INTO visits (patient_id, visit_type, advice) VALUES (?, ?, ?)',
                   (patient_id, visit_type, advice))
    conn.commit()
