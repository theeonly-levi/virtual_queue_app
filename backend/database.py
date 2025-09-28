import sqlite3
import bcrypt

"""Legacy simple DB layer (clinic_queue.db) originally holding only patients & visits.

Extended to also store application users (username + bcrypt hashed password) so that
basic registration/auth flows can work without using the newer db_manager module.

NOTE: There is already a richer abstraction in `db_manager.py` that defines a
separate `database.db` with users + queue tables. For long‑term maintainability
you should pick ONE approach and migrate callers. This file is kept minimal for
backwards compatibility with any code still importing `database.py`.

Tables in clinic_queue.db now:
    patients(id, name, visit_type, status)
    visits(id, patient_id, visit_type, advice)
    users(id, username UNIQUE, password_hash)

Functions added:
    create_user(username, password) -> user_id | raises on duplicate
    get_user_by_username(username) -> dict | None
    verify_password(raw_password, stored_hash) -> bool
"""

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

# New users table (very small surface – prefer db_manager for new code)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
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

# ------------------ User Management (minimal) ------------------
def create_user(username: str, password: str):
    """Create a user and return its id.

    Raises sqlite3.IntegrityError if username already exists.
    """
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
    conn.commit()
    return cursor.lastrowid

def get_user_by_username(username: str):
    cursor.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    if not row:
        return None
    return { 'id': row[0], 'username': row[1], 'password_hash': row[2] }

def verify_password(raw_password: str, stored_hash: str) -> bool:
    try:
        return bcrypt.checkpw(raw_password.encode(), stored_hash.encode())
    except Exception:
        return False

__all__ = [
    'add_patient','log_visit','create_user','get_user_by_username','verify_password'
]
