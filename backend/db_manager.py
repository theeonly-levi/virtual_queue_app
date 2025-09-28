"""Database management system for users and queue integration.

Provides a thin abstraction layer around SQLite for:
- User registration & authentication (with bcrypt hashing)
- Queue entry creation & status updates
- Position calculation

NOTE: For hackathon/POC simplicity this uses synchronous sqlite3 access with a
single shared connection (thread-safe operations could be added with locks if needed).

Schema (tables):
  users(id INTEGER PK, username TEXT UNIQUE, password_hash TEXT, role TEXT DEFAULT 'patient', created_at TIMESTAMP)
  queue_entries(id INTEGER PK, user_id INTEGER, name TEXT, visit_type TEXT, status TEXT, created_at TIMESTAMP, started_at TIMESTAMP, completed_at TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id))

Queue statuses: waiting -> serving -> done (or skipped/cancelled if extended later)
"""
from __future__ import annotations

import sqlite3, bcrypt, datetime, contextlib
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path

DB_PATH = Path(__file__).parent / "database.db"

# --- Connection Helpers ----------------------------------------------------
_conn: Optional[sqlite3.Connection] = None

def get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
    return _conn

@contextlib.contextmanager
def cursor_ctx():
    cur = get_conn().cursor()
    try:
        yield cur
        get_conn().commit()
    finally:
        cur.close()

# --- Schema Init -----------------------------------------------------------

def init_schema():
    with cursor_ctx() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              role TEXT DEFAULT 'patient',
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS queue_entries (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              name TEXT NOT NULL,
              visit_type TEXT NOT NULL,
                            status TEXT NOT NULL DEFAULT 'waiting',
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              started_at TIMESTAMP,
              completed_at TIMESTAMP,
              FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_queue_status_created ON queue_entries(status, created_at)")

# --- User Management -------------------------------------------------------

def hash_password(raw: str) -> str:
    return bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()

def verify_password(raw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(raw.encode(), hashed.encode())
    except Exception:
        return False

def create_user(username: str, password: str, role: str = "patient") -> Tuple[bool, Optional[int], Optional[str]]:
    with cursor_ctx() as c:
        try:
            c.execute("INSERT INTO users(username, password_hash, role) VALUES(?,?,?)", (username, hash_password(password), role))
            return True, c.lastrowid, None
        except sqlite3.IntegrityError:
            return False, None, "Username already exists"

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    with cursor_ctx() as c:
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        row = c.fetchone()
        return dict(row) if row else None

def get_user(user_id: int) -> Optional[Dict[str, Any]]:
    with cursor_ctx() as c:
        c.execute("SELECT * FROM users WHERE id=?", (user_id,))
        row = c.fetchone()
        return dict(row) if row else None

# --- Queue Operations ------------------------------------------------------

def user_in_active_queue(user_id: int) -> bool:
    with cursor_ctx() as c:
        c.execute("SELECT 1 FROM queue_entries WHERE user_id=? AND status IN ('waiting','serving')", (user_id,))
        return c.fetchone() is not None

def join_queue(user_id: int, name: str, visit_type: str) -> Tuple[bool, Optional[int], Optional[str]]:
    if user_in_active_queue(user_id):
        return False, None, "User already in queue"
    with cursor_ctx() as c:
        c.execute("INSERT INTO queue_entries(user_id, name, visit_type) VALUES(?,?,?)", (user_id, name, visit_type))
        return True, c.lastrowid, None

def list_queue(include_serving: bool = True) -> List[Dict[str, Any]]:
    statuses = ("waiting","serving") if include_serving else ("waiting",)
    with cursor_ctx() as c:
        q_marks = ",".join(["?"]*len(statuses))
        c.execute(f"SELECT * FROM queue_entries WHERE status IN ({q_marks}) ORDER BY created_at ASC", statuses)
        return [dict(r) for r in c.fetchall()]

def get_position(user_id: int) -> Optional[int]:
    with cursor_ctx() as c:
        c.execute("SELECT id, user_id FROM queue_entries WHERE status='waiting' ORDER BY created_at ASC")
        waiting = c.fetchall()
        for idx, row in enumerate(waiting, start=1):
            if row[1] == user_id:
                return idx
    return None

def next_patient() -> Optional[Dict[str, Any]]:
    # Mark current serving (if any) done, then take first waiting -> serving
    with cursor_ctx() as c:
        # complete current
        c.execute("UPDATE queue_entries SET status='done', completed_at=? WHERE status='serving'", (datetime.datetime.utcnow(),))
        # fetch first waiting
        c.execute("SELECT id FROM queue_entries WHERE status='waiting' ORDER BY created_at ASC LIMIT 1")
        row = c.fetchone()
        if not row:
            return None
        pid = row[0]
        c.execute("UPDATE queue_entries SET status='serving', started_at=? WHERE id=?", (datetime.datetime.utcnow(), pid))
        c.execute("SELECT * FROM queue_entries WHERE id=?", (pid,))
        r2 = c.fetchone()
        return dict(r2) if r2 else None

def mark_done(entry_id: int) -> bool:
    with cursor_ctx() as c:
        c.execute("UPDATE queue_entries SET status='done', completed_at=? WHERE id=?", (datetime.datetime.utcnow(), entry_id))
        return c.rowcount > 0

def cancel_active_for_user(user_id: int) -> bool:
    """Cancel a user's active waiting entry (cannot cancel once serving)."""
    with cursor_ctx() as c:
        c.execute("UPDATE queue_entries SET status='cancelled', completed_at=? WHERE user_id=? AND status='waiting'", (datetime.datetime.utcnow(), user_id))
        return c.rowcount > 0

# Convenience for demo ------------------------------------------------------

def reset_all():  # caution: clears data (for hackathon demos)
    with cursor_ctx() as c:
        c.execute("DELETE FROM queue_entries")
        c.execute("DELETE FROM users")

# Initialize schema on import
init_schema()

# Legacy compatibility: if an older 'users' table exists with column name 'password'
# instead of 'password_hash', attempt a lightweight migration.
def _maybe_migrate_legacy_password_column():
    try:
        with cursor_ctx() as c:
            c.execute("PRAGMA table_info(users)")
            cols = [r[1] for r in c.fetchall()]
            if 'password' in cols and 'password_hash' not in cols:
                # Perform an in-place rename by creating temp table
                c.execute("ALTER TABLE users RENAME TO users_legacy_tmp")
                c.execute("""
                    CREATE TABLE users (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE NOT NULL,
                      password_hash TEXT NOT NULL,
                      role TEXT DEFAULT 'patient',
                      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                c.execute("SELECT id, username, password as password_legacy, role, created_at FROM users_legacy_tmp")
                rows = c.fetchall()
                for r in rows:
                    # We cannot know if legacy password was hashed; just copy into password_hash field.
                    c.execute("INSERT INTO users(id, username, password_hash, role, created_at) VALUES(?,?,?,?,?)",
                              (r[0], r[1], r[2], r[3], r[4]))
                c.execute("DROP TABLE users_legacy_tmp")
    except Exception:
        pass

_maybe_migrate_legacy_password_column()

__all__ = [
    'create_user','get_user_by_username','verify_password','get_user','join_queue','get_position',
    'list_queue','next_patient','mark_done','user_in_active_queue','reset_all','cancel_active_for_user'
]
