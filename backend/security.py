# import hashlib
# from cryptography.fernet import Fernet

# key = Fernet.generate_key()
# cipher = Fernet(key)

# def hash_id(input_str):
#     return hashlib.sha256(input_str.encode()).hexdigest()

# def encrypt_data(data):
#     return cipher.encrypt(data.encode())

# def decrypt_data(encrypted_data):
#     return cipher.decrypt(encrypted_data).decode()

# session_data = {}
# def store_session(patient_id, info):
#     session_data[patient_id] = info

# def clear_session():
#     session_data.clear()

# print("test")


#HTTPS Enforcement & Security Headers (Flask Example)
from flask import Flask, request, jsonify, redirect
from functools import wraps
import os, bcrypt, jwt, sqlite3, datetime, re
from dotenv import load_dotenv
from collections import defaultdict

# Load environment
load_dotenv()
SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-key"  # fallback for POC

app = Flask(__name__)

# -------------------------------
# HTTPS Enforcement & Security Headers
# -------------------------------
@app.before_request
def enforce_https():
    if not request.is_secure and app.env != "development":
        return redirect(request.url.replace("http://", "https://"), code=301)

@app.after_request
def set_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    # Relaxed CSP for hackathon iteration (allows inline). Tighten later.
    response.headers['Content-Security-Policy'] = "default-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
    # Simple permissive CORS for POC
    origin = request.headers.get('Origin', '*')
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Vary'] = 'Origin'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, OPTIONS'
    if request.method == 'OPTIONS':
        response.status_code = 204
    return response

# -------------------------------
# Database setup
# -------------------------------
DB_PATH = "database.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE,
                 password TEXT
                 )''')
    conn.commit()
    conn.close()

init_db()

# Integrate new db-backed queue + users abstraction
from . import db_manager  # type: ignore  # noqa: E402
from .queue_manager import queue_manager  # noqa: E402

def seed_admin():
    adm = db_manager.get_user_by_username('admin')
    if not adm:
        ok, uid, err = db_manager.create_user('admin', 'admin123', role='admin')
        if ok:
            print('[seed] admin user created id', uid)
        else:
            print('[seed] admin user creation failed', err)

seed_admin()

# -------------------------------
# Auth & JWT
# -------------------------------
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def generate_token(user_id, roles=None):
    payload = {
        "user_id": user_id,
        "roles": roles or [],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            user_roles = request.user.get("roles", [])
            if not any(role in user_roles for role in required_roles):
                return jsonify({"error": "Insufficient permissions"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# -------------------------------
# Input Sanitization & Validation
# -------------------------------
def sanitize(input_string):
    if not input_string:
        return ""
    return re.sub(r'[<>"\']', '', input_string).strip()

# -------------------------------
# Rate Limiting
# -------------------------------
requests_log = defaultdict(list)
MAX_REQUESTS = 10
WINDOW = 60  # seconds

def rate_limiter(identifier):
    now = datetime.datetime.utcnow().timestamp()
    requests_log[identifier] = [t for t in requests_log[identifier] if now - t < WINDOW]
    if len(requests_log[identifier]) >= MAX_REQUESTS:
        return False
    requests_log[identifier].append(now)
    return True

# -------------------------------
# Routes (generalized)
# -------------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(force=True, silent=True) or {}
    username = sanitize(data.get('username'))
    password = data.get('password')
    name = sanitize(data.get('name') or username)
    visit_type = sanitize(data.get('visit_type') or 'General')
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    ok, user_id, err = db_manager.create_user(username, password)
    if not ok:
        return jsonify({"error": err or 'Registration failed'}), 409
    if data.get('auto_join'):
        queue_manager.add_patient(user_id, name=name, visit_type=visit_type)
    return jsonify({"message": "User registered", "user_id": user_id}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = sanitize(data.get('username'))
    password = data.get('password')
    ip = request.remote_addr
    if not rate_limiter(ip):
        return jsonify({"error": "Too many requests"}), 429
    user = db_manager.get_user_by_username(username)
    if not user or not db_manager.verify_password(password, user['password_hash']):
        return jsonify({"error": "Invalid credentials"}), 401
    token = generate_token(user['id'], roles=[user.get('role','patient')])
    # Added 'username' key for frontend expectations
    return jsonify({"token": token, "user_id": user['id'], "role": user.get('role'), "username": user['username']})

@app.route("/protected", methods=["GET"])
@login_required
def protected():
    return jsonify({"message": f"Hello user {request.user['user_id']}!"})

@app.route("/admin", methods=["GET"])
@role_required(["admin"])
def admin_only():
    return jsonify({"message": "Welcome, admin!"})

# -------------------------------
# Queue Endpoints
# -------------------------------
@app.route('/queue/join', methods=['POST'])
@login_required
def queue_join():
    data = request.get_json(force=True, silent=True) or {}
    visit_type = sanitize(data.get('visit_type') or 'General')
    name = sanitize(data.get('name') or 'Anonymous')
    user_id = request.user['user_id']
    entry_id, err = queue_manager.add_patient(user_id=user_id, name=name, visit_type=visit_type)
    if not entry_id:
        return jsonify({"error": err or 'Already in queue'}), 409
    position = queue_manager.user_position(user_id)
    return jsonify({"message": 'Joined queue', "entry_id": entry_id, "position": position})

@app.route('/queue/me', methods=['GET'])
@login_required
def queue_me():
    user_id = request.user['user_id']
    position = queue_manager.user_position(user_id)
    entries = queue_manager.list_waiting()
    total_waiting = sum(1 for e in entries if e['status'] == 'waiting')
    serving = next((e for e in entries if e['status'] == 'serving'), None)
    # Determine the current user's active entry (waiting or serving)
    user_entry = next((e for e in entries if e['user_id'] == user_id and e['status'] in ('waiting','serving')), None)
    entry_payload = None
    if user_entry:
        entry_payload = {
            'id': user_entry['id'],
            'status': user_entry['status'],
            'position': position if user_entry['status'] == 'waiting' else None
        }
    # Added 'entry' key to align with frontend script expectation (data.entry)
    return jsonify({
        'in_queue': position is not None,
        'position': position,
        'total_waiting': total_waiting,
        'serving': serving,
        'entry': entry_payload
    })

@app.route('/queue/list', methods=['GET'])
@role_required(['admin'])
def queue_list():
    return jsonify(queue_manager.list_waiting())

@app.route('/queue/next', methods=['POST'])
@role_required(['admin'])
def queue_next():
    nxt = queue_manager.advance()
    if not nxt:
        return jsonify({'message': 'Queue empty'})
    return jsonify({'serving': nxt})

@app.route('/queue/done/<int:entry_id>', methods=['POST'])
@role_required(['admin'])
def queue_done(entry_id: int):
    ok = queue_manager.mark_done(entry_id)
    if not ok:
        return jsonify({'error': 'Not found or already done'}), 404
    return jsonify({'message': 'Marked done'})

# -------------------------------
# Run
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)
