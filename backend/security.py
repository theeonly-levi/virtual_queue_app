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
SECRET_KEY = os.environ.get("SECRET_KEY")

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
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
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
    data = request.json
    username = sanitize(data.get("username"))
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
    hashed = hash_password(password)
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username exists"}), 409

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = sanitize(data.get("username"))
    password = data.get("password")
    ip = request.remote_addr
    if not rate_limiter(ip):
        return jsonify({"error": "Too many requests"}), 429
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if not row or not verify_password(password, row[1]):
        return jsonify({"error": "Invalid credentials"}), 401
    token = generate_token(row[0])
    return jsonify({"token": token})

@app.route("/protected", methods=["GET"])
@login_required
def protected():
    return jsonify({"message": f"Hello user {request.user['user_id']}!"})

@app.route("/admin", methods=["GET"])
@role_required(["admin"])
def admin_only():
    return jsonify({"message": "Welcome, admin!"})

# -------------------------------
# Run
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)
