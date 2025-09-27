import hashlib
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

def hash_id(input_str):
    return hashlib.sha256(input_str.encode()).hexdigest()

def encrypt_data(data):
    return cipher.encrypt(data.encode())

def decrypt_data(encrypted_data):
    return cipher.decrypt(encrypted_data).decode()

session_data = {}
def store_session(patient_id, info):
    session_data[patient_id] = info

def clear_session():
    session_data.clear()
