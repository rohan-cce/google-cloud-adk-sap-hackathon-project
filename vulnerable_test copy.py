import hashlib
import sqlite3
# Hardcoded credentials
API_KEY = "sk-proj-FAKE-KEY-12345"
DB_PASSWORD = "admin123"
def get_user(username):
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return conn.execute(query)
def process_input(data):
    return eval(data)
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()
