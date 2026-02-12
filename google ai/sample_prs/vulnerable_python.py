# Vulnerable Python code — for testing the Security Review Agent
# This file contains INTENTIONAL security vulnerabilities. DO NOT use in production.

import hashlib
import os
import sqlite3


# ❌ CWE-798: Hardcoded credentials
DB_PASSWORD = "super_secret_password_123"
API_KEY = "sk-proj-abc123def456ghi789"
SECRET_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"


def connect_to_database():
    """Connect to database with hardcoded password."""
    conn = sqlite3.connect("app.db")
    # ❌ CWE-798: Password in source code
    conn.execute(f"PRAGMA key = '{DB_PASSWORD}'")
    return conn


def get_user(username):
    """Get user from database — SQL injection vulnerable."""
    conn = connect_to_database()
    cursor = conn.cursor()
    # ❌ CWE-89: SQL Injection via string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def search_products(search_term, category):
    """Search products — another SQL injection vector."""
    conn = connect_to_database()
    cursor = conn.cursor()
    # ❌ CWE-89: SQL Injection via f-string
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{search_term}%' AND category = '{category}'")
    return cursor.fetchall()


def process_user_input(user_data):
    """Process user input — code injection vulnerability."""
    # ❌ CWE-94: Code injection via eval()
    result = eval(user_data)
    return result


def execute_dynamic_code(code_string):
    """Execute dynamic code — another code injection vector."""
    # ❌ CWE-94: Code injection via exec()
    exec(code_string)


def hash_password(password):
    """Hash a password — using weak algorithm."""
    # ❌ CWE-327: Weak cryptographic hash
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    """Verify password — also weak hashing."""
    # ❌ CWE-327: Weak cryptographic hash (SHA1)
    return hashlib.sha1(password.encode()).hexdigest() == stored_hash


def read_user_file(filename):
    """Read a file based on user input — path traversal."""
    # ❌ CWE-22: Path traversal — no sanitization
    filepath = os.path.join("/var/data/uploads", filename)
    with open(filepath, "r") as f:
        return f.read()


if __name__ == "__main__":
    # This would be triggered by user input in a real app
    user = get_user("admin' OR 1=1 --")
    print(f"User: {user}")

    hashed = hash_password("mysecretpassword")
    print(f"Hash: {hashed}")

    # Dangerous!
    result = process_user_input("__import__('os').system('whoami')")
    print(f"Result: {result}")
