import os
import hashlib
import sqlite3

# ==========================================
# 1. HARDCODED CREDENTIALS (CWE-798)
# ==========================================

# Pattern: password = "..."
def db_connect():
    password = "supersecretpassword123"  # 🔴 Critical
    return sqlite3.connect("db", password=password)

# Pattern: api_key = "..."
def call_external_api():
    api_key = "AIzaSyD-1234567890abcdef1234567890"  # 🔴 Critical
    return "called"

# Pattern: aws_secret = "..."
aws_access_key = "AKIA1234567890EXAMPLE"  # 🔴 Critical
aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 🔴 Critical


# ==========================================
# 2. SQL INJECTION (CWE-89)
# ==========================================

def get_user_unsafe(username, user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # Case 1: Simple execution with concatenation
    # 🔴 Critical
    conn.execute("SELECT * FROM users WHERE name = '" + username + "'")

    # Case 2: f-string execution
    # 🔴 Critical
    cursor.execute(f"SELECT * FROM products WHERE id = {user_id}")

    # Case 3: % formatting
    # 🔴 Critical
    conn.execute("DELETE FROM logs WHERE id = %s" % user_id)

    # Case 4: Multi-line Assignment + Execution (conn)
    # 🔴 Critical (Should be replaced by single line)
    query = "SELECT * FROM users WHERE email = '" + username + "'"
    return conn.execute(query).fetchall()

    # Case 5: Multi-line Assignment + Execution (cursor)
    # 🔴 Critical
    delete_q = "DELETE FROM users WHERE id = '" + user_id + "'"
    cursor.execute(delete_q)


# ==========================================
# 3. CODE INJECTION (CWE-94)
# ==========================================

def run_calculator(operation):
    # 🔴 Critical: eval()
    # User can pass "__import__('os').system('rm -rf /')"
    result = eval(operation)
    return result

def execute_plugin(code_snippet):
    # 🔴 Critical: exec()
    exec(code_snippet)


# ==========================================
# 4. WEAK CRYPTOGRAPHY (CWE-327)
# ==========================================

def hash_password_weak(password):
    # 🟡 Medium: MD5 is broken
    return hashlib.md5(password.encode()).hexdigest()

def hash_data_sha1(data):
    # 🟡 Medium: SHA1 is deprecated
    return hashlib.sha1(data.encode()).hexdigest()


# ==========================================
# 5. PATH TRAVERSAL (CWE-22)
# ==========================================

def read_user_file(filename, request):
    # 🟠 High: No validation, can access ../../../etc/passwd
    path = os.path.join("/var/www/uploads", request.args.get("file"))
    with open(path, "r") as f:
        return f.read()

    # Another pattern
    return open(filename).read()
