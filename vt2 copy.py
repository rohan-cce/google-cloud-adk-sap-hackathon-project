# sql_demo.py — Intentionally vulnerable for testing
import sqlite3

def get_user_by_name(username):
    """VULNERABLE: SQL Injection via string concatenation."""
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()

def search_products(search_term):
    """VULNERABLE: SQL Injection via f-string."""
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{search_term}%'")
    return cursor.fetchall()

def delete_user(user_id):
    """VULNERABLE: SQL Injection via format string."""
    conn = sqlite3.connect("app.db")
    conn.execute("DELETE FROM users WHERE id = %s" % user_id)
    conn.commit()
