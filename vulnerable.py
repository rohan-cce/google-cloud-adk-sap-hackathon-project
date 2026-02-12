import sqlite3
from flask import Flask, request

app = Flask(__name__)
conn = sqlite3.connect("users.db", check_same_thread=False)
cursor = conn.cursor()

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    result = cursor.execute(query).fetchone()

    if result:
        return "Login successful"
    else:
        return "Invalid credentials"

@app.route("/profile")
def profile():
    user = request.args.get("user")
    query = "SELECT * FROM users WHERE username = '" + user + "'"
    data = cursor.execute(query).fetchall()
    return str(data)

@app.route("/delete_user")
def delete_user():
    user_id = request.args.get("id")
    cursor.execute("DELETE FROM users WHERE id = " + user_id)
    conn.commit()
    return "User deleted"

@app.route("/debug")
def debug():
    return str(cursor.execute("SELECT * FROM users").fetchall())

app.run(debug=True)
