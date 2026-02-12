import re
from security_review_agent.tools.vulnerability_detector import detect_vulnerabilities

# Test case 1: Assignment + Execute with indentation and return
code1 = """
def get_users(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()
"""

# Test case 2: Just assignment (single line)
code2 = """
def get_users(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
"""

# Test case 3: Execute with different object name
code3 = """
def delete_user(user_id):
    query = "DELETE FROM users WHERE id = '" + user_id + "'"
    db.execute(query)
"""

print("--- Test Case 1 ---")
result1 = detect_vulnerabilities(code1, "test1.py")
for v in result1["vulnerabilities"]:
    print(f"Type: {v['type']}")
    print(f"Suggestion:\n{v['secure_suggestion']}")
    print(f"Span: {v.get('span_lines', 1)}")

print("\n--- Test Case 2 ---")
result2 = detect_vulnerabilities(code2, "test2.py")
for v in result2["vulnerabilities"]:
    print(f"Type: {v['type']}")
    print(f"Suggestion:\n{v['secure_suggestion']}")
    print(f"Span: {v.get('span_lines', 1)}")

print("\n--- Test Case 3 ---")
result3 = detect_vulnerabilities(code3, "test3.py")
for v in result3["vulnerabilities"]:
    print(f"Type: {v['type']}")
    print(f"Suggestion:\n{v['secure_suggestion']}")
    print(f"Span: {v.get('span_lines', 1)}")
