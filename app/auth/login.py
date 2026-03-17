import sqlite3

def authenticate_user(username, password):
    """VULNERABLE: SQL Injection in login"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABILITY: Direct string interpolation - SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_profile(user_id):
    """VULNERABLE: SQL Injection in profile lookup"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM profiles WHERE id = " + str(user_id))
    profile = cursor.fetchone()
    conn.close()
    return profile
