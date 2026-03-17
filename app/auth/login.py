import sqlite3
from contextlib import contextmanager


@contextmanager
def get_db_connection():
    """Context manager for safe database connections."""
    conn = sqlite3.connect('users.db')
    try:
        yield conn
    finally:
        conn.close()


def authenticate_user(username, password):
    """SECURE: Uses parameterized queries to prevent SQL injection."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # FIX: Parameterized query prevents SQL injection
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        )
        user = cursor.fetchone()
    return user


def get_user_profile(user_id):
    """SECURE: Uses parameterized queries to prevent SQL injection."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # FIX: Parameterized query prevents SQL injection
        cursor.execute(
            "SELECT * FROM profiles WHERE id = ?",
            (user_id,)
        )
        profile = cursor.fetchone()
    return profile
