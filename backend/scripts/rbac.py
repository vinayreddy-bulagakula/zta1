import sys
import os
import pymysql

# Ensure DB module path is included
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'db')))
from connection import get_db_connection

def get_user_roles(username):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        sql = """
            SELECT r.role_name
            FROM users u
            JOIN user_roles ur ON u.user_id = ur.user_id
            JOIN roles r ON ur.role_id = r.role_id
            WHERE u.username = %s
        """
        cursor.execute(sql, (username,))
        roles = [row[0] for row in cursor.fetchall()]

        return roles

    except Exception as e:
        print(f"[!] Error fetching roles for {username}: {e}")
        return []

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

# Test utility
if __name__ == "__main__":
    username = input("Enter username to check roles: ")
    roles = get_user_roles(username)
    if roles:
        print(f"[✓] Roles for {username}: {roles}")
    else:
        print(f"[✗] No roles found or error occurred.")
