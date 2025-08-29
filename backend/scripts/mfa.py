import sys
import os
import pyotp
import qrcode
import bcrypt
import pymysql

# Add backend and db paths for module imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'db')))

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'db')))
from connection import get_db_connection
from rbac import get_user_roles
from logger import log_event

def register_user(username, password, email):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Hash the password
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    # Generate MFA secret
    mfa_secret = pyotp.random_base32()
    totp = pyotp.TOTP(mfa_secret)

    # Insert user into DB
    sql = "INSERT INTO users (username, password_hash, mfa_secret, email) VALUES (%s, %s, %s, %s)"
    cursor.execute(sql, (username, hashed_pw.decode(), mfa_secret, email))
    conn.commit()

    # Generate QR Code for Google Authenticator
    uri = totp.provisioning_uri(name=username, issuer_name="ZTA Security System")
    img = qrcode.make(uri)

    # Save locally in backend
    qr_filename = f"{username}_mfa_qr.png"
    img.save(qr_filename)

    # ✅ Copy QR to WebApp static folder
    webapp_images_path = r"C:\Users\vinay\Downloads\MF-133-2 2\MF-133-2 2\web-ui\ZTAWebApp\wwwroot\images"
    try:
        import shutil
        shutil.copy(qr_filename, os.path.join(webapp_images_path, qr_filename))
        print(f"[+] QR Code saved to webapp: {webapp_images_path}\\{qr_filename}")
    except Exception as e:
        print(f"[!] Failed to copy QR code to webapp images folder: {e}")

    print(f"[+] User '{username}' registered with MFA.\nScan the QR code in your authenticator app.")

    cursor.close()
    conn.close()
    return mfa_secret

def verify_otp(username, otp_code, ip_address="127.0.0.1"):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT mfa_secret FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()

    if result:
        mfa_secret = result[0]
        totp = pyotp.TOTP(mfa_secret)
        is_valid = totp.verify(otp_code)

        if is_valid:
            print(f"[✓] OTP verified successfully for {username}.")
            log_attempt(username, True, "OTP matched")
            log_attempt("admin", "LOGIN", "OTP matched") 
            cursor.close()
            conn.close()
            return True
        else:    
            print(f"[✗] OTP verification failed for {username}.")
            log_attempt(username, False, "OTP mismatch")
            log_attempt("admin", "LOGIN", "OTP failed")
            cursor.close()
            conn.close()
            return False
    else:
        print("[!] User not found.")
        log_attempt(username, False, "User not found")
        log_event("LOGIN", username, "FAILURE", "User not found")
        cursor.close()
        conn.close()
        return False

def log_attempt(username, event_type, description):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get user_id from username
    cursor.execute("SELECT user_id FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()

    if not result:
        print("[!] User not found when logging attempt.")
        conn.close()
        return

    user_id = result[0]

    query = """
        INSERT INTO logs (user_id, event_type, description)
        VALUES (%s, %s, %s)
    """
    cursor.execute(query, (user_id, event_type, description))
    conn.commit()
    cursor.close()
    conn.close()


# Example CLI use
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Invalid usage. Use:")
        print("  python mfa.py register <username> <email>")
        print("  python mfa.py verify <username>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "register" and len(sys.argv) == 4:
        username = sys.argv[2]
        email = sys.argv[3]
        password = input("Enter password: ")
        register_user(username, password, email)

    elif command == "verify" and len(sys.argv) == 3:
        username = sys.argv[2]
        otp_input = input("Enter current OTP: ")
        verify_otp(username, otp_input)

    else:
        print("Invalid usage. Use:")
        print("  python mfa.py register <username> <email>")
        print("  python mfa.py verify <username>")

