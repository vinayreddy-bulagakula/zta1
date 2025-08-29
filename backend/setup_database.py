import pymysql
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'db')))
from connection import get_db_connection

def create_database_schema():
    conn = None
    cursor = None
    try:
        conn = pymysql.connect(
    host='localhost',
    user='root',
    password='root123',
    db='MySQL',
    port=3307
)
        cursor = conn.cursor()
        
        cursor.execute("CREATE DATABASE IF NOT EXISTS zta_security")
        cursor.execute("USE zta_security")
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                mfa_secret VARCHAR(32) NOT NULL,
                email VARCHAR(100) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                first_login BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                role_id INT AUTO_INCREMENT PRIMARY KEY,
                role_name VARCHAR(50) UNIQUE NOT NULL,
                description TEXT
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id INT,
                role_id INT,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (role_id) REFERENCES roles(role_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                log_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                event_type VARCHAR(50) NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                event_id INT AUTO_INCREMENT PRIMARY KEY,
                event_type VARCHAR(50) NOT NULL,
                severity ENUM('NORMAL', 'MALICIOUS') DEFAULT 'NORMAL',
                description TEXT NOT NULL,
                source_ip VARCHAR(45),
                user_id INT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_traffic (
                traffic_id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip VARCHAR(45),
                dest_ip VARCHAR(45),
                protocol VARCHAR(10),
                packet_data TEXT,
                analysis_result ENUM('NORMAL', 'SUSPICIOUS', 'MALICIOUS') DEFAULT 'NORMAL'
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                session_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                logout_time TIMESTAMP NULL,
                ip_address VARCHAR(45),
                status ENUM('ACTIVE', 'EXPIRED', 'LOGGED_OUT') DEFAULT 'ACTIVE',
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_actions (
                action_id INT AUTO_INCREMENT PRIMARY KEY,
                admin_user_id INT,
                action_type VARCHAR(50) NOT NULL,
                target_user_id INT,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_user_id) REFERENCES users(user_id),
                FOREIGN KEY (target_user_id) REFERENCES users(user_id)
            )
        """)
        
        cursor.execute("INSERT IGNORE INTO roles (role_name, description) VALUES ('admin', 'Administrator')")
        cursor.execute("INSERT IGNORE INTO roles (role_name, description) VALUES ('user', 'Regular User')")
        cursor.execute("INSERT IGNORE INTO roles (role_name, description) VALUES ('guest', 'Guest User')")
        
        # Create pre-configured admin user
        import bcrypt
        import pyotp
        import qrcode
        
        # Check if admin user already exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        admin_exists = cursor.fetchone()[0]
        
        if admin_exists == 0:
            # Create admin user
            password_hash = bcrypt.hashpw('admin123'.encode(), bcrypt.gensalt()).decode()
            mfa_secret = pyotp.random_base32()
            
            cursor.execute(
                "INSERT INTO users (username, password_hash, mfa_secret, email) VALUES (%s, %s, %s, %s)",
                ('admin', password_hash, mfa_secret, 'admin@example.com')
            )
            
            # Assign admin role
            cursor.execute(
                "INSERT INTO user_roles (user_id, role_id) SELECT u.user_id, r.role_id FROM users u, roles r WHERE u.username = 'admin' AND r.role_name = 'admin'"
            )
            
            # Generate QR code
            totp = pyotp.TOTP(mfa_secret)
            uri = totp.provisioning_uri(name='admin', issuer_name='ZTA Security System')
            img = qrcode.make(uri)
            
            # Save QR code in project root (go up from backend to MF-133 root)
            qr_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'admin_mfa_qr.png')
            img.save(qr_path)
            
            print("[✓] Pre-configured admin user created:")
            print("    Username: admin")
            print("    Password: admin123")
            print("    QR Code: admin_mfa_qr.png (scan with Google Authenticator)")
        else:
            print("[✓] Admin user already exists")
        
        conn.commit()
        print("[✓] Database schema created successfully")
        
    except Exception as e:
        print(f"[✗] Database setup error: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    create_database_schema()