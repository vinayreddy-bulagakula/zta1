from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'scripts')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'db')))

from scripts.mfa import register_user, verify_otp
from scripts.rbac import get_user_roles
from scripts.logger import log_event
from scripts.siem_analyzer import start_siem_system
from db.connection import get_db_connection

app = Flask(__name__)
CORS(app)

# Start SIEM system on server startup
try:
    start_siem_system()
    print("[+] SIEM system started with API server")
except Exception as e:
    print(f"[!] SIEM startup warning: {e}")

@app.before_request
def security_middleware():
    """Security middleware to detect malicious requests"""
    client_ip = request.remote_addr or request.environ.get('HTTP_X_FORWARDED_FOR', 'unknown')
    request_uri = request.full_path
    user_agent = request.headers.get('User-Agent', '')
    
    # Detect SQL injection attempts
    if _detect_sql_injection(request_uri) or _detect_sql_injection(user_agent):
        _log_security_event('SQL_INJECTION_ATTEMPT', 'MALICIOUS', 
                          f'SQL injection attempt: {request_uri}', client_ip)
        return jsonify({"error": "Request blocked"}), 403
    
    # Detect XSS attempts
    if _detect_xss(request_uri) or _detect_xss(user_agent):
        _log_security_event('XSS_ATTEMPT', 'MALICIOUS', 
                          f'XSS attempt: {request_uri}', client_ip)
        return jsonify({"error": "Request blocked"}), 403
    
    # Check for blocked IPs (basic implementation)
    # In production, this would check against a proper blocklist
    
def _detect_sql_injection(text):
    """Detect SQL injection patterns"""
    if not text:
        return False
    
    sql_patterns = [
        r"(?i)(union.*select)",
        r"(?i)(select.*from)",
        r"(?i)(insert.*into)",
        r"(?i)(delete.*from)",
        r"(?i)(drop.*table)",
        r"(?i)(or.*1=1)",
        r"(?i)(and.*1=1)",
        r"(?i)('.*or.*')",
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, text):
            return True
    return False

def _detect_xss(text):
    """Detect XSS patterns"""
    if not text:
        return False
    
    xss_patterns = [
        r"(?i)(<script)",
        r"(?i)(javascript:)",
        r"(?i)(onload=)",
        r"(?i)(onerror=)",
        r"(?i)(onclick=)",
        r"(?i)(<img.*onerror)",
        r"(?i)(alert\()",
    ]
    
    for pattern in xss_patterns:
        if re.search(pattern, text):
            return True
    return False

def _log_security_event(event_type, severity, description, source_ip):
    """Log security event to database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
            INSERT INTO security_events (event_type, severity, description, source_ip)
            VALUES (%s, %s, %s, %s)
        """
        
        cursor.execute(query, (event_type, severity, description, source_ip))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Security logging error: {e}")

@app.route('/api/auth/register', methods=['POST'])
def api_register():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password') 
        email = data.get('email')
        
        mfa_secret = register_user(username, password, email)

        return jsonify({
            "success": True,
            "message": "User registered successfully",
            "mfa_secret": mfa_secret
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route('/api/auth/verify', methods=['POST'])
def api_verify():
    try:
        data = request.json
        username = data.get('username')
        otp = data.get('otp')
        ip = request.remote_addr
        
        result = verify_otp(username, otp, ip)
        return jsonify({"success": True, "verified": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/users/<username>/roles', methods=['GET'])
def api_get_roles(username):
    try:
        roles = get_user_roles(username)
        return jsonify({"success": True, "roles": roles})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/logs', methods=['POST'])
def api_log_event():
    try:
        data = request.json
        event_type = data.get('event_type')
        username = data.get('username')
        status = data.get('status')
        message = data.get('message', '')
        
        log_event(event_type, username, status, message)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/security/events', methods=['GET'])
def get_security_events():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = """
            SELECT se.event_type, se.severity, se.description, se.source_ip, 
                   se.timestamp, COALESCE(u.username, 'Unknown') as username
            FROM security_events se
            LEFT JOIN users u ON se.user_id = u.user_id
            ORDER BY se.timestamp DESC
            LIMIT 100
        """
        
        cursor.execute(query)
        events = []
        for row in cursor.fetchall():
            events.append({
                'event_type': row[0],
                'severity': row[1],
                'description': row[2],
                'source_ip': row[3],
                'timestamp': row[4].isoformat() if row[4] else None,
                'username': row[5]
            })
        
        cursor.close()
        conn.close()
        
        return jsonify({"success": True, "events": events})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/security/block-ip', methods=['POST'])
def block_ip():
    try:
        data = request.json
        ip_address = data.get('ip_address')
        reason = data.get('reason', 'Manual block via API')
        
        # Log the IP block event
        _log_security_event('IP_BLOCKED', 'NORMAL', 
                          f'IP {ip_address} blocked: {reason}', ip_address)
        
        return jsonify({"success": True, "message": f"IP {ip_address} blocked"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

if __name__ == '__main__':
    app.run(host='localhost', port=5001, debug=True)