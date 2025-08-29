import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'db')))
from connection import get_db_connection

class ThreatDetector:
    def __init__(self):
        self.running = False
        self.detection_thread = None
        
        # Track failed login attempts per IP
        self.failed_logins = defaultdict(deque)
        self.blocked_ips = set()
        
        # Thresholds
        self.max_failed_logins = 3
        self.time_window = timedelta(minutes=10)
        self.block_duration = timedelta(minutes=30)
        
    def start_detection(self):
        """Start threat detection service"""
        self.running = True
        self.detection_thread = threading.Thread(target=self._monitor_threats, daemon=True)
        self.detection_thread.start()
        print("[+] Threat detection started")
    
    def stop_detection(self):
        """Stop threat detection service"""
        self.running = False
        print("[+] Threat detection stopped")
    
    def _monitor_threats(self):
        """Main threat monitoring loop"""
        while self.running:
            try:
                # Check for brute force attacks
                self._detect_brute_force()
                
                # Check for repeated malicious requests
                self._detect_repeated_attacks()
                
                # Clean up old data
                self._cleanup_old_data()
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"[!] Threat detection error: {e}")
                time.sleep(30)
    
    def _detect_brute_force(self):
        """Detect brute force login attempts"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Get recent failed login attempts
            query = """
                SELECT source_ip, COUNT(*) as attempts, MAX(timestamp) as last_attempt
                FROM security_events 
                WHERE event_type IN ('LOGIN_FAILED', 'MFA_FAILED') 
                AND timestamp > NOW() - INTERVAL 10 MINUTE
                GROUP BY source_ip
                HAVING attempts >= %s
            """
            
            cursor.execute(query, (self.max_failed_logins,))
            results = cursor.fetchall()
            
            for source_ip, attempts, last_attempt in results:
                if source_ip not in self.blocked_ips:
                    self._create_brute_force_alert(source_ip, attempts)
                    self.blocked_ips.add(source_ip)
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            print(f"[!] Brute force detection error: {e}")
    
    def _detect_repeated_attacks(self):
        """Detect repeated attack patterns"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Look for repeated XSS/SQL injection attempts
            query = """
                SELECT source_ip, event_type, COUNT(*) as attempts
                FROM security_events 
                WHERE event_type IN ('SQL_INJECTION_ATTEMPT', 'XSS_ATTEMPT') 
                AND timestamp > NOW() - INTERVAL 5 MINUTE
                GROUP BY source_ip, event_type
                HAVING attempts >= 2
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            for source_ip, event_type, attempts in results:
                self._create_repeated_attack_alert(source_ip, event_type, attempts)
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            print(f"[!] Repeated attack detection error: {e}")
    
    def _create_brute_force_alert(self, source_ip, attempts):
        """Create alert for brute force attack"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            description = f"BRUTE FORCE ATTACK: {attempts} failed login attempts from {source_ip} - IP BLOCKED"
            
            query = """
                INSERT INTO security_events 
                (event_type, severity, description, source_ip)
                VALUES ('BRUTE_FORCE_ATTACK', 'MALICIOUS', %s, %s)
            """
            
            cursor.execute(query, (description, source_ip))
            conn.commit()
            cursor.close()
            conn.close()
            
            print(f"[!] CRITICAL ALERT: Brute force attack from {source_ip} - {attempts} attempts")
            
        except Exception as e:
            print(f"[!] Brute force alert error: {e}")
    
    def _create_repeated_attack_alert(self, source_ip, event_type, attempts):
        """Create alert for repeated attacks"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            description = f"REPEATED {event_type}: {attempts} attempts from {source_ip}"
            
            query = """
                INSERT INTO security_events 
                (event_type, severity, description, source_ip)
                VALUES ('REPEATED_ATTACK', 'MALICIOUS', %s, %s)
            """
            
            cursor.execute(query, (description, source_ip))
            conn.commit()
            cursor.close()
            conn.close()
            
            print(f"[!] ALERT: Repeated {event_type} from {source_ip} - {attempts} attempts")
            
        except Exception as e:
            print(f"[!] Repeated attack alert error: {e}")
    
    def _cleanup_old_data(self):
        """Clean up old tracking data"""
        current_time = datetime.now()
        
        # Clean up failed login tracking
        for ip in list(self.failed_logins.keys()):
            # Remove old attempts outside time window
            while (self.failed_logins[ip] and 
                   current_time - self.failed_logins[ip][0] > self.time_window):
                self.failed_logins[ip].popleft()
            
            # Remove empty entries
            if not self.failed_logins[ip]:
                del self.failed_logins[ip]
        
        # Clean up blocked IPs after block duration
        self.blocked_ips = {ip for ip in self.blocked_ips 
                           if self._should_keep_blocked(ip)}
    
    def _should_keep_blocked(self, ip):
        """Check if IP should remain blocked"""
        # In a real implementation, you'd track when each IP was blocked
        # For now, we'll just keep them blocked for this session
        return True
    
    def check_ip_blocked(self, ip):
        """Check if an IP is currently blocked"""
        return ip in self.blocked_ips
    
    def add_failed_login(self, ip):
        """Add a failed login attempt for an IP"""
        current_time = datetime.now()
        self.failed_logins[ip].append(current_time)
        
        # Check if this IP should be blocked
        if len(self.failed_logins[ip]) >= self.max_failed_logins:
            if ip not in self.blocked_ips:
                self.blocked_ips.add(ip)
                self._create_brute_force_alert(ip, len(self.failed_logins[ip]))

# Global detector instance
detector = ThreatDetector()

def start_threat_detection():
    """Start the threat detection service"""
    detector.start_detection()

def is_ip_blocked(ip):
    """Check if an IP is blocked"""
    return detector.check_ip_blocked(ip)

if __name__ == "__main__":
    print("[+] Starting ZTA Threat Detector")
    detector.start_detection()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Shutting down threat detector")
        detector.stop_detection()