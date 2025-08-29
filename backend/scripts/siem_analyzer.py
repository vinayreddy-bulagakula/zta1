import threading
import time
from datetime import datetime
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'db')))
from connection import get_db_connection
from network_monitor import NetworkMonitor
from threat_detector import ThreatDetector

class SIEMAnalyzer:
    def __init__(self):
        self.running = False
        self.network_monitor = NetworkMonitor()
        self.threat_detector = ThreatDetector()
        self.analysis_thread = None
        
    def start_siem(self):
        """Start complete SIEM system"""
        print("[+] Starting ZTA SIEM System...")
        
        # Start network monitoring
        self.network_monitor.start_monitoring()
        
        # Start threat detection
        self.threat_detector.start_detection()
        
        # Start SIEM analysis
        self.running = True
        self.analysis_thread = threading.Thread(target=self._analyze_events, daemon=True)
        self.analysis_thread.start()
        
        print("[+] SIEM System fully operational")
    
    def stop_siem(self):
        """Stop SIEM system"""
        print("[+] Stopping SIEM System...")
        
        self.running = False
        self.network_monitor.stop_monitoring()
        self.threat_detector.stop_detection()
        
        print("[+] SIEM System stopped")
    
    def _analyze_events(self):
        """Analyze security events and generate reports"""
        while self.running:
            try:
                # Generate periodic security reports
                self._generate_security_summary()
                
                # Clean up old events
                self._cleanup_old_events()
                
                time.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                print(f"[!] SIEM analysis error: {e}")
                time.sleep(60)
    
    def _generate_security_summary(self):
        """Generate security summary"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Get event statistics for the last hour
            query = """
                SELECT 
                    event_type,
                    severity,
                    COUNT(*) as count
                FROM security_events 
                WHERE timestamp > NOW() - INTERVAL 1 HOUR
                GROUP BY event_type, severity
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            if results:
                summary = "Security Summary (Last Hour):\\n"
                malicious_count = 0
                normal_count = 0
                
                for event_type, severity, count in results:
                    summary += f"  {event_type} ({severity}): {count}\\n"
                    if severity == 'MALICIOUS':
                        malicious_count += count
                    else:
                        normal_count += count
                
                if malicious_count > 0:
                    print(f"[!] SECURITY ALERT: {malicious_count} malicious events in the last hour")
                    
                    # Log summary as security event
                    summary_query = """
                        INSERT INTO security_events 
                        (event_type, severity, description)
                        VALUES ('SECURITY_SUMMARY', 'NORMAL', %s)
                    """
                    cursor.execute(summary_query, (summary,))
                    conn.commit()
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            print(f"[!] Security summary error: {e}")
    
    def _cleanup_old_events(self):
        """Clean up old security events"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Keep only last 30 days of events
            query = """
                DELETE FROM security_events 
                WHERE timestamp < NOW() - INTERVAL 30 DAY
            """
            
            cursor.execute(query)
            deleted_count = cursor.rowcount
            
            if deleted_count > 0:
                print(f"[+] Cleaned up {deleted_count} old security events")
            
            # Clean up old network traffic logs (keep 7 days)
            query = """
                DELETE FROM network_traffic 
                WHERE timestamp < NOW() - INTERVAL 7 DAY
            """
            
            cursor.execute(query)
            deleted_count = cursor.rowcount
            
            if deleted_count > 0:
                print(f"[+] Cleaned up {deleted_count} old network traffic logs")
            
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            print(f"[!] Cleanup error: {e}")
    
    def get_real_time_alerts(self):
        """Get recent high-priority alerts"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Get malicious events from last 10 minutes
            query = """
                SELECT event_type, description, source_ip, timestamp
                FROM security_events 
                WHERE severity = 'MALICIOUS' 
                AND timestamp > NOW() - INTERVAL 10 MINUTE
                ORDER BY timestamp DESC
                LIMIT 10
            """
            
            cursor.execute(query)
            alerts = cursor.fetchall()
            
            cursor.close()
            conn.close()
            
            return alerts
            
        except Exception as e:
            print(f"[!] Alert retrieval error: {e}")
            return []
    
    def block_ip(self, ip_address, reason="Manual block"):
        """Manually block an IP address"""
        try:
            self.threat_detector.blocked_ips.add(ip_address)
            
            conn = get_db_connection()
            cursor = conn.cursor()
            
            description = f"IP {ip_address} manually blocked: {reason}"
            
            query = """
                INSERT INTO security_events 
                (event_type, severity, description, source_ip)
                VALUES ('IP_BLOCKED', 'NORMAL', %s, %s)
            """
            
            cursor.execute(query, (description, ip_address))
            conn.commit()
            cursor.close()
            conn.close()
            
            print(f"[+] Blocked IP: {ip_address}")
            return True
            
        except Exception as e:
            print(f"[!] IP blocking error: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        """Manually unblock an IP address"""
        try:
            if ip_address in self.threat_detector.blocked_ips:
                self.threat_detector.blocked_ips.remove(ip_address)
                
                conn = get_db_connection()
                cursor = conn.cursor()
                
                description = f"IP {ip_address} manually unblocked"
                
                query = """
                    INSERT INTO security_events 
                    (event_type, severity, description, source_ip)
                    VALUES ('IP_UNBLOCKED', 'NORMAL', %s, %s)
                """
                
                cursor.execute(query, (description, ip_address))
                conn.commit()
                cursor.close()
                conn.close()
                
                print(f"[+] Unblocked IP: {ip_address}")
                return True
            else:
                return False
                
        except Exception as e:
            print(f"[!] IP unblocking error: {e}")
            return False

# Global SIEM instance
siem = SIEMAnalyzer()

def start_siem_system():
    """Start the complete SIEM system"""
    siem.start_siem()

def stop_siem_system():
    """Stop the SIEM system"""
    siem.stop_siem()

if __name__ == "__main__":
    print("[+] Starting Complete ZTA SIEM System")
    siem.start_siem()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Shutting down SIEM system")
        siem.stop_siem()