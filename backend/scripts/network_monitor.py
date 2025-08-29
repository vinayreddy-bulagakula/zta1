import subprocess
import threading
import time
import re
import sys
import os
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'db')))
from connection import get_db_connection

class NetworkMonitor:
    def __init__(self):
        self.running = False
        self.wireshark_process = None
        self.monitoring_thread = None
        
    def start_monitoring(self):
        """Start Wireshark packet capture and monitoring"""
        self.running = True
        self.monitoring_thread = threading.Thread(target=self._monitor_traffic, daemon=True)
        self.monitoring_thread.start()
        print("[+] Network monitoring started")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.running = False
        if self.wireshark_process:
            self.wireshark_process.terminate()
        print("[+] Network monitoring stopped")
    
    def _monitor_traffic(self):
        """Monitor network traffic using tshark (Wireshark command line)"""
        try:
            cmd = [
                "tshark",
                "-i", "any",  # Monitor all interfaces
                "-f", "port 5090 or port 5001 or port 3306",  # Filter for our application ports
                "-T", "fields",
                "-e", "frame.time",
                "-e", "ip.src",
                "-e", "ip.dst", 
                "-e", "tcp.port",
                "-e", "http.request.method",
                "-e", "http.request.uri",
                "-e", "tcp.flags",
                "-Y", "http or tcp.flags.syn==1 or tcp.flags.rst==1"
            ]
            
            self.wireshark_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            while self.running and self.wireshark_process:
                line = self.wireshark_process.stdout.readline()
                if line:
                    self._analyze_packet(line.strip())
                elif self.wireshark_process.poll() is not None:
                    break
                    
        except FileNotFoundError:
            print("[!] Wireshark/tshark not found. Please install Wireshark.")
        except Exception as e:
            print(f"[!] Network monitoring error: {e}")
    
    def _analyze_packet(self, packet_data):
        """Analyze captured packet for suspicious activity"""
        if not packet_data or packet_data.count('\t') < 3:
            return
            
        fields = packet_data.split('\t')
        timestamp = fields[0] if len(fields) > 0 else ""
        src_ip = fields[1] if len(fields) > 1 else ""
        dst_ip = fields[2] if len(fields) > 2 else ""
        port = fields[3] if len(fields) > 3 else ""
        method = fields[4] if len(fields) > 4 else ""
        uri = fields[5] if len(fields) > 5 else ""
        tcp_flags = fields[6] if len(fields) > 6 else ""
        
        analysis_result = self._detect_threats(src_ip, dst_ip, port, method, uri, tcp_flags)
        
        # Log to database
        self._log_network_traffic(src_ip, dst_ip, port, packet_data, analysis_result)
        
        # If malicious, create security event
        if analysis_result == "MALICIOUS":
            self._create_security_event(src_ip, method, uri, tcp_flags)
    
    def _detect_threats(self, src_ip, dst_ip, port, method, uri, tcp_flags):
        """Detect potential security threats"""
        
        # Check for port scanning (multiple SYN packets)
        if tcp_flags and "0x00000002" in tcp_flags:  # SYN flag
            if self._is_port_scan(src_ip):
                return "MALICIOUS"
        
        # Check for SQL injection patterns
        if uri and self._detect_sql_injection(uri):
            return "MALICIOUS"
        
        # Check for XSS patterns
        if uri and self._detect_xss(uri):
            return "MALICIOUS"
        
        # Check for suspicious HTTP methods
        if method in ["TRACE", "TRACK", "CONNECT"]:
            return "SUSPICIOUS"
        
        # Check for abnormal request patterns
        if uri and len(uri) > 1000:  # Unusually long URI
            return "SUSPICIOUS"
            
        return "NORMAL"
    
    def _detect_sql_injection(self, uri):
        """Detect SQL injection patterns in URI"""
        sql_patterns = [
            r"(?i)(union.*select)",
            r"(?i)(select.*from)",
            r"(?i)(insert.*into)",
            r"(?i)(delete.*from)",
            r"(?i)(drop.*table)",
            r"(?i)(or.*1=1)",
            r"(?i)(and.*1=1)",
            r"(?i)('.*or.*')",
            r"(?i)(exec.*xp_)",
            r"(?i)(script.*>)",
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, uri):
                return True
        return False
    
    def _detect_xss(self, uri):
        """Detect XSS patterns in URI"""
        xss_patterns = [
            r"(?i)(<script)",
            r"(?i)(javascript:)",
            r"(?i)(onload=)",
            r"(?i)(onerror=)",
            r"(?i)(onclick=)",
            r"(?i)(<img.*onerror)",
            r"(?i)(alert\()",
            r"(?i)(document\.cookie)",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, uri):
                return True
        return False
    
    def _is_port_scan(self, src_ip):
        """Detect potential port scanning"""
        # Simple detection: if we see many connections from same IP in short time
        # In a real implementation, this would be more sophisticated
        return False  # Placeholder
    
    def _log_network_traffic(self, src_ip, dst_ip, port, packet_data, analysis_result):
        """Log network traffic to database"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            query = """
                INSERT INTO network_traffic 
                (source_ip, dest_ip, protocol, packet_data, analysis_result)
                VALUES (%s, %s, %s, %s, %s)
            """
            
            cursor.execute(query, (src_ip, dst_ip, port, packet_data[:1000], analysis_result))
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            print(f"[!] Database logging error: {e}")
    
    def _create_security_event(self, src_ip, method, uri, tcp_flags):
        """Create security event for malicious activity"""
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            event_type = "NETWORK_THREAT"
            description = f"Malicious network activity detected from {src_ip}"
            
            if method and uri:
                if self._detect_sql_injection(uri):
                    event_type = "SQL_INJECTION_ATTEMPT"
                    description = f"SQL injection attempt: {method} {uri[:100]}"
                elif self._detect_xss(uri):
                    event_type = "XSS_ATTEMPT"
                    description = f"XSS attempt: {method} {uri[:100]}"
            
            query = """
                INSERT INTO security_events 
                (event_type, severity, description, source_ip)
                VALUES (%s, 'MALICIOUS', %s, %s)
            """
            
            cursor.execute(query, (event_type, description, src_ip))
            conn.commit()
            cursor.close()
            conn.close()
            
            print(f"[!] ALERT: {description}")
            
        except Exception as e:
            print(f"[!] Security event logging error: {e}")

# Global monitor instance
monitor = NetworkMonitor()

def start_network_monitoring():
    """Start the network monitoring service"""
    monitor.start_monitoring()

if __name__ == "__main__":
    print("[+] Starting ZTA Network Monitor")
    monitor.start_monitoring()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Shutting down network monitor")
        monitor.stop_monitoring()