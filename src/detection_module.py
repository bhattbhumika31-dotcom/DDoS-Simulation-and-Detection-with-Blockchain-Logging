import time
import threading

MAX_REQUESTS_PER_WINDOW = 5
TIME_WINDOW_SECONDS = 10  
class DetectionModule:
    """
    Implements a traffic detection mechanism using a simple time-window rate limiter
    to detect potential Denial-of-Service (DoS) attacks.
    """
    MAX_REQUESTS_PER_WINDOW = MAX_REQUESTS_PER_WINDOW  
    TIME_WINDOW_SECONDS = TIME_WINDOW_SECONDS
    
    def __init__(self):
      
        self.ip_request_history = {}
    
        self.lock = threading.Lock()
        print(f"Detection: Initialized with Rate Limit Threshold={MAX_REQUESTS_PER_WINDOW} reqs/{TIME_WINDOW_SECONDS}s.")

    def _cleanup_old_requests(self, ip):
        """Removes request timestamps that fall outside the current time window."""
        current_time = time.time()
        time_limit = current_time - TIME_WINDOW_SECONDS
        
        self.ip_request_history[ip] = [
            t for t in self.ip_request_history[ip] 
            if t > time_limit
        ]

    def check_traffic(self, ip):
        """
        Logs the incoming request and checks if the IP has exceeded the rate limit.
        Returns 'detected' for an attack or 'normal'.
        """
        with self.lock:
            current_time = time.time()

            if ip not in self.ip_request_history:
                self.ip_request_history[ip] = []

            self._cleanup_old_requests(ip)

            self.ip_request_history[ip].append(current_time)

            current_count = len(self.ip_request_history[ip])

            if current_count > MAX_REQUESTS_PER_WINDOW:
                return 'detected'
            else:
                return 'normal'