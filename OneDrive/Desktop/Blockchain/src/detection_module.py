# from flask import Flask, request, jsonify
# import time

# app = Flask(_name_)

# window = 2       # seconds to check
# threshold = 50   # requests in window considered attack

# requests_by_ip = {}

# @app.route("/", methods=["GET", "POST"])
# def detect():
#     ip = request.remote_addr or "unknown"
#     now = time.time()

#     if ip not in requests_by_ip:
#         requests_by_ip[ip] = []
#     requests_by_ip[ip].append(now)

#     cutoff = now - window
#     recent = [t for t in requests_by_ip[ip] if t >= cutoff]
#     requests_by_ip[ip] = recent

#     count = len(recent)

#     if count > threshold:
#         status = "attack"
#         print(f" DDoS detected from {ip}: {count} requests in last {window}s")
#     else:
#         status = "normal"

#     return jsonify({"status": status, "count": count})

# @app.route("/metrics")
# def metrics():
#     now = time.time()
#     snapshot = {}
#     for ip, times in requests_by_ip.items():
#         recent = [t for t in times if t >= now - window]
#         requests_by_ip[ip] = recent
#         snapshot[ip] = len(recent)

#     return jsonify({"window": window, "threshold": threshold, "counts": snapshot})

# if _name_ == "_main_":
#     print("Starting simple DDoS detection demo (detection only)")
#     print(f"Visit http://127.0.0.1:8000/ — window={window}s, threshold={threshold}")
#     app.run(host="127.0.0.1", port=8000)# # Mansi Kabdal - Detection Module

import time
import threading

# Configuration for the threshold logic
MAX_REQUESTS_PER_WINDOW = 5  # Max requests allowed from a single IP
TIME_WINDOW_SECONDS = 10     # Time window for counting requests (10 seconds)

class DetectionModule:
    """
    Implements a simple rate-limiting/threshold-based DDoS detection mechanism.
    Tracks recent requests from each IP and flags an 'attack' if the rate
    exceeds the defined threshold within the time window.
    """
    def __init__(self):
        # Stores IP -> list of timestamps for recent requests
        self.ip_request_history = {}
        # Mutex lock for thread-safe access to the shared history dictionary
        self.lock = threading.Lock()
        print(f"Detection: Initialized with Threshold={MAX_REQUESTS_PER_WINDOW} reqs/{TIME_WINDOW_SECONDS}s.")

    def _cleanup_old_requests(self, ip):
        """Removes timestamps from the history that are outside the time window."""
        current_time = time.time()
        # Keep only timestamps that are within the TIME_WINDOW_SECONDS
        self.ip_request_history[ip] = [
            t for t in self.ip_request_history[ip] 
            if t > (current_time - TIME_WINDOW_SECONDS)
        ]

    def check_traffic(self, ip):
        """
        Processes a new request from an IP, updates its history, and determines
        if the traffic should be flagged as an attack.

        :param ip: The source IP address of the request.
        :return: 'normal' or 'detected'
        """
        with self.lock:
            current_time = time.time()

            # Initialize history for new IP
            if ip not in self.ip_request_history:
                self.ip_request_history[ip] = []

            # Step 1: Clean up old requests
            self._cleanup_old_requests(ip)

            # Step 2: Add the new request timestamp
            self.ip_request_history[ip].append(current_time)

            # Step 3: Check the count against the threshold
            current_count = len(self.ip_request_history[ip])

            if current_count > MAX_REQUESTS_PER_WINDOW:
                # DDoS condition met
                print(f"Detection: ATTACK DETECTED from IP {ip}. Rate: {current_count} in {TIME_WINDOW_SECONDS}s.")
                return 'detected'
            else:
                # Normal traffic condition
                return 'normal'

# Example usage (for testing this module in isolation)
if __name__ == '__main__':
    detector = DetectionModule()
    
    # Simulate normal traffic (one request every 5 seconds)
    print("Simulating Normal Traffic...")
    print(f"IP 1.1.1.1: {detector.check_traffic('1.1.1.1')}") # 1
    time.sleep(5)
    print(f"IP 1.1.1.1: {detector.check_traffic('1.1.1.1')}") # 2
    
    # Simulate an attack from a different IP (burst traffic)
    print("\nSimulating Attack Traffic...")
    
    # 5 requests are generally allowed (threshold is > 5)
    for i in range(1, 6): 
        status = detector.check_traffic('2.2.2.2')
        print(f"IP 2.2.2.2 Request {i}: {status}")
        time.sleep(0.1) # Fast burst

    # The 6th request should trigger detection
    status = detector.check_traffic('2.2.2.2')
    print(f"IP 2.2.2.2 Request 6: {status}") # Should be 'detected'
