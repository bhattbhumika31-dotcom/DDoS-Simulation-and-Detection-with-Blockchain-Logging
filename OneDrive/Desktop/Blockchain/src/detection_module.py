import pandas as pd
import time
import json
from datetime import datetime

# Constants
WINDOW = 2             # Time window for rate calculation (seconds)
THRESHOLD = 50         # Request count threshold for attack detection
LOGFILE = "detection_log_data.jsonl" # File to store detection events

class DetectionModule:
    """
    Simulates a network traffic anomaly detection system based on rate limiting 
    within a defined time window.
    """
    def __init__(self):
        # Initialize an empty DataFrame to store recent traffic logs
        self.traffic_dataframe = pd.DataFrame(columns=["ip", "timestamp", "phase", "detected"])
        self.WINDOW = WINDOW
        self.THRESHOLD = THRESHOLD
        
        # Metrics for dashboard display
        self.total_requests = 0
        self.detected_attacks = 0
        self.last_detection_time = "N/A"

    def reset_metrics_for_new_simulation(self):
        """Resets all metrics and the internal DataFrame."""
        self.traffic_dataframe = pd.DataFrame(columns=["ip", "timestamp", "phase", "detected"])
        self.total_requests = 0
        self.detected_attacks = 0
        self.last_detection_time = "N/A"

    def get_metrics(self):
        """Returns current state metrics for the Flask API."""
        return {
            "total_requests": self.total_requests,
            "detected_attacks": self.detected_attacks,
            "current_rate_window": f"{self.WINDOW}s",
            "detection_threshold": self.THRESHOLD,
            "last_detection_time": self.last_detection_time
        }

    def log_data_event(self, event):
        """Appends a detection event to the JSON Lines log file."""
        with open(LOGFILE, "a") as file:
            file.write(json.dumps(event) + "\n")

    def record_request(self, ip, phase):
        """
        Records an incoming request, updates the traffic window, and checks 
        for an attack based on the rate threshold.
        """
        self.total_requests += 1
        now = time.time()
        
        # 1. Add new request row
        new_row = pd.DataFrame([{
            "ip": ip,
            "timestamp": now,
            "phase": phase
        }])
        self.traffic_dataframe = pd.concat([self.traffic_dataframe, new_row], ignore_index=True)
        
        # 2. Trim old data outside the window
        self.traffic_dataframe = self.traffic_dataframe[self.traffic_dataframe["timestamp"] >= now - self.WINDOW]
        
        # 3. Calculate rate for this IP
        same_ip_rows = self.traffic_dataframe[self.traffic_dataframe["ip"] == ip]
        ip_count = same_ip_rows.shape[0]
        detected = ip_count > self.THRESHOLD
        
        if detected:
            self.detected_attacks += 1
            self.last_detection_time = datetime.now().strftime("%H:%M:%S")
            print(f" !!! ATTACK DETECTED !!! from {ip}: {ip_count} requests in {self.WINDOW} seconds [{phase}]")
            
        # 4. Create and log the event structure
        event = {
            "ip": ip,
            "count": ip_count,
            "phase": phase,
            "detected": detected,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        }
        self.log_data_event(event)

        # 5. Return the event structure
        return event
