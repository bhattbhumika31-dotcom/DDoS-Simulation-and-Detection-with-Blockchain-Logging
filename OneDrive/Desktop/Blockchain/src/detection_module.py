import pandas as pd
import time
import json
from datetime import datetime

WINDOW = 2           
THRESHOLD = 50       
LOGFILE = "detection_log_data.jsonl"   

traffic_dataframe = pd.DataFrame(columns=["ip", "timestamp", "phase", "detected"])
def log_data_event(event):
    with open(LOGFILE, "a") as file:
        file.write(json.dumps(event) + "\n")

def record_request(ip, phase):
    global traffic_dataframe 
    now = time.time()
    new_row = pd.DataFrame([{
        "ip": ip,
        "timestamp": now,
        "phase": phase
    }])
    traffic_dataframe = pd.concat([traffic_dataframe, new_row], ignore_index=True)
    traffic_dataframe = traffic_dataframe[traffic_dataframe["timestamp"] >= now - WINDOW]
    same_ip_rows = traffic_dataframe[traffic_dataframe["ip"] == ip]
    ip_count = same_ip_rows.shape[0]
    detected = ip_count > THRESHOLD
    if detected:
        print(f" Attack detected from {ip}: {ip_count} requests in {WINDOW} seconds [{phase}]")
    event = {
        "ip": ip,
        "count": ip_count,
        "phase": phase,
        "detected": detected,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }
    log_data_event(event)
 return event
