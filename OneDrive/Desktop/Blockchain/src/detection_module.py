from flask import Flask, request, jsonify
from collections import deque
import time
import threading
import json
WINDOW = 2          
THRESHOLD = 50      
LOGFILE = "detection_log.jsonl"

traffic = {}           
lock = threading.Lock()  

def log_event(event):
    with open(LOGFILE, "a") as f:
        f.write(json.dumps(event) + "\n")

def create_app(evaluation_callback=None):
    app = Flask(__name__)
    @app.route("/", methods=["GET", "POST"])
    def detect():
        ip = request.remote_addr or "unknown"
        phase = request.headers.get("X-Phase", "Unknown")
        now = time.time()

        with lock:
            dq = traffic.setdefault(ip, deque())
            dq.append(now)
            while dq and now - dq[0] > WINDOW:
                dq.popleft()
            count = len(dq)

        detected = False
        if count > THRESHOLD:
            detected = True
            print(f"Attack detected from {ip}: {count} reqs in {WINDOW}s [{phase}]")

        event = {
            "ip": ip,
            "count": count,
            "phase": phase,
            "detected": detected
        }

        log_event(event)

        if evaluation_callback:
            evaluation_callback(detected, phase, event)
       return jsonify(event)
    
    @app.route("/metrics")
    def metrics():
        now = time.time()
        with lock:
            snapshot = {}
            count = 0
        for t in dq:
            if now - t <= WINDOW:
             count += 1
        return jsonify(snapshot)
    return app
    
if __name__ == "__main__":
    app = create_app()
    print("Detection server running at http://127.0.0.1:8000")
    app.run(port=8000, threaded=True)

