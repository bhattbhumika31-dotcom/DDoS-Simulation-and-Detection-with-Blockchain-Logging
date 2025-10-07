import threading
import requests
import time

# Target URL (local server only)
target_url = "http://localhost:8000"

# Configuration
normal_threads = 10       # Simulates normal traffic
attack_threads = 40       # Simulates DDoS-like traffic
rps = 2                   # Requests per second per thread
timeout = 3               # Request timeout in seconds
duration = 10             # Duration of each traffic phase in seconds

# Counters
success_count = 0
fail_count = 0
status_codes = []

# Lock for thread-safe updates
lock = threading.Lock()

def send_requests(label):
    global success_count, fail_count
    interval = 1.0 / rps
    end_time = time.perf_counter() + duration
    while time.perf_counter() < end_time:
        start = time.perf_counter()
        try:
            response = requests.get(target_url, timeout=timeout)
            with lock:
                success_count += 1
                status_codes.append(f"{label}:{response.status_code}")
        except:
            with lock:
                fail_count += 1
                status_codes.append(f"{label}:Error")
        elapsed = time.perf_counter() - start
        sleep_for = interval - elapsed
        if sleep_for > 0:
            time.sleep(sleep_for)

# Launch normal traffic
print("🚦 Starting normal traffic...")
normal_threads_list = []
for _ in range(normal_threads):
    thread = threading.Thread(target=send_requests, args=("Normal",))
    thread.start()
    normal_threads_list.append(thread)

# Wait for normal traffic to finish
for thread in normal_threads_list:
    thread.join()

# Short pause before attack
print("⚠ Launching attack traffic...")
attack_threads_list = []
for _ in range(attack_threads):
    thread = threading.Thread(target=send_requests, args=("Attack",))
    thread.start()
    attack_threads_list.append(thread)

# Wait for attack traffic to finish
for thread in attack_threads_list:
    thread.join()

# Print summary
print("\n📊 Simulation Summary")
print(f"✅ Successful requests: {success_count}")
print(f"❌ Failed requests: {fail_count}")
