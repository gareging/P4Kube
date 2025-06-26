import threading
import time
import requests
from collections import Counter, defaultdict


TARGET_URL = "http://10.0.0.2"
NUM_THREADS = 500
DURATION = 3000 # seconds
REPORT_INTERVAL = 270  # seconds

# Shared data
response_counts = Counter()
lock = threading.Lock()
stop_event = threading.Event()

def worker():
    while not stop_event.is_set():
        try:
            response = requests.get(TARGET_URL, timeout=150)
            node_name = response.text.strip()
            with lock:
                response_counts[node_name] += 1
        except Exception:
            pass  
        time.sleep(0.01)  

def print_stats():
    total = sum(response_counts.values())
    if total == 0:
        print("No responses yet.")
        return
    print(f"\n[Stats at {int(time.time() - start_time)}s]")
    with lock:
        for node in sorted(response_counts):
            count = response_counts[node]
            percent = 100.0 * count / total
            print(f"{node}: {percent:.2f}% ({count})")
            # Reset counters
            response_counts[node] = 0
    print()


threads = []
for _ in range(NUM_THREADS):
    t = threading.Thread(target=worker, daemon=True)
    threads.append(t)
    t.start()

start_time = time.time()
next_report = REPORT_INTERVAL

try:
    while time.time() - start_time < DURATION:
        elapsed = time.time() - start_time
        if elapsed >= next_report:
            print_stats()
            next_report += REPORT_INTERVAL
        time.sleep(1)
finally:
    stop_event.set()
    for t in threads:
        t.join(timeout=1)
    print("\n[Final Stats]")
    print_stats()
