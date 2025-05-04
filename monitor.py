# monitor.py
# This script monitors file system events in a specified directory ("critical")
# and logs the timestamp, action (CREATED, MODIFIED, DELETED), and file path
# to a CSV file (monitor_log.csv). It uses the watchdog library.

import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import csv
from datetime import datetime
import os

# Path to the directory to monitor
monitor_path = "C:/Users/Nagesh Goud Karinga/critical"

# Log file name
log_file = "monitor_log.csv"

class MonitorHandler(FileSystemEventHandler):
    """Custom event handler for file system events."""
    def on_modified(self, event):
        if not event.is_directory:  # Ignore directory modifications
            self.log_event("MODIFIED", event.src_path)

    def on_created(self, event):
        self.log_event("CREATED", event.src_path)

    def on_deleted(self, event):
        self.log_event("DELETED", event.src_path)

    def log_event(self, action, file_path):
        """Logs the file system event to the CSV file and prints to console."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([timestamp, action, file_path])
        print(f"{timestamp} | {action} | {file_path}")

if __name__ == "__main__":
    # Initialize log file with headers if it doesn't exist
    if not os.path.exists(log_file):
        with open(log_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Timestamp", "Action", "File"])
        print(f"Created log file: {log_file}")
    else:
        print(f"Appending to log file: {log_file}")

    print(f"Monitoring started on: {monitor_path}")
    event_handler = MonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, path=monitor_path, recursive=True)  # Monitor recursively
    observer.start()
    try:
        while True:
            time.sleep(1)  # Keep the script running
    except KeyboardInterrupt:
        observer.stop()   # Stop the observer on keyboard interrupt
    observer.join()      # Wait for the observer thread to finish
    print("Monitoring stopped.")