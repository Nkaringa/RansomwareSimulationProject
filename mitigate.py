# mitigation.py
# This script analyzes the monitor_log.csv file for detected ransomware activity
# and simulates mitigation actions based on the triggered detection rules.
# It logs the triggered rules and simulated mitigation steps to mitigation_log.txt.

import csv
from collections import defaultdict
from datetime import datetime, timedelta
import os  # For basic file operations (optional for simulation)

# File to log the simulated mitigation actions
MITIGATION_LOG_FILE = "mitigation_log.txt"

def log_mitigation(timestamp, rule, action, details=""):
    """
    Logs a simulated mitigation action to the mitigation log file and prints it to the console.

    Args:
        timestamp (str): The timestamp of the detected activity.
        rule (str): The name of the triggered detection rule.
        action (str): A description of the simulated mitigation action.
        details (str, optional): Additional details about the mitigation. Defaults to "".
    """
    with open(MITIGATION_LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] Rule: {rule} - Mitigation: {action} - Details: {details}\n")
    print(f"🚨 MITIGATION TRIGGERED: [{timestamp}] Rule: {rule} - Action: {action} - Details: {details}")

def check_high_creation_rate(logs, window=60, threshold=3, suspicious_extension=".enc"):
    """
    Checks for a high rate of suspicious file creation within a given time window and simulates mitigation.

    Args:
        logs (list): A list of log entries (dictionaries) from the monitor log.
        window (int): The time window in seconds to consider for the rate.
        threshold (int): The minimum number of creations within the window to trigger an alert.
        suspicious_extension (str): The file extension considered suspicious (e.g., ".enc").

    Returns:
        list: A list of alerts (dictionaries) for high creation rate.
    """
    alerts = []
    # Extract timestamps of all 'created' events with the suspicious extension
    creation_timestamps = [datetime.fromisoformat(log['Timestamp']) for log in logs if log['Action'].lower() == 'created' and log['File'].lower().endswith(suspicious_extension)]
    creation_timestamps.sort()
    # Iterate through the creation timestamps to check for high density within the window
    for i in range(len(creation_timestamps)):
        start_time = creation_timestamps[i]
        # Count the number of creations within the defined time window from the current timestamp
        count = sum(1 for ts in creation_timestamps[i:] if ts - start_time < timedelta(seconds=window))
        # If the count exceeds the threshold, a potential high creation rate is detected
        if count >= threshold:
            alert = {'timestamp': start_time.isoformat(), 'count': count, 'rule': f"High Creation Rate of {suspicious_extension} Files"}
            alerts.append(alert)
            # Enhanced Mitigation Simulation for Rule 1:
            # Identify the suspicious files created within the detection window
            suspicious_files = [log['File'] for log in logs if datetime.fromisoformat(log['Timestamp']) >= start_time and log['Action'].lower() == 'created' and log['File'].lower().endswith(suspicious_extension)][:count]
            # Log the simulated mitigation action: isolate the files and alert the user
            log_mitigation(start_time.isoformat(), alert['rule'], "Simulated Action: Isolate Affected Files & Alert",
                           f"Detected rapid creation of {count} files with '{suspicious_extension}'. Consider isolating: {', '.join(suspicious_files)}")
    return remove_duplicate_alerts(alerts)

def check_rapid_deletion_after_creation(logs, window=10, threshold=2, suspicious_extension=".enc"):
    """
    Checks for rapid deletion of original files after suspicious creation and simulates mitigation.

    Args:
        logs (list): A list of log entries (dictionaries) from the monitor log.
        window (int): The time window in seconds to consider between creation and deletion.
        threshold (int): The minimum number of deletions of the original file after a suspicious creation.
        suspicious_extension (str): The file extension considered suspicious.

    Returns:
        list: A list of alerts (dictionaries) for rapid deletion after creation.
    """
    alerts = []
    enc_creations = defaultdict(list)  # Stores creation times of .enc files, keyed by the original filename
    deletions = defaultdict(list)       # Stores deletion times, keyed by the file path
    # Populate the dictionaries with creation and deletion events
    for log in logs:
        timestamp = datetime.fromisoformat(log['Timestamp'])
        action = log['Action'].lower()
        file_path = log['File']
        if action == 'created' and file_path.lower().endswith(suspicious_extension):
            original_name = file_path[:-len(suspicious_extension)]
            enc_creations[original_name].append(timestamp)
        elif action == 'deleted':
            deletions[file_path].append(timestamp)

    # Check for deletions of original files within the time window after an encrypted file was created
    for original_file, creation_times in enc_creations.items():
        for create_time in creation_times:
            # Count the number of times the original file was deleted within the time window after its encrypted counterpart was created
            deleted_count = sum(1 for deleted_file, delete_times in deletions.items() if original_file == deleted_file and any(timedelta(seconds=0) < dt - create_time < timedelta(seconds=window) for dt in delete_times))
            # If the deletion count meets the threshold, trigger an alert and simulate mitigation
            if deleted_count >= threshold:
                alert = {'timestamp': create_time.isoformat(), 'deleted_count': deleted_count, 'rule': f"Rapid Deletion After {suspicious_extension} Creation"}
                alerts.append(alert)
                # Enhanced Mitigation Simulation for Rule 2:
                log_mitigation(create_time.isoformat(), alert['rule'], "Simulated Action: Isolate & Investigate",
                               f"Detected rapid deletion of '{original_file}' after '{'.enc'}' creation. Investigate processes accessing '{original_file}'.")
    return remove_duplicate_alerts(alerts)

def check_rapid_modification_before_creation(logs, window=5, threshold=3, suspicious_extension=".enc"):
    """
    Checks for rapid modification of original files before suspicious creation and simulates mitigation.

    Args:
        logs (list): A list of log entries (dictionaries) from the monitor log.
        window (int): The time window in seconds to consider before creation.
        threshold (int): The minimum number of modifications of the original file before a suspicious creation.
        suspicious_extension (str): The file extension considered suspicious.

    Returns:
        list: A list of alerts (dictionaries) for rapid modification before creation.
    """
    alerts = []
    modifications = defaultdict(list)      # Stores modification times, keyed by the file path
    enc_creations_times = defaultdict(list) # Stores creation times of .enc files, keyed by the original filename
    # Populate the dictionaries with modification and creation events
    for log in logs:
        timestamp = datetime.fromisoformat(log['Timestamp'])
        action = log['Action'].lower()
        file_path = log['File']
        if action == 'modified':
            modifications[file_path].append(timestamp)
        elif action == 'created' and file_path.lower().endswith(suspicious_extension):
            original_name = file_path[:-len(suspicious_extension)]
            enc_creations_times[original_name].append(timestamp)

    # Check for modifications of original files within the time window before an encrypted file was created
    for original_file, creation_times in enc_creations_times.items():
        for create_time in creation_times:
            # Count the number of times the original file was modified within the time window before its encrypted counterpart was created
            modification_count = sum(1 for modify_time in modifications.get(original_file, []) if timedelta(seconds=0) < create_time - modify_time < timedelta(seconds=window))
            # If the modification count meets the threshold, trigger an alert and simulate mitigation
            if modification_count >= threshold:
                alert = {'timestamp': create_time.isoformat(), 'modification_count': modification_count, 'rule': f"Rapid Modification Before {suspicious_extension} Creation"}
                alerts.append(alert)
                # Enhanced Mitigation Simulation for Rule 3:
                log_mitigation(create_time.isoformat(), alert['rule'], "Simulated Action: Snapshot & Alert",
                               f"Detected rapid modification of '{original_file}' before '{'.enc'}' creation. Consider taking a snapshot and alerting administrators.")
    return remove_duplicate_alerts(alerts)

def analyze_logs(log_file="monitor_log.csv", creation_window=60, creation_threshold=3,
                 deletion_window=10, deletion_threshold=2, modification_window=5, modification_threshold=3, suspicious_extension=".enc"):
    """
    Analyzes monitor logs by applying individual detection rules and returns any detected suspicious activity.

    Args:
        log_file (str, optional): The path to the monitor log CSV file. Defaults to "monitor_log.csv".
        creation_window (int, optional): The time window for checking high creation rate (in seconds). Defaults to 60.
        creation_threshold (int, optional): The threshold for high creation rate. Defaults to 3.
        deletion_window (int, optional): The time window for checking rapid deletion after creation (in seconds). Defaults to 10.
        deletion_threshold (int, optional): The threshold for rapid deletion after creation. Defaults to 2.
        modification_window (int, optional): The time window for checking rapid modification before creation (in seconds). Defaults to 5.
        modification_threshold (int, optional): The threshold for rapid modification before creation. Defaults to 3.
        suspicious_extension (str, optional): The file extension considered suspicious. Defaults to ".enc".

    Returns:
        list: A list of detected suspicious activities (alerts).
    """
    detections = []
    logs = []
    try:
        with open(log_file, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            # Ensure the log file has the required columns
            if not all(field in reader.fieldnames for field in ["Timestamp", "Action", "File"]):
                print("Error: Missing required columns in log file.")
                return detections
            for row in reader:
                logs.append(row)
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
        return detections

    # Apply each detection rule to the logs
    detections.extend(check_high_creation_rate(logs, creation_window, creation_threshold, suspicious_extension))
    detections.extend(check_rapid_deletion_after_creation(logs, deletion_window, deletion_threshold, suspicious_extension))
    detections.extend(check_rapid_modification_before_creation(logs, modification_window, modification_threshold, suspicious_extension))

    return detections

def remove_duplicate_alerts(alerts):
    """
    Removes duplicate alerts based on the timestamp and the triggered rule.

    Args:
        alerts (list): A list of alert dictionaries.

    Returns:
        list: A list of unique alert dictionaries.
    """
    unique_alerts = []
    seen_timestamps_rules = set()
    for alert in alerts:
        # Create a unique key for each alert based on timestamp and rule
        key = (alert['timestamp'], alert['rule'])
        # If the key has not been seen before, add the alert to the unique list and mark the key as seen
        if key not in seen_timestamps_rules:
            unique_alerts.append(alert)
            seen_timestamps_rules.add(key)
    return unique_alerts

if __name__ == "__main__":
    # Analyze the logs to detect potential ransomware activity
    detections = analyze_logs()
    # If any suspicious activity is detected, print the alerts
    if detections:
        print("\n" + "=" * 40)
        print("  🚨 POTENTIAL RANSOMWARE ACTIVITY DETECTED! 🚨")
        print("=" * 40 + "\n")
        for detection in detections:
            print("-" * 30)
            print(f"⏰ Timestamp: {detection['timestamp']}")
            print(f"🛡️ Rule Triggered: {detection['rule']}")
            if 'count' in detection:
                print(f"   ➡️ Creation Count: {detection['count']}")
            if 'deleted_count' in detection:
                print(f"   🗑️ Deleted Count: {detection['deleted_count']}")
            if 'modification_count' in detection:
                print(f"   ✍️ Modification Count: {detection['modification_count']}")
            print("-" * 30 + "\n")
    # If no suspicious activity is detected, print a corresponding message
    else:
        print("\n" + "✅ No potential ransomware activity detected based on the defined rules.")
        print("=" * 60 + "\n")