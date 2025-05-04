import csv
from collections import defaultdict
from datetime import datetime, timedelta

def check_high_creation_rate(logs, window=60, threshold=3, suspicious_extension=".enc"):
    """Checks for a high rate of suspicious file creation."""
    creation_timestamps = [datetime.fromisoformat(log['Timestamp']) for log in logs if log['Action'].lower() == 'created' and log['File'].lower().endswith(suspicious_extension)]
    creation_timestamps.sort()
    alerts = []
    for i in range(len(creation_timestamps)):
        start_time = creation_timestamps[i]
        count = sum(1 for ts in creation_timestamps[i:] if ts - start_time < timedelta(seconds=window))
        if count >= threshold:
            alerts.append({'timestamp': start_time.isoformat(), 'count': count, 'rule': f"High Creation Rate of {suspicious_extension} Files"})
    return remove_duplicate_alerts(alerts)

def check_rapid_deletion_after_creation(logs, window=10, threshold=2, suspicious_extension=".enc"):
    """Checks for rapid deletion of original files after suspicious creation."""
    enc_creations = defaultdict(list)
    deletions = defaultdict(list)
    for log in logs:
        timestamp = datetime.fromisoformat(log['Timestamp'])
        action = log['Action'].lower()
        file_path = log['File']
        if action == 'created' and file_path.lower().endswith(suspicious_extension):
            original_name = file_path[:-len(suspicious_extension)]
            enc_creations[original_name].append(timestamp)
        elif action == 'deleted':
            deletions[file_path].append(timestamp)

    alerts = []
    for original_file, creation_times in enc_creations.items():
        for create_time in creation_times:
            deleted_count = sum(1 for deleted_file, delete_times in deletions.items() if original_file == deleted_file and any(timedelta(seconds=0) < dt - create_time < timedelta(seconds=window) for dt in delete_times))
            if deleted_count >= threshold:
                alerts.append({'timestamp': create_time.isoformat(), 'deleted_count': deleted_count, 'rule': f"Rapid Deletion After {suspicious_extension} Creation"})
    return remove_duplicate_alerts(alerts)

def check_rapid_modification_before_creation(logs, window=5, threshold=3, suspicious_extension=".enc"):
    """Checks for rapid modification of original files before suspicious creation."""
    modifications = defaultdict(list)
    enc_creations_times = defaultdict(list)
    for log in logs:
        timestamp = datetime.fromisoformat(log['Timestamp'])
        action = log['Action'].lower()
        file_path = log['File']
        if action == 'modified':
            modifications[file_path].append(timestamp)
        elif action == 'created' and file_path.lower().endswith(suspicious_extension):
            original_name = file_path[:-len(suspicious_extension)]
            enc_creations_times[original_name].append(timestamp)

    alerts = []
    for original_file, creation_times in enc_creations_times.items():
        for create_time in creation_times:
            modification_count = sum(1 for modify_time in modifications.get(original_file, []) if timedelta(seconds=0) < create_time - modify_time < timedelta(seconds=window))
            if modification_count >= threshold:
                alerts.append({'timestamp': create_time.isoformat(), 'modification_count': modification_count, 'rule': f"Rapid Modification Before {suspicious_extension} Creation"})
    return remove_duplicate_alerts(alerts)

def analyze_logs(log_file="monitor_log.csv", creation_window=60, creation_threshold=3,
                 deletion_window=10, deletion_threshold=2, modification_window=5, modification_threshold=3, suspicious_extension=".enc"):
    """Analyzes monitor logs by applying individual detection rules."""
    detections = []
    logs = []
    with open(log_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        if not all(field in reader.fieldnames for field in ["Timestamp", "Action", "File"]):
            print("Error: Missing required columns in log file.")
            return detections
        for row in reader:
            logs.append(row)

    detections.extend(check_high_creation_rate(logs, creation_window, creation_threshold, suspicious_extension))
    detections.extend(check_rapid_deletion_after_creation(logs, deletion_window, deletion_threshold, suspicious_extension))
    detections.extend(check_rapid_modification_before_creation(logs, modification_window, modification_threshold, suspicious_extension))

    return detections

def remove_duplicate_alerts(alerts):
    unique_alerts = []
    seen_timestamps_rules = set()
    for alert in alerts:
        key = (alert['timestamp'], alert['rule'])
        if key not in seen_timestamps_rules:
            unique_alerts.append(alert)
            seen_timestamps_rules.add(key)
    return unique_alerts

if __name__ == "__main__":
    detections = analyze_logs()
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
    else:
        print("\n" + "✅ No potential ransomware activity detected based on the defined rules.")
        print("=" * 60 + "\n")