import re
import json
import csv
from collections import Counter

# Input and output file names
log_file = 'server_logs.txt'
failed_logins_json = 'failed_logins.json'
threat_ips_json = 'threat_ips.json'
combined_security_json = 'combined_security_data.json'
log_analysis_txt = 'log_analysis.txt'
log_analysis_csv = 'log_analysis.csv'

# Threat intelligence feed
threat_feed = ["malicious-site.com", "phishing-example.net", "blacklisteddomain.com"]

def extract_log_data(file_path):
    """Extract IP addresses, dates, methods, and status codes from log data."""
    with open(file_path, 'r') as file:
        logs = file.readlines()

    extracted_data = []
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>[^\]]+)\] "(?P<method>[A-Z]+) [^ ]+ HTTP/[^ ]+" (?P<status>\d{3})'
    )

    for log in logs:
        match = log_pattern.search(log)
        if match:
            extracted_data.append(match.groupdict())

    return extracted_data

def analyze_failed_logins(logs):
    """Analyze logs for failed login attempts with 400-series status codes."""
    failed_attempts = Counter()

    for log in logs:
        status_code = log.get('status', '')
        if status_code.startswith('4'):
            failed_attempts[log['ip']] += 1

    failed_ips = {ip: count for ip, count in failed_attempts.items() if count > 5}

    with open(failed_logins_json, 'w') as json_file:
        json.dump(failed_ips, json_file, indent=4)

    return failed_ips

def write_txt(failed_ips):
    """Write failed IPs and attempt counts to a text file."""
    with open(log_analysis_txt, 'w') as txt_file:
        for ip, count in failed_ips.items():
            txt_file.write(f"{ip}: {count} failed attempts\n")

def write_csv(logs):
    """Write extracted log data to a CSV file."""
    with open(log_analysis_csv, 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=['IP Address', 'Date', 'HTTP Method', 'Status Code'])
        writer.writeheader()
        for log in logs:
            writer.writerow({
                'IP Address': log['ip'],
                'Date': log['date'],
                'HTTP Method': log['method'],
                'Status Code': log['status']
            })

def threat_analysis(logs, threat_feed):
    """Identify IPs related to threat intelligence feed."""
    threat_ips = {
        log['ip'] for log in logs
        if any(threat in log.get('method', '') for threat in threat_feed)
    }

    with open(threat_ips_json, 'w') as json_file:
        json.dump(list(threat_ips), json_file, indent=4)

    return threat_ips

def combine_security_data(failed_ips, threat_ips):
    """Combine failed login and threat intelligence data."""
    combined_data = {
        'failed_ips': failed_ips,
        'threat_ips': list(threat_ips),
    }

    with open(combined_security_json, 'w') as json_file:
        json.dump(combined_data, json_file, indent=4)

def main():
    logs = extract_log_data(log_file)
    failed_ips = analyze_failed_logins(logs)
    write_txt(failed_ips)
    write_csv(logs)
    threat_ips = threat_analysis(logs, threat_feed)
    combine_security_data(failed_ips, threat_ips)

if __name__ == "__main__":
    main()
