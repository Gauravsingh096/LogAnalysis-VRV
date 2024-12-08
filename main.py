import re
from collections import Counter
import csv

FAILED_LOGIN_THRESHOLD = 10

log_data = """
192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512
203.0.113.5 - - [03/Dec/2024:10:12:35 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:36 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:37 +0000] "GET /contact HTTP/1.1" 200 312
198.51.100.23 - - [03/Dec/2024:10:12:38 +0000] "POST /register HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:12:39 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:40 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:41 +0000] "GET /dashboard HTTP/1.1" 200 1024
198.51.100.23 - - [03/Dec/2024:10:12:42 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:12:43 +0000] "GET /dashboard HTTP/1.1" 200 1024
203.0.113.5 - - [03/Dec/2024:10:12:44 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
203.0.113.5 - - [03/Dec/2024:10:12:45 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:46 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:47 +0000] "GET /profile HTTP/1.1" 200 768
192.168.1.1 - - [03/Dec/2024:10:12:48 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:49 +0000] "POST /feedback HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:12:50 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.1 - - [03/Dec/2024:10:12:51 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:52 +0000] "GET /about HTTP/1.1" 200 256
203.0.113.5 - - [03/Dec/2024:10:12:53 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:12:54 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:55 +0000] "GET /contact HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:12:56 +0000] "GET /home HTTP/1.1" 200 512
192.168.1.100 - - [03/Dec/2024:10:12:57 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
203.0.113.5 - - [03/Dec/2024:10:12:58 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:12:59 +0000] "GET /dashboard HTTP/1.1" 200 1024
192.168.1.1 - - [03/Dec/2024:10:13:00 +0000] "GET /about HTTP/1.1" 200 256
198.51.100.23 - - [03/Dec/2024:10:13:01 +0000] "POST /register HTTP/1.1" 200 128
203.0.113.5 - - [03/Dec/2024:10:13:02 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
192.168.1.100 - - [03/Dec/2024:10:13:03 +0000] "POST /login HTTP/1.1" 401 128 "Invalid credentials"
10.0.0.2 - - [03/Dec/2024:10:13:04 +0000] "GET /profile HTTP/1.1" 200 768
198.51.100.23 - - [03/Dec/2024:10:13:05 +0000] "GET /about HTTP/1.1" 200 256
192.168.1.1 - - [03/Dec/2024:10:13:06 +0000] "GET /home HTTP/1.1" 200 512
198.51.100.23 - - [03/Dec/2024:10:13:07 +0000] "POST /feedback HTTP/1.1" 200 128...
"""
def parse_log(log):
    ip_pattern = r"(\d{1,3}(?:\.\d{1,3}){3})"
    endpoint_pattern = r"\"[A-Z]+\s(\/\S*)"
    failed_login_pattern = r"(401).*Invalid credentials"

    ip_addresses = re.findall(ip_pattern, log)
    endpoints = re.findall(endpoint_pattern, log)
    failed_logins = re.findall(f"{ip_pattern}.*{failed_login_pattern}", log)

    return ip_addresses, endpoints, failed_logins

def analyze_log(log):
    ip_addresses, endpoints, failed_logins = parse_log(log)

    ip_request_count = Counter(ip_addresses)

    endpoint_count = Counter(endpoints)
    most_accessed_endpoint = endpoint_count.most_common(1)

    failed_login_count = Counter(ip for ip, _ in failed_logins)
    suspicious_ips = {ip: count for ip, count in failed_login_count.items() if count > FAILED_LOGIN_THRESHOLD}

    return ip_request_count, most_accessed_endpoint, suspicious_ips

def save_to_csv(ip_request_count, most_accessed_endpoint, suspicious_ips, filename="log_analysis_results.csv"):
    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_request_count.items():
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        if most_accessed_endpoint:
            writer.writerow([most_accessed_endpoint[0][0], most_accessed_endpoint[0][1]])

        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def display_results(ip_request_count, most_accessed_endpoint, suspicious_ips):
    print("Requests per IP Address:")
    print(f"{'IP Address':<20}{'Request Count'}")
    for ip, count in ip_request_count.items():
        print(f"{ip:<20}{count}")

    if most_accessed_endpoint:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint[0][0]} (Accessed {most_accessed_endpoint[0][1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts'}")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20}{count}")

if __name__ == "__main__":
    ip_request_count, most_accessed_endpoint, suspicious_ips = analyze_log(log_data)

    display_results(ip_request_count, most_accessed_endpoint, suspicious_ips)

    save_to_csv(ip_request_count, most_accessed_endpoint, suspicious_ips)
    print("\nResults saved to 'log_analysis_results.csv'")