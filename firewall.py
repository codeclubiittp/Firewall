import pyufw
import re
from collections import defaultdict

# Paths to various log files for different services
log_files = {
    "SSH": "/var/log/auth.log",            # SSH login attempts
    "FTP": "/var/log/vsftpd.log",          # FTP login attempts
    "RDP": "/var/log/xrdp.log",            # RDP login attempts
    "SMTP": "/var/log/mail.log",           # Mail server login attempts (Postfix, etc.)
    "HTTP": "/var/log/apache2/access.log", # HTTP server log (Apache)
    "POP3/IMAP": "/var/log/dovecot.log"    # Email access logs (Dovecot)
}

# Threshold for blocking an IP (more than 5 failed attempts)
failed_attempts_threshold = 5

# Dictionary to track failed login attempts by IP
failed_attempts = defaultdict(int)

# Regular expression to capture IP addresses
ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')

# List of known failed login patterns for different protocols
protocol_patterns = {
    "SSH": r"Failed password|authentication failure",
    "FTP": r"530 Login incorrect",
    "RDP": r"authentication failure",
    "SMTP": r"authentication failed|535 5.7.8",
    "HTTP": r"401 Unauthorized|403 Forbidden",  # Detecting failed login attempts or restricted access
    "POP3/IMAP": r"Authentication failed|auth-worker"
}

def check_log_file(file_path, service_name, pattern):
    """Parses a log file and counts failed attempts for each IP address."""
    try:
        with open(file_path, "r") as file:
            for line in file:
                if re.search(pattern, line):
                    ip_match = ip_pattern.search(line)
                    if ip_match:
                        ip_address = ip_match.group(0)
                        failed_attempts[ip_address] += 1
                        print(f"{service_name}: Detected failed login attempt from {ip_address}")
    except FileNotFoundError:
        print(f"Log file not found: {file_path}")

# Scan each log file for failed login attempts across protocols
for service_name, log_file in log_files.items():
    if service_name in protocol_patterns:
        pattern = protocol_patterns[service_name]
        check_log_file(log_file, service_name, pattern)

# Block IPs with failed attempts over the threshold
for ip, attempts in failed_attempts.items():
    if attempts > failed_attempts_threshold:
        print(f"Blocking IP {ip} with {attempts} failed attempts.")
        pyufw.add(f'deny from {ip}')

# Ensure UFW is enabled
if not pyufw.status():
    pyufw.enable()

# Block incoming traffic on common ports used for scanning
common_scan_ports = [
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    80,   # HTTP
    443,  # HTTPS
    3306, # MySQL
    5432, # PostgreSQL
    6379  # Redis
]

for port in common_scan_ports:
    pyufw.add(f'deny from any to any port {port}')


# Prevent spoofed packets by blocking invalid source addresses
# Assuming 192.168.1.0/24 is your internal network
pyufw.add('deny from any to 192.168.1.0/24')
pyufw.add('allow from 192.168.1.0/24 to any')

# Example: Allow traffic from your trusted IP address
trusted_ip = '192.168.1.100'  # Change this to your trusted IP
pyufw.add(f'allow from {trusted_ip} to any')
pyufw.add('limit from any to any port 22')

# Logging rules to monitor dropped packets
pyufw.set_logging('on')

# Status of UFW rules
print(pyufw.status())
