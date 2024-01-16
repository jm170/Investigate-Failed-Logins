import re

def extract_ip_addresses(log_file):
    try:
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        with open(log_file, 'r') as file:
            log_content = file.read()
            ip_addresses = re.findall(ip_pattern, log_content)
        return list(set(ip_addresses))  # Remove duplicates
    except Exception as e:
        print(f"Error extracting IP addresses from log file: {e}")
        return []

def write_ips_to_file(output_file, ip_addresses):
    try:
        with open(output_file, 'w') as file:
            for ip in ip_addresses:
                file.write(f"{ip}\n")
        print(f"IP addresses written to {output_file}.")
    except Exception as e:
        print(f"Error writing IP addresses to file: {e}")

if __name__ == "__main__":
    auth_log_file = 'auth.log'  # Update with your actual auth.log file path
    output_file = 'ip_addresses.txt'

    ip_addresses = extract_ip_addresses(auth_log_file)

    if not ip_addresses:
        print("No IP addresses found in the log file.")
    else:
        write_ips_to_file(output_file, ip_addresses)