import subprocess
import time

def read_ip_addresses(file_path):
    try:
        with open(file_path, 'r') as file:
            ip_addresses = [line.strip() for line in file.readlines()]
        return ip_addresses
    except Exception as e:
        print(f"Error reading IP addresses from file '{file_path}': {e}")
        return []

def make_curl_request(api_key, ip_address):
    try:
        command = [
            'curl',
            '-X', 'GET',
            f'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={api_key}&ip={ip_address}'
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error making cURL request for IP '{ip_address}': {e}")
        return f"Error making cURL request for IP '{ip_address}': {e}"

def write_results_to_file(output_file, results):
    try:
        with open(output_file, 'a') as file:
            file.write(results + '\n\n')
        print(f"Results written to '{output_file}'.")
    except Exception as e:
        print(f"Error writing results to file '{output_file}': {e}")

if __name__ == "__main__":
    input_file_path = 'ip_addresses.txt'
    results_file_path = 'results-test.txt'
    virustotal_api_key = 'YOUR_VIRUSTOTAL_API_KEY'  # Replace YOUR_VIRUSTOTAL_API_KEY with your actual API key

    try:
        if virustotal_api_key == 'YOUR_VIRUSTOTAL_API_KEY':
            raise ValueError("Please replace 'YOUR_VIRUSTOTAL_API_KEY' with your actual VirusTotal API key.")

        ip_addresses = read_ip_addresses(input_file_path)

        if not ip_addresses:
            raise ValueError(f"No IP addresses found in the input file '{input_file_path}'.")

        for ip in ip_addresses:
            try:
                response = make_curl_request(virustotal_api_key, ip)
                write_results_to_file(results_file_path, response)
            except Exception as e:
                print(f"Error processing IP '{ip}': {e}")

            finally:
                if ip != ip_addresses[-1]:  # Check if it's not the last IP address
                    time.sleep(20)  # Wait 20 seconds before the next API request

    except Exception as e:
        print(f"Unexpected error: {e}")
