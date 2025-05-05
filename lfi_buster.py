import requests
from urllib.parse import urlencode
import hashlib
import threading
import queue
import argparse
import os
from colorama import Fore, Style, init
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

# Configuration
TIMEOUT = 5  # seconds
NUM_THREADS = 10
output_lock = threading.Lock()

# Global list to store anomalies
anomalies = []

# Banner for the tool
BANNER = r"""
.____   ___________._____________                __                
|    |  \_   _____/|   \______   \__ __  _______/  |_  ___________ 
|    |   |    __)  |   ||    |  _/  |  \/  ___/\   __\/ __ \_  __ \
|    |___|     \   |   ||    |   \  |  /\___ \  |  | \  ___/|  | \/
|_______ \___  /   |___||______  /____//____  > |__|  \___  >__|   
        \/   \/                \/           \/            \/       
                     Local File Inclusion Buster - Made by Poellie
"""

# Function to read lines from a file
def read_lines(filepath):
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]

# Function to generate a fingerprint for the response (length and hash)
def get_response_fingerprint(response):
    content_length = len(response.text)
    content_hash = hashlib.md5(response.text.encode()).hexdigest()
    return content_length, content_hash

# Function to compare the current response with the baseline to detect anomalies
def is_anomalous(baseline, current):
    base_length, base_hash = baseline
    curr_length, curr_hash = current
    return curr_hash != base_hash and abs(curr_length - base_length) > 100

# Function to save anomalies to an output file
def save_anomaly_info(info, output_file):
    with output_lock:
        with open(output_file, 'a') as f:
            f.write(info + '\n')

# Worker function for each thread
def worker(task_queue, param_name, output_file, verbose, progress_bar):
    while not task_queue.empty():
        try:
            domain, payload, baseline_fp = task_queue.get_nowait()
            base_url = domain.split('?')[0]
            query_string = urlencode({param_name: payload})
            full_url = f"{base_url}?{query_string}"

            if verbose:
                print(Fore.GREEN + f"[>] Testing: {full_url} | Param: {param_name}")

            try:
                resp = requests.get(full_url, timeout=TIMEOUT)
                resp_fp = get_response_fingerprint(resp)
                if is_anomalous(baseline_fp, resp_fp):
                    message = (
                        f"[!] Anomalous response detected\n"
                        f"    URL: {full_url}\n"
                        f"    Payload: {payload}\n"
                        f"    Param: {param_name}\n"
                        f"    Response length: {resp_fp[0]}"
                    )
                    print(Fore.RED + message)
                    save_anomaly_info(message, output_file)
                    with output_lock:
                        anomalies.append({
                            "url": full_url,
                            "payload": payload,
                            "param": param_name,
                            "length": resp_fp[0]
                        })
            except Exception as e:
                print(Fore.YELLOW + f"[-] Request failed for {full_url}: {e}")
        finally:
            task_queue.task_done()
            progress_bar.update(1)

# Main function to execute the program
def main():
    parser = argparse.ArgumentParser(description="Threaded LFI Payload Tester")
    parser.add_argument('--param', required=True, help="LFI parameter name (e.g., file, page, p)")
    parser.add_argument('--domains', required=True, help="Path to the domain.txt file")
    parser.add_argument('--payloads', required=True, help="Path to the payloads.txt file")
    parser.add_argument('--output', default='anomalies.txt', help="Output file for anomalies")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    args = parser.parse_args()

    print(Fore.CYAN + BANNER)

    if os.path.exists(args.output):
        os.remove(args.output)

    # Read domain and payload files from user-specified paths
    domains = read_lines(args.domains)
    payloads = read_lines(args.payloads)

    for domain in domains:
        print(Fore.CYAN + f"\n[+] Testing domain: {domain}")
        try:
            baseline_resp = requests.get(domain, timeout=TIMEOUT)
            baseline_fp = get_response_fingerprint(baseline_resp)
        except Exception as e:
            print(Fore.YELLOW + f"[-] Could not get baseline for {domain}: {e}")
            continue

        # Create the task queue and add tasks
        task_queue = queue.Queue()
        for payload in payloads:
            task_queue.put((domain, payload, baseline_fp))

        # Initialize progress bar
        progress_bar = tqdm(total=task_queue.qsize(), desc=f"Testing {domain}", ncols=80)

        # Start threads
        threads = []
        for _ in range(NUM_THREADS):
            t = threading.Thread(target=worker, args=(task_queue, args.param, args.output, args.verbose, progress_bar))
            t.start()
            threads.append(t)

        # Wait for all tasks to complete
        task_queue.join()
        progress_bar.close()

    # Print summary report
    print(Fore.CYAN + "\n" + "=" * 50)
    print(Fore.CYAN + "                SUMMARY REPORT")
    print(Fore.CYAN + "=" * 50)

    print(f"Total domains tested: {len(domains)}")
    total_payloads = len(payloads) * len(domains)
    print(f"Total payloads tested: {total_payloads}")
    print(f"Total anomalies found: {len(anomalies)}\n")

    if anomalies:
        print(Fore.RED + "Anomalies detected:")
        for i, item in enumerate(anomalies, 1):
            print(
                Fore.YELLOW + f"{i}. URL: {item['url']}\n"
                f"   Param: {item['param']}\n"
                f"   Payload: {item['payload']}\n"
                f"   Response length: {item['length']}\n"
            )
    else:
        print(Fore.GREEN + "No anomalies detected.")

if __name__ == '__main__':
    main()