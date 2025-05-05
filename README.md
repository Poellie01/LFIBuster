# LFIBuster

LFI Buster is a multi-threaded Python script designed to test for Local File Inclusion (LFI) vulnerabilities across multiple domains and payloads. It features:
- Customizable domains and payload files via command-line arguments.
- Multi-threaded testing for speed.
- Configurable parameter name for LFI injection (e.g., file, page, p).
- Optional verbose mode to print every test attempt.
- Progress bars for real-time monitoring using tqdm.
- Colored terminal output using colorama.
- Anomaly detection by comparing response lengths and content hashes.
- Summary report printed at the end with total domains, payloads, and anomalies found.

### Requirements
- Python 3.6+
- ```requests```
- ```tqdm```
- ```colorama```

### Installation

Install dependencies via pip:
pip install requests tqdm colorama

### Usage
```
python lfi_buster.py --param <PARAM_NAME> --domains <DOMAINS_FILE> --payloads <PAYLOADS_FILE> [options]
```
### Required Arguments
--param: Name of the LFI parameter (e.g., file, page, p).
--domains: Path to the domains file (one domain/URL per line).
--payloads: Path to the payloads file (one payload per line, relative paths like ../../../../etc/passwd).

### Optional Arguments
-v, --verbose: Enable verbose output (prints every test attempt).
--output: Path to the output file for anomalies (default: anomalies.txt).

### Example
```
python lfi_buster.py --param file --domains domains.txt --payloads payloads.txt -v --output results.txt
```
### New features in the make:
- Parameter buster
- Help menu 

License

This project is released under the MIT License.

