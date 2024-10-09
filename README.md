
# VirusTotal IP & URL Scanner

This project allows you to scan IP addresses and URLs to check if they are malicious, using the VirusTotal API. The script will log any malicious addresses or URLs into a file called `malicious.txt`.

## Features
- **Supports both IP addresses and URLs**: The script can handle both IPs and URLs, checking their status on VirusTotal.
- **Cycles through multiple API keys**: Avoids API rate limits by cycling through a list of VirusTotal API keys.
- **Logs malicious addresses**: Outputs malicious addresses or URLs to a `malicious.txt` file for easy reference.

## Prerequisites

You need the following to run this project:
- **Python 3.x**
- Required Python libraries: `requests`, `vt-py`

## Setup Instructions

Follow these steps to run the script:

1. **Clone the repository**:
```bash
   git clone https://github.com/rodanmaharjan/IPDomainReputationChecker
   cd IPDomainReputationChecker
```
2. **Install the required dependencies**:
```bash
   pip install -r requirements.txt
```
3. **Prepare the input files**:
```bash
  input.txt: Add a list of IP addresses or URLs (one per line) that you want to scan.
  api_keys.txt: Add your VirusTotal API keys (one per line). 
```

4. **Run the script**:
```bash
  python3 main.py
```
5. ***Check the results***:
```bash
   Open malicious.txt to see any malicious IPs or URLs.
```

## Example Input Files
**input.txt**:
```
   Copy code
   8.8.8.8
   example.com
```
**api_keys.txt**:
```
   your_api_key_1
   your_api_key_2
```
**Output**:
```
   The malicious.txt file will contain a list of IP addresses or URLs flagged as malicious by VirusTotal.
```
**Contributing**
```
   Contributions are welcome! Feel free to open an issue or submit a pull request.
```
## License
This project is licensed under the MIT License - see the LICENSE file for details.
