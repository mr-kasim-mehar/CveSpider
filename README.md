# CVE Spidering Tool

This tool is designed to help security researchers and bug bounty hunters easily find and investigate CVEs associated with a given domain or IP address. It fetches detailed information from various sources such as Shodan and NVD (National Vulnerability Database), and displays the relevant CVE details, hostnames, ports, and base scores.

## Features

- **Resolve Domain to IP**: Resolve a domain name to an IP address for further scanning.
- **Fetch Data from Shodan**: Get detailed information about the IP from Shodan's InternetDB.
- **Fetch CVE Base Scores**: Retrieve and display CVE base scores from NVD.
- **Concurrent Requests**: Optimized with threading to handle multiple CVE queries concurrently.
- **Custom Output**: Results can be saved to a text file or printed directly to the console.

## Installation

1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/yourusername/cve-spidering-tool.git
   cd CveSpider
   pip install -r requirements.txt
   Python3 CveSpider.py -d example.com
   ```
## Example Usage
### Scan by Domain
```
python cve_spider.py -d example.com -o result.txt
```
### Scan by IP
```
python cve_spider.py -d 192.168.1.1 -o result.txt
```
### Pipe Input to Scan
```
echo "example.com" | python cve_spider.py -o result.txt
```


![Alt Text](https://raw.githubusercontent.com/mr-kasim-mehar/myimgs/refs/heads/main/my.gif)
