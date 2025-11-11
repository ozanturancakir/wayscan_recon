![Wayscan Banner](images/wayscan_banner.png) 
Wayscan is a Python tool that passively collects the historical URLs of a target domain from the Wayback Machine (Internet Archive CDX API) and analyzes these URLs for potential security vulnerabilities.

**Author:** Ozan Turan Çakır

⚠️ Use this tool only for authorized testing.

## Usage
wayscan_recon.py [-h] [--include-subdomains] [--alive200] [--threads THREADS] [--outdir OUTDIR] [--limit LIMIT] target



## Requirements
- Python 3.8+
- requests, termcolor, pyfiglet




## ⚙️ Installation

Wayscan requires Python 3.x. To install the necessary libraries:

```bash
git clone [https://github.com/ozanturancakir/Wayscan.git](https://github.com/ozanturancakir/Wayscan.git)
cd Wayscan
pip3 install -r requirements.txt

