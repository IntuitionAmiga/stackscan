      ██████ ▄▄▄█████▓ ▄▄▄       ▄████▄   ██ ▄█▀   ██████  ▄████▄   ▄▄▄        ███▄    █
    ▒██    ▒ ▓  ██▒ ▓▒▒████▄    ▒██▀ ▀█   ██▄█▒  ▒██    ▒ ▒██▀ ▀█  ▒████▄      ██ ▀█   █
    ░ ▓██▄   ▒ ▓██░ ▒░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░  ░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
      ▒   ██▒░ ▓██▓ ░ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄    ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
    ▒██████▒▒  ▒██▒ ░  ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄ ▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
    ▒ ▒▓▒ ▒ ░  ▒ ░░    ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒
    ░ ░▒  ░ ░    ░      ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░░ ░▒  ░ ░   ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
    ░  ░  ░    ░        ░   ▒          ░ ░░ ░ ░ ░  ░  ░          ░     ░   ▒      ░   ░ ░
          ░                ░  ░░ ░      ░  ░          ░   ░ ░          ░  ░        ░
                                ░                        ░

                           StackScan (c) 2024 Zayn Otley
                     https://github.com/intuitionamiga/stackscan
                        MIT License - Use at your own risk!


## StackScan

- StackScan is a comprehensive server security scanning tool that automates vulnerability assessments across multiple service groups.
- Building upon the awesome work of industry-standard scanners (such as Nmap, Wapiti, Nikto, WPScan, and SQLMap)
- Performs dynamic CVE lookups against the National Vulnerability Database (NVD)
- StackScan thoroughly evaluates your target’s security posture.
- It supports both IPv4 and IPv6 targets and generates comprehensive HTML reports summarizing its findings.


#### **Important:** StackScan must be run with root privileges.

## Features

- **Multi-Group Scanning with Nmap:**  
  - Organizes scans into predefined groups (web, auth, database, common, vuln) based on configurable port ranges and script sets.  
  - Supports an optional custom scan group via the configuration file.

- **Third-Party Scanner Integration:**  
  - Runs **Wapiti** and **Nikto** concurrently on detected web server ports.  
  - Launches **WPScan** and **SQLMap** scans when specific services (like WordPress or SQL databases) are detected.

- **Dynamic CVE Lookups:**  
  - Performs real‑time queries to the NVD for CVE details (descriptions and CVSS scores) corresponding to detected vulnerabilities.  
  - Enforces rate limiting on API calls to comply with NVD usage policies.

- **Parallel & Efficient Scanning:**  
  - Executes scan groups concurrently to minimize total scanning time.  
  - Implements timeouts and resource limits (e.g., process count, file size) to maintain system stability.

- **IPv4 and IPv6 Support:**  
  - Automatically detects whether the target is IPv4, IPv6, or a domain name and adjusts scan parameters accordingly.

- **Detailed Logging and Error Handling:**  
  - Provides detailed logging to a file (with secure permissions) and displays real-time status messages on the console.  
  - Offers a verbose logging mode (enabled via the configuration file) for in-depth debugging.  
  - Implements cleanup routines to remove temporary files after scanning.

- **Professional HTML Reporting:**  
  - Generates a comprehensive HTML report summarizing scan results, including detailed outputs and CVE information.  
  - Optionally opens the HTML report in the default browser once the scan completes.

- **Secure & Configurable:**  
  - Uses a configuration file (`~/.stackscan.conf`) to customize scanner options (e.g., Nmap options, third‑party scanner settings, report generation).  
  - Ensures secure file ownership and permissions for logs, reports, and temporary data.

---

## Prerequisites

Before using StackScan, ensure that the following tools are installed on your system:

- `nmap`
- `wapiti`
- `nikto`
- `wpscan`
- `sqlmap`
- `jq`
- `curl`
- `ping6`
- `dig`

Install these via your package manager (e.g., `apt`, `dnf`, `pacman` (`gem` for installing WPScan)).

---

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/intuitionamiga/stackscan
   cd stackscan
   ```

2. **Make the Script Executable:**

   ```bash
   chmod +x stackscan.sh
   ```

---

## Usage

Run StackScan with root privileges and specify a target IP address or domain.

```bash
sudo ./stackscan.sh 127.0.0.1
```

> **Note:** All configuration is handled via the configuration file
```bash
~/.stackscan.conf
```

---

## Configuration

On the first run, StackScan generates a default configuration file at `/home/<your_username>/.stackscan.conf`. This file allows you to customize:

- **Global & Group-Specific Nmap Options:**  
  Adjust `NMAP_OPTIONS` as well as options for each scan group (e.g., `WEB_NMAP_OPTIONS`, `AUTH_NMAP_OPTIONS`, etc.).

- **Scan Groups:**  
  Define arrays of Nmap scripts (e.g., `WEB_NMAP_SCRIPTS`) and their corresponding arguments, plus specify port ranges for each group (e.g., `WEB_PORTS`, `AUTH_PORTS`, etc.).

- **Third-Party Scanner Settings:**  
  Customize options for **Wapiti** (`WAPITI_OPTIONS`), **Nikto** (`NIKTO_OPTIONS`), **WPScan** (`WPSCAN_OPTIONS`), and **SQLMap** (`SQLMAP_OPTIONS`).

- **Report Generation:**  
  Enable or disable HTML report generation via the `GENERATE_HTML_REPORT` setting.

- **Logging:**  
  Set the desired logging level via `LOG_LEVEL` (the script defaults to a standard level unless `-v` is provided).

For detailed explanations of each configuration parameter, refer to the comments within the configuration file.

---

## Output

StackScan produces several outputs:

- **Console Output:**  
  Real‑time status messages and progress spinners indicate scan progress.

- **Log File:**  
  A detailed log file (named using the target and the current date/time, e.g., `TARGET_DATE_TIME_scan.log`) is saved under `/var/log/stackscan`.

- **HTML Report:**  
  A comprehensive HTML report (e.g., `TARGET_DATE_TIME_scan_report.html`) is generated in `/var/lib/stackscan/reports` if HTML reporting is enabled.

All files are created with secure permissions and proper ownership.

---

## CVE Lookups

During scanning, StackScan automatically queries the National Vulnerability Database (NVD) to retrieve CVE details for any detected vulnerabilities. This provides:

- Detailed vulnerability descriptions.
- CVSS scores to help prioritize remediation.

Rate limiting is implemented to avoid exceeding NVD API limits.

---

## Contributing

Contributions are welcome! If you’d like to contribute:

1. Fork the repository.
2. Create a new branch for your changes.
3. Submit a pull request with a clear description of your improvements.

---

## License

StackScan is released under the [MIT License](LICENSE).

---

## Acknowledgements

StackScan integrates and builds upon several open‑source tools and resources:

- [Nmap](https://nmap.org/)
- [Wapiti](http://wapiti.sourceforge.io/)
- [Nikto](https://cirt.net/Nikto2)
- [WPScan](https://wpscan.org/)
- [SQLMap](https://sqlmap.org/)
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [jq](https://stedolan.github.io/jq/)
- [curl](https://curl.se/)

---

Happy scanning and stay secure!