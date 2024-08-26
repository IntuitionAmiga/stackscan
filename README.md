      ██████ ▄▄▄█████▓ ▄▄▄       ▄████▄   ██ ▄█▀   ██████  ▄████▄   ▄▄▄        ███▄    █
    ▒██    ▒ ▓  ██▒ ▓▒▒████▄    ▒██▀ ▀█   ██▄█▒  ▒██    ▒ ▒██▀ ▀█  ▒████▄      ██ ▀█   █
    ░ ▓██▄   ▒ ▓██░ ▒░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░  ░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
      ▒   ██▒░ ▓██▓ ░ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄    ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
    ▒██████▒▒  ▒██▒ ░  ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄ ▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
    ▒ ▒▓▒ ▒ ░  ▒ ░░    ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒
    ░ ░▒  ░ ░    ░      ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░░ ░▒  ░ ░   ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
    ░  ░  ░    ░        ░   ▒          ░ ░ ░░ ░ ░  ░  ░          ░     ░   ▒      ░   ░ ░
          ░                ░  ░░ ░      ░  ░          ░   ░ ░          ░  ░        ░
                                ░                        ░

                                   StackScan (c) 2024 Zayn Otley
                             https://github.com/intuitionamiga/stackscan
                                MIT License - Use at your own risk!
```

# StackScan

StackScan is a comprehensive server security scanning tool designed to identify vulnerabilities, misconfigurations, and potential threats across multiple service groups, including web, authentication, database, and common services. The tool leverages powerful scanning utilities like Nmap, Wapiti, and Nikto, along with CVE lookups from the National Vulnerability Database (NVD), to conduct thorough assessments of your server's security posture.

## Features

- **Automated and Parallel Scanning**: The script conducts thorough scans using Nmap for open ports and services, and Nikto for web server vulnerabilities, running them in parallel across multiple ports to cover a wide range of potential issues, including those identified by the OWASP Top Ten.
- **IPv6 Awareness**: Automatically detects and adjusts scans based on IPv6 support on the target machine.
- **Configurable Scanning**: Fully configurable via the `~/stackscan.conf` file, allowing users to adjust Nmap options, scripts, and other parameters to suit their environment.
- **Parallel and Grouped Nmap Scans**: Nmap scans are organized into meaningful groups (web, auth, database, common, vuln) and run in parallel, with each group using tailored script arguments and specific port ranges to enhance performance and improve the relevance of the security assessment.
- **Group-Specific Port Scanning and Script Arguments**: Each scan group (web, auth, database, common, vuln, custom) uses its own predefined set of ports and Nmap script arguments, improving the precision and effectiveness of the security assessment.
- **Concurrent Wapiti and Nikto Scanning**: Wapiti and Nikto scans run concurrently across multiple Nmap-detected web server ports, speeding up the identification of web vulnerabilities.
- **Customizable Scan Groups**: Users can define a custom group in the configuration file to add additional scans, ensuring flexibility while maintaining safety.
- **CVE Lookups**: The script performs CVE lookups from the NVD based on detected service versions, providing detailed information about vulnerabilities found, including descriptions and CVSS scores.
- **Detailed Logging with Verbose Option**: The script includes a `VERBOSE` logging level, providing comprehensive logs that detail every action taken, including the specific commands executed and their outputs.
- **Professional HTML Reports**: Generates detailed HTML reports that include scan results, service detection results, and vulnerability details, with relevant CVE lookups where applicable.
- **Enhanced Error Handling**: Improved handling of missing commands and configuration issues ensures robust operation and clear error messages.
- **File Ownership and Cleanup**: Ensures that all generated files are owned by the user running the script and that temporary files are properly cleaned up after the scan completes.

## Prerequisites

Ensure that the following tools are installed on your system:

- `nmap`
- `wapiti`
- `nikto`
- `jq`
- `curl`
- `ping6`
- `dig`

You can install these tools using your package manager (e.g., `apt`, `yum`, `brew`).

## Installation

1. Clone this repository:

   ```
   git clone https://github.com/intuitionamiga/stackscan
   cd stackscan
   ```

2. Ensure the script has executable permissions:

   ```sh
   chmod +x stackscan.sh
   ```

## Usage

To run a scan, execute the script with a target IP or domain. The script must be run with root privileges.

```sh
sudo ./stackscan.sh [options] <target>
```

### Options

- `-v`: Enable verbose mode for more detailed output.

### Example

```sh
sudo ./stackscan.sh -v 127.0.0.1
```

### Configuration

Upon first run, a default configuration file is generated at `~/.stackscan.conf`. This file allows you to customize the scan options for Nmap, Wapiti, and Nikto, as well as other parameters.

**Key Configuration Options:**
- **NMAP_OPTIONS**: Customize Nmap scan options.
- **WEB_NMAP_SCRIPTS**: Define scripts to be used for web scanning.
- **NIKTO_OPTIONS**: Set options for Nikto web server scanning.
- **WAPITI_OPTIONS**: Configure Wapiti options for web vulnerability scanning.

For detailed configuration instructions, including all available options and their usage, please refer to the User Manual.

### Output

- **Console**: Real-time status updates and scan results.
- **Log File**: Detailed log saved to `TARGET_DATE_TIME_scan.log`.
- **HTML Report**: Generated in the same directory, named `TARGET_DATE_TIME_scan_report.html`.

### CVE Lookup

During the scan, StackScan performs CVE lookups from the National Vulnerability Database (NVD) for any detected vulnerabilities. These lookups provide detailed information about the vulnerabilities found, including descriptions and CVSS scores.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss potential changes.

## License

StackScan is released under the MIT License. See `LICENSE` for more details.

## Acknowledgements

- [Nmap](https://nmap.org/)
- [Wapiti](http://wapiti.sourceforge.io/)
- [Nikto](https://cirt.net/Nikto2)
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
