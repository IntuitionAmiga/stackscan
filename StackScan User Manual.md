# **StackScan End User Manual**

## **1. Introduction**

### **Overview of StackScan**
StackScan is a comprehensive server security scanning tool designed to identify vulnerabilities, misconfigurations, and potential threats across multiple service groups, including web, authentication, database, and common services. The tool leverages powerful scanning utilities like Nmap, Wapiti, and Nikto, along with CVE lookups from the National Vulnerability Database (NVD), to conduct thorough assessments of your server's security posture.

### **Purpose of the Tool**
The primary purpose of StackScan is to provide system administrators, security professionals, and IT staff with a reliable and efficient way to identify and mitigate security risks on their servers. Whether used as part of regular security assessments or for incident response, StackScan delivers actionable insights into your server environment.

### **Key Features**
- **Automated and Parallel Scanning**: Efficiently scans multiple service groups using Nmap, Wapiti, and Nikto in parallel.
- **CVE Lookups**: Integrates with the NVD to provide detailed vulnerability information.
- **Configurable Scans**: Fully customizable through a configuration file to suit different environments and security requirements.
- **Detailed Reporting**: Generates comprehensive HTML reports and logs for in-depth analysis.

### **Intended Audience**
This manual is intended for system administrators, security professionals, and IT staff responsible for server security. It assumes a basic understanding of server operations, networking, and security concepts.

---

## **2. Getting Started**

### **System Requirements**
To run StackScan effectively, ensure your system meets the following requirements:
- **Operating System**: Linux (any modern distribution)
- **Tools**: `nmap`, `wapiti`, `nikto`, `jq`, `curl`, `ping6`, `dig`
- **Permissions**: Root privileges required

### **Installation**

#### **Prerequisites**
Before installing StackScan, ensure that the following tools are installed on your system:
```sh
sudo apt-get install nmap wapiti nikto jq curl inetutils-ping dnsutils
```

#### **Installation Steps**
1. **Clone the Repository**:
   ```sh
   git clone https://github.com/intuitionamiga/stackscan
   cd stackscan
   ```
2. **Set Execution Permissions**:
   ```sh
   chmod +x stackscan.sh
   ```

### **Basic Usage**

#### **Running a Simple Scan**
To perform a basic scan with StackScan, execute the following command:
```sh
sudo ./stackscan.sh <target>
```
Replace `<target>` with the IP address or domain name of the server you wish to scan.

#### **Understanding the Output**
StackScan provides real-time feedback during the scan process. Once the scan is complete, the tool generates a detailed log file and an HTML report for review.

---

## **3. Configuration**

### **Overview of Configuration File (`stackscan.conf`)**
The `~/stackscan.conf` file is the core configuration file for StackScan. It allows you to customize the behavior of the scans, including Nmap options, Wapiti options, Nikto options, and more.

### **Detailed Configuration Options**

#### **Nmap Options**
- **NMAP_OPTIONS**: General options for Nmap scans, e.g., `-Pn -sC -A -sV -sS`.

#### **Wapiti Options**
- **WAPITI_OPTIONS**: Options to configure the scope and depth of Wapiti web vulnerability scans.

#### **Nikto Options**
- **NIKTO_OPTIONS**: Options for running Nikto scans, such as SSL settings and verbosity levels.

#### **Group-Specific Scripts and Arguments**
- **WEB_NMAP_SCRIPTS**: Define the Nmap scripts for web scans, e.g., `http-enum`, `http-vuln*`.
- **WEB_NMAP_SCRIPT_ARGS**: Arguments specific to the Nmap scripts used in web scans.

#### **Port Definitions by Group**
- **WEB_PORTS**: Ports to scan in the web group, e.g., `80,443,8080,8443`.

### **Modifying the Configuration File**
To modify the `stackscan.conf` file, open it in any text editor:
```sh
nano ~/.stackscan.conf
```
Adjust the parameters as needed and save the file.

### **Example Configurations**
Below is an example configuration for a typical web and database server environment:

```plaintext
NMAP_OPTIONS="-Pn -sC -A -sV -sS"
WEB_NMAP_SCRIPTS=("http-enum" "http-vuln*" "http-wordpress*")
WEB_NMAP_SCRIPT_ARGS=("http-wordpress-enum.threads=10" "http-wordpress-brute.threads=10")
WEB_PORTS="80,443,8080,8443"
```

### **Full Default Configuration**
For a full breakdown of the default configuration file, please refer to [Appendix A](#appendix-a-full-default-configuration-file).

---

## **4. Running Scans**

### **Command-Line Options**

#### **Target Specification**
Specify the target server's IP address or domain name:
```sh
sudo ./stackscan.sh <target>
```

#### **Verbose Mode**
Enable verbose output for detailed logging:
```sh
sudo ./stackscan.sh -v <target>
```

#### **Output Options**
- **Log File**: The scan results are saved in a log file named after the target and timestamp.
- **HTML Report**: An HTML report is generated summarizing the scan results.

### **Scan Types**

#### **Web Scans**
Focuses on HTTP/HTTPS services, identifying vulnerabilities in web servers and applications.

#### **Auth Scans**
Targets authentication services like SSH and FTP to detect potential weaknesses in authentication mechanisms.

#### **Database Scans**
Scans database services (e.g., MySQL, PostgreSQL) for vulnerabilities and misconfigurations.

#### **Common Scans**
Covers widely-used services like DNS, SMB, and SSL, ensuring comprehensive coverage.

#### **Vulnerability Scans**
Utilizes Nmap's vulnerability scripts to identify known security issues.

### **Parallel and Grouped Scans**

#### **How Parallel Scanning Works**
StackScan runs multiple scans in parallel, significantly reducing the total time required to assess a target. This feature is particularly useful when scanning multiple services on a large network.

#### **Optimizing Scans for Performance**
To optimize scan performance, ensure that your system has adequate resources (CPU, RAM) and consider narrowing the scope of scans (e.g., limiting the number of ports or services).

### **Example Scenarios**

#### **Scanning a Web Server**
```sh
sudo ./stackscan.sh -v example.com
```
This command will perform a comprehensive scan of the web services hosted on `example.com`.

#### **Scanning a Database Server**
```sh
sudo ./stackscan.sh -v 192.168.1.100
```
This command will scan the database services running on the server at `192.168.1.100`.

#### **Comprehensive Vulnerability Assessment**
For a full vulnerability assessment:
```sh
sudo ./stackscan.sh -v <target>
```
This will run all available scans in parallel, providing a thorough evaluation of the target's security posture.

---

## **5. Output and Reporting**

### **Understanding Console Output**
During the scan, StackScan provides real-time feedback in the console. This includes the status of each scan group and any detected vulnerabilities.

### **Log Files**

#### **Location and Structure**
Log files are saved in the same directory as the script, named after the target and timestamp, e.g., `127.0.0.1_20240826_114046_scan.log`.

#### **Log File Naming Conventions**
Log files follow the naming convention: `<target>_<date>_<time>_scan.log`, ensuring easy identification and organization.

### **HTML Reports**

#### **Report Structure**
HTML reports summarize the scan results, including:
- Overview of detected services
- Vulnerabilities with associated CVE details
- Recommendations for remediation

#### **Viewing Reports**
Reports can be viewed in any web browser. The file is saved in the same directory as the script and log file.

#### **Interpreting the Results**
The HTML report is divided into sections corresponding to each scan group. Each section provides details on detected services, open ports, and identified vulnerabilities.

### **CVE Lookups**

#### **How CVE Lookups Are Performed**
StackScan automatically queries the NVD for CVEs related to detected services and vulnerabilities. This information is included in the HTML report.

#### **Understanding CVE Information in Reports**
Each CVE entry includes:
- **CVE ID**: The unique identifier for the vulnerability.
- **Description**: A brief overview of the issue.
- **CVSS Score**: A numerical score representing the severity of the vulnerability.

---

## **6. Advanced Usage**

### **Custom Scan Groups**
Users can define additional scan groups in the configuration file. This allows for tailored scans that focus on specific services or vulnerabilities.

### **Custom Nmap Scripts and Arguments**
The `stackscan.conf` file allows you to specify custom Nmap scripts and arguments, enabling advanced users to fine-tune their scans.

### **Running Wapiti and Nikto Scans Concurrently**
StackScan runs Wapiti and Nikto scans concurrently across multiple ports, improving scan efficiency. This is particularly useful for large-scale web application assessments.

### **Integrating StackScan with Other Tools**
StackScan can be integrated into a larger security toolkit, using its output for further analysis with tools like Metasploit, Burp Suite, or SIEM solutions.

---

##

**7. Troubleshooting**

### **Common Issues and Solutions**

#### **Issue**: Missing dependencies
**Solution**: Ensure all required tools (`nmap`, `wapiti`, `nikto`, etc.) are installed on your system.

#### **Issue**: Permission errors
**Solution**: Run the script with `sudo` to ensure it has the necessary permissions to perform scans.

### **Error Messages and What They Mean**

#### **Error**: "This script must be run as root."
**Meaning**: The script requires root privileges to perform certain actions. Run it with `sudo`.

#### **Error**: "Command not found: nmap"
**Meaning**: The `nmap` tool is not installed or not in the system's PATH. Install it using your package manager.

### **Where to Find Help**
For additional assistance, refer to the project’s GitHub Issues page or consult the community.

---

## **8. Best Practices**

### **Configuring Scans for Different Environments**
Customize the `stackscan.conf` file to suit your specific environment. For example, use different port ranges or Nmap scripts for web servers versus database servers.

### **Interpreting Results for Actionable Security Improvements**
Focus on high-severity vulnerabilities first. Use the CVSS scores and recommendations in the HTML report to prioritize remediation efforts.

### **Regular Use and Maintenance**
Regularly update the tools used by StackScan (`nmap`, `wapiti`, `nikto`) to ensure that scans incorporate the latest vulnerability checks. Schedule periodic scans to maintain your server's security posture.

---

## **9. FAQs**

### **Frequently Asked Questions**

#### **Q1**: Can StackScan be used on multiple targets simultaneously?
**A**: Yes, StackScan can be run in parallel on different terminals to scan multiple targets simultaneously.

#### **Q2**: How do I customize the Nmap scripts used by StackScan?
**A**: Edit the `stackscan.conf` file and modify the script lists and arguments under each group.

#### **Q3**: What is the difference between Verbose mode and regular mode?
**A**: Verbose mode provides more detailed output in the console and logs, showing each command executed and its results.

### **Quick Reference Guide**

- **Run a scan**: `sudo ./stackscan.sh <target>`
- **Enable verbose mode**: `sudo ./stackscan.sh -v <target>`
- **View logs**: `<target>_<date>_<time>_scan.log`
- **View report**: `<target>_<date>_<time>_scan_report.html`

---

## **10. Appendices**

### **Appendix A: Full Default Configuration File**

Below is the full default configuration file generated by StackScan (`~/.stackscan.conf`):

```bash
# Default Nmap options
NMAP_OPTIONS="-Pn -sC -A -sV -sS"

# Group-specific Nmap scripts and their specific arguments

# Web Group
WEB_NMAP_SCRIPTS=("http-enum" "http-vuln*" "http-wordpress*" "http-phpmyadmin-dir-traversal" "http-config-backup" "http-vhosts")
WEB_NMAP_SCRIPT_ARGS=("http-wordpress-enum.threads=10" "http-wordpress-brute.threads=10" "" "" "" "")

# Auth Group
AUTH_NMAP_SCRIPTS=("ssh*" "ftp*" "auth*" "ssh-auth-methods")
AUTH_NMAP_SCRIPT_ARGS=("" "" "" "")

# Database Group
DATABASE_NMAP_SCRIPTS=("*sql*" "mysql*" "http-sql-injection")
DATABASE_NMAP_SCRIPT_ARGS=("ftp-anon.maxlist=10" "" "")

# Common Group
COMMON_NMAP_SCRIPTS=("*apache*" "dns*" "smb*" "firewall*" "ssl-enum-ciphers" "ssl-cert")
COMMON_NMAP_SCRIPT_ARGS=("" "" "" "" "" "")

# Vulnerability Group
VULN_NMAP_SCRIPTS=("vuln*" "vulners")
VULN_NMAP_SCRIPT_ARGS=("" "")

# Ports to scan by group
WEB_PORTS="80,443,8080,8443"
AUTH_PORTS="389,636"
DATABASE_PORTS="3306,5432,1433,1521"
COMMON_PORTS="22,21,53,445"
VULN_PORTS="25,110,143,993,995,1194,500,4500"
CUSTOM_PORTS=""

# Custom Group (User-defined)
CUSTOM_NMAP_SCRIPTS=("")
CUSTOM_NMAP_SCRIPT_ARGS=("")

# Nikto scan options
NIKTO_OPTIONS="-ssl"

# Wapiti scan options
WAPITI_OPTIONS="--scope domain -d 5 --max-links-per-page 100 --flush-attacks --max-scan-time 3600 -m all"

# Report generation
GENERATE_HTML_REPORT="true"

# Log level
LOG_LEVEL="INFO"  # Change this to "VERBOSE" for more detailed logs
```

---

## **License**
StackScan is released under the MIT License. See `LICENSE` for more details.

## **Acknowledgements**
- [Nmap](https://nmap.org/)
- [Wapiti](http://wapiti.sourceforge.io/)
- [Nikto](https://cirt.net/Nikto2)
- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)