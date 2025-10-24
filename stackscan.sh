#!/bin/bash
if ((BASH_VERSINFO[0] < 4)); then
    echo "Error: Bash 4.0 or higher required" >&2
    exit 1
fi

# Check for --help before requiring root
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    # We'll handle help below after loading functions
    SHOW_HELP_ONLY=true
else
    # Ensure the script is run as root (check this early, before any directory operations)
    if [ "$EUID" -ne 0 ]; then
        echo -e "\033[31mError: This script must be run as root.\033[0m" >&2
        echo "Usage: sudo $0 [OPTIONS] <domain_or_ip>" >&2
        echo "Use --help for more information" >&2
        exit 1
    fi
fi

scan_start_time=$(date +%s)

# Global statistics tracking variables
declare -A STATS_NMAP_SCANS=(
    [web]=0
    [auth]=0
    [database]=0
    [common]=0
    [vuln]=0
    [custom]=0
)
STATS_WAPITI_SCANS=0
STATS_NIKTO_SCANS=0
STATS_WPSCAN_SCANS=0
STATS_SQLMAP_SCANS=0
STATS_OPEN_PORTS=0
STATS_VULNERABILITIES=0
STATS_CVES=0

# Phase 3: Progress tracking and error handling
STATS_FAILED_SCANS=0
declare -A SCAN_STAGE_STATUS=(
    [initialization]="PENDING"
    [nmap_ipv4]="PENDING"
    [nmap_ipv6]="PENDING"
    [port_detection]="PENDING"
    [third_party_scans]="PENDING"
    [vulnerability_analysis]="PENDING"
    [report_generation]="PENDING"
)
CURRENT_SCAN_STAGE=""
TOTAL_SCAN_STAGES=7

# Phase 4A: OWASP Top 10 tracking (2021)
declare -A OWASP_FINDINGS=(
    [A01_Broken_Access_Control]=0
    [A02_Cryptographic_Failures]=0
    [A03_Injection]=0
    [A04_Insecure_Design]=0
    [A05_Security_Misconfiguration]=0
    [A06_Vulnerable_Components]=0
    [A07_Auth_Failures]=0
    [A08_Data_Integrity_Failures]=0
    [A09_Logging_Failures]=0
    [A10_SSRF]=0
)
OWASP_TOTAL_FINDINGS=0

# Phase 4A: ExploitDB tracking
STATS_CVES_WITH_EXPLOITS=0
STATS_TOTAL_EXPLOITS=0
declare -A CVE_EXPLOIT_DATA  # Stores exploit info for each CVE

readonly STACKSCAN_LOG_DIR="/var/log/stackscan"
readonly STACKSCAN_DATA_DIR="/var/lib/stackscan"
readonly STACKSCAN_TMP_DIR="/tmp/stackscan"
readonly SCAN_DIR="."

setup_directories() {
    # Create log directory with root:root ownership and restricted permissions
    if [ ! -d "$STACKSCAN_LOG_DIR" ]; then
        mkdir -p "$STACKSCAN_LOG_DIR"
        chmod 755 "$STACKSCAN_LOG_DIR"  # drwxr-xr-x
    fi

    # Create data directory that will hold the reports
    # We make this readable by the group to allow web servers or other tools to access reports
    if [ ! -d "$STACKSCAN_DATA_DIR" ]; then
        mkdir -p "$STACKSCAN_DATA_DIR"
        chmod 775 "$STACKSCAN_DATA_DIR"  # drwxrwxr-x
        # Create a reports subdirectory
        mkdir -p "$STACKSCAN_DATA_DIR/reports"
        chmod 775 "$STACKSCAN_DATA_DIR/reports"
    fi
    mkdir -p "$STACKSCAN_TMP_DIR" && chmod 700 "$STACKSCAN_TMP_DIR"
}

setup_directories

setup_secure_permissions() {
    # Set secure umask
    umask 077

    # Ensure log directory has secure permissions
    chmod 755 "$STACKSCAN_LOG_DIR"

    # Ensure data directory has secure permissions
    chmod 775 "$STACKSCAN_DATA_DIR"
    chmod 775 "$STACKSCAN_DATA_DIR/reports"

    # Ensure log file has secure permissions from the start
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    # Ensure HTML report file has secure permissions
    touch "$HTML_REPORT_FILE"
    chmod 644 "$HTML_REPORT_FILE"
}

setup_resource_limits() {
    # Set maximum number of concurrent processes (increased from 50 to avoid fork issues)
    # Note: This limit applies only to child processes spawned by this script
    local max_procs=1000
    ulimit -u "$max_procs"

    # Set maximum file size (500MB)
    ulimit -f 512000

    # Check available disk space (need at least 1GB free)
    local free_space=$(df -P "$STACKSCAN_DATA_DIR" | awk 'NR==2 {print $4}')
    if [ "$free_space" -lt 1048576 ]; then
        log_message "ERROR" "Insufficient disk space. Need at least 1GB free."
        exit 1
    fi
}

setup_resource_limits

readonly CLEANUP_PATTERNS=(
    "*_scan_output.txt"
    "*_output.txt"
)

# Cleanup
trap 'cleanup_handler' EXIT INT TERM

cleanup_handler() {
    local exit_code=$?

    # Kill all background processes
    for pid in "${BACKGROUND_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done

    # Clean up temporary scan output files
    rm -f "${STACKSCAN_LOG_DIR}"/*_scan_output.txt
    rm -f "${STACKSCAN_DATA_DIR}"/*_output.txt

    exit "$exit_code"
}

# Function to handle errors
handle_error() {
    local exit_code=$?
    local cmd="${BASH_COMMAND}"
    local line_number="${BASH_LINENO[0]}"

    case $exit_code in
        124)
            log_message "ERROR" "Command timed out: ${cmd}"
            ;;
        127)
            log_message "ERROR" "Command not found: ${cmd}"
            ;;
        *)
            log_message "ERROR" "Command failed with exit code ${exit_code}: ${cmd}"
            ;;
    esac

    # Log the stack trace
    local i=0
    local stack_size=${#FUNCNAME[@]}
    log_message "ERROR" "Stack trace:"
    while [ $i -lt $stack_size ]; do
        log_message "ERROR" "  ${BASH_SOURCE[$i]}:${BASH_LINENO[$i]} ${FUNCNAME[$i]}"
        i=$((i + 1))
    done

    cleanup_handler
    exit "$exit_code"
}

# Automatically trap errors and call the handle_error function
trap 'handle_error ${BASH_SOURCE[0]} ${LINENO} ${FUNCNAME[0]:-main} $?' ERR
trap 'kill -TERM $$ 2>/dev/null' INT TERM

run_with_timeout() {
    local timeout=$1
    shift
    print_verbose "Running command with ${timeout}s timeout: $*"
    timeout "$timeout" "$@"
    local exit_code=$?
    if [ $exit_code -eq 124 ]; then
        log_message "WARNING" "Command timed out after ${timeout} seconds: $*"
        return 124
    fi
    return $exit_code
}

# Phase 3: Handle scanner errors gracefully
handle_scanner_error() {
    local scanner_name="$1"
    local exit_code="$2"
    local target="$3"

    if [ $exit_code -ne 0 ]; then
        ((STATS_FAILED_SCANS++))
        if [ $exit_code -eq 124 ]; then
            log_message "WARNING" "${scanner_name} scan timed out on ${target}"
            print_warning "$(date '+[%Y-%m-%d %H:%M:%S]') ${scanner_name} scan timed out on ${target} (continuing...)"
        elif [ $exit_code -eq 127 ]; then
            log_message "WARNING" "${scanner_name} command not found - skipping"
            print_warning "$(date '+[%Y-%m-%d %H:%M:%S]') ${scanner_name} not installed - skipping scan"
        else
            log_message "WARNING" "${scanner_name} scan failed with exit code ${exit_code} on ${target}"
            print_warning "$(date '+[%Y-%m-%d %H:%M:%S]') ${scanner_name} scan failed on ${target} (continuing...)"
        fi
        return 1
    fi
    return 0
}

# Phase 3: Check if external scanner tool is available
check_scanner_available() {
    local scanner="$1"
    if ! command -v "$scanner" &> /dev/null; then
        print_warning "$(date '+[%Y-%m-%d %H:%M:%S]') ${scanner} not found - skipping ${scanner} scans"
        log_message "WARNING" "${scanner} not available in PATH"
        return 1
    fi
    return 0
}

# ANSI color codes
BOLD="\033[1m"
CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

# Default log level (INFO)
LOG_LEVEL="INFO"

# Default log file (in case it's needed before configuration is loaded)
LOG_FILE=""

# Function to log messages with timestamps
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    # Only log VERBOSE messages if in verbose mode
    if [ "$level" = "VERBOSE" ] && [ "$LOG_LEVEL" != "VERBOSE" ]; then
        return
    fi

    if [ -n "$LOG_FILE" ]; then
        echo "[$timestamp] $level: $message" >> "$LOG_FILE"
    fi

    case "$level" in
        ERROR)   echo -e "${RED}$message${RESET}" ;;
        WARNING) [[ "$LOG_LEVEL" != "QUIET" ]] && echo -e "${YELLOW}$message${RESET}" ;;
        INFO)    [[ "$LOG_LEVEL" =~ ^(INFO|VERBOSE)$ ]] && echo -e "${GREEN}$message${RESET}" ;;
        VERBOSE) [[ "$LOG_LEVEL" == "VERBOSE" ]] && echo -e "${CYAN}$message${RESET}" ;;
    esac
}

# Function to print status messages
print_status() {
    log_message "INFO" "$1"
}

# Function to print verbose messages
print_verbose() {
    log_message "VERBOSE" "$1" >/dev/null 2>&1
}

# Function to print warnings
print_warning() {
    log_message "WARNING" "$1"
}

# Function to print errors
print_error() {
    log_message "ERROR" "$1"
}

# Phase 3: Progress tracking functions
update_scan_stage() {
    local stage="$1"
    local status="$2"  # PENDING, IN_PROGRESS, COMPLETED, FAILED

    SCAN_STAGE_STATUS[$stage]="$status"
    CURRENT_SCAN_STAGE="$stage"

    # Calculate progress percentage
    local completed_stages=0
    for s in "${!SCAN_STAGE_STATUS[@]}"; do
        if [ "${SCAN_STAGE_STATUS[$s]}" = "COMPLETED" ]; then
            ((completed_stages++))
        fi
    done
    local progress_percent=$((completed_stages * 100 / TOTAL_SCAN_STAGES))

    # Display progress
    local stage_display=$(echo "$stage" | tr '_' ' ' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2));}1')
    if [ "$status" = "IN_PROGRESS" ]; then
        print_status "$(date '+[%Y-%m-%d %H:%M:%S]') [${progress_percent}%] Stage: ${stage_display} - ${status}"
    elif [ "$status" = "COMPLETED" ]; then
        print_status "$(date '+[%Y-%m-%d %H:%M:%S]') [${progress_percent}%] Stage: ${stage_display} - ${status} ✓"
    elif [ "$status" = "FAILED" ]; then
        print_warning "$(date '+[%Y-%m-%d %H:%M:%S]') [${progress_percent}%] Stage: ${stage_display} - ${status} ✗"
    fi
}

show_scan_progress() {
    local completed=0
    local failed=0
    local in_progress=0
    local pending=0

    for stage in "${!SCAN_STAGE_STATUS[@]}"; do
        case "${SCAN_STAGE_STATUS[$stage]}" in
            COMPLETED) ((completed++)) ;;
            FAILED) ((failed++)) ;;
            IN_PROGRESS) ((in_progress++)) ;;
            PENDING) ((pending++)) ;;
        esac
    done

    echo ""
    echo "Scan Progress: $completed/$TOTAL_SCAN_STAGES stages completed"
    if [ $failed -gt 0 ]; then
        echo "Failed stages: $failed"
    fi
}

# Configuration validation function
validate_configuration() {
    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Validating configuration..."

    local validation_errors=0

    # Validate port ranges
    for group in WEB AUTH DATABASE COMMON VULN; do
        local ports_var="${group}_PORTS"
        local ports="${!ports_var}"
        if [ -n "$ports" ]; then
            # Check if ports contain valid numbers and commas
            if ! [[ "$ports" =~ ^[0-9,]+$ ]]; then
                print_error "Invalid port format in ${group}_PORTS: $ports"
                ((validation_errors++))
            fi
        fi
    done

    # Validate Nmap scripts exist
    for group in WEB AUTH DATABASE COMMON VULN; do
        local scripts_var="${group}_NMAP_SCRIPTS[@]"
        local scripts=("${!scripts_var}")
        for script in "${scripts[@]}"; do
            if [ -n "$script" ] && [[ ! "$script" =~ \* ]]; then
                # Only validate non-wildcard scripts
                if [ ! -f "/usr/share/nmap/scripts/${script}.nse" ]; then
                    print_warning "Nmap script not found: ${script}.nse (will be skipped)"
                fi
            fi
        done
    done

    if [ $validation_errors -gt 0 ]; then
        print_error "Configuration validation failed with $validation_errors error(s)"
        return 1
    fi

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Configuration validation passed ✓"
    return 0
}

# Phase 4A: Educational Mode - Knowledge Base System
print_educational_info() {
    local topic="$1"

    if [ "$EDUCATIONAL_MODE" != "true" ]; then
        return 0
    fi

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}${GREEN}📚 EDUCATIONAL INFO: $topic${RESET}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${RESET}"

    case "$topic" in
        "SCAN_START")
            cat <<'EOF'

🎯 WHAT WE'RE DOING:
   StackScan performs a comprehensive security assessment using multiple
   industry-standard tools to discover vulnerabilities in your target.

🔍 SCAN METHODOLOGY:
   1. Reconnaissance - Gather information about the target
   2. Service Detection - Identify running services and versions
   3. Vulnerability Scanning - Test for known weaknesses
   4. Web Application Testing - Check for web-specific vulnerabilities
   5. Exploitation Verification - Confirm vulnerabilities are real

📖 WHY THIS MATTERS:
   Security assessments help identify weaknesses BEFORE attackers do.
   Each vulnerability found is an opportunity to strengthen your defenses.

⚠️  LEGAL NOTE:
   Only scan systems you own or have explicit written permission to test.
   Unauthorized scanning is illegal in most jurisdictions.

EOF
            ;;

        "NMAP_SCANNING")
            cat <<'EOF'

🔧 NMAP - The Network Mapper

WHAT IT DOES:
   Nmap is the industry standard for network discovery and security auditing.
   It sends specially crafted packets to determine what ports are open and
   what services are running.

HOW IT WORKS:
   • Port Scanning: Tests which network ports (1-65535) are accepting connections
   • Service Detection: Identifies software/version running on each port
   • OS Fingerprinting: Attempts to determine the operating system
   • Script Scanning: Runs specialized tests for known vulnerabilities

ATTACK PERSPECTIVE:
   Attackers use Nmap to:
   - Find exposed services (potential entry points)
   - Identify outdated software versions (known vulnerabilities)
   - Map network topology (plan multi-stage attacks)

DEFENSIVE VALUE:
   - Discover unnecessary exposed services (reduce attack surface)
   - Find misconfigured systems (fix before attackers find them)
   - Verify firewall rules are working correctly

CEH EXAM TIP:
   Know the different Nmap scan types:
   -sT (TCP Connect), -sS (SYN Stealth), -sU (UDP), -sV (Version Detection)

EOF
            ;;

        "WEB_SCANNING")
            cat <<'EOF'

🌐 WEB APPLICATION SCANNING

WHY WEB APPS ARE TARGETED:
   70% of attacks target the application layer (OWASP statistics).
   Web apps often have direct access to databases and sensitive data.

TOOLS USED:
   • Wapiti - Automated web vulnerability scanner
   • Nikto - Web server misconfiguration detector
   • WPScan - WordPress-specific security scanner (if detected)
   • SQLMap - SQL injection detection and exploitation (if detected)

COMMON WEB VULNERABILITIES:
   1. SQL Injection (OWASP A03:2021)
      - Attackers inject malicious SQL to access/modify database
      - Can lead to complete database compromise

   2. Cross-Site Scripting/XSS (OWASP A03:2021)
      - Inject malicious JavaScript into pages viewed by other users
      - Can steal sessions, credentials, or redirect to malware

   3. Authentication Flaws (OWASP A07:2021)
      - Weak passwords, session hijacking, broken logout
      - Direct access to user accounts

   4. Security Misconfiguration (OWASP A05:2021)
      - Default credentials, unnecessary features enabled
      - Directory listings, verbose error messages

WHAT ATTACKERS LOOK FOR:
   - Login pages (brute force attempts)
   - File upload functionality (malware upload)
   - User input fields (injection attacks)
   - Admin interfaces (privilege escalation)

EOF
            ;;

        "CVE_LOOKUP")
            cat <<'EOF'

🔐 CVE - Common Vulnerabilities and Exposures

WHAT IS A CVE:
   CVEs are standardized identifiers for publicly known security vulnerabilities.
   Format: CVE-YEAR-NUMBER (e.g., CVE-2024-12345)

WHY THEY MATTER:
   • Vendors use CVEs to coordinate patches
   • Security teams prioritize fixes based on CVE severity
   • Attackers search for systems vulnerable to known CVEs

CVSS SCORING (0-10):
   • 0.0: Informational
   • 0.1-3.9: Low severity
   • 4.0-6.9: Medium severity
   • 7.0-8.9: High severity
   • 9.0-10.0: Critical severity

WHAT WE'RE DOING:
   For each CVE found, we query the National Vulnerability Database (NVD)
   to get detailed descriptions, CVSS scores, and remediation guidance.

ATTACKER PERSPECTIVE:
   - Search exploit databases for proof-of-concept code
   - Look for "exploit in the wild" indicators
   - Prioritize high-value, low-difficulty exploits

DEFENDER PERSPECTIVE:
   - Prioritize critical/high CVEs with known exploits
   - Patch or mitigate before attackers weaponize
   - Monitor threat intelligence for active exploitation

EOF
            ;;

        "OWASP_TOP_10")
            cat <<'EOF'

🛡️  OWASP TOP 10 - Web Application Security Risks (2021)

The Open Web Application Security Project (OWASP) Top 10 represents the
most critical security risks to web applications, updated every 3-4 years.

A01:2021 – Broken Access Control
   • Users can act outside their intended permissions
   • Example: Accessing other users' data by changing URL parameters

A02:2021 – Cryptographic Failures
   • Sensitive data exposed due to lack of encryption
   • Example: Passwords transmitted over HTTP instead of HTTPS

A03:2021 – Injection
   • Untrusted data sent to interpreter as part of command/query
   • Example: SQL injection, command injection, LDAP injection

A04:2021 – Insecure Design
   • Missing or ineffective security controls by design
   • Example: No rate limiting on password resets

A05:2021 – Security Misconfiguration
   • Missing security hardening, unnecessary features enabled
   • Example: Default credentials, directory listings enabled

A06:2021 – Vulnerable and Outdated Components
   • Using components with known vulnerabilities
   • Example: WordPress plugins with unpatched CVEs

A07:2021 – Identification and Authentication Failures
   • Broken authentication and session management
   • Example: Weak passwords, session fixation

A08:2021 – Software and Data Integrity Failures
   • Code/infrastructure without integrity verification
   • Example: Unverified updates, deserialization attacks

A09:2021 – Security Logging and Monitoring Failures
   • Insufficient logging allows attacks to go undetected
   • Example: No alerts for failed login attempts

A10:2021 – Server-Side Request Forgery (SSRF)
   • Application fetches remote resources without validation
   • Example: Accessing internal services via crafted URLs

WHY THIS MATTERS FOR CEH:
   The CEH exam expects you to recognize these categories and understand
   how to test for and remediate each type of vulnerability.

EOF
            ;;

        "REPORT_ANALYSIS")
            cat <<'EOF'

📊 ANALYZING YOUR SCAN RESULTS

HOW TO READ THIS REPORT:

1. SEVERITY PRIORITIZATION:
   Start with Critical/High severity findings first.
   These pose the most immediate risk to your organization.

2. EXPLOITABILITY:
   Findings marked "exploit available" should be prioritized.
   Attackers have ready-made tools to exploit these vulnerabilities.

3. FALSE POSITIVES:
   Not every finding is a real vulnerability. Verify manually:
   - Test the exploit yourself in a safe environment
   - Check if compensating controls exist
   - Validate the vulnerable version is actually running

4. RISK ASSESSMENT:
   Consider: Severity × Exploitability × Business Impact
   A high-severity bug in a non-critical system may be lower priority
   than a medium-severity bug in your payment processing system.

5. REMEDIATION STRATEGIES:
   • Patch: Apply vendor security updates
   • Configuration: Fix misconfigurations
   • Compensating Controls: WAF, IPS, network segmentation
   • Acceptance: Document and accept the risk (rare)

NEXT STEPS:
   1. Create remediation tickets for each finding
   2. Assign priority based on risk score
   3. Set target dates for fixes
   4. Re-scan after remediation to verify fixes
   5. Track metrics over time (vulnerabilities found/fixed)

COMMON MISTAKES:
   ❌ Ignoring "informational" findings (they provide attack intel)
   ❌ Patching without testing (can break production)
   ❌ Not re-scanning (verify fixes worked)
   ❌ Focusing on quantity over quality (one critical > ten low)

EOF
            ;;
    esac

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${RESET}"
    echo ""
}

# Phase 4A: OWASP Top 10 Mapping Function
map_to_owasp() {
    local finding="$1"
    local finding_lower=$(echo "$finding" | tr '[:upper:]' '[:lower:]')

    # A01: Broken Access Control
    if [[ "$finding_lower" =~ (access.*control|authorization|privilege.*escalation|idor|path.*traversal|directory.*traversal|forced.*browsing|insecure.*direct.*object) ]]; then
        ((OWASP_FINDINGS[A01_Broken_Access_Control]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A02: Cryptographic Failures
    if [[ "$finding_lower" =~ (weak.*cipher|ssl|tls|crypto|encryption|cleartext|plaintext|weak.*hash|md5|sha1|des|rc4|heartbleed|poodle) ]]; then
        ((OWASP_FINDINGS[A02_Cryptographic_Failures]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A03: Injection
    if [[ "$finding_lower" =~ (injection|sql.*inject|xss|cross.*site.*script|ldap.*inject|xml.*inject|command.*inject|code.*inject|os.*command|eval) ]]; then
        ((OWASP_FINDINGS[A03_Injection]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A04: Insecure Design
    if [[ "$finding_lower" =~ (rate.*limit|brute.*force|account.*enumeration|predictable|business.*logic|workflow|trust.*boundary) ]]; then
        ((OWASP_FINDINGS[A04_Insecure_Design]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A05: Security Misconfiguration
    if [[ "$finding_lower" =~ (misconfigur|default.*credential|default.*password|directory.*listing|verbose.*error|debug.*mode|unnecessary.*feature|unpatched|outdated.*software|missing.*header|security.*header|cors|csp) ]]; then
        ((OWASP_FINDINGS[A05_Security_Misconfiguration]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A06: Vulnerable and Outdated Components
    if [[ "$finding_lower" =~ (cve-|vulnerable.*component|outdated.*library|known.*vulnerability|vulnerable.*version|end.*of.*life|eol) ]]; then
        ((OWASP_FINDINGS[A06_Vulnerable_Components]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A07: Identification and Authentication Failures
    if [[ "$finding_lower" =~ (authentication|session|cookie|jwt|token|password|credential|login|logout|session.*fixation|session.*hijack) ]]; then
        ((OWASP_FINDINGS[A07_Auth_Failures]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A08: Software and Data Integrity Failures
    if [[ "$finding_lower" =~ (deserialization|insecure.*deserialization|update.*mechanism|ci.*cd|plugin|integrity.*check|untrusted.*source) ]]; then
        ((OWASP_FINDINGS[A08_Data_Integrity_Failures]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A09: Security Logging and Monitoring Failures
    if [[ "$finding_lower" =~ (logging|monitoring|audit|alerting|intrusion.*detection|siem) ]]; then
        ((OWASP_FINDINGS[A09_Logging_Failures]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    # A10: Server-Side Request Forgery (SSRF)
    if [[ "$finding_lower" =~ (ssrf|server.*side.*request|url.*fetch|remote.*fetch|internal.*service) ]]; then
        ((OWASP_FINDINGS[A10_SSRF]++))
        ((OWASP_TOTAL_FINDINGS++))
        return 0
    fi

    return 1
}

# Phase 4A: Analyze scan outputs for OWASP mapping
analyze_scan_outputs_for_owasp() {
    local scan_dir="$1"

    if [ ! -d "$scan_dir" ]; then
        return 0
    fi

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Analyzing findings for OWASP Top 10 mapping..."

    # Analyze all scan output files
    for output_file in "$scan_dir"/*_output.txt "$scan_dir"/*_scan_output.txt; do
        if [ -f "$output_file" ]; then
            # Read file line by line
            while IFS= read -r line; do
                # Skip empty lines
                [ -z "$line" ] && continue

                # Map findings to OWASP categories
                map_to_owasp "$line"
            done < "$output_file"
        fi
    done

    if [ "$EDUCATIONAL_MODE" = "true" ]; then
        echo ""
        echo -e "${GREEN}OWASP Top 10 Mapping Results:${RESET}"
        for category in "${!OWASP_FINDINGS[@]}"; do
            local count=${OWASP_FINDINGS[$category]}
            if [ $count -gt 0 ]; then
                local category_name=$(echo "$category" | tr '_' ' ')
                echo "  • $category_name: $count finding(s)"
            fi
        done
        echo "  Total OWASP-classified findings: $OWASP_TOTAL_FINDINGS"
        echo ""
    fi
}

# Load the configuration file early in the script
load_config() {
    local config_file="/home/$SUDO_USER/.stackscan.conf"
    if [ -f "$config_file" ]; then
        # Check ownership and permissions
        local owner=$(stat -c '%U' "$config_file")
        local perms=$(stat -c '%a' "$config_file")

        if [ "$owner" != "$SUDO_USER" ] || [ "$perms" != "600" ]; then
            log_message "ERROR" "Configuration file has incorrect ownership or permissions."
            exit 1
        fi
        if ! source "$config_file"; then
            print_error "Failed to source config: $config_file"
            return 1
        fi
    else
        log_message "WARNING" "Configuration file not found."
        create_default_config
    fi
}

# Create a default configuration file if it doesn't exist
create_default_config() {
    if [ -z "$SUDO_USER" ]; then
        log_message "ERROR" "SUDO_USER is not set. Please run the script with sudo."
        exit 1
    fi

    cat <<EOL > /home/"$SUDO_USER"/.stackscan.conf
# Default Nmap options
NMAP_OPTIONS="-Pn"  # More general, no aggressive scanning options

# Group-specific Nmap scripts and their specific arguments

# Web Group
WEB_NMAP_OPTIONS="-sT"  # TCP scan
WEB_NMAP_SCRIPTS=(
  "http-enum"
  "http-vuln*"
  "http-wordpress*"
  "http-phpmyadmin-dir-traversal"
  "http-config-backup"
  "http-vhosts"
  "http-sql-injection"
  "service-info"
)
WEB_NMAP_SCRIPT_ARGS=(
  "http-wordpress-enum.threads=10"
  "http-wordpress-brute.threads=10"
  "" "" "" "" "" "" ""
)
WEB_PORTS="80,443,8080,8443,8000,8888,8181,9090,8081,9000,10000,3000,5000,7000,7001,4433,10443,16080,61000,61001"

# Auth Group
AUTH_NMAP_OPTIONS="-sS -sV"  # Stealth and version detection
AUTH_NMAP_SCRIPTS=(
  "ssh*"
  "ftp*"
  "auth*"
  "ssh-auth-methods"
  "mysql-brute"
  "pgsql-brute"
  "ms-sql-brute"
  "oracle-brute"
  "mysql-empty-password"
  "ms-sql-empty-password"
)
AUTH_NMAP_SCRIPT_ARGS=(
  "" "" "" "" "" "" "" "" "" ""
)
AUTH_PORTS="22,21,389,636"

# Database Group
DATABASE_NMAP_OPTIONS="-sT -sV"  # TCP scan and version detection
DATABASE_NMAP_SCRIPTS=(
  "mysql-audit"
  "mysql-info"
  "mysql-enum"
  "pgsql-info"
  "pgsql-databases"
  "ms-sql-config"
  "ms-sql-info"
  "ms-sql-dump-hashes"
  "ms-sql-query"
  "ms-sql-tables"
  "oracle-enum-users"
  "oracle-query"
  "oracle-tns-version"
  "oracle-sid-brute"
)
DATABASE_NMAP_SCRIPT_ARGS=(
  "" "" "" "" "" "" "" "" "" "" "" "" "" ""
)
DATABASE_PORTS="3306,5432,1433,1521,1522,1434,3050,3051"

# VULN Group-specific Nmap scripts and their specific arguments
VULN_NMAP_OPTIONS="-sS -A -sV" # Aggressive scan with OS detection
VULN_NMAP_SCRIPTS=(
  "vulners"
  "http-vuln*"
  "ssl-heartbleed"
  "ftp-vsftpd-backdoor"
  "smb-vuln*"
  "http-csrf"
  "dns-zone-transfer"
)
VULN_NMAP_SCRIPT_ARGS=(
  "" "" "" "" "" "" ""
)
VULN_PORTS="21,22,25,53,80,110,443,445,1433,3306,3389"

# Common Group
COMMON_NMAP_OPTIONS="-sS -sV"  # Stealth and version detection
COMMON_NMAP_SCRIPTS=(
  "*apache*"
  "dns*"
  "smb*"
  "firewall*"
  "ssl-enum-ciphers"
  "ssl-cert"
  "service-info"
)
COMMON_NMAP_SCRIPT_ARGS=(
  "" "" "" "" "" "" ""
)
COMMON_PORTS="22,21,53,445"

# Custom Group (User-defined)
CUSTOM_NMAP_OPTIONS=""
CUSTOM_NMAP_SCRIPTS=("")
CUSTOM_NMAP_SCRIPT_ARGS=("")
CUSTOM_PORTS=""

# Nikto scan options
NIKTO_OPTIONS="-timeout 10"

# Wapiti scan options
WAPITI_OPTIONS="--flush-session --scope domain -d 5 --max-links-per-page 100 --flush-attacks --max-scan-time 1800 --timeout 10 -m all --verify-ssl 1"

# WPScan options
WPSCAN_OPTIONS="--random-user-agent --disable-tls-checks --max-threads 10"

# SQLMap options
SQLMAP_OPTIONS="--batch --random-agent --level=3 --risk=2"

# Report generation
GENERATE_HTML_REPORT="true"

# Log level
LOG_LEVEL="VERBOSE"  # Change this to "INFO" for less chatty logs

EOL

    log_message "INFO" "Default configuration file created at /home/$SUDO_USER/.stackscan.conf"
    sync
    chown "$SUDO_USER":"$SUDO_USER" /home/"$SUDO_USER"/.stackscan.conf
    chmod 600 /home/"$SUDO_USER"/.stackscan.conf

    if [ -f "/home/$SUDO_USER/.stackscan.conf" ]; then
        source /home/"$SUDO_USER"/.stackscan.conf
    else
        log_message "ERROR" "Failed to create and source the configuration file."
        exit 1
    fi

    # Validate the config file was sourced properly
    if [ -z "$NMAP_OPTIONS" ] || [ -z "$WEB_NMAP_OPTIONS" ] || [ -z "$DATABASE_NMAP_OPTIONS" ]; then
        log_message "ERROR" "One or more required configuration options are missing after sourcing the config file."
        exit 1
    fi
}

# Function to validate the target domain, IPv4, or IPv6 address
validate_target() {
    # Sanitize input - remove any potentially dangerous characters
    TARGET=$(printf '%s' "$TARGET" | tr -cd 'a-zA-Z0-9.-')

    # Rest of the validation logic remains the same
    local domain_regex="^([a-zA-Z0-9](-*[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$"
    local ipv4_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    local ipv6_regex="^(([0-9a-fA-F]{1,4}:){1,7}([0-9a-fA-F]{1,4})?|::([0-9a-fA-F]{1,4}:){0,7}([0-9a-fA-F]{1,4})?)$"

    if [[ $TARGET =~ $ipv4_regex ]]; then
        TARGET_TYPE="IPv4"
    elif [[ $TARGET =~ $ipv6_regex ]]; then
        TARGET_TYPE="IPv6"
    elif [[ $TARGET =~ $domain_regex ]]; then
        TARGET_TYPE="DOMAIN"
    else
        print_banner
        print_error "Invalid target: $TARGET. Please provide a valid domain name, IPv4, or IPv6 address."
        exit 1
    fi
}

# Now load the configuration
load_config

# Initialize global variables for command-line options
OUTPUT_JSON=false
EDUCATIONAL_MODE=false
TARGET=""

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json)
            OUTPUT_JSON=true
            shift
            ;;
        --explain|--learn|--educational)
            EDUCATIONAL_MODE=true
            shift
            ;;
        --help|-h)
            echo ""
            echo "StackScan - Comprehensive Security Scanner"
            echo "==========================================="
            echo ""
            echo "Usage: sudo $0 [OPTIONS] <domain_or_ip>"
            echo ""
            echo "OPTIONS:"
            echo "  --json              Output JSON report to console"
            echo "  --explain           Enable educational mode with detailed explanations"
            echo "  --learn             Alias for --explain"
            echo "  --educational       Alias for --explain"
            echo "  --help, -h          Show this help message"
            echo ""
            echo "EXAMPLES:"
            echo "  sudo $0 192.168.1.1                 # Basic scan"
            echo "  sudo $0 --explain example.com       # Scan with educational explanations"
            echo "  sudo $0 --json --explain target.com # JSON output + learning mode"
            echo ""
            echo "EDUCATIONAL MODE:"
            echo "  The --explain flag provides detailed explanations about:"
            echo "  • What each scan does and why"
            echo "  • How tools work (Nmap, Wapiti, Nikto, etc.)"
            echo "  • OWASP Top 10 vulnerabilities"
            echo "  • CVE/CVSS scoring systems"
            echo "  • Attack vs Defense perspectives"
            echo "  • CEH exam preparation tips"
            echo ""
            echo "Perfect for security training and education!"
            echo ""
            exit 0
            ;;
        -*)
            echo "Unknown option: $1" >&2
            echo "Usage: $0 [OPTIONS] <domain_or_ip>" >&2
            echo "Use --help for more information" >&2
            exit 1
            ;;
        *)
            if [ -z "$TARGET" ]; then
                TARGET="$1"
            else
                echo "Error: Multiple targets specified" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

# Check if target was provided
if [ -z "$TARGET" ]; then
    print_banner
    echo "Usage: $0 [OPTIONS] <domain_or_ip>"
    echo "Use --help for more information"
    exit 1
fi

# Validate the target input
validate_target "$TARGET"
readonly TARGET_SAFE=$(printf '%q' "$TARGET")
readonly DATE_TIME=$(date +"%Y%m%d_%H%M%S")
readonly LOG_FILE="${STACKSCAN_LOG_DIR}/${TARGET_SAFE}_${DATE_TIME}_scan.log"
readonly HTML_REPORT_FILE="${STACKSCAN_DATA_DIR}/reports/${TARGET_SAFE}_${DATE_TIME}_scan_report.html"
setup_secure_permissions

# Function to print the banner to console and log file
print_banner() {
    local banner_text="
    \e[1;31m  ██████ \e[1;32m▄▄▄█████▓ \e[1;33m▄▄▄       \e[1;34m▄████▄  \e[1;35m ██ ▄█▀  \e[1;36m ██████  \e[1;31m▄████▄  \e[1;32m ▄▄▄       \e[1;33m ███▄    █
    \e[1;31m▒██    ▒ \e[1;32m▓  ██▒ ▓▒\e[1;33m▒████▄    \e[1;34m▒██▀ ▀█  \e[1;35m ██▄█▒  \e[1;36m▒██    ▒ \e[1;31m▒██▀ ▀█  \e[1;32m▒████▄     \e[1;33m ██ ▀█   █
    \e[1;31m░ ▓██▄   \e[1;32m▒ ▓██░ ▒░\e[1;33m▒██  ▀█▄  \e[1;34m▒▓█    ▄ \e[1;35m▓███▄░  \e[1;36m░ ▓██▄   \e[1;31m▒▓█    ▄ \e[1;32m▒██  ▀█▄  \e[1;33m▓██  ▀█ ██▒
    \e[1;31m  ▒   ██▒\e[1;32m░ ▓██▓ ░ \e[1;33m░██▄▄▄▄██ \e[1;34m▒▓▓▄ ▄██▒\e[1;35m▓██ █▄  \e[1;36m  ▒   ██▒\e[1;31m▒▓▓▄ ▄██▒\e[1;32m░██▄▄▄▄██ \e[1;33m▓██▒  ▐▌██▒
    \e[1;31m▒██████▒▒\e[1;32m  ▒██▒ ░  \e[1;33m▓█   ▓██▒\e[1;34m▒ ▓███▀ ░\e[1;35m▒██▒ █▄ \e[1;36m▒██████▒▒\e[1;31m▒ ▓███▀ ░\e[1;32m ▓█   ▓██▒\e[1;33m▒██░   ▓██░
    \e[1;31m▒ ▒▓▒ ▒ ░\e[1;32m  ▒ ░░    \e[1;33m▒▒   ▓▒█░\e[1;34m░ ░▒ ▒  ░\e[1;35m▒ ▒▒ ▓▒\e[1;36m▒ ▒▓▒ ▒ ░\e[1;31m░ ░▒ ▒  ░\e[1;32m ▒▒   ▓▒█░\e[1;33m░ ▒░   ▒ ▒
    \e[1;31m░ ░▒  ░ ░\e[1;32m    ░      \e[1;33m▒   ▒▒ ░\e[1;34m  ░  ▒   \e[1;35m░ ░▒ ▒░\e[1;36m░ ░▒  ░ ░ \e[1;31m  ░  ▒   \e[1;32m  ▒   ▒▒ ░\e[1;33m░ ░░   ░ ▒░
    \e[1;31m░  ░  ░  \e[1;32m  ░        \e[1;33m░   ▒   \e[1;34m       ░ \e[1;35m░ ░░ ░ \e[1;36m░  ░  ░   \e[1;31m       ░ \e[1;32m    ░   ▒   \e[1;33m   ░   ░ ░
    \e[1;31m      ░  \e[1;32m             \e[1;33m ░  ░\e[1;34m░ ░      \e[1;35m░  ░   \e[1;36m       ░   \e[1;31m░ ░      \e[1;32m    ░  ░\e[1;33m        ░
                                ░                        ░

    \e[1;31m                               StackScan (c) 2024 Zayn Otley
    \e[1;32m                         https://github.com/intuitionamiga/stackscan
    \e[1;34m                            MIT License - Use at your own risk!

    "

    # Print with ANSI coloring to the console
    echo -e "${BOLD}${CYAN}$banner_text${RESET}"

# If target not blank then log the banner to the log file
if [ -n "$TARGET" ] && [ -n "$TARGET_TYPE" ]; then
  # Strip all ANSI escape codes from the banner and print to the log file
  echo -e "$banner_text" | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" >> "$LOG_FILE"
fi
}

# Check required commands
check_required_commands() {
    local cmds=("nmap" "dig" "ping6" "jq" "curl" "nikto" "wapiti" "wpscan" "sqlmap")
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            print_error "$cmd could not be found. Please install it and try again."
            exit 1
        fi
    done
}

check_ipv6_support() {
    # Only check IPv6 support if the target is specifically identified as an IPv6 address
    if [ "$TARGET_TYPE" = "IPv6" ]; then
        if ping6 -c 1 -W 1 "$TARGET" &> /dev/null; then
            IPV6_SUPPORTED=true
            print_banner
            log_message "INFO" "IPv6 is supported and reachable for $TARGET."
        else
            IPV6_SUPPORTED=false
            print_banner
            log_message "ERROR" "IPv6 is not supported or not reachable for $TARGET. Exiting."
            exit 1
        fi
    else
        IPV6_SUPPORTED=false
        log_message "INFO" "IPv6 check skipped as the target is not an IPv6 address."
    fi
}

# Check if the local machine supports IPv6
check_ipv6_support

# Check required commands
check_required_commands

# Print the banner
print_banner
log_message "INFO" "$(date '+[%Y-%m-%d %H:%M:%S]') Scan Date: $(date)"

# Phase 4A: Educational mode introduction
print_educational_info "SCAN_START"

# If -v parameter is provided, print message to console else print current log level
if [ "$LOG_LEVEL" = "VERBOSE" ]; then
    log_message "VERBOSE" "$(date '+[%Y-%m-%d %H:%M:%S]') Verbose mode enabled. Detailed logs will be printed."
else
    log_message "WARNING" "$(date '+[%Y-%m-%d %H:%M:%S]') Verbose mode disabled. Only important logs will be printed."
fi

# Phase 3: Initialize scan stages
update_scan_stage "initialization" "IN_PROGRESS"
validate_configuration || exit 1
update_scan_stage "initialization" "COMPLETED"

# Spinner function
spinner() {
    local delay
    delay=0.1
    local spinstr='|/-\'

    local scan_name
    scan_name="$1"
    local start_time
    start_time=$(date +%s)  # Capture the start time

    while kill -0 $! 2>/dev/null; do
        # Calculate elapsed time
        local current_time
        current_time=$(date +%s)
        local elapsed_time
        elapsed_time=$((current_time - start_time))

        # Format elapsed time as HH:MM:SS
        local hours=$((elapsed_time / 3600))
        local minutes=$(( (elapsed_time % 3600) / 60 ))
        local seconds=$((elapsed_time % 60))
        local formatted_time=$(printf "%02d:%02d:%02d" $hours $minutes $seconds)

        # Create the spinner string
        local temp=${spinstr#?}
        local spinner_str=$(printf " [%c] %s (%s)" "$spinstr" "$scan_name" "$formatted_time")
        spinstr=$temp${spinstr%"$temp"}

        # Calculate the padding needed to right-align the spinner
        local terminal_width=$(tput cols)
        #local spinner_length=${#spinner_str}
        #local padding=$((terminal_width - spinner_length))

        # Display the right-justified spinner
        printf "%*s\r" "$terminal_width" "$spinner_str"
        sleep $delay
    done
    printf "    \r"  # Clear spinner after process is done
}
# Function to expand wildcard patterns to actual script names
expand_wildcard_scripts() {
    local script_pattern="$1"
    local expanded_scripts=()

    # Expand wildcard pattern to actual script names
    readarray -t expanded_scripts < <(find /usr/share/nmap/scripts/ -name "${script_pattern}.nse" -exec basename {} .nse \;)

    # Return the expanded script names as an array
    echo "${expanded_scripts[@]}"
}
# Function to execute Nmap with scripts and their arguments
run_nmap_with_scripts() {
    local scripts=("$1")
    local script_args=("$2")
    local ports="$3"
    local target="$4"
    local group_name="$5"

    # Determine the Nmap options based on the group name
    local nmap_options_var="${group_name^^}_NMAP_OPTIONS"
    local nmap_options="${!nmap_options_var}"

    # Initialize the base Nmap command
    local nmap_command="nmap $nmap_options -p $ports $target"

    # Check if there are any scripts to run
    if [ ${#scripts[@]} -eq 0 ]; then
        echo "No Nmap scripts defined for this group. Skipping script execution."
        return
    fi

    # Loop through each script and apply its specific arguments
    for i in "${!scripts[@]}"; do
        script="${scripts[$i]}"
        args="${script_args[$i]}"

        if [ -n "$args" ]; then
            nmap_command+=" --script=\"$script\" --script-args=\"$args\""
        else
            nmap_command+=" --script=\"$script\""
        fi
    done

    # Execute the Nmap command
    ($nmap_command > /dev/null 2>&1) &
}
# Function to run a group scan
run_scan_group() {
    local group_name="$1"
    local group_scripts=("${!2}")
    local group_script_args=("${!3}")
    local group_ports="$4"
    local ip_version="$5"
    local target_ip="$6"

    # Determine the Nmap options based on the group name
    local nmap_options_var="${group_name^^}_NMAP_OPTIONS"
    local nmap_options="${!nmap_options_var}"

    if [ "$ip_version" == "IPv6" ]; then
        nmap_options="$nmap_options -6"
    fi

    local output_file="${target_ip}_${group_name}_${ip_version}_scan_output.txt"

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Starting Nmap $group_name scan on $target_ip ($ip_version)..."

    # Loop through each script and apply its specific arguments
    for i in "${!group_scripts[@]}"; do
        local script="${group_scripts[$i]}"
        local script_args="${group_script_args[$i]}"

        # Expand wildcard patterns to actual script names
        expanded_scripts=($(expand_wildcard_scripts "$script"))

        # Loop through each expanded script name
        for expanded_script in "${expanded_scripts[@]}"; do
            local individual_nmap_command="nmap $nmap_options -p $group_ports $target_ip --min-rate=100 --randomize-hosts >> $output_file -vv"

            if [ -n "$script_args" ]; then
                individual_nmap_command+=" --script=\"$expanded_script\" --script-args=\"$script_args\""
            else
                individual_nmap_command+=" --script=\"$expanded_script\""
            fi

            # Execute the Nmap command and append the command and its output to the output file
            echo "Executing Nmap Command: $individual_nmap_command" >> "$output_file"
            eval run_with_timeout 3600 $individual_nmap_command >> "$output_file" 2>&1

            # Add a dividing line after each command's output
            echo " " >> "$output_file"
            echo "------------------------------------------------------------------" >> "$output_file"
            echo " " >> "$output_file"

            (spinner "Nmap $group_name scan - Script: $expanded_script") &
            print_verbose "Nmap command executed for $group_name ($ip_version), Script: $expanded_script: $individual_nmap_command"
        done

    done

    # Track statistics: count executed Nmap commands
    if [ -f "$output_file" ]; then
        local nmap_cmd_count
        nmap_cmd_count=$(grep -c "Executing Nmap Command" "$output_file" 2>/dev/null || echo "0")
        STATS_NMAP_SCANS[$group_name]=$((STATS_NMAP_SCANS[$group_name] + nmap_cmd_count))
    fi

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Nmap $group_name scan on $target_ip ($ip_version) completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') Nmap $group_name scan on $target_ip ($ip_version) completed."
}
# Function to execute scans in parallel for IPv4 and IPv6
run_scans() {
   local ip_version="$1"
   local target_ip="$2"

   # Run web scan and capture PID
   run_scan_group "web" WEB_NMAP_SCRIPTS[@] WEB_NMAP_SCRIPT_ARGS[@] "$WEB_PORTS" "$ip_version" "$target_ip" &
   web_scan_pid=$!

   # Run auth scan
   run_scan_group "auth" AUTH_NMAP_SCRIPTS[@] AUTH_NMAP_SCRIPT_ARGS[@] "$AUTH_PORTS" "$ip_version" "$target_ip" &

   # Run database scan and capture PID
   run_scan_group "database" DATABASE_NMAP_SCRIPTS[@] DATABASE_NMAP_SCRIPT_ARGS[@] "$DATABASE_PORTS" "$ip_version" "$target_ip" &
   database_scan_pid=$!

   # Run remaining scans
   run_scan_group "common" COMMON_NMAP_SCRIPTS[@] COMMON_NMAP_SCRIPT_ARGS[@] "$COMMON_PORTS" "$ip_version" "$target_ip" &
   run_scan_group "vuln" VULN_NMAP_SCRIPTS[@] VULN_NMAP_SCRIPT_ARGS[@] "$VULN_PORTS" "$ip_version" "$target_ip" &

   # Run custom group if defined
   if [ -n "${CUSTOM_NMAP_SCRIPTS[0]}" ]; then
       if ! nmap --script-help="${CUSTOM_NMAP_SCRIPTS[0]}" > /dev/null 2>&1; then
           print_warning "Custom scripts not found or invalid: ${CUSTOM_NMAP_SCRIPTS[0]}"
       else
           run_scan_group "custom" CUSTOM_NMAP_SCRIPTS[@] CUSTOM_NMAP_SCRIPT_ARGS[@] "$CUSTOM_PORTS" "$ip_version" "$target_ip" &
       fi
   fi
}
# Extract any open web server ports and scan them with Wapiti, Nikto, WPScan and SQLMap
get_open_web_ports() {
    local ipv4_file="${TARGET}_web_IPv4_scan_output.txt"
    local ipv6_file="${TARGET}_web_IPv6_scan_output.txt"
    local open_ports=""
    local retry_count=0
    local max_retries=3

    while [ "$retry_count" -lt "$max_retries" ]; do
        # Check and extract from the IPv4 scan output
        if [ -f "$ipv4_file" ]; then
            local ipv4_ports
            ipv4_ports=$(awk '
            /^[0-9]+\/tcp\s+open/ {
                if ($3 ~ /^http/) {
                    split($1, port_info, "/")
                    print port_info[1]
                }
            }' "$ipv4_file")

            open_ports+="$ipv4_ports "
        fi

        # Check and extract from the IPv6 scan output if available
        if [ -f "$ipv6_file" ]; then
            local ipv6_ports
            ipv6_ports=$(awk '
            /^[0-9]+\/tcp\s+open/ {
                if ($3 ~ /^http/) {
                    split($1, port_info, "/")
                    print port_info[1]
                }
            }' "$ipv6_file")

            open_ports+="$ipv6_ports "
        fi

        open_ports=$(echo "$open_ports" | xargs)

        if [ -n "$open_ports" ]; then
            break
        fi

        ((retry_count++))
        echo "Retrying to detect open web ports ($retry_count/$max_retries)..."
        run_scans "IPv4" "$TARGET"
        wait "$web_scan_pid_v4"
    done

    if [ $retry_count -eq $max_retries ]; then
        echo "Failed to detect open web ports after $max_retries attempts."
        return 1
    else
        echo "$open_ports"
    fi

    return 0
}
run_wapiti_scan() {
    local target_ip="$1"
    shift  # Shift the arguments to get only ports
    local ports=("$@")  # Capture all ports into an array
    local wapiti_pids=()  # Array to hold the PIDs of background Wapiti processes
    declare -A wapiti_scanned_ports  # Declare associative array locally

    local wapiti_scan_count=0  # Initialize a counter

    trap '' PIPE  # Ignore SIGPIPE to prevent script termination
    for port in "${ports[@]}"; do
        if [ "${wapiti_scanned_ports[$port]}" ]; then
            continue
        fi

        local url="http://$target_ip:$port"
        if [[ "$port" == "443" || "$port" == "8443" ]]; then
            url="https://$target_ip:$port"
        fi

        print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Starting Wapiti scan on $target_ip:$port..."
        local output_file="${SCAN_DIR}/${target_ip}_${port}_wapiti_output.txt"
        # Log the exact Wapiti command being executed
        print_verbose "Executing Wapiti command: wapiti -u \"$url\" $WAPITI_OPTIONS -f txt -o \"$output_file\""

        (run_with_timeout 3600 wapiti -u "$url" $WAPITI_OPTIONS -f txt -o "$output_file" > "${output_file}_log.txt" 2>&1) &

        wapiti_pid=$!  # Capture the PID of the Wapiti process
        wapiti_pids+=("$wapiti_pid")

        wapiti_scanned_ports[$port]=1  # Mark this port as scanned

        # Increment the counter
        ((wapiti_scan_count++))

        # Start the spinner for this Wapiti process
        (spinner "Wapiti on Port $port") &
        spinner_pid=$!

        # Wait for Wapiti to complete and kill the spinner
        wait "$wapiti_pid" || true
        kill $spinner_pid 2>/dev/null
    done

    # Add dividing line after each scan's output
    echo " " >> "$output_file"
    echo "------------------------------------------------------------------" >> "$output_file"
    echo " " >> "$output_file"

    # Wait for all Wapiti processes to complete
    for pid in "${wapiti_pids[@]}"; do
        wait $pid || true
    done

    # Store the number of Wapiti scans
    echo "$wapiti_scan_count" > /tmp/wapiti_scan_count.txt
    STATS_WAPITI_SCANS=$wapiti_scan_count

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Wapiti scan on $target_ip:$port completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') Wapiti scan on $target_ip:$port completed."
}
run_nikto_scan() {
    local target_ip="$1"
    shift  # Shift the arguments to get only ports
    local ports=("$@")  # Capture all ports into an array
    local nikto_pids=()  # Array to hold the PIDs of background Nikto processes
    declare -A nikto_scanned_ports  # Declare associative array locally

    # Initialize or reset the scan count
    local nikto_scan_count=0

    trap '' PIPE  # Ignore SIGPIPE to prevent script termination
    for port in "${ports[@]}"; do
        if [ "${nikto_scanned_ports[$port]}" ]; then
            continue
        fi

        print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Starting Nikto scan on $target_ip:$port..."

        # Define the output file
        local output_file="${target_ip}_${port}_nikto_output.txt"

        # Log the exact Nikto command being executed
        print_verbose "Nikto command executed for $target_ip:$port: nikto -h $target_ip -p $port $NIKTO_OPTIONS -output ${output_file}"

        # Run Nikto in the background and immediately capture the PID
        (run_with_timeout 3600 nikto -h "$target_ip" -p "$port" $NIKTO_OPTIONS -output "$output_file" > "${output_file}_log.txt" 2>&1) &

        # Add dividing line after each scan's output
        {
            echo " "
            echo "------------------------------------------------------------------"
            echo " "
        } >> "$output_file"
        local nikto_pid=$!  # Store the PID for this particular Nikto process
        nikto_pids+=("$nikto_pid")  # Append the PID to the array

        nikto_scanned_ports[$port]=1  # Mark this port as scanned

        # Increment the scan count
        ((nikto_scan_count++))

        # Start the spinner for this Nikto process
        (spinner "Nikto on Port $port") &
        local spinner_pid=$!

        # Wait for Nikto to complete and kill the spinner
        wait "$nikto_pid" || true
        kill $spinner_pid 2>/dev/null

        print_verbose "Nikto command executed for $target_ip:$port: nikto -h $target_ip -p $port $NIKTO_OPTIONS -output ${target_ip}_${port}_nikto_output.txt"
    done

    # Wait for all Nikto processes to complete
    for pid in "${nikto_pids[@]}"; do
        wait $pid
    done

    # Store the number of Nikto scans
    echo "$nikto_scan_count" > /tmp/nikto_scan_count.txt
    STATS_NIKTO_SCANS=$nikto_scan_count

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Nikto scan on $target_ip:$port completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') Nikto scan on $target_ip:$port completed."
}
run_wpscan_scan() {
    local target_ip="$1"
    shift  # Shift the arguments to get only ports
    local ports=("$@")  # Capture all ports into an array
    local wpscan_pids=()  # Array to hold the PIDs of background WPScan processes
    declare -A wpscan_scanned_ports  # Declare associative array locally

    local wpscan_scan_count=0  # Initialize a counter

    for port in "${ports[@]}"; do
        if [ "${wpscan_scanned_ports[$port]}" ]; then
            continue  # Skip if already scanned
        fi

        local url="http://$target_ip:$port"
        if [[ "$port" == "443" || "$port" == "8443" ]]; then
            url="https://$target_ip:$port"
        fi

        print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Starting WPScan on $url..."
        local output_file="${target_ip}_${port}_wpscan_output.txt"

        # Log the exact WPScan command being executed
        print_verbose "WPScan command executed for $url: wpscan $WPSCAN_OPTIONS --url $url > $output_file"

        (run_with_timeout 3600 sudo -u "$SUDO_USER" wpscan $WPSCAN_OPTIONS --url "$url" > "$output_file" 2>&1) &
        wpscan_pid=$!  # Capture the PID of the WPScan process
        wpscan_pids+=("$wpscan_pid")

        wpscan_scanned_ports[$port]=1  # Mark this port as scanned

        # Increment the counter
        ((wpscan_scan_count++))

        # Start the spinner for this WPScan process
        (spinner "WPScan on Port $port") &
        spinner_pid=$!

        # Wait for WPScan to complete and kill the spinner
        wait "$wpscan_pid" || true
        kill $spinner_pid 2>/dev/null

        # Add dividing line after each scan's output
        echo " " >> "$output_file"
        echo "------------------------------------------------------------------" >> "$output_file"
        echo " " >> "$output_file"
    done

    # Wait for all WPScan processes to complete
    for pid in "${wpscan_pids[@]}"; do
        wait $pid || true
    done

    # Store the number of WPScan scans
    echo "$wpscan_scan_count" > /tmp/wpscan_scan_count.txt
    STATS_WPSCAN_SCANS=$wpscan_scan_count

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') WPScan scan on $target_ip:$port completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') WPScan scan on $target_ip:$port completed."
}
run_sqlmap_scan() {
    local target_ip="$1"
    shift  # Shift the arguments to get only ports
    local ports=("$@")  # Capture all ports into an array
    local sqlmap_pids=()  # Array to hold the PIDs of background SQLMap processes
    declare -A sqlmap_scanned_ports  # Declare associative array locally

    local sqlmap_scan_count=0  # Initialize a counter

    for port in "${ports[@]}"; do
        if [ "${sqlmap_scanned_ports[$port]}" ]; then
            continue  # Skip if already scanned
        fi

        local url="http://$target_ip:$port"
        if [[ "$port" == "443" || "$port" == "8443" ]]; then
            url="https://$target_ip:$port"
        fi

        print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Starting SQLMap on $url..."
        local output_file="${target_ip}_${port}_sqlmap_output.txt"

        # Log the exact SQLmap command being executed
        print_verbose "SQLMap command executed for $url: sqlmap $SQLMAP_OPTIONS -u \"$url\" > $output_file"

        (run_with_timeout 3600 sudo -u "$SUDO_USER" sqlmap $SQLMAP_OPTIONS -u "$url" > "$output_file" 2>&1) &
        sqlmap_pid=$!  # Capture the PID of the SQLMap process
        sqlmap_pids+=("$sqlmap_pid")

        sqlmap_scanned_ports[$port]=1  # Mark this port as scanned

        # Increment the counter
        ((sqlmap_scan_count++))

        # Start the spinner for this SQLMap process
        (spinner "SQLMap on Port $port") &
        spinner_pid=$!

        # Wait for SQLMap to complete and kill the spinner
        wait "$sqlmap_pid" || true
        kill $spinner_pid 2>/dev/null

        # Add dividing line after each scan's output
        echo " " >> "$output_file"
        echo "------------------------------------------------------------------" >> "$output_file"
        echo " " >> "$output_file"
    done

    # Wait for all SQLMap processes to complete
    for pid in "${sqlmap_pids[@]}"; do
        wait $pid || true
    done

    # Store the number of SQLMap scans
    echo "$sqlmap_scan_count" > /tmp/sqlmap_scan_count.txt
    STATS_SQLMAP_SCANS=$sqlmap_scan_count

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') SQLMap scan on $target_ip:$port completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') SQLMap scan on $target_ip:$port completed."
}
# Function to detect WordPress and SQL databases in both IPv4 and IPv6 outputs
detect_services() {
    local target_ip="$1"
    local wp_detected=false
    local sql_detected=false

    # Check the Nmap IPv4 output for web services (WordPress)
    local nmap_web_output_v4="${target_ip}_web_IPv4_scan_output.txt"
    if [ -f "$nmap_web_output_v4" ] && grep -qis "<meta name=\"generator\" content=\"WordPress\"" "$nmap_web_output_v4"; then
        wp_detected=true
    fi

    # Check the Nmap IPv6 output for web services (WordPress)
    local nmap_web_output_v6="${target_ip}_web_IPv6_scan_output.txt"
    if [ -f "$nmap_web_output_v6" ] && grep -qis "<meta name=\"generator\" content=\"WordPress\"" "$nmap_web_output_v6"; then
        wp_detected=true
    fi

    # Check the Nmap IPv4 output for all 35 SQL database services known to SQLMap
    local nmap_db_output_v4="${target_ip}_database_IPv4_scan_output.txt"
    if [ -f "$nmap_db_output_v4" ] && grep -qis -e "mysql" -e "postgresql" -e "mssql" -e "mariadb" -e "oracle" -e "sybase" -e "db2" -e "sqlite" -e "access" -e "firebird" -e "informix" -e "teradata" -e "memsql" -e "dynamodb" -e "arangodb" -e "couchdb" -e "mongodb" -e "monetdb" -e "mckoi" -e "presto" -e "altibase" -e "cubrid" -e "intersystems cache" -e "tibero" -e "columnstore" -e "vertica" -e "mimer" -e "hana" -e "redshift" -e "clickhouse" -e "cockroachdb" -e "greenplum" -e "nuodb" -e "oceanbase" "$nmap_db_output_v4"; then
        sql_detected=true
    fi

    # Check the Nmap IPv6 output for all 35 SQL database services known to SQLMap
    local nmap_db_output_v6="${target_ip}_database_IPv6_scan_output.txt"
    if [ -f "$nmap_db_output_v6" ] && grep -qis -e "mysql" -e "postgresql" -e "mssql" -e "mariadb" -e "oracle" -e "sybase" -e "db2" -e "sqlite" -e "access" -e "firebird" -e "informix" -e "teradata" -e "memsql" -e "dynamodb" -e "arangodb" -e "couchdb" -e "mongodb" -e "monetdb" -e "mckoi" -e "presto" -e "altibase" -e "cubrid" -e "intersystems cache" -e "tibero" -e "columnstore" -e "vertica" -e "mimer" -e "hana" -e "redshift" -e "clickhouse" -e "cockroachdb" -e "greenplum" -e "nuodb" -e "oceanbase" "$nmap_db_output_v6"; then
        sql_detected=true
    fi

    # Return the results
    echo "$wp_detected $sql_detected"
}

# Phase 4A: Educational info about Nmap
print_educational_info "NMAP_SCANNING"

# Phase 3: Start Nmap IPv4 scans
update_scan_stage "nmap_ipv4" "IN_PROGRESS"
run_scans "IPv4" "$TARGET"
web_scan_pid_v4=$web_scan_pid
database_scan_pid_v4=$database_scan_pid

# Run for IPv6 only if supported and the target is not an IPv4 address, capture the web scan PID
if [ "$IPV6_SUPPORTED" = true ] && [ "$TARGET_TYPE" != "IPv4" ]; then
   update_scan_stage "nmap_ipv6" "IN_PROGRESS"
   run_scans "IPv6" "$TARGET"
   web_scan_pid_v6=$web_scan_pid
else
   update_scan_stage "nmap_ipv6" "COMPLETED"
fi

# Wait for the web-related Nmap scans to finish so that we can extract the web server port numbers
wait "$web_scan_pid_v4" || true
[ -n "$web_scan_pid_v6" ] && wait "$web_scan_pid_v6" || true
update_scan_stage "nmap_ipv4" "COMPLETED"
if [ "$IPV6_SUPPORTED" = true ] && [ "$TARGET_TYPE" != "IPv4" ]; then
   update_scan_stage "nmap_ipv6" "COMPLETED"
fi

# Phase 3: Port detection stage
update_scan_stage "port_detection" "IN_PROGRESS"
open_ports=$(get_open_web_ports)

# Initialize associative array
declare -A unique_ports
for port in $open_ports; do
    unique_ports["$port"]=1
done

# Convert deduped associative array back to a string list
open_ports="${!unique_ports[@]}"

# Track statistics: count open ports
STATS_OPEN_PORTS=$(echo "$open_ports" | wc -w)
update_scan_stage "port_detection" "COMPLETED"

# Initialize arrays to hold PIDs
wapiti_pids=()
nikto_pids=()
wpscan_pids=()
sqlmap_pids=()

# Phase 4A: Educational info about web scanning
print_educational_info "WEB_SCANNING"

# Phase 3: Start third-party scans
update_scan_stage "third_party_scans" "IN_PROGRESS"

# If no open ports found, skip all scans
if [ -n "$open_ports" ]; then
    # Run Wapiti scans in parallel (with availability check)
    if check_scanner_available "wapiti"; then
        run_wapiti_scan "$TARGET" $open_ports &
        wapiti_pids+=($!)  # Append the PID of the Wapiti process to the array
    fi

    # Run Nikto scans in parallel (with availability check)
    if check_scanner_available "nikto"; then
        run_nikto_scan "$TARGET" $open_ports &
        nikto_pids+=($!)  # Append the PID of the Nikto process to the array
    fi

    # Wait for the database-related Nmap scans to finish
    wait "$database_scan_pid_v4" || true
    if [ -n "$database_scan_pid_v6" ]; then
        wait "$database_scan_pid_v6" || true
    fi

    # Detect services after database scan
    services_detection=$(detect_services "$TARGET")
    wp_detected=$(echo "$services_detection" | awk '{print $1}')
    sql_detected=$(echo "$services_detection" | awk '{print $2}')

    # Run WPScan only if WordPress was detected (with availability check)
    if [ "$wp_detected" = "true" ] && check_scanner_available "wpscan"; then
        run_wpscan_scan "$TARGET" $open_ports &
        wpscan_pids+=($!)  # Append the PID of the WPScan process to the array
    fi

    # Run SQLMap only if an SQL database was detected (with availability check)
    if [ "$sql_detected" = true ] && check_scanner_available "sqlmap"; then
        run_sqlmap_scan "$TARGET" $open_ports &
        sqlmap_pids+=($!)  # Append the PID of the SQLMap process to the array
    fi
fi

# Wait for all Wapiti processes to complete and handle errors
for pid in "${wapiti_pids[@]}"; do
    wait $pid
    exit_code=$?
    handle_scanner_error "Wapiti" "$exit_code" "$TARGET" || true
done

# Wait for all Nikto processes to complete and handle errors
for pid in "${nikto_pids[@]}"; do
    wait $pid
    exit_code=$?
    handle_scanner_error "Nikto" "$exit_code" "$TARGET" || true
done

# Wait for all WPScan processes to complete and handle errors
for pid in "${wpscan_pids[@]}"; do
    wait $pid
    exit_code=$?
    handle_scanner_error "WPScan" "$exit_code" "$TARGET" || true
done

# Wait for all SQLMap processes to complete and handle errors
for pid in "${sqlmap_pids[@]}"; do
    wait $pid
    exit_code=$?
    handle_scanner_error "SQLMap" "$exit_code" "$TARGET" || true
done
update_scan_stage "third_party_scans" "COMPLETED"

# Function to print scan statistics summary
print_scan_summary() {
    local total_nmap=$((STATS_NMAP_SCANS[web] + STATS_NMAP_SCANS[auth] + STATS_NMAP_SCANS[database] + STATS_NMAP_SCANS[common] + STATS_NMAP_SCANS[vuln] + STATS_NMAP_SCANS[custom]))
    local total_third_party=$((STATS_WAPITI_SCANS + STATS_NIKTO_SCANS + STATS_WPSCAN_SCANS + STATS_SQLMAP_SCANS))
    local total_scans=$((total_nmap + total_third_party))

    echo ""
    echo "=========================================="
    echo "           SCAN STATISTICS SUMMARY        "
    echo "=========================================="
    echo ""
    echo "Target: $TARGET ($TARGET_TYPE)"
    echo "Scan Duration: $formatted_scan_duration"
    echo ""
    echo "Nmap Scans:"
    echo "  - Web:      ${STATS_NMAP_SCANS[web]}"
    echo "  - Auth:     ${STATS_NMAP_SCANS[auth]}"
    echo "  - Database: ${STATS_NMAP_SCANS[database]}"
    echo "  - Common:   ${STATS_NMAP_SCANS[common]}"
    echo "  - Vuln:     ${STATS_NMAP_SCANS[vuln]}"
    echo "  - Custom:   ${STATS_NMAP_SCANS[custom]}"
    echo "  Total Nmap: $total_nmap"
    echo ""
    echo "Third-Party Scans:"
    echo "  - Wapiti:   $STATS_WAPITI_SCANS"
    echo "  - Nikto:    $STATS_NIKTO_SCANS"
    echo "  - WPScan:   $STATS_WPSCAN_SCANS"
    echo "  - SQLMap:   $STATS_SQLMAP_SCANS"
    echo "  Total:      $total_third_party"
    echo ""
    echo "Findings:"
    echo "  - Open Ports:      $STATS_OPEN_PORTS"
    echo "  - Vulnerabilities: $STATS_VULNERABILITIES"
    echo "  - CVEs:            $STATS_CVES"
    if [ $STATS_CVES_WITH_EXPLOITS -gt 0 ]; then
        echo "  - CVEs with Public Exploits: $STATS_CVES_WITH_EXPLOITS (⚠️  High Priority!)"
    fi
    echo ""

    # Phase 4A: Display OWASP Top 10 summary
    if [ $OWASP_TOTAL_FINDINGS -gt 0 ]; then
        echo "OWASP Top 10 (2021) Findings:"
        for category in A01_Broken_Access_Control A02_Cryptographic_Failures A03_Injection A04_Insecure_Design A05_Security_Misconfiguration A06_Vulnerable_Components A07_Auth_Failures A08_Data_Integrity_Failures A09_Logging_Failures A10_SSRF; do
            local count=${OWASP_FINDINGS[$category]}
            if [ $count -gt 0 ]; then
                local display_name=$(echo "$category" | sed 's/_/ /g')
                echo "  - $display_name: $count"
            fi
        done
        echo "  Total OWASP Findings: $OWASP_TOTAL_FINDINGS"
        echo ""
    fi

    echo "Scan Status:"
    echo "  - Total Scans:     $total_scans"
    echo "  - Failed Scans:    $STATS_FAILED_SCANS"
    echo "=========================================="
    echo ""
}

# Print final status messages
print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Scanning complete for $TARGET."
log_message "INFO" "$(date '+[%Y-%m-%d %H:%M:%S]') Log saved to: $LOG_FILE"

# Count vulnerabilities and CVEs from scan results
count_findings() {
    local vuln_count=0
    local cve_count=0

    # Count vulnerabilities from all scan output files
    for file in "${TARGET}"_*_scan_output.txt "${TARGET}"_*_wapiti_output.txt "${TARGET}"_*_nikto_output.txt "${TARGET}"_*_wpscan_output.txt "${TARGET}"_*_sqlmap_output.txt; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            # Count lines containing vulnerability indicators
            vuln_count=$((vuln_count + $(grep -ic -E "vuln|vulnerable|exploit|weakness|security" "$file" 2>/dev/null || echo "0")))
        fi
    done

    # Count unique CVEs from all scan output files
    local cve_list=""
    for file in "${TARGET}"_*_scan_output.txt "${TARGET}"_*_wapiti_output.txt "${TARGET}"_*_nikto_output.txt "${TARGET}"_*_wpscan_output.txt "${TARGET}"_*_sqlmap_output.txt; do
        if [ -f "$file" ] && [ -s "$file" ]; then
            cve_list+=$(grep -oE "CVE-[0-9]+-[0-9]+" "$file" 2>/dev/null || echo "")$'\n'
        fi
    done
    cve_count=$(echo "$cve_list" | sort -u | grep -c "CVE-" || echo "0")

    STATS_VULNERABILITIES=$vuln_count
    STATS_CVES=$cve_count
}

# Phase 3: Vulnerability analysis stage
update_scan_stage "vulnerability_analysis" "IN_PROGRESS"
count_findings

# Phase 4A: Analyze findings for OWASP Top 10 mapping
analyze_scan_outputs_for_owasp "${STACKSCAN_DATA_DIR}/reports"

# Phase 4A: Show OWASP Top 10 educational info if enabled
if [ "$EDUCATIONAL_MODE" = "true" ] && [ $OWASP_TOTAL_FINDINGS -gt 0 ]; then
    print_educational_info "OWASP_TOP_10"
fi

# Phase 4A: Check for public exploits (ExploitDB/Metasploit)
if [ $STATS_CVES -gt 0 ]; then
    analyze_cve_exploits "${STACKSCAN_DATA_DIR}/reports"
fi

update_scan_stage "vulnerability_analysis" "COMPLETED"

# Calculate scan duration before displaying summary
scan_end_time=$(date +%s)
scan_duration=$((scan_end_time - scan_start_time))
formatted_scan_duration=$(printf "%02d:%02d:%02d" $((scan_duration/3600)) $((scan_duration%3600/60)) $((scan_duration%60)))

# Print scan statistics summary to console
print_scan_summary

readonly API_CALLS_FILE="/tmp/stackscan_api_calls"
readonly API_RATE_LIMIT=30

check_rate_limit() {
    local current_time=$(date +%s)
    local minute_ago=$((current_time - 60))

    touch "$API_CALLS_FILE"
    sed -i "/$minute_ago/d" "$API_CALLS_FILE"
    local recent_calls=$(wc -l < "$API_CALLS_FILE")

    if [ "$recent_calls" -ge "$API_RATE_LIMIT" ]; then
        return 1
    fi

    echo "$current_time" >> "$API_CALLS_FILE"
    return 0
}

# Function to generate JSON report
generate_json_report() {
    local json_file="${STACKSCAN_DATA_DIR}/reports/${TARGET_SAFE}_${DATE_TIME}_scan_report.json"

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Generating JSON report..."

    # Create JSON structure
    cat > "$json_file" <<EOF
{
  "scan_metadata": {
    "target": "$TARGET",
    "target_type": "$TARGET_TYPE",
    "scan_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "scan_start_time": "$scan_start_time",
    "scan_end_time": "$scan_end_time",
    "scan_duration": "$formatted_scan_duration",
    "scan_duration_seconds": $scan_duration
  },
  "statistics": {
    "nmap_scans": {
      "web": ${STATS_NMAP_SCANS[web]},
      "auth": ${STATS_NMAP_SCANS[auth]},
      "database": ${STATS_NMAP_SCANS[database]},
      "common": ${STATS_NMAP_SCANS[common]},
      "vuln": ${STATS_NMAP_SCANS[vuln]},
      "custom": ${STATS_NMAP_SCANS[custom]}
    },
    "third_party_scans": {
      "wapiti": $STATS_WAPITI_SCANS,
      "nikto": $STATS_NIKTO_SCANS,
      "wpscan": $STATS_WPSCAN_SCANS,
      "sqlmap": $STATS_SQLMAP_SCANS
    },
    "findings": {
      "open_ports": $STATS_OPEN_PORTS,
      "vulnerabilities": $STATS_VULNERABILITIES,
      "cves": $STATS_CVES,
      "cves_with_exploits": $STATS_CVES_WITH_EXPLOITS,
      "total_public_exploits": $STATS_TOTAL_EXPLOITS
    },
    "owasp_top_10_2021": {
      "A01_Broken_Access_Control": ${OWASP_FINDINGS[A01_Broken_Access_Control]},
      "A02_Cryptographic_Failures": ${OWASP_FINDINGS[A02_Cryptographic_Failures]},
      "A03_Injection": ${OWASP_FINDINGS[A03_Injection]},
      "A04_Insecure_Design": ${OWASP_FINDINGS[A04_Insecure_Design]},
      "A05_Security_Misconfiguration": ${OWASP_FINDINGS[A05_Security_Misconfiguration]},
      "A06_Vulnerable_Components": ${OWASP_FINDINGS[A06_Vulnerable_Components]},
      "A07_Auth_Failures": ${OWASP_FINDINGS[A07_Auth_Failures]},
      "A08_Data_Integrity_Failures": ${OWASP_FINDINGS[A08_Data_Integrity_Failures]},
      "A09_Logging_Failures": ${OWASP_FINDINGS[A09_Logging_Failures]},
      "A10_SSRF": ${OWASP_FINDINGS[A10_SSRF]},
      "total_owasp_findings": $OWASP_TOTAL_FINDINGS
    },
    "total_scans": $((STATS_NMAP_SCANS[web] + STATS_NMAP_SCANS[auth] + STATS_NMAP_SCANS[database] + STATS_NMAP_SCANS[common] + STATS_NMAP_SCANS[vuln] + STATS_NMAP_SCANS[custom] + STATS_WAPITI_SCANS + STATS_NIKTO_SCANS + STATS_WPSCAN_SCANS + STATS_SQLMAP_SCANS)),
    "failed_scans": $STATS_FAILED_SCANS
  },
  "log_file": "$LOG_FILE",
  "html_report_file": "$HTML_REPORT_FILE"
}
EOF

    # Set secure permissions
    chmod 644 "$json_file"
    if [ -n "$SUDO_USER" ]; then
        chown "$SUDO_USER":"$SUDO_USER" "$json_file"
    fi

    log_message "INFO" "$(date '+[%Y-%m-%d %H:%M:%S]') JSON Report saved to: $json_file"

    # If --json flag was used, output the JSON to console
    if [ "$OUTPUT_JSON" = true ]; then
        cat "$json_file"
    fi
}

# Function to generate an HTML report with advanced features
lookup_cve_details() {
   local cve_id="$1"
   print_verbose "Looking up CVE details for $cve_id"

   # Check rate limit before making API call
   if ! check_rate_limit; then
       print_verbose "Rate limit hit, waiting 2s before retry"
       sleep 2
       if ! check_rate_limit; then
           print_warning "Rate limit exceeded for NVD API"
           echo "N/A,N/A" # Return placeholder values
           return 1
       fi
   fi

   local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/2.0/$cve_id"
   print_verbose "Making API request to: $nvd_api_url"

   # Make API request with timeout and user agent
   local cve_details
   cve_details=$(run_with_timeout 10 curl -s \
       -H "User-Agent: Stackscan/0.1" \
       -H "Accept: application/json" \
       "$nvd_api_url" | jq '.result.CVE_Items[0].cve')

   # Validate response
   if [[ -z "$cve_details" || "$cve_details" == "null" ]]; then
       print_warning "CVE details for $cve_id could not be retrieved."
       print_verbose "Empty or invalid response received from NVD API"
       echo "N/A,N/A"
       return 1
   fi

   # Extract details with error handling
   local cve_description
   local cve_impact_score

   cve_description=$(echo "$cve_details" | jq -r '.description.description_data[0].value // "N/A"')
   cve_impact_score=$(echo "$cve_details" | jq -r '.impact.baseMetricV2.cvssV2.baseScore // "N/A"')

   print_verbose "Retrieved CVE $cve_id: Score=$cve_impact_score Description=$cve_description"

   # Return description and score
   echo "$cve_description,$cve_impact_score"
   return 0
}

# Phase 4A: ExploitDB Integration - Check for public exploits
check_exploitdb_for_cve() {
    local cve_id="$1"

    # First, try using searchsploit if available (local ExploitDB database)
    if command -v searchsploit >/dev/null 2>&1; then
        print_verbose "Checking ExploitDB using searchsploit for $cve_id"

        local exploit_results
        exploit_results=$(searchsploit --cve "$cve_id" --json 2>/dev/null)

        if [ $? -eq 0 ] && [ -n "$exploit_results" ]; then
            local exploit_count=$(echo "$exploit_results" | jq '.RESULTS_EXPLOIT | length' 2>/dev/null || echo "0")

            if [ "$exploit_count" -gt 0 ]; then
                # Extract first exploit details
                local exploit_title=$(echo "$exploit_results" | jq -r '.RESULTS_EXPLOIT[0].Title' 2>/dev/null || echo "N/A")
                local exploit_path=$(echo "$exploit_results" | jq -r '.RESULTS_EXPLOIT[0].Path' 2>/dev/null || echo "N/A")

                print_verbose "Found $exploit_count exploit(s) for $cve_id"
                echo "YES|$exploit_count|$exploit_title|local:$exploit_path"
                return 0
            fi
        fi
    fi

    # Fallback: Query ExploitDB website (rate-limited)
    print_verbose "Checking ExploitDB website for $cve_id"

    # Use Exploit-DB search page
    local search_url="https://www.exploit-db.com/search?cve=$cve_id"
    local search_results

    search_results=$(run_with_timeout 10 curl -s -L "$search_url" 2>/dev/null)

    if [ $? -eq 0 ] && [ -n "$search_results" ]; then
        # Check if results contain exploit entries (look for exploit IDs in the page)
        if echo "$search_results" | grep -q "exploits/.*href.*$cve_id"; then
            print_verbose "Found exploit(s) for $cve_id on ExploitDB website"
            echo "YES|unknown|Public Exploit Available|web:$search_url"
            return 0
        fi
    fi

    # Check Metasploit modules (if msfconsole is available)
    if command -v msfconsole >/dev/null 2>&1; then
        print_verbose "Checking Metasploit for $cve_id"

        # Search Metasploit database for CVE
        local msf_search
        msf_search=$(msfconsole -q -x "search cve:$cve_id; exit" 2>/dev/null | grep -v "^#" | grep -v "^msf" | grep -v "Matching Modules" | grep -v "^=")

        if [ -n "$msf_search" ] && echo "$msf_search" | grep -q "exploit/"; then
            local module_name=$(echo "$msf_search" | grep "exploit/" | head -1 | awk '{print $2}')
            print_verbose "Found Metasploit module for $cve_id: $module_name"
            echo "YES|metasploit|Metasploit Module Available|msf:$module_name"
            return 0
        fi
    fi

    # No exploit found
    print_verbose "No exploits found for $cve_id"
    echo "NO|0|N/A|N/A"
    return 1
}

# Phase 4A: Analyze all CVEs for exploit availability
analyze_cve_exploits() {
    local scan_dir="$1"

    if [ ! -d "$scan_dir" ]; then
        return 0
    fi

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Checking for public exploits (ExploitDB/Metasploit)..."

    # Extract unique CVEs from scan results
    local cve_list=""
    for output_file in "$scan_dir"/*_output.txt "$scan_dir"/*_scan_output.txt; do
        if [ -f "$output_file" ]; then
            cve_list+=$(grep -oE "CVE-[0-9]+-[0-9]+" "$output_file" 2>/dev/null || echo "")$'\n'
        fi
    done

    # Get unique CVEs
    local unique_cves=$(echo "$cve_list" | sort -u | grep "CVE-")

    if [ -z "$unique_cves" ]; then
        print_verbose "No CVEs found to check for exploits"
        return 0
    fi

    # Initialize exploit tracking
    local cves_with_exploits=0
    local total_exploits=0

    # Store results in associative array
    declare -g -A CVE_EXPLOIT_DATA

    # Check each CVE for exploits (limit to first 10 to avoid excessive queries)
    local cve_count=0
    while IFS= read -r cve_id; do
        [ -z "$cve_id" ] && continue

        cve_count=$((cve_count + 1))
        if [ $cve_count -gt 10 ]; then
            print_verbose "Limiting exploit checks to first 10 CVEs to avoid rate limits"
            break
        fi

        # Check for exploits
        local exploit_info
        exploit_info=$(check_exploitdb_for_cve "$cve_id")

        # Parse result: "YES/NO|count|title|source"
        local has_exploit=$(echo "$exploit_info" | cut -d'|' -f1)

        if [ "$has_exploit" = "YES" ]; then
            cves_with_exploits=$((cves_with_exploits + 1))
            CVE_EXPLOIT_DATA["$cve_id"]="$exploit_info"

            local exploit_count=$(echo "$exploit_info" | cut -d'|' -f2)
            if [[ "$exploit_count" =~ ^[0-9]+$ ]]; then
                total_exploits=$((total_exploits + exploit_count))
            else
                total_exploits=$((total_exploits + 1))
            fi
        fi

        # Rate limiting: wait 1 second between checks
        sleep 1
    done <<< "$unique_cves"

    # Store statistics
    STATS_CVES_WITH_EXPLOITS=$cves_with_exploits
    STATS_TOTAL_EXPLOITS=$total_exploits

    if [ "$EDUCATIONAL_MODE" = "true" ] && [ $cves_with_exploits -gt 0 ]; then
        echo ""
        echo -e "${RED}⚠️  CRITICAL: Found $cves_with_exploits CVE(s) with public exploits available!${RESET}"
        echo -e "${YELLOW}   Total exploits available: $total_exploits${RESET}"
        echo -e "${YELLOW}   These vulnerabilities are actively exploitable and should be prioritized.${RESET}"
        echo ""
    fi
}

lookup_cve_by_service_version() {
   local service_name="$1"
   local version="$2"
   print_verbose "Looking up CVEs for $service_name version $version"

   # Check rate limit before making API call
   if ! check_rate_limit; then
       print_verbose "Rate limit hit, waiting 2s before retry"
       sleep 2
       if ! check_rate_limit; then
           print_warning "Rate limit exceeded for NVD API"
           return 1
       fi
   fi

   local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=$service_name+$version"
   print_verbose "Making API request to: $nvd_api_url"

   # Fetch CVE details
   local cve_details
   cve_details=$(run_with_timeout 10 curl -s \
       -H "User-Agent: Stackscan/0.1" \
       -H "Accept: application/json" \
       "$nvd_api_url")

   # Debugging output
   print_verbose "API Response: $cve_details"
   echo "API Response for $service_name $version: $cve_details" >> "$LOG_FILE"

   # Validate JSON response
   if ! echo "$cve_details" | jq empty; then
       print_warning "Invalid JSON received from NVD API for $service_name $version."
       print_verbose "Failed to parse API response as JSON"
       return 1
   fi

   # Parse CVE details
   local cve_list
   cve_list=$(echo "$cve_details" | jq -r '.result.CVE_Items[] | .cve.CVE_data_meta.ID + " - " + .cve.description.description_data[0].value + " (CVSS Score: " + (.impact.baseMetricV2.cvssV2.baseScore | tostring) + ")"')

   if [ -z "$cve_list" ]; then
       print_verbose "No CVEs found for $service_name $version"
       echo "No CVEs found for $service_name $version."
   else
       print_verbose "Found CVEs for $service_name $version:\n$cve_list"
       echo "$cve_list"
   fi
}

generate_html_report() {
    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Generating HTML report..."
        echo "<html><head><title>StackScan Report for $TARGET</title>" > "$HTML_REPORT_FILE"
        echo "<style>
                body { font-family: Arial, sans-serif; }
                h1, h2 { color: #2e6c80; }
                pre { background-color: #f4f4f4; padding: 10px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; }
                .scan-section { margin-bottom: 20px; }
                .vuln-section { margin-bottom: 10px; border: 1px solid #ccc; padding: 10px; border-radius: 5px; }
                .banner { font-family: monospace; text-align: center; }
                .red { color: #ff0000; }
                .green { color: #00ff00; }
                .yellow { color: #ffff00; }
                .blue { color: #0000ff; }
                .magenta { color: #ff00ff; }
                .cyan { color: #00ffff; }
              </style>" >> "$HTML_REPORT_FILE"
        echo "</head><body>" >> "$HTML_REPORT_FILE"

        # Add the coloured ANSI banner
        echo "<div class=\"banner\"><pre>" >> "$HTML_REPORT_FILE"
        echo -e "<span class=\"red\">  ██████ </span><span class=\"green\">▄▄▄█████▓ </span><span class=\"yellow\">▄▄▄       </span><span class=\"blue\">▄████▄  </span><span class=\"magenta\"> ██ ▄█▀  </span><span class=\"cyan\"> ██████  </span><span class=\"red\">▄████▄  </span><span class=\"green\"> ▄▄▄       </span><span class=\"yellow\"> ███▄    █</span>" >> "$HTML_REPORT_FILE"
        echo -e "<span class=\"red\">▒██    ▒ </span><span class=\"green\">▓  ██▒ ▓▒</span><span class=\"yellow\">▒████▄    </span><span class=\"blue\">▒██▀ ▀█  </span><span class=\"magenta\"> ██▄█▒  </span><span class=\"cyan\">▒██    ▒ </span><span class=\"red\">▒██▀ ▀█  </span><span class=\"green\">▒████▄     </span><span class=\"yellow\"> ██ ▀█   █</span>" >> "$HTML_REPORT_FILE"
        echo -e "<span class=\"red\">░ ▓██▄   </span><span class=\"green\">▒ ▓██░ ▒░</span><span class=\"yellow\">▒██  ▀█▄  </span><span class=\"blue\">▒▓█    ▄ </span><span class=\"magenta\">▓███▄░  </span><span class=\"cyan\">░ ▓██▄   </span><span class=\"red\">▒▓█    ▄ </span><span class=\"green\">▒██  ▀█▄  </span><span class=\"yellow\">▓██  ▀█ ██▒</span>" >> "$HTML_REPORT_FILE"
        echo -e "<span class=\"red\">  ▒   ██▒</span><span class=\"green\">░ ▓██▓ ░ </span><span class=\"yellow\">░██▄▄▄▄██ </span><span class=\"blue\">▒▓▓▄ ▄██▒</span><span class=\"magenta\">▓██ █▄  </span><span class=\"cyan\">  ▒   ██▒</span><span class=\"red\">▒▓▓▄ ▄██▒</span><span class=\"green\">░██▄▄▄▄██ </span><span class=\"yellow\">▓██▒  ▐▌██▒</span>" >> "$HTML_REPORT_FILE"
        echo -e "<span class=\"red\">▒██████▒▒</span><span class=\"green\">  ▒██▒ ░  </span><span class=\"yellow\">▓█   ▓██▒</span><span class=\"blue\">▒ ▓███▀ ░</span><span class=\"magenta\">▒██▒ █▄ </span><span class=\"cyan\">▒██████▒▒</span><span class=\"red\">▒ ▓███▀ ░</span><span class=\"green\"> ▓█   ▓██▒</span><span class=\"yellow\">▒██░   ▓██░</span>" >> "$HTML_REPORT_FILE"
        echo -e "<span class=\"red\">▒ ▒▓▒ ▒ ░</span><span class=\"green\">  ▒ ░░    </span><span class=\"yellow\">▒▒   ▓▒█░</span><span class=\"blue\">░ ░▒ ▒  ░</span><span class=\"magenta\">▒ ▒▒ ▓▒</span><span class=\"cyan\">▒ ▒▓▒ ▒ ░</span><span class=\"red\">░ ░▒ ▒  ░</span><span class=\"green\"> ▒▒   ▓▒█░</span><span class=\"yellow\">░ ▒░   ▒ ▒ </span>" >> "$HTML_REPORT_FILE"
        echo -e "<span class=\"red\">░ ░▒  ░ ░</span><span class=\"green\">    ░      </span><span class=\"yellow\">▒   ▒▒ ░</span><span class=\"blue\">  ░  ▒   </span><span class=\"magenta\">░ ░▒ ▒░</span><span class=\"cyan\">░ ░▒  ░ ░ </span><span class=\"red\">  ░  ▒   </span><span class=\"green\">  ▒   ▒▒ ░</span><span class=\"yellow\">░ ░░   ░ ▒░</span>" >> "$HTML_REPORT_FILE"
        echo -e "<span class=\"red\">░  ░  ░  </span><span class=\"green\">  ░        </span><span class=\"yellow\">░   ▒   </span><span class=\"blue\">       ░ </span><span class=\"magenta\">░ ░░ ░ </span><span class=\"cyan\">░  ░  ░   </span><span class=\"red\">       ░ </span><span class=\"green\">    ░   ▒   </span><span class=\"yellow\">   ░   ░ ░</span>" >> "$HTML_REPORT_FILE"
        echo -e "<span class=\"red\">      ░  </span><span class=\"green\">             </span><span class=\"yellow\"> ░  ░</span><span class=\"blue\">░ ░      </span><span class=\"magenta\">░  ░   </span><span class=\"cyan\">       ░   </span><span class=\"red\">░ ░      </span><span class=\"green\">    ░  ░</span><span class=\"yellow\">        ░</span>" >> "$HTML_REPORT_FILE"
        echo -e "<br>" >> "$HTML_REPORT_FILE"
        echo "</pre></div>" >> "$HTML_REPORT_FILE"
    echo "<h1>StackScan Report for $TARGET</h1>" >> "$HTML_REPORT_FILE"
    echo "<p><strong>Scan Date:</strong> $(date)</p>" >> "$HTML_REPORT_FILE"
    echo "<p><strong>Total Scanning Time:</strong> $formatted_scan_duration</p>" >> "$HTML_REPORT_FILE"

    # Add statistics summary section
    local total_nmap=$((STATS_NMAP_SCANS[web] + STATS_NMAP_SCANS[auth] + STATS_NMAP_SCANS[database] + STATS_NMAP_SCANS[common] + STATS_NMAP_SCANS[vuln] + STATS_NMAP_SCANS[custom]))
    local total_third_party=$((STATS_WAPITI_SCANS + STATS_NIKTO_SCANS + STATS_WPSCAN_SCANS + STATS_SQLMAP_SCANS))
    local total_scans=$((total_nmap + total_third_party))

    echo "<div class=\"scan-section\" style=\"background-color: #f0f8ff; padding: 15px; border-radius: 10px;\">" >> "$HTML_REPORT_FILE"
    echo "<h2>Scan Statistics Summary</h2>" >> "$HTML_REPORT_FILE"
    echo "<table style=\"width: 100%; border-collapse: collapse;\">" >> "$HTML_REPORT_FILE"
    echo "<tr style=\"background-color: #e6f2ff;\"><th colspan=\"2\" style=\"padding: 10px; text-align: left; border: 1px solid #ddd;\">Nmap Scans</th></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">Web</td><td style=\"padding: 8px; border: 1px solid #ddd;\">${STATS_NMAP_SCANS[web]}</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">Auth</td><td style=\"padding: 8px; border: 1px solid #ddd;\">${STATS_NMAP_SCANS[auth]}</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">Database</td><td style=\"padding: 8px; border: 1px solid #ddd;\">${STATS_NMAP_SCANS[database]}</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">Common</td><td style=\"padding: 8px; border: 1px solid #ddd;\">${STATS_NMAP_SCANS[common]}</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">Vuln</td><td style=\"padding: 8px; border: 1px solid #ddd;\">${STATS_NMAP_SCANS[vuln]}</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">Custom</td><td style=\"padding: 8px; border: 1px solid #ddd;\">${STATS_NMAP_SCANS[custom]}</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr style=\"font-weight: bold;\"><td style=\"padding: 8px; border: 1px solid #ddd;\">Total Nmap</td><td style=\"padding: 8px; border: 1px solid #ddd;\">$total_nmap</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr style=\"background-color: #e6f2ff;\"><th colspan=\"2\" style=\"padding: 10px; text-align: left; border: 1px solid #ddd;\">Third-Party Scans</th></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">Wapiti</td><td style=\"padding: 8px; border: 1px solid #ddd;\">$STATS_WAPITI_SCANS</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">Nikto</td><td style=\"padding: 8px; border: 1px solid #ddd;\">$STATS_NIKTO_SCANS</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">WPScan</td><td style=\"padding: 8px; border: 1px solid #ddd;\">$STATS_WPSCAN_SCANS</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">SQLMap</td><td style=\"padding: 8px; border: 1px solid #ddd;\">$STATS_SQLMAP_SCANS</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr style=\"font-weight: bold;\"><td style=\"padding: 8px; border: 1px solid #ddd;\">Total Third-Party</td><td style=\"padding: 8px; border: 1px solid #ddd;\">$total_third_party</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr style=\"background-color: #e6f2ff;\"><th colspan=\"2\" style=\"padding: 10px; text-align: left; border: 1px solid #ddd;\">Findings</th></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">Open Ports</td><td style=\"padding: 8px; border: 1px solid #ddd;\">$STATS_OPEN_PORTS</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">Vulnerabilities</td><td style=\"padding: 8px; border: 1px solid #ddd;\">$STATS_VULNERABILITIES</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">CVEs</td><td style=\"padding: 8px; border: 1px solid #ddd;\">$STATS_CVES</td></tr>" >> "$HTML_REPORT_FILE"

    # Phase 4A: Add exploit availability statistics
    if [ $STATS_CVES_WITH_EXPLOITS -gt 0 ]; then
        echo "<tr style=\"background-color: #ffcccc; font-weight: bold;\"><td style=\"padding: 8px; border: 1px solid #ddd; color: #d32f2f;\">⚠️  CVEs with Public Exploits</td><td style=\"padding: 8px; border: 1px solid #ddd; color: #d32f2f;\">$STATS_CVES_WITH_EXPLOITS (High Priority!)</td></tr>" >> "$HTML_REPORT_FILE"
        echo "<tr style=\"background-color: #ffcccc;\"><td style=\"padding: 8px; border: 1px solid #ddd;\">Total Public Exploits Available</td><td style=\"padding: 8px; border: 1px solid #ddd;\">$STATS_TOTAL_EXPLOITS</td></tr>" >> "$HTML_REPORT_FILE"
    fi

    echo "<tr style=\"background-color: #e6f2ff;\"><th colspan=\"2\" style=\"padding: 10px; text-align: left; border: 1px solid #ddd;\">Scan Status</th></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr style=\"background-color: #d0e8ff; font-weight: bold;\"><td style=\"padding: 8px; border: 1px solid #ddd;\">Total Scans Performed</td><td style=\"padding: 8px; border: 1px solid #ddd;\">$total_scans</td></tr>" >> "$HTML_REPORT_FILE"
    echo "<tr style=\"background-color: #ffe6e6;\"><td style=\"padding: 8px; border: 1px solid #ddd;\">Failed Scans</td><td style=\"padding: 8px; border: 1px solid #ddd;\">$STATS_FAILED_SCANS</td></tr>" >> "$HTML_REPORT_FILE"
    echo "</table>" >> "$HTML_REPORT_FILE"
    echo "</div>" >> "$HTML_REPORT_FILE"

    # Phase 4A: Add OWASP Top 10 section to HTML report
    if [ $OWASP_TOTAL_FINDINGS -gt 0 ]; then
        echo "<br>" >> "$HTML_REPORT_FILE"
        echo "<div class=\"scan-section\" style=\"background-color: #fff3cd; padding: 15px; border-radius: 10px; border-left: 5px solid #ff9800;\">" >> "$HTML_REPORT_FILE"
        echo "<h2 style=\"color: #ff6f00;\">🛡️ OWASP Top 10 (2021) Vulnerability Mapping</h2>" >> "$HTML_REPORT_FILE"
        echo "<p style=\"margin-bottom: 15px;\">This section maps discovered vulnerabilities to the OWASP Top 10 Web Application Security Risks. Understanding these categories helps prioritize remediation efforts.</p>" >> "$HTML_REPORT_FILE"
        echo "<table style=\"width: 100%; border-collapse: collapse;\">" >> "$HTML_REPORT_FILE"
        echo "<tr style=\"background-color: #ff9800; color: white;\"><th style=\"padding: 10px; text-align: left; border: 1px solid #ddd;\">OWASP Category</th><th style=\"padding: 10px; text-align: center; border: 1px solid #ddd;\">Findings</th><th style=\"padding: 10px; text-align: left; border: 1px solid #ddd;\">Risk Level</th></tr>" >> "$HTML_REPORT_FILE"

        # Define OWASP categories with descriptions and risk levels
        declare -A owasp_descriptions=(
            ["A01_Broken_Access_Control"]="A01:2021 - Broken Access Control|High"
            ["A02_Cryptographic_Failures"]="A02:2021 - Cryptographic Failures|High"
            ["A03_Injection"]="A03:2021 - Injection|Critical"
            ["A04_Insecure_Design"]="A04:2021 - Insecure Design|Medium"
            ["A05_Security_Misconfiguration"]="A05:2021 - Security Misconfiguration|Medium"
            ["A06_Vulnerable_Components"]="A06:2021 - Vulnerable and Outdated Components|High"
            ["A07_Auth_Failures"]="A07:2021 - Identification and Authentication Failures|Critical"
            ["A08_Data_Integrity_Failures"]="A08:2021 - Software and Data Integrity Failures|Medium"
            ["A09_Logging_Failures"]="A09:2021 - Security Logging and Monitoring Failures|Low"
            ["A10_SSRF"]="A10:2021 - Server-Side Request Forgery (SSRF)|Medium"
        )

        for category in A01_Broken_Access_Control A02_Cryptographic_Failures A03_Injection A04_Insecure_Design A05_Security_Misconfiguration A06_Vulnerable_Components A07_Auth_Failures A08_Data_Integrity_Failures A09_Logging_Failures A10_SSRF; do
            local count=${OWASP_FINDINGS[$category]}
            if [ $count -gt 0 ]; then
                local desc_and_risk="${owasp_descriptions[$category]}"
                local description=$(echo "$desc_and_risk" | cut -d'|' -f1)
                local risk=$(echo "$desc_and_risk" | cut -d'|' -f2)

                # Color code by risk level
                local risk_color="#4caf50"  # Green for Low
                if [ "$risk" = "Medium" ]; then
                    risk_color="#ff9800"  # Orange
                elif [ "$risk" = "High" ]; then
                    risk_color="#f44336"  # Red
                elif [ "$risk" = "Critical" ]; then
                    risk_color="#b71c1c"  # Dark Red
                fi

                echo "<tr><td style=\"padding: 8px; border: 1px solid #ddd;\">$description</td><td style=\"padding: 8px; border: 1px solid #ddd; text-align: center; font-weight: bold;\">$count</td><td style=\"padding: 8px; border: 1px solid #ddd; background-color: $risk_color; color: white; font-weight: bold; text-align: center;\">$risk</td></tr>" >> "$HTML_REPORT_FILE"
            fi
        done

        echo "<tr style=\"background-color: #e0e0e0; font-weight: bold; font-size: 1.1em;\"><td style=\"padding: 10px; border: 1px solid #ddd;\">Total OWASP-Classified Findings</td><td style=\"padding: 10px; border: 1px solid #ddd; text-align: center;\">$OWASP_TOTAL_FINDINGS</td><td style=\"padding: 10px; border: 1px solid #ddd;\"></td></tr>" >> "$HTML_REPORT_FILE"
        echo "</table>" >> "$HTML_REPORT_FILE"

        # Add educational note
        echo "<div style=\"margin-top: 15px; padding: 10px; background-color: #e3f2fd; border-left: 4px solid #2196f3; border-radius: 5px;\">" >> "$HTML_REPORT_FILE"
        echo "<p style=\"margin: 0; font-size: 0.9em;\"><strong>📚 Note:</strong> The OWASP Top 10 represents a broad consensus about the most critical security risks to web applications. Prioritize fixes for Critical and High risk items, especially those with known exploits.</p>" >> "$HTML_REPORT_FILE"
        echo "</div>" >> "$HTML_REPORT_FILE"
        echo "</div>" >> "$HTML_REPORT_FILE"
    fi

    # Iterate over scan groups and IP versions
    for ip_version in IPv4 IPv6; do
        for group_name in web auth database common vuln; do
            local output_file="${TARGET}_${group_name}_${ip_version}_scan_output.txt"
            if [ -f "$output_file" ]; then
                # Count the number of Nmap commands executed by counting the occurrence of "Executing Nmap Command" in the output file
                local scan_count
                scan_count=$(grep -c "Executing Nmap Command" "$output_file")
                echo "<div class=\"scan-section\"><h2>Nmap ${group_name^} Group - $scan_count Scan Report(s) ($ip_version)</h2><pre>" >> "$HTML_REPORT_FILE"
                cat "$output_file" >> "$HTML_REPORT_FILE"
                echo "</pre></div>" >> "$HTML_REPORT_FILE"
            fi
        done
    done

    # Wapiti Scan Results
    # Read the Wapiti scan count from the temporary file
    if [ -f /tmp/wapiti_scan_count.txt ]; then
        wapiti_scan_count=$(cat /tmp/wapiti_scan_count.txt)
    else
        wapiti_scan_count=0
    fi
    if [ "$wapiti_scan_count" -gt 0 ]; then
        echo "<div class=\"scan-section\"><h2>Wapiti Scan - $wapiti_scan_count Report(s)</h2><pre>" >> "$HTML_REPORT_FILE"
    else
        echo "<div class=\"scan-section\"><h2>Wapiti Scan - 0 Report(s)</h2><pre>" >> "$HTML_REPORT_FILE"
    fi
    wapiti_found=false

    # Iterate over Wapiti result files for each scanned port
    for wapiti_file in "${TARGET}"_*_wapiti_output.txt; do
        if [ -f "$wapiti_file" ] && [ -s "$wapiti_file" ]; then
            cat "$wapiti_file" >> "$HTML_REPORT_FILE"
            echo -e "\n" >> "$HTML_REPORT_FILE"  # Add a newline between results for readability
            wapiti_found=true
        fi
    done

    if [ "$wapiti_found" = false ]; then
        echo "No Wapiti results found." >> "$HTML_REPORT_FILE"
    fi
    echo "</pre></div>" >> "$HTML_REPORT_FILE"

    # Nikto Scan Results
    # Read the Nikto scan count from the temporary file
    if [ -f /tmp/nikto_scan_count.txt ]; then
        nikto_scan_count=$(cat /tmp/nikto_scan_count.txt)
    else
        nikto_scan_count=0
    fi
    if [ "$nikto_scan_count" -gt 0 ]; then
        echo "<div class=\"scan-section\"><h2>Nikto Scan - $nikto_scan_count Report(s)</h2><pre>" >> "$HTML_REPORT_FILE"
    else
        echo "<div class=\"scan-section\"><h2>Nikto Scan - 0 Report(s)</h2><pre>" >> "$HTML_REPORT_FILE"
    fi
    nikto_found=false

    # Iterate over Nikto result files for each scanned port
    for nikto_file in ${TARGET}_*_nikto_output.txt; do
        if [ -f "$nikto_file" ] && [ -s "$nikto_file" ]; then
            # Count the number of lines in the file
            line_count=$(wc -l < "$nikto_file")
            # Include only if there is more than one line
            if [ "$line_count" -gt 1 ]; then
                cat "$nikto_file" >> "$HTML_REPORT_FILE"
                echo -e "\n" >> "$HTML_REPORT_FILE"  # Add a newline between results for readability
                nikto_found=true
            fi
        fi
    done

    if [ "$nikto_found" = false ]; then
        echo "No Nikto results found." >> "$HTML_REPORT_FILE"
    fi
    echo "</pre></div>" >> "$HTML_REPORT_FILE"

        # WPScan Scan Results
        if [ -f /tmp/wpscan_scan_count.txt ]; then
            wpscan_scan_count=$(cat /tmp/wpscan_scan_count.txt)
        else
            wpscan_scan_count=0
        fi
        if [ "$wpscan_scan_count" -gt 0 ]; then
            echo "<div class=\"scan-section\"><h2>WPScan - $wpscan_scan_count Report(s)</h2><pre>" >> "$HTML_REPORT_FILE"
        else
            echo "<div class=\"scan-section\"><h2>WPScan - 0 Report(s)</h2><pre>" >> "$HTML_REPORT_FILE"
        fi
        wpscan_found=false

        # Iterate over WPScan result files for each scanned port
        for wpscan_file in ${TARGET}_*_wpscan_output.txt; do
            if [ -f "$wpscan_file" ] && [ -s "$wpscan_file" ]; then
                cat "$wpscan_file" >> "$HTML_REPORT_FILE"
                echo -e "\n" >> "$HTML_REPORT_FILE"  # Add a newline between results for readability
                wpscan_found=true
            fi
        done

        if [ "$wpscan_found" = false ]; then
            echo "No WPScan results found." >> "$HTML_REPORT_FILE"
        fi
        echo "</pre></div>" >> "$HTML_REPORT_FILE"

    # SQLMap Scan Results
    if [ -f /tmp/sqlmap_scan_count.txt ]; then
        sqlmap_scan_count=$(cat /tmp/sqlmap_scan_count.txt)
    else
        sqlmap_scan_count=0
    fi
    if [ "$sqlmap_scan_count" -gt 0 ]; then
        echo "<div class=\"scan-section\"><h2>SQLMap - $sqlmap_scan_count Report(s)</h2><pre>" >> "$HTML_REPORT_FILE"
    else
        echo "<div class=\"scan-section\"><h2>SQLMap - 0 Report(s)</h2><pre>" >> "$HTML_REPORT_FILE"
    fi
    sqlmap_found=false

    # Iterate over SQLMap result files for each scanned port
    for sqlmap_file in ${TARGET}_*_sqlmap_output.txt; do
        if [ -f "$sqlmap_file" ] && [ -s "$sqlmap_file" ]; then
            cat "$sqlmap_file" >> "$HTML_REPORT_FILE"
            echo -e "\n" >> "$HTML_REPORT_FILE"  # Add a newline between results for readability
            sqlmap_found=true
        fi
    done

    if [ "$sqlmap_found" = false ]; then
        echo "No SQLMap results found." >> "$HTML_REPORT_FILE"
    fi
    echo "</pre></div>" >> "$HTML_REPORT_FILE"

    # Detailed Vulnerability Information
    echo "<div class=\"scan-section\"><h2>Detailed Vulnerability Report(s)</h2>" >> "$HTML_REPORT_FILE"

    # Collect vulnerabilities from the scan results
    local vuln_file="${TARGET}_vuln_scan_output.txt"
    if [ -f "$vuln_file" ]; then
        while IFS= read -r line; do
            local severity="N/A"
            local cvss_score="N/A"
            local cve_id=""

            # Extract CVE if present
            if echo "$line" | grep -q "CVE-"; then
                cve_id=$(echo "$line" | grep -o "CVE-[0-9]\+-[0-9]\+")
                if [ -n "$cve_id" ]; then
                    local cve_info
                    cve_info=$(lookup_cve_details "$cve_id")
                    severity=$(echo "$cve_info" | cut -d',' -f1)
                    cvss_score=$(echo "$cve_info" | cut -d',' -f2)
                fi
            fi

            # Display vulnerability information in the report
            echo "<div class=\"vuln-section\"><pre>" >> "$HTML_REPORT_FILE"
            echo "$line" >> "$HTML_REPORT_FILE"
            if [ -n "$cve_id" ]; then
                echo "<strong>CVE:</strong> $cve_id<br>" >> "$HTML_REPORT_FILE"
            fi
            echo "<strong>Severity:</strong> $severity<br>" >> "$HTML_REPORT_FILE"
            echo "<strong>CVSS Score:</strong> $cvss_score<br>" >> "$HTML_REPORT_FILE"
            echo "</pre></div>" >> "$HTML_REPORT_FILE"

        done < "$vuln_file"
    else
        echo "<p>No CVE's detected during the scan.</p>" >> "$HTML_REPORT_FILE"
    fi

    echo "</div>" >> "$HTML_REPORT_FILE"

    # Phase 4A: Add educational sections to HTML report (if educational mode is enabled)
    if [ "$EDUCATIONAL_MODE" = "true" ]; then
        echo "<br><hr><br>" >> "$HTML_REPORT_FILE"
        echo "<div style=\"background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px;\">" >> "$HTML_REPORT_FILE"
        echo "<h1 style=\"color: white; margin-top: 0;\">📚 Educational Resources & Guidance</h1>" >> "$HTML_REPORT_FILE"
        echo "<p style=\"font-size: 1.1em;\">This section helps you understand your security assessment results and provides actionable guidance for improving your security posture.</p>" >> "$HTML_REPORT_FILE"
        echo "</div>" >> "$HTML_REPORT_FILE"

        # Understanding Your Results
        echo "<div class=\"scan-section\" style=\"background-color: #e3f2fd; padding: 20px; border-radius: 10px; margin-bottom: 20px; border-left: 5px solid #2196f3;\">" >> "$HTML_REPORT_FILE"
        echo "<h2 style=\"color: #1976d2;\">🎯 Understanding Your Results</h2>" >> "$HTML_REPORT_FILE"
        echo "<p><strong>What is a vulnerability scan?</strong></p>" >> "$HTML_REPORT_FILE"
        echo "<p>A vulnerability scan is an automated process that identifies potential security weaknesses in your systems. Think of it as a security checkup - we're looking for doors left unlocked, windows left open, and known design flaws.</p>" >> "$HTML_REPORT_FILE"
        echo "<p><strong>How to read this report:</strong></p>" >> "$HTML_REPORT_FILE"
        echo "<ul style=\"line-height: 1.8;\">" >> "$HTML_REPORT_FILE"
        echo "<li><strong>Statistics Table:</strong> Shows the scope of testing (how many scans were run, what tools were used)</li>" >> "$HTML_REPORT_FILE"
        echo "<li><strong>Findings:</strong> Number of open ports, vulnerabilities, and CVEs discovered</li>" >> "$HTML_REPORT_FILE"
        echo "<li><strong>OWASP Top 10:</strong> Vulnerabilities mapped to industry-standard web application security risks</li>" >> "$HTML_REPORT_FILE"
        echo "<li><strong>CVE Details:</strong> Known vulnerabilities with severity ratings and descriptions</li>" >> "$HTML_REPORT_FILE"
        echo "</ul>" >> "$HTML_REPORT_FILE"
        echo "</div>" >> "$HTML_REPORT_FILE"

        # Severity Levels Explained
        echo "<div class=\"scan-section\" style=\"background-color: #fff3e0; padding: 20px; border-radius: 10px; margin-bottom: 20px; border-left: 5px solid #ff9800;\">" >> "$HTML_REPORT_FILE"
        echo "<h2 style=\"color: #f57c00;\">⚠️  Understanding Severity Levels</h2>" >> "$HTML_REPORT_FILE"
        echo "<p>Vulnerabilities are rated using the <strong>CVSS (Common Vulnerability Scoring System)</strong> on a scale of 0-10:</p>" >> "$HTML_REPORT_FILE"
        echo "<table style=\"width: 100%; border-collapse: collapse; margin-top: 15px;\">" >> "$HTML_REPORT_FILE"
        echo "<tr style=\"background-color: #b71c1c; color: white;\"><th style=\"padding: 10px; border: 1px solid #ddd;\">Critical (9.0-10.0)</th><td style=\"padding: 10px; border: 1px solid #ddd; color: white;\">Immediate action required. These vulnerabilities can be exploited remotely without authentication. Fix within 24 hours.</td></tr>" >> "$HTML_REPORT_FILE"
        echo "<tr style=\"background-color: #f44336; color: white;\"><th style=\"padding: 10px; border: 1px solid #ddd;\">High (7.0-8.9)</th><td style=\"padding: 10px; border: 1px solid #ddd; color: white;\">Significant risk. Exploitable with moderate effort. Fix within 7 days.</td></tr>" >> "$HTML_REPORT_FILE"
        echo "<tr style=\"background-color: #ff9800; color: white;\"><th style=\"padding: 10px; border: 1px solid #ddd;\">Medium (4.0-6.9)</th><td style=\"padding: 10px; border: 1px solid #ddd; color: white;\">Moderate risk. May require user interaction or specific conditions. Fix within 30 days.</td></tr>" >> "$HTML_REPORT_FILE"
        echo "<tr style=\"background-color: #4caf50; color: white;\"><th style=\"padding: 10px; border: 1px solid #ddd;\">Low (0.1-3.9)</th><td style=\"padding: 10px; border: 1px solid #ddd; color: white;\">Minor risk. Difficult to exploit or limited impact. Fix when convenient.</td></tr>" >> "$HTML_REPORT_FILE"
        echo "</table>" >> "$HTML_REPORT_FILE"
        echo "</div>" >> "$HTML_REPORT_FILE"

        # OWASP Top 10 Primer (if OWASP findings exist)
        if [ $OWASP_TOTAL_FINDINGS -gt 0 ]; then
            echo "<div class=\"scan-section\" style=\"background-color: #fff3cd; padding: 20px; border-radius: 10px; margin-bottom: 20px; border-left: 5px solid #ff9800;\">" >> "$HTML_REPORT_FILE"
            echo "<h2 style=\"color: #ff6f00;\">🛡️ OWASP Top 10 Quick Reference</h2>" >> "$HTML_REPORT_FILE"
            echo "<p>The <strong>OWASP Top 10</strong> represents the most critical security risks to web applications. Here's what was found in your scan:</p>" >> "$HTML_REPORT_FILE"
            echo "<div style=\"padding: 15px; background-color: white; border-radius: 5px; margin-top: 10px;\">" >> "$HTML_REPORT_FILE"

            for category in A01_Broken_Access_Control A02_Cryptographic_Failures A03_Injection; do
                local count=${OWASP_FINDINGS[$category]}
                if [ $count -gt 0 ]; then
                    case $category in
                        A01_Broken_Access_Control)
                            echo "<h3>A01:2021 - Broken Access Control ($count findings)</h3>" >> "$HTML_REPORT_FILE"
                            echo "<p><strong>What it is:</strong> Users can access resources they shouldn't be able to (e.g., viewing other users' data).</p>" >> "$HTML_REPORT_FILE"
                            echo "<p><strong>How to fix:</strong> Implement proper authorization checks, deny by default, use secure session management.</p>" >> "$HTML_REPORT_FILE"
                            ;;
                        A02_Cryptographic_Failures)
                            echo "<h3>A02:2021 - Cryptographic Failures ($count findings)</h3>" >> "$HTML_REPORT_FILE"
                            echo "<p><strong>What it is:</strong> Sensitive data transmitted or stored without proper encryption (e.g., passwords in plain text).</p>" >> "$HTML_REPORT_FILE"
                            echo "<p><strong>How to fix:</strong> Use TLS/HTTPS for all data in transit, encrypt sensitive data at rest, use strong encryption algorithms.</p>" >> "$HTML_REPORT_FILE"
                            ;;
                        A03_Injection)
                            echo "<h3>A03:2021 - Injection ($count findings)</h3>" >> "$HTML_REPORT_FILE"
                            echo "<p><strong>What it is:</strong> Malicious data sent to interpreters (SQL, OS commands, LDAP) causing unintended execution.</p>" >> "$HTML_REPORT_FILE"
                            echo "<p><strong>How to fix:</strong> Use parameterized queries, input validation, escape special characters, use ORMs.</p>" >> "$HTML_REPORT_FILE"
                            ;;
                    esac
                    echo "<hr style=\"margin: 15px 0;\">" >> "$HTML_REPORT_FILE"
                fi
            done

            echo "<p><em>For complete OWASP Top 10 information, visit <a href=\"https://owasp.org/Top10/\" target=\"_blank\">https://owasp.org/Top10/</a></em></p>" >> "$HTML_REPORT_FILE"
            echo "</div></div>" >> "$HTML_REPORT_FILE"
        fi

        # Remediation Prioritization Guide
        echo "<div class=\"scan-section\" style=\"background-color: #e8f5e9; padding: 20px; border-radius: 10px; margin-bottom: 20px; border-left: 5px solid #4caf50;\">" >> "$HTML_REPORT_FILE"
        echo "<h2 style=\"color: #2e7d32;\">🔧 How to Prioritize Fixes</h2>" >> "$HTML_REPORT_FILE"
        echo "<p>Not all vulnerabilities are equal. Use this priority matrix to decide what to fix first:</p>" >> "$HTML_REPORT_FILE"
        echo "<ol style=\"line-height: 1.8;\">" >> "$HTML_REPORT_FILE"
        echo "<li><strong style=\"color: #b71c1c;\">CRITICAL PRIORITY:</strong> CVEs with public exploits + Critical/High CVSS score</li>" >> "$HTML_REPORT_FILE"
        echo "<li><strong style=\"color: #d32f2f;\">HIGH PRIORITY:</strong> Critical/High CVSS vulnerabilities on internet-facing services</li>" >> "$HTML_REPORT_FILE"
        echo "<li><strong style=\"color: #f57c00;\">MEDIUM PRIORITY:</strong> Medium CVSS vulnerabilities or High CVSS on internal services</li>" >> "$HTML_REPORT_FILE"
        echo "<li><strong style=\"color: #388e3c;\">LOW PRIORITY:</strong> Low CVSS scores, informational findings, or security hardening recommendations</li>" >> "$HTML_REPORT_FILE"
        echo "</ol>" >> "$HTML_REPORT_FILE"

        if [ $STATS_CVES_WITH_EXPLOITS -gt 0 ]; then
            echo "<div style=\"background-color: #ffcdd2; padding: 15px; border-radius: 5px; margin-top: 15px; border-left: 4px solid #d32f2f;\">" >> "$HTML_REPORT_FILE"
            echo "<p style=\"margin: 0; font-weight: bold; color: #b71c1c;\">⚠️  URGENT: You have $STATS_CVES_WITH_EXPLOITS CVE(s) with public exploits available!</p>" >> "$HTML_REPORT_FILE"
            echo "<p style=\"margin: 10px 0 0 0;\">These vulnerabilities can be exploited by attackers right now. Prioritize these fixes immediately.</p>" >> "$HTML_REPORT_FILE"
            echo "</div>" >> "$HTML_REPORT_FILE"
        fi

        echo "</div>" >> "$HTML_REPORT_FILE"

        # Learning Resources
        echo "<div class=\"scan-section\" style=\"background-color: #f3e5f5; padding: 20px; border-radius: 10px; margin-bottom: 20px; border-left: 5px solid #9c27b0;\">" >> "$HTML_REPORT_FILE"
        echo "<h2 style=\"color: #7b1fa2;\">📖 Learning Resources for CEH Students</h2>" >> "$HTML_REPORT_FILE"
        echo "<p>Want to learn more about the vulnerabilities found in this scan? Here are excellent resources:</p>" >> "$HTML_REPORT_FILE"
        echo "<ul style=\"line-height: 1.8;\">" >> "$HTML_REPORT_FILE"
        echo "<li><strong>OWASP Foundation:</strong> <a href=\"https://owasp.org\" target=\"_blank\">https://owasp.org</a> - Web application security best practices</li>" >> "$HTML_REPORT_FILE"
        echo "<li><strong>NIST National Vulnerability Database:</strong> <a href=\"https://nvd.nist.gov\" target=\"_blank\">https://nvd.nist.gov</a> - Official CVE details and CVSS scores</li>" >> "$HTML_REPORT_FILE"
        echo "<li><strong>Exploit Database:</strong> <a href=\"https://www.exploit-db.com\" target=\"_blank\">https://www.exploit-db.com</a> - Public exploit repository</li>" >> "$HTML_REPORT_FILE"
        echo "<li><strong>MITRE ATT&CK Framework:</strong> <a href=\"https://attack.mitre.org\" target=\"_blank\">https://attack.mitre.org</a> - Adversary tactics and techniques</li>" >> "$HTML_REPORT_FILE"
        echo "<li><strong>CWE (Common Weakness Enumeration):</strong> <a href=\"https://cwe.mitre.org\" target=\"_blank\">https://cwe.mitre.org</a> - Software weakness catalog</li>" >> "$HTML_REPORT_FILE"
        echo "<li><strong>SANS Reading Room:</strong> <a href=\"https://www.sans.org/reading-room\" target=\"_blank\">https://www.sans.org/reading-room</a> - Security whitepapers</li>" >> "$HTML_REPORT_FILE"
        echo "</ul>" >> "$HTML_REPORT_FILE"
        echo "<h3 style=\"color: #7b1fa2; margin-top: 20px;\">🎓 CEH Exam Tips:</h3>" >> "$HTML_REPORT_FILE"
        echo "<ul style=\"line-height: 1.8;\">" >> "$HTML_REPORT_FILE"
        echo "<li>Know the OWASP Top 10 in order (they appear on the exam!)</li>" >> "$HTML_REPORT_FILE"
        echo "<li>Understand CVSS scoring categories: Low (0.1-3.9), Medium (4.0-6.9), High (7.0-8.9), Critical (9.0-10.0)</li>" >> "$HTML_REPORT_FILE"
        echo "<li>Be familiar with Nmap scan types: -sT (TCP Connect), -sS (SYN Stealth), -sU (UDP), -sV (Version Detection)</li>" >> "$HTML_REPORT_FILE"
        echo "<li>Know the difference between vulnerability scanning and penetration testing</li>" >> "$HTML_REPORT_FILE"
        echo "<li>Understand the phases: Reconnaissance → Scanning → Gaining Access → Maintaining Access → Covering Tracks</li>" >> "$HTML_REPORT_FILE"
        echo "</ul>" >> "$HTML_REPORT_FILE"
        echo "</div>" >> "$HTML_REPORT_FILE"

        # Footer note
        echo "<div style=\"text-align: center; padding: 20px; background-color: #f5f5f5; border-radius: 10px; margin-top: 20px;\">" >> "$HTML_REPORT_FILE"
        echo "<p style=\"margin: 0; color: #666;\"><em>This report was generated in Educational Mode. For production scanning, run without --explain flag for streamlined output.</em></p>" >> "$HTML_REPORT_FILE"
        echo "<p style=\"margin: 10px 0 0 0; color: #999; font-size: 0.9em;\">Generated by StackScan - Open Source Security Assessment Tool</p>" >> "$HTML_REPORT_FILE"
        echo "</div>" >> "$HTML_REPORT_FILE"
    fi

    echo "</body></html>" >> "$HTML_REPORT_FILE"

    log_message "INFO" "$(date '+[%Y-%m-%d %H:%M:%S]') HTML Report saved to: $HTML_REPORT_FILE"
}

scan_end_time=$(date +%s)
scan_duration=$((scan_end_time - scan_start_time))
formatted_scan_duration=$(printf "%02d:%02d:%02d" $((scan_duration/3600)) $((scan_duration%3600/60)) $((scan_duration%60)))

# Phase 3: Report generation stage
update_scan_stage "report_generation" "IN_PROGRESS"

# Generate HTML report if enabled
if [ "$GENERATE_HTML_REPORT" = "true" ]; then
    generate_html_report
fi

# Generate JSON report (always generated, but only output to console if --json flag is set)
generate_json_report

update_scan_stage "report_generation" "COMPLETED"

# Ensure all created files are owned by the user running the script
if [ -n "$SUDO_USER" ]; then
    chown "$SUDO_USER":"$SUDO_USER" "$LOG_FILE" "$HTML_REPORT_FILE"
fi

#wait for any background jobs to finish
exec {fd}< <(spinner "Waiting for background jobs to finish...")
wait "$!"
exec {fd}<&-
sync &

# Print total scan duration
log_message "INFO" "$(date '+[%Y-%m-%d %H:%M:%S]') Total execution time: $formatted_scan_duration"

# Clean up the temporary files
trap 'rm -f -- "${temp_files[@]}"' EXIT
temp_files+=("${TARGET}_${port}_output.txt")

# Open the HTML report in the default browser as the non-root user
# We have to do this because KDE 6.1 borked xdg-open
if [ "$GENERATE_HTML_REPORT" = "true" ]; then
        run_with_timeout 3600 sudo -u "$SUDO_USER" x-www-browser "$HTML_REPORT_FILE" & > /dev/null 2>&1 &
fi

exit 0