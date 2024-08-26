#!/bin/bash
scan_start_time=$(date +%s)

# Function to handle errors
handle_error() {
    local exit_code=$?
    local cmd="${BASH_COMMAND}"
    local line_number="${BASH_LINENO[0]}"
    log_message "ERROR" "An error occurred during the execution of the script."
    log_message "ERROR" "Command: '${cmd}' failed with exit code ${exit_code}."
    log_message "ERROR" "Error occurred on line ${line_number}."
    echo "Cleaning up..."
    # Delete temp files
    rm -f *_output.txt
    exit $exit_code
}

# Automatically trap errors and call the handle_error function
trap 'handle_error' ERR

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
    if [ "$level" = "ERROR" ]; then
        echo -e "${RED}$message${RESET}"
        if [ -n "$LOG_FILE" ]; then echo "[$timestamp] ERROR: $message" >> "$LOG_FILE"; fi
    elif [ "$level" = "WARNING" ]; then
        echo -e "${YELLOW}$message${RESET}"
        if [ -n "$LOG_FILE" ]; then echo "[$timestamp] WARNING: $message" >> "$LOG_FILE"; fi
    elif [ "$level" = "INFO" ]; then
        if [ "$LOG_LEVEL" = "INFO" ] || [ "$LOG_LEVEL" = "VERBOSE" ]; then
            echo -e "${GREEN}$message${RESET}"
            if [ -n "$LOG_FILE" ]; then echo "[$timestamp] INFO: $message" >> "$LOG_FILE"; fi
        fi
    elif [ "$level" = "VERBOSE" ]; then
        if [ "$LOG_LEVEL" = "VERBOSE" ]; then
            echo -e "${CYAN}$message${RESET}"
            if [ -n "$LOG_FILE" ]; then echo "[$timestamp] VERBOSE: $message" >> "$LOG_FILE"; fi
        fi
    fi
}

# Function to print status messages
print_status() {
    log_message "INFO" "$1"
}

# Function to print verbose messages
print_verbose() {
    log_message "VERBOSE" "$1"
}

# Function to print warnings
print_warning() {
    log_message "WARNING" "$1"
}

# Function to print errors
print_error() {
    log_message "ERROR" "$1"
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    log_message "ERROR" "This script must be run as root."
    exit 1
fi

# Load the configuration file early in the script
load_config() {
    local config_file="/home/$SUDO_USER/.stackscan.conf"
    if [ -f "$config_file" ]; then
        source "$config_file"
    else
        log_message "WARNING" "Configuration file not found."
        create_default_config
    fi
}

create_default_config() {
    cat <<EOL > /home/$SUDO_USER/.stackscan.conf
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
EOL

    log_message "INFO" "Default configuration file created at /home/$SUDO_USER/.stackscan.conf"
    sync

    if [ -f "/home/$SUDO_USER/.stackscan.conf" ]; then
        source /home/$SUDO_USER/.stackscan.conf
    else
        log_message "ERROR" "Failed to create and source the configuration file."
        exit 1
    fi
}

# Now load the configuration
load_config

TARGET="$1"

# Initialize log file based on the target and current date/time
DATE_TIME=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${TARGET}_${DATE_TIME}_scan.log"
HTML_REPORT_FILE="${TARGET}_${DATE_TIME}_scan_report.html"
NIKTO_OUTPUT_FILE="${TARGET}_${DATE_TIME}_nikto_output.txt"

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
if [ -z "$1" ]; then
    # Strip all ANSI escape codes from the banner and print to the log file
    echo -e "$banner_text" | sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" >> "$LOG_FILE"
fi
}

# Check if the user provided an argument
if [ -z "$1" ]; then
  print_banner
  echo "Usage: $0 [-v] <domain_or_ip>"
  exit 1
fi

# Check for verbose flag
if [ "$1" == "-v" ]; then
    LOG_LEVEL="VERBOSE"
    shift  # Remove the -v from the argument list
fi


# Function to validate the target domain, IPv4, or IPv6 address
# Function to validate the target domain, IPv4, or IPv6 address
validate_target() {
    local target="$1"

    # Regex for valid IPv4 address
    local ipv4_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"

    # Regex for valid IPv6 address
    local ipv6_regex="^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})$|^::([0-9a-fA-F]{1,4}:){0,6}([0-9a-fA-F]{1,4})$|^([0-9a-fA-F]{1,4}:){1,6}:([0-9a-fA-F]{1,4})$"

    # Regex for valid domain name (simple check)
    local domain_regex="^([a-zA-Z0-9](-*[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$"

    # Check if the target is a valid IPv4 address
    if [[ $target =~ $ipv4_regex ]]; then
        TARGET_TYPE="IPv4"
    # Check if the target is a valid IPv6 address
    elif [[ $target =~ $ipv6_regex ]]; then
        TARGET_TYPE="IPv6"
    # Check if the target is a valid domain name
    elif [[ $target =~ $domain_regex ]]; then
        TARGET_TYPE="DOMAIN"
    else
        print_error "Invalid target: $target. Please provide a valid domain name, IPv4, or IPv6 address."
        exit 1
    fi
}

# Validate the target input
validate_target "$TARGET"


# Check required commands
check_required_commands() {
    local cmds=("nmap" "dig" "ping6" "jq" "curl" "nikto" "wapiti")
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            print_error "$cmd could not be found. Please install it and try again."
            exit 1
        fi
    done
}

check_ipv6_support() {
    local target="$1"

    # Only check IPv6 support for domain names or IPv6 addresses
    if [ "$TARGET_TYPE" = "IPv6" ] || [ "$TARGET_TYPE" = "DOMAIN" ]; then
        if ping6 -c 1 -W 1 "$target" &> /dev/null; then
            IPV6_SUPPORTED=true
            log_message "INFO" "IPv6 is supported and reachable for $target."
        else
            IPV6_SUPPORTED=false
            log_message "INFO" "IPv6 is not supported or not reachable for $target."
        fi
    else
        IPV6_SUPPORTED=false
        log_message "INFO" "IPv6 check skipped as the target is an IPv4 address."
    fi
}


# Check if the local machine supports IPv6
check_ipv6_support

# Check required commands
check_required_commands



# Print the banner
print_banner
log_message "INFO" "Scan Date: $(date)"

# If -v parameter is provided, print message to console else print current log level
if [ "$LOG_LEVEL" = "VERBOSE" ]; then
    log_message "VERBOSE" "Verbose mode enabled. Detailed logs will be printed."
else
    log_message "WARNING" "Verbose mode disabled. Only important logs will be printed."
fi

# Spinner function
spinner() {
    local delay=0.1
    local spinstr='|/-\'
    local scan_name="$1"
    local start_time=$(date +%s)  # Capture the start time

    while kill -0 $! 2>/dev/null; do
        # Calculate elapsed time
        local current_time=$(date +%s)
        local elapsed_time=$((current_time - start_time))

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
        local spinner_length=${#spinner_str}
        local padding=$((terminal_width - spinner_length))

        # Display the right-justified spinner
        printf "%*s\r" "$terminal_width" "$spinner_str"
        sleep $delay
    done
    printf "    \r"  # Clear spinner after process is done
}


# Function to execute Nmap with scripts and their arguments
run_nmap_with_scripts() {
    local scripts=("$1")
    local script_args=("$2")
    local ports="$3"
    local target="$4"

    # Initialize the base Nmap command
    nmap_command="nmap -Pn -sC -A"

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
            nmap_command+=" --script $script --script-args $args"
        else
            nmap_command+=" --script $script"
        fi
    done

    # Execute the Nmap command if scripts are provided
    if [ -n "$nmap_command" ]; then
        $nmap_command -p $ports $target > /dev/null 2>&1
    fi
}


# Function to run a group scan
run_scan_group() {
    local group_name="$1"
    local group_scripts=($2)  # Convert to array
    local group_script_args=($3)  # Convert to array
    local group_ports="$4"
    local ip_version="$5"
    local target_ip="$6"

    local output_file="${TARGET}_${group_name}_${ip_version}_scan_output.txt"
    local nmap_options="$NMAP_OPTIONS"

    if [ "$ip_version" == "IPv6" ]; then
        nmap_options="$nmap_options -6"
    fi

    print_status "Starting $group_name scan on $target_ip ($ip_version)..."

    # Loop through each script and its arguments
    for i in "${!group_scripts[@]}"; do
        script="${group_scripts[$i]}"
        script_args="${group_script_args[$i]}"

        # Construct the Nmap command
        nmap_command="nmap $nmap_options --script \"$script\""

        if [ -n "$script_args" ]; then
            nmap_command+=" --script-args=\"$script_args\""
        fi

        nmap_command+=" -p \"$group_ports\" \"$target_ip\" --min-rate=100 --randomize-hosts -oN \"$output_file\" -vv"

        # Execute the Nmap command
        eval $nmap_command > /dev/null 2>&1 &
        spinner "Nmap $group_name scan"
        print_verbose "Nmap command executed for $group_name ($ip_version): $nmap_command" >/dev/null 2>&1
    done
}

# Execute scans in parallel for IPv4 and IPv6
run_scans() {
    local ip_version="$1"
    local target_ip="$2"

    # Run predefined scan groups
    run_scan_group "web" "$WEB_NMAP_SCRIPTS" "$WEB_NMAP_SCRIPT_ARGS" "$WEB_PORTS" "$ip_version" "$target_ip" &
    run_scan_group "auth" "$AUTH_NMAP_SCRIPTS" "$AUTH_NMAP_SCRIPT_ARGS" "$AUTH_PORTS" "$ip_version" "$target_ip" &
    run_scan_group "database" "$DATABASE_NMAP_SCRIPTS" "$DATABASE_NMAP_SCRIPT_ARGS" "$DATABASE_PORTS" "$ip_version" "$target_ip" &
    run_scan_group "common" "$COMMON_NMAP_SCRIPTS" "$COMMON_NMAP_SCRIPT_ARGS" "$COMMON_PORTS" "$ip_version" "$target_ip" &
    run_scan_group "vuln" "$VULN_NMAP_SCRIPTS" "$VULN_NMAP_SCRIPT_ARGS" "$VULN_PORTS" "$ip_version" "$target_ip" &

    # Run the custom group if defined
    if [ -n "${CUSTOM_NMAP_SCRIPTS[0]}" ]; then
        if ! nmap --script-help="${CUSTOM_NMAP_SCRIPTS[0]}" > /dev/null 2>&1; then
            print_warning "Custom scripts not found or invalid: ${CUSTOM_NMAP_SCRIPTS[0]}"
        else
            run_scan_group "custom" "$CUSTOM_NMAP_SCRIPTS" "$CUSTOM_NMAP_SCRIPT_ARGS" "$CUSTOM_PORTS" "$ip_version" "$target_ip" &
        fi
    fi
}

# Run for IPv4
run_scans "IPv4" "$TARGET"

# Run for IPv6 only if supported and the target is not an IPv4 address
if [ "$IPV6_SUPPORTED" = true ] && [ "$TARGET_TYPE" != "IPv4" ]; then
    run_scans "IPv6" "$TARGET"
fi

# Wait for all nmap scans to finish so that we can extract the web server port numbers
wait

# Extract and clean port numbers
extract_web_servers() {
    local ipv4_file="${TARGET}_web_IPv4_scan_output.txt"
    local ipv6_file="${TARGET}_web_IPv6_scan_output.txt"

    if [ -f "$ipv4_file" ]; then
        awk '
        /^[0-9]{1,5}\/tcp/ {
            if ($0 ~ /http|https|nginx|apache/) {
                split($1, a, "/")
                print a[1]
            }
        }' "$ipv4_file"
    fi

    if [ -f "$ipv6_file" ]; then
        awk '
        /^[0-9]{1,5}\/tcp/ {
            if ($0 ~ /http|https|nginx|apache/) {
                split($1, a, "/")
                print a[1]
            }
        }' "$ipv6_file"
    fi

    if [ ! -f "$ipv4_file" ] && [ ! -f "$ipv6_file" ]; then
        echo "Error: Neither web scan file found for IPv4 or IPv6."
        return 1
    fi
}

print_extracted_web_servers() {
    local web_servers
    web_servers=$(extract_web_servers)

    log_message "INFO" "Potential Web Servers detected on following ports:"
    log_message "INFO" "--------------------------------"

    # Print each extracted web server line
    while IFS= read -r line; do
        echo "$line"
    done <<< "$web_servers"

    log_message "INFO" "--------------------------------"
}

# Call the function to print the extracted web servers
#print_extracted_web_servers

run_wapiti_scan() {
    local target_ip="$1"
    shift  # Shift the arguments to get only ports
    local ports=("$@")  # Capture all ports into an array
    local wapiti_pids=()  # Array to hold the PIDs of background Wapiti processes

    for port in "${ports[@]}"; do
        local url="http://$target_ip:$port"  # Assume HTTP by default
        if [[ "$port" == "443" || "$port" == "8443" ]]; then
            url="https://$target_ip:$port"  # Use HTTPS for common secure ports
        fi

        print_status "Starting Wapiti scan on $url..."
        local output_file="${target_ip}_${port}_wapiti_output.txt"
        wapiti -u "$url" $WAPITI_OPTIONS -f txt -o "$output_file" > /dev/null 2>&1 &
        wapiti_pids+=($!)  # Capture the PID of the Wapiti process

        # Start the spinner for this Wapiti process
        (spinner "Wapiti on Port $port") &
        print_verbose "Wapiti command executed for $url: wapiti -u $url $WAPITI_OPTIONS -f txt -o $output_file" >/dev/null 2>&1
    done

    # Wait for all Wapiti processes to complete
    for pid in "${wapiti_pids[@]}"; do
        wait $pid
    done

    # Check if Wapiti has not run properly due to no web server
    for port in "${ports[@]}"; do
        local output_file="${target_ip}_${port}_wapiti_output.txt"
        if [ -f "$output_file" ]; then
            if grep -q "Cannot establish connection" "$output_file"; then
                print_status "No web server found on $target_ip:$port, Wapiti scan did not run."
                echo "No web server found on $target_ip:$port" > "$output_file"
            fi
        fi
    done
}

# Run Nikto scan on extracted ports in parallel
run_nikto_scan() {
    local target_ip="$1"
    shift  # Shift the arguments to get only ports
    local ports=("$@")  # Capture all ports into an array
    local nikto_pids=()  # Array to hold the PIDs of background Nikto processes

    for port in "${ports[@]}"; do
        print_status "Starting Nikto scan on $target_ip:$port..."

        # Run Nikto in the background and immediately capture the PID
        nikto -h "$target_ip" -p "$port" $NIKTO_OPTIONS -output "${target_ip}_${port}_nikto_output.txt" > /dev/null 2>&1 &
        nikto_pids+=($!)  # Store the PID for later waiting

        # Start the spinner in the background
        (spinner "Nikto on Port $port") &
        print_verbose "Nikto command executed for $target_ip:$port: nikto -h $target_ip -p $port $NIKTO_OPTIONS -output ${target_ip}_${port}_nikto_output.txt" >/dev/null 2>&1
    done

    # Wait for all Nikto processes to complete
    for pid in "${nikto_pids[@]}"; do
        wait $pid  # Ensure that the script waits for each Nikto process
    done
}

ports=$(extract_web_servers)
# Run Wapiti and Nikto scans concurrently
run_wapiti_scan "$TARGET" $ports &
wapiti_pid=$!

run_nikto_scan "$TARGET" $ports &
nikto_pid=$!

# Wait for both Wapiti and Nikto to complete
wait $wapiti_pid
wait $nikto_pid

# Merge results
FINAL_OUTPUT_FILE="${TARGET}_${DATE_TIME}_final_scan_output.txt"
cat *_scan_output.txt > "$FINAL_OUTPUT_FILE"

# Print final status messages
print_status "Nmap and Nikto scanning complete for $TARGET."
log_message "INFO" "Log saved to: $LOG_FILE"

# Function to generate an HTML report with advanced features
function lookup_cve_details() {
    local cve_id="$1"
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cve/1.0/$cve_id"

    # Fetch CVE details from NVD
    local cve_details
    cve_details=$(curl -s "$nvd_api_url" | jq '.result.CVE_Items[0].cve')

    # Check if we got a valid response
    if [[ -z "$cve_details" || "$cve_details" == "null" ]]; then
        print_warning "CVE details for $cve_id could not be retrieved."
        echo "N/A,N/A"
        return
    fi

    # Extract relevant information from the JSON response
    local cve_description
    cve_description=$(echo "$cve_details" | jq -r '.description.description_data[0].value')
    #local cve_published_date
    #cve_published_date=$(echo "$cve_details" | jq -r '.publishedDate')
    local cve_impact_score
    cve_impact_score=$(echo "$cve_details" | jq -r '.impact.baseMetricV2.cvssV2.baseScore // "N/A"')

    # Return severity and CVSS score
    echo "$cve_description,$cve_impact_score"
}

# Function to lookup CVEs based on service version
lookup_cve_by_service_version() {
    local service_name="$1"
    local version="$2"
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=$service_name+$version"

    # Fetch CVE details from NVD with proper headers
    local cve_details
    cve_details=$(curl -s -H "User-Agent: YourScriptName/1.0" "$nvd_api_url")

    # Debugging: Print the raw API response
    echo "API Response for $service_name $version: $cve_details" >> "$LOG_FILE"

    # Check if the response is valid JSON
    if ! echo "$cve_details" | jq empty; then
        print_warning "Invalid JSON received from NVD API for $service_name $version."
        return
    fi

    # Parse the CVE details from the response
    local cve_list
    cve_list=$(echo "$cve_details" | jq -r '.result.CVE_Items[] | .cve.CVE_data_meta.ID + " - " + .cve.description.description_data[0].value + " (CVSS Score: " + (.impact.baseMetricV2.cvssV2.baseScore | tostring) + ")"')

    if [ -z "$cve_list" ]; then
        echo "No CVEs found for $service_name $version."
    else
        echo "$cve_list"
    fi
}

generate_html_report() {
    print_status "Generating HTML report..."
        echo "<html><head><title>Scan Report for $TARGET</title>" > "$HTML_REPORT_FILE"
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

    # Iterate over scan groups and IP versions
    for ip_version in IPv4 IPv6; do
        for group_name in web auth database common vuln; do
            local output_file="${TARGET}_${group_name}_${ip_version}_scan_output.txt"
            if [ -f "$output_file" ]; then
                echo "<div class=\"scan-section\"><h2>${group_name^} Scan Results ($ip_version)</h2><pre>" >> "$HTML_REPORT_FILE"
                cat "$output_file" >> "$HTML_REPORT_FILE"
                echo "</pre></div>" >> "$HTML_REPORT_FILE"
            fi
        done
    done

    # Wapiti Scan Results
    echo "<div class=\"scan-section\"><h2>Wapiti Scan Results</h2><pre>" >> "$HTML_REPORT_FILE"
    wapiti_found=false
    for wapiti_file in ${TARGET}_*_wapiti_output.txt; do
        if [ -f "$wapiti_file" ] && [ -s "$wapiti_file" ]; then
            if grep -q "No web server found" "$wapiti_file"; then
                echo "$(cat "$wapiti_file")" >> "$HTML_REPORT_FILE"
            else
                cat "$wapiti_file" >> "$HTML_REPORT_FILE"
            fi
            echo -e "\n" >> "$HTML_REPORT_FILE"
            wapiti_found=true
        fi
    done
    if [ "$wapiti_found" = false ]; then
        echo "No Wapiti results found." >> "$HTML_REPORT_FILE"
    fi
    echo "</pre></div>" >> "$HTML_REPORT_FILE"


   # Nikto Scan Results
       echo "<div class=\"scan-section\"><h2>Nikto Scan Results</h2><pre>" >> "$HTML_REPORT_FILE"
       nikto_found=false
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

    # Detailed Vulnerability Information
    echo "<div class=\"scan-section\"><h2>Detailed Vulnerability Information</h2>" >> "$HTML_REPORT_FILE"

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
                    local cve_info=$(lookup_cve_details "$cve_id")
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

    echo "</body></html>" >> "$HTML_REPORT_FILE"

    log_message "INFO" "HTML Report saved to: $HTML_REPORT_FILE"
}

scan_end_time=$(date +%s)
scan_duration=$((scan_end_time - scan_start_time))
formatted_scan_duration=$(printf "%02d:%02d:%02d" $((scan_duration/3600)) $((scan_duration%3600/60)) $((scan_duration%60)))

# Generate HTML report if enabled
if [ "$GENERATE_HTML_REPORT" = "true" ]; then
    generate_html_report
fi

# Ensure all created files are owned by the user running the script
if [ -n "$SUDO_USER" ]; then
    chown $SUDO_USER:$SUDO_USER "$LOG_FILE" "$HTML_REPORT_FILE"
fi

# Print total scan duration
log_message "INFO" "Total scan time: $formatted_scan_duration"

# Clean up the temporary files
rm -f *_output.txt

# Open the HTML report in the default browser as the non-root user
if [ "$GENERATE_HTML_REPORT" = "true" ]; then
    if command -v xdg-open &> /dev/null; then
        export DISPLAY=:0
        export XDG_RUNTIME_DIR="/tmp/runtime-$SUDO_USER"
        sudo -u "$SUDO_USER" xdg-open "$HTML_REPORT_FILE" > /dev/null 2>&1
    elif command -v open &> /dev/null; then
        sudo -u "$SUDO_USER" open "$HTML_REPORT_FILE" > /dev/null 2>&1
    fi
fi

exit 0