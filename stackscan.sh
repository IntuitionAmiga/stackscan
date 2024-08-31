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
    rm -f ./*_output.txt
    exit "$exit_code"
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
VULN_NMAP_OPTIONS="-sS -A" # Aggressive scan with OS detection
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
LOG_LEVEL="INFO"  # Change this to "VERBOSE" for more detailed logs

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

# Now load the configuration
load_config

TARGET="$1"

# Initialize log file based on the target and current date/time
DATE_TIME=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${TARGET}_${DATE_TIME}_scan.log"
HTML_REPORT_FILE="${TARGET}_${DATE_TIME}_scan_report.html"

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
validate_target() {
    # Regex for valid domain name (simple check)
    local domain_regex="^([a-zA-Z0-9](-*[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$"

    # Regex for valid IPv4 address
    local ipv4_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"

    # Regex for valid IPv6 address (including shorter notations)
    local ipv6_regex="^(([0-9a-fA-F]{1,4}:){1,7}([0-9a-fA-F]{1,4})?|::([0-9a-fA-F]{1,4}:){0,7}([0-9a-fA-F]{1,4})?)$"

    # Check if the target is a valid IPv4 address
    if [[ $TARGET =~ $ipv4_regex ]]; then
        TARGET_TYPE="IPv4"
    # Check if the target is a valid IPv6 address
    elif [[ $TARGET =~ $ipv6_regex ]]; then
        TARGET_TYPE="IPv6"
    # Check if the target is a valid domain name
    elif [[ $TARGET =~ $domain_regex ]]; then
        TARGET_TYPE="DOMAIN"
    else
        print_banner
        print_error "Invalid target: $TARGET. Please provide a valid domain name, IPv4, or IPv6 address."
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

# If -v parameter is provided, print message to console else print current log level
if [ "$LOG_LEVEL" = "VERBOSE" ]; then
    log_message "VERBOSE" "$(date '+[%Y-%m-%d %H:%M:%S]') Verbose mode enabled. Detailed logs will be printed."
else
    log_message "WARNING" "$(date '+[%Y-%m-%d %H:%M:%S]') Verbose mode disabled. Only important logs will be printed."
fi

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
    expanded_scripts=($(find /usr/share/nmap/scripts/ -name "${script_pattern}.nse" -exec basename {} .nse \;))

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
            eval $individual_nmap_command >> "$output_file" 2>&1

            # Add a dividing line after each command's output
            echo " " >> "$output_file"
            echo "------------------------------------------------------------------" >> "$output_file"
            echo " " >> "$output_file"

            (spinner "Nmap $group_name scan - Script: $expanded_script") &
            print_verbose "Nmap command executed for $group_name ($ip_version), Script: $expanded_script: $individual_nmap_command" >/dev/null 2>&1
        done

    done
    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Nmap $group_name scan on $target_ip ($ip_version) completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') Nmap $group_name scan on $target_ip ($ip_version) completed." >>/dev/null 2>&1
}
# Function to execute scans in parallel for IPv4 and IPv6
run_scans() {
    local ip_version="$1"
    local target_ip="$2"

    # Run predefined scan groups and capture the PID for the web scan group
    run_scan_group "web" WEB_NMAP_SCRIPTS[@] WEB_NMAP_SCRIPT_ARGS[@] "$WEB_PORTS" "$ip_version" "$target_ip" &
    web_scan_pid=$!

    # Run other scan groups in the background (no need to capture these PIDs for now)
    run_scan_group "auth" AUTH_NMAP_SCRIPTS[@] AUTH_NMAP_SCRIPT_ARGS[@] "$AUTH_PORTS" "$ip_version" "$target_ip" &

    run_scan_group "database" DATABASE_NMAP_SCRIPTS[@] DATABASE_NMAP_SCRIPT_ARGS[@] "$DATABASE_PORTS" "$ip_version" "$target_ip" &
    database_scan_pid=$!

    run_scan_group "common" COMMON_NMAP_SCRIPTS[@] COMMON_NMAP_SCRIPT_ARGS[@] "$COMMON_PORTS" "$ip_version" "$target_ip" &
    run_scan_group "vuln" VULN_NMAP_SCRIPTS[@] VULN_NMAP_SCRIPT_ARGS[@] "$VULN_PORTS" "$ip_version" "$target_ip" &

    # Run the custom group if defined
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

    while [ $retry_count -lt $max_retries ]; do
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
        wait $web_scan_pid_v4
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
        local output_file="${target_ip}_${port}_wapiti_output.txt"
        # Log the exact Wapiti command being executed
        print_verbose "Executing Wapiti command: wapiti -u \"$url\" $WAPITI_OPTIONS -f txt -o \"$output_file\"" >>/dev/null 2>&1

        (wapiti -u "$url" $WAPITI_OPTIONS -f txt -o "$output_file" > "${output_file}_log.txt" 2>&1) &

        wapiti_pid=$!  # Capture the PID of the Wapiti process
        wapiti_pids+=($wapiti_pid)

        wapiti_scanned_ports[$port]=1  # Mark this port as scanned

        # Increment the counter
        ((wapiti_scan_count++))

        # Start the spinner for this Wapiti process
        (spinner "Wapiti on Port $port") &
        spinner_pid=$!

        # Wait for Wapiti to complete and kill the spinner
        wait $wapiti_pid || true
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

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Wapiti scan on $target_ip:$port completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') Wapiti scan on $target_ip:$port completed." >>/dev/null 2>&1
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
        print_verbose "Nikto command executed for $target_ip:$port: nikto -h $target_ip -p $port $NIKTO_OPTIONS -output ${output_file}" >/dev/null 2>&1

        # Run Nikto in the background and immediately capture the PID
        (nikto -h "$target_ip" -p "$port" $NIKTO_OPTIONS -output "$output_file" > "${output_file}_log.txt" 2>&1) &

        # Add dividing line after each scan's output
        echo " " >> "$output_file"
        echo "------------------------------------------------------------------" >> "$output_file"
        echo " " >> "$output_file"
        local nikto_pid=$!  # Store the PID for this particular Nikto process
        nikto_pids+=($nikto_pid)  # Append the PID to the array

        nikto_scanned_ports[$port]=1  # Mark this port as scanned

        # Increment the scan count
        ((nikto_scan_count++))

        # Start the spinner for this Nikto process
        (spinner "Nikto on Port $port") &
        local spinner_pid=$!

        # Wait for Nikto to complete and kill the spinner
        wait $nikto_pid || true
        kill $spinner_pid 2>/dev/null

        print_verbose "Nikto command executed for $target_ip:$port: nikto -h $target_ip -p $port $NIKTO_OPTIONS -output ${target_ip}_${port}_nikto_output.txt" >/dev/null 2>&1
    done

    # Wait for all Nikto processes to complete
    for pid in "${nikto_pids[@]}"; do
        wait $pid
    done

    # Store the number of Nikto scans
    echo "$nikto_scan_count" > /tmp/nikto_scan_count.txt

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Nikto scan on $target_ip:$port completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') Nikto scan on $target_ip:$port completed." >>/dev/null 2>&1
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
        print_verbose "WPScan command executed for $url: wpscan $WPSCAN_OPTIONS --url $url > $output_file" >/dev/null 2>&1

        (sudo -u "$SUDO_USER" wpscan $WPSCAN_OPTIONS --url "$url" > "$output_file" 2>&1) &
        wpscan_pid=$!  # Capture the PID of the WPScan process
        wpscan_pids+=($wpscan_pid)

        wpscan_scanned_ports[$port]=1  # Mark this port as scanned

        # Increment the counter
        ((wpscan_scan_count++))

        # Start the spinner for this WPScan process
        (spinner "WPScan on Port $port") &
        spinner_pid=$!

        # Wait for WPScan to complete and kill the spinner
        wait $wpscan_pid || true
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

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') WPScan scan on $target_ip:$port completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') WPScan scan on $target_ip:$port completed." >>/dev/null 2>&1
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
        print_verbose "SQLMap command executed for $url: sqlmap $SQLMAP_OPTIONS -u \"$url\" > $output_file" >/dev/null 2>&1

        (sudo -u "$SUDO_USER" sqlmap $SQLMAP_OPTIONS -u "$url" > "$output_file" 2>&1) &
        sqlmap_pid=$!  # Capture the PID of the SQLMap process
        sqlmap_pids+=($sqlmap_pid)

        sqlmap_scanned_ports[$port]=1  # Mark this port as scanned

        # Increment the counter
        ((sqlmap_scan_count++))

        # Start the spinner for this SQLMap process
        (spinner "SQLMap on Port $port") &
        spinner_pid=$!

        # Wait for SQLMap to complete and kill the spinner
        wait $sqlmap_pid || true
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

    print_status "$(date '+[%Y-%m-%d %H:%M:%S]') SQLMap scan on $target_ip:$port completed."
    print_verbose "$(date '+[%Y-%m-%d %H:%M:%S]') SQLMap scan on $target_ip:$port completed." >>/dev/null 2>&1
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

# Run for IPv4 and capture the web and database scan PIDs
run_scans "IPv4" "$TARGET"
web_scan_pid_v4=$web_scan_pid
database_scan_pid_v4=$database_scan_pid

# Run for IPv6 only if supported and the target is not an IPv4 address, capture the web scan PID
if [ "$IPV6_SUPPORTED" = true ] && [ "$TARGET_TYPE" != "IPv4" ]; then
    run_scans "IPv6" "$TARGET"
    web_scan_pid_v6=$web_scan_pid
fi

# Wait for the web-related Nmap scans to finish so that we can extract the web server port numbers
wait $web_scan_pid_v4
if [ -n "$web_scan_pid_v6" ]; then
    wait $web_scan_pid_v6
fi

# Extract any open web server ports and scan them with Wapiti and Nikto
# Initialize associative array
declare -A unique_ports
for port in $open_ports; do
    unique_ports["$port"]=1
done

# Convert deduped associative array back to a list
open_ports="${!unique_ports[@]}"


# Initialize arrays to hold PIDs
wapiti_pids=()
nikto_pids=()
wpscan_pids=()
sqlmap_pids=()

# If no open ports found, skip all scans
if [ -n "$open_ports" ]; then
    # Run Wapiti scans in parallel
    run_wapiti_scan "$TARGET" $open_ports &
    wapiti_pids+=($!)  # Append the PID of the Wapiti process to the array

    # Run Nikto scans in parallel
    run_nikto_scan "$TARGET" $open_ports &
    nikto_pids+=($!)  # Append the PID of the Nikto process to the array

    # Wait for the database-related Nmap scans to finish
    wait $database_scan_pid_v4
    if [ -n "$database_scan_pid_v6" ]; then
        wait $database_scan_pid_v6
    fi

    # Detect services after database scan
    services_detection=$(detect_services "$TARGET")
    wp_detected=$(echo "$services_detection" | awk '{print $1}')
    sql_detected=$(echo "$services_detection" | awk '{print $2}')

    # Run WPScan only if WordPress was detected
    if [ "$wp_detected" = "true" ]; then
        run_wpscan_scan "$TARGET" $open_ports &
        wpscan_pids+=($!)  # Append the PID of the WPScan process to the array
    fi

    # Run SQLMap only if an SQL database was detected
    if [ "$sql_detected" = true ]; then
        run_sqlmap_scan "$TARGET" $open_ports &
        sqlmap_pids+=($!)  # Append the PID of the SQLMap process to the array
    fi
fi

# Wait for all Wapiti processes to complete
for pid in "${wapiti_pids[@]}"; do
    wait $pid || true
done

# Wait for all Nikto processes to complete
for pid in "${nikto_pids[@]}"; do
    wait $pid || true
done

# Wait for all WPScan processes to complete
for pid in "${wpscan_pids[@]}"; do
    wait $pid || true
done

# Wait for all SQLMap processes to complete
for pid in "${sqlmap_pids[@]}"; do
    wait $pid || true
done

# Wait for other background processes if any
wait $nmap_pid

# Merge results
FINAL_OUTPUT_FILE="${TARGET}_${DATE_TIME}_final_scan_output.txt"
cat ./*_scan_output.txt > "$FINAL_OUTPUT_FILE"

# Print final status messages
print_status "$(date '+[%Y-%m-%d %H:%M:%S]') Scanning complete for $TARGET."
log_message "INFO" "$(date '+[%Y-%m-%d %H:%M:%S]') Log saved to: $LOG_FILE"

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
    cve_details=$(curl -s -H "User-Agent: Stackscan/0.1" "$nvd_api_url")

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
    for wapiti_file in ${TARGET}_*_wapiti_output.txt; do
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

    echo "</body></html>" >> "$HTML_REPORT_FILE"

    log_message "INFO" "$(date '+[%Y-%m-%d %H:%M:%S]') HTML Report saved to: $HTML_REPORT_FILE"
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
    chown "$SUDO_USER":"$SUDO_USER" "$LOG_FILE" "$HTML_REPORT_FILE"
fi

#wait for any background jobs to finish
(spinner "Waiting for background jobs to finish...") &
wait
sync &

# Print total scan duration
log_message "INFO" "$(date '+[%Y-%m-%d %H:%M:%S]') Total execution time: $formatted_scan_duration"

# Clean up the temporary files
rm -f ./*_output.txt &

# Open the HTML report in the default browser as the non-root user
# We have to do this because KDE 6.1 borked xdg-open
if [ "$GENERATE_HTML_REPORT" = "true" ]; then
        sudo -u "$SUDO_USER" x-www-browser "$HTML_REPORT_FILE" > /dev/null 2>&1 &
fi

exit 0