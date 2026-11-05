#!/bin/bash

# Enhanced script to install Sysmon on Amazon Linux 2, Amazon Linux 2023, and Ubuntu.
# This script must be run with root or sudo privileges.

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# --- Variables ---
# Sysmon directories and files
SYSMON_DIR="/opt/sysmon"
SYSMON_CONFIG_FILE="$SYSMON_DIR/yt-sysmon-linux.xml"

# Accept config file as first argument (overrides default)
if [ -n "${1:-}" ]; then
  SYSMON_CONFIG_FILE="$1"
fi

# Log file for installation
LOG_FILE="/var/log/sysmon_install.log"

# Sysmon log file path
SYSMON_LOG_FILE="/var/log/sysmon.log"

# --- Logging function ---sy
log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log_error() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $*" | tee -a "$LOG_FILE" >&2
}

# --- Function to detect OS type ---
get_os_type() {
  if [ -f "/etc/os-release" ]; then
    . /etc/os-release
    if [[ "$ID" == "amzn" ]]; then
      VERSION_ID=$(grep -oP '(?<=VERSION_ID=")[^"]*' /etc/os-release 2>/dev/null || echo "")
      if [ "$VERSION_ID" == "2" ]; then
        echo "amazon-2"
      elif [ "$VERSION_ID" == "2023" ]; then
        echo "amazon-2023"
      else
        echo "unsupported"
      fi
    elif [[ "$ID" == "ubuntu" ]]; then
      echo "ubuntu"
    elif [[ "$ID" == "centos" ]]; then
      VERSION_ID=$(grep -oP '(?<=VERSION_ID=")[^"]*' /etc/os-release 2>/dev/null || echo "")
      if [[ "$VERSION_ID" == "7"* ]]; then
        echo "centos-7"
      else
        echo "centos-other"
      fi
    else
      echo "unsupported"
    fi
  else
    echo "unsupported"
  fi
}

# --- Function to check if Sysmon is already installed ---
check_existing_installation() {
  if command -v sysmon &> /dev/null; then
    log "Sysmon is already installed. Checking version..."
    sysmon -v || true
    return 0
  fi
  return 1
}

# --- Function to remove existing Sysmon ---
remove_existing_sysmon() {
  log "Removing existing Sysmon installation..."
  case "$OS_TYPE" in
    amazon-2|centos-7)
      yum remove -y sysmonforlinux || log "No existing Sysmon package to remove"
      ;;
    amazon-2023|centos-other)
      dnf remove -y sysmonforlinux || log "No existing Sysmon package to remove"
      ;;
    ubuntu)
      apt-get remove -y sysmonforlinux || log "No existing Sysmon package to remove"
      ;;
  esac
}

# --- Function to create Sysmon directory and config ---
create_sysmon_config() {
  log "Creating Sysmon directory and configuration..."
  
  # Create directory if it doesn't exist
  if [ ! -d "$SYSMON_DIR" ]; then
    mkdir -p "$SYSMON_DIR"
    log "Created directory: $SYSMON_DIR"
  else
    log "Directory already exists: $SYSMON_DIR"
  fi
  
  # Create default config file
  cat > "$SYSMON_DIR/yt-sysmon-linux.xml" << 'EOF'
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <!-- Event ID 1 == ProcessCreate. Log all newly created processes -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 3 == NetworkConnect Detected. Log all network connections -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 5 == ProcessTerminate. Log all processes terminated -->
    <RuleGroup name="" groupRelation="or">
      <ProcessTerminate onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 9 == RawAccessRead. Log all raw access read -->
    <RuleGroup name="" groupRelation="or">
      <RawAccessRead onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 10 == ProcessAccess. Log all open process operations -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="exclude"/>
    </RuleGroup>
    <!-- Event ID 11 == FileCreate. Log every file creation -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="exclude"/>
    </RuleGroup>
    <!--Event ID 23 == FileDelete. Log all files being deleted -->
    <RuleGroup name="" groupRelation="or">
      <FileDelete onmatch="exclude"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
EOF

  log "Created Sysmon configuration file: $SYSMON_DIR/yt-sysmon-linux.xml"
  log "Configuration captures all events (onmatch=exclude with no conditions)"
}

# --- Function to validate config file ---
validate_config_file() {
  if [ -n "$SYSMON_CONFIG_FILE" ]; then
    if [[ "$SYSMON_CONFIG_FILE" =~ ^https?:// ]]; then
      log "Config file is a URL: $SYSMON_CONFIG_FILE"
      # Test if URL is accessible
      if ! wget --spider -q "$SYSMON_CONFIG_FILE" 2>/dev/null; then
        log_error "Unable to access config file URL: $SYSMON_CONFIG_FILE"
        return 1
      fi
    elif [ -f "$SYSMON_CONFIG_FILE" ]; then
      log "Config file found locally: $SYSMON_CONFIG_FILE"
    else
      log_error "Config file not found: $SYSMON_CONFIG_FILE"
      return 1
    fi
  fi
  return 0
}

# --- Function to configure rsyslog for Sysmon ---
configure_rsyslog() {
  log "Configuring rsyslog for Sysmon..."
  
  RSYSLOG_CONF="/etc/rsyslog.d/yt-sysmon-log.conf"
  
  cat > "$RSYSLOG_CONF" << 'EOF'
# Sysmon for Linux rsyslog configuration
if $msg contains "Linux-Sysmon" then /var/log/sysmon.log
& stop
EOF

  log "Created rsyslog configuration: $RSYSLOG_CONF"
  
  # Restart rsyslog service
  log "Restarting rsyslog service..."
  if systemctl restart rsyslog 2>&1 | tee -a "$LOG_FILE"; then
    log "Rsyslog service restarted successfully"
  else
    log_error "Failed to restart rsyslog service"
    return 1
  fi
  
  # Verify rsyslog is running
  if systemctl is-active --quiet rsyslog; then
    log "Rsyslog service is active and running"
  else
    log_error "Rsyslog service is not running"
    return 1
  fi
}

# --- Function to install on CentOS 7 ---
install_centos7() {
  log "Installing prerequisites for CentOS 7..."
  
  #yum install -y make cmake elfutils-libelf-devel gcc git wget rsyslog 2>&1 | tee -a "$LOG_FILE"

  # Add Microsoft GPG key and repo
  log "Importing Microsoft GPG key..."
  rpm --import https://packages.microsoft.com/keys/microsoft.asc 2>&1 | tee -a "$LOG_FILE"

  log "Adding Microsoft repository..."
  wget -q -O /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/rhel/7/packages-microsoft-prod.repo

  # Update package list and install Sysmon
  log "Installing sysmonforlinux package..."
  #yum update -y 2>&1 | tee -a "$LOG_FILE"
  yum install -y sysmonforlinux 2>&1 | tee -a "$LOG_FILE"
}

# --- Function to install on Amazon Linux ---
install_amazon_linux() {
  log "Installing prerequisites for Amazon Linux $AMAZON_LINUX_VERSION..."
  
  if [ "$AMAZON_LINUX_VERSION" == "2" ]; then
    yum install -y make cmake elfutils-libelf-devel gcc git wget rsyslog 2>&1 | tee -a "$LOG_FILE"
  else
    dnf install -y make cmake elfutils-libelf-devel gcc git wget rsyslog 2>&1 | tee -a "$LOG_FILE"
  fi

  # Add Microsoft GPG key and repo
  log "Importing Microsoft GPG key..."
  rpm --import https://packages.microsoft.com/keys/microsoft.asc 2>&1 | tee -a "$LOG_FILE"

  log "Adding Microsoft repository..."
  if [ "$AMAZON_LINUX_VERSION" == "2" ]; then
    wget -q -O /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/rhel/7/prod.repo
  else
    wget -q -O /etc/yum.repos.d/microsoft-prod.repo https://packages.microsoft.com/config/rhel/9.0/prod.repo
  fi

  # Update package list and install Sysmon
  log "Installing sysmonforlinux package..."
  if [ "$AMAZON_LINUX_VERSION" == "2" ]; then
    yum update -y 2>&1 | tee -a "$LOG_FILE"
    yum install -y sysmonforlinux 2>&1 | tee -a "$LOG_FILE"
  else
    dnf update -y 2>&1 | tee -a "$LOG_FILE"
    dnf install -y sysmonforlinux 2>&1 | tee -a "$LOG_FILE"
  fi
}

# --- Function to install on Ubuntu ---
install_ubuntu() {
  log "Installing prerequisites for Ubuntu..."
  
  # Install rsyslog if not present
  apt-get install -y rsyslog wget 2>&1 | tee -a "$LOG_FILE"
  
  log "Downloading Microsoft package repository..."
  UBUNTU_VERSION=$(lsb_release -rs)
  wget -q https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/packages-microsoft-prod.deb -O packages-microsoft-prod.deb 2>&1 | tee -a "$LOG_FILE"
  
  log "Installing Microsoft package repository..."
  dpkg -i packages-microsoft-prod.deb 2>&1 | tee -a "$LOG_FILE"
  
  log "Updating package list..."
  apt-get update 2>&1 | tee -a "$LOG_FILE"
  
  log "Installing Sysmon for Linux..."
  apt-get install -y sysmonforlinux 2>&1 | tee -a "$LOG_FILE"
  
  # Clean up
  rm -f packages-microsoft-prod.deb
}

# --- Main installation logic ---
main() {
  log "====== Starting Sysmon for Linux installation ======"

  # Check for root privileges
  if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be run as root. Please use 'sudo'."
    exit 1
  fi

  # Determine OS type
  OS_TYPE=$(get_os_type)
  if [ "$OS_TYPE" == "unsupported" ]; then
    log_error "Unsupported operating system. This script supports Amazon Linux 2, Amazon Linux 2023, CentOS 7, and Ubuntu."
    exit 1
  fi

  log "Detected OS: $OS_TYPE"

  # Set version variables if applicable
  if [[ "$OS_TYPE" == amazon-* ]]; then
    AMAZON_LINUX_VERSION="${OS_TYPE#amazon-}"
  fi

  # Create Sysmon directory and default config
  create_sysmon_config

  # Validate config file if provided as argument
  if [ -n "${1:-}" ]; then
    SYSMON_CONFIG_FILE="$1"
    if ! validate_config_file; then
      log_error "Config file validation failed. Exiting."
      exit 1
    fi
  else
    log "Using default configuration: $SYSMON_CONFIG_FILE"
  fi

  # Check for existing installation
  if check_existing_installation; then
    read -p "Sysmon is already installed. Remove and reinstall? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      remove_existing_sysmon
    else
      log "Installation cancelled by user."
      exit 0
    fi
  fi

  # Install based on OS type
  case "$OS_TYPE" in
    amazon-2|amazon-2023)
      install_amazon_linux
      ;;
    centos-7)
      install_centos7
      ;;
    centos-other)
      log_error "Only CentOS 7 is currently supported. For other CentOS versions, please check Microsoft's documentation."
      exit 1
      ;;
    ubuntu)
      install_ubuntu
      ;;
  esac

  # Install Sysmon with the specified configuration
  log "Installing Sysmon with configuration file: $SYSMON_CONFIG_FILE"
  sysmon -accepteula -i "$SYSMON_CONFIG_FILE" 2>&1 | tee -a "$LOG_FILE"

  # Configure rsyslog for Sysmon
  if ! configure_rsyslog; then
    log_error "Rsyslog configuration failed, but Sysmon was installed."
  fi

  # Verify installation
  log "Verifying Sysmon installation..."
  if command -v sysmon &> /dev/null; then
    sysmon -v | tee -a "$LOG_FILE"
    log "====== Sysmon installation completed successfully ======"
    log ""
    log "Configuration file location: $SYSMON_CONFIG_FILE"
    log "Sysmon logs are configured to write to: $SYSMON_LOG_FILE"
    log ""
    log "Useful commands:"
    log "  - View events: sudo tail -f $SYSMON_LOG_FILE"
    log "  - View formatted events: sudo tail -f $SYSMON_LOG_FILE | sudo /opt/sysmon/sysmonLogView"
    log "  - Check Sysmon status: sudo systemctl status sysmon"
    log "  - Check rsyslog status: sudo systemctl status rsyslog"
    log "  - Update config: sudo sysmon -c $SYSMON_CONFIG_FILE"
    log ""
    log "Installation log saved to: $LOG_FILE"
  else
    log_error "Sysmon installation verification failed!"
    exit 1
  fi
}

# Execute the main function
main "$@"