#!/bin/bash

# Enhanced script to install Sysmon on Amazon Linux 2, Amazon Linux 2023, and Ubuntu.
# This script must be run with root or sudo privileges.

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# --- Variables ---
# Replace with the path to your Sysmon configuration file.
# Example: "sysmon_config.xml" for a local file, or a URL for a remote file.
#SYSMON_CONFIG_FILE="${1:-}"  # Accept config file as first argument

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

# --- Logging function ---
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
    amazon-2)
      yum autoremove -y sysmonforlinux || log "No existing Sysmon package to remove"
      ;;
    amazon-2023)
      dnf autoremove -y sysmonforlinux || log "No existing Sysmon package to remove"
      ;;
    ubuntu)
      apt-get purge -y sysmonforlinux || log "No existing Sysmon package to remove"
      ;;
  esac
}

create_sysmon_config() {
  log "Creating Sysmon directory and configuration..."
  
  # Create directory if it doesn't exist
  if [ ! -d "$SYSMON_DIR" ]; then
    mkdir -p "$SYSMON_DIR"
    log "Created directory: $SYSMON_DIR"
  else
    log "Directory already exists: $SYSMON_DIR"
  fi
  
  # Remove existing config if it exists (use -f to ignore missing file and quote the path)
  rm -f "$SYSMON_DIR/yt-sysmon-linux.xml"
  # Create default config file
  cat > "$SYSMON_DIR/yt-sysmon-linux.xml" << 'EOF'
<Sysmon schemaversion="4.81">
  <EventFiltering>

    <!-- ========================== -->
    <!-- Event ID 1 == ProcessCreate -->
    <!-- ========================== -->
    <RuleGroup name="Process Creation" groupRelation="or">
      <ProcessCreate onmatch="include">

        <!-- ───────── Original MITRE-Mapped Rules ───────── -->
        <Rule name="Suspicious Process Creation" groupRelation="or">
          <CommandLine condition="contains"> -c </CommandLine>
          <CommandLine condition="contains"> echo </CommandLine>
          <CommandLine condition="contains"> base64 </CommandLine>
          <CommandLine condition="contains"> curl </CommandLine>
        </Rule>

        <Rule name="TechniqueID=T1021.004,TechniqueName=Remote Services: SSH" groupRelation="and">
          <Image condition="end with">ssh</Image>
          <CommandLine condition="contains">ConnectTimeout=</CommandLine>
          <CommandLine condition="contains">BatchMode=yes</CommandLine>
          <CommandLine condition="contains">StrictHostKeyChecking=no</CommandLine>
          <CommandLine condition="contains any">wget;curl</CommandLine>
        </Rule>

        <Rule name="TechniqueID=T1027.001,TechniqueName=Obfuscated Files or Information: Binary Padding" groupRelation="and">
          <Image condition="is">/bin/dd</Image>
          <CommandLine condition="contains all">dd;if=</CommandLine>
        </Rule>

        <Rule name="TechniqueID=T1033,TechniqueName=System Owner/User Discovery" groupRelation="or">
          <CommandLine condition="contains">/var/run/utmp</CommandLine>
          <CommandLine condition="contains">/var/log/btmp</CommandLine>
          <CommandLine condition="contains">/var/log/wtmp</CommandLine>
        </Rule>

        <Rule name="TechniqueID=T1053.003,TechniqueName=Scheduled Task/Job: Cron" groupRelation="or">
          <Image condition="end with">crontab</Image>
        </Rule>

        <Rule name="TechniqueID=T1059.004,TechniqueName=Command and Scripting Interpreter: Unix Shell" groupRelation="or">
          <Image condition="end with">/bin/bash</Image>
          <Image condition="end with">/bin/dash</Image>
          <Image condition="end with">/bin/sh</Image>
        </Rule>

        <Rule name="TechniqueID=T1070.006,TechniqueName=Indicator Removal on Host: Timestomp" groupRelation="and">
          <Image condition="is">/bin/touch</Image>
          <CommandLine condition="contains any">-r;--reference;-t;--time</CommandLine>
        </Rule>

        <Rule name="TechniqueID=T1087.001,TechniqueName=Account Discovery: Local Account" groupRelation="or">
          <CommandLine condition="contains">/etc/passwd</CommandLine>
          <CommandLine condition="contains">/etc/sudoers</CommandLine>
        </Rule>

        <Rule name="TechniqueID=T1105,TechniqueName=Ingress Tool Transfer" groupRelation="or">
          <Image condition="end with">wget</Image>
          <Image condition="end with">curl</Image>
          <Image condition="end with">ftpget</Image>
          <Image condition="end with">tftp</Image>
          <Image condition="end with">lwp-download</Image>
        </Rule>

        <Rule name="TechniqueID=T1123,TechniqueName=Audio Capture" groupRelation="and">
          <Image condition="contains">/bin/aplay</Image>
          <CommandLine condition="contains">arecord</CommandLine>
        </Rule>

        <Rule name="TechniqueID=T1136.001,TechniqueName=Create Account: Local Account" groupRelation="or">
          <Image condition="end with">useradd</Image>
          <Image condition="end with">adduser</Image>
        </Rule>

        <Rule name="TechniqueID=T1203,TechniqueName=Exploitation for Client Execution" groupRelation="and">
          <User condition="is">root</User>
          <LogonId condition="is">0</LogonId>
          <CurrentDirectory condition="is">/var/opt/microsoft/scx/tmp</CurrentDirectory>
          <CommandLine condition="contains">/bin/sh</CommandLine>
        </Rule>

        <Rule name="TechniqueID=T1485,TechniqueName=Data Destruction" groupRelation="and">
          <Image condition="is">/bin/dd</Image>
          <CommandLine condition="contains all">dd;of=;if=</CommandLine>
          <CommandLine condition="contains any">if=/dev/zero;if=/dev/null</CommandLine>
        </Rule>

        <Rule name="TechniqueID=T1505.003,TechniqueName=Server Software Component: Web Shell" groupRelation="and">
          <Image condition="contains any">whoami;ifconfig;/usr/bin/ip;/bin/uname</Image>
          <ParentImage condition="contains any">httpd;lighttpd;nginx;apache2;node;dash</ParentImage>
        </Rule>

        <Rule name="TechniqueID=T1543.002,TechniqueName=Create or Modify System Process: Systemd Service" groupRelation="or">
          <Image condition="end with">systemd</Image>
        </Rule>

        <Rule name="TechniqueID=T1548.001,TechniqueName=Abuse Elevation Control Mechanism: Setuid and Setgid" groupRelation="or">
          <Image condition="end with">chmod</Image>
          <Image condition="end with">chown</Image>
          <Image condition="end with">setuid</Image>
          <Image condition="end with">setgid</Image>
        </Rule>

        <!-- ───────── Added Operational Visibility Rules ───────── -->
        <Rule name="Interpreter and Payload Execution" groupRelation="or">
          <Image condition="end with">/python</Image>
          <Image condition="end with">/perl</Image>
          <Image condition="end with">/php</Image>
          <Image condition="end with">/ruby</Image>
          <Image condition="end with">/pwsh</Image>
          <Image condition="contains">powershell</Image>
          <CommandLine condition="contains any">/tmp/;/dev/shm/;chmod +x;bash -c;base64 -d</CommandLine>
        </Rule>

        <Rule name="Malware Download Tools" groupRelation="or">
          <Image condition="end with">/curl</Image>
          <Image condition="end with">/wget</Image>
          <Image condition="end with">/nc</Image>
          <Image condition="end with">/ncat</Image>
          <Image condition="end with">/socat</Image>
          <CommandLine condition="contains any">http;https;ftp;</CommandLine>
        </Rule>

        <!-- ───────── PowerShell Abuse: T1059.001 (Windows-style pwsh/powershell on Linux) ───────── -->
        <Rule name="PS-EncodedOrObfuscatedCommand" groupRelation="or">
          <!-- process images for PowerShell Core (pwsh) and classic powershell (if present) -->
          <Image condition="end with">/pwsh</Image>
          <Image condition="contains">powershell</Image>

          <!-- common encoded / obfuscation flags -->
          <CommandLine condition="contains">-EncodedCommand</CommandLine>
          <CommandLine condition="contains">-enc</CommandLine>
          <CommandLine condition="contains">-e </CommandLine>
          <CommandLine condition="contains">-NoProfile</CommandLine>
          <CommandLine condition="contains">-NonInteractive</CommandLine>

          <!-- suspicious cmd patterns often used in malicious PS scripts -->
          <CommandLine condition="contains any">IEX;Invoke-Expression;FromBase64String;Add-Type;DllImport;VirtualAlloc;WriteProcessMemory;GetDelegateForFunctionPointer;DefineDynamicAssembly;Reflection</CommandLine>

          <!-- typical pipeline/download+execute combos -->
          <CommandLine condition="contains any">Invoke-WebRequest;IWR;wget;curl;base64</CommandLine>

          <!-- inline assembly creation / runtime compilation -->
          <CommandLine condition="contains any">DefineMethod;DefineType;DefineDynamicModule;AssemblyBuilder</CommandLine>
        </Rule>

        <Rule name="PS-Base64-RegistryStaging" groupRelation="or">
          <!-- detect PowerShell reading base64 payloads from environment/registry/files -->
          <Image condition="end with">/pwsh</Image>
          <Image condition="contains">powershell</Image>
          <CommandLine condition="contains any">Get-ItemProperty;Get-ItemPropertyValue;FromBase64String;Convert]::FromBase64String</CommandLine>
          <CommandLine condition="contains">HKLM:\</CommandLine>
        </Rule>

        <Rule name="PS-ReflectiveAndPInvokeIndicators" groupRelation="or">
          <Image condition="end with">/pwsh</Image>
          <Image condition="contains">powershell</Image>
          <!-- P/Invoke, DllImport, Marshal, VirtualAlloc, WriteProcessMemory -->
          <CommandLine condition="contains any">DllImport;Marshal::GetDelegateForFunctionPointer;VirtualAlloc;WriteProcessMemory;SetErrorMode</CommandLine>
        </Rule>

        <Rule name="PS-AssemblyCompileOrCsc" groupRelation="or">
          <Image condition="end with">/pwsh</Image>
          <Image condition="contains">powershell</Image>
          <CommandLine condition="contains any">csc.exe;Add-Type;AssemblyBuilderAccess;DefineDynamicAssembly</CommandLine>
          <CommandLine condition="contains">/out:*.dll</CommandLine>
        </Rule>

      </ProcessCreate>
    </RuleGroup>

    <!-- ========================== -->
    <!-- Event ID 3 == NetworkConnect -->
    <!-- ========================== -->
    <RuleGroup name="Network Connections" groupRelation="or">
      <NetworkConnect onmatch="include">

        <Rule name="TechniqueID=T1105,TechniqueName=Ingress Tool Transfer" groupRelation="or">
          <Image condition="end with">wget</Image>
          <Image condition="end with">curl</Image>
          <Image condition="end with">ftpget</Image>
          <Image condition="end with">tftp</Image>
          <Image condition="end with">lwp-download</Image>
        </Rule>

        <Rule name="Suspicious Outbound Connections" groupRelation="or">
          <Image condition="end with">/bash</Image>
          <Image condition="end with">/python</Image>
          <Image condition="end with">/pwsh</Image>
          <Image condition="contains">powershell</Image>
          <Image condition="end with">/curl</Image>
          <Image condition="end with">/wget</Image>
          <Image condition="end with">/socat</Image>
          <DestinationIp condition="is not">127.0.0.1</DestinationIp>
          <DestinationIp condition="is not">::1</DestinationIp>
        </Rule>

      </NetworkConnect>
    </RuleGroup>

    <!-- ========================== -->
    <!-- Event ID 5 == ProcessTerminate -->
    <!-- ========================== -->
    <RuleGroup name="Process Terminate" groupRelation="or">
      <ProcessTerminate onmatch="include">
        <Image condition="end with">/bash</Image>
        <Image condition="end with">/python</Image>
        <Image condition="end with">/perl</Image>
        <Image condition="end with">/pwsh</Image>
        <Image condition="contains">powershell</Image>
      </ProcessTerminate>
    </RuleGroup>

    <!-- ========================== -->
    <!-- Event ID 9 == RawAccessRead -->
    <!-- ========================== -->
    <RuleGroup name="Raw Access Read" groupRelation="or">
      <RawAccessRead onmatch="include" />
    </RuleGroup>

    <!-- ========================== -->
    <!-- Event ID 10 == ProcessAccess -->
    <!-- ========================== -->
    <RuleGroup name="Process Access" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">/sshd</TargetImage>
        <TargetImage condition="end with">/sudo</TargetImage>
        <TargetImage condition="end with">/cron</TargetImage>
        <TargetImage condition="contains">powershell</TargetImage>
        <TargetImage condition="end with">/pwsh</TargetImage>
      </ProcessAccess>
    </RuleGroup>

    <!-- ========================== -->
    <!-- Event ID 11 == FileCreate -->
    <!-- ========================== -->
    <RuleGroup name="File Creation" groupRelation="or">
      <FileCreate onmatch="include">

        <Rule name="TechniqueID=T1037,TechniqueName=Boot or Logon Initialization Scripts" groupRelation="or">
          <TargetFilename condition="begin with">/etc/init/</TargetFilename>
          <TargetFilename condition="begin with">/etc/init.d/</TargetFilename>
          <TargetFilename condition="begin with">/etc/rc.d/</TargetFilename>
        </Rule>

        <Rule name="TechniqueID=T1053.003,TechniqueName=Scheduled Task/Job: Cron" groupRelation="or">
          <TargetFilename condition="is">/etc/cron.allow</TargetFilename>
          <TargetFilename condition="is">/etc/cron.deny</TargetFilename>
          <TargetFilename condition="is">/etc/crontab</TargetFilename>
          <TargetFilename condition="begin with">/etc/cron.d/</TargetFilename>
          <TargetFilename condition="begin with">/var/spool/cron/crontabs/</TargetFilename>
        </Rule>

        <Rule name="TechniqueID=T1105,TechniqueName=Ingress Tool Transfer" groupRelation="or">
          <Image condition="end with">wget</Image>
          <Image condition="end with">curl</Image>
        </Rule>

        <Rule name="TechniqueID=T1543.002,TechniqueName=Create or Modify System Process: Systemd Service" groupRelation="or">
          <TargetFilename condition="begin with">/etc/systemd/system</TargetFilename>
          <TargetFilename condition="begin with">/usr/lib/systemd/system</TargetFilename>
          <TargetFilename condition="contains">/systemd/user/</TargetFilename>
        </Rule>

        <Rule name="Temp or Script File Creation" groupRelation="or">
          <TargetFilename condition="contains any">/tmp/;/dev/shm/;/var/tmp/</TargetFilename>
          <TargetFilename condition="end with">.sh</TargetFilename>
          <TargetFilename condition="end with">.py</TargetFilename>
          <TargetFilename condition="end with">.pl</TargetFilename>
          <TargetFilename condition="end with">.php</TargetFilename>
          <TargetFilename condition="end with">.so</TargetFilename>
          <TargetFilename condition="end with">.bin</TargetFilename>
          <TargetFilename condition="end with">.dll</TargetFilename>
        </Rule>

        <!-- PowerShell-specific file creation: compiled DLLs or temp staging -->
        <Rule name="PS-DLLOrTempStaging" groupRelation="or">
          <TargetFilename condition="contains">/tmp/</TargetFilename>
          <TargetFilename condition="end with">.dll</TargetFilename>
          <TargetFilename condition="contains">3cw0vfzj</TargetFilename> <!-- example artifact pattern from sample; optional -->
        </Rule>

      </FileCreate>
    </RuleGroup>

    <!-- ========================== -->
    <!-- Event ID 23 == FileDelete -->
    <!-- ========================== -->
    <RuleGroup name="File Deletion" groupRelation="or">
      <FileDelete onmatch="include">
        <TargetFilename condition="contains any">/tmp/;/dev/shm/;/var/tmp/</TargetFilename>
      </FileDelete>
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

# --- Function to install on Amazon Linux ---
install_amazon_linux() {
  log "Installing prerequisites for Amazon Linux $AMAZON_LINUX_VERSION..."
  
  if [ "$AMAZON_LINUX_VERSION" == "2" ]; then
    yum install  wget rsyslog 2>&1 | tee -a "$LOG_FILE"
  else
    dnf install  wget rsyslog 2>&1 | tee -a "$LOG_FILE"
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
    yum makecache fast 2>&1 | tee -a "$LOG_FILE"
    yum install sysmonforlinux 2>&1 | tee -a "$LOG_FILE"
  else
    # For dnf-based systems (CentOS 8+, Fedora, RHEL 8+)
    dnf makecache 2>&1 | tee -a "$LOG_FILE"
    dnf install sysmonforlinux 2>&1 | tee -a "$LOG_FILE"
  fi
}

# --- Function to install on Ubuntu ---
install_ubuntu() {
  log "Installing prerequisites for Ubuntu..."
  
  # Install rsyslog if not present
  apt-get install rsyslog wget 2>&1 | tee -a "$LOG_FILE"
  
  log "Downloading Microsoft package repository..."
  UBUNTU_VERSION=$(lsb_release -rs)
  wget -q https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/packages-microsoft-prod.deb -O packages-microsoft-prod.deb 2>&1 | tee -a "$LOG_FILE"
  
  log "Installing Microsoft package repository..."
  dpkg -i packages-microsoft-prod.deb 2>&1 | tee -a "$LOG_FILE"
  
  log "Updating package list..."
  apt-get update 2>&1 | tee -a "$LOG_FILE"
  
  log "Installing Sysmon for Linux..."
  apt-get install sysmonforlinux 2>&1 | tee -a "$LOG_FILE"
  
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
    log_error "Unsupported operating system. This script supports Amazon Linux 2, Amazon Linux 2023, and Ubuntu."
    exit 1
  fi

  log "Detected OS: $OS_TYPE"

  # Set Amazon Linux version if applicable
  if [[ "$OS_TYPE" == amazon-* ]]; then
    AMAZON_LINUX_VERSION="${OS_TYPE#amazon-}"
  fi
 # Create Sysmon directory and default config
  create_sysmon_config
  # Validate config file if provided
  if ! validate_config_file; then
    log_error "Config file validation failed. Exiting."
    exit 1
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
    ubuntu)
      install_ubuntu
      ;;
  esac

  # Install Sysmon with the specified configuration
  if [ -z "$SYSMON_CONFIG_FILE" ]; then
    log "No configuration file provided. Installing with default settings."
    sysmon -accepteula -i 2>&1 | tee -a "$LOG_FILE"
  else
    log "Installing Sysmon with configuration file: $SYSMON_CONFIG_FILE"
    sysmon -accepteula -i "$SYSMON_CONFIG_FILE" 2>&1 | tee -a "$LOG_FILE"
  fi

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
    log "Sysmon logs are configured to write to: $SYSMON_LOG_FILE"
    log ""
    log "Useful commands:"
    log "  - View events: sudo tail -f $SYSMON_LOG_FILE"
    log "  - View formatted events: sudo tail -f $SYSMON_LOG_FILE | sudo /opt/sysmon/sysmonLogView"
    log "  - Check Sysmon status: sudo systemctl status sysmon"
    log "  - Check rsyslog status: sudo systemctl status rsyslog"
    log ""
    log "Installation log saved to: $LOG_FILE"
  else
    log_error "Sysmon installation verification failed!"
    exit 1
  fi
}

# Execute the main function
main "$@"