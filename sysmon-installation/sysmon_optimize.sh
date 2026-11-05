#!/bin/bash

# Variables
# need to change the config file path (cat /etc/systemd/system/sysmon.service |  grep ExecStart)
##Example, ExecStart=/opt/sysmon/sysmon -i /opt/sysmon/config.xml -service
CONFIG_DIR="/opt/sysmon"
CONFIG_PATH="/opt/sysmon/config3.xml"
BACKUP_DIR="/opt/sysmon/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/config.xml.backup.$TIMESTAMP"

# 1. Create config directory if it doesn't exist
if [ ! -d "$CONFIG_DIR" ]; then
    echo "Config directory not found. Creating: $CONFIG_DIR"
    mkdir -p "$CONFIG_DIR"
else
    echo "Config directory exists: $CONFIG_DIR"
fi
# Create backup directory if it doesn't exist
if [ ! -d "$BACKUP_DIR" ]; then
    echo "Backup directory not found. Creating: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
else
    echo "Backup directory exists: $BACKUP_DIR"
fi
# Stop sysmon service
echo "[*] Stopping sysmon service..."
sudo systemctl stop sysmon
if [ $? -eq 0 ]; then
    echo "[+] Sysmon stopped successfully"
else
    echo "[-] Failed to stop sysmon"
    exit 1
fi

# Create backup of current config
if [ -f "$CONFIG_PATH" ]; then
    echo "[*] Backing up current config to $BACKUP_FILE..."
    sudo cp "$CONFIG_PATH" "$BACKUP_FILE"
    echo "[+] Backup created successfully"
else
    echo "[!] Warning: Current config not found at $CONFIG_PATH"
fi

# Write new config
echo "[*] Writing new configuration..."
sudo tee "$CONFIG_PATH" > /dev/null << 'EOF'
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

if [ $? -eq 0 ]; then
    echo "[+] New configuration written successfully"
else
    echo "[-] Failed to write new configuration"
    exit 1
fi

# Start sysmon service
echo "[*] Starting sysmon service..."
sudo sysmon -c $CONFIG_PATH
sudo systemctl start sysmon
if [ $? -eq 0 ]; then
    echo "[+] Sysmon started successfully"
else
    echo "[-] Failed to start sysmon"
    exit 1
fi

# Verify service is running
if sudo systemctl is-active --quiet sysmon; then
    echo "[+] Sysmon is running"
    echo "[+] Configuration update completed successfully"
    echo "[+] Backup saved at: $BACKUP_FILE"
else
    echo "[-] Warning: Sysmon service is not running"
    exit 1
fi

echo ""
echo "=========================================="
echo "      SYSMON CONFIGURATION SUMMARY"
echo "=========================================="
echo ""

# Log file path
echo "[*] Log File Path:"
LOG_PATH=$(grep -r "LogPath" /opt/sysmon/ 2>/dev/null | head -1)
if [ -z "$LOG_PATH" ]; then
    DEFAULT_LOG="/var/log/sysmon/sysmon.log"
    echo "    $DEFAULT_LOG (default)"
else
    echo "    $LOG_PATH"
fi
echo ""

# Service command
echo "[*] Service Management Commands:"
echo "    Start:   sudo systemctl start sysmon"
echo "    Stop:    sudo systemctl stop sysmon"
echo "    Restart: sudo systemctl restart sysmon"
echo "    Status:  sudo systemctl status sysmon"
echo ""

# Current service status
echo "[*] Current Service Status:"
if sudo systemctl is-active --quiet sysmon; then
    echo "    ✓ Sysmon is RUNNING"
else
    echo "    ✗ Sysmon is STOPPED"
fi
echo ""

# Service details
echo "[*] Service Information:"
sudo systemctl status sysmon --no-pager | grep -E "Active|Since|Main PID|Memory"
echo ""

# Last 2 log entries
echo "[*] Last 2 Sysmon Log Entries:"
echo "    ────────────────────────────────────────"
if [ -f "/var/log/sysmon/sysmon.log" ]; then
    sudo tail -n 2 /var/log/sysmon/sysmon.log | sed 's/^/    /'
elif [ -f "/var/log/sysmon.log" ]; then
    sudo tail -n 2 /var/log/sysmon.log | sed 's/^/    /'
else
    echo "    [!] Log file not found at standard locations"
    echo "    Checking journalctl for sysmon entries..."
    sudo journalctl -u sysmon -n 2 --no-pager | sed 's/^/    /'
fi
echo "    ────────────────────────────────────────"
echo ""

# Config file info
echo "[*] Configuration File:"
if [ -f "/opt/sysmon/config.xml" ]; then
    CONFIG_SIZE=$(stat -f%z "/opt/sysmon/config.xml" 2>/dev/null || stat -c%s "/opt/sysmon/config.xml" 2>/dev/null)
    CONFIG_MOD=$(stat -f %Sm -t "%Y-%m-%d %H:%M:%S" "/opt/sysmon/config.xml" 2>/dev/null || stat -c %y "/opt/sysmon/config.xml" 2>/dev/null | cut -d. -f1)
    echo "    Path:     /opt/sysmon/config.xml"
    echo "    Size:     $CONFIG_SIZE bytes"
    echo "    Modified: $CONFIG_MOD"
else
    echo "    [!] Config file not found"
fi
echo ""

# Backup info
echo "[*] Available Backups:"
if [ -d "$BACKUP_DIR" ]; then
    BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/*.backup.* 2>/dev/null | wc -l)
    if [ "$BACKUP_COUNT" -gt 0 ]; then
        echo "    Found $BACKUP_COUNT backup(s):"
        sudo ls -lh "$BACKUP_DIR"/*.backup.* 2>/dev/null | awk '{print "    " $9 " (" $5 ")"}' | tail -5
    else
        echo "    No backups found"
    fi
else
    echo "    Backup directory not found"
fi
echo ""

echo "=========================================="