# Sysmon for Linux: Installation and Deployment Guide

This guide shows how to install Sysmon for Linux, write its events to `/var/log/sysmon.log`, rotate that log, and forward it to a Wazuh agent. It covers two ways to install: an automated installer script, and manual steps for each distribution.

> **Handling.** Section 9 lists problems found by reading the scripts and the original notes. They were not found by running the scripts, so test on one host before rolling out. The scripts create their files as `yt-sysmon-linux.xml` and `yt-sysmon-log.conf`, and this guide uses those names.

---

## Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Installation](#3-installation)
4. [Sysmon configuration](#4-sysmon-configuration)
5. [Verify the installation](#5-verify-the-installation)
6. [Log rotation](#6-log-rotation)
7. [Forward the events to Wazuh](#7-forward-the-events-to-wazuh)
8. [Troubleshooting](#8-troubleshooting)
9. [Notes and known issues](#9-notes-and-known-issues)

---

## 1. Overview

Sysmon for Linux records system activity, such as process creation and network connections, as events. It sends them to **syslog**. A small **rsyslog rule** picks out the Sysmon events and writes them to their own file, `/var/log/sysmon.log`. A Sysmon **XML configuration** decides which events are recorded.

```
Sysmon (service "sysmon")
   -> syslog
   -> rsyslog rule: message contains "Linux-Sysmon"
   -> /var/log/sysmon.log
   -> logrotate (section 6) and the Wazuh agent (section 7)
```

**Supported platforms**

| Method | Platforms |
|---|---|
| Installer script `sysmon_installv1.2.sh` (section 3.2) | Ubuntu, Amazon Linux 2, Amazon Linux 2023 |
| Manual steps (section 3.3) | Debian or Ubuntu, Fedora, RHEL |

The original guide states that the manual steps were tested on Debian 11 and on "Ubuntu 16.14". That Ubuntu version number is not a valid release (see section 9, note 1), so confirm the Ubuntu version you test on.

## 2. Prerequisites

1. **Root access**, either as root or with `sudo`.
2. **Outbound HTTPS** to `packages.microsoft.com`, where the `sysmonforlinux` package is published.
3. **rsyslog**, installed and running. The script installs it on Ubuntu and Amazon Linux. On Debian, Fedora and RHEL, install it yourself if it is missing.
4. **`wget`**, and `gpg` for the Debian key step in section 3.3.
5. **Unix line endings on the scripts.** The three install scripts (`sysmon_installv1.sh`, `v1.1`, `v1.2`) and the two config files in this folder have Windows line endings. A script like that fails on Linux with `bad interpreter: /bin/bash^M`. Convert it before you run it:

   ```bash
   sed -i 's/\r$//' sysmon_installv1.2.sh
   ```

## 3. Installation

### 3.1 Configure rsyslog

Add the rsyslog rule that writes Sysmon events to their own file. The installer script does this step for you, after it installs Sysmon. For a manual install, do it first.

Create the rule file:

```bash
sudo nano /etc/rsyslog.d/yt-sysmon-log.conf
```

Add these two lines:

```
if $msg contains "Linux-Sysmon" then /var/log/sysmon.log
& stop
```

The first line sends every message that contains `Linux-Sysmon` to `/var/log/sysmon.log`. The second line (`& stop`) ends processing for those messages, so they are not also written to the general syslog files.

Then restart rsyslog:

```bash
sudo systemctl restart rsyslog
```

> **File name.** Use `yt-sysmon-log.conf` so that a manual install and the script agree and the script simply overwrites your file. Under a different name you can end up with two rule files that hold the same rule.

### 3.2 Option A: installer script

`sysmon_installv1.2.sh` is the latest of the three installer scripts. It works on **Ubuntu, Amazon Linux 2 and Amazon Linux 2023** only. On any other system it stops with "Unsupported operating system", and you should use section 3.3.

```bash
sed -i 's/\r$//' sysmon_installv1.2.sh      # only needed if the file has Windows line endings
chmod +x sysmon_installv1.2.sh
sudo ./sysmon_installv1.2.sh
systemctl status sysmon
```

To install with your own configuration file, pass its path as the first argument:

```bash
sudo ./sysmon_installv1.2.sh /opt/sysmon/my-sysmon-config.xml
```

**What the script does, in order**

1. Checks that it runs as root and detects the OS (Ubuntu, Amazon Linux 2 or Amazon Linux 2023).
2. Creates `/opt/sysmon/` and writes the default configuration to `/opt/sysmon/yt-sysmon-linux.xml`. **It overwrites that file on every run** (section 4).
3. Checks that the configuration file you passed exists.
4. If Sysmon is already installed, it asks `Remove and reinstall? (y/N)`. Answer `n` and it exits without installing anything. Answer `y` and it removes the old package first. Note that step 2 has already rewritten `/opt/sysmon/yt-sysmon-linux.xml` by this point, even if you answer `n`.
5. Installs `rsyslog` and `wget`, adds the Microsoft package repository and installs the `sysmonforlinux` package (table below).
6. Installs Sysmon with `sysmon -accepteula -i <configuration file>`.
7. Writes `/etc/rsyslog.d/yt-sysmon-log.conf` (section 3.1), restarts rsyslog and checks that it is active.
8. Prints the Sysmon version and a list of useful commands. The installation log is in `/var/log/sysmon_install.log`.

| OS | Microsoft repository used |
|---|---|
| Ubuntu | `packages-microsoft-prod.deb` for your release (`lsb_release -rs`) |
| Amazon Linux 2 | `rhel/7/prod.repo` |
| Amazon Linux 2023 | `rhel/9.0/prod.repo` |

> **The script is interactive.** The package installs do not use `-y`, so `apt-get`, `yum` or `dnf` may ask you to confirm. It is not suitable for unattended runs as written.

### 3.3 Option B: manual installation

Use these steps on Debian, Fedora and RHEL, or on any system the script does not support. Do section 3.1 first.

#### Debian or Ubuntu

**Step 1: Register the Microsoft key and repository.** These commands are for Debian 11. For another Debian release, use the matching Microsoft repository, if one is published.

```bash
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg
sudo mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/
wget -q https://packages.microsoft.com/config/debian/11/prod.list
sudo mv prod.list /etc/apt/sources.list.d/microsoft-prod.list
sudo chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg
sudo chown root:root /etc/apt/sources.list.d/microsoft-prod.list
```

On **Ubuntu**, use the Ubuntu repository package instead of the Debian 11 list. This is what the installer script does:

```bash
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
rm -f packages-microsoft-prod.deb
```

**Step 2: Install Sysmon for Linux.**

```bash
sudo apt-get update
sudo apt-get install apt-transport-https -y
sudo apt-get update
sudo apt-get install sysmonforlinux -y
```

#### Fedora

**Step 1: Register the Microsoft key and repository.**

```bash
sudo rpm -Uvh https://packages.microsoft.com/config/fedora/$(rpm -E %fedora)/packages-microsoft-prod.rpm
```

**Step 2: Install Sysmon for Linux.**

```bash
sudo dnf update -y
sudo dnf install sysmonforlinux -y
```

#### RHEL

**Step 1: Register the Microsoft key and repository.**

```bash
sudo rpm -Uvh https://packages.microsoft.com/config/rhel/$(. /etc/os-release && echo ${VERSION_ID%%.*})/packages-microsoft-prod.rpm
```

**Step 2: Install Sysmon for Linux.**

```bash
sudo yum update -y
sudo yum install sysmonforlinux -y
```

### 3.4 Deploy Sysmon with a configuration

After a manual install, start Sysmon with a configuration file. Replace the path with the path to your file (see section 4 for the available configurations):

```bash
sudo sysmon -accepteula -i /opt/sysmon/yt-sysmon-linux.xml
```

The original guide uses `sudo sysmon -i /path/...` without `-accepteula`. The installer script uses `-accepteula`, so this guide does too. Sysmon then runs as the `sysmon` service.

## 4. Sysmon configuration

Two ready-made configurations are available.

**A. The rule-based configuration built into the installer.** The script writes it to `/opt/sysmon/yt-sysmon-linux.xml` (schema 4.81). It logs only events that match its rules, and 20 of its 30 rules carry a MITRE ATT&CK technique ID in their name.

| Event ID | Event | Rules |
|---|---|---|
| 1 | Process creation | 22 |
| 3 | Network connection | 2 |
| 5 | Process terminated | 0 |
| 9 | Raw disk access | 0 |
| 10 | Process access | 0 |
| 11 | File creation | 6 |
| 23 | File deletion | 0 |

Every group uses `onmatch="include"`. Only process creation, network connection and file creation have rules. The other four groups are `include` with no rules, so I would expect them to record nothing. Confirm this on a test host.

**B. The collect-all configuration** (`sysmon-linux-collect-all.xml`, schema 4.70, in this folder). It covers the same seven event types, each as `onmatch="exclude"` with no conditions, so **every** event of those types is logged. This produces a high volume of logs. Use it for testing or when you need full visibility, and size `/var/log/sysmon.log` and the rotation (section 6) for it.

**Change the configuration of a running Sysmon:**

```bash
sudo sysmon -c /path/to/config.xml
```

**Keep your own changes safe.** The installer script rewrites `/opt/sysmon/yt-sysmon-linux.xml` every time it runs. If you edit the configuration, save your version under a different name and pass it to the script as the first argument.

## 5. Verify the installation

Check that the service is running:

```bash
systemctl status sysmon
```

Check that Sysmon events are being logged:

```bash
sudo grep -i sysmon /var/log/sysmon.log
```

On distributions that use systemd, you can also look at the service log:

```bash
sudo journalctl -u sysmon | tail -n 50
```

The script also prints two helpers. The first follows the log live, and the second formats the events so they are easier to read:

```bash
sudo tail -f /var/log/sysmon.log
sudo tail -f /var/log/sysmon.log | sudo /opt/sysmon/sysmonLogView
```

**Generate a test event.** With the rule-based configuration, a process whose command line contains ` -c ` or ` echo ` matches the "Suspicious Process Creation" rule. This was not run here, so treat it as a quick check:

```bash
sh -c 'echo sysmon-test'
sudo grep -i 'sysmon-test' /var/log/sysmon.log
```

## 6. Log rotation

`/var/log/sysmon.log` grows without limit unless it is rotated. Add it to the existing rsyslog rotation:

1. Open the logrotate file for rsyslog:

   ```bash
   sudo nano /etc/logrotate.d/rsyslog
   ```

2. Add `/var/log/sysmon.log` on its own line, in the list of log files at the top, **above** the line that starts the `{` block. For example:

   ```
   /var/log/syslog
   /var/log/mail.log
   /var/log/sysmon.log        <- the new line
   {
           rotate 4
           weekly
           ...
   }
   ```

3. Check the configuration without changing anything (a dry run):

   ```bash
   sudo logrotate -d /etc/logrotate.d/rsyslog
   ```

4. Force a rotation to test it:

   ```bash
   sudo logrotate -fv /etc/logrotate.conf
   ```

> **Forced rotation affects every log.** `logrotate -f /etc/logrotate.conf` rotates all the logs that logrotate manages, not only the Sysmon log. On a production host, test with `sudo logrotate -fv /etc/logrotate.d/rsyslog` instead. That still rotates every file listed in that one file.

> **File name on RHEL.** On RHEL-family systems the rsyslog rotation file is usually `/etc/logrotate.d/syslog`, not `rsyslog`. Check which one exists with `ls /etc/logrotate.d/`.

## 7. Forward the events to Wazuh

To send the Sysmon events to the Wazuh manager, add `/var/log/sysmon.log` to the agent configuration. Follow the procedure in section 5 ("Adding more logs") of the [Wazuh agent installation guide](../wazuh-installation/Wazuh%20for%20Linux/wazuh-installation-guide.md), which uses OpenVPN as its example, and use this location instead:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/sysmon.log</location>
</localfile>
```

Place it inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`, then restart the agent:

```bash
sudo systemctl restart wazuh-agent
```

> **Check for an existing entry first.** Agents set up with the Wazuh installer script already collect `/var/log/*.log`, and that pattern also matches `/var/log/sysmon.log`. Look in `ossec.conf` before adding a second entry. I have not checked how the agent handles two entries that match the same file.

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `bad interpreter: /bin/bash^M` or `$'\r': command not found` | Windows line endings in the script | `sed -i 's/\r$//' <script>.sh` (section 2) |
| `Unsupported operating system. This script supports Amazon Linux 2, Amazon Linux 2023, and Ubuntu.` | The OS is not one of the three | Use the manual steps (section 3.3) |
| `This script must be run as root. Please use 'sudo'.` | The script was not run as root | Run it with `sudo` |
| `Config file not found: <path>` or `Unable to access config file URL` | The first argument is wrong | Pass the path of an existing local file |
| `Sysmon is already installed. Remove and reinstall? (y/N)` | Sysmon is installed already | `y` removes it and reinstalls, `n` exits without installing anything (the default config file has already been rewritten) |
| `Rsyslog configuration failed, but Sysmon was installed.` | rsyslog did not restart or is not running | Check `systemctl status rsyslog`, then repeat section 3.1 by hand |
| `sysmon: command not found` | The `sysmonforlinux` package is not installed | Check that the Microsoft repository was added and that `packages.microsoft.com` is reachable |
| `/var/log/sysmon.log` does not exist or stays empty | The rsyslog rule is missing, rsyslog was not restarted, Sysmon is not running, or no event matches your rules | Check `/etc/rsyslog.d/yt-sysmon-log.conf`, restart rsyslog, check `systemctl status sysmon`, then run the test in section 5 |
| `apt-get`, `yum` or `dnf` waits for confirmation during the script | The script installs packages without `-y` | Answer the prompt, or install the prerequisites first with `-y` |

## 9. Notes and known issues

These were found by reading the scripts and the original notes. They were not found by running anything. They are listed so that the guide matches what the files actually do.

1. **"Ubuntu 16.14" is not a valid Ubuntu version.** The original guide says it was tested on "Ubuntu 16.14 / Debian 11". Ubuntu uses `YY.04` and `YY.10` numbers, such as 16.04. Confirm what you tested.
2. **The manual Debian or Ubuntu steps use the Debian 11 repository for both.** The installer script uses an Ubuntu-specific URL, so the Ubuntu variant in section 3.3 comes from the script.
3. **The original deploy command is incomplete.** It shows `sysmon -i /path/…sysmon-linux` with no `.xml` extension and without `-accepteula`. The guide uses the form from the script.
4. **The original guide has two sections called "Verify Installation".** The second one is the Wazuh step, so it is section 7 here.
5. **The notes file names the script `sysmon_intstallv1.sh`.** That is a typo. The files are `sysmon_installv1.sh`, `sysmon_installv1.1.sh` and `sysmon_installv1.2.sh`, and v1.2 is the latest. All three target Amazon Linux 2, Amazon Linux 2023 and Ubuntu.
6. **All three scripts and both config files have Windows line endings.** See section 2.
7. **The v1.2 log message is out of date.** After it writes the configuration, the script logs "Configuration captures all events (onmatch=exclude with no conditions)". The configuration it actually writes uses `include` rules (section 4, option A). The "capture all" description fits only `sysmon-linux-collect-all.xml`.
8. **The script overwrites its configuration on every run.** It deletes and re-creates `/opt/sysmon/yt-sysmon-linux.xml`, even when you pass your own configuration file.
9. **The config URL option is unverified.** The script accepts an `http://` or `https://` URL as the first argument, but then passes it straight to `sysmon -i`. I have not confirmed that Sysmon for Linux downloads a configuration from a URL. Use a local file path.
10. **File names differ between the scripts and this folder.** The scripts create `yt-sysmon-linux.xml` and `yt-sysmon-log.conf` on the host. The matching files in this folder are named `sysmon-linux-collect-all.xml` and `sysmon-syslog.conf`. The first is not a copy of the script's configuration (section 4). The folder's `sysmonconfig-windows-v1.xml` and `v2.xml` are Windows configurations and are not used by any script or by this guide.
11. **The v1.2 script does not set up log rotation.** The rotation in section 6 is a separate manual step, taken from the original notes.
