#!/usr/bin/env bash
#set -euo pipefail

# Universal Wazuh Agent installer (single file)
# - Detects distro/arch, installs agent
# - All inputs are named options: -ahost (agent name), -wm (manager address),
#   -certUrl, -certkeyUrl and -auth (request header, for example Authorization)
# - The manager address is required and validated; there is no built-in default
# - Downloads the agent TLS certificate (and key) from the URLs given as input,
#   or reads them from local files when no URL is given
# - Copies TLS certs to /var/ossec/etc/sslmanager
# - Injects <client>, <syscheck>, and distro-specific <localfile> (journald when available)
# - Idempotent XML edits: no duplicate <localfile> locations
# - Tight, depth-limited permissions (avoid client.keys denial)
# - Enables and restarts wazuh-agent (systemd or SysV)

usage() {
  cat <<USAGE
Usage: $0 -ahost <AGENT_NAME> -wm <MANAGER_ADDRESS> [-certUrl <URL>] [-certkeyUrl <URL>] [-auth <HEADER>]

All inputs are named options. Write each one as "-name value" or "-name=value". They
can appear in any order, and the names are not case-sensitive (-AUTH and -certurl
work too). There are no positional arguments.

  -ahost NAME      REQUIRED. Name of this agent. Letters, digits, '.', '-' and '_',
                   up to 128 characters, starting with a letter or digit.
  -wm ADDRESS      REQUIRED. Host name or IP address (IPv4 or IPv6) of the Wazuh
                   manager that this agent reports to, for example wazuh.example.com
                   or 203.0.113.10. Give it without a scheme (no https://) and
                   without a port: the agent uses 1514/tcp for events and 1515/tcp
                   for enrollment.
  -certUrl URL     Optional. HTTPS URL to download the agent certificate from. It can
                   point to a PEM file, or to an archive (.zip, .tar.gz, .tgz) that
                   holds the certificate and, optionally, the key.
  -certkeyUrl URL  Optional. HTTPS URL of the agent private key (PEM). Not needed
                   when the file behind -certUrl also contains the key, or when the
                   key is available locally (see below).
  -auth HEADER     Optional. Request header sent with the -certUrl and -certkeyUrl
                   downloads, for example -auth="Authorization: Bearer <token>".
                   A value that does not start with a header name and a colon is
                   sent as the value of the Authorization header, so
                   -auth="Bearer <token>" gives the same result. It overrides the
                   URL_AUTH_HEADER variable.

The certificate is downloaded and checked BEFORE the agent is installed. If no
-certUrl is given, the certificate and key are read from local files instead:
the script directory, the current directory, CERT_SRC_DIR, or the paths in
CERT_AGENT_CERT_PATH / CERT_AGENT_KEY_PATH. A key that is not supplied by a URL
is also looked up there.

Env overrides: WAZUH_VERSION, CERT_URL, KEY_URL,
               URL_AUTH_HEADER, URL_CACERT, CERT_SHA256, KEY_SHA256,
               CERT_SRC_DIR, CERT_AGENT_CERT_PATH, CERT_AGENT_KEY_PATH,
               SSL_AGENT_CERT_NAME, SSL_AGENT_KEY_NAME,
               OSSEC_CONF_MODE, OSSEC_ETC_MODE,
               OSSEC_CONF_GROUP_RWX, OSSEC_DEPTH.

  CERT_URL, KEY_URL  Used when -certUrl / -certkeyUrl are not given. The options win.
  URL_AUTH_HEADER  Extra request header for the downloads, for example
                   "Authorization: Bearer <token>". Sent with both downloads.
                   Same as -auth, but kept out of the command line (see below).
  URL_CACERT       CA bundle to trust for the download (internal CA).
  CERT_SHA256      Expected SHA-256 of the file downloaded from -certUrl.
  KEY_SHA256       Expected SHA-256 of the file downloaded from -certkeyUrl.

Only https:// URLs are accepted. The URL and header are passed to curl through
stdin, so curl's own command line does not show them. Do not put credentials in
the URL itself; use -auth, URL_AUTH_HEADER or a signed URL.

Note: a token given with -auth is part of THIS script's command line, so it is
visible in the process list and in shell history, and sudo logs the command line.
On shared hosts, set URL_AUTH_HEADER in the environment instead.

Examples:
  sudo $0 -ahost host-01 -wm wazuh.example.com -certUrl https://files.example.com/agent/sslagent.zip -certkeyUrl https://files.example.com/agent/sslagent.key
  sudo $0 -ahost=host-02 -wm=wazuh.example.com -certUrl=https://files.example.com/agent/bundle.zip -auth="Authorization: Bearer \$TOKEN"
  sudo URL_AUTH_HEADER="Authorization: Bearer \$TOKEN" $0 -ahost host-03 -wm wazuh.example.com -certUrl https://files.example.com/agent/bundle.zip
  sudo CERT_SHA256=<sha256> $0 -ahost host-04 -wm wazuh.example.com -certUrl https://files.example.com/agent/sslagent.cert
  sudo $0 -ahost host-05 -wm 203.0.113.10      # local sslagent.cert / sslagent.key next to the script
  sudo WAZUH_VERSION=4.11.1 $0 -ahost host-06 -wm wazuh.example.com -certUrl https://files.example.com/agent/bundle.tgz
USAGE
}

# The manager address is written into ossec.conf as XML text, so accept only a DNS
# name, an IPv4 address or an IPv6 address. URLs, ports, quotes, < > & and spaces
# are rejected here, before anything on the system is changed.
validate_manager_address() {
  local addr="$1"
  if [[ "$addr" == *://* ]]; then
    echo "[!] The -wm value must be a host name or IP address, not a URL (got: $addr)"
    echo "    Example: -wm wazuh.example.com"
    exit 1
  fi
  if [[ ${#addr} -gt 253 ]]; then
    echo "[!] The -wm value is too long (max 253 characters)."; exit 1
  fi
  # IPv6: hex digits, colons and (for IPv4-mapped forms) dots, with at least one colon
  if [[ "$addr" == *:* && "$addr" =~ ^[0-9A-Fa-f:.]+$ ]]; then return 0; fi
  # DNS name or IPv4: letters, digits, dots and hyphens; no leading/trailing dot or hyphen; no empty label
  if [[ "$addr" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ && "$addr" != *..* ]]; then return 0; fi
  echo "[!] The -wm value is not a valid host name or IP address (got: $addr)"
  echo "    Give the address only, with no port or scheme. Example: -wm wazuh.example.com or -wm 203.0.113.10"
  exit 1
}

# -auth takes a full header line ("Authorization: Bearer <token>") or only the value
# ("Bearer <token>"), which is then sent as the Authorization header. Sets
# URL_AUTH_HEADER. Error messages never print the value, because it is a secret.
set_auth_header() {
  local v="$1"
  if [[ -z "$v" ]]; then
    echo "[!] -auth needs a value, for example -auth=\"Authorization: Bearer <token>\"."; exit 1
  fi
  if [[ "$v" == *$'\n'* || "$v" == *$'\r'* ]]; then
    echo "[!] The -auth value must be a single line."; exit 1
  fi
  if [[ "$v" =~ ^[A-Za-z0-9-]+:[[:space:]]*$ ]]; then
    echo "[!] The -auth header has a name but no value."; exit 1
  fi
  if [[ "$v" =~ ^[A-Za-z0-9-]+:[[:space:]]*[^[:space:]] ]]; then
    URL_AUTH_HEADER="$v"                       # already "Name: value"
  else
    URL_AUTH_HEADER="Authorization: $v"        # value only
  fi
}

# Agent names: letters, digits, '.', '-' and '_', starting with a letter or digit. This
# also catches "-ahost -wm x", where -ahost has no value and swallows the next option.
validate_agent_name() {
  local n="$1"
  if [[ ! "$n" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
    echo "[!] The -ahost value is not a valid agent name (got: $n)"
    echo "    Use letters, digits, '.', '-' and '_' (max 128 characters), starting with a letter or digit."
    exit 1
  fi
}

# ---- Arguments ---- #
# Every input is a named option, written "-name value" or "-name=value", in any order.
# Names are case-insensitive. There are no positional arguments.
AGENT_ARG=""; WAZUH_MANAGER=""; CERT_ARG=""; KEY_ARG=""; AUTH_ARG=""
seen=" "
while [[ $# -gt 0 ]]; do
  opt="${1,,}"
  case "$opt" in
    -h|--help) usage; exit 0 ;;
    -ahost|-wm|-certurl|-certkeyurl|-auth)
      [[ $# -ge 2 ]] || { echo "[!] $1 needs a value."; usage; exit 1; }
      val="$2"; shift 2 ;;
    -ahost=*|-wm=*|-certurl=*|-certkeyurl=*|-auth=*)
      opt="${opt%%=*}"; val="${1#*=}"; shift ;;
    -*) echo "[!] Unknown option: ${1%%=*}"; usage; exit 1 ;;
    *)  echo "[!] Unexpected argument. All inputs are named options: -ahost, -wm, -certUrl, -certkeyUrl, -auth."; usage; exit 1 ;;
  esac
  if [[ -z "$val" ]]; then echo "[!] $opt needs a value."; usage; exit 1; fi
  if [[ "$seen" == *" $opt "* ]]; then echo "[!] $opt was given more than once."; exit 1; fi
  seen+="$opt "
  case "$opt" in
    -ahost)   AGENT_ARG="$val" ;;
    -wm)      WAZUH_MANAGER="$val" ;;
    -certurl) CERT_ARG="$val" ;;
    -certkeyurl)  KEY_ARG="$val" ;;
    -auth)    AUTH_ARG="$val" ;;
  esac
done

if [[ -z "$AGENT_ARG" ]]; then
  echo "[!] The agent name is missing. Pass it with -ahost <AGENT_NAME>."; usage; exit 1
fi
if [[ -z "$WAZUH_MANAGER" ]]; then
  echo "[!] The Wazuh manager address is missing. Pass it with -wm <MANAGER_ADDRESS>."; usage; exit 1
fi
WAZUH_AGENT_NAME="$AGENT_ARG"
CERT_URL="${CERT_ARG:-${CERT_URL:-}}"
KEY_URL="${KEY_ARG:-${KEY_URL:-}}"
validate_agent_name "$WAZUH_AGENT_NAME"
validate_manager_address "$WAZUH_MANAGER"
[[ "$seen" == *" -auth "* ]] && set_auth_header "$AUTH_ARG"
if [[ "$seen" == *" -auth "* && -z "$CERT_URL" && -z "$KEY_URL" ]]; then
  echo "[!] Note: -auth is not used, because no -certUrl or -certkeyUrl was given."
fi

# ---- Defaults ---- #
WAZUH_VERSION="${WAZUH_VERSION:-4.11.1}"

START_DIR="$(pwd -P 2>/dev/null || pwd)"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CERT_SRC_DIR="${CERT_SRC_DIR:-$SCRIPT_DIR}"
CERT_AGENT_CERT_PATH="${CERT_AGENT_CERT_PATH:-}"
CERT_AGENT_KEY_PATH="${CERT_AGENT_KEY_PATH:-}"
SSL_AGENT_CERT_NAME="${SSL_AGENT_CERT_NAME:-sslagent.cert}"
SSL_AGENT_KEY_NAME="${SSL_AGENT_KEY_NAME:-sslagent.key}"
URL_AUTH_HEADER="${URL_AUTH_HEADER:-}"
URL_CACERT="${URL_CACERT:-}"
CERT_SHA256="${CERT_SHA256:-}"
KEY_SHA256="${KEY_SHA256:-}"

CERT_DIR="/var/ossec/etc/sslmanager"
ETC_DIR="/var/ossec/etc"
CONFIG_FILE="${ETC_DIR}/ossec.conf"
BACKUP_FILE="${CONFIG_FILE}.bak.$(date +%Y%m%dT%H%M%SZ)"

OSSEC_CONF_MODE="${OSSEC_CONF_MODE:-640}"
OSSEC_ETC_MODE="${OSSEC_ETC_MODE:-750}"
OSSEC_CONF_GROUP_RWX="${OSSEC_CONF_GROUP_RWX:-0}"
OSSEC_DEPTH="${OSSEC_DEPTH:-7}"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "[!] Required command '$1' not found."; exit 1; }; }
try_cmd() { command -v "$1" >/dev/null 2>&1; }

# Run privileged commands through sudo only when not already root
SUDO=""
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then need_cmd sudo; SUDO="sudo"; fi

# ---- OS detection ---- #
if [[ -r /etc/os-release ]]; then . /etc/os-release; else echo "[!] /etc/os-release not found"; exit 1; fi
OS_FAMILY=""; PM=""; INSTALL_LOCAL_RPM=""
case "${ID_LIKE:-$ID}" in
  *debian*|*ubuntu*) OS_FAMILY="debian"; PM="apt-get" ;;
  *rhel*|*centos*|*fedora*|*almalinux*|*rocky*|*anolis*|*alinux*)
    OS_FAMILY="rhel"
    if try_cmd dnf; then PM="dnf"; INSTALL_LOCAL_RPM="dnf -y install"; else PM="yum"; INSTALL_LOCAL_RPM="yum -y localinstall"; fi ;;
  *amzn*|*amazon*) OS_FAMILY="rhel"; PM="yum"; INSTALL_LOCAL_RPM="yum -y localinstall" ;;
  *)
    case "$ID" in
      debian|ubuntu) OS_FAMILY="debian"; PM="apt-get" ;;
      rhel|centos|fedora|rocky|almalinux|anolis)
        OS_FAMILY="rhel"
        if try_cmd dnf; then PM="dnf"; INSTALL_LOCAL_RPM="dnf -y install"; else PM="yum"; INSTALL_LOCAL_RPM="yum -y localinstall"; fi ;;
      amzn) OS_FAMILY="rhel"; PM="yum"; INSTALL_LOCAL_RPM="yum -y localinstall" ;;
      *) echo "[!] Unsupported OS family: ID=$ID ID_LIKE=${ID_LIKE:-}"; exit 1 ;;
    esac
    ;;
esac
echo "[+] Detected OS: ${PRETTY_NAME:-$ID} (family=${OS_FAMILY}, pm=${PM})"

# ---- Arch detection ---- #
UNAME_ARCH="$(uname -m)"; RPM_ARCH=""; DEB_ARCH=""
case "$UNAME_ARCH" in
  x86_64) RPM_ARCH="x86_64"; DEB_ARCH="amd64" ;;
  aarch64|arm64) RPM_ARCH="aarch64"; DEB_ARCH="arm64" ;;
  armv7l) RPM_ARCH="armhf"; DEB_ARCH="armhf" ;; # Wazuh may not ship armv7 RPMs
  *) echo "[!] Unsupported/unknown architecture: $UNAME_ARCH"; exit 1 ;;
esac
echo "[+] Detected Arch: uname=$UNAME_ARCH"

need_cmd curl
need_cmd awk
need_cmd od

# ---- TLS certificate: download, locate, validate (BEFORE installing the agent) ---- #
# begin: cert-fetch-functions
SRC_CERT=""
SRC_KEY=""

# URL without query string or fragment, safe to print (signed URLs carry tokens there)
redact_url() { local u="$1"; u="${u%%\#*}"; printf '%s' "${u%%\?*}"; }

# Escape a value for a double-quoted string in a curl config file
curl_conf_escape() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; printf '%s' "$s"; }

# Accept only https:// URLs with no credentials, spaces, quotes or backslashes
validate_https_url() {
  local label="$1" url="$2"
  if [[ ! "$url" =~ ^https://[^/?#@[:space:]]+([/?#].*)?$ ]]; then
    echo "[!] $label must be an https:// URL without credentials (got: $(redact_url "$url"))"
    echo "    Use -auth (or URL_AUTH_HEADER) for credentials instead of user:password@host."
    exit 1
  fi
  if [[ "$url" == *[[:space:]]* || "$url" == *'"'* || "$url" == *'\'* ]]; then
    echo "[!] $label contains spaces, quotes or backslashes. Percent-encode them."
    exit 1
  fi
}

# Download $1 to $2. URL and header go to curl on stdin, not on the command line.
download_file() {
  local url="$1" out="$2" label="$3"
  if [[ "$URL_AUTH_HEADER" == *$'\n'* || "$URL_AUTH_HEADER" == *$'\r'* ]]; then
    echo "[!] URL_AUTH_HEADER must be a single line."; exit 1
  fi
  local -a opts=( --proto '=https' --proto-redir '=https' --tlsv1.2 -fsS -L
                  --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 120
                  --max-filesize 5242880 -o "$out" )
  [[ -n "$URL_CACERT" ]] && opts+=( --cacert "$URL_CACERT" )
  if ! {
        printf 'url = "%s"\n' "$url"
        [[ -n "$URL_AUTH_HEADER" ]] && printf 'header = "%s"\n' "$(curl_conf_escape "$URL_AUTH_HEADER")"
        true
      } | curl -K - "${opts[@]}"; then
    echo "[!] Download of the $label failed from $(redact_url "$url")"
    exit 1
  fi
  [[ -s "$out" ]] || { echo "[!] The downloaded $label is empty"; exit 1; }
}

# SHA-256 pin: verify_sha256 <file> <expected-hex or empty> <label>
verify_sha256() {
  local f="$1" want="${2,,}" label="$3" got=""
  [[ -n "$want" ]] || return 0
  if try_cmd sha256sum; then got="$(sha256sum "$f" | awk '{print $1}')"
  elif try_cmd shasum;  then got="$(shasum -a 256 "$f" | awk '{print $1}')"
  elif try_cmd openssl; then got="$(openssl dgst -sha256 "$f" | awk '{print $NF}')"
  else echo "[!] No SHA-256 tool found (sha256sum, shasum or openssl)."; exit 1; fi
  if [[ "$got" != "$want" ]]; then
    echo "[!] SHA-256 mismatch for the $label"
    echo "    expected: $want"
    echo "    actual  : $got"
    exit 1
  fi
  echo "[+] SHA-256 of the $label matches"
}

# Print zip, gzip, pem or unknown, based on the first bytes / content
file_kind() {
  local magic
  magic="$(od -An -tx1 -N4 "$1" 2>/dev/null | tr -d ' \n')"
  case "$magic" in
    504b0304*|504b0506*) echo zip; return ;;
    1f8b*) echo gzip; return ;;
  esac
  if grep -q -- '-----BEGIN ' "$1" 2>/dev/null; then echo pem; else echo unknown; fi
}

# Put the content of a download into $dest (PEM copied, archive extracted)
unpack_download() {
  local file="$1" dest="$2" label="$3" kind
  kind="$(file_kind "$file")"
  mkdir -p "$dest"
  case "$kind" in
    pem)  cp -f "$file" "$dest/downloaded.pem" ;;
    zip)
      if try_cmd unzip; then unzip -qq -o "$file" -d "$dest" || { echo "[!] Could not extract the $label (zip)"; exit 1; }
      elif try_cmd python3; then python3 -m zipfile -e "$file" "$dest" || { echo "[!] Could not extract the $label (zip)"; exit 1; }
      else echo "[!] unzip (or python3) is required to extract a .zip"; exit 1; fi ;;
    gzip) tar -xzf "$file" -C "$dest" || { echo "[!] Could not extract the $label (tar.gz)"; exit 1; } ;;
    *)    echo "[!] The $label is not a PEM file, .zip or .tar.gz (is the URL a login or error page?)"; exit 1 ;;
  esac
}

# Find a PEM certificate or private key below a directory (regular files only).
# pick_pem <dir> <cert|key>; prints the path or returns 1.
pick_pem() {
  local dir="$1" type="$2" re name f
  local -a names
  if [[ "$type" == "cert" ]]; then
    re='-----BEGIN (TRUSTED )?CERTIFICATE-----'
    names=( "$SSL_AGENT_CERT_NAME" "sslagent.crt" "cert.pem" "sslagent.pem" "downloaded.pem" )
  else
    re='-----BEGIN ([A-Z]+ )?PRIVATE KEY-----'
    names=( "$SSL_AGENT_KEY_NAME" "key.pem" "sslagent.pem" "downloaded.pem" )
  fi
  for name in "${names[@]}"; do
    while IFS= read -r f; do
      if grep -qE -- "$re" "$f" 2>/dev/null; then printf '%s\n' "$f"; return 0; fi
    done < <(find "$dir" -type f -name "$name" 2>/dev/null | sort)
  done
  while IFS= read -r f; do
    if grep -qE -- "$re" "$f" 2>/dev/null; then printf '%s\n' "$f"; return 0; fi
  done < <(find "$dir" -type f -size -64k 2>/dev/null | sort)
  return 1
}

# First existing file from a list of names inside a directory
_pick_first() {
  local base="$1"; shift
  local name
  for name in "$@"; do
    if [[ -f "$base/$name" ]]; then
      printf '%s\n' "$base/$name"
      return 0
    fi
  done
  return 1
}

# Fill SRC_CERT / SRC_KEY from local files when they are still empty
discover_local_certs() {
  local search_roots=() _script_dir _cert_src
  _script_dir="$(cd -- "${SCRIPT_DIR:-.}" 2>/dev/null && pwd -P || echo "${SCRIPT_DIR:-.}")"
  _cert_src="${CERT_SRC_DIR:-}"

  search_roots+=("$_script_dir")
  [[ -n "$START_DIR" && "$START_DIR" != "$_script_dir" ]] && search_roots+=("$START_DIR")
  [[ -n "$_cert_src" && "$_cert_src" != "$_script_dir" && "$_cert_src" != "$START_DIR" ]] && search_roots+=("$_cert_src")

  local cert_names=("$SSL_AGENT_CERT_NAME" "sslagent.crt" "cert.pem" "sslagent.pem")
  local key_names=("$SSL_AGENT_KEY_NAME"  "key.pem"        "sslagent.pem")

  # Explicit paths fill whatever the URLs did not supply
  [[ -z "$SRC_CERT" && -n "$CERT_AGENT_CERT_PATH" ]] && SRC_CERT="$CERT_AGENT_CERT_PATH"
  [[ -z "$SRC_KEY"  && -n "$CERT_AGENT_KEY_PATH"  ]] && SRC_KEY="$CERT_AGENT_KEY_PATH"

  local root one_pem
  if [[ -z "$SRC_CERT" || -z "$SRC_KEY" ]]; then
    for root in "${search_roots[@]}"; do
      [[ -z "$SRC_CERT" ]] && SRC_CERT="$(_pick_first "$root" "${cert_names[@]}")" || true
      [[ -z "$SRC_KEY"  ]] && SRC_KEY="$(_pick_first "$root" "${key_names[@]}")"   || true
      [[ -n "$SRC_CERT" && -n "$SRC_KEY" ]] && break
    done
  fi

  # Still missing: try a single combined PEM
  if [[ -z "$SRC_CERT" || -z "$SRC_KEY" ]]; then
    for root in "${search_roots[@]}"; do
      one_pem="$(_pick_first "$root" "sslagent.pem" "cert.pem" "key.pem")" || true
      if [[ -n "$one_pem" ]]; then
        [[ -z "$SRC_CERT" ]] && SRC_CERT="$one_pem"
        [[ -z "$SRC_KEY"  ]] && SRC_KEY="$one_pem"
        break
      fi
    done
  fi
  LOCAL_SEARCH_ROOTS=("${search_roots[@]}")
}

# Check the pair when openssl is available: valid PEM, key readable, key matches cert
validate_ssl_pair() {
  if ! try_cmd openssl; then
    echo "[!] openssl not found: the certificate and key were not validated."
    return 0
  fi
  if ! openssl x509 -in "$SRC_CERT" -noout >/dev/null 2>&1; then
    echo "[!] $SRC_CERT is not a valid PEM certificate."; exit 1
  fi
  if ! openssl x509 -in "$SRC_CERT" -noout -checkend 0 >/dev/null 2>&1; then
    echo "[!] Warning: the certificate has expired ($(openssl x509 -in "$SRC_CERT" -noout -enddate 2>/dev/null))."
  fi
  if ! openssl pkey -in "$SRC_KEY" -noout -passin pass: </dev/null >/dev/null 2>&1; then
    echo "[!] $SRC_KEY is not a readable PEM private key (encrypted keys are not supported by the agent)."; exit 1
  fi
  local c_pub k_pub
  c_pub="$(openssl x509 -in "$SRC_CERT" -noout -pubkey 2>/dev/null | openssl sha256 2>/dev/null)"
  k_pub="$(openssl pkey -in "$SRC_KEY" -pubout -passin pass: </dev/null 2>/dev/null | openssl sha256 2>/dev/null)"
  if [[ -z "$c_pub" || "$c_pub" != "$k_pub" ]]; then
    echo "[!] The private key does not match the certificate."; exit 1
  fi
  echo "[+] Certificate and key are valid and match"
}

fetch_ssl_certs() {
  echo "[+] Preparing TLS certificate and key ..."
  local old_umask base
  old_umask="$(umask)"; umask 077
  base="$WORKDIR/certs"; mkdir -p "$base/dl" "$base/cert" "$base/key"

  if [[ -n "$CERT_URL" ]]; then
    validate_https_url "-certUrl" "$CERT_URL"
    echo "[+] Downloading certificate from $(redact_url "$CERT_URL") ..."
    download_file "$CERT_URL" "$base/dl/cert.download" "certificate"
    verify_sha256 "$base/dl/cert.download" "$CERT_SHA256" "certificate download"
    unpack_download "$base/dl/cert.download" "$base/cert" "certificate download"
    SRC_CERT="$(pick_pem "$base/cert" cert)" || {
      echo "[!] No PEM certificate found in the file downloaded from -certUrl."; exit 1; }
    # The same download may also carry the key (archive or combined PEM)
    if [[ -z "$KEY_URL" ]]; then SRC_KEY="$(pick_pem "$base/cert" key)" || SRC_KEY=""; fi
  elif [[ -n "$CERT_SHA256" ]]; then
    echo "[!] CERT_SHA256 is set but there is no -certUrl."; exit 1
  fi

  if [[ -n "$KEY_URL" ]]; then
    validate_https_url "-certkeyUrl" "$KEY_URL"
    echo "[+] Downloading private key from $(redact_url "$KEY_URL") ..."
    download_file "$KEY_URL" "$base/dl/key.download" "private key"
    verify_sha256 "$base/dl/key.download" "$KEY_SHA256" "private key download"
    unpack_download "$base/dl/key.download" "$base/key" "private key download"
    SRC_KEY="$(pick_pem "$base/key" key)" || {
      echo "[!] No PEM private key found in the file downloaded from -certkeyUrl."; exit 1; }
  elif [[ -n "$KEY_SHA256" ]]; then
    echo "[!] KEY_SHA256 is set but there is no -certkeyUrl."; exit 1
  fi

  # Anything the URLs did not supply comes from local files, as before
  if [[ -z "$SRC_CERT" || -z "$SRC_KEY" ]]; then
    LOCAL_SEARCH_ROOTS=()
    discover_local_certs
    [[ -n "$CERT_URL" && -n "$SRC_KEY" && "$SRC_KEY" != "$base"/* ]] && \
      echo "[+] No key in the download: using local key $SRC_KEY"
  fi

  if [[ -z "$SRC_CERT" || -z "$SRC_KEY" || ! -f "$SRC_CERT" || ! -f "$SRC_KEY" ]]; then
    echo "[!] TLS files not found."
    echo "    Resolved cert: ${SRC_CERT:-<none>}"
    echo "    Resolved key : ${SRC_KEY:-<none>}"
    if [[ ${#LOCAL_SEARCH_ROOTS[@]} -gt 0 ]]; then
      echo "    Searched locally (in order):"
      printf '      - %s\n' "${LOCAL_SEARCH_ROOTS[@]}"
    fi
    echo "    Tip: pass -certUrl (and -certkeyUrl), keep $SSL_AGENT_CERT_NAME + $SSL_AGENT_KEY_NAME next to the script,"
    echo "         or set CERT_AGENT_CERT_PATH / CERT_AGENT_KEY_PATH."
    exit 1
  fi

  validate_ssl_pair
  umask "$old_umask"
}

# Copy the prepared files into the agent directory (after the package is installed)
install_ssl_certs() {
  echo "[+] Installing TLS certificate and key ..."
  $SUDO mkdir -p "${CERT_DIR}"
  $SUDO cp -f "$SRC_CERT" "${CERT_DIR}/sslagent.cert"
  $SUDO cp -f "$SRC_KEY"  "${CERT_DIR}/sslagent.key"

  # Tight perms (CentOS 7 friendly)
  $SUDO chown -R wazuh:wazuh "${CERT_DIR}" || true
  $SUDO chmod 700 "${CERT_DIR}" || true
  $SUDO chmod 600 "${CERT_DIR}/sslagent.cert" "${CERT_DIR}/sslagent.key" || true

  # SELinux relabel if enforcing (CentOS 7)
  if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then
    command -v restorecon >/dev/null 2>&1 && $SUDO restorecon -Rv "${CERT_DIR}" || true
  fi
  echo "[+] TLS certificates installed at ${CERT_DIR}/(sslagent.cert|sslagent.key)"
}
# end: cert-fetch-functions

# ---- Work directory ---- #
WORKDIR="$(mktemp -d /tmp/wazuh.XXXXXX)"; trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR" || exit 1

# Fail early: get and check the certificate before touching the system
fetch_ssl_certs

# ---- Install agent ---- #
if [[ "$OS_FAMILY" == "debian" ]]; then
  PKG="wazuh-agent_${WAZUH_VERSION}-1_${DEB_ARCH}.deb"
  URL="https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/${PKG}"
  echo "[+] Downloading ${PKG} ..."; curl -fS --retry 3 --retry-delay 2 -L "$URL" -o "$PKG"
  [[ -s "$PKG" ]] || { echo "[!] Download failed"; exit 1; }
  echo "[+] Installing (apt-get) ..."
  $SUDO ${PM} update -y
  $SUDO ${PM} install -y "./${PKG}"
  (command -v apt-mark >/dev/null 2>&1 && $SUDO apt-mark hold wazuh-agent) || true
else
  PKG="wazuh-agent-${WAZUH_VERSION}-1.${RPM_ARCH}.rpm"
  URL="https://packages.wazuh.com/4.x/yum/${PKG}"
  echo "[+] Downloading ${PKG} ..."; curl -fS --retry 3 --retry-delay 2 -L "$URL" -o "$PKG"
  [[ -s "$PKG" ]] || { echo "[!] Download failed"; exit 1; }
  echo "[+] Installing (${PM}) ..."; $SUDO ${INSTALL_LOCAL_RPM} "./${PKG}"
fi

# ---- TLS certs ---- #
install_ssl_certs

# ---- Permissions (depth-limited) ---- #
set_permissions() {
  if [[ -d "$CERT_DIR" ]]; then
    $SUDO chown -R wazuh:wazuh "$CERT_DIR" || true
    $SUDO chmod 700 "$CERT_DIR" || true
    $SUDO chmod 600 "$CERT_DIR"/sslagent.cert "$CERT_DIR"/sslagent.key 2>/dev/null || true
  fi
  $SUDO chown root:wazuh "/var/ossec/etc/ossec.conf" || true
  $SUDO chmod 640 /var/ossec/etc/ossec.conf || true
}
set_permissions "$OSSEC_DEPTH"

# ---- XML helpers ---- #
ensure_single_ossec_root() {
  $SUDO awk 'BEGIN{open=0}
    /<[[:space:]]*ossec_config[[:space:]]*>/{ if(open){next}else{open=1; print; next} }
    {print}' "$CONFIG_FILE" | $SUDO tee "${CONFIG_FILE}.tmp" >/dev/null
  $SUDO mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"

  local closings
  closings="$(grep -c -E '</[[:space:]]*ossec_config[[:space:]]*>' "$CONFIG_FILE" || true)"
  if [[ "${closings:-0}" -gt 1 ]]; then
    $SUDO awk -v nskip=$((closings-1)) '
      /<\/[[:space:]]*ossec_config[[:space:]]*>/ { if(nskip>0){nskip--; next} }
      { print }' "$CONFIG_FILE" | $SUDO tee "${CONFIG_FILE}.tmp" >/dev/null
    $SUDO mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
  fi
}


strip_injected_blocks() {
  $SUDO awk '
    BEGIN{skip=0}
    /<client>/ { if($0 ~ /<client>/){skip=1} }
    skip==1 { if($0 ~ /<\/client>/){skip=0; next} else {next} }
    /<syscheck>/ { if($0 ~ /<syscheck>/){skip=2} }
    skip==2 { if($0 ~ /<\/syscheck>/){skip=0; next} else {next} }
    { print }' "$CONFIG_FILE" | $SUDO tee "${CONFIG_FILE}.tmp" >/dev/null
  $SUDO mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

inject_block_before_close() {
  local block_file="$1"
  local cf="$CONFIG_FILE"
  local tmp; tmp="$(mktemp /tmp/ossec.inject.XXXXXX)"

  local last_ln
  last_ln="$(grep -n -E '</[[:space:]]*ossec_config[[:space:]]*>' "$cf" | tail -n1 | cut -d: -f1)"
  [[ -n "$last_ln" ]] || { echo "[!] Could not find </ossec_config> in $cf"; rm -f "$tmp"; return 1; }

  head -n $(( last_ln - 1 )) "$cf" > "$tmp"
  cat "$block_file" >> "$tmp"; echo >> "$tmp"
  tail -n +"$last_ln" "$cf" >> "$tmp"
  $SUDO mv "$tmp" "$cf"
}

# Return 0 if there is already a <localfile> whose <location> equals $1
# Uses xmlstarlet when available; falls back to awk (handles multi-line).
# The awk fallback avoids gawk-only features so it also works with mawk (Debian/Ubuntu).
localfile_has_location() {
  local needle="$1"
  if command -v xmlstarlet >/dev/null 2>&1; then
    local count
    count="$(xmlstarlet sel -t -v "count(/ossec_config/localfile[normalize-space(location)='${needle}'])" "$CONFIG_FILE" 2>/dev/null || echo 0)"
    [[ "${count:-0}" -gt 0 ]]
    return
  fi
  awk -v needle="$needle" '
    BEGIN{inlf=0; found=0}
    /<localfile[[:space:]>]/ {inlf=1}
    inlf {
      if (match($0, /<location>[[:space:]]*[^<]+[[:space:]]*<\/location>/)) {
        loc=substr($0, RSTART, RLENGTH)
        sub(/^<location>[[:space:]]*/, "", loc)
        sub(/[[:space:]]*<\/location>$/, "", loc)
        if (loc==needle) {found=1; exit}
      }
    }
    /<\/localfile>/ {inlf=0}
    END{ exit(found?0:1) }
  ' "$CONFIG_FILE"
}

build_client_syscheck_block() {
  local f; f="$(mktemp /tmp/ossec.client.XXXXXX)"
  cat >"$f" <<XML
  <client>
    <server>
      <address>${WAZUH_MANAGER}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>default</config-profile>
    <enrollment>
      <agent_certificate_path>${CERT_DIR}/sslagent.cert</agent_certificate_path>
      <agent_key_path>${CERT_DIR}/sslagent.key</agent_key_path>
      <port>1515</port>
    </enrollment>
  </client>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories realtime="yes" check_all="yes" report_changes="yes">/etc</directories>
    <directories realtime="yes" check_all="yes">/usr/bin</directories>
    <directories realtime="yes" check_all="yes">/usr/sbin</directories>
    <directories realtime="yes" check_all="yes">/sbin</directories>
    <directories realtime="yes" check_all="yes">/bin</directories>
    <directories realtime="yes" check_all="yes">/boot</directories>
    <directories realtime="yes" check_all="yes">/usr/local/bin</directories>
    <directories realtime="yes" check_all="yes">/usr/local/sbin</directories>
  </syscheck>
XML
  echo "$f"
}

build_and_maybe_inject_localfiles() {
  local tmp; tmp="$(mktemp /tmp/ossec.localfiles.XXXXXX)"

  # Detect journald presence
  local have_journald=0
  if command -v journalctl >/dev/null 2>&1 && pgrep -x systemd-journald >/dev/null 2>&1; then
    have_journald=1
  fi

  # 1) Always prefer native journald input if available
  if (( have_journald )); then
    if ! localfile_has_location "journald"; then
      cat >>"$tmp" <<'XML'
  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>
XML
    fi
  fi

  # 2) Select ordered file locations per OS family/version (your spec)
  local locations=()

  if [[ "$OS_FAMILY" == "debian" ]]; then
    # Debian (Ubuntu)
    # /var/log/*.log (/var/log/auth.log, /var/log/kern.log)
    # /var/log/wtmp
    # /var/log/syslog
    # /var/log/lastlog
    # /var/log/faillog
    locations=( "/var/log/*.log" "/var/log/wtmp" "/var/log/syslog" "/var/log/lastlog" )

  else
    # RHEL family — branch by ID and VERSION_ID
    # Normalize VERSION_ID to first number part (e.g., "9", "8", "7", "2", "2023")
    local ver="${VERSION_ID:-}"
    ver="${ver%%.*}"   # keep major only, e.g., "8.9" -> "8"

    if [[ "$ID" == "amzn" ]]; then
      # RHEL (Amazon Linux 2, 2023)
      # /var/log/*.log
      # /var/log/wtmp
      # /var/log/lastlog
      # /var/log/faillog
      # /var/log/journal
      locations=( "/var/log/*.log" "/var/log/wtmp" "/var/log/lastlog" "/var/log/secure")
      # Add /var/log/journal only if journald NOT in use (binary journal is handled above)

    elif [[ "$ID" == "centos" && "$ver" == "9" ]]; then
      # RHEL (CentOS 9)
      # /var/log/*.log
      # /var/log/wtmp
      # /var/log/journal
      # /var/log/lastlog
      # /var/log/faillog
      locations=( "/var/log/*.log" "/var/log/wtmp" )

      locations+=( "/var/log/lastlog" )

    else
      # RHEL (CentOS 6,7,8)
      # /var/log/*.log
      # /var/log/wtmp
      # /var/log/secure
      # /var/log/messages
      # /var/log/lastlog
      # /var/log/faillog
      locations=( "/var/log/*.log" "/var/log/wtmp" "/var/log/secure" "/var/log/messages" "/var/log/lastlog" )
    fi
  fi

  # 3) Insert locations in given order if not already present
  local loc
  for loc in "${locations[@]}"; do
    if ! localfile_has_location "$loc"; then
      cat >>"$tmp" <<XML
  <localfile>
    <log_format>syslog</log_format>
    <location>${loc}</location>
  </localfile>
XML
    fi
  done

  # 4) Commit once (keeps the ossec.conf write atomic)
  if [[ -s "$tmp" ]]; then
    inject_block_before_close "$tmp"
  fi
  rm -f "$tmp"
}

validate_xml_if_possible() {
  if command -v xmllint >/dev/null 2>&1; then
    xmllint --noout "$CONFIG_FILE" && echo "[+] xmllint: ossec.conf is well-formed"
  elif command -v xmlstarlet >/dev/null 2>&1; then
    xmlstarlet val -e "$CONFIG_FILE" && echo "[+] xmlstarlet: ossec.conf is well-formed" || true
  fi
}

# ---- Backup & modify ossec.conf ---- #
echo "[+] Backing up ${CONFIG_FILE} -> ${BACKUP_FILE}"
$SUDO cp -a "$CONFIG_FILE" "$BACKUP_FILE"

ensure_single_ossec_root
strip_injected_blocks
client_block_file="$(build_client_syscheck_block)"; inject_block_before_close "$client_block_file"; rm -f "$client_block_file"
build_and_maybe_inject_localfiles
validate_xml_if_possible

# ---- Final permissions ---- #
set_permissions "$OSSEC_DEPTH"

# ---- Service control ---- #
start_agent() {
  if command -v systemctl >/dev/null 2>&1 && pidof systemd >/dev/null 2>&1; then
    echo "[+] Enabling and restarting wazuh-agent (systemd) ..."
    $SUDO systemctl daemon-reload || true
    $SUDO systemctl enable wazuh-agent || true
    $SUDO systemctl restart wazuh-agent || true
    sleep 2
    $SUDO systemctl --no-pager --full status wazuh-agent || true
  else
    echo "[+] Starting wazuh-agent (SysV/init) ..."
    if [[ -x /etc/init.d/wazuh-agent ]]; then
      $SUDO /etc/init.d/wazuh-agent restart || $SUDO /etc/init.d/wazuh-agent start || true
      sleep 2
      $SUDO tail -n 200 /var/ossec/logs/ossec.log || true
    else
      echo "[!] wazuh-agent service script not found."
    fi
  fi
}

start_agent
$SUDO tail -n 200 /var/ossec/logs/ossec.log || true
echo "[+] Done."
