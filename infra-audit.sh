#!/usr/bin/env bash
# =============================================================================
#  infra_audit.sh  -  audit an EXISTING server (Docker / Kubernetes) over SSH
#
#  Run it from your Mac, Linux, WSL, or Windows Git Bash. Put your *.pem key in
#  the SAME FOLDER as this script. Nothing needs to be installed on the server.
#
#  What it does (one report file per requirement, saved in ./audit_reports/):
#   1  Logs in with the .pem (tries every *.pem and the usual default users)
#   2  01_instance_resources.txt    CPU / RAM / storage of the instance
#   3  02_images_pods_logs.txt      biggest images / pods / logs, in use?, safe to delete?
#   4  03_ports_licenses.txt        image port bindings + licence info
#   5  04_network_outbound.txt      network + outbound calls (incl. container traffic)
#   6  05_logins.txt                how many IPs logged in, and when
#   7  06_image_updates.txt         newer image? pull it, keep the previous version
#   8  07_connection_health.txt     packet loss, retransmits, repeated connections
#      00_summary.txt               findings ranked CRIT / WARN / INFO
#
#  SAFETY: steps 2-6 and 8 are read-only. Nothing is ever deleted.
#          Step 7 pulls newer images (old image is tagged "rollback-*" and kept).
#          Containers are only replaced if you pass --apply; the old container is
#          then kept (stopped) until a human removes it, with automatic rollback
#          if the new one does not become healthy.
#
#  Usage:   ./infra_audit.sh <host | user@host> [more hosts] [options]
#  Windows: use Git Bash (Git for Windows) or WSL. If you edited this file on
#           Windows and get odd errors, fix line endings:  sed -i 's/\r$//' infra_audit.sh
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS="$(date +%Y%m%d_%H%M%S)"
OUT_ROOT="$SCRIPT_DIR/audit_reports"
SSH_PORT=22
SSH_USER=""
KEY_ARG=""
APPLY=0
FAIL_ON=""
LOCAL_MODE=0
HOSTS=()
KEY_COPIES=()
TMP_DIR=""
CUR_HOST=""; CUR_USER=""; CUR_KEY=""
DEFAULT_USERS="ec2-user ubuntu admin centos debian fedora bitnami root"
SSH_OPTS=(-o BatchMode=yes -o IdentitiesOnly=yes -o PreferredAuthentications=publickey
          -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10
          -o ServerAliveInterval=15 -o ServerAliveCountMax=6 -o LogLevel=ERROR)

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '[%s] WARN: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf '[%s] ERROR: %s\n' "$(date +%H:%M:%S)" "$*" >&2; exit 1; }

usage() {
cat <<'USAGE_EOF'
infra_audit.sh - audit an existing server over SSH using the .pem key in this folder

USAGE
  ./infra_audit.sh <host | user@host> [more hosts...] [options]

OPTIONS
  -u, --user USER   SSH user. If omitted, tries: ec2-user ubuntu admin centos debian fedora bitnami root
  -k, --key FILE    Key to use. If omitted, every *.pem next to this script is tried
  -p, --port N      SSH port (default 22)
  -o, --out DIR     Report folder (default: ./audit_reports)
      --apply       Step 7: after pulling a newer image ALSO replace the running container
                    (old container + old image are kept; auto-rollback if unhealthy).
                    Without this flag, step 7 only pulls and preserves.
      --fail-on LVL Exit with code 3 if the summary has findings at LVL or above
                    (crit | warn). For CI pipelines. Reports are still saved.
      --local       Run the checks on THIS Linux machine instead of over SSH
  -h, --help        This help

ENV: AUDIT_HOST=<host> can be used instead of a positional host.
USAGE_EOF
}

cleanup() { [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"; }


# --------------------------------------------------------------------------
#  SSH helpers
# --------------------------------------------------------------------------
rssh() { ssh "${SSH_OPTS[@]}" -i "$CUR_KEY" -p "$SSH_PORT" "${CUR_USER}@${CUR_HOST}" "$@"; }

# prints exactly one of:  OK | AUTH | FATAL:<message>
try_login() {   # $1=user $2=key $3=host
  local out attempt=1 errf="$TMP_DIR/ssh_err.txt" err
  while [ "$attempt" -le 3 ]; do
    : > "$errf"
    out="$(ssh "${SSH_OPTS[@]}" -i "$2" -p "$SSH_PORT" "$1@$3" 'echo AUDIT_OK' 2>"$errf" </dev/null)"
    if [ "$out" = "AUDIT_OK" ]; then echo OK; return 0; fi
    err="$(tr '\r\n' '  ' < "$errf")"
    case "$err" in
      *"HOST IDENTIFICATION HAS CHANGED"*|*"Host key verification failed"*)
        echo "FATAL:Host key for $3 changed or could not be verified. NOT overriding (possible MITM). Fix ~/.ssh/known_hosts yourself if the server was rebuilt."; return 0 ;;
      *"Permission denied"*|*"UNPROTECTED PRIVATE KEY"*|*"invalid format"*|*"Load key"*|*"no mutual signature"*|*"No supported authentication"*)
        echo AUTH; return 0 ;;
      *"timed out"*|*"refused"*|*"No route"*|*"Could not resolve"*|*"unreachable"*|*"reset by peer"*|*"closed by remote"*|*"banner exchange"*|*"Connection closed"*)
        if [ "$attempt" -ge 3 ]; then echo "FATAL:Cannot reach $3:$SSH_PORT after 3 tries (${err:-no detail}). Check IP, security group / firewall, and that the instance is running."; return 0; fi
        sleep $((attempt * 3)) ;;
      *) echo AUTH; return 0 ;;
    esac
    attempt=$((attempt + 1))
  done
  echo "FATAL:unexpected SSH failure for $3"
}
