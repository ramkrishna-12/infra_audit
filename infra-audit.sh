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

prepare_keys() {
  local k i=0 dst
  local cands=()
  if [ -n "$KEY_ARG" ]; then
    [ -f "$KEY_ARG" ] || die "Key file not found: $KEY_ARG"
    cands+=("$KEY_ARG")
  else
    shopt -s nullglob nocaseglob
    for k in "$SCRIPT_DIR"/*.pem; do [ -f "$k" ] && cands+=("$k"); done
    shopt -u nullglob nocaseglob
  fi
  [ "${#cands[@]}" -gt 0 ] || die "No .pem file found in $SCRIPT_DIR (put your key next to this script or use -k FILE)."
  for k in "${cands[@]}"; do
    if ! grep -q 'PRIVATE KEY' "$k" 2>/dev/null; then warn "Skipping '$k': does not look like a private key."; continue; fi
    grep -q 'ENCRYPTED' "$k" 2>/dev/null && warn "'$k' is passphrase-protected; BatchMode cannot prompt. Load it first with: ssh-add '$k'"
    i=$((i + 1)); dst="$TMP_DIR/key$i.pem"
    tr -d '\r' < "$k" > "$dst" || die "Cannot copy key $k"      # strips Windows CRLF
    chmod 600 "$dst" 2>/dev/null
    case "$(ls -ld "$dst" 2>/dev/null | cut -c1-10)" in
      "-rw-------") : ;;
      *) warn "Could not restrict key permissions on this filesystem; ssh may refuse the key. On Windows run from Git Bash or from WSL (not /mnt/c)." ;;
    esac
    KEY_COPIES+=("$dst")
  done
  [ "${#KEY_COPIES[@]}" -gt 0 ] || die "No usable private key found."
  log "Keys to try: ${#KEY_COPIES[@]}"
}

# --------------------------------------------------------------------------
#  Audit one host
# --------------------------------------------------------------------------
audit_host() {
  local target="$1" host user list u k res rdir ldir rc fetch_rc tar_rc applyflag pst
  user="$SSH_USER"
  case "$target" in
    *@*) user="${target%%@*}"; host="${target#*@}" ;;
    *)   host="$target" ;;
  esac
  [ -n "$host" ] || { warn "Empty host in '$target'"; return 1; }
  if [ -n "$user" ]; then list="$user"; else list="$DEFAULT_USERS"; fi

  CUR_HOST="$host"; CUR_USER=""; CUR_KEY=""
  log "================ $host ================"
  log "[login] trying key(s) x user(s) ..."
  for u in $list; do
    for k in "${KEY_COPIES[@]}"; do
      res="$(try_login "$u" "$k" "$host")"
      case "$res" in
        OK)      CUR_USER="$u"; CUR_KEY="$k"; break 2 ;;
        FATAL:*) warn "${res#FATAL:}"; return 1 ;;
        *)       : ;;
      esac
    done
  done
  if [ -z "$CUR_USER" ]; then
    warn "No working user/key combination for $host (tried users: $list). Use -u USER / -k KEY."
    warn "Last ssh error: $(tr '\r\n' '  ' < "$TMP_DIR/ssh_err.txt" 2>/dev/null | cut -c1-300)"
    case "$(cat "$TMP_DIR/ssh_err.txt" 2>/dev/null)" in
      *UNPROTECTED*|*"bad permissions"*) warn "The key file permissions are too open. On Windows run this from WSL (inside your Linux home, not /mnt/c) or Git Bash." ;;
    esac
    return 1
  fi
  log "[login] OK as '$CUR_USER'"

  rdir="/tmp/infra_audit_${TS}_$$"
  ldir="$OUT_ROOT/${host}_${TS}"
  mkdir -p "$ldir" || { warn "Cannot create $ldir"; return 1; }

  emit_remote_script > "$TMP_DIR/audit_remote.sh" || { warn "Cannot build remote payload"; return 1; }
  log "[upload] sending audit payload ..."
  if ! rssh "mkdir -p '$rdir/report' && cat > '$rdir/audit.sh' && chmod 700 '$rdir/audit.sh'" < "$TMP_DIR/audit_remote.sh"; then
    warn "Upload failed (is /tmp writable on the server?)"; return 1
  fi

  applyflag=""; [ "$APPLY" = 1 ] && applyflag="--apply"
  log "[run] executing on server (this can take a few minutes) ..."
  rssh "bash '$rdir/audit.sh' --out '$rdir/report' $applyflag" </dev/null 2>&1 | tee "$ldir/run.log"
  rc="${PIPESTATUS[0]}"
  [ "${rc:-1}" -ne 0 ] && warn "Remote audit exited with code $rc (partial results are still fetched)."

  log "[fetch] downloading reports ..."
  rssh "tar -C '$rdir/report' -cf - ." </dev/null | tar -xf - -C "$ldir"
  pst=("${PIPESTATUS[@]}"); fetch_rc="${pst[0]}"; tar_rc="${pst[1]}"
  if [ "$fetch_rc" -ne 0 ] || [ "$tar_rc" -ne 0 ] || [ ! -s "$ldir/00_summary.txt" ]; then
    warn "Fetch incomplete. Reports remain on the server in $rdir/report (copy with scp -i KEY -r)."
    return 1
  fi
  rssh "rm -rf '$rdir'" </dev/null || warn "Could not remove $rdir on the server (harmless; it is under /tmp)."

  log "DONE. Reports in: $ldir"
  echo
  sed -n '1,70p' "$ldir/00_summary.txt"
  if [ -n "$FAIL_ON" ]; then
    local pat='^\[CRIT\]'; [ "$FAIL_ON" = "warn" ] && pat='^\[(CRIT|WARN)\]'
    if grep -Eq "$pat" "$ldir/00_summary.txt"; then
      warn "$host: findings at '$FAIL_ON' level or above (--fail-on)."; return 3
    fi
  fi
  return 0
}

# --------------------------------------------------------------------------
#  main
# --------------------------------------------------------------------------
main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -H|--host)  [ $# -ge 2 ] || die "$1 needs a value"; HOSTS+=("$2"); shift 2 ;;
      -u|--user)  [ $# -ge 2 ] || die "$1 needs a value"; SSH_USER="$2"; shift 2 ;;
      -k|--key)   [ $# -ge 2 ] || die "$1 needs a value"; KEY_ARG="$2"; shift 2 ;;
      -p|--port)  [ $# -ge 2 ] || die "$1 needs a value"; SSH_PORT="$2"; shift 2 ;;
      -o|--out)   [ $# -ge 2 ] || die "$1 needs a value"; OUT_ROOT="$2"; shift 2 ;;
      --apply)    APPLY=1; shift ;;
      --fail-on)  [ $# -ge 2 ] || die "$1 needs a value"; FAIL_ON="$2"; shift 2
                  case "$FAIL_ON" in crit|warn) : ;; *) die "--fail-on must be 'crit' or 'warn'" ;; esac ;;
      --local)    LOCAL_MODE=1; shift ;;
      -h|--help)  usage; exit 0 ;;
      -*)         die "Unknown option: $1 (try --help)" ;;
      *)          HOSTS+=("$1"); shift ;;
    esac
  done
  case "$SSH_PORT" in ''|*[!0-9]*) die "Port must be a number" ;; esac
  mkdir -p "$OUT_ROOT" || die "Cannot create $OUT_ROOT"

  TMP_DIR="$(mktemp -d "${HOME:-/tmp}/.infra_audit.XXXXXX")" || die "Cannot create temp dir"
  trap cleanup EXIT
  trap 'exit 130' INT TERM

  if [ "$LOCAL_MODE" = 1 ]; then
    [ "$(uname -s)" = "Linux" ] || die "--local needs a Linux machine (the checks use /proc, ss, ip)."
    emit_remote_script > "$TMP_DIR/audit_remote.sh"
    local lo="$OUT_ROOT/local_${TS}" extra=""; [ "$APPLY" = 1 ] && extra="--apply"
    mkdir -p "$lo"
    bash "$TMP_DIR/audit_remote.sh" --out "$lo" $extra
    local lrc=$?
    echo; echo "Reports: $lo"; exit "$lrc"
  fi

  [ -z "${AUDIT_HOST:-}" ] || [ "${#HOSTS[@]}" -gt 0 ] || HOSTS+=("$AUDIT_HOST")
  [ "${#HOSTS[@]}" -gt 0 ] || { usage; die "No host given."; }
  command -v ssh >/dev/null 2>&1 || die "OpenSSH client not found. Windows: install Git for Windows (Git Bash) or use WSL. Mac/Linux: install openssh-client."
  command -v tar >/dev/null 2>&1 || die "tar not found."

  prepare_keys

  local h rc ok=0 bad=0 gated=0
  for h in "${HOSTS[@]}"; do
    audit_host "$h"; rc=$?
    case "$rc" in 0) ok=$((ok + 1)) ;; 3) gated=$((gated + 1)) ;; *) bad=$((bad + 1)) ;; esac
  done
  echo
  log "Finished: $ok clean, $gated with findings above --fail-on, $bad could not be audited."
  [ "$bad" -gt 0 ] && exit 1
  [ "$gated" -gt 0 ] && exit 3
  exit 0
}

# --------------------------------------------------------------------------
#  Payload executed ON the server (Linux, bash 4+). Uploaded over SSH.
# --------------------------------------------------------------------------
emit_remote_script() {
cat <<'__REMOTE_PAYLOAD__'
#!/usr/bin/env bash
# infra_audit remote payload. Read-only, except step 7 (docker pull; optional --apply).

if [ "$(uname -s)" != "Linux" ]; then echo "This payload needs Linux." >&2; exit 2; fi

# Re-run as root if passwordless sudo exists (needed for logs, docker root dir, auth logs)
if [ "$(id -u)" -ne 0 ] && [ -z "${AUDIT_ELEVATED:-}" ]; then
  if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    exec sudo -n env AUDIT_ELEVATED=1 bash "$0" "$@"
  fi
fi

OUT=""; APPLY=0
MIN_FREE_GB=3      # step 7: refuse to pull if less free space than this (GB)
BIG_LOG_MB=100     # flag logs bigger than this
HOT_CONN=10        # flag >= this many connections to/from one IP:port
BRUTE_FAILS=20     # flag >= this many failed-SSH log lines from one IP
CMD_TIMEOUT=60     # per-command timeout (seconds)

while [ $# -gt 0 ]; do
  case "$1" in
    --out)   [ $# -ge 2 ] || { echo "--out needs a value" >&2; exit 2; }; OUT="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    *)       echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$OUT" ] || { echo "--out is required" >&2; exit 2; }
mkdir -p "$OUT" || { echo "cannot create $OUT" >&2; exit 2; }

TS="$(date +%Y%m%d%H%M%S)"
FLAGS="$OUT/.flags"; STATUS="$OUT/.status"; : > "$FLAGS"; : > "$STATUS"
export OUT TS CMD_TIMEOUT

# ------------------------------ helpers ------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
T()    { if have timeout; then timeout "$CMD_TIMEOUT" "$@"; else "$@"; fi; }
flag() { printf '%s\n' "$1" >> "$FLAGS"; }                  # "CRIT|WARN|INFO|message"
hdr()  { printf '\n==================== %s ====================\n' "$1"; }
hs()   { awk -v b="${1:-0}" 'BEGIN{split("B KB MB GB TB",u," ");i=1;while(b>=1024&&i<5){b/=1024;i++}printf "%.1f%s",b,u[i]}'; }

# L "label" "shell command"  -> runs it, always reports success / failure / timeout
L() {
  local label="$1" cmd="$2" rc
  printf '\n--- %s\n$ %s\n' "$label" "$cmd"
  if have timeout; then timeout "$CMD_TIMEOUT" bash -c "$cmd" 2>&1; rc=$?; else bash -c "$cmd" 2>&1; rc=$?; fi
  if [ "$rc" -eq 124 ]; then echo "[TIMED OUT after ${CMD_TIMEOUT}s]"
  elif [ "$rc" -ne 0 ]; then echo "[command exited with code $rc]"; fi
  return 0
}
# LI tool "label" "cmd" -> same, but states clearly when the tool is missing
LI() {
  local tool="$1"; shift
  if have "$tool"; then L "$@"; else printf '\n--- %s\n[SKIPPED: "%s" is not installed on this host]\n' "$1" "$tool"; fi
  return 0
}

# --------------------------- tool detection --------------------------------
detect_tools() {
  DOCKER_OK=0; DOCKER_NOTE="docker is not installed"
  if have docker; then
    if T docker info >/dev/null 2>"$OUT/.derr"; then DOCKER_OK=1; DOCKER_NOTE=""
    else DOCKER_NOTE="docker is installed but the daemon is not reachable: $(tr '\n' ' ' < "$OUT/.derr" | cut -c1-200)"; fi
  fi

  KC=""; KNOTE="no kubectl / k3s / microk8s with a reachable cluster found"
  local c cfg tried=" "
  for c in "kubectl" "k3s kubectl" "microk8s kubectl"; do
    [ -z "$KC" ] || break
    have "${c%% *}" || continue
    for cfg in "${KUBECONFIG:-}" "" /etc/kubernetes/admin.conf /etc/rancher/k3s/k3s.yaml \
               "${SUDO_USER:+/home/$SUDO_USER/.kube/config}" /root/.kube/config "${HOME:-/root}/.kube/config"; do
      case "$tried" in *" $c|$cfg "*) continue ;; esac
      tried="$tried$c|$cfg "
      if [ -n "$cfg" ]; then [ -r "$cfg" ] || continue; export KUBECONFIG="$cfg"; else unset KUBECONFIG; fi
      if T $c --request-timeout=5s get --raw=/version >/dev/null 2>&1; then
        KC="$c --request-timeout=20s"; KNOTE="using: $c${cfg:+ (KUBECONFIG=$cfg)}"; break
      fi
    done
  done
  [ -n "$KC" ] || unset KUBECONFIG

  CRI=""
  for c in "crictl" "k3s crictl"; do
    [ -z "$CRI" ] || break
    have "${c%% *}" || continue
    if T $c ps >/dev/null 2>&1; then CRI="$c"; fi
  done
  export DOCKER_OK KC CRI
}

# ======================= SECTION 2: instance resources =====================
sec_resources() {
  hdr "HOST IDENTITY"
  echo "Report time : $(date '+%F %T %Z')"
  echo "Hostname    : $(hostname 2>/dev/null)"
  if [ -r /etc/os-release ]; then ( . /etc/os-release; echo "OS          : ${PRETTY_NAME:-unknown}" ); fi
  echo "Kernel      : $(uname -r)"
  echo "Uptime      : $(uptime -p 2>/dev/null || uptime)"
  echo "Audited as  : $(id -un) (uid $(id -u))"
  if [ "$(id -u)" -ne 0 ]; then
    echo "NOTE        : not root and no passwordless sudo - some checks have limited visibility."
    flag "WARN|Audit ran without root: logs, docker files and auth logs may be only partly visible."
  fi

  hdr "CLOUD INSTANCE (AWS metadata, if present)"
  if have curl; then
    local tok v p
    tok="$(curl -s -m 2 -X PUT 'http://169.254.169.254/latest/api/token' -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null)"
    for p in instance-id instance-type placement/availability-zone local-ipv4 public-ipv4; do
      if [ -n "$tok" ]; then v="$(curl -s -m 2 -H "X-aws-ec2-metadata-token: $tok" "http://169.254.169.254/latest/meta-data/$p" 2>/dev/null)"
      else v="$(curl -s -m 2 "http://169.254.169.254/latest/meta-data/$p" 2>/dev/null)"; fi
      case "$v" in ""|*"<"*|*" "*) v="n/a (not AWS, or metadata blocked)" ;; esac
      printf '%-22s: %s\n' "$p" "$v"
    done
  else
    echo "[SKIPPED: curl not installed]"
  fi

  hdr "CPU"
  local cores l1 l5 l15 ratio
  cores="$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo)"; [ -n "$cores" ] || cores=1
  echo "vCPUs: $cores"
  LI lscpu "CPU model" "lscpu | grep -E 'Model name|Architecture|^CPU\(s\)|Thread|Core|Socket'"
  read -r l1 l5 l15 _ < /proc/loadavg
  ratio="$(awk -v l="$l5" -v c="$cores" 'BEGIN{printf "%.2f", l/c}')"
  echo; echo "Load average 1/5/15 min: $l1 / $l5 / $l15   (5-min load per vCPU: $ratio)"
  if awk -v r="$ratio" 'BEGIN{exit !(r>1.5)}'; then flag "CRIT|CPU overloaded: 5-min load is $ratio per vCPU."
  elif awk -v r="$ratio" 'BEGIN{exit !(r>1.0)}'; then flag "WARN|CPU busy: 5-min load is $ratio per vCPU."; fi
  LI top "CPU snapshot" "top -bn1 | head -15"
  LI vmstat "vmstat (3 samples)" "vmstat 1 3"
  L "Top 10 processes by CPU" "ps -eo pid,user,%cpu,%mem,rss,etime,comm --sort=-%cpu | head -11"

  hdr "RAM / SWAP"
  LI free "memory" "free -h"
  local mt ma pct
  mt="$(awk '/^MemTotal:/{print $2}' /proc/meminfo)"; ma="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"
  if [ -n "$mt" ] && [ -n "$ma" ] && [ "$mt" -gt 0 ]; then
    pct=$(( ma * 100 / mt ))
    echo; echo "Total RAM: $(hs $((mt*1024)))   Available: $(hs $((ma*1024))) (${pct}%)"
    [ "$pct" -lt 10 ] && flag "CRIT|RAM almost exhausted: only ${pct}% available."
    [ "$pct" -ge 10 ] && [ "$pct" -lt 20 ] && flag "WARN|RAM low: ${pct}% available."
  else
    echo "[could not read /proc/meminfo]"
  fi
  L "Top 10 processes by memory" "ps -eo pid,user,%mem,rss,etime,comm --sort=-%mem | head -11"

  hdr "STORAGE"
  L "Filesystems" "df -hT -x tmpfs -x devtmpfs -x squashfs -x overlay"
  L "Inodes" "df -ih -x tmpfs -x devtmpfs -x squashfs -x overlay"
  LI lsblk "Block devices" "lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT"
  local pu mp
  while read -r pu mp; do
    [ -n "$pu" ] || continue
    if [ "$pu" -ge 90 ]; then flag "CRIT|Disk $mp is ${pu}% full."
    elif [ "$pu" -ge 80 ]; then flag "WARN|Disk $mp is ${pu}% full."; fi
  done < <(df -P -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | awk 'NR>1{gsub("%","",$5); print $5+0, $6}')
  while read -r pu mp; do
    [ -n "$pu" ] || continue
    [ "$pu" -ge 85 ] && flag "WARN|Inodes on $mp are ${pu}% used."
  done < <(df -iP -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | awk 'NR>1{gsub("%","",$5); print $5+0, $6}')
  CMD_TIMEOUT=180 L "Biggest top-level directories (stay on one filesystem)" "du -xh --max-depth=1 / 2>/dev/null | sort -rh | head -15"
  CMD_TIMEOUT=180 L "Biggest directories under /var" "du -xh --max-depth=2 /var 2>/dev/null | sort -rh | head -15"
  return 0
}

# ============== SECTION 3: images / pods / logs: usage & deletability ======
docker_report() {
  hdr "DOCKER - DISK USAGE OVERVIEW"
  L "docker system df" "docker system df"

  hdr "DOCKER - LIVE CPU / MEMORY PER RUNNING CONTAINER (highest memory first)"
  if [ -z "$(T docker ps -q 2>/dev/null)" ]; then
    echo "(no running containers)"
  else
    echo "MEM% | CPU% | CONTAINER | MEM USAGE | NET I/O | BLOCK I/O"
    T docker stats --no-stream --format '{{.MemPerc}}|{{.CPUPerc}}|{{.Name}}|{{.MemUsage}}|{{.NetIO}}|{{.BlockIO}}' 2>&1 | sort -t'|' -k1,1nr
  fi
  L "Container writable-layer sizes" "docker ps -a -s --format 'table {{.Names}}\t{{.Status}}\t{{.Size}}'"

  hdr "DOCKER - IMAGES: size, who uses them, safe to delete?"
  declare -A TAGS SIZE RUN STOP
  local iid ref size cname state id drv path cfg
  while IFS='|' read -r iid cname state; do
    [ -n "$iid" ] || continue
    cname="${cname#/}"
    case "$state" in
      running|restarting|paused) RUN[$iid]+="${RUN[$iid]:+, }$cname($state)" ;;
      *)                         STOP[$iid]+="${STOP[$iid]:+, }$cname($state)" ;;
    esac
  done < <(T docker ps -aq --no-trunc 2>/dev/null | xargs -r docker inspect --format '{{.Image}}|{{.Name}}|{{.State.Status}}' 2>/dev/null)

  while IFS='|' read -r iid ref; do
    [ -n "$iid" ] || continue
    case "$ref" in *"<none>"*) ref="" ;; esac
    if [ -n "$ref" ]; then TAGS[$iid]+="${TAGS[$iid]:+, }$ref"
    elif [ -z "${TAGS[$iid]+x}" ]; then TAGS[$iid]=""; fi
  done < <(T docker image ls -a --no-trunc --format '{{.ID}}|{{.Repository}}:{{.Tag}}' 2>/dev/null)

  if [ "${#TAGS[@]}" -gt 0 ]; then
    while IFS='|' read -r iid size; do SIZE[$iid]="$size"; done \
      < <(printf '%s\n' "${!TAGS[@]}" | xargs -r docker image inspect --format '{{.Id}}|{{.Size}}' 2>/dev/null)
  fi

  local rows="$OUT/.img_rows" verdict tags run stop
  : > "$rows"
  for iid in "${!TAGS[@]}"; do
    tags="${TAGS[$iid]}"; size="${SIZE[$iid]:-0}"; run="${RUN[$iid]:-}"; stop="${STOP[$iid]:-}"
    if [ -n "$run" ]; then
      verdict="IN USE by running container(s): $run -> DO NOT DELETE"
    elif [ -n "$stop" ]; then
      verdict="CAUTION - used by STOPPED container(s): $stop -> remove those containers first, only if no longer needed"
    elif [ -z "$tags" ]; then
      verdict="SAFE - unused AND dangling (no tag, no container)"
    elif printf '%s' "$tags" | grep -q 'rollback-'; then
      verdict="KEEP - rollback copy created by this audit; delete only after a human confirms the new version works"
    else
      verdict="PROBABLY SAFE - no container uses it, but it is tagged: confirm it is not a version you may roll back to"
    fi
    printf '%s|%s|%s|%s\n' "$size" "${iid#sha256:}" "${tags:-<none>}" "$verdict" | sed 's/|\(.\{12\}\)[0-9a-f]*|/|\1|/' >> "$rows"
  done
  if [ -s "$rows" ]; then
    sort -t'|' -k1,1nr "$rows" | awk -F'|' 'function h(b,  i,u){split("B KB MB GB TB",u," ");i=1;while(b>=1024&&i<5){b/=1024;i++}return sprintf("%.1f%s",b,u[i])}
      {printf "%9s  %s  %s\n           => %s\n", h($1), $2, $3, $4}'
    local rec; rec="$(awk -F'|' '$4 ~ /^SAFE - unused AND dangling/ {s+=$1} END{printf "%d", s+0}' "$rows")"
    echo; echo "Reclaimable by deleting only the 'SAFE' dangling images: $(hs "$rec")  (layers shared with other images may make the real figure smaller)"
    echo "Command (review first):  docker image prune        # removes dangling images only"
    [ "$rec" -ge 1073741824 ] && flag "INFO|Docker: $(hs "$rec") of dangling images can be safely removed (docker image prune)."
  else
    echo "(no images found)"
  fi

  hdr "DOCKER - CONTAINER LOG FILES (largest first)"
  local lrows="$OUT/.log_rows" sz rot lverdict
  : > "$lrows"
  while IFS='|' read -r id cname state drv path cfg; do
    [ -n "$id" ] || continue
    cname="${cname#/}"; sz=-1
    if [ "$drv" = "local" ] && [ -z "$path" ]; then path="/var/lib/docker/containers/$id/local-logs/container.log"; fi
    case "$drv" in
      json-file|local)
        if [ -n "$path" ] && [ -r "$path" ]; then sz="$(stat -c %s "$path" 2>/dev/null || echo -1)"; fi ;;
    esac
    case "$cfg" in *max-size*) rot="yes" ;; *) rot="NO" ;; esac
    if [ "$drv" != "json-file" ] && [ "$drv" != "local" ]; then
      lverdict="driver '$drv': logs are NOT on local disk (see the logging backend)"
    elif [ "$sz" -lt 0 ]; then
      lverdict="UNKNOWN - log file unreadable (need root) or missing"
    else
      case "$state" in
        running|restarting|paused)
          lverdict="IN USE - active log of a running container: never rm the file; archive it, then 'truncate -s 0 <file>', and set max-size/max-file" ;;
        *) lverdict="SAFE once the stopped container is removed (docker rm deletes its log)" ;;
      esac
      if [ "$sz" -ge $((BIG_LOG_MB * 1048576)) ]; then
        flag "WARN|Container '$cname' log is $(hs "$sz") (rotation configured: $rot)."
      fi
    fi
    printf '%s|%s|%s|%s|%s|%s|%s\n' "$sz" "$cname" "$state" "$drv" "$rot" "$lverdict" "$path" >> "$lrows"
  done < <(T docker ps -aq --no-trunc 2>/dev/null | xargs -r docker inspect --format '{{.Id}}|{{.Name}}|{{.State.Status}}|{{.HostConfig.LogConfig.Type}}|{{.LogPath}}|{{.HostConfig.LogConfig.Config}}' 2>/dev/null)
  if [ -s "$lrows" ]; then
    sort -t'|' -k1,1nr "$lrows" | awk -F'|' 'function h(b,  i,u){if(b<0)return "n/a";split("B KB MB GB TB",u," ");i=1;while(b>=1024&&i<5){b/=1024;i++}return sprintf("%.1f%s",b,u[i])}
      {printf "%9s  %-28s state=%-10s driver=%-9s rotation=%s\n           => %s\n           file: %s\n", h($1),$2,$3,$4,$5,$6,$7}'
  else
    echo "(no containers)"
  fi
  [ -r /etc/docker/daemon.json ] && L "Docker daemon log settings" "grep -n -i 'log' /etc/docker/daemon.json || echo '(no log settings in daemon.json -> unlimited json-file logs by default)'"