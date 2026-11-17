#!/bin/bash

###############################################################################
# Infrastructure Audit Script
# Version: 1.0
###############################################################################

set -euo pipefail

REPORT_DIR="./audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

HOSTS_FILE="hosts.txt"

if [ ! -f "$HOSTS_FILE" ]; then
    echo "hosts.txt not found"
    exit 1
fi

PEM=$(find . -maxdepth 1 -name "*.pem" | head -1)

if [ -z "$PEM" ]; then
    echo "No pem file found"
    exit 1
fi

chmod 400 "$PEM"

while read -r HOST
do

    echo "Processing $HOST"

    ssh -o StrictHostKeyChecking=no \
        -i "$PEM" ec2-user@"$HOST" 'bash -s' <<'REMOTE'

HOSTNAME=$(hostname)

REPORT="/tmp/${HOSTNAME}_report.txt"

{
echo "===================================================="
echo "HOST: $HOSTNAME"
echo "DATE: $(date)"
echo "===================================================="

########################################################
# CPU RAM DISK
########################################################

echo
echo "CPU"
lscpu

echo
echo "CPU LOAD"
uptime

echo
echo "MEMORY"
free -h

echo
echo "DISK"
df -h

echo
echo "TOP MEMORY CONSUMERS"
ps aux --sort=-%mem | head

echo
echo "TOP CPU CONSUMERS"
ps aux --sort=-%cpu | head

########################################################
# DOCKER
########################################################

if command -v docker >/dev/null 2>&1
then

echo
echo "DOCKER CONTAINERS"

docker ps -a

echo
echo "DOCKER IMAGE SIZE"

docker images --format '{{.Repository}} {{.Tag}} {{.Size}}'

echo
echo "RUNNING CONTAINER RESOURCE USAGE"

timeout 10 docker stats --no-stream

echo
echo "UNUSED IMAGES"

docker images -f dangling=true

echo
echo "UNUSED VOLUMES"

docker volume ls -f dangling=true

echo
echo "PORT BINDINGS"

docker ps --format \
'{{.Names}} -> {{.Ports}}'

fi

########################################################
# KUBERNETES
########################################################

if command -v kubectl >/dev/null 2>&1
then

echo
echo "K8S PODS"

kubectl get pods -A -o wide

echo
echo "K8S TOP PODS"

kubectl top pod -A 2>/dev/null || true

echo
echo "K8S TOP NODES"

kubectl top nodes 2>/dev/null || true

echo
echo "RECENT ERROR LOGS"

for p in $(kubectl get pods -A \
--no-headers | awk '{print $2}' | head -20)
do
    kubectl logs "$p" --tail=50 2>/dev/null | \
    grep -iE "error|fatal|panic|oom" || true
done

fi

########################################################
# PORTS
########################################################

echo
echo "OPEN PORTS"

ss -tulpn

########################################################
# NETWORK
########################################################

echo
echo "ESTABLISHED CONNECTIONS"

ss -tpn state established

echo
echo "LISTENING SOCKETS"

ss -lntup

echo
echo "CONNECTION SUMMARY"

netstat -s 2>/dev/null || true


########################################################
# SSH LOGINS
########################################################

echo
echo "CURRENT USERS"

who

echo
echo "LOGIN HISTORY"

last -a | head -100

echo
echo "UNIQUE IPS"

last -i | awk "{print \$3}" | sort -u

########################################################
# USER ACCESS
########################################################

echo
echo "ACTIVE SSH SESSIONS"

w

########################################################
# FAILED CONNECTIONS
########################################################

echo
echo "FAILED SSH LOGINS"

grep "Failed password" /var/log/secure 2>/dev/null | tail -50 || true

grep "Failed password" /var/log/auth.log 2>/dev/null | tail -50 || true

echo
echo "DROPPED CONNECTIONS"

dmesg | grep -iE \
"reset|timeout|disconnect|network" | tail -50


########################################################
# IMAGE UPDATE CHECK
########################################################

if command -v docker >/dev/null 2>&1
then

echo
echo "IMAGE UPDATE CHECK"

docker images --format "{{.Repository}}:{{.Tag}}" |
while read IMAGE
do
    echo "Checking $IMAGE"

    docker pull "$IMAGE" >/tmp/pull.out 2>&1 || true

    cat /tmp/pull.out | grep -i \
    "Image is up to date" || true
done

fi

########################################################
# LICENSE
########################################################

echo
echo "INSTALLED LICENSE FILES"

find /opt /etc /usr/local \
-type f \
\( -iname "*license*" -o -iname "*.lic" \) \
2>/dev/null

########################################################
# RISK SECTION
########################################################

echo
echo "POTENTIALLY SAFE CLEANUP ITEMS"

echo "- Dangling Docker images"
docker images -f dangling=true 2>/dev/null || true

echo "- Dangling Volumes"
docker volume ls -f dangling=true 2>/dev/null || true

echo "- Journal Usage"
journalctl --disk-usage 2>/dev/null || true

} > "$REPORT"

echo "$REPORT generated"

REMOTE

    scp -i "$PEM" \
        -o StrictHostKeyChecking=no \
        ec2-user@"$HOST":/tmp/*_report.txt \
        "$REPORT_DIR"/

done < "$HOSTS_FILE"

echo
echo "Audit complete."
echo "Reports stored in: $REPORT_DIR"