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