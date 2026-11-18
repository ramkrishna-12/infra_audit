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
