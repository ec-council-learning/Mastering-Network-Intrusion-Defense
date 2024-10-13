#!/bin/bash

# Check if correct number of arguments is provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <true_positive_pcap> <false_positive_pcap>"
    exit 1
fi

# Assign arguments to variables
TP_PCAP="$1"
FP_PCAP="$2"

# Paths
SURICATA_CONFIG="/etc/suricata/suricata.yaml"
LOG_DIR="/var/log/suricata"
FAST_LOG="$LOG_DIR/fast.log"

# Check if PCAP files exist
if [ ! -f "$TP_PCAP" ] || [ ! -f "$FP_PCAP" ]; then
    echo "Error: One or both PCAP files do not exist."
    exit 1
fi

# Clear fast.log
cat /dev/null > "$FAST_LOG"

# Run Suricata on both PCAPs
echo "Processing $TP_PCAP and $FP_PCAP"
suricata -c $SURICATA_CONFIG -r "$TP_PCAP" -l $LOG_DIR
suricata -c $SURICATA_CONFIG -r "$FP_PCAP" -l $LOG_DIR

# Count alerts
ALERTS=$(wc -l < "$FAST_LOG")

# Check alerts and set exit status
if [ "$ALERTS" -eq 1 ]; then
    echo "Pass: Detected 1 alert (Expected behavior)"
    exit 0
elif [ "$ALERTS" -eq 2 ]; then
    echo "Warn: Detected 2 alerts (Possible false positive)"
    exit 1
elif [ "$ALERTS" -eq 0 ]; then
    echo "Fail: No alerts detected (Expected at least 1)"
    exit 1
else
    echo "Fail: Too many alerts ($ALERTS detected, expected 1)"
    exit 1
fi