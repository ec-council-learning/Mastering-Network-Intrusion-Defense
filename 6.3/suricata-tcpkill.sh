#!/bin/bash

# Configuration
FAST_LOG="fast.log"
INTERFACE="ens33"
POLL_INTERVAL=10

# Function to process log and run tcpkill
process_log() {
    # Find critical alerts and extract IPs
    grep "signature_severity Critical" "$FAST_LOG" | grep -i 'malware' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u | while read -r ip; do
        echo "ALERT: Blocking IP: $ip"
        echo "Running command: tcpkill -i $INTERFACE host $ip &"
        # Uncomment the line below to actually run tcpkill (not possible on repl.it)
         tcpkill -i $INTERFACE host $ip &
    done
}

# Main loop
while true; do
    process_log
    echo "Sleeping for $POLL_INTERVAL seconds..."
    sleep "$POLL_INTERVAL"
done
