#!/bin/bash

# Usage: ./cpu_load_test_one_node.sh nodeX

NODE_NAME="$1"

if [[ ! $NODE_NAME =~ ^node([1-9]|10)$ ]]; then
  echo "Usage: $0 node1 .. node10"
  exit 1
fi

# Extract node number (from 'nodeX')
NODE_NUM=${NODE_NAME:4}

# Ensure it's a number
if ! [[ "$NODE_NUM" =~ ^[0-9]+$ ]]; then
  echo "Invalid node number."
  exit 1
fi

# Each node is its own group. Delay 30s between node starts.
DELAY=$(( (NODE_NUM - 1) * 270 ))

# Log file
LOGFILE="cpu_load_test_single_node_groups.log"
echo "[$(date)] $NODE_NAME waiting $DELAY seconds before starting stress cycle" | tee -a "$LOGFILE"
sleep "$DELAY"

# Stress cycle loop
while true; do
  echo "[$(date)] $NODE_NAME starting stress-ng for 240 seconds" | tee -a "$LOGFILE"
  sudo stress-ng --cpu 2 --cpu-method matrixprod --vm 1 --vm-bytes 256M --sched rr --timeout 240

  echo "[$(date)] $NODE_NAME done. Waiting for next cycle." | tee -a "$LOGFILE"

  # Wait for the full cycle (e.g., 10 minutes) minus the 240s spent stressing
  sleep 2460
done
