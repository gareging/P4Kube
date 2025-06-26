#!/bin/bash

# Usage: ./cpu_load_test_2_nodes.sh nodeX

NODE_NAME="$1"

if [[ ! $NODE_NAME =~ ^node([1-9]|10)$ ]]; then
  echo "Usage: $0 node1 .. node10"
  exit 1
fi

# Extract node number
NODE_NUM=${NODE_NAME:4}

# Ensure numeric
if ! [[ "$NODE_NUM" =~ ^[0-9]+$ ]]; then
  echo "Invalid node number."
  exit 1
fi

# Compute group index (0 for node1 & node2, 1 for node3 & node4, etc.)
GROUP=$(( (NODE_NUM - 1) / 2 ))
# Each group starts 150s after the previous one
DELAY=$(( GROUP * 270 ))

# Optional: log to CPU log
LOGFILE="cpu_load_test_2_nodes.log"
echo "[$(date)] $NODE_NAME waiting $DELAY seconds before stress" | tee -a "$LOGFILE"
sleep "$DELAY"
while true; do
  echo "[$(date)] $NODE_NAME starting stress-ng for 120 seconds" | tee -a "$LOGFILE"
  sudo stress-ng --cpu 2 --cpu-method matrixprod --vm 1 --vm-bytes 256M --sched rr --timeout 240

  echo "[$(date)] $NODE_NAME done. Waiting for next cycle." | tee -a "$LOGFILE"

  # Wait for full pattern cycle (e.g., 10 minutes)
  # Adjust for time already spent (stress)
  sleep 1110
done
