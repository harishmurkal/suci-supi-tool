#!/bin/bash

# Start the command in background
"$@" &
PID=$!

peak=0

while kill -0 $PID 2>/dev/null; do
    rss=$(awk '/VmRSS/ {print $2}' /proc/$PID/status 2>/dev/null)
    if [ ! -z "$rss" ]; then
        if [ "$rss" -gt "$peak" ]; then
            peak=$rss
        fi
    fi
    sleep 0.1
done

wait $PID
echo "Peak RSS: $peak kB"

