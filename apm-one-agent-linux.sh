#!/bin/sh

exec >>"/home/durbar-11363/Documents/archive/ONEAGENT_INTEGRATION/test.log" 2>&1
echo "AGENT RUN WITH ARGS "$0" "$@""
if [ "$(id -u)" -ne 0 ]; then
    echo "OneAgent installer script is run without root privilege. Please run the script apm-one-agent-linux.sh with root privilege"
    exit 1
fi
