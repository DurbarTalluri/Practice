#!/bin/bash

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROCESS_NAME="Site24x7_EBPF_APM"
# PID_FILE will be set after parsing logs_dir argument

usage() {
  echo "Usage:"
  echo "  $0 start --logs_dir <logs_dir> --conf_dir <conf_dir> [--exporter_ip <host>] [--debug]"
  echo "  $0 stop"
  echo "  $0 status"
  echo "  $0 restart --logs_dir <logs_dir> --conf_dir <conf_dir> [--exporter_ip <host>] [--debug]"
  echo "  $0 --test-run --logs_dir <logs_dir> --conf_dir <conf_dir> [--exporter_ip <host>] [--debug]"
  echo ""
  echo "Commands:"
  echo "  start              Start the eBPF APM process"
  echo "  stop               Gracefully stop the running process"
  echo "  status             Check if process is running"
  echo "  restart            Stop and start the process"
  echo ""
  echo "Options:"
  echo "  --logs_dir <dir>       Directory for logs (required for start/restart)"
  echo "  --conf_dir <dir>       Directory for configuration files (required for start/restart)"
  echo "  --exporter_ip <ip>     IP address of the exporter server (default: 127.0.0.1)"
  echo "  --debug                Enable BPF debug messages to userspace log"
  echo "  --test-run            Test the binary without starting as background process"
  exit 1
}

# Function to find PID file in common locations
find_pid_file() {
  # Common locations to search for PID file
  local search_paths=(
    "/opt/site24x7/apmoneagent/logs/EBPF/site24x7_ebpf_apm.pid"
    "/opt/site24x7/apmoneagent/agents/EBPF/site24x7_ebpf_apm.pid"
    "/var/log/site24x7/EBPF/site24x7_ebpf_apm.pid"
    "/var/log/EBPF/site24x7_ebpf_apm.pid"
    "/tmp/EBPF/site24x7_ebpf_apm.pid"
    "$HOME/logs/EBPF/site24x7_ebpf_apm.pid"
  )
  
  for path in "${search_paths[@]}"; do
    if [ -f "$path" ]; then
      echo "$path"
      return 0
    fi
  done
  
  # If not found in common locations, search for it
  local found_pid=$(find /opt/site24x7 /var/log /tmp "$HOME" -name "site24x7_ebpf_apm.pid" 2>/dev/null | head -n 1)
  if [ -n "$found_pid" ]; then
    echo "$found_pid"
    return 0
  fi
  
  return 1
}

# Function to check if process is running
is_process_running() {
  if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
      return 0  # Process is running
    else
      # PID file exists but process is dead
      echo "[!] Stale PID file found, removing..."
      rm -f "$PID_FILE"
      return 1  # Process is not running
    fi
  fi
  
  # Also check if any instance of the binary is already running (without PID file)
  if pgrep -f "Site24x7_EBPF_APM.*--logs_dir.*--conf_dir" > /dev/null 2>&1; then
    echo "[!] Warning: Found running instance(s) of $PROCESS_NAME without PID file"
    return 0  # Process is running
  fi
  
  return 1  # PID file doesn't exist and no process found
}

# Handle stop command
if [ "$1" = "stop" ]; then
  echo "[+] Stopping $PROCESS_NAME..."
  
  # Find PID file
  PID_FILE=$(find_pid_file) || true
  
  # First try to stop using PID file if it exists
  if [ -n "$PID_FILE" ] && [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
      echo "[+] Found running process with PID: $PID"
      echo "[+] Sending SIGTERM for graceful shutdown..."
      
      if kill -TERM "$PID" 2>/dev/null; then
        # Wait for process to stop (max 15 seconds)
        for i in {1..15}; do
          if ! ps -p "$PID" > /dev/null 2>&1; then
            echo "[✓] Process stopped gracefully"
            rm -f "$PID_FILE"
            break
          fi
          sleep 1
        done
        
        # If still running, force kill
        if ps -p "$PID" > /dev/null 2>&1; then
          echo "[!] Process did not stop gracefully, sending SIGKILL..."
          kill -KILL "$PID" 2>/dev/null
          sleep 1
          echo "[✓] Process forcefully terminated"
        fi
      fi
      rm -f "$PID_FILE"
    else
      echo "[!] PID file exists but process not found, removing stale PID file"
      rm -f "$PID_FILE"
    fi
  else
    echo "[!] Could not find PID file"
    echo "[!] Searching for running processes by name..."
  fi
  
  # Also kill any orphaned instances
  ORPHAN_PIDS=$(pgrep -f "Site24x7_EBPF_APM.*--logs_dir.*--conf_dir") || true
  
  if [ -n "$ORPHAN_PIDS" ]; then
    echo "[+] Found orphaned process(es), stopping them..."
    for OPID in $ORPHAN_PIDS; do
      echo "[+] Stopping orphaned process PID: $OPID"
      kill -TERM "$OPID" 2>/dev/null || true
    done
    sleep 2
    # Force kill if still running
    for OPID in $ORPHAN_PIDS; do
      if ps -p "$OPID" > /dev/null 2>&1; then
        echo "[+] Force killing PID: $OPID"
        kill -KILL "$OPID" 2>/dev/null || true
      fi
    done
  fi
  
  echo "[✓] All $PROCESS_NAME processes stopped"
  exit 0
fi

# Handle status command
if [ "$1" = "status" ]; then
  # Find PID file
  PID_FILE=$(find_pid_file)
  if [ -z "$PID_FILE" ]; then
    echo "[!] Could not find PID file"
    echo "[!] Checking for running processes by name..."
    if pgrep -f "Site24x7_EBPF_APM.*--logs_dir.*--conf_dir" > /dev/null 2>&1; then
      PIDS=$(pgrep -f "Site24x7_EBPF_APM.*--logs_dir.*--conf_dir")
      echo "[✓] $PROCESS_NAME is running (without PID file)"
      echo ""
      ps -p $PIDS -o pid,ppid,cmd,%mem,%cpu,etime
      exit 0
    else
      echo "[!] $PROCESS_NAME is not running"
      exit 1
    fi
  fi
  
  if is_process_running; then
    PID=$(cat "$PID_FILE")
    echo "[✓] $PROCESS_NAME is running (PID: $PID)"
    echo ""
    ps -p "$PID" -o pid,ppid,cmd,%mem,%cpu,etime
    exit 0
  else
    echo "[!] $PROCESS_NAME is not running"
    exit 1
  fi
fi

# Handle restart command
if [ "$1" = "restart" ]; then
  echo "[+] Restarting $PROCESS_NAME..."
  
  # Find PID file for checking if running
  PID_FILE=$(find_pid_file)
  
  # Stop if running
  if [ -n "$PID_FILE" ] && is_process_running; then
    $0 stop
    sleep 2
  fi
  
  # Remove 'restart' from arguments and call start
  shift
  exec $0 start "$@"
fi


# Parse start command args
COMMAND=""
if [ "$1" = "start" ] || [ "$1" = "--test-run" ]; then
  COMMAND="$1"
  shift
fi

TEST_RUN=false
if [ "$COMMAND" = "--test-run" ]; then
  TEST_RUN=true
  COMMAND="start"
fi

# Parse remaining arguments
DEBUG_FLAG=""
while [ $# -gt 0 ]; do
  case $1 in
    --logs_dir)
      LOGS_DIR="$2"
      shift 2
      ;;
    --conf_dir)
      CONF_DIR="$2"
      shift 2
      ;;
    --exporter_ip)
      HOST="$2"
      shift 2
      ;;
    --debug)
      DEBUG_FLAG="--debug"
      shift
      ;;
    --test-run)
      TEST_RUN=true
      shift
      ;;
    *)
      usage
      ;;
  esac
done

# Validate command
if [ "$COMMAND" != "start" ]; then
  usage
fi

# Validate required arguments
if [ -z "$LOGS_DIR" ] || [ -z "$CONF_DIR" ]; then
  echo "Error: Both --logs_dir and --conf_dir are required for start command"
  usage
fi

# Set PID file location in logs directory
PID_FILE="$LOGS_DIR/EBPF/site24x7_ebpf_apm.pid"

# Create log directory early (needed for PID file)
mkdir -p "$LOGS_DIR/EBPF"

# Check if process is already running (only for non-test runs)
if [ "$TEST_RUN" = false ] && is_process_running; then
  PID=$(cat "$PID_FILE")
  echo "[!] $PROCESS_NAME is already running (PID: $PID)"
  echo "[!] Use '$0 stop' to stop the running process first"
  echo "[!] Or use '$0 restart' to restart it"
  exit 1
fi

# Set default exporter IP if not provided
if [ -z "$HOST" ]; then
  HOST="127.0.0.1"
  echo "[+] No exporter IP specified, using default: 127.0.0.1"
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_PATH="$SCRIPT_DIR/Site24x7_EBPF_APM"

# Check if binary exists in the same directory
echo "[+] Checking for binary in script directory..."
if [ ! -f "$BINARY_PATH" ]; then
  echo "[!] Error: Site24x7_EBPF_APM binary not found"
  echo "[!] Expected location: $BINARY_PATH"
  echo "[!] Please ensure the binary is in the same directory as this script"
  exit 1
fi

echo "[+] Found binary at: $BINARY_PATH"

# Make sure the binary is executable
chmod +x "$BINARY_PATH"

# Pre-flight checks for binary compatibility and dependencies
echo "[+] Running pre-flight checks..."
echo "[+] Binary info:"
file "$BINARY_PATH" 2>/dev/null || echo "[!] Could not determine binary type"

echo "[+] Checking library dependencies:"
if command -v ldd &> /dev/null; then
    ldd "$BINARY_PATH" 2>/dev/null || echo "[!] Binary may be statically linked or ldd failed"
else
    echo "[!] ldd not available for dependency check"
fi

# Check if host supports eBPF by checking kernel version
echo "[+] Checking eBPF support..."
KERNEL_VERSION=$(uname -r | cut -d'.' -f1)
KERNEL_MINOR=$(uname -r | cut -d'.' -f2 | sed 's/[^0-9].*//')

if [ "$KERNEL_VERSION" -lt 4 ] || ([ "$KERNEL_VERSION" -eq 4 ] && [ "$KERNEL_MINOR" -lt 16 ]); then
  echo "[!] Error: Kernel version $(uname -r) is too old for eBPF"
  echo "[!] Minimum required kernel version: 4.16"
  echo "[!] Recommended kernel version: 5.8 or higher"
  echo "[!] Current kernel: $(uname -r)"
  exit 1
fi

echo "[✓] eBPF support verified (Kernel: $(uname -r))"

# Check if autoprofilerconf.ini exists in conf directory
CONFIG_FILE="$CONF_DIR/autoprofilerconf.ini"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "[!] Error: autoprofilerconf.ini not found in $CONF_DIR"
  echo "[!] This file is required and should contain the encrypted license key"
  echo "[!] Please ensure the config file exists with the following format:"
  echo "[!]   APMINSIGHT_LICENSEKEY = <encrypted_license_key>"
  echo "[!]   APMINSIGHT_AGENT_START_TIME = <agent_start_time>"
  echo "[!]   APMINSIGHT_AGENT_ID = <agent_id>"
  exit 1
fi

# 1. Prepare installation
echo "[+] Using binary from: $BINARY_PATH"

# Handle test run mode
if [ "$TEST_RUN" = true ]; then
    echo ""
    echo "[+] TEST RUN MODE - Running binary directly to test for crashes"
    echo "[+] Command: $BINARY_PATH --logs_dir $LOGS_DIR --conf_dir $CONF_DIR --exporter_ip $HOST $DEBUG_FLAG"
    echo "[+] Press Ctrl+C to stop the test run"
    echo ""
    
    # Run the binary directly with timeout to prevent infinite execution
    timeout 30s "$BINARY_PATH" --logs_dir "$LOGS_DIR" --conf_dir "$CONF_DIR" --exporter_ip "$HOST" $DEBUG_FLAG || {
        EXIT_CODE=$?
        echo ""
        echo "[!] Binary execution finished with exit code: $EXIT_CODE"
        
        if [ $EXIT_CODE -eq 124 ]; then
            echo "[+] Test completed - binary ran for 30 seconds without crashing"
            echo "[+] This indicates the binary is working properly"
        elif [ $EXIT_CODE -eq 130 ]; then
            echo "[+] Test interrupted by user (Ctrl+C)"
        elif [ $EXIT_CODE -eq 134 ]; then
            echo "[!] CRITICAL: Stack smashing detected (SIGABRT)"
            echo "[!] This is a buffer overflow in the license decryption code"
            echo "[!] POSSIBLE CAUSES:"
            echo "    1. Invalid license key format causing buffer overflow"
            echo "    2. Binary incompatibility with your system's glibc version"
            echo "    3. Corrupted binary or license key"
            echo ""
            echo "[!] RECOMMENDED ACTIONS:"
            echo "    1. Download a fresh binary from the server"
            echo "    2. The current binary has buffer overflow bugs in the AES decryption"
            echo "    3. Source code has been fixed but binary needs recompilation"
            echo "    4. Contact support with system details:"
            echo "       - Kernel: $(uname -r)"
            echo "       - Architecture: $(uname -m)"
            echo "       - glibc version: $(ldd --version | head -n1)"
        else
            echo "[!] Binary crashed or exited unexpectedly"
            echo "[!] Check the logs for more details:"
            if [ -f "$LOGS_DIR/EBPF/ebpf_tracer.log" ]; then
                echo "[!] ebpf_tracer.log:"
                tail -n 10 "$LOGS_DIR/EBPF/ebpf_tracer.log" 2>/dev/null || echo "Could not read log file"
            fi
        fi
        
        echo ""
        echo "[+] Test run completed. Use '$0 start' with the same arguments to run in background."
        exit 0
    }
    exit 0
fi

# Start the process in background
echo "[+] Starting $PROCESS_NAME in background..."
echo "[+] Command: $BINARY_PATH --logs_dir $LOGS_DIR --conf_dir $CONF_DIR --exporter_ip $HOST $DEBUG_FLAG"

# Start the process in background and redirect output to log files
bash -c "nohup '$BINARY_PATH' --logs_dir '$LOGS_DIR' --conf_dir '$CONF_DIR' --exporter_ip '$HOST' $DEBUG_FLAG > '$LOGS_DIR/EBPF/stdout.log' 2> '$LOGS_DIR/EBPF/stderr.log' & echo \$! > '$PID_FILE'"

# Wait a moment for the process to start
sleep 2

# Read the actual PID from the file
if [ -f "$PID_FILE" ]; then
  PROCESS_PID=$(cat "$PID_FILE")
  echo "[+] Process started with PID: $PROCESS_PID"
else
  echo "[!] Failed to create PID file"
  exit 1
fi

# Wait a bit more and check if process is still running
sleep 2

if ps -p "$PROCESS_PID" > /dev/null 2>&1; then
    echo "[✓] Process is running successfully"
    echo ""
    echo "[+] Configuration:"
    echo "    Binary Path: $BINARY_PATH"
    echo "    Process PID: $PROCESS_PID"
    echo "    PID File: $PID_FILE"
    echo "    Logs Directory: $LOGS_DIR"
    echo "    Config Directory: $CONF_DIR"
    echo "    Exporter IP: $HOST"
    echo "    License Key: Read from $CONFIG_FILE"
    echo ""
    echo "[+] Process Management:"
    echo "    Status:     $0 status"
    echo "    Stop:       $0 stop"
    echo "    Restart:    $0 restart --logs_dir $LOGS_DIR --conf_dir $CONF_DIR --exporter_ip $HOST"
    echo ""
    echo "[+] Log Files:"
    echo "    Stdout:     $LOGS_DIR/EBPF/stdout.log"
    echo "    Stderr:     $LOGS_DIR/EBPF/stderr.log"
    echo "    Tracer:     $LOGS_DIR/EBPF/ebpf_tracer.log"
    echo ""
    echo "[+] Monitor logs with:"
    echo "    tail -f $LOGS_DIR/EBPF/stdout.log"
    echo "    tail -f $LOGS_DIR/EBPF/stderr.log"
else
    echo "[!] Process failed to start or crashed immediately"
    echo "[!] Checking logs..."
    echo ""
    if [ -f "$LOGS_DIR/EBPF/stderr.log" ]; then
        echo "[!] stderr.log:"
        cat "$LOGS_DIR/EBPF/stderr.log" 2>/dev/null || echo "[!] Could not read stderr.log"
    fi
    echo ""
    if [ -f "$LOGS_DIR/EBPF/stdout.log" ]; then
        echo "[!] stdout.log:"
        cat "$LOGS_DIR/EBPF/stdout.log" 2>/dev/null || echo "[!] Could not read stdout.log"
    fi
    echo ""
    if [ -f "$LOGS_DIR/EBPF/ebpf_tracer.log" ]; then
        echo "[!] ebpf_tracer.log:"
        tail -n 20 "$LOGS_DIR/EBPF/ebpf_tracer.log" 2>/dev/null || echo "[!] Could not read ebpf_tracer.log"
    fi
    echo ""
    echo "[!] CRASH ANALYSIS:"
    echo "    - The process appears to be crashing during startup"
    echo "    - This could be due to:"
    echo "      * Corrupted or invalid license key format"
    echo "      * Missing cryptographic libraries"
    echo "      * Binary compatibility issues with your system"
    echo "      * Insufficient permissions for eBPF operations"
    echo ""
    echo "[!] TROUBLESHOOTING STEPS:"
    echo "    1. Verify license key format in $CONFIG_FILE"
    echo "    2. Check if binary is compatible: file $BINARY_PATH"
    echo "    3. Check library dependencies: ldd $BINARY_PATH"
    echo "    4. Try test run mode: $0 --test-run --logs_dir $LOGS_DIR --conf_dir $CONF_DIR --exporter_ip $HOST"
    echo "    5. Check system capabilities for eBPF: sysctl kernel.unprivileged_bpf_disabled"
    
    # Clean up PID file
    rm -f "$PID_FILE"
    exit 1
fi