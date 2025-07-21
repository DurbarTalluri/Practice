#!/bin/bash

set -e

SERVICE_NAME="S247_eBPF_APM"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"

usage() {
  echo "Usage:"
  echo "  $0 --logs_dir <logs_dir> --conf_dir <conf_dir> [--exporter_ip <host>]"
  echo "  $0 --uninstall"
  echo "  $0 --test-run --logs_dir <logs_dir> --conf_dir <conf_dir> [--exporter_ip <host>]"
  echo ""
  echo "Options:"
  echo "  --logs_dir <dir>       Directory for logs (required)"
  echo "  --conf_dir <dir>       Directory for configuration files (required)"
  echo "  --exporter_ip <ip>     IP address of the exporter server (default: 127.0.0.1)"
  echo "  --uninstall           Remove the service and cleanup"
  echo "  --test-run            Test the binary without installing as service"
  exit 1
}

# Handle uninstall option
if [ "$1" = "--uninstall" ]; then
  echo "[+] Stopping and removing service"
  sudo systemctl stop "$SERVICE_NAME.service" || true
  sudo systemctl disable "$SERVICE_NAME.service" || true
  
  # Read the logs and conf paths from the service file
  if [ -f "$SERVICE_FILE" ]; then
    LOGS_DIR=$(grep "ExecStart=" "$SERVICE_FILE" | sed 's/.*--logs_dir \([^ ]*\).*/\1/')
    CONF_DIR=$(grep "ExecStart=" "$SERVICE_FILE" | sed 's/.*--conf_dir \([^ ]*\).*/\1/')
    if [ -n "$LOGS_DIR" ]; then
      echo "[+] Found logs directory: $LOGS_DIR"
      echo "[+] Removing logs directory"
      sudo rm -rf "$LOGS_DIR" 2>/dev/null || true
    else
      echo "[!] Could not determine logs directory from service file"
    fi
    if [ -n "$CONF_DIR" ]; then
      echo "[+] Found config directory: $CONF_DIR"
      echo "[+] Note: Config directory preserved (contains configuration files)"
    else
      echo "[!] Could not determine config directory from service file"
    fi
  else
    echo "[!] Service file not found, cannot determine directories"
  fi
  
  sudo rm -f "$SERVICE_FILE"
  
  echo "[✓] Uninstalled $SERVICE_NAME service and removed logs directory"
  sudo systemctl daemon-reload
  exit 0
fi

# Parse install args
TEST_RUN=false
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
    --test-run)
      TEST_RUN=true
      shift
      ;;
    *)
      usage
      ;;
  esac
done

# Validate required arguments
if [ -z "$LOGS_DIR" ] || [ -z "$CONF_DIR" ]; then
  echo "Error: Both --logs_dir and --conf_dir are required"
  usage
fi

# Set default exporter IP if not provided
if [ -z "$HOST" ]; then
  HOST="127.0.0.1"
  echo "[+] No exporter IP specified, using default: 127.0.0.1"
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"
BINARY_PATH="$SCRIPT_DIR/Site24x7_EBPF_APM"

# Always download fresh binary from server
echo "[+] Downloading fresh binary from server..."
if [ -f "$BINARY_PATH" ]; then
  echo "[+] Removing existing binary to ensure fresh download"
  rm -f "$BINARY_PATH"
fi
  
  # Check if curl is available
  if ! command -v curl &> /dev/null; then
    echo "[!] Error: curl is required but not installed"
    echo "[!] Please install curl: sudo apt-get install curl (Ubuntu/Debian) or sudo yum install curl (RHEL/CentOS)"
    exit 1
  fi
  
  # Check if unzip is available
  if ! command -v unzip &> /dev/null; then
    echo "[!] Error: unzip is required but not installed"
    echo "[!] Please install unzip: sudo apt-get install unzip (Ubuntu/Debian) or sudo yum install unzip (RHEL/CentOS)"
    exit 1
  fi
  
  # Download the zip file
  echo "[+] Downloading Site24x7_EBPF_APM.zip..."
  curl https://raw.githubusercontent.com/DurbarTalluri/Practice/main/Site24x7_EBPF_APM.zip
  # if ! curl -f "http://10.15.213.72:1359/" -o "$SCRIPT_DIR/Site24x7_EBPF_APM.zip"; then
  #   echo "[!] Error: Failed to download binary from http://10.71.94.73:1359/"
  #   echo "[!] Please check your network connection and server availability"
  #   exit 1
  # fi
  
  # Extract the zip file
  echo "[+] Extracting binary..."
  if ! unzip -o "$SCRIPT_DIR/Site24x7_EBPF_APM.zip" -d "$SCRIPT_DIR"; then
    echo "[!] Error: Failed to extract Site24x7_EBPF_APM.zip"
    echo "[!] The downloaded file may be corrupted"
    rm -f "$SCRIPT_DIR/Site24x7_EBPF_APM.zip"
    exit 1
  fi
  
  # Clean up the zip file
  rm -f "$SCRIPT_DIR/Site24x7_EBPF_APM.zip"
  
  # Verify the binary was extracted
  if [ ! -f "$BINARY_PATH" ]; then
    echo "[!] Error: Site24x7_EBPF_APM binary not found after extraction"
    echo "[!] The zip file may not contain the expected binary"
    exit 1
  fi
  
  echo "[+] Binary downloaded and extracted successfully"

# Make sure the binary is executable
sudo chmod +x "$BINARY_PATH"

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
echo "[+] Creating directories"
sudo mkdir -p "$LOGS_DIR/EBPF"
sudo mkdir -p "$CONF_DIR/EBPF"
echo "[+] Using binary from: $BINARY_PATH"

# Handle test run mode
if [ "$TEST_RUN" = true ]; then
    echo ""
    echo "[+] TEST RUN MODE - Running binary directly to test for crashes"
    echo "[+] Command: sudo $BINARY_PATH --logs_dir $LOGS_DIR --conf_dir $CONF_DIR --exporter_ip $HOST"
    echo "[+] Press Ctrl+C to stop the test run"
    echo ""
    
    # Run the binary directly with timeout to prevent infinite execution
    timeout 30s sudo "$BINARY_PATH" --logs_dir "$LOGS_DIR" --conf_dir "$CONF_DIR" --exporter_ip "$HOST" || {
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
        echo "[+] Test run completed. Use the same command without --test-run to install as service."
        exit 0
    }
fi

# 2. Create systemd service
echo "[+] Creating systemd service at $SERVICE_FILE"
sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=$SERVICE_NAME
After=network.target

[Service]
Type=simple
ExecStart=$BINARY_PATH --logs_dir $LOGS_DIR --conf_dir $CONF_DIR --exporter_ip $HOST
User=root
# NO RESTART POLICY - Application stops permanently on any exit
Restart=no
# Timeout settings
TimeoutStartSec=30
TimeoutStopSec=15
# Kill the service if it doesn't stop gracefully
KillMode=mixed
KillSignal=SIGTERM
# Logging
StandardOutput=append:$LOGS_DIR/stdout.log
StandardError=append:$LOGS_DIR/stderr.log
# Set working directory
WorkingDirectory=$SCRIPT_DIR

[Install]
WantedBy=multi-user.target
EOF

# 3. Reload and start service
echo "[+] Reloading systemd and enabling service"
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE_NAME.service"

# Check if service is already running
if sudo systemctl is-active --quiet "$SERVICE_NAME.service"; then
    echo "[!] Service is already running"
    echo "[+] Stopping existing service before restart..."
    sudo systemctl stop "$SERVICE_NAME.service"
    sleep 2
    echo "[+] Existing service stopped"
fi

# Start the service and check if it starts successfully
echo "[+] Starting service..."
if sudo systemctl start "$SERVICE_NAME.service"; then
    echo "[+] Service start command executed"
    sleep 5  # Give it more time to initialize and potentially crash
    
    # Check if service is still running
    if sudo systemctl is-active --quiet "$SERVICE_NAME.service"; then
        echo "[✓] Service is running properly"
    else
        echo "[!] Service failed to start or crashed immediately"
        echo "[!] Checking service status..."
        sudo systemctl status "$SERVICE_NAME.service" --no-pager
        echo ""
        echo "[!] Recent systemd logs:"
        sudo journalctl -u "$SERVICE_NAME.service" --no-pager -n 30 --since "5 minutes ago"
        echo ""
        echo "[!] Checking application logs..."
        if [ -f "$LOGS_DIR/EBPF/ebpf_tracer.log" ]; then
            echo "[!] Last 20 lines from ebpf_tracer.log:"
            tail -n 20 "$LOGS_DIR/EBPF/ebpf_tracer.log" 2>/dev/null || echo "[!] Could not read ebpf_tracer.log"
        else
            echo "[!] ebpf_tracer.log not found at $LOGS_DIR/EBPF/ebpf_tracer.log"
        fi
        echo ""
        if [ -f "$LOGS_DIR/stdout.log" ]; then
            echo "[!] stdout.log content:"
            cat "$LOGS_DIR/stdout.log" 2>/dev/null || echo "[!] Could not read stdout.log"
        fi
        echo ""
        if [ -f "$LOGS_DIR/stderr.log" ]; then
            echo "[!] stderr.log content:"
            cat "$LOGS_DIR/stderr.log" 2>/dev/null || echo "[!] Could not read stderr.log"
        fi
        echo ""
        echo "[!] CRASH ANALYSIS:"
        echo "    - The service appears to be crashing during license decryption"
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
        echo "    4. Try running binary manually: sudo $BINARY_PATH --logs_dir $LOGS_DIR --conf_dir $CONF_DIR --exporter_ip $HOST"
        echo "    5. Check system capabilities for eBPF: sudo sysctl kernel.unprivileged_bpf_disabled"
        exit 1
    fi
else
    echo "[!] Error: Failed to execute service start command"
    echo "[!] Checking service status and logs..."
    sudo systemctl status "$SERVICE_NAME.service" --no-pager
    echo ""
    echo "[!] Recent logs:"
    sudo journalctl -u "$SERVICE_NAME.service" --no-pager -n 20
    exit 1
fi

# 4. Show status
echo "[+] Service status:"
sudo systemctl status "$SERVICE_NAME.service" --no-pager

echo ""
echo "[✓] Setup completed successfully!"
echo "[+] Configuration:"
echo "    Binary Path: $BINARY_PATH"
echo "    Logs Directory: $LOGS_DIR"
echo "    Config Directory: $CONF_DIR"
echo "    Exporter IP: $HOST"
echo "    License Key: Read from $CONFIG_FILE"
echo ""
echo "[+] Service Management:"
echo "    Status:     sudo systemctl status $SERVICE_NAME.service"
echo "    Stop:       sudo systemctl stop $SERVICE_NAME.service"
echo "    Start:      sudo systemctl start $SERVICE_NAME.service"
echo "    Disable:    sudo systemctl disable $SERVICE_NAME.service"
echo "    Live Logs:  sudo journalctl -u $SERVICE_NAME.service -f"
echo "    Recent:     sudo journalctl -u $SERVICE_NAME.service -n 50"
echo ""
echo "[+] Log Files:"
echo "    Stdout:     $LOGS_DIR/stdout.log"
echo "    Stderr:     $LOGS_DIR/stderr.log"
echo "    Journal:    sudo journalctl -u $SERVICE_NAME.service"

