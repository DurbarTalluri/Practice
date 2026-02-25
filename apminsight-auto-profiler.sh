#!/bin/sh

AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_LINKS="AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL_PREFIX=/apminsight/agents/autoprofiler/linux/glibc/ AUTOPROFILER_INSTALL_SCRIPT_CHECKSUM_URL_PREFIX=/apminsight/agents/autoprofiler/linux/glibc/"
AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL="https://raw.githubusercontent.com/DurbarTalluri/Practice/durbar/apminsight-auto-profiler-install.sh"
AUTOPROFILER_INSTALL_SCRIPT_CHECKSUM_URL="https://raw.githubusercontent.com/DurbarTalluri/Practice/durbar/apminsight-auto-profiler-install.sh.sha256"
APMINSIGHT_BRAND="Site24x7"
APMINSIGHT_BRAND_UCASE=$(echo "$APMINSIGHT_BRAND" | sed 's/[a-z]/\U&/g')
APMINSIGHT_BRAND_LCASE=$(echo "$APMINSIGHT_BRAND" | sed 's/[A-Z]/\L&/g')
CURRENT_DIRECTORY="$(dirname "$(readlink -f "$0")")"
TEMP_FOLDER_PATH="$CURRENT_DIRECTORY/temp"
APMINSIGHT_AUTOPROFILER_PATH="/opt"
APMINSIGHT_AUTOPROFILER_VERSION="1.2.0"
STARTUP_CONF_FILEPATH="$CURRENT_DIRECTORY/autoprofilerconf.ini"
AGENT_STARTUP_LOGFILE_PATH=""
INSTALL_ARGUMENTS=""

OS_ARCH=$(uname -m)
BOOLEAN_TRUE="true"
BOOLEAN_FALSE="false"
MATCH_PHRASE_64BIT="64"
MATCH_PHRASE1_ARM="arm"
MATCH_PHRASE2_ARM="aarch"
IS_ARM=$BOOLEAN_FALSE
IS_NOTARM=$BOOLEAN_FALSE
IS_32BIT=$BOOLEAN_FALSE
IS_64BIT=$BOOLEAN_FALSE
SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_NAME="$(basename "$SCRIPT_PATH")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
ARCH_BASED_DOWNLOAD_PATH_EXTENSION=""
INSTALLATION_FAILURE_MESSAGE=""

exitFunc() {
    if [ $? -eq 1 ]; then
        Log "$INSTALLATION_FAILURE_MESSAGE"
        AUTOPROFILER_INSTALL_STATUS="Failed"
    else
        INSTALLATION_FAILURE_MESSAGE=""
    fi
    cat <<EOF > "$FS_AUTOPROFILER_STATUS_FILEPATH"
    {
    "version": "$APMINSIGHT_AUTOPROFILER_VERSION",
    "status": "$AUTOPROFILER_INSTALL_STATUS",
    "failure_message": "$INSTALLATION_FAILURE_MESSAGE"
    }
EOF
}

trap exitFunc EXIT

Log() {
    echo $(date +"%F %T.%N") " $1\n"
}

RedirectLogs() {
    # if [ -n "$EXISTING_AUTOPROFILERPATH" ] && [ -f "$EXISTING_AUTOPROFILERPATH/logs/apminsight-auto-profiler-install.log" ]; then
    #     AGENT_STARTUP_LOGFILE_PATH="$EXISTING_AUTOPROFILERPATH/logs/apminsight-auto-profiler-install.log"
    EXISTING_AGENT_LOGFILE_PATH=""
    if [ -f "$AGENT_INSTALLATION_PATH/logs/apminsight-auto-profiler-install.log" ]; then
        EXISTING_AGENT_LOGFILE_PATH="$AGENT_INSTALLATION_PATH/logs/apminsight-auto-profiler-install.log"
    elif [ -f "$AGENT_ROOT_DIR/apminsight-auto-profiler-install.log" ]; then
        EXISTING_AGENT_LOGFILE_PATH="$AGENT_ROOT_DIR/apminsight-auto-profiler-install.log"
    else
        Log "$(mkdir -p $AGENT_INSTALLATION_PATH/logs 2>&1)"
    fi
    if [ -n "$EXISTING_AGENT_LOGFILE_PATH" ]; then
        file_size=$(stat -c%s "$EXISTING_AGENT_LOGFILE_PATH")
        if [ "$file_size" -gt 1048576 ]; then
            echo "$EXISTING_AGENT_LOGFILE_PATH is larger than 1 MB. Redirecting the logs to a new file"
            mv "$EXISTING_AGENT_LOGFILE_PATH" "$AGENT_ROOT_DIR/apminsight-auto-profiler-install.log.1"
        else
            AGENT_STARTUP_LOGFILE_PATH="$EXISTING_AGENT_LOGFILE_PATH"
        fi
    fi
    exec >>"$AGENT_STARTUP_LOGFILE_PATH" 2>&1
    Log "Apminsight AutoProfilert Installation"
}

StoreInstallArgs() {
    INSTALL_ARGUMENTS="$@"
}

ReadBrandName() {
    if [ "$APMINSIGHT_BRAND" = "Site24x7" ]; then
        DATAEXPORTER_NAME="S247DataExporter"
    else
        DATAEXPORTER_NAME="AppManagerDataExporter"
    fi
    AGENT_INSTALLATION_PATH="/opt/$APMINSIGHT_BRAND_LCASE/apminsight"
    AUTOPROFILER_INFO_FILEPATH="$AGENT_INSTALLATION_PATH/fs_apm_insight_config.ini"
    AGENT_ROOT_DIR="/opt/$APMINSIGHT_BRAND_LCASE"
    APMINSIGHT_USER="$APMINSIGHT_BRAND_LCASE-user"
    APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_NAME="lib"$APMINSIGHT_BRAND_LCASE"apmautoprofilerloader.so"
    APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_PATH="/lib/$APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_NAME"
    FS_AUTOPROFILER_STATUS_FILEPATH="$AGENT_INSTALLATION_PATH/fs_apm_insight_status.json"
    AGENT_STARTUP_LOGFILE_PATH="$AGENT_INSTALLATION_PATH/apminsight-auto-profiler-install.log"
}

displayHelp() {
    echo "Usage: $0 [option] [arguments]\n \n Options:\n"
    echo "  --APMINSIGHT_LICENSE_KEY             To configure the License key"
    echo "  --APMINSIGHT_PROXY_URL               To configure Proxy Url if using, Format: protocol://user:password@host:port or protocol://user@host:port or protocol://host:port"
    #echo "  --APMINSIGHT_AUTOPROFILER_PATH           To configure Custom path for Apminsight AutoProfiler related files"
    echo "  --APMINSIGHT_MONITOR_GROUP           To configure Agent monitor groups"
}

CheckRoot() {
    if [ "$(id -u)" -ne 0 ]; then
        INSTALLATION_FAILURE_MESSAGE="Apminsight AutoProfiler installer script is run without root privilege. Please run the script apminsight-auto-profiler.sh with sudo"
        exit 1
    fi
}

CheckArgs() {
    if [ "$*" = "--help" ]; then
        displayHelp
        exit 0
    elif [ "$*" = "-version" ]; then
        echo "$APMINSIGHT_AUTOPROFILER_VERSION"
        exit 0
    fi
}

ReadConfigFromFile() {
    if [ -f $STARTUP_CONF_FILEPATH ]; then
        Log "Found autoprofilerconf.ini file. Started reading the file for Apminsight AutoProfiler startup configurations"
        while IFS= read -r line || [ -n "$line" ]; do
            case "$line" in
                *=*)
                    key=$(echo "$line" | cut -d '=' -f 1 | sed 's/[[:space:]]*$//')
                    value=$(echo "$line" | cut -d '=' -f 2- | sed 's/^[[:space:]]*//')
                    if [ -n "$key" ] && [ -n "$value" ] && [ "$value" != "0" ]; then
                        eval $key=\"$value\"
                    fi
                    ;;
            esac
        done < "$STARTUP_CONF_FILEPATH"
    fi
}

ReadConfigFromArgs() {
    Log "READING CONFIG INFO FROM COMMAND-LINE ARGUMENTS" 
    # Parse command-line arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --*=*)
                Key_val_pair="${1#--}"
                Key=$(echo "$Key_val_pair" | cut -d '=' -f 1 | sed 's/[[:space:]]*$//')
                value=$(echo "$Key_val_pair" | cut -d '=' -f 2- | sed 's/^[[:space:]]*//')
                if [ -z "$value" ] || [ "$value" = "0" ]; then
                    Log "Unacceptable value $value for the argument: $Key"
                elif [ "$Key" = "APMINSIGHT_PROXY_URL" ]; then
                    APMINSIGHT_PROXY_URL=$value
                elif [ "$Key" = "APMINSIGHT_LICENSE_KEY" ]; then
                    APMINSIGHT_LICENSE_KEY=$value
                elif [ "$Key" = "APMINSIGHT_HOST" ]; then
                    APMINSIGHT_HOST=$value
                elif [ "$Key" = "AGENT_KEY" ]; then
                    SERVER_MONITOR_KEY=$value
                elif [ "$Key" = "AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL" ]; then
                    AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL=$value
                elif [ "$Key" = "AUTOPROFILER_INSTALL_SCRIPT_CHECKSUM_URL" ]; then
                    AUTOPROFILER_INSTALL_SCRIPT_CHECKSUM_URL=$value
                fi
                ;;
            -upgrade)
                :
                ;;
            -uninstall)
                :
                ;;
            -update)
                :
                ;;
            *)
                Log "Unknown argument: $Key"
                ;;
        esac
        shift 1
    done
    if [ -z "$APMINSIGHT_LICENSE_KEY" ]; then
        Log "Unable to find License Key from commandline arguments. Please run the apminsight-auto-profiler-install.sh script again providing License Key or set License Key in the configuration file located at $AGENT_INSTALLATION_PATH in the format APMINSIGHT_LICENSEKEY=<Your License Key>"
    fi 
}

CheckMandatoryConfigurations() {
    if [ -z "$APMINSIGHT_LICENSE_KEY" ]; then
        INSTALLATION_FAILURE_MESSAGE="No License key found. Please run the script again with proper License Key"
        exit 1
    elif [ -z "$SERVER_MONITOR_KEY" ]; then
        INSTALLATION_FAILURE_MESSAGE="Server Monitor Key not found. Exiting Installation"
        exit 1
    fi
    if [ "$APMINSIGHT_BRAND" = "ApplicationsManager" ] && [ -z "$APMINSIGHT_HOST" ]; then
        INSTALLATION_FAILURE_MESSAGE="APMINSIGHT_HOST is not found. Please run the script again with proper Apminsight Host details"
        exit 1
    fi 
}

SetProxy() {
    if [ -n "$APMINSIGHT_PROXY_URL" ]; then
        export http_proxy=$APMINSIGHT_PROXY_URL
        export https_proxy=$APMINSIGHT_PROXY_URL
        export ftp_proxy=$APMINSIGHT_PROXY_URL
    fi
}

ReadStaticDomain() {
    if [ "$APMINSIGHT_BRAND" = "Site24x7" ]; then
        if echo "$APMINSIGHT_LICENSE_KEY" | grep -q "_"; then
            APMINSIGHT_DC="${APMINSIGHT_LICENSE_KEY%%_*}"
            if [ "$APMINSIGHT_DC" = "uk" ] || [ "$APMINSIGHT_DC" = "uae" ]; then
                APMINSIGHT_STATIC_DOMAIN="https://s247downloads.nimbuspop.com"
            else
                APMINSIGHT_STATIC_DOMAIN="https://staticdownloads.site24x7.com"
            fi
        fi
    fi
}

EncryptLicenseKey() {
    if [ -n "$APMINSIGHT_LICENSE_KEY" ]; then
        APMINSIGHT_AGENT_START_TIME=$(echo -n $(date -u +"%Y%m%dT%H%M%S%N") | xargs printf "%-32s" | tr ' ' '0')
        KEY_HEX=$(printf "%s" "$APMINSIGHT_AGENT_START_TIME" | od -An -tx1 | tr -d ' \n')
        APMINSIGHT_AGENT_ID="$(cat /dev/urandom | tr -dc '0-9' | fold -w 16 | head -n 1)"
        IV_HEX=$(printf "%s" "$APMINSIGHT_AGENT_ID" | od -An -tx1 | tr -d ' \n')
        APMINSIGHT_LICENSEKEY=$(echo -n "$APMINSIGHT_LICENSE_KEY" | openssl enc -aes-256-cbc -K "$KEY_HEX" -iv "$IV_HEX" -base64 -A)
        if [ -z "$APMINSIGHT_LICENSEKEY" ]; then
                INSTALLATION_FAILURE_MESSAGE="Unable to generate the License string. Abandoning the installation process"
                exit 1
        fi
    fi
}

ReadConfig() {
    ReadConfigFromFile
    ReadConfigFromArgs "$@"
    CheckMandatoryConfigurations
    SetProxy
    ReadStaticDomain
}

FindKeyValPairInFile() {
    FILEPATH="$1"
    if [ -f $FILEPATH ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            case "$line" in
                *=*)
                    key=$(echo "$line" | cut -d '=' -f 1 | sed 's/[[:space:]]*$//')
                    value=$(echo "$line" | cut -d '=' -f 2- | sed 's/^[[:space:]]*//')
                    if [ "$key" = "$2" ]; then
                        eval $3=\"$value\"
                        return 0
                    fi
                    ;;
            esac
        done < "$FILEPATH"
    fi
    return 1
}

CheckInitSystem() {
    if command -v systemctl >/dev/null 2>&1 && systemctl list-units --type=service --all >/dev/null 2>&1; then
        Log "Detected systemd as init system"
        INIT_SYSTEM="systemd"
        APMINSIGHT_SERVICE_FILE="$APMINSIGHT_BRAND_LCASE""apmautoprofiler.service"
    elif [ -f /etc/init.d/cron ] || [ -f /etc/init.d/crond ]; then
        Log "Detected sysvinit as init system"
        INIT_SYSTEM="sysvinit"
        APMINSIGHT_SERVICE_FILE="$APMINSIGHT_BRAND_LCASE""apmautoprofiler"
    else
        INSTALLATION_FAILURE_MESSAGE="Unsupported init system. Only systemd and init.d are supported."
        exit 1
    fi
    INIT_SYSTEM="sysvinit"
    APMINSIGHT_SERVICE_FILE="$APMINSIGHT_BRAND_LCASE""apmautoprofiler"
}

CheckDistribution() {
    if cat /etc/os-release 2>/dev/null | grep -iqE "rhel"; then
        IS_RHEL_BASED_DIST=1
        Log "Red Hat Enterprise Linux detected."
    elif cat /etc/os-release 2>/dev/null | grep -iqE "centos"; then
        IS_RHEL_BASED_DIST=1
        Log "CentOS detected."
    fi
}

CheckAndRemoveExistingService() {
    CheckInitSystem
    CheckDistribution
    Log "CHECKING AND REMOVING EXISTING AUTOPROFILER SERVICE IF ANY"
    if [ "$INIT_SYSTEM" = "sysvinit" ]; then
        if service --status-all 2>&1 | grep -q "$APMINSIGHT_SERVICE_FILE"; then
            Log "Found an existing $APMINSIGHT_SERVICE_FILE, Removing the service"
            Log "$(service $APMINSIGHT_SERVICE_FILE stop 2>&1)"
            if [ $IS_RHEL_BASED_DIST -eq 1 ]; then
                Log "$(chkconfig $APMINSIGHT_SERVICE_FILE off 2>&1)"
                Log "$(chkconfig --del $APMINSIGHT_SERVICE_FILE 2>&1)"
            else
                Log "$(update-rc.d -f $APMINSIGHT_SERVICE_FILE remove 2>&1)"
            fi
            rm -f /etc/init.d/$APMINSIGHT_SERVICE_FILE
        else
            Log "No existing $APMINSIGHT_SERVICE_FILE found"
        fi
    elif [ "$INIT_SYSTEM" = "systemd" ]; then
        if systemctl list-units --type=service --all | grep -q "$APMINSIGHT_SERVICE_FILE"; then
            Log "Found an existing $APMINSIGHT_SERVICE_FILE, Removing the service"
            Log "$(systemctl stop $APMINSIGHT_SERVICE_FILE 2>&1)"
            Log "$(systemctl disable $APMINSIGHT_SERVICE_FILE 2>&1)"
            Log "$(systemctl daemon-reload 2>&1)"
        else
            Log "No existing $APMINSIGHT_SERVICE_FILE found"
        fi
        rm -f /etc/systemd/system/$APMINSIGHT_SERVICE_FILE
    fi
}

UninstallAutoProfiler() {
    Log "$(sed -i "\|$APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_NAME|d" /etc/ld.so.preload 2>&1)"
    Log "$(sed -i "\|$APMINSIGHT_BRAND_UCASE|d" /etc/environment 2>&1)"
    CheckAndRemoveExistingService
    Log "$(rm $APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_PATH 2>&1)"
    Log "$(sh /opt/$DATAEXPORTER_NAME/bin/service.sh uninstall 2>&1)"
    Log "$(rm -r /opt/$DATAEXPORTER_NAME 2>&1)"
    Log "$(pip uninstall --yes apminsight 2>&1)"
    if grep -q '\b'$APMINSIGHT_USER'\b' /etc/sudoers; then
        Log "$(sed -i '/\b'$APMINSIGHT_USER'\b/d' /etc/sudoers 2>&1)"
    fi
    Log "$(mv $AGENT_STARTUP_LOGFILE_PATH "$AGENT_ROOT_DIR" 2>&1)"
    Log "$(rm -r $AGENT_INSTALLATION_PATH 2>&1)"
    exit 0
}

UpdateAutoProfilerConfig() {
    AUTOPROFILER_CONF_FILEPATH="$AGENT_INSTALLATION_PATH/conf/autoprofilerconf.ini"
    EXISTING_CONFIG=$(<"$AUTOPROFILER_CONF_FILEPATH")
    CHANGED_CONFIGS=""
    for key in $@; do
        while [ $# -gt 0 ]; do
            case "$1" in
                --*=*)
                    Key_val_pair="${1#--}"
                    Key=$(echo "$Key_val_pair" | cut -d '=' -f 1 | sed 's/[[:space:]]*$//')
                    value=$(echo "$Key_val_pair" | cut -d '=' -f 2- | sed 's/^[[:space:]]*//')
                    if [ -z "$value" ] || [ "$value" = "0" ]; then
                        Log "Unacceptable value $value for the argument: $Key"
                    elif [ "$Key" = "APMINSIGHT_LICENSE_KEY" ]; then
                        APMINSIGHT_LICENSE_KEY=$value
                        EncryptLicenseKey
                        CHANGED_CONFIGS="$CHANGED_CONFIGS APMINSIGHT_LICENSEKEY APMINSIGHT_AGENT_START_TIME APMINSIGHT_AGENT_ID"
                    elif [ "$Key" = "APMINSIGHT_PROXY_URL" ]; then
                        APMINSIGHT_PROXY_URL=$value
                        CHANGED_CONFIGS="$CHANGED_CONFIGS APMINSIGHT_PROXY_URL"
                    elif [ "$Key" = "APMINSIGHT_HOST" ]; then
                        APMINSIGHT_HOST=$value
                        CHANGED_CONFIGS="$CHANGED_CONFIGS APMINSIGHT_HOST"
                    elif [ "$Key" = "AGENT_KEY" ]; then
                        SERVER_MONITOR_KEY=$value
                        CHANGED_CONFIGS="$CHANGED_CONFIGS SERVER_MONITOR_KEY"
                    else
                        Log "Invalid argument name for AutoProfiler Config Update : $Key. Please provide a valid one"
                    fi
                    ;;
                -upgrade)
                    :
                    ;;
                -uninstall)
                    :
                    ;;
                -update)
                    :
                    ;;
                *)
                    Log "Unknown argument: $Key"
                    ;;
            esac
            shift 1
        done
    done
    if grep -q "^\[$APMINSIGHT_AUTOPROFILER_CONF_SECTION\]" $AUTOPROFILER_CONF_FILEPATH; then
        for config in $CHANGED_CONFIGS; do
            Log "CONFIG: $config"
            eval "config_val=\$$config"
            VALUE="$(printf '%s\n' "$config_val" | sed 's/[&/\]/\\&/g')"
            if grep -A10 "^\[$APMINSIGHT_AUTOPROFILER_CONF_SECTION\]" $AUTOPROFILER_CONF_FILEPATH | grep -q "^$config *= *"; then
                sed -i "/^\[$APMINSIGHT_AUTOPROFILER_CONF_SECTION\]/,/^\[/ s/^$config *= *.*/$config = $VALUE/" $AUTOPROFILER_CONF_FILEPATH
            else
                sed -i "/^\[$APMINSIGHT_AUTOPROFILER_CONF_SECTION\]/a $config = $VALUE" $AUTOPROFILER_CONF_FILEPATH
            fi
        done
    else
        Log "No AutoProfiler Configuration File detected to update..."
        exit 0  
    fi
}

CompareAgentVersions() {
    Log "Found existing Apminsight AutoProfiler of Version $EXISTING_APMINSIGHT_AUTOPROFILER_VERSION"
    EXISTING_AGENT_VERSION_NUM="$(echo "$EXISTING_APMINSIGHT_AUTOPROFILER_VERSION" | sed 's/\.//g')"
    EXISTING_AGENT_VERSION_NUM=$((EXISTING_AGENT_VERSION_NUM))
    CURRENT_AGENT_VERSION_NUM="$(echo "$APMINSIGHT_AUTOPROFILER_VERSION" | sed 's/\.//g')"
    CURRENT_AGENT_VERSION_NUM=$((CURRENT_AGENT_VERSION_NUM))
    if [ "$EXISTING_AGENT_VERSION_NUM" -lt "$CURRENT_AGENT_VERSION_NUM" ]; then
        if [ -f "$AGENT_INSTALLATION_PATH/conf/autoprofilerconf.ini" ]; then
            STARTUP_CONF_FILEPATH="$AGENT_INSTALLATION_PATH/conf/autoprofilerconf.ini"
        fi
        if [ "$AUTOPROFILER_OPERATION" = "install" ]; then
            INSTALLATION_FAILURE_MESSAGE="An outdated version of Apminsight AutoProfiler exists. Please run sudo sh apminsight-auto-profiler-install.sh -upgrade to upgrade Apminsight AutoProfiler to latest version"
            exit 1
        else
            Log "Proceeding to Upgrade the existing Apminsight AutoProfiler of version $EXISTING_APMINSIGHT_AUTOPROFILER_VERSION"
            return
        fi
        
    elif [ "$EXISTING_AGENT_VERSION_NUM" -gt "$CURRENT_AGENT_VERSION_NUM" ]; then
        INSTALLATION_FAILURE_MESSAGE="A greater version of Apminsight AutoProfiler already exists. Skipping Apminsight AutoProfiler $AUTOPROFILER_OPERATION"
        exit 1
    else
        INSTALLATION_FAILURE_MESSAGE="This version of Apminsight AutoProfiler already exists. Skipping Apminsight AutoProfiler $AUTOPROFILER_OPERATION"
        exit 1
    fi

}

CheckAgentInstallation() {
    FindKeyValPairInFile "/etc/environment" ""$APMINSIGHT_BRAND_UCASE"_APMINSIGHT_AUTOPROFILER_VERSION" "EXISTING_APMINSIGHT_AUTOPROFILER_VERSION"
    if [ "$1" = "-uninstall" ]; then
        Log "Uninstalling Apminsight AutoProfiler...."
        AUTOPROFILER_OPERATION="uninstall"
        if [ -z "$EXISTING_APMINSIGHT_AUTOPROFILER_VERSION" ]; then
            Log "Apminsight AutoProfiler is not found installed. Purging AutoProfiler resources..."
        fi
        UninstallAutoProfiler

    elif [ "$1" = "-update" ]; then
        Log "Updating Apminsight AutoProfiler Configurations..."
        if [ -z "$EXISTING_APMINSIGHT_AUTOPROFILER_VERSION" ]; then
            Log "Apminsight AutoProfiler is not found installed. Purging AutoProfiler resources..."
        fi
        UpdateAutoProfilerConfig $@
        exit 0

    elif [ "$1" = "-upgrade" ]; then
        AUTOPROFILER_OPERATION="upgrade"
        if [ -z "$EXISTING_APMINSIGHT_AUTOPROFILER_VERSION" ]; then
            Log "No existing Apminsight AutoProfiler version found."
            Log "Installing Apminsight AutoProfiler..."
            AUTOPROFILER_OPERATION="install"
            return
        else
            Log "Upgrading Apminsight AutoProfiler..."
        fi
     else
        if [ -z "$EXISTING_APMINSIGHT_AUTOPROFILER_VERSION" ]; then
            Log "Installing Apminsight AutoProfiler..."
            return
        fi
    fi
    CompareAgentVersions
}

WriteToInfoFile() {
    Log "WRITING TO $AUTOPROFILER_INFO_FILEPATH file"
    mkdir -p "$AGENT_INSTALLATION_PATH"
    touch "$AUTOPROFILER_INFO_FILEPATH"
    echo "[apm_insight]\nProcessName=apminsight-autoprofiler start\nServiceName="$APMINSIGHT_BRAND_LCASE"apmautoprofiler\nDisplayName="$APMINSIGHT_BRAND_LCASE"apmautoprofiler\nVersion=$APMINSIGHT_AUTOPROFILER_VERSION" > "$AUTOPROFILER_INFO_FILEPATH"
}

CheckBit() {
	Log "Action: Checking if Operating System is 32 or 64 bit"

	if echo "${OS_ARCH}" | grep -i -q "${MATCH_PHRASE_64BIT}"; then
		IS_64BIT=$BOOLEAN_TRUE
		Log "Info: Detected as 64bit"
	else
		IS_32BIT=$BOOLEAN_TRUE
		Log "Info: Detected as 32bit"
	fi
}

CheckARM() {
	Log "Action: Checking if ARM achitecture"

	if echo "${OS_ARCH}" | grep -i -q "${MATCH_PHRASE1_ARM}"; then
		IS_ARM=$BOOLEAN_TRUE
		Log "Info: Detected as ARM"
	elif echo "${OS_ARCH}" | grep -i -q "${MATCH_PHRASE2_ARM}"; then
		IS_ARM=$BOOLEAN_TRUE
		Log "Info: Detected as ARM"
	else
		IS_NOTARM=$BOOLEAN_TRUE
		Log "Info: Detected as not ARM"
	fi
}

SetArchBasedDownloadPathExtension() {
    if [ "$IS_NOTARM" = "$BOOLEAN_TRUE" ] && [ "$IS_32BIT" = "$BOOLEAN_TRUE" ]; then
		ARCH_BASED_DOWNLOAD_PATH_EXTENSION="386"
	elif [ "$IS_NOTARM" = "$BOOLEAN_TRUE" ] && [ "$IS_64BIT" = "$BOOLEAN_TRUE" ]; then
		ARCH_BASED_DOWNLOAD_PATH_EXTENSION="amd64"
	elif [ "$IS_ARM" = "$BOOLEAN_TRUE" ] && [ "$IS_32BIT" = "$BOOLEAN_TRUE" ]; then
		ARCH_BASED_DOWNLOAD_PATH_EXTENSION="arm"
	elif [ "$IS_ARM" = "$BOOLEAN_TRUE" ] && [ "$IS_64BIT" = "$BOOLEAN_TRUE" ]; then
		ARCH_BASED_DOWNLOAD_PATH_EXTENSION="arm64"
	else
		INSTALLATION_FAILURE_MESSAGE="Info: $OS_ARCH not supported in this version"
        exit 1
    fi
}

CheckAndCollectHostInfo() {
    CheckBit
    CheckARM
    SetArchBasedDownloadPathExtension
}

ParseInstallScriptDownloadLinks() {
    for kv in $AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_LINKS; do
        key=$(echo "$kv" | cut -d'=' -f1)
        value=$(echo "$kv" | cut -d'=' -f2)
        eval "$key='$value'"
    done
}

RemoveInstallationFiles() {
    rm -rf "$TEMP_FOLDER_PATH"
}

MoveInstallationFiles() {
    if [ "$SCRIPT_DIR" != "$AGENT_INSTALLATION_PATH/bin" ]; then
        if [ -f "$SCRIPT_PATH" ]; then
            mv "$SCRIPT_PATH" "$AGENT_INSTALLATION_PATH/bin/"
        else
            Log "Script file $SCRIPT_PATH not found, cannot move."
        fi
    fi
    
}

ValidateChecksumAndInstallAutoProfiler() {
    Log "Checksum validation for the file $1"
    file="$1"
    checksumVerificationLink="$2"
    destinationpath="$3"
    checksumfilename="$file-checksum"
    wget --no-check-certificate -nv -O "$checksumfilename" $checksumVerificationLink
    Originalchecksumvalue="$(cat "$checksumfilename")"
    Originalchecksumvalue="$(echo "$Originalchecksumvalue" | tr '[:upper:]' '[:lower:]')"
    Downloadfilechecksumvalue="$(sha256sum $file | awk -F' ' '{print $1}')"
    if [ "$Originalchecksumvalue" = "$Downloadfilechecksumvalue" ]; then
        mv "$file" "$destinationpath"
        cd "$destinationpath"
        sh apminsight-auto-profiler-install.sh $INSTALL_ARGUMENTS
        INSTALL_EXIT_CODE=$?
        if [ $INSTALL_EXIT_CODE -ne 0 ]; then
            Log "Failed to Install Apminsight AutoProfiler"
            exit 1
        else
            Log "Successfully Installed Apminsight AutoProfiler"
            AUTOPROFILER_INSTALL_STATUS="Success"
            RemoveInstallationFiles
            MoveInstallationFiles
        fi
    fi
}

DownloadAndRunInstallScriptFile() {
    mkdir -p "$TEMP_FOLDER_PATH"
    cd "$TEMP_FOLDER_PATH"
    if [ "$APMINSIGHT_BRAND" = "Site24x7" ]; then
        if [ -z "$AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL" ]; then
            AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL="$APMINSIGHT_STATIC_DOMAIN""$AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL_PREFIX""$ARCH_BASED_DOWNLOAD_PATH_EXTENSION""/apminsight-auto-profiler-install.sh"
            AUTOPROFILER_INSTALL_SCRIPT_CHECKSUM_URL="$APMINSIGHT_STATIC_DOMAIN""$AUTOPROFILER_INSTALL_SCRIPT_CHECKSUM_URL_PREFIX""$ARCH_BASED_DOWNLOAD_PATH_EXTENSION""/apminsight-auto-profiler-install.sh.sha256"
        fi
        if wget -q -nv "$AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL"; then
            ValidateChecksumAndInstallAutoProfiler "apminsight-auto-profiler-install.sh" "$AUTOPROFILER_INSTALL_SCRIPT_CHECKSUM_URL" "$AGENT_INSTALLATION_PATH"
        else
            INSTALLATION_FAILURE_MESSAGE="Failed to Download Apminsight AutoProfiler Install Script"
            exit 1
        fi
    else
        DOWNLOAD_SUCCESSFUL="$BOOLEAN_FALSE"
        if [ -n "$AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL" ]; then
            if wget --no-check-certificate -q -nv "$AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL"; then
                ValidateChecksumAndInstallAutoProfiler "apminsight-auto-profiler-install.sh" "$AUTOPROFILER_INSTALL_SCRIPT_CHECKSUM_URL" "$AGENT_INSTALLATION_PATH"
                DOWNLOAD_SUCCESSFUL="$BOOLEAN_TRUE"
            else
                INSTALLATION_FAILURE_MESSAGE="Failed to Download Apminsight AutoProfiler Install Script"
                exit 1
            fi
        else
            for host_url in $(echo "$APMINSIGHT_HOST" | tr ',' '\n'); do
                AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL="$host_url""$AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL_PREFIX""$ARCH_BASED_DOWNLOAD_PATH_EXTENSION""/apminsight-auto-profiler-install.sh"
                AUTOPROFILER_INSTALL_SCRIPT_CHECKSUM_URL="$host_url""$AUTOPROFILER_INSTALL_SCRIPT_CHECKSUM_URL_PREFIX""$ARCH_BASED_DOWNLOAD_PATH_EXTENSION""/apminsight-auto-profiler-install.sh.sha256"
                Log "Downloading Apminsight AutoProfiler Install Script from $AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL"
                if wget --no-check-certificate -q -nv "$AUTOPROFILER_INSTALL_SCRIPT_DOWNLOAD_URL"; then
                    ValidateChecksumAndInstallAutoProfiler "apminsight-auto-profiler-install.sh" "$AUTOPROFILER_INSTALL_SCRIPT_CHECKSUM_URL" "$AGENT_INSTALLATION_PATH"
                    DOWNLOAD_SUCCESSFUL="$BOOLEAN_TRUE"
                    break
                else
                    Log "Failed to Download Apminsight AutoProfiler Install Script"
                    continue
                fi
            done
            if [ "$DOWNLOAD_SUCCESSFUL" = "$BOOLEAN_FALSE" ]; then
                INSTALLATION_FAILURE_MESSAGE="Failed to Download Apminsight AutoProfiler Install Script"
                exit 1
            fi
        fi
    fi
    cd "$CURRENT_DIRECTORY"
}

InstallAutoProfiler() {
    CheckAndCollectHostInfo
    ParseInstallScriptDownloadLinks
    DownloadAndRunInstallScriptFile
}

main() {
    StoreInstallArgs "$@"
    ReadBrandName
    RedirectLogs
    CheckArgs "$@"
    CheckRoot
    CheckAgentInstallation "$@"
    WriteToInfoFile
    ReadConfig "$@"
    InstallAutoProfiler
    exit 0
    }

main "$@"
