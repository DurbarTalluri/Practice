#!/bin/sh

AGENT_DOWNLOAD_LINKS="AUTOPROFILER_FILES_DOWNLOAD_URL_PREFIX=/apminsight/agents/autoprofiler/linux/glibc/ AUTOPROFILER_FILES_CHECKSUM_URL_PREFIX=/apminsight/agents/autoprofiler/linux/glibc/"
AUTOPROFILER_FILES_DOWNLOAD_URL=https://raw.githubusercontent.com/DurbarTalluri/Practice/main/apminsight-auto-profiler-files.zip
AUTOPROFILER_FILES_CHECKSUM_URL=https://raw.githubusercontent.com/DurbarTalluri/Practice/main/apminsight-auto-profiler-files.zip.sha256
APMINSIGHT_BRAND="Site24x7"
APMINSIGHT_BRAND_UCASE=$(echo "$APMINSIGHT_BRAND" | sed 's/[a-z]/\U&/g')
APMINSIGHT_BRAND_LCASE=$(echo "$APMINSIGHT_BRAND" | sed 's/[A-Z]/\L&/g')
CURRENT_DIRECTORY="$(dirname "$(readlink -f "$0")")"
APMINSIGHT_AUTOPROFILER_PATH="/opt"
PRELOAD_FILE_PATH="/etc/ld.so.preload"
AGENT_STARTUP_LOGFILE_PATH="$CURRENT_DIRECTORY/apminsight-auto-profiler-install.log"
STARTUP_CONF_FILEPATH="$CURRENT_DIRECTORY/autoprofilerconf.ini"
FS_AUTOPROFILER_STATUS_FILEPATH=""
INSTALLATION_FAILURE_MESSAGE="ERROR OCCURED WHILE EXECUTING APMINSIGHT AUTOPROFILER SCRIPT"
APMINSIGHT_AUTOPROFILER_CONF_SECTION=apminsight_auto_profiler
BUNDLED=0
APMINSIGHT_LICENSEKEY=""
APMINSIGHT_LICENSE_KEY=""
TEMP_FOLDER_PATH="$CURRENT_DIRECTORY/temp"
AGENT_CONF_STR=""
APMINSIGHT_HOST=""
APMINSIGHT_PROXY_URL=""
APMINSIGHT_AGENT_START_TIME=""
APMINSIGHT_AGENT_ID=""
APMINSIGHT_DATAEXPORTER_HOST=""
HOST_OS="linux"
HOST_ARCH=""
HOST_LIBC_DIST=""

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
ARCH_BASED_DOWNLOAD_PATH_EXTENSION=""
APMSIGHT_PROTOCOL="http"
APMINSIGHT_AUTOPROFILER_VERSION="1.0.0"
AUTOPROFILER_OPERATION="install"
GLIBC_VERSION_COMPATIBLE="2.7"
GCC_VERSION_COMPATIBLE="5.4"
AUTOPROFILER_INSTALL_STATUS="Successful"

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

displayHelp() {
    echo "Usage: $0 [option] [arguments]\n \n Options:\n"
    echo "  --APMINSIGHT_LICENSE_KEY             To configure the License key"
    echo "  --APMINSIGHT_PROXY_URL               To configure Proxy Url if using, Format: protocol://user:password@host:port or protocol://user@host:port or protocol://host:port"
    #echo "  --APMINSIGHT_AUTOPROFILER_PATH           To configure Custom path for Apminsight AutoProfiler related files"
    echo "  --APMINSIGHT_MONITOR_GROUP           To configure Agent monitor groups"
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


ParseAgentDownloadLinks() {
    for kv in $AGENT_DOWNLOAD_LINKS; do
        key=$(echo "$kv" | cut -d'=' -f1)
        value=$(echo "$kv" | cut -d'=' -f2)
        eval "$key='$value'"
    done
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
    APMINSIGHT_GROUP="$APMINSIGHT_BRAND_LCASE-group"
    APMINSIGHT_SERVICE_FILE="$APMINSIGHT_BRAND_LCASE""apmautoprofiler.service"
    APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_NAME="lib"$APMINSIGHT_BRAND_LCASE"apmautoprofilerloader.so"
    APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_PATH="/lib/$APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_NAME"
    NEW_PYTHON_PATH="$AGENT_INSTALLATION_PATH/lib/PYTHON/wheels:$AGENT_INSTALLATION_PATH/lib/PYTHON/wheels/apminsight/bootstrap"
    FS_AUTOPROFILER_STATUS_FILEPATH="$AGENT_INSTALLATION_PATH/fs_apm_insight_status.json"
    ParseAgentDownloadLinks
}

RedirectLogs() {
    # if [ -n "$EXISTING_AUTOPROFILERPATH" ] && [ -f "$EXISTING_AUTOPROFILERPATH/logs/apminsight-auto-profiler-install.log" ]; then
    #     AGENT_STARTUP_LOGFILE_PATH="$EXISTING_AUTOPROFILERPATH/logs/apminsight-auto-profiler-install.log"
    EXISTING_AGENT_LOGFILE_PATH=""
    if [ -f "$AGENT_INSTALLATION_PATH/logs/apminsight-auto-profiler-install.log" ]; then
        EXISTING_AGENT_LOGFILE_PATH="$AGENT_INSTALLATION_PATH/logs/apminsight-auto-profiler-install.log"
    elif [ -f "$AGENT_ROOT_DIR/apminsight-auto-profiler-install.log" ]; then
        EXISTING_AGENT_LOGFILE_PATH="$AGENT_ROOT_DIR/apminsight-auto-profiler-install.log"
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
}

Log() {
    echo $(date +"%F %T.%N") " $1\n"
}

CheckRoot() {
    if [ "$(id -u)" -ne 0 ]; then
        INSTALLATION_FAILURE_MESSAGE="Apminsight AutoProfiler installer script is run without root privilege. Please run the script apminsight-auto-profiler.sh with sudo"
        exit 1
    fi
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

SetHostArch() {
    HOST_ARCH="$ARCH_BASED_DOWNLOAD_PATH_EXTENSION"
}

SetupPreInstallationChecks() {
    CheckBit
    CheckARM
    SetArchBasedDownloadPathExtension
    SetHostArch
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
                elif [ "$Key" = "BUNDLED" ]; then
                    BUNDLED=1
                elif [ "$Key" = "APMINSIGHT_LICENSE_KEY" ]; then
                    APMINSIGHT_LICENSE_KEY=$value     
                elif [ "$Key" = "APMINSIGHT_PROXY_URL" ]; then
                    APMINSIGHT_PROXY_URL=$value
                elif [ "$Key" = "APMINSIGHT_HOST" ]; then
                    APMINSIGHT_HOST=$value
                elif [ "$Key" = "APMINSIGHT_MONITOR_GROUP" ]; then
                    APMINSIGHT_MONITOR_GROUP=$value
                elif [ "$Key" = "AGENT_KEY" ]; then
                    AGENT_KEY=$value
                elif [ "$Key" = "CUSTOM_APM_AGENTS" ]; then
                    CUSTOM_APM_AGENTS="$value"
                elif [ "$Key" = "JAVA_AGENT_DOWNLOAD_URL" ]; then
                    JAVA_AGENT_DOWNLOAD_URL="$value"
                elif [ "$Key" = "NODEJS_AGENT_DOWNLOAD_URL" ]; then
                    NODEJS_AGENT_DOWNLOAD_URL="$value"
                elif [ "$Key" = "PYTHON_AGENT_DOWNLOAD_URL" ]; then
                    PYTHON_AGENT_DOWNLOAD_URL="$value"
                elif [ "$Key" = "DOTNET_AGENT_DOWNLOAD_URL" ]; then
                    DOTNET_AGENT_DOWNLOAD_URL="$value"
                elif [ "$Key" = "DATAEXPORTER_DOWNLOAD_URL" ]; then
                    DATAEXPORTER_DOWNLOAD_URL="$value"
                elif [ "$Key" = "AUTOPROFILER_FILES_DOWNLOAD_URL" ]; then
                    AUTOPROFILER_FILES_DOWNLOAD_URL="$value"
                elif [ "$Key" = "JAVA_AGENT_CHECKSUM_VALUE" ]; then
                    JAVA_AGENT_CHECKSUM_VALUE="$value"
                elif [ "$Key" = "NODEJS_AGENT_CHECKSUM_VALUE" ]; then
                    NODEJS_AGENT_CHECKSUM_VALUE="$value"
                elif [ "$Key" = "PYTHON_AGENT_CHECKSUM_VALUE" ]; then
                    PYTHON_AGENT_CHECKSUM_VALUE="$value"
                elif [ "$Key" = "DOTNET_AGENT_CHECKSUM_VALUE" ]; then
                    DOTNET_AGENT_CHECKSUM_VALUE="$value"
                elif [ "$Key" = "DATAEXPORTER_CHECKSUM_VALUE" ]; then
                    DATAEXPORTER_CHECKSUM_VALUE="$value"
                elif [ "$Key" = "JAVA_AGENT_CHECKSUM_URL" ]; then
                    JAVA_AGENT_CHECKSUM_URL="$value"
                elif [ "$Key" = "NODEJS_AGENT_CHECKSUM_URL" ]; then
                    NODEJS_AGENT_CHECKSUM_URL="$value"
                elif [ "$Key" = "PYTHON_AGENT_CHECKSUM_URL" ]; then
                    PYTHON_AGENT_CHECKSUM_URL="$value"
                elif [ "$Key" = "DOTNET_AGENT_CHECKSUM_URL" ]; then
                    DOTNET_AGENT_CHECKSUM_URL="$value"
                elif [ "$Key" = "DATAEXPORTER_CHECKSUM_URL" ]; then
                    DATAEXPORTER_CHECKSUM_URL="$value"
                elif [ "$Key" = "AUTOPROFILER_FILES_CHECKSUM_URL" ]; then
                    AUTOPROFILER_FILES_CHECKSUM_URL="$value"
                elif [ "$Key" = "JAVA_AGENT_VERSION" ]; then
                    JAVA_AGENT_VERSION="$value"
                elif [ "$Key" = "PYTHON_AGENT_VERSION" ]; then
                    PYTHON_AGENT_VERSION="$value"
                elif [ "$Key" = "NODEJS_AGENT_VERSION" ]; then
                    NODEJS_AGENT_VERSION="$value"
                elif [ "$Key" = "DOTNET_AGENT_VERSION" ]; then
                    DOTNET_AGENT_VERSION="$value"
                elif [ "$Key" = "DATAEXPORTER_VERSION" ]; then
                    DATAEXPORTER_VERSION="$value"
                elif [ "$Key" = "APMINSIGHT_DATAEXPORTER_HOST" ]; then
                    APMINSIGHT_DATAEXPORTER_HOST="$value"
                else
                    Log "Invalid argument name : $Key. Please provide a valid one"
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
        Log "Unable to find License Key from commandline arguments. Please run the apminsight-auto-profiler.sh script again providing License Key or set License Key in the configuration file located at $AGENT_INSTALLATION_PATH in the format APMINSIGHT_LICENSEKEY=<Your License Key>"
    fi
}

SetProxy() {
    if [ -n "$APMINSIGHT_PROXY_URL" ]; then
        export http_proxy=$APMINSIGHT_PROXY_URL
        export https_proxy=$APMINSIGHT_PROXY_URL
        export ftp_proxy=$APMINSIGHT_PROXY_URL
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

CheckMandatoryConfigurations() {
    if [ -z "$APMINSIGHT_LICENSE_KEY" ]; then
        INSTALLATION_FAILURE_MESSAGE="No License key found. Please run the script again with proper License Key"
        exit 1
    elif [ -z "$AGENT_KEY" ]; then
        INSTALLATION_FAILURE_MESSAGE="Agent Key not found. Exiting Installation"
        exit 1
    fi
    if [ "$APMINSIGHT_BRAND" = "ApplicationsManager" ] && [ -z "$APMINSIGHT_HOST" ]; then
        INSTALLATION_FAILURE_MESSAGE="APMINSIGHT_HOST is not found. Please run the script again with proper Apminsight Host details"
        exit 1
    fi 
}

SetupAgentConfigurations() {
    ReadConfigFromFile
    ReadConfigFromArgs "$@"
    CheckMandatoryConfigurations
    SetProxy
    EncryptLicenseKey
}

#CHECKSUM VALIDATION
ValidateChecksumAndInstallAgent() {
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
        unzip "$file" -d "$destinationpath"
    fi
}

RemoveExistingAutoProfilerFiles() {
    Log "Removing existing Apminsight AutoProfiler binaries and files"
    find "$AGENT_INSTALLATION_PATH/bin" -mindepth 1 -delete
    sed -i '/'$APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_NAME'$/d' /etc/ld.so.preload
    rm -f "$APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_PATH"
}

#CREATE AGENT FOLDERS IN USER MACHINE AND STORE THE DOWNLOADED AGENT FILES 
CreateAutoProfilerFiles() {
    Log "CREATING AUTOPROFILER FILES"
    mkdir -p "$AGENT_INSTALLATION_PATH"
    mkdir -p "$AGENT_INSTALLATION_PATH/conf"
    mkdir -p "$AGENT_INSTALLATION_PATH/lib"
    mkdir -p "$AGENT_INSTALLATION_PATH/bin"
    mkdir -p "$AGENT_INSTALLATION_PATH/logs"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents"
    touch "$AGENT_INSTALLATION_PATH/logs/autoprofilerloader.log"
    touch "$AGENT_INSTALLATION_PATH/conf/apm-agents-versions.json"
}

DownloadAutoProfilerBinaries() {
    mkdir -p "$TEMP_FOLDER_PATH"
    cd "$TEMP_FOLDER_PATH"
    if [ "$APMINSIGHT_BRAND" = "Site24x7" ]; then
        if [ -z "$AUTOPROFILER_FILES_DOWNLOAD_URL" ]; then
            AUTOPROFILER_FILES_DOWNLOAD_URL="https://staticdownloads.site24x7.com""$AUTOPROFILER_FILES_DOWNLOAD_URL_PREFIX""$ARCH_BASED_DOWNLOAD_PATH_EXTENSION""/apminsight-auto-profiler-files.zip"
            AUTOPROFILER_FILES_CHECKSUM_URL="https://staticdownloads.site24x7.com""$AUTOPROFILER_FILES_CHECKSUM_URL_PREFIX""$ARCH_BASED_DOWNLOAD_PATH_EXTENSION""/apminsight-auto-profiler-files.zip.sha256"
        fi
        if wget -q -nv "$AUTOPROFILER_FILES_DOWNLOAD_URL"; then
            ValidateChecksumAndInstallAgent "apminsight-auto-profiler-files.zip" "$AUTOPROFILER_FILES_CHECKSUM_URL" "$AGENT_INSTALLATION_PATH/bin"
        else
            INSTALLATION_FAILURE_MESSAGE="Failed to Download Apminsight AutoProfiler binaries"
            exit 1
        fi
    else
        DOWNLOAD_SUCCESSFUL="$BOOLEAN_FALSE"
        if [ -n "$AUTOPROFILER_FILES_DOWNLOAD_URL" ]; then
            if wget --no-check-certificate -q -nv "$AUTOPROFILER_FILES_DOWNLOAD_URL"; then
                ValidateChecksumAndInstallAgent "apminsight-auto-profiler-files.zip" "$AUTOPROFILER_FILES_CHECKSUM_URL" "$AGENT_INSTALLATION_PATH/bin"
                DOWNLOAD_SUCCESSFUL="$BOOLEAN_TRUE"
            else
                INSTALLATION_FAILURE_MESSAGE="Failed to Download Apminsight AutoProfiler binaries"
                exit 1
            fi
        else
            for host_url in $(echo "$APMINSIGHT_HOST" | tr ',' '\n'); do
                AUTOPROFILER_FILES_DOWNLOAD_URL="$host_url""$AUTOPROFILER_FILES_DOWNLOAD_URL_PREFIX""$ARCH_BASED_DOWNLOAD_PATH_EXTENSION""/apminsight-auto-profiler-files.zip"
                AUTOPROFILER_FILES_CHECKSUM_URL="$host_url""$AUTOPROFILER_FILES_CHECKSUM_URL_PREFIX""$ARCH_BASED_DOWNLOAD_PATH_EXTENSION""/apminsight-auto-profiler-files.zip.sha256"
                Log "Downloading Apminsight AutoProfiler binaries from $AUTOPROFILER_FILES_DOWNLOAD_URL"
                if wget --no-check-certificate -q -nv "$AUTOPROFILER_FILES_DOWNLOAD_URL"; then
                    ValidateChecksumAndInstallAgent "apminsight-auto-profiler-files.zip" "$AUTOPROFILER_FILES_CHECKSUM_URL" "$AGENT_INSTALLATION_PATH/bin"
                    DOWNLOAD_SUCCESSFUL="$BOOLEAN_TRUE"
                else
                    Log "Failed to Download Apminsight AutoProfiler binaries"
                    continue
                fi
            done
            if [ "$DOWNLOAD_SUCCESSFUL" = "$BOOLEAN_FALSE" ]; then
                INSTALLATION_FAILURE_MESSAGE="Failed to Download Apminsight AutoProfiler binaries"
                exit 1
            fi
        fi
    fi
    mv "$AGENT_INSTALLATION_PATH/bin/autoprofilerloader.so" "$APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_PATH"
    cd "$CURRENT_DIRECTORY"
}

SetupAutoProfilerFiles() {
    Log "DELETING EXISTING AUTOPROFILER FILES IF ANY"
    RemoveExistingAutoProfilerFiles
    CreateAutoProfilerFiles
    DownloadAutoProfilerBinaries
}

#GIVE RESPECTIVE PERMISSIONS TO AGENT FILES
GiveFilePermissions() {
    Log "GIVING FILE PERMISSIONS"
    chown -R $APMINSIGHT_USER:$APMINSIGHT_GROUP "$AGENT_INSTALLATION_PATH"
    chmod 777 -R "$AGENT_INSTALLATION_PATH"
    chmod 755 -R "$AGENT_INSTALLATION_PATH/bin"
    chmod 755 -R "$AGENT_INSTALLATION_PATH/logs"
    chmod 777 -R "$AGENT_INSTALLATION_PATH/agents"
    chmod 755 -R "$AGENT_INSTALLATION_PATH/lib"
    chmod 777 -R "$AGENT_INSTALLATION_PATH/logs/autoprofilerloader.log"
    chmod 644 "$PRELOAD_FILE_PATH"
    chmod 644 "$APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_PATH"
}

RemoveExistingAgentFiles() {
    Log "REMOVING EXISTING APMINSIGHT AGENT FILES"
    rm -rf "$AGENT_INSTALLATION_PATH/lib/"
}

WriteToAgentConfFile() {
	AGENT_CONF_STR="[$APMINSIGHT_AUTOPROFILER_CONF_SECTION]\n"

	if [ -n "$APMINSIGHT_PROXY_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_PROXY_URL=$APMINSIGHT_PROXY_URL\n"
    fi
    if [ -n "$APMINSIGHT_MONITOR_GROUP" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_MONITOR_GROUP=$APMINSIGHT_MONITOR_GROUP\n"
    fi
    if [ -n "$NEW_PYTHON_PATH" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""NEW_PYTHON_PATH=$NEW_PYTHON_PATH\n"
    fi
    if [ -n "$APMINSIGHT_LICENSEKEY" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_LICENSEKEY=$APMINSIGHT_LICENSEKEY\n"
    fi
    if [ -n "$APMINSIGHT_AGENT_START_TIME" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_AGENT_START_TIME=$APMINSIGHT_AGENT_START_TIME\n"
    fi
    if [ -n "$APMINSIGHT_AGENT_ID" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_AGENT_ID=$APMINSIGHT_AGENT_ID\n"
    fi
    if [ -n "$APMINSIGHT_DATAEXPORTER_HOST" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_DATAEXPORTER_HOST=$APMINSIGHT_DATAEXPORTER_HOST\n"
    fi
    if [ -n "$CUSTOM_APM_AGENTS" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""CUSTOM_APM_AGENTS=$CUSTOM_APM_AGENTS\n"
    fi
    if [ -n "$JAVA_AGENT_DOWNLOAD_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""JAVA_AGENT_DOWNLOAD_URL=$JAVA_AGENT_DOWNLOAD_URL\n"
    fi
    if [ -n "$JAVA_AGENT_CHECKSUM_VALUE" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""JAVA_AGENT_CHECKSUM_VALUE=$JAVA_AGENT_CHECKSUM_VALUE\n"
    fi
    if [ -n "$JAVA_AGENT_CHECKSUM_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""JAVA_AGENT_CHECKSUM_URL=$JAVA_AGENT_CHECKSUM_URL\n"
    fi
    if [ -n "$JAVA_AGENT_VERSION" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""JAVA_AGENT_VERSION=$JAVA_AGENT_VERSION\n"
    fi
    if [ -n "$PYTHON_AGENT_DOWNLOAD_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""PYTHON_AGENT_DOWNLOAD_URL=$PYTHON_AGENT_DOWNLOAD_URL\n"
    fi
    if [ -n "$PYTHON_AGENT_CHECKSUM_VALUE" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""PYTHON_AGENT_CHECKSUM_VALUE=$PYTHON_AGENT_CHECKSUM_VALUE\n"
    fi
    if [ -n "$PYTHON_AGENT_CHECKSUM_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""PYTHON_AGENT_CHECKSUM_URL=$PYTHON_AGENT_CHECKSUM_URL\n"
    fi
    if [ -n "$PYTHON_AGENT_VERSION" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""PYTHON_AGENT_VERSION=$PYTHON_AGENT_VERSION\n"
    fi
    if [ -n "$NODEJS_AGENT_DOWNLOAD_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""NODEJS_AGENT_DOWNLOAD_URL=$NODEJS_AGENT_DOWNLOAD_URL\n"
    fi
    if [ -n "$NODEJS_AGENT_CHECKSUM_VALUE" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""NODEJS_AGENT_CHECKSUM_VALUE=$NODEJS_AGENT_CHECKSUM_VALUE\n"
    fi
    if [ -n "$NODEJS_AGENT_CHECKSUM_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""NODEJS_AGENT_CHECKSUM_URL=$NODEJS_AGENT_CHECKSUM_URL\n"
    fi
    if [ -n "$NODEJS_AGENT_VERSION" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""NODEJS_AGENT_VERSION=$NODEJS_AGENT_VERSION\n"
    fi
    if [ -n "$DOTNET_AGENT_DOWNLOAD_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""DOTNET_AGENT_DOWNLOAD_URL=$DOTNET_AGENT_DOWNLOAD_URL\n"
    fi
    if [ -n "$DOTNET_AGENT_CHECKSUM_VALUE" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""DOTNET_AGENT_CHECKSUM_VALUE=$DOTNET_AGENT_CHECKSUM_VALUE\n"
    fi
    if [ -n "$DOTNET_AGENT_CHECKSUM_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""DOTNET_AGENT_CHECKSUM_URL=$DOTNET_AGENT_CHECKSUM_URL\n"
    fi
    if [ -n "$DOTNET_AGENT_VERSION" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""DOTNET_AGENT_VERSION=$DOTNET_AGENT_VERSION\n"
    fi
    if [ -n "$DATAEXPORTER_DOWNLOAD_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""DATAEXPORTER_DOWNLOAD_URL=$DATAEXPORTER_DOWNLOAD_URL\n"
    fi
    if [ -n "$DATAEXPORTER_CHECKSUM_VALUE" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""DATAEXPORTER_CHECKSUM_VALUE=$DATAEXPORTER_CHECKSUM_VALUE\n"
    fi
    if [ -n "$DATAEXPORTER_CHECKSUM_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""DATAEXPORTER_CHECKSUM_URL=$DATAEXPORTER_CHECKSUM_URL\n"
    fi
    if [ -n "$DATAEXPORTER_VERSION" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""DATAEXPORTER_VERSION=$DATAEXPORTER_VERSION\n"
    fi
    if [ -n "$APMINSIGHT_HOST" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_HOST=$APMINSIGHT_HOST\n"
    fi
    AGENT_CONF_STR="$AGENT_CONF_STR""AGENT_KEY=$AGENT_KEY\n"
    AGENT_CONF_STR="$AGENT_CONF_STR""HOST_OS=$HOST_OS\n"
    AGENT_CONF_STR="$AGENT_CONF_STR""HOST_ARCH=$HOST_ARCH\n"
    AGENT_CONF_STR="$AGENT_CONF_STR""HOST_LIBC_DIST=$HOST_LIBC_DIST\n"
    conf_filepath="$AGENT_INSTALLATION_PATH/conf/autoprofilerconf.ini"
    printf "$AGENT_CONF_STR" > "$conf_filepath"
    if [ -f "$conf_filepath" ]; then
        Log "Successfully created the autoprofilerconf.ini at $AGENT_INSTALLATION_PATH/conf"
    else
        Log "Error creating file autoprofilerconf.ini at $AGENT_INSTALLATION_PATH/conf"
    fi
}

RemoveInstallationFiles() {
    rm -rf "$TEMP_FOLDER_PATH"
}

MoveInstallationFiles() {
    if [ "$AGENT_STARTUP_LOGFILE_PATH" != "$AGENT_INSTALLATION_PATH/logs/apminsight-auto-profiler-install.log" ]; then
        mv "$AGENT_STARTUP_LOGFILE_PATH" "$AGENT_INSTALLATION_PATH/logs"
    fi
    if [ "$(dirname "$(readlink -f "$0")")" != "$AGENT_INSTALLATION_PATH/bin" ]; then
        mv "$(dirname "$(readlink -f "$0")")"/apminsight-auto-profiler.sh "$AGENT_INSTALLATION_PATH/bin/"
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
            INSTALLATION_FAILURE_MESSAGE="An outdated version of Apminsight AutoProfiler exists. Please run sudo sh apminsight-auto-profiler.sh -upgrade to upgrade Apminsight AutoProfiler to latest version"
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

RegisterAutoProfilerVersion() {
    if [ -f "/etc/environment" ]; then
        sed -i '/^'$APMINSIGHT_BRAND_UCASE'_APMINSIGHT_AUTOPROFILER_VERSION/d' /etc/environment
    fi
    echo ""$APMINSIGHT_BRAND_UCASE"_APMINSIGHT_AUTOPROFILER_VERSION=$APMINSIGHT_AUTOPROFILER_VERSION" >> "/etc/environment"
    Log "Registered Apminsight AutoProfiler Version successfully"
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

ReadExistingAutoProfilerPath() {
    EXISTING_AUTOPROFILERPATH="$AGENT_INSTALLATION_PATH"
    FindKeyValPairInFile "/etc/environment" "AUTOPROFILERPATH" "EXISTING_AUTOPROFILERPATH"
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
                        Log "AGENT_KEY"
                        AGENT_KEY=$value
                        CHANGED_CONFIGS="$CHANGED_CONFIGS AGENT_KEY"
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

CheckAgentInstallation() {
    FindKeyValPairInFile "/etc/environment" ""$APMINSIGHT_BRAND_UCASE"_APMINSIGHT_AUTOPROFILER_VERSION" "EXISTING_APMINSIGHT_AUTOPROFILER_VERSION"
    if [ "$1" = "-uninstall" ]; then
        Log "Uninstalling Apminsight AutoProfiler...."
        AUTOPROFILER_OPERATION="uninstall"
        if [ -z "$EXISTING_APMINSIGHT_AUTOPROFILER_VERSION" ]; then
            Log "Apminsight AutoProfiler is not found installed. Purging AutoProfiler resources..."
        fi
        UninstallAutoProfiler

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
    elif [ "$1" = "-update" ]; then
        Log "Updating Apminsight AutoProfiler Configurations..."
        if [ -z "$EXISTING_APMINSIGHT_AUTOPROFILER_VERSION" ]; then
            Log "Apminsight AutoProfiler is not found installed. Purging AutoProfiler resources..."
        fi
        UpdateAutoProfilerConfig $@
        exit 0
    else
        if [ -z "$EXISTING_APMINSIGHT_AUTOPROFILER_VERSION" ]; then
            Log "Installing Apminsight AutoProfiler..."
            return
        fi
    fi
    #FOUND EXISTING AUTOPROFILER
    CompareAgentVersions
}

ApminsightUserExists() {
    if id "$APMINSIGHT_USER" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

CheckAndAddUserToApminsightGroup() {
    if groups $APMINSIGHT_USER | grep -q "\b$APMINSIGHT_GROUP\b"; then
        Log "User '$APMINSIGHT_USER' already found in $APMINSIGHT_GROUP."
    else
        usermod -aG $APMINSIGHT_GROUP $APMINSIGHT_USER
    fi
}
CheckAndCreateApminsightUser() {
    if ApminsightUserExists; then
        Log "User '$APMINSIGHT_USER' already exists."
    else
        Log "Creating $APMINSIGHT_USER"
        useradd --system --no-create-home --no-user-group $APMINSIGHT_USER
        if ! ApminsightUserExists; then
            INSTALLATION_FAILURE_MESSAGE="Could not create $APMINSIGHT_USER. Aborting Apminsight AutoProfiler Installation"
            exit 1
        fi
    fi
    if ! grep -q '\b'$APMINSIGHT_USER'\b' /etc/sudoers; then
        echo ''$APMINSIGHT_USER' ALL=(ALL:ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo
    fi
    CheckAndAddUserToApminsightGroup
}

CheckAndRemoveExistingService() {
    if systemctl list-units --type=service --all | grep -q "$APMINSIGHT_SERVICE_FILE"; then
        Log "Found an existing $APMINSIGHT_SERVICE_FILE, Removing the service"
        Log "$(systemctl stop $APMINSIGHT_SERVICE_FILE 2>&1)"
        Log "$(systemctl disable $APMINSIGHT_SERVICE_FILE 2>&1)"
    fi
    rm -f /etc/systemd/system/$APMINSIGHT_SERVICE_FILE
    Log "$(systemctl daemon-reload 2>&1)"
}

RegisterAutoProfilerService() {
    Log "Registering $APMINSIGHT_SERVICE_FILE"
    CheckAndRemoveExistingService
    if ! [ -f "$AGENT_INSTALLATION_PATH/bin/$APMINSIGHT_SERVICE_FILE" ]; then
        INSTALLATION_FAILURE_MESSAGE="Cannot find Apminsight AutoProfiler service binary. Skipping the service start"
        exit 1
    fi
    cp "$AGENT_INSTALLATION_PATH/bin/$APMINSIGHT_SERVICE_FILE" /etc/systemd/system/
    Log "$(systemctl enable $APMINSIGHT_SERVICE_FILE 2>&1)"
    Log "$(systemctl daemon-reload 2>&1)"
    Log "$(systemctl restart $APMINSIGHT_SERVICE_FILE 2>&1)"
    if systemctl list-unit-files --type=service | grep -q "^$APMINSIGHT_SERVICE_FILE"; then
        echo "$APMINSIGHT_SERVICE_FILE is registered properly."
    else
        INSTALLATION_FAILURE_MESSAGE="$APMINSIGHT_SERVICE_FILE is not registered properly."
        exit 1
    fi
}

checkGlibcCompatibility() {
    if ! command -v ldd >/dev/null 2>&1; then
        INSTALLATION_FAILURE_MESSAGE="ldd command not found. Unable to check for glibc."
        exit 1
    fi

    if ldd --version 2>/dev/null | grep -iqE "GNU libc|Free Software Foundation|Roland McGrath"; then
        Log "GLIBC detected."
    else
        INSTALLATION_FAILURE_MESSAGE="GLIBC not detected. Apminsight AutoProfiler is not supported for non-GLIBC distributions for now"
        exit 1
    fi
    HOST_LIBC_DIST="glibc"
    GLIBC_VERSION="$(ldd --version | awk 'NR==1{ print $NF }')"
    GLIBC_VERSION_MAJ=$(echo "$GLIBC_VERSION" | sed 's/\..*//')
    GLIBC_VERSION_MIN=$(echo "$GLIBC_VERSION" | sed 's/^[^\.]*\.\([^\.]*\).*/\1/')
    GLIBC_VERSION_COMPATIBLE_MAJ=$(echo "$GLIBC_VERSION_COMPATIBLE" | sed 's/\..*//')
    GLIBC_VERSION_COMPATIBLE_MIN=$(echo "$GLIBC_VERSION_COMPATIBLE" | sed 's/^[^\.]*\.\([^\.]*\).*/\1/')
    if [ "$GLIBC_VERSION_MAJ" -lt "$GLIBC_VERSION_COMPATIBLE_MAJ" ]; then 
        INSTALLATION_FAILURE_MESSAGE="GLIBC VERSION INCOMPATIBLE"
        exit 1
    elif [ "$GLIBC_VERSION_MAJ" -eq "$GLIBC_VERSION_COMPATIBLE_MAJ" ]; then
        if [ "$GLIBC_VERSION_MIN" -lt "$GLIBC_VERSION_COMPATIBLE_MIN" ]; then
            INSTALLATION_FAILURE_MESSAGE="GLIBC VERSION INCOMPATIBLE"
            exit 1
        fi
    fi
}

WriteToInfoFile() {
    Log "WRITING TO $AUTOPROFILER_INFO_FILEPATH file"
    mkdir -p "$AGENT_INSTALLATION_PATH"
    touch "$AUTOPROFILER_INFO_FILEPATH"
    echo "[apm_insight]\nProcessName=apminsight-autoprofiler start\nServiceName="$APMINSIGHT_BRAND_LCASE"apmautoprofiler.service\nDisplayName="$APMINSIGHT_BRAND_LCASE"apmautoprofiler\nVersion=$APMINSIGHT_AUTOPROFILER_VERSION" > "$AUTOPROFILER_INFO_FILEPATH"
}

checkCompatibility() {
    checkGlibcCompatibility
}

UninstallAutoProfiler() {
    Log "$(sed -i "\|$APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_NAME|d" /etc/ld.so.preload 2>&1)"
    Log "$(sed -i "\|$APMINSIGHT_BRAND_UCASE|d" /etc/environment 2>&1)"
    Log "$(systemctl stop $APMINSIGHT_SERVICE_FILE 2>&1)"
    Log "$(systemctl disable $APMINSIGHT_SERVICE_FILE 2>&1)"
    Log "$(rm $APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_PATH 2>&1)"
    Log "$(sh /opt/$DATAEXPORTER_NAME/bin/service.sh uninstall 2>&1)"
    Log "$(rm -r /opt/$DATAEXPORTER_NAME 2>&1)"
    Log "$(pip uninstall --yes apminsight 2>&1)"
    Log "$(rm /etc/systemd/system/$APMINSIGHT_SERVICE_FILE 2>&1)"
    if grep -q '\b'$APMINSIGHT_USER'\b' /etc/sudoers; then
        Log "$(sudo sed -i '/\b'$APMINSIGHT_USER'\b/d' /etc/sudoers 2>&1)"
    fi
    Log "$(systemctl daemon-reload 2>&1)"
    Log "$(mv $AGENT_STARTUP_LOGFILE_PATH "$AGENT_ROOT_DIR" 2>&1)"
    Log "$(rm -r $AGENT_INSTALLATION_PATH 2>&1)"
    exit 0
}

checkPreloaderCompatibility() {
    Log "TESTING APM INSIGHT PRELOADER BINARY COMPATIBILITY"
    Log "$(timeout 1 LD_PRELOAD="$APMINSIGHT_AUTOPROFILER_PRELOADER_BINARY_PATH" /bin/true 2>&1)"

    if [ $? -ne 0 ]; then
        INSTALLATION_FAILURE_MESSAGE="❌ PRELOADER INCOMPATIBLE WITH HOST ENVIRONMENT"
        exit 1
    fi
    Log "✅ PRELOADER COMPATIBLE WITH HOST ENVIRONMENT"
}

main() {
    CheckArgs $@
    CheckRoot
    ReadBrandName
    RedirectLogs
    checkCompatibility
    CheckAgentInstallation $@
    WriteToInfoFile
    CheckAndCreateApminsightUser
    SetupPreInstallationChecks
    SetupAgentConfigurations "$@"
    SetupAutoProfilerFiles
    checkPreloaderCompatibility
    WriteToAgentConfFile
    GiveFilePermissions
    RegisterAutoProfilerService
    RegisterAutoProfilerVersion
    MoveInstallationFiles
    RemoveInstallationFiles
    exit 0
    }
main "$@"
