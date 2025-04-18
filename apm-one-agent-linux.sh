#!/bin/sh

AGENT_DOWNLOAD_LINKS="NODE_MINIFIED_DOWNLOAD_PATH=https://staticdownloads.site24x7.com/apminsight/agents/nodejs/apm_insight_agent_nodejs.zip NODE_AGENT_CHECKSUM=https://staticdownloads.site24x7.com/apminsight/agents/nodejs/apm_insight_agent_nodejs.zip.sha256 JAVA_AGENT_DOWNLOAD_PATH=https://staticdownloads.site24x7.com/apminsight/agents/apminsight-javaagent.zip JAVA_AGENT_CHECKSUM=https://staticdownloads.site24x7.com/apminsight/checksum/apminsight-javaagent.zip.sha256 PYTHON_AGENT_DOWNLOAD_PATH_PREFIX=https://staticdownloads.site24x7.com/apminsight/agents/python/linux/glibc/ PYTHON_AGENT_CHECKSUM_PREFIX=https://staticdownloads.site24x7.com/apminsight/agents/python/linux/glibc/ DOTNETCORE_AGENT_DOWNLOAD_PATH=https://staticdownloads.site24x7.com/apminsight/agents/dotnet/apminsight-dotnetcoreagent-linux.sh DOTNETCORE_AGENT_CHECKSUM=https://staticdownloads.site24x7.com/apminsight/agents/dotnet/apminsight-dotnetcoreagent-linux.sh.sha256 DATA_EXPORTER_SCRIPT_DOWNLOAD_PATH_EXTENSION=/apminsight/S247DataExporter/linux/InstallDataExporter.sh ONEAGENT_FILES_DOWNLOAD_PATH_PREFIX=https://build.zohocorp.com/me/apm_insight_one_agent/webhost/test_appmanager/Apr_15_2025/apminsight_one_agent/apminsight_one_agent/applicationsmanager/agents/linux/linux/glibc/ ONEAGENT_FILES_CHECKSUM_PREFIX=https://build.zohocorp.com/me/apm_insight_one_agent/webhost/test_appmanager/Apr_15_2025/apminsight_one_agent/apminsight_one_agent/applicationsmanager/checksum/linux/linux/glibc/"
APMINSIGHT_BRAND="ApplicationsManager"
APMINSIGHT_BRAND_UCASE=$(echo "$APMINSIGHT_BRAND" | sed 's/[a-z]/\U&/g')
APMINSIGHT_BRAND_LCASE=$(echo "$APMINSIGHT_BRAND" | sed 's/[A-Z]/\L&/g')
CURRENT_DIRECTORY="$(dirname "$(readlink -f "$0")")"
APMINSIGHT_ONEAGENT_PATH="/opt"
PRELOAD_FILE_PATH="/etc/ld.so.preload"
AGENT_STARTUP_LOGFILE_PATH="$CURRENT_DIRECTORY/apm-one-agent-installation.log"
STARTUP_CONF_FILEPATH="$CURRENT_DIRECTORY/oneagentconf.ini"

KUBERNETES_ENV=0
BUNDLED=0
APMINSIGHT_LICENSEKEY=""
APMINSIGHT_LICENSE_KEY=""
TEMP_FOLDER_PATH="$CURRENT_DIRECTORY/temp"
AGENT_CONF_STR=""
APMINSIGHT_HOST=""
APMINSIGHT_PORT=""
APMINSIGHT_PROTOCOL="http"
APMINSIGHT_HOST_URL=""
APMINSIGHT_PROXY_URL=""
APMINSIGHT_DOMAIN="com"
APMINSIGHT_AGENT_START_TIME=""
APMINSIGHT_AGENT_ID=""
APMINSIGHT_DATAEXPORTER_HOST=""

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
APMINSIGHT_ONEAGENT_VERSION="1.0.0"
ONEAGENT_OPERATION="install"
GLIBC_VERSION_COMPATIBLE="2.23"
GCC_VERSION_COMPATIBLE="5.4"

displayHelp() {
    echo "Usage: $0 [option] [arguments]\n \n Options:\n"
    echo "  --APMINSIGHT_LICENSE_KEY             To configure the License key"
    echo "  --APMINSIGHT_PROXY_URL               To configure Proxy Url if using, Format: protocol://user:password@host:port or protocol://user@host:port or protocol://host:port"
    #echo "  --APMINSIGHT_ONEAGENT_PATH           To configure Custom path for Oneagent related files"
    echo "  --APMINSIGHT_MONITOR_GROUP           To configure Agent monitor groups"
}

CheckArgs() {
    if [ "$*" = "--help" ]; then
        displayHelp
        exit 1
    elif [ "$*" = "-version" ]; then
        echo "$APMINSIGHT_ONEAGENT_VERSION"
        exit 1
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
    AGENT_INSTALLATION_PATH="/opt/$APMINSIGHT_BRAND_LCASE/apmoneagent"
    AGENT_ROOT_DIR="/opt/$APMINSIGHT_BRAND_LCASE"
    APMINSIGHT_USER="$APMINSIGHT_BRAND_LCASE-user"
    APMINSIGHT_GROUP="$APMINSIGHT_BRAND_LCASE-group"
    APMINSIGHT_SERVICE_FILE="$APMINSIGHT_BRAND_LCASE""apmoneagent.service"
    APMINSIGHT_ONEAGENT_PRELOADER_BINARY_NAME="lib"$APMINSIGHT_BRAND_LCASE"apmoneagentloader.so"
    APMINSIGHT_ONEAGENT_PRELOADER_BINARY_PATH="/lib/$APMINSIGHT_ONEAGENT_PRELOADER_BINARY_NAME"
    PYTHON_AGENT_PATH="$AGENT_INSTALLATION_PATH/lib/PYTHON"
    ParseAgentDownloadLinks
}

RedirectLogs() {
    # if [ -n "$EXISTING_ONEAGENTPATH" ] && [ -f "$EXISTING_ONEAGENTPATH/logs/apm-one-agent-installation.log" ]; then
    #     AGENT_STARTUP_LOGFILE_PATH="$EXISTING_ONEAGENTPATH/logs/apm-one-agent-installation.log"
    EXISTING_AGENT_LOGFILE_PATH=""
    if [ -f "$AGENT_INSTALLATION_PATH/logs/apm-one-agent-installation.log" ]; then
        EXISTING_AGENT_LOGFILE_PATH="$AGENT_INSTALLATION_PATH/logs/apm-one-agent-installation.log"
    elif [ -f "$AGENT_ROOT_DIR/apm-one-agent-installation.log" ]; then
        EXISTING_AGENT_LOGFILE_PATH="$AGENT_ROOT_DIR/apm-one-agent-installation.log"
    fi
    if [ -n "$EXISTING_AGENT_LOGFILE_PATH" ]; then
        file_size=$(stat -c%s "$EXISTING_AGENT_LOGFILE_PATH")
        if [ "$file_size" -gt 1048576 ]; then
            echo "$EXISTING_AGENT_LOGFILE_PATH is larger than 1 MB. Redirecting the logs to a new file"
            mv "$EXISTING_AGENT_LOGFILE_PATH" "$AGENT_ROOT_DIR/apm-one-agent-installation.log.1"
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
        Log "OneAgent installer script is run without root privilege. Please run the script apm-one-agent-linux.sh with sudo"
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
		Log "Info: $OS_ARCH not supported in this version"
    fi
}

#DETECT IF KUBERNETES ENVIRONMENT
DetectKubernetes() {
    Log "DETECTING KUBERNETES ENVIRONMENT"
    if [ -n "${KUBERNETES_SERVICE_HOST}" ]; then
        KUBERNETES_ENV=1
        Log "KUBERNETES ENVIRONMENT DETECTED"
    fi
}

SetupPreInstallationChecks() {
    CheckBit
    CheckARM
    SetArchBasedDownloadPathExtension
    DetectKubernetes
}

ReadConfigFromFile() {
    if [ -f $STARTUP_CONF_FILEPATH ]; then
        Log "Found oneagentconf.ini file. Started reading the file for Oneagent startup configurations"
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
                elif [ "$Key" = "APMINSIGHT_PORT" ]; then
                    APMINSIGHT_PORT=$value
                elif [ "$Key" = "APMINSIGHT_PROTOCOL" ]; then
                    APMINSIGHT_PROTOCOL=$value
                elif [ "$Key" = "APMINSIGHT_HOST_URL" ]; then
                    APMINSIGHT_HOST_URL=$value
                elif [ "$Key" = "APMINSIGHT_MONITOR_GROUP" ]; then
                    APMINSIGHT_MONITOR_GROUP=$value
                elif [ "$Key" = "AGENT_KEY" ]; then
                    AGENT_KEY=$value
                elif [ "$Key" = "JAVA_AGENT_DOWNLOAD_PATH" ]; then
                    JAVA_AGENT_DOWNLOAD_PATH="$value"
                elif [ "$Key" = "NODE_AGENT_DOWNLOAD_PATH" ]; then
                    NODE_MINIFIED_DOWNLOAD_PATH="$value"
                elif [ "$Key" = "PYTHON_AGENT_DOWNLOAD_PATH" ]; then
                    PYTHON_AGENT_DOWNLOAD_PATH="$value"
                elif [ "$Key" = "DOTNETCORE_AGENT_DOWNLOAD_PATH" ]; then
                    DOTNETCORE_AGENT_DOWNLOAD_PATH="$value"
                elif [ "$Key" = "ONEAGENT_FILES_DOWNLOAD_PATH" ]; then
                    ONEAGENT_FILES_DOWNLOAD_PATH="$value"
                elif [ "$Key" = "DATA_EXPORTER_SCRIPT_DOWNLOAD_PATH" ]; then
                    DATA_EXPORTER_SCRIPT_DOWNLOAD_PATH="$value"
                elif [ "$Key" = "JAVA_AGENT_CHECKSUM" ]; then
                    JAVA_AGENT_CHECKSUM="$value"
                elif [ "$Key" = "NODE_AGENT_CHECKSUM" ]; then
                    NODE_AGENT_CHECKSUM="$value"
                elif [ "$Key" = "PYTHON_AGENT_CHECKSUM" ]; then
                    PYTHON_AGENT_CHECKSUM="$value"
                elif [ "$Key" = "DOTNETCORE_AGENT_CHECKSUM" ]; then
                    DOTNETCORE_AGENT_CHECKSUM="$value"
                elif [ "$Key" = "ONEAGENT_FILES_CHECKSUM" ]; then
                    ONEAGENT_FILES_CHECKSUM="$value"
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
            *)
                Log "Unknown argument: $Key"
                ;;
        esac
        shift 1
    done
    if [ -z "$APMINSIGHT_LICENSE_KEY" ]; then
        Log "Unable to find License Key from commandline arguments. Please run the apm-one-agent-linux.sh script again providing License Key or set License Key in the configuration file located at $AGENT_INSTALLATION_PATH in the format APMINSIGHT_LICENSEKEY=<Your License Key>"
    fi
}

BuildApmHostUrl() {
    if [ -n "$APMINSIGHT_HOST_URL" ]; then
        return
    fi
    if [ "$APMINSIGHT_HOST" != "" ]; then
        APMINSIGHT_HOST_URL="$APMINSIGHT_HOST"
        if [ "$APMINSIGHT_PORT" != "" ]; then
            APMINSIGHT_HOST_URL="$APMINSIGHT_HOST_URL:"$APMINSIGHT_PORT""
        else
            APMINSIGHT_HOST_URL="$APMINSIGHT_HOST_URL:443"
        fi
        APMINSIGHT_HOST_URL="$APMINSIGHT_PROTOCOL://$APMINSIGHT_HOST_URL"

    elif [ "$APMINSIGHT_BRAND" = "Site24x7" ]; then
        ReadDomain
        APMINSIGHT_HOST_URL="https://plusinsight.site24x7.""$APMINSIGHT_DOMAIN:443"
    else
        Log "Please provide a proper Apminsight Host details. Exiting Installation"
        exit 0 
    fi
}

SetProxy() {
    if [ -n "$APMINSIGHT_PROXY_URL" ]; then
        export http_proxy=$APMINSIGHT_PROXY_URL
        export https_proxy=$APMINSIGHT_PROXY_URL
        export ftp_proxy=$APMINSIGHT_PROXY_URL
    fi
}

ReadDomain() {
    if [ -z "$APMINSIGHT_LICENSE_KEY" ]; then
        return
    fi
    if echo "$APMINSIGHT_LICENSE_KEY" | grep -q "_"; then
        APMINSIGHT_DOMAIN="${APMINSIGHT_LICENSE_KEY%%_*}"
        if [ "$APMINSIGHT_DOMAIN" = "us" ] || [ "$APMINSIGHT_DOMAIN" = "gd" ]; then
            APMINSIGHT_DOMAIN="com"
        fi
    fi
}

EncryptLicenseKey() {
    if [ -n "$APMINSIGHT_LICENSE_KEY" ]; then
        APMINSIGHT_AGENT_START_TIME=$(echo -n $(date +"%Y%m%dT%H%M%S%N") | xargs printf "%-32s" | tr ' ' '0')
        APMINSIGHT_AGENT_ID="$(cat /dev/urandom | tr -dc '0-9' | fold -w 16 | head -n 1)"
        APMINSIGHT_LICENSEKEY=$(echo -n "$APMINSIGHT_LICENSE_KEY" | openssl enc -aes-256-cbc -K $(echo -n "$APMINSIGHT_AGENT_START_TIME" | xxd -p -c 256) -iv $(echo -n "$APMINSIGHT_AGENT_ID" | xxd -p -c 256) -base64)
        if [ -z "$APMINSIGHT_LICENSEKEY" ]; then
                Log "Unable to generate the License string. Abandoning the installation process"
                exit 1
        fi
    fi
}

SetupAgentConfigurations() {
    ReadConfigFromFile
    ReadConfigFromArgs "$@"
    BuildApmHostUrl
    SetProxy
    EncryptLicenseKey
}

DownloadAgentFiles() {
    if [ "$KUBERNETES_ENV" -eq 1 ]; then
        return

    elif [ "$BUNDLED" -eq 0 ]; then
        Log "DOWNLOADING AGENT FILES"
        mkdir -p "$TEMP_FOLDER_PATH"
        cd "$TEMP_FOLDER_PATH"
        wget -nv "$NODE_MINIFIED_DOWNLOAD_PATH"
        ValidateChecksumAndInstallAgent "apm_insight_agent_nodejs.zip" "$NODE_AGENT_CHECKSUM" "$AGENT_INSTALLATION_PATH/lib/NODE"

        wget -nv "$JAVA_AGENT_DOWNLOAD_PATH"
        ValidateChecksumAndInstallAgent "apminsight-javaagent.zip" "$JAVA_AGENT_CHECKSUM" "$AGENT_INSTALLATION_PATH/lib/JAVA"
        
        cd "$CURRENT_DIRECTORY"
        return
    fi

    unzip "apm_insight_agent_nodejs.zip" -d "$AGENT_INSTALLATION_PATH/lib/NODE"
    unzip "apminsight-javaagent.zip" -d "$AGENT_INSTALLATION_PATH/lib/JAVA"

    rm "apm_insight_agent_nodejs.zip"
    rm "apminsight-javaagent.zip"
}

#CHECKSUM VALIDATION
ValidateChecksumAndInstallAgent() {
    Log "Checksum validation for the file $1"
    file="$1"
    checksumVerificationLink="$2"
    destinationpath="$3"
    checksumfilename="$file-checksum"
    wget -nv -O "$checksumfilename" $checksumVerificationLink
    Originalchecksumvalue="$(cat "$checksumfilename")"
    Originalchecksumvalue="$(echo "$Originalchecksumvalue" | tr '[:upper:]' '[:lower:]')"
    Downloadfilechecksumvalue="$(sha256sum $file | awk -F' ' '{print $1}')"
    if [ "$Originalchecksumvalue" = "$Downloadfilechecksumvalue" ]; then
        unzip "$file" -d "$destinationpath"
    fi
}

#INSTALL NODEJS AGENT DEPENDENCIES
InstallNodeJSDependencies() {
    Log "INSTALLING NODE DEPENDENCIES"
    NODE_AGENT_PATH="$AGENT_INSTALLATION_PATH/lib/NODE/agent_minified"
    if [ "$KUBERNETES_ENV" -eq 1 ]; then
        NODE_AGENT_PATH="$AGENT_INSTALLATION_PATH/agent_minified"
    fi
    cd "$NODE_AGENT_PATH"
    npm install
    cd $CURRENT_DIRECTORY
}

#INSTALL PYTHON AGENT DEPENDENCIES
InstallPythonDependencies() {
    Log "DOWNLOADING PYTHON AGENT PACKAGE"
    if [ -z "$PYTHON_AGENT_DOWNLOAD_PATH" ]; then
        PYTHON_AGENT_DOWNLOAD_PATH="$PYTHON_AGENT_DOWNLOAD_PATH_PREFIX$ARCH_BASED_DOWNLOAD_PATH_EXTENSION/apm_insight_agent_python.zip"
        PYTHON_AGENT_CHECKSUM="$PYTHON_AGENT_CHECKSUM_PREFIX$ARCH_BASED_DOWNLOAD_PATH_EXTENSION/apm_insight_agent_python.zip.sha256"
    fi
    cd "$TEMP_FOLDER_PATH"
    wget -nv "$PYTHON_AGENT_DOWNLOAD_PATH"
    ValidateChecksumAndInstallAgent "apm_insight_agent_python.zip" "$PYTHON_AGENT_CHECKSUM" "$TEMP_FOLDER_PATH"
    cd "$CURRENT_DIRECTORY"
    Log "INSTALLING APMINSIGHT PYTHON PACKAGE"
    PYTHON_FILE_PATH="$TEMP_FOLDER_PATH/wheels"
    if [ "$KUBERNETES_ENV" -eq 1 ]; then
        PYTHON_FILE_PATH="$AGENT_INSTALLATION_PATH/wheels"
    fi
    pip uninstall --yes apminsight
    pip install --upgrade --no-index --target="$PYTHON_AGENT_PATH" --find-links="$PYTHON_FILE_PATH" apminsight 2>/tmp/python_agent_installation_warnings.log
    NEW_PYTHON_PATH="$PYTHON_AGENT_PATH/apminsight/bootstrap:$PYTHON_AGENT_PATH:"
    AGENT_CONF_STR="$AGENT_CONF_STR""NEW_PYTHON_PATH=$NEW_PYTHON_PATH\n"
}

InstallDotNetCoreAgent() {
    cd "$TEMP_FOLDER_PATH"
    wget -nv "$DOTNETCORE_AGENT_DOWNLOAD_PATH"
    wget -nv "$DOTNETCORE_AGENT_CHECKSUM"
    Originalchecksumvalue="$(cat "apminsight-dotnetcoreagent-linux.sh.sha256")"
    Originalchecksumvalue=$(cat "apminsight-dotnetcoreagent-linux.sh.sha256" | tr '[:upper:]' '[:lower:]' | cut -c 1-64)
    Downloadfilechecksumvalue="$(sha256sum "apminsight-dotnetcoreagent-linux.sh" | awk '{print tolower(substr($1, 1, 64))}')"
    if [ "$Originalchecksumvalue" = "$Downloadfilechecksumvalue" ]; then
        bash ./apminsight-dotnetcoreagent-linux.sh -Destination "$AGENT_INSTALLATION_PATH/lib/DOTNETCORE" -OneAgentInstall -OneAgentHomePath "$AGENT_INSTALLATION_PATH/agents/DOTNETCORE"
    else
        Log "Checksum Validation failed for DotnetCore agent installation file"
    fi
    cd "$CURRENT_DIRECTORY"
}

#INSTALL DATAEXPORTER (Not handled for Appmanager)
InstallDataExporter() {
    Log "INSTALLING DATAEXPORTER"
    EXPORTER_INSTALLATION_ARGUMENTS="-license.key "$APMINSIGHT_LICENSE_KEY" -apminsight.oneagent.conf.filepath "$AGENT_INSTALLATION_PATH/conf/oneagentconf.ini""
    if [ -z "$DATA_EXPORTER_SCRIPT_DOWNLOAD_PATH" ]; then
        DOWNLOAD_PATH="https://staticdownloads.site24x7.""$APMINSIGHT_DOMAIN""$DATA_EXPORTER_SCRIPT_DOWNLOAD_PATH_EXTENSION"
    fi
    DOWNLOAD_PATH="$DATA_EXPORTER_SCRIPT_DOWNLOAD_PATH"
    if [ "$BUNDLED" -eq 0 ] && [ "$KUBERNETES_ENV" -eq 0 ]; then
        cd "$TEMP_FOLDER_PATH"
        wget -nv -O InstallDataExporter.sh "$DOWNLOAD_PATH"
        eval "sudo -E sh InstallDataExporter.sh "$EXPORTER_INSTALLATION_ARGUMENTS""
        cd "$CURRENT_DIRECTORY"
        return
    fi
    exporter_zip_path="S247DataExporterFolder/$ARCH_BASED_DOWNLOAD_PATH_EXTENSION/S247DataExporter.zip"
    if [ "$KUBERNETES_ENV" -eq 1 ]; then
        exporter_zip_path="$AGENT_INSTALLATION_PATH/S247DataExporterFolder/$ARCH_BASED_DOWNLOAD_PATH_EXTENSION/S247DataExporter.zip"
    unzip "$exporter_zip_path" -d "/opt"
    cd /opt/S247DataExporter/bin
    sh service.sh install "$EXPORTER_INSTALLATION_ARGUMENTS"
    rm /opt/S247DataExporter.zip
    cd "$CURRENT_DIRECTORY"
    fi
}

RemoveExistingOneagentFiles() {
    Log "Removing existing Oneagent binaries and files"
    find "$AGENT_INSTALLATION_PATH/bin" -mindepth 1 -delete
    sed -i '/'$APMINSIGHT_ONEAGENT_PRELOADER_BINARY_NAME'$/d' /etc/ld.so.preload
    rm -f "$APMINSIGHT_ONEAGENT_PRELOADER_BINARY_PATH"
}

#CREATE AGENT FOLDERS IN USER MACHINE AND STORE THE DOWNLOADED AGENT FILES 
CreateOneAgentFiles() {
    Log "CREATING ONEAGENT FILES"
    mkdir -p "$AGENT_INSTALLATION_PATH"
    mkdir -p "$AGENT_INSTALLATION_PATH/conf"
    mkdir -p "$AGENT_INSTALLATION_PATH/lib"
    mkdir -p "$AGENT_INSTALLATION_PATH/bin"
    mkdir -p "$AGENT_INSTALLATION_PATH/logs"
    touch "$AGENT_INSTALLATION_PATH/logs/oneagentloader.log"
}

SetupOneagentFiles() {
    Log "DELETING EXISTING ONEAGENT FILES IF ANY"
    RemoveExistingOneagentFiles
    CreateOneAgentFiles
    mkdir -p "$TEMP_FOLDER_PATH"
    cd "$TEMP_FOLDER_PATH"
    if [ -z "$ONEAGENT_FILES_DOWNLOAD_PATH" ]; then
        ONEAGENT_FILES_DOWNLOAD_PATH="$ONEAGENT_FILES_DOWNLOAD_PATH_PREFIX""$ARCH_BASED_DOWNLOAD_PATH_EXTENSION""/apm_insight_oneagent_linux_files.zip"
    fi
    if [ -z "$ONEAGENT_FILES_CHECKSUM" ]; then
        ONEAGENT_FILES_CHECKSUM="$ONEAGENT_FILES_CHECKSUM_PREFIX""$ARCH_BASED_DOWNLOAD_PATH_EXTENSION""/apm_insight_oneagent_linux_files.zip.sha256"
    fi
    wget -nv "$ONEAGENT_FILES_DOWNLOAD_PATH"
    ValidateChecksumAndInstallAgent "apm_insight_oneagent_linux_files.zip" "$ONEAGENT_FILES_CHECKSUM" "$AGENT_INSTALLATION_PATH/bin"
    cd "$CURRENT_DIRECTORY"
}

#GIVE RESPECTIVE PERMISSIONS TO AGENT FILES
GiveFilePermissions() {
    Log "GIVING FILE PERMISSIONS"
    chown -R $APMINSIGHT_USER:$APMINSIGHT_GROUP "$AGENT_INSTALLATION_PATH"
    chmod 777 -R "$AGENT_INSTALLATION_PATH"
    chmod 755 -R "$AGENT_INSTALLATION_PATH/bin"
    chmod 755 -R "$AGENT_INSTALLATION_PATH/logs"
    chmod 777 -R "$AGENT_INSTALLATION_PATH/logs/oneagentloader.log"
    chmod 644 "$PRELOAD_FILE_PATH"
    chmod 644 "$APMINSIGHT_ONEAGENT_PRELOADER_BINARY_PATH"
}

RemoveExistingAgentFiles() {
    Log "REMOVING EXISTING APMINSIGHT AGENT FILES"
    rm -rf "$AGENT_INSTALLATION_PATH/lib/"
}

CreateApmAgentFiles() {
    Log "CREATING APMINSIGHT AGENT FILES"
    mkdir -p "$AGENT_INSTALLATION_PATH/lib"
    mkdir -p "$AGENT_INSTALLATION_PATH/lib/NODE"
    mkdir -p "$AGENT_INSTALLATION_PATH/lib/JAVA"
    mkdir -p "$AGENT_INSTALLATION_PATH/lib/PYTHON"
    mkdir -p "$AGENT_INSTALLATION_PATH/lib/DOTNETCORE"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/JAVA"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/JAVA/logs"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/NODE/"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/NODE/logs"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/PYTHON"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/PYTHON/logs"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/DOTNETCORE"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/DOTNETCORE/logs"
}

SetupAgents() {
    SetupOneagentFiles
    if ! [ "$ONEAGENT_OPERATION"  = "install" ]; then
        Log "Ignoring APM agents Installation"
        return
    fi
    RemoveExistingAgentFiles
    CreateApmAgentFiles
    DownloadAgentFiles
    InstallNodeJSDependencies
    InstallPythonDependencies
    InstallDotNetCoreAgent
}

#CHECK FOR EXISTING JAVA PROCESSES AND LOAD AGENT DYNAMICALLY INTO THE PROCESS
LoadAgentForExistingJavaProcesses() {
    if [ "$APMINSIGHT_LICENSEKEY" = "" ]; then
        Log "NO LICENSE KEY FOUND, LOADING AGENT TO EXISTING JAVA PROCESSES WILL BE SKIPPED"
        return
    fi
    Log "LOADING AGENT TO EXISTING JAVA PROCESSES"
    pids=$(ps -ef | grep -e 'java' -e 'tomcat' | grep -v 'grep' | awk '{print $2}')

    # Iterate over each PID and run the command with java -jar apminsight-javaagent.jar -start <pid>
    DYNAMIC_LOAD_ARGUMENTS="-lk "$APMINSIGHT_LICENSE_KEY""
    if [ "$APMINSIGHT_PROXY_URL" != "" ]; then
        DYNAMIC_LOAD_ARGUMENTS="$DYNAMIC_LOAD_ARGUMENTS -ap $APMINSIGHT_PROXY_URL"
    fi
    if [ "$APMINSIGHT_HOST_URL" != "" ]; then
        DYNAMIC_LOAD_ARGUMENTS="$DYNAMIC_LOAD_ARGUMENTS -aph $APMINSIGHT_HOST_URL"
    fi
    for pid in $pids; do
    Log "JAVA PROCESS DETECTED: $pid"
        eval "java -jar $AGENT_INSTALLATION_PATH/lib/JAVA/apminsight-javaagent.jar -start "$pid" "$DYNAMIC_LOAD_ARGUMENTS""
    done
}

WriteToAgentConfFile() {
	AGENT_CONF_STR="[ApminsightOneAgent]\n"

	if [ -n "$APMINSIGHT_PROXY_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_PROXY_URL=$APMINSIGHT_PROXY_URL\n"
    fi
    if [ -n "$APMINSIGHT_HOST" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_HOST=$APMINSIGHT_HOST\n"
    fi
    if [ -n "$APMINSIGHT_PORT" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_PORT=$APMINSIGHT_PORT\n"
    fi
    if [ -n "$APMINSIGHT_PROTOCOL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_PROTOCOL=$APMINSIGHT_PROTOCOL\n"
    fi
    if [ -n "$APMINSIGHT_MONITOR_GROUP" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_MONITOR_GROUP=$APMINSIGHT_MONITOR_GROUP\n"
    fi
    if [ -n "$PYTHON_AGENT_PATH" ]; then
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
    AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_HOST_URL=$APMINSIGHT_HOST_URL\n"
    AGENT_CONF_STR="$AGENT_CONF_STR""APMINSIGHT_DOMAIN=$APMINSIGHT_DOMAIN\n"
    AGENT_CONF_STR="$AGENT_CONF_STR""AGENT_KEY=$AGENT_KEY\n"
    conf_filepath="$AGENT_INSTALLATION_PATH/conf/oneagentconf.ini"
    printf "$AGENT_CONF_STR" > "$conf_filepath"
    if [ -f "$conf_filepath" ]; then
        Log "Successfully created the oneagentconf.ini at $AGENT_INSTALLATION_PATH/conf"
    else
        Log "Error creating file oneagentconf.ini at $AGENT_INSTALLATION_PATH/conf"
    fi
}

#CREATE /etc/ld.so.preload FILE AND POPULATE IT
SetPreload() {
    Log "SETTING PRELOAD"
    if [ -f "$AGENT_INSTALLATION_PATH/bin/oneagentloader.so" ]; then
        mv "$AGENT_INSTALLATION_PATH/bin/oneagentloader.so" "$APMINSIGHT_ONEAGENT_PRELOADER_BINARY_PATH"
        echo "$APMINSIGHT_ONEAGENT_PRELOADER_BINARY_PATH" >> "$PRELOAD_FILE_PATH"
    else
        Log "oneagentloader.so file not found at "$AGENT_INSTALLATION_PATH/bin/""
        INSTALLATION_UNSUCCESSFUL="true"
    fi

}

RemoveInstallationFiles() {
    rm -rf "$TEMP_FOLDER_PATH"
}

MoveInstallationFiles() {
    if [ "$AGENT_STARTUP_LOGFILE_PATH" != "$AGENT_INSTALLATION_PATH/logs/apm-one-agent-installation.log" ]; then
        mv "$AGENT_STARTUP_LOGFILE_PATH" "$AGENT_INSTALLATION_PATH/logs"
    fi
    if [ "$(dirname "$(readlink -f "$0")")" != "$AGENT_INSTALLATION_PATH/bin" ]; then
        mv "$(dirname "$(readlink -f "$0")")"/apm-one-agent-linux.sh "$AGENT_INSTALLATION_PATH/bin/"
    fi
    
}

CompareAgentVersions() {
    Log "Found existing ApminsightOneagentLinux of Version $EXISTING_APMINSIGHT_ONEAGENT_VERSION"
    EXISTING_AGENT_VERSION_NUM="$(echo "$EXISTING_APMINSIGHT_ONEAGENT_VERSION" | sed 's/\.//g')"
    EXISTING_AGENT_VERSION_NUM=$((EXISTING_AGENT_VERSION_NUM))
    CURRENT_AGENT_VERSION_NUM="$(echo "$APMINSIGHT_ONEAGENT_VERSION" | sed 's/\.//g')"
    CURRENT_AGENT_VERSION_NUM=$((CURRENT_AGENT_VERSION_NUM))
    if [ "$EXISTING_AGENT_VERSION_NUM" -lt "$CURRENT_AGENT_VERSION_NUM" ]; then
        # ReadExistingOneagentPath
        # if [ -f "$EXISTING_ONEAGENTPATH/conf/oneagentconf.ini" ]; then
        #     STARTUP_CONF_FILEPATH="$EXISTING_ONEAGENTPATH/conf/oneagentconf.ini"
        # fi
        # AGENT_INSTALLATION_PATH="$EXISTING_ONEAGENTPATH"
        if [ -f "$AGENT_INSTALLATION_PATH/conf/oneagentconf.ini" ]; then
            STARTUP_CONF_FILEPATH="$AGENT_INSTALLATION_PATH/conf/oneagentconf.ini"
        fi
        if [ "$ONEAGENT_OPERATION" = "install" ]; then
            echo -n "An outdated version of oneagent exists. Would you like to install the new version?\nPlease enter y[es] or n[o]:"
            read upgrade
            if [ "$upgrade" = "y" ] || [ "$upgrade" = "yes" ]; then
                Log "Proceeding to upgrade Oneagent"
                ONEAGENT_OPERATION="upgrade"
                return
            else
                exit 0
            fi
        else
            Log "Proceeding to Upgrade the existing Oneagent of version $EXISTING_APMINSIGHT_ONEAGENT_VERSION"
            return
        fi
        
    elif [ "$EXISTING_AGENT_VERSION_NUM" -gt "$CURRENT_AGENT_VERSION_NUM" ]; then
        Log "Skipping ApminsightOneagentLinux $ONEAGENT_OPERATION as Oneagent with greater version already exists"

    else
        Log "Skipping ApminsightOneagentLinux $ONEAGENT_OPERATION as Oneagent with the current version already exists"
    exit 1
    fi

}

RegisterOneagentVersion() {
    if [ "$INSTALLATION_UNSUCCESSFUL" = "true" ]; then
        Log "Installation unsuccessful"
        exit 0
    fi
    if [ -f "/etc/environment" ]; then
        sed -i '/^'$APMINSIGHT_BRAND_UCASE'_APMINSIGHT_ONEAGENT_VERSION/d' /etc/environment
        echo ""$APMINSIGHT_BRAND_UCASE"_APMINSIGHT_ONEAGENT_VERSION=$APMINSIGHT_ONEAGENT_VERSION" >> "/etc/environment"
        Log "Registered Oneagent Version successfully"
    fi
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

ReadExistingOneagentPath() {
    EXISTING_ONEAGENTPATH="$AGENT_INSTALLATION_PATH"
    FindKeyValPairInFile "/etc/environment" "ONEAGENTPATH" "EXISTING_ONEAGENTPATH"
}

CheckAgentInstallation() {
    FindKeyValPairInFile "/etc/environment" ""$APMINSIGHT_BRAND_UCASE"_APMINSIGHT_ONEAGENT_VERSION" "EXISTING_APMINSIGHT_ONEAGENT_VERSION"
    if [ "$1" = "-uninstall" ]; then
        Log "Uninstalling Oneagent...."
        ONEAGENT_OPERATION="uninstall"
        if [ -z "$EXISTING_APMINSIGHT_ONEAGENT_VERSION" ]; then
            Log "Oneagent is not installed. Aborting uninstallation"
            exit 1
        fi
        # ReadExistingOneagentPath
        # if ! [ -f "$EXISTING_ONEAGENTPATH/bin/apm-one-agent-linux-uninstall.sh" ]; then
        #     Log "Cannot find apm-one-agent-linux-uninstall.sh file at Oneagent installed location: $EXISTING_ONEAGENTPATH/bin/apm-one-agent-linux-uninstall.sh"
        #     exit 1
        # fi
        # sh "$EXISTING_ONEAGENTPATH/bin/apm-one-agent-linux-uninstall.sh"
        if [ -f "$AGENT_INSTALLATION_PATH/bin/apm-one-agent-linux-uninstall.sh" ]; then
            sh "$AGENT_INSTALLATION_PATH/bin/apm-one-agent-linux-uninstall.sh"
            exit 0
        else
            Log "Cannot find apm-one-agent-linux-uninstall.sh file at Oneagent installed location: $AGENT_INSTALLATION_PATH/bin/apm-one-agent-linux-uninstall.sh"
            exit 1
        fi
        exit 0

    elif [ "$1" = "-upgrade" ]; then
        ONEAGENT_OPERATION="upgrade"
        if [ -z "$EXISTING_APMINSIGHT_ONEAGENT_VERSION" ]; then
            Log "No existing Oneagent version found."
            Log "Installing ApminsightOneagentLinux..."
            ONEAGENT_OPERATION="install"
            return
        else
            Log "Upgrading ApminsightOneagentLinux..."
        fi

    else
        if [ -z "$EXISTING_APMINSIGHT_ONEAGENT_VERSION" ]; then
            Log "Installing ApminsightOneagentLinux..."
            return
        fi
    fi
    #FOUND EXISTING ONEAGENT
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
            Log "Could not create $APMINSIGHT_USER, Aborting Apminsight Oneagent Installation"
            exit 1
        fi
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

RegisterOneagentService() {
    Log "Registering $APMINSIGHT_SERVICE_FILE"
    CheckAndRemoveExistingService
    if ! [ -f "$AGENT_INSTALLATION_PATH/bin/$APMINSIGHT_SERVICE_FILE" ]; then
        Log "Cannot find Oneagent service binary. Skipping the service start"
        INSTALLATION_UNSUCCESSFUL="true"
        return
    fi
    cp "$AGENT_INSTALLATION_PATH/bin/$APMINSIGHT_SERVICE_FILE" /etc/systemd/system/
    Log "$(systemctl enable $APMINSIGHT_SERVICE_FILE 2>&1)"
    Log "$(systemctl daemon-reload 2>&1)"
    Log "$(systemctl restart $APMINSIGHT_SERVICE_FILE 2>&1)"
    if systemctl list-unit-files --type=service | grep -q "^$APMINSIGHT_SERVICE_FILE"; then
        echo "$APMINSIGHT_SERVICE_FILE is registered properly."
    else
        echo "$APMINSIGHT_SERVICE_FILE is not registered properly."
        INSTALLATION_UNSUCCESSFUL="true"
    fi
}

checkGlibcCompatibility() {
    if ! command -v ldd >/dev/null 2>&1; then
        Log "ldd command not found. Unable to check for glibc."
        exit 0
    fi

    if ldd --version 2>/dev/null | grep -iqE "GNU libc|Free Software Foundation|Roland McGrath"; then
        Log "GLIBC detected."
    else
        Log "GLIBC not detected. ApminsightOneagentLinux is not supported for non-GLIBC distributions for now"
        exit 0
    fi
    GLIBC_VERSION="$(ldd --version | awk 'NR==1{ print $NF }')"
    GLIBC_VERSION_MAJ=$(echo "$GLIBC_VERSION" | sed 's/\..*//')
    GLIBC_VERSION_MIN=$(echo "$GLIBC_VERSION" | sed 's/^[^\.]*\.\([^\.]*\).*/\1/')
    GLIBC_VERSION_COMPATIBLE_MAJ=$(echo "$GLIBC_VERSION_COMPATIBLE" | sed 's/\..*//')
    GLIBC_VERSION_COMPATIBLE_MIN=$(echo "$GLIBC_VERSION_COMPATIBLE" | sed 's/^[^\.]*\.\([^\.]*\).*/\1/')
    if [ "$GLIBC_VERSION_MAJ" -lt "$GLIBC_VERSION_COMPATIBLE_MAJ" ]; then
        Log "GLIBC VERSION INCOMPATIBLE"
        exit 1
    elif [ "$GLIBC_VERSION_MAJ" -eq "$GLIBC_VERSION_COMPATIBLE_MAJ" ]; then
        if [ "$GLIBC_VERSION_MIN" -lt "$GLIBC_VERSION_COMPATIBLE_MIN" ]; then
            Log "GLIBC VERSION INCOMPATIBLE"
            exit 1
        fi
    fi
}

checkGccCompatibility() {
    GCC_VERSION="$(gcc --version | awk 'NR==1{ print $NF }')"
    GCC_VERSION_MAJ=$(echo "$GCC_VERSION" | sed 's/\..*//')
    GCC_VERSION_MIN=$(echo "$GCC_VERSION" | sed 's/^[^\.]*\.\([^\.]*\).*/\1/')
    GCC_VERSION_COMPATIBLE_MAJ=$(echo "$GCC_VERSION_COMPATIBLE" | sed 's/\..*//')
    GCC_VERSION_COMPATIBLE_MIN=$(echo "$GCC_VERSION_COMPATIBLE" | sed 's/^[^\.]*\.\([^\.]*\).*/\1/')
    if [ "$GCC_VERSION_MAJ" -lt "$GCC_VERSION_COMPATIBLE_MAJ" ]; then
        Log "GCC VERSION INCOMPATIBLE"
        exit 1
    elif [ "$GCC_VERSION_MAJ" -eq "$GCC_VERSION_COMPATIBLE_MAJ" ]; then
        if [ "$GCC_VERSION_MIN" -lt "$GCC_VERSION_COMPATIBLE_MIN" ]; then
            Log "GCC VERSION INCOMPATIBLE"
            exit 1
        fi
    fi
}

checkCompatibility() {
    checkGlibcCompatibility
    checkGccCompatibility
}

main() {
    CheckArgs $@
    CheckRoot
    ReadBrandName
    RedirectLogs
    checkCompatibility
    CheckAgentInstallation $@
    CheckAndCreateApminsightUser
    SetupPreInstallationChecks
    SetupAgentConfigurations "$@"
    SetupAgents
    WriteToAgentConfFile
    InstallS247DataExporter
    LoadAgentForExistingJavaProcesses
    SetPreload
    GiveFilePermissions
    RegisterOneagentService
    RegisterOneagentVersion
    MoveInstallationFiles
    RemoveInstallationFiles
    }
main "$@"
