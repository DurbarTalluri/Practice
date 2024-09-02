#!/bin/sh

NODE_MINIFIED_DOWNLOAD_PATH="https://staticdownloads.site24x7.com/apminsight/agents/apm_insight_agent_nodejs.zip"
NODE_AGENT_CHECKSUM="https://staticdownloads.site24x7.com/apminsight/checksum/apm_insight_agent_nodejs.zip.sha256"
JAVA_AGENT_DOWNLOAD_PATH="https://staticdownloads.site24x7.com/apminsight/agents/apminsight-javaagent.zip"
JAVA_AGENT_CHECKSUM="https://staticdownloads.site24x7.com/apminsight/checksum/apminsight-javaagent.zip.sha256"
PYTHON_AGENT_DOWNLOAD_PATH_PREFIX="https://staticdownloads.site24x7.com/apminsight/agents/linux/glibc/"
PYTHON_AGENT_CHECKSUM_PREFIX="https://staticdownloads.site24x7.com/apminsight/checksum/linux/glibc/"
DOTNETCORE_AGENT_DOWNLOAD_PATH="https://staticdownloads.site24x7.com/apminsight/agents/apminsight-dotnetcoreagent-linux.sh"
DOTNETCORE_AGENT_CHECKSUM="https://staticdownloads.site24x7.com/apminsight/checksum/apminsight-dotnetcoreagent-linux.sh.sha256"
DATA_EXPORTER_SCRIPT_DOWNLOAD_PATH_EXTENSION="/apminsight/S247DataExporter/linux/InstallDataExporter.sh"
ONEAGENT_FILES_DOWNLOAD_PATH="https://staticdownloads.site24x7.com/apminsight/agents/apm-one-agent-linux-files.zip"
ONEAGENT_FILES_CHECKSUM="https://staticdownloads.site24x7.com/apminsight/checksum/apm-one-agent-linux-files.zip.sha256"

APM_ONEAGENT_PATH="/opt"
AGENT_INSTALLATION_PATH="/opt/site24x7/apmoneagent"
PRELOAD_FILE_PATH="/etc/ld.so.preload"
AGENT_STARTUP_LOGFILE_PATH="ApmOneagentInstallation.log"
STARTUP_CONF_FILEPATH="./oneagentconf.ini"

KUBERNETES_ENV=0
BUNDLED=0
APM_LICENSE_KEY=""
CURRENT_DIRECTORY=$(pwd)
TEMP_FOLDER_PATH="$CURRENT_DIRECTORY/temp"
AGENT_CONF_STR=""
APM_SERVER_HOST=""
APM_SERVER_PORT=""
APM_SERVER_PROTOCOL=""
APM_HOST_URL=""
APM_PROXY_SERVER_NAME=""
APM_PROXY_SERVER_PORT=""
APM_PROXY_USER_NAME=""
APM_PROXY_PASSWORD=""
APM_PROXY_URL=""
APM_PROXY_SERVER_PROTOCOL=""
PROXY_STR=""
DOMAIN="com"
PYTHON_AGENT_PATH=""
AGENT_START_TIME=""
AGENT_ID=""
APM_LICENSE_KEY_ENCRYPTED=""

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
SECURED_PROTOCOL=""
ONEAGENT_VERSION="1.0.0"
ONEAGENT_OPERATION="install"

displayHelp() {
    echo "Usage: $0 [option] [arguments]\n \n Options:\n"
    echo "  --APM_LICENSE_KEY             To configure the site24x7 License key"
    echo "  --APM_PROXY_SERVER_NAME       To configure Proxy server/host name if using any"
    echo "  --APM_PROXY_SERVER_PORT       To configure Proxy server port"
    echo "  --APM_PROXY_USER_NAME         To configure Proxy server username"
    echo "  --APM_PROXY_SERVER_PORT       To configure Proxy server password"
    echo "  --APM_PROXY_SERVER_PORT       To configure Proxy server protocol"
    echo "  --APM_ONEAGENT_PATH           To configure Custom path for Oneagent related files"
    echo "  --APM_MONITOR_GROUP           To configure Agent monitor groups"
}

CheckArgs() {
    if [ "$*" = "--help" ]; then
        displayHelp
        exit 1
    fi
}

RedirectLogs() {
    exec >>"$AGENT_STARTUP_LOGFILE_PATH" 2>&1
}

Log() {
    echo $(date +"%F %T.%N") " $1\n"
}

CheckUser() {
    if [ "$(id -u)" -ne 0 ]; then
        Log "OneAgent installer script is run without root privilege. Please run the script apm-one-agent-linux.sh with root privilege"
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
    CheckUser
    CheckBit
    CheckARM
    SetArchBasedDownloadPathExtension
    DetectKubernetes
}

ConstructProxyUrl() {
    if [ -n "$APM_PROXY_URL" ]; then
        return
    fi
    if [ "$APM_PROXY_SERVER_NAME" ]; then
        APM_PROXY_URL="$APM_PROXY_SERVER_NAME"
        if [ -n "$APM_PROXY_SERVER_PORT" ]; then
            APM_PROXY_URL="$APM_PROXY_URL:$APM_PROXY_SERVER_PORT"
        fi
    fi
    if [ -n "$APM_PROXY_USER_NAME" ]; then
        if [ -n "$APM_PROXY_PASSWORD" ]; then
            APM_PROXY_URL="$APM_PROXY_USER_NAME:$APM_PROXY_PASSWORD@$APM_PROXY_URL"
        else
            APM_PROXY_URL="$APM_PROXY_USER_NAME@$APM_PROXY_URL"
        fi
    fi
    if [ -z "$APM_PROXY_SERVER_PROTOCOL" ]; then
        APM_PROXY_SERVER_PROTOCOL="http"
    fi
    if [ -n "$APM_PROXY_URL" ]; then
        PROXY_STR="$APM_PROXY_SERVER_PROTOCOL://$APM_PROXY_URL"
    fi
    
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
            --*)
                key="${1#--}"
                value="$2"
                if [ -z "$value" ] || [ "$value" = "0" ]; then
                    shift 2 
                    continue
                fi
                if [ "$key" = "BUNDLED" ]; then
                    BUNDLED=1
                elif [ "$key" = "APM_LICENSE_KEY" ]; then
                    APM_LICENSE_KEY=$value
                elif [ "$key" = "APM_PROXY_URL" ]; then
                    APM_PROXY_URL=$value
                elif [ "$key" = "APM_PROXY_SERVER_NAME" ]; then
                    APM_PROXY_SERVER_NAME="$value"
                elif [ "$key" = "APM_PROXY_SERVER_PORT" ]; then
                    APM_PROXY_SERVER_PORT="$value"
                elif [ "$key" = "APM_PROXY_USER_NAME" ]; then
                    APM_PROXY_USER_NAME="$value"
                elif [ "$key" = "APM_PROXY_PASSWORD" ]; then
                    APM_PROXY_PASSWORD="$value"
                elif [ "$key" = "APM_PROXY_SERVER_PROTOCOL" ]; then
                    APM_PROXY_SERVER_PROTOCOL="$value"
                elif [ "$key" = "APM_ONEAGENT_PATH" ]; then
                    if [ -d $value ]; then
                        APM_ONEAGENT_PATH=$(echo "$value" | sed 's/\/$//')
                        AGENT_INSTALLATION_PATH="$value/site24x7/apmoneagent"
                        echo "APM_ONEAGENT_PATH=$AGENT_INSTALLATION_PATH" >> /etc/environment 
                    else
                        Log "Path provided as APM_ONEAGENT_PATH not present. Installing agent at default location /opt/Site24x7/apmoneagent"
                    fi
                elif [ "$key" = "APM_SERVER_HOST" ]; then
                    APM_SERVER_HOST=$value
                elif [ "$key" = "APM_SERVER_PORT" ]; then
                    APM_SERVER_PORT=$value
                elif [ "$key" = "APM_SERVER_PROTOCOL" ]; then
                    if [ "$value" = "true" ]; then
                        SECURED_PROTOCOL="true"
                    fi
                elif [ "$key" = "APM_MONITOR_GROUP" ]; then
                    APM_MONITOR_GROUP=$value
                elif [ "$key" = "JAVA_AGENT_DOWNLOAD_PATH" ]; then
                    JAVA_AGENT_DOWNLOAD_PATH="$value"
                elif [ "$key" = "NODE_AGENT_DOWNLOAD_PATH" ]; then
                    NODE_MINIFIED_DOWNLOAD_PATH="$value"
                elif [ "$key" = "PYTHON_AGENT_DOWNLOAD_PATH" ]; then
                    PYTHON_AGENT_DOWNLOAD_PATH="$value"
                elif [ "$key" = "DOTNETCORE_AGENT_DOWNLOAD_PATH" ]; then
                    DOTNETCORE_AGENT_DOWNLOAD_PATH="$value"
                elif [ "$key" = "ONEAGENT_DOWNLOAD_PATH" ]; then
                    ONEAGENT_FILES_DONWLOAD_PATH="$value"
                elif [ "$key" = "S247DATAEXPORTER_DOWNLOAD_PATH" ]; then
                    DATA_EXPORTER_SCRIPT_DOWNLOAD_PATH="$value"
                elif [ "$key" = "JAVA_AGENT_CHECKSUM" ]; then
                    JAVA_AGENT_CHECKSUM="$value"
                elif [ "$key" = "NODE_AGENT_CHECKSUM" ]; then
                    NODE_AGENT_CHECKSUM="$value"
                elif [ "$key" = "PYTHON_AGENT_CHECKSUM" ]; then
                    PYTHON_AGENT_CHECKSUM="$value"
                elif [ "$key" = "DOTNETCORE_AGENT_CHECKSUM" ]; then
                    DOTNETCORE_AGENT_CHECKSUM="$value"
                elif [ "$key" = "ONEAGENT_FILES_CHECKSUM" ]; then
                    ONEAGENT_FILES_CHECKSUM="$value"
                else
                    Log "Invalid argument name : $key. Please provide a valid one"
                fi
                shift 2  # Move to the next key-value pair
                ;;
            *)
        esac
        shift 1
    done
    if [ -z "$APM_LICENSE_KEY" ]; then
        Log "Unable to find License key from commandline arguments. Please run the apm-one-agent-linux.sh script again providing License key or set License Key in the configuration file located at $AGENT_INSTALLATION_PATH in the format LICENSEKEY=<Your License Key>"
    fi
}

BuildApmHostUrl() {
    if [ "$APM_SERVER_HOST" != "" ]; then
        APM_HOST_URL="$APM_SERVER_HOST"
        if [ "$APM_SERVER_PORT" != "" ]; then
            APM_HOST_URL="$APM_HOST_URL:"$APM_SERVER_PORT""
        else
            APM_HOST_URL="$APM_HOST_URL:443"
        fi
        if [ -n "$SECURED_PROTOCOL" ]; then
            APM_HOST_URL="https://$APM_HOST_URL"
        else
            APM_HOST_URL="http://$APM_HOST_URL"
        fi
    fi
}

SetProxy() {
    ConstructProxyUrl
    if [ -n "$PROXY_STR" ]; then
        export http_proxy=$PROXY_STR
        export https_proxy=$PROXY_STR
        export ftp_proxy=$PROXY_STR
    fi
}

ReadDomain() {
    if [ -z "$APM_LICENSE_KEY" ]; then
        return
    fi
    if echo "$APM_LICENSE_KEY" | grep -q "_"; then
        DOMAIN="${APM_LICENSE_KEY%%_*}"
        if [ "$DOMAIN" = "us" ] || [ "$DOMAIN" = "gd" ]; then
            DOMAIN="com"
        fi
    fi
}

EncryptLicenseKey() {
    AGENT_START_TIME=$(echo -n $(date +"%Y%m%dT%H%M%S%N") | xargs printf "%-32s" | tr ' ' '0')
    AGENT_ID="$(openssl rand -hex 24 | cut -c1-16)"
    APM_LICENSE_KEY_ENCRYPTED=$(echo -n "$APM_LICENSE_KEY" | openssl enc -aes-256-cbc -K $(echo -n "$AGENT_START_TIME" | xxd -p -c 256) -iv $(echo -n "$AGENT_ID" | xxd -p -c 256) -base64)
    if [ -z "$APM_LICENSE_KEY_ENCRYPTED" ]; then
        Log "Unable to generate the License string. Abandoning the installation process"
        exit 1
    fi
}

SetupAgentConfigurations() {
    ReadConfigFromFile
    ReadConfigFromArgs "$@"
    BuildApmHostUrl
    SetProxy
    ReadDomain
    EncryptLicenseKey
}

RemoveExistingOneagentFiles() {
    rm -rf "$AGENT_INSTALLATION_PATH/lib"
    rm -rf "$AGENT_INSTALLATION_PATH/bin"
    sed -i '/liboneagentloader.so$/d' /etc/ld.so.preload
    rm -f /lib/liboneagentloader.so
}

#CREATE AGENT FOLDERS IN USER MACHINE AND STORE THE DOWNLOADED AGENT FILES 
CreateAgentFiles() {
    Log "DELETING EXISTING ONEAGENT FILES IF ANY"
    RemoveExistingOneagentFiles
    Log "CREATING AGENT FILES"
    mkdir -p "$AGENT_INSTALLATION_PATH"
    mkdir -p "$AGENT_INSTALLATION_PATH/conf"
    mkdir -p "$AGENT_INSTALLATION_PATH/lib"
    mkdir -p "$AGENT_INSTALLATION_PATH/bin"
    mkdir -p "$AGENT_INSTALLATION_PATH/lib/NODEJS"
    mkdir -p "$AGENT_INSTALLATION_PATH/lib/JAVA"
    mkdir -p "$AGENT_INSTALLATION_PATH/lib/PYTHON"
    mkdir -p "$AGENT_INSTALLATION_PATH/lib/DOTNETCORE"
    mkdir -p "$AGENT_INSTALLATION_PATH/logs"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/JAVA"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/JAVA/logs"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/NODEJS/"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/NODEJS/logs"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/PYTHON"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/PYTHON/logs"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/DOTNETCORE"
    mkdir -p "$AGENT_INSTALLATION_PATH/agents/DOTNETCORE/logs"
    touch "$AGENT_INSTALLATION_PATH/logs/oneagentloader.log"
}

DownloadAgentFiles() {
    if [ "$KUBERNETES_ENV" -eq 1 ]; then
        return

    elif [ "$BUNDLED" -eq 0 ]; then
        Log "DOWNLOADING AGENT FILES"
        mkdir -p "$TEMP_FOLDER_PATH"
        cd "$TEMP_FOLDER_PATH"
        wget -nv "$NODE_MINIFIED_DOWNLOAD_PATH"
        ValidateChecksumAndInstallAgent "apm_insight_agent_nodejs.zip" "$NODE_AGENT_CHECKSUM" "$AGENT_INSTALLATION_PATH/lib/NODEJS"

        wget -nv "$JAVA_AGENT_DOWNLOAD_PATH"
        ValidateChecksumAndInstallAgent "apminsight-javaagent.zip" "$JAVA_AGENT_CHECKSUM" "$AGENT_INSTALLATION_PATH/lib/JAVA"
        
        cd "$CURRENT_DIRECTORY"
        return
    fi

    unzip "apm_insight_agent_nodejs.zip" -d "$AGENT_INSTALLATION_PATH/lib/NODEJS"
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
    Downloadfilechecksumvalue="$(sha256sum $file | awk -F' ' '{print $1}')"
    if [ "$Originalchecksumvalue" = "$Downloadfilechecksumvalue" ]; then
        unzip "$file" -d "$destinationpath"
    fi
}

#INSTALL NODEJS AGENT DEPENDENCIES
InstallNodeJSDependencies() {
    Log "INSTALLING NODE DEPENDENCIES"
    NODE_AGENT_PATH="$AGENT_INSTALLATION_PATH/lib/NODEJS/agent_minified"
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
    ValidateChecksumAndInstallAgent "apm_insight_agent_python.zip" "$PYTHON_AGENT_CHECKSUM" "$AGENT_INSTALLATION_PATH/lib/PYTHON"
    cd "$CURRENT_DIRECTORY"
    Log "INSTALLING APMINSIGHT PYTHON PACKAGE"
    PYTHON_FILE_PATH="$AGENT_INSTALLATION_PATH/lib/PYTHON/wheels"
    if [ "$KUBERNETES_ENV" -eq 1 ]; then
        PYTHON_FILE_PATH="$AGENT_INSTALLATION_PATH/wheels"
    fi
    pip uninstall --yes apminsight
    pip install --upgrade --no-index --find-links="$PYTHON_FILE_PATH" apminsight 2>/tmp/python_agent_installation_warnings.log
    PYTHON_AGENT_PATH="$(pip show apminsight | awk '/^Location:/ {print $2}')"
    NEW_PYTHON_PATH="$PYTHON_AGENT_PATH/apminsight/bootstrap:$PYTHON_AGENT_PATH:"

}

InstallDotNetCoreAgent() {
    cd "$TEMP_FOLDER_PATH"
    wget -nv "$DOTNETCORE_AGENT_DOWNLOAD_PATH"
    wget -nv "$DOTNETCORE_AGENT_CHECKSUM"
    Originalchecksumvalue="$(cat "apminsight-dotnetcoreagent-linux.sh.sha256")"
    Downloadfilechecksumvalue="$(sha256sum "apminsight-dotnetcoreagent-linux.sh" | awk -F' ' '{print $1}')"
    if [ "$Originalchecksumvalue" = "$Downloadfilechecksumvalue" ]; then
        sudo bash ./apminsight-dotnetcoreagent-linux.sh -Destination "$AGENT_INSTALLATION_PATH/lib/DOTNETCORE" -LicenseKey "$APM_LICENSE_KEY" -OneAgentInstall -OneAgentHomePath "$AGENT_INSTALLATION_PATH/agents/DOTNETCORE"
    else
        Log "Checksum Validation failed for DotnetCore agent installation file"
    fi
    cd "$CURRENT_DIRECTORY"
}

#INSTALL S247DATAEXPORTER
InstallS247DataExporter() {
    Log "INSTALLING S247DATAEXPORTER"
    EXPORTER_INSTALLATION_ARGUMENTS="-license.key "$APM_LICENSE_KEY""
    if [ "$APM_PROXY_URL" != "" ]; then
        EXPORTER_INSTALLATION_ARGUMENTS="$EXPORTER_INSTALLATION_ARGUMENTS -behind.proxy true -proxy.url $PROXY_STR"
    fi
    if [ "$APM_HOST_URL" != "" ]; then
        EXPORTER_INSTALLATION_ARGUMENTS="$EXPORTER_INSTALLATION_ARGUMENTS -apm.host $APM_HOST_URL"
    fi
    DOWNLOAD_PATH="https://staticdownloads.site24x7.""$DOMAIN""$DATA_EXPORTER_SCRIPT_DOWNLOAD_PATH_EXTENSION"
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
    sudo rm /opt/S247DataExporter.zip
    cd "$CURRENT_DIRECTORY"
    fi
}

SetupOneagentFiles() {
    cd "$TEMP_FOLDER_PATH"
    wget -nv "$ONEAGENT_FILES_DOWNLOAD_PATH"
    ValidateChecksumAndInstallAgent "apm_insight_oneagent_linux_files.zip" "$ONEAGENT_FILES_CHECKSUM" "$AGENT_INSTALLATION_PATH/bin"
    cd "$CURRENT_DIRECTORY"
}

#GIVE RESPECTIVE PERMISSIONS TO AGENT FILES
GiveFilePermissions() {
    Log "GIVING FILE PERMISSIONS"
    chmod 777 -R "$APM_ONEAGENT_PATH"
    chmod 755 -R "$AGENT_INSTALLATION_PATH/bin"
    chmod 755 -R "$AGENT_INSTALLATION_PATH/lib/JAVA"
    chmod 777 -R "$AGENT_INSTALLATION_PATH/logs"
    chmod 777 -R "$AGENT_INSTALLATION_PATH/agents"
}

SetupApmAgents() {
    if ! [ "$ONEAGENT_OPERATION"  = "install" ]; then
        Log "Ignoring APM agents Installation"
        return
    fi
    CreateAgentFiles
    DownloadAgentFiles
    InstallNodeJSDependencies
    InstallPythonDependencies
    InstallDotNetCoreAgent
    InstallS247DataExporter
    GiveFilePermissions
}

#CHECK FOR EXISTING JAVA PROCESSES AND LOAD AGENT DYNAMICALLY INTO THE PROCESS
LoadAgentForExistingJavaProcesses() {
    Log "LOADING AGENT INTO EXISTING JAVA PROCESSES"
    if [ "$APM_LICENSE_KEY" = "" ]; then
        Log "NO LICENSE KEY FOUND, LOADING AGENT TO EXISTING JAVA PROCESSES WILL BE SKIPPED"
        return
    fi
    Log "LOADING AGENT TO EXISTING JAVA PROCESSES"
    pids=$(ps -ef | grep -e 'java' -e 'tomcat' | grep -v 'grep' | awk '{print $2}')

    # Iterate over each PID and run the command with java -jar apminsight-javaagent.jar -start <pid>
    DYNAMIC_LOAD_ARGUMENTS="-lk "$APM_LICENSE_KEY""
    if [ "$APM_PROXY_URL" != "" ]; then
        DYNAMIC_LOAD_ARGUMENTS="$DYNAMIC_LOAD_ARGUMENTS -ap $APM_PROXY_URL"
    fi
    if [ "$APM_HOST_URL" != "" ]; then
        DYNAMIC_LOAD_ARGUMENTS="$DYNAMIC_LOAD_ARGUMENTS -aph $APM_HOST_URL"
    fi
    for pid in $pids; do
    Log "JAVA PROCESS DETECTED: $pid"
        eval "java -jar $AGENT_INSTALLATION_PATH/lib/JAVA/apminsight-javaagent.jar -start "$pid" "$DYNAMIC_LOAD_ARGUMENTS""
    done
}

WriteToAgentConfFile() {
	AGENT_CONF_STR="[CONFIG]\n"

	if [ -n "$APM_PROXY_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APM_PROXY_URL=$APM_PROXY_URL\n"
    fi
    if [ -n "$APM_PROXY_SERVER_NAME" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APM_PROXY_SERVER_NAME=$APM_PROXY_SERVER_NAME\n"
    fi
    if [ -n "$APM_PROXY_SERVER_PORT" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APM_PROXY_SERVER_PORT=$APM_PROXY_SERVER_PORT\n"
    fi
    if [ -n "$APM_PROXY_SERVER_PROTOCOL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APM_PROXY_SERVER_PROTOCOL=$APM_PROXY_SERVER_PROTOCOL\n"
    fi
    if [ -n "$APM_PROXY_USER_NAME" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APM_PROXY_USER_NAME=$APM_PROXY_USER_NAME\n"
    fi
    if [ -n "$APM_PROXY_PASSWORD" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APM_PROXY_PASSWORD=$APM_PROXY_PASSWORD\n"
    fi
    if [ -n "$APM_SERVER_HOST" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APM_SERVER_HOST=$APM_SERVER_HOST\n"
    fi
    if [ -n "$APM_SERVER_PORT" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APM_SERVER_PORT=$APM_SERVER_PORT\n"
    fi
    if [ -n "$APM_SERVER_PROTOCOL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APM_SERVER_PROTOCOL=$APM_SERVER_PROTOCOL\n"
    fi
    if [ -n "$APM_HOST_URL" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APM_HOST_URL=$APM_HOST_URL\n"
    fi  
    if [ -n "$APM_MONITOR_GROUP" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APM_MONITOR_GROUP=$APM_MONITOR_GROUP\n"
    fi
    if [ -n "$PYTHON_AGENT_PATH" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""NEW_PYTHON_PATH=$NEW_PYTHON_PATH\n"
    fi
    if [ -n "$APM_LICENSE_KEY_ENCRYPTED" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""LICENSEKEY=$APM_LICENSE_KEY_ENCRYPTED\n"
    fi
    if [ -n "$AGENT_START_TIME" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""AGENT_START_TIME=$AGENT_START_TIME\n"
    fi
    if [ -n "$AGENT_ID" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""AGENT_ID=$AGENT_ID\n"
    fi
    AGENT_CONF_STR="$AGENT_CONF_STR""DOMAIN=$DOMAIN\n"
    conf_filepath="$AGENT_INSTALLATION_PATH/conf/oneagentconf.ini"
    echo "$AGENT_CONF_STR" > "$conf_filepath"
    if [ -f "$conf_filepath" ]; then
        Log "Successfully created the oneagentconf.json at $AGENT_INSTALLATION_PATH/conf"
    else
        Log "Error creating file oneagentconf.json at $AGENT_INSTALLATION_PATH/conf"
    fi
}

#CREATE /etc/ld.so.preload FILE AND POPULATE IT
SetPreload() {
    Log "SETTING PRELOAD"
    if [ -f "$AGENT_INSTALLATION_PATH/bin/oneagentloader.so" ]; then
        mv "$AGENT_INSTALLATION_PATH/bin/oneagentloader.so" /lib/liboneagentloader.so
        echo "/lib/liboneagentloader.so" >> "$PRELOAD_FILE_PATH"
        chmod 644 "$PRELOAD_FILE_PATH"
        chmod 644 "/lib/liboneagentloader.so"
    else
        Log "No file found at "$AGENT_INSTALLATION_PATH/bin/oneagentloader.so""
    fi

}

RemoveInstallationFiles() {
    rm -rf "$TEMP_FOLDER_PATH"
}

MoveInstallationFiles() {
    if [ "$ONEAGENT_OPERATION" = "install" ]; then
        mv "$AGENT_STARTUP_LOGFILE_PATH" "$AGENT_INSTALLATION_PATH/logs"
        mv ./apm-one-agent-linux.sh "$AGENT_INSTALLATION_PATH/bin"
    fi
}

CompareAgentVersions() {
    if [ "$EXISTING_AGENT_VERSION_NUM" -lt "$CURRENT_AGENT_VERSION_NUM" ]; then
        ReadExistingOneagentPath
        AGENT_STARTUP_LOGFILE_PATH="$EXISTING_ONEAGENTPATH/logs/ApmOneagentInstallation.log"
        if [ "$ONEAGENT_OPERATION" = "install" ]; then
            Log -n "An outdated version of oneagent exists. Would you like to install the new version?\nPlease enter y[es] or n[o]:"
            read upgrade
            if [ "$upgrade" = "y" ] || [ "$upgrade" = "yes" ]; then
                echo "Proceeding to upgrade Oneagent"
                ONEAGENT_OPERATION="upgrade"
                return
            else
                exit 0
            fi
        fi
        return
    elif [ "$EXISTING_AGENT_VERSION_NUM" -gt "$CURRENT_AGENT_VERSION_NUM" ]; then
        Log "Skipping Installation as Oneagent with greater version already exists"

    else
        Log "Skipping Installation as Oneagent with the current version already exists"
    exit 1
    fi

}

checkVersion() {
    ETC_ENV_FILEPATH="/etc/environment"
    if [ -f $ETC_ENV_FILEPATH ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            case "$line" in
                *=*)
                    key=$(echo "$line" | cut -d '=' -f 1 | sed 's/[[:space:]]*$//')
                    if [ "$key" = "ONEAGENT_VERSION" ]; then
                        EXISTING_ONEAGENT_VERSION=$(echo "$line" | cut -d '=' -f 2- | sed 's/^[[:space:]]*//')
                        EXISTING_AGENT_VERSION_NUM="$(echo "$EXISTING_ONEAGENT_VERSION" | sed 's/\.//g')"
                        EXISTING_AGENT_VERSION_NUM=$((EXISTING_AGENT_VERSION_NUM))
                        CURRENT_AGENT_VERSION_NUM="$(echo "$ONEAGENT_VERSION" | sed 's/\.//g')"
                        CURRENT_AGENT_VERSION_NUM=$((CURRENT_AGENT_VERSION_NUM))
                    fi
                    ;;
            esac
        done < "$ETC_ENV_FILEPATH"
        if [ "$EXISTING_ONEAGENT_VERSION" ]; then
            CompareAgentVersions
        fi
    fi

}

RegisterOneagentVersion() {
    if [ -f "/etc/environment" ]; then
        sed -i '/^ONEAGENT_VERSION/d' /etc/environment
        echo "ONEAGENT_VERSION=$ONEAGENT_VERSION" >> "/etc/environment"
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
                        eval $key=\"$value\"
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
    FindKeyValPairInFile "/etc/environment" "ONEAGENTPATH"
}

CheckIfOneagentExists() {
    OneagentExists="$(FindKeyValPairInFile "/etc/environment" "OENAGENT_VERISON")"
    return $((OneagentExists))
}

CheckAgentInstallation() {
    if [ "$1" = "-uninstall" ]; then
        Log "Uninstalling Oneagent...."
        ONEAGENT_OPERATION="uninstall"
        if ! CheckIfOneagentExists; then
            Log "Oneagent is not installed. Aborting uninstallation"
            exit 1
        fi
        ReadExistingOneagentPath
        if ! [ -f "$EXISTING_ONEAGENTPATH/bin/uninstall.sh" ]; then
            Log "Cannot find uninstall.sh file at Oneagent installed location: $EXISTING_ONEAGENTPATH/bin/uninstall.sh"
            exit 1
        fi
        sh "$EXISTING_ONEAGENTPATH/bin/uninstall.sh"
        exit 0

    elif [ "$1" = "-upgrade" ]; then
        Log "Upgrading Oneagent...."
        ONEAGENT_OPERATION="upgrade"
        if ! CheckIfOneagentExists; then
            Log "No existing Oneagent version found. Installing this version of Oneagent"
            ONEAGENT_OPERATION="install"
        fi
    else
        Log "Installing Oneagent...."
    fi
    checkVersion
}

main() {
    CheckAgentInstallation $@
    CheckArgs $@
    RedirectLogs
    SetupPreInstallationChecks
    SetupAgentConfigurations "$@"
    SetupOneagentFiles
    SetupApmAgents
    LoadAgentForExistingJavaProcesses
    WriteToAgentConfFile
    RegisterOneagentVersion
    SetPreload
    MoveInstallationFiles
    RemoveInstallationFiles
    }
main "$@"