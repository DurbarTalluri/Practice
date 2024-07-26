#!/bin/sh

NODE_MINIFIED_DOWNLOAD_PATH="https://build.zohocorp.com/me/apm_insight_agent_nodejs/webhost/one_agent_changes_branch/Jul_26_2024/apm_insight_agent_nodejs.zip"
NODE_AGENT_CHECKSUM="https://build.zohocorp.com/me/apm_insight_agent_nodejs/webhost/one_agent_changes_branch/Jul_26_2024/apm_insight_agent_nodejs.zip.sha256"
JAVA_AGENT_DOWNLOAD_PATH="https://build.zohocorp.com/me/agent_java/webhost/oneagent_java/Jul_26_2024/apminsight_javaagent/site24x7/apminsight-javaagent.zip"
JAVA_AGENT_CHECKSUM="https://build.zohocorp.com/me/agent_java/webhost/oneagent_java/Jul_26_2024/apminsight_javaagent/site24x7/apminsight-javaagent.zip.sha256"
PYTHON_AGENT_DOWNLOAD_PATH="https://build.zohocorp.com/me/apm_insight_agent_python/webhost/ONE_AGENT/Jul_26_2024_2/apm_insight_agent_python_wheels.zip"
PYTHON_AGENT_CHECKSUM="https://build.zohocorp.com/me/apm_insight_agent_python/webhost/ONE_AGENT/Jul_26_2024_2/apm_insight_agent_python_wheels.zip.sha256"
DOTNETCORE_AGENT_DOWNLOAD_PATH="<Agent-Download-Path>" #Use actual Download path 
DOTNETCORE_AGENT_CHECKSUM="<Agent-Download-checksum>" #Use actual checksum download path
DATA_EXPORTER_SCRIPT_DOWNLOAD_PATH_EXTENSION="/apminsight/S247DataExporter/linux/InstallDataExporter.sh"
ONEAGENT_FILES_DOWNLOAD_PATH="https://build.zohocorp.com/me/apm_insight_one_agent/webhost/server_agent_integration/Jul_26_2024/apminsight_one_agent/Linux/site24x7/apm_insight_oneagent_linux_files.zip"
ONEAGENT_FILES_CHECKSUM="https://build.zohocorp.com/me/apm_insight_one_agent/webhost/server_agent_integration/Jul_26_2024/apminsight_one_agent/Linux/site24x7/apm_insight_oneagent_linux_files.zip.sha256"

AGENT_INSTALLATION_PATH="/opt/site24x7/apmoneagent"
PRELOAD_FILE_PATH="/etc/ld.so.preload"
AGENT_STARTUP_LOGFILE_PATH="s247OneagentInstallation.log"
STARTUP_CONF_FILEPATH="./apminsightconf.ini"

KUBERNETES_ENV=0
BUNDLED=0
APM_LICENSE_KEY=""
CURRENT_DIRECTORY=$(pwd)
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

RedirectLogs() {
    exec >"$AGENT_STARTUP_LOGFILE_PATH" 2>&1
}

Log() {
    echo $(date +"%F %T.%N") " $1\n"
}

CheckUser() {
    if [ "$(id -u)" -ne 0 ]; then
        Log "OneAgent installer script is run without root privilege. Please run the script s247OneagentInstaller.sh with root privilege"
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
        Log "Found apminsightcong.ini file. Started reading the file for Oneagent startup configurations"
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
                Log "Invalid argument: $1"
                exit 1
                ;;
        esac
    done
    if [ -z "$APM_LICENSE_KEY" ]; then
        Log "Unable to find License key from commandline arguments. Please run the s247OneagentInstaller.sh script again providing License key or set License Key in the configuration file located at $AGENT_INSTALLATION_PATH in the format LICENSEKEY=<Your License Key>"
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

SetupAgentConfigurations() {
    ReadConfigFromFile
    ReadConfigFromArgs "$@"
    BuildApmHostUrl
    SetProxy
    ReadDomain
}

#CREATE AGENT FOLDERS IN USER MACHINE AND STORE THE DOWNLOADED AGENT FILES 
CreateAgentFiles() {
    Log "DELETING EXISTING ONEAGENT FILES IF ANY"
    rm -r "$AGENT_INSTALLATION_PATH"
    Log "CREATING AGENT FILES"
    mkdir -p "$AGENT_INSTALLATION_PATH"
    mkdir "$AGENT_INSTALLATION_PATH/conf"
    mkdir "$AGENT_INSTALLATION_PATH/lib"
    mkdir "$AGENT_INSTALLATION_PATH/bin"
    mkdir "$AGENT_INSTALLATION_PATH/lib/NODEJS"
    mkdir "$AGENT_INSTALLATION_PATH/lib/JAVA"
    mkdir "$AGENT_INSTALLATION_PATH/lib/PYTHON"
    mkdir "$AGENT_INSTALLATION_PATH/lib/DOTNETCORE"
    mkdir "$AGENT_INSTALLATION_PATH/logs"
    mkdir "$AGENT_INSTALLATION_PATH/agents"
    mkdir "$AGENT_INSTALLATION_PATH/agents/JAVA"
    mkdir "$AGENT_INSTALLATION_PATH/agents/JAVA/logs"
    mkdir "$AGENT_INSTALLATION_PATH/agents/NODEJS/"
    mkdir "$AGENT_INSTALLATION_PATH/agents/NODEJS/logs"
    mkdir "$AGENT_INSTALLATION_PATH/agents/PYTHON"
    mkdir "$AGENT_INSTALLATION_PATH/agents/PYTHON/logs"
    mkdir "$AGENT_INSTALLATION_PATH/agents/DOTNETCORE"
    mkdir "$AGENT_INSTALLATION_PATH/agents/DOTNETCORE/logs"
    touch "$AGENT_INSTALLATION_PATH/logs/oneagentloader.log"
}

DownloadAgentFiles() {
    if [ "$KUBERNETES_ENV" -eq 1 ]; then
        return

    elif [ "$BUNDLED" -eq 0 ]; then
        Log "DOWNLOADING AGENT FILES"
        wget -nv "$NODE_MINIFIED_DOWNLOAD_PATH"
        ValidateChecksumAndInstallAgent "apm_insight_agent_nodejs.zip" "$NODE_AGENT_CHECKSUM" "$AGENT_INSTALLATION_PATH/lib/NODEJS"

        wget -nv "$JAVA_AGENT_DOWNLOAD_PATH"
        ValidateChecksumAndInstallAgent "apminsight-javaagent.zip" "$JAVA_AGENT_CHECKSUM" "$AGENT_INSTALLATION_PATH/lib/JAVA"

        wget -nv "$DOTNETCORE_AGENT_DOWNLOAD_PATH"
        ValidateChecksumAndInstallAgent "OneAgentDotNetCore.zip" "$DOTNETCORE_AGENT_CHECKSUM" "$AGENT_INSTALLATION_PATH/lib/DOTNETCORE"

        wget -nv "$PYTHON_AGENT_DOWNLOAD_PATH"
        ValidateChecksumAndInstallAgent "apm_insight_agent_python_wheels.zip" "$PYTHON_AGENT_CHECKSUM" "$AGENT_INSTALLATION_PATH/lib/PYTHON"

        wget -nv "$ONEAGENT_FILES_DOWNLOAD_PATH"
        ValidateChecksumAndInstallAgent "apm_insight_oneagent_linux_files.zip" "$ONEAGENT_FILES_CHECKSUM" "$AGENT_INSTALLATION_PATH/bin"
        return
    fi

    unzip "apm_insight_agent_nodejs.zip" -d "$AGENT_INSTALLATION_PATH/lib/NODEJS"
    unzip "apminsight-javaagent.zip" -d "$AGENT_INSTALLATION_PATH/lib/JAVA"
    unzip "apm_insight_oneagent_linux_files.zip" -d "$AGENT_INSTALLATION_PATH/bin"
    unzip "apm_insight_agent_python_wheels.zip" -d "$AGENT_INSTALLATION_PATH/lib/PYTHON"
    unzip "OneAgentDotNetCore.zip" -d "$AGENT_INSTALLATION_PATH/lib/DOTNETCORE"

    rm "apm_insight_agent_nodejs.zip"
    rm "apminsight-javaagent.zip"
    rm "apm_insight_oneagent_linux_files.zip"
    rm "apm_insight_agent_python_wheels.zip"
    rm "OneAgentDotNetCore.zip"
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
    rm "$file"
    rm "$checksumfilename"
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
    Log "INSTALLING APMINSIGHT PYTHON PACKAGE"
    PYTHON_FILE_PATH="$AGENT_INSTALLATION_PATH/lib/PYTHON/wheels"
    if [ "$KUBERNETES_ENV" -eq 1 ]; then
        PYTHON_FILE_PATH="$AGENT_INSTALLATION_PATH/wheels"
    fi
    pip uninstall --yes apminsight
    pip install --upgrade --no-index --find-links="$PYTHON_FILE_PATH" apminsight 2>/tmp/python_agent_installation_warnings.log
    PYTHON_AGENT_PATH="$(pip show apminsight | awk '/^Location:/ {print $2}')"

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
        wget -nv -O InstallDataExporter.sh "$DOWNLOAD_PATH"
        eval "sudo -E sh InstallDataExporter.sh "$EXPORTER_INSTALLATION_ARGUMENTS""
        rm InstallDataExporter.sh
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

#GIVE RESPECTIVE PERMISSIONS TO AGENT FILES
GiveFilePermissions() {
    Log "GIVING FILE PERMISSIONS"
    chmod 777 -R "$AGENT_INSTALLATION_PATH/bin"
    chmod 777 -R "$AGENT_INSTALLATION_PATH/lib/JAVA"
    chmod 777 -R "$AGENT_INSTALLATION_PATH/logs"
    chmod 777 -R "$AGENT_INSTALLATION_PATH/agents"
}

SetupApmAgents() {
    CreateAgentFiles
    DownloadAgentFiles
    InstallNodeJSDependencies
    InstallPythonDependencies
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

    if [ -n "$APM_LICENSE_KEY" ]; then
        AGENT_CONF_STR="$AGENT_CONF_STR""APM_LICENSE_KEY=$APM_LICENSE_KEY\n"
    fi
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
        AGENT_CONF_STR="$AGENT_CONF_STR""PYTHON_AGENT_PATH=$PYTHON_AGENT_PATH\n"
    fi

    AGENT_CONF_STR="$AGENT_CONF_STR""DOMAIN=$DOMAIN\n"

    conf_filepath="$AGENT_INSTALLATION_PATH/conf/apminsightconf.ini"
    echo "$AGENT_CONF_STR" > "$conf_filepath"
    if [ -f "$conf_filepath" ]; then
        Log "Successfully created the apminsightconf.json at $AGENT_INSTALLATION_PATH/conf"
    else
        Log "Error creating file apminsightconf.json at $AGENT_INSTALLATION_PATH/conf"
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

RemoveInstallationFile() {
    rm ./s247OneagentInstaller.sh
}

MoveInstallationLogFile() {
    mv "$AGENT_STARTUP_LOGFILE_PATH" "$AGENT_INSTALLATION_PATH/logs"
}

main() {
    RedirectLogs
    SetupPreInstallationChecks
    SetupAgentConfigurations "$@"
    SetupApmAgents
    LoadAgentForExistingJavaProcesses
    WriteToAgentConfFile
    SetPreload
    MoveInstallationLogFile
    RemoveInstallationFile
    }
main "$@"