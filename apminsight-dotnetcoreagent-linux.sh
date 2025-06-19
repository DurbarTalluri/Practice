#!/bin/bash

# Define variables
Destination=""
InstallType="global"
LicenseKey=""
AppName=""
ForceUpdate=false
Help=false
IgnoreFolderPermission=false
IsBehindProxy=false
ProxyHost=""
ProxyPort=0
ProxyUser=""
ProxyPassword=""
DisableAppFilter=false
AutoProfilerInstall=false
AutoProfilerHomePath=""
OfflineInstall=false
EncryptedString=""
InitVector=""
SaltKey=""


AgentVersion="6.8.0"

agentZipGLibcUrl="https://raw.githubusercontent.com/DurbarTalluri/Practice/main/apminsight-dotnetcoreagent-linux.zip"
agentZipMuslUrl="https://staticdownloads.site24x7.com/apminsight/agents/dotnet/linux/musl/apminsight-dotnetcoreagent-linux.zip"
checksumGLibcUrl="https://raw.githubusercontent.com/DurbarTalluri/Practice/main/apminsight-dotnetcoreagent-linux.zip.sha256"
checksumMuslUrl="https://staticdownloads.site24x7.com/apminsight/agents/dotnet/linux/musl/apminsight-dotnetcoreagent-linux.zip.sha256"
agentZipName="apminsight-dotnetcoreagent-linux.zip"

IsUpdateFound=false

function InstallAgent() {
    
        agentPath="$Destination/ApmInsightDotNetCoreAgent"
        PSScriptRoot=$(dirname "$(realpath "$0")")

        if [ "$OfflineInstall" = true ]; then
            if [ ! -d "$PSScriptRoot/Agent" ]; then
                Print "The Script is an Online Installer; remove the '-OfflineInstall' flag and try again."
                exit 1
            fi
        else
            DownloadAndExtractAgent
        fi

        if [ -f "$agentPath/version.info" ]; then
            installedAgentVersionString=$(cat "$agentPath/version.info")
            currentVersionNumber=${installedAgentVersionString//./}
            newVersionNumber=${AgentVersion//./}
            
            if [ "$currentVersionNumber" -lt "$newVersionNumber" ]; then
                IsUpdateFound=true
                userInput="Y"
                if [ "$ForceUpdate" = false ]; then
                    read -p "APM Insight .NET core agent is already installed in the given location. Currently installed agent version is $installedAgentVersionString. Do you want to upgrade to $AgentVersion [Y/N]?" userInput
                fi
                
                if [[ "$userInput" =~ ^[Nn]$ ]]; then
                    Print "Setting the agent environment with the existing version $installedAgentVersionString."
                    SetEnvironmentVariables "$agentPath"
                elif [[ "$userInput" =~ ^[Yy]$ ]]; then
                    Print "Upgrading the agent to the version $AgentVersion."
                    CopyFiles "$agentPath"
				    rm -rf dotnet_core_linux
                else
                    Print "Enter valid input."
                fi
                Print "The APM Insight .NET Core agent version $AgentVersion is set up successfully."
            elif [ "$currentVersionNumber" -eq "$newVersionNumber" ]; then
                Print "Same version of agent is found. Setting the agent environment for the version $installedAgentVersionString."
                SetEnvironmentVariables "$agentPath"
                Print "The APM Insight .NET Core agent version $AgentVersion is set up successfully."
            else
                Print "Higher version of agent is found. Upgrade will not be proceeded."
            fi
        else
            Print "Setting up the APM Insight .NET Core agent version $AgentVersion."
            CopyFiles "$agentPath"
	    exit 0
            if [ "$OfflineInstall" = false ]; then
                rm -rf dotnet_core_linux
            fi
            Print "The APM Insight .NET Core agent version $AgentVersion is set up successfully."
            Print "Kindly do the below steps to finish the configuration: "
            Print "1)Run 'source /etc/environment' \n2)Start your .NET Application \n3)To customize your Monitor name , refer: https://www.site24x7.com/help/apm/dotnet-agent/install-dot-net-core-agent.html \n"
            Print "If your application is Self-Contained, please refer to: https://www.site24x7.com/help/apm/dotnet-agent/agent-loader-api.html"
            Print "To Uninstall the Agent, run $agentPath/UninstallAgent.sh ."
        fi
}

function DownloadAndExtractAgent() {
    # Determine the system's libc implementation and set URLs
    if ldd --version 2>&1 | grep -q 'GLIBC'; then
        echo "System uses glibc"
        agentUrl="$agentZipGLibcUrl"
        checksumUrl="$checksumGLibcUrl"
    else
        echo "System uses musl"
        agentUrl="$agentZipMuslUrl"
        checksumUrl="$checksumMuslUrl"
    fi

    # Download the agent zip file
    Print "Downloading the agent zip file..."
    wget -O "$agentZipName" "$agentUrl"

    if [ $? -ne 0 ]; then
        echo "Failed to download the agent zip file"
        exit 1
    fi

    # Download the checksum file
    Print "Downloading the checksum file..."
    wget -O "checksum.txt" "$checksumUrl"

    if [ $? -ne 0 ]; then
        echo "Failed to download the checksum file"
        rm "$agentZipName"
        exit 1
    fi

    # Verify the checksum
    actualChecksum=$(sha256sum "$agentZipName" | awk '{print tolower(substr($1, 1, 64))}')
    expectedChecksum=$(cat checksum.txt | tr '[:upper:]' '[:lower:]' | cut -c 1-64)

    if [ "$actualChecksum" != "$expectedChecksum" ]; then
        echo "Checksum verification failed! Expected $expectedChecksum but got $actualChecksum"
        rm "checksum.txt"
        exit 1
    else 
        echo "Checksum verification successful.."
    fi

    # Extract the agent zip file
    Print "Extracting the agent zip file..."
    unzip "$agentZipName"

    if [ $? -ne 0 ]; then
        echo "Failed to extract the agent zip file"
        rm "$agentZipName"
        exit 1
    fi

    # Clean up the downloaded files
    rm "$agentZipName" "checksum.txt"
}

function Print() {
    echo -e "\n$1"
}

function CopyFiles() {
    agentPath=$1
    mkdir -p "$agentPath"

    if [ "$IsUpdateFound" = false ] && [ "$IgnoreFolderPermission" = false ]; then
        SetFolderPermissions "$agentPath"
    fi

    resolvedPath=$(realpath "$agentPath")

	# Rename existing .dll files
	if [ -d "$resolvedPath/netstandard2.0" ]; then
		find "$resolvedPath/netstandard2.0" -name "*.dll" -exec sh -c 'mv "$0" "${0%.dll}_old.dll"' {} \;
	fi
	if [ -d "$resolvedPath/x64" ]; then
		find "$resolvedPath/x64" -name "*.so" -exec sh -c 'mv "$0" "${0%.so}_old.so"' {} \;
	fi
	if [ -d "$resolvedPath/x86" ]; then
		find "$resolvedPath/x86" -name "*.so" -exec sh -c 'mv "$0" "${0%.so}_old.so"' {} \;
	fi

    CopyAgentFiles "$resolvedPath"

    if [ "$IsUpdateFound" = false ] && [ "$AutoProfilerInstall" = false ]; then
        SetEnvironmentVariables "$resolvedPath"
        ModifyConfiguration "$resolvedPath"
    elif [ "$AutoProfilerInstall" = true ]; then
        ModifyConfiguration "$AutoProfilerHomePath/ApmInsightDotNetCoreAgent"
    fi

    find "$resolvedPath/netstandard2.0" -type f -exec chmod +x {} \;

    if [ "$AutoProfilerInstall" = false ]; then
        # Set write access for everyone in the <InstallLocation>/ApmInsightDotNetCoreAgent/DotNetCoreAgent directory
        dotNetAgentPath="$installPath/DotNetCoreAgent"
        if [ -d "$dotNetAgentPath" ]; then
            sudo chmod -R 777 "$dotNetAgentPath"
        fi
    fi

    CreateVersionInfoFile "$resolvedPath"
}

function CopyAgentFiles() {
    resolvedPath=$1
    PSScriptRoot=$(dirname "$(realpath "$0")")

    if [ "$OfflineInstall" = false ]; then
        PSScriptRoot="$PSScriptRoot/dotnet_core_linux"
    fi

    if [ "$AutoProfilerInstall" = true ]; then
        mkdir -p "$AutoProfilerHomePath/ApmInsightDotNetCoreAgent"
        cp -r "$PSScriptRoot/Agent/DotNetCoreAgent" "$AutoProfilerHomePath/ApmInsightDotNetCoreAgent"
    elif [ "$IsUpdateFound" = false ]; then
        cp -r "$PSScriptRoot/Agent/DotNetCoreAgent" "$resolvedPath"
    fi

    cp "$PSScriptRoot/UninstallAgent.sh" "$resolvedPath"

    cp -r "$PSScriptRoot/Agent/packages/x64" "$resolvedPath"
    cp -r "$PSScriptRoot/Agent/packages/x86" "$resolvedPath"

    mkdir -p "$resolvedPath/netstandard2.0"
    cp -r "$PSScriptRoot/Agent/packages/AnyCPU/." "$resolvedPath/netstandard2.0"
    
}

function ModifyConfiguration() {

    if [ -n "$LicenseKey" ]; then
        local encrypt_output
        encrypt_output=$(encrypt_aes "$LicenseKey")

        # Read the encrypted string, salt key, and initialization vector using a pipe delimiter
        IFS='|' read -r EncryptedString SaltKey InitVector <<< "$encrypt_output"
    fi

    agentPath=$1
    filePath="$agentPath/DotNetCoreAgent/apminsight.conf"
    if [ -f "$filePath" ]; then
        sed -i "s|license.key=.*|license.key=$EncryptedString|" "$filePath"
        sed -i "s|agent_start_time=.*|agent_start_time=$SaltKey|" "$filePath"
        sed -i "s|agent_id=.*|agent_id=$InitVector|" "$filePath"
        if [ "$IsBehindProxy" = true ]; then
            sed -i "s/behind.proxy=false/behind.proxy=true/" "$filePath"
            sed -i "s/proxy.server.host=proxyserver/proxy.server.host=$ProxyHost/" "$filePath"
            sed -i "s/proxy.server.port=proxyport/proxy.server.port=$ProxyPort/" "$filePath"
            sed -i "s/proxy.auth.username=proxyuser/proxy.auth.username=$ProxyUser/" "$filePath"
            sed -i "s/proxy.auth.password=proxypassword/proxy.auth.password=$ProxyPassword/" "$filePath"
        fi
        if [ "$DisableAppFilter" = true ]; then
            DisableAppFilterInConfig "$filePath"
        fi
    fi
}

function DisableAppFilterInConfig() {
    agentConfigFilePath=$1
    keyValueToFind="enable.appfilter="
    keyValueToAddOrReplace="enable.appfilter=false"
    fileContent=$(cat "$agentConfigFilePath")

    if grep -q "$keyValueToFind" "$agentConfigFilePath"; then
        sed -i "s/$keyValueToFind.*/$keyValueToAddOrReplace/" "$agentConfigFilePath"
    else
        echo "$keyValueToAddOrReplace" >> "$agentConfigFilePath"
    fi
}

function SetEnvironmentVariables() {
    installPath=$1
    if [ "$InstallType" == "global" ]; then
        SetLocalEnvironment "$installPath"
        SetGlobalEnvironment "$installPath"
    else
        SetLocalEnvironment "$installPath"
    fi
}

function SetLocalEnvironment() {
    installPath=$1

    export CORECLR_ENABLE_PROFILING=1
    export CORECLR_PROFILER={9D363A5F-ED5F-4AAC-B456-75AFFA6AA0C8}
    export DOTNETCOREAGENT_HOME=$installPath
    export CORECLR_PROFILER_PATH_64="$installPath/x64/libClrProfilerAgent.so"
    export CORECLR_PROFILER_PATH_32="$installPath/x86/libClrProfilerAgent.so"
    export DOTNET_STARTUP_HOOKS="$installPath/netstandard2.0/DotNetAgent.Loader.dll"
    export S247_LICENSE_KEY=$LicenseKey
    export MANAGEENGINE_COMMUNICATION_MODE="direct"
    if [ "$DisableAppFilter" = true ] && [ -n "$AppName" ]; then
        export SITE24X7_APP_NAME=$AppName
    fi
}

function SetGlobalEnvironment() {
    installPath=$1
    
    echo "CORECLR_ENABLE_PROFILING=1" | sudo tee -a /etc/environment
    echo "CORECLR_PROFILER={9D363A5F-ED5F-4AAC-B456-75AFFA6AA0C8}" | sudo tee -a /etc/environment
    echo "DOTNETCOREAGENT_HOME=$installPath" | sudo tee -a /etc/environment
    echo "CORECLR_PROFILER_PATH_64=$installPath/x64/libClrProfilerAgent.so" | sudo tee -a /etc/environment
    echo "CORECLR_PROFILER_PATH_32=$installPath/x86/libClrProfilerAgent.so" | sudo tee -a /etc/environment
    echo "DOTNET_STARTUP_HOOKS=$installPath/netstandard2.0/DotNetAgent.Loader.dll" | sudo tee -a /etc/environment
    echo "S247_LICENSE_KEY=$LicenseKey" | sudo tee -a /etc/environment
    echo "MANAGEENGINE_COMMUNICATION_MODE=direct" | sudo tee -a /etc/environment
    if [ "$DisableAppFilter" = true ] && [ -n "$AppName" ]; then
        echo "SITE24X7_APP_NAME=$AppName" | sudo tee -a /etc/environment
    fi
}

function IsAdmin() {
    if [ "$EUID" -ne 0 ]; then
        echo false
    else
        echo true
    fi
}

function ValidateParameters() {
    InstallType=$(echo "$InstallType" | tr '[:upper:]' '[:lower:]' | xargs)
    Destination=$(echo "$Destination" | xargs)
    LicenseKey=$(echo "$LicenseKey" | xargs)
    AppName=$(echo "$AppName" | xargs)

    flag=false
    
    if [ -z "$Destination" ]; then
        Print " * Please provide -Destination parameter."
        flag=true
    fi
    if [ "$AutoProfilerInstall" = false ]; then
        if [ -z "$LicenseKey" ]; then
            Print " * Please provide -LicenseKey parameter."
            flag=true
        fi
    fi
    if [ "$IsBehindProxy" = true ]; then
        if [ -z "$ProxyHost" ]; then
            Print " * Please provide -ProxyHost parameter."
            flag=true
        fi
        if [ "$ProxyPort" -eq 0 ]; then
            Print " * Please provide -ProxyPort parameter and the value should not be zero."
            flag=true
        fi
    fi
    if [ "$AutoProfilerInstall" = true ]; then
        if [ -z "$AutoProfilerHomePath" ]; then
            Print " * Please provide -AutoProfilerHomePath parameter."
            flag=true
        fi
    fi
    
    if [ "$flag" = true ]; then
        exit 1
    fi
}

function CreateVersionInfoFile() {
    agentPath=$1
    echo "$AgentVersion" > "$agentPath/version.info"
}

function CheckAdminRights() {
    	Print "Checking Admin Rights"
	if [ "$(IsAdmin)" = false ] && [ "$InstallType" = "global" ]; then
        	Print "You must have administrator rights to install the agent globally. Please run this script with sudo."
        	exit 1
    	fi
    
}

function SetFolderPermissions() {
    directory=$1
    
    # Set default permissions for the entire installation location
    sudo chown -R $USER:$USER "$directory"
    sudo chmod -R 755 "$directory"
}

function generate_random_salt_key() {
    local size=${1:-32}
    # Generate a random alphanumeric string of the given size (32 characters for AES-256 key)
    head /dev/urandom | tr -dc a-z0-9 | head -c $size
}

function generate_random_iv() {
    local size=${1:-16}
    # Generate a random alphanumeric string of the given size (16 characters for AES CBC IV)
    head /dev/urandom | tr -dc a-z0-9 | head -c $size
}

function encrypt_aes() {
    local originalStr="$1"

    if [ -z "$originalStr" ]; then
        echo "No String For Encryption" >&2
        return 1
    fi

    # Generate a random alphanumeric key and IV
    SaltKey=$(generate_random_salt_key 32)
    InitVector=$(generate_random_iv 16)

    # Convert alphanumeric key and IV to hexadecimal
    SaltKeyHex=$(echo -n "$SaltKey" | xxd -p | tr -d '\n')
    InitVectorHex=$(echo -n "$InitVector" | xxd -p | tr -d '\n')

    # Encrypt the string using openssl with AES-256-CBC and Base64 encoding
    local EncryptedString=$(echo -n "$originalStr" | openssl enc -aes-256-cbc -base64 -K "$SaltKeyHex" -iv "$InitVectorHex" -md md5 -nosalt 2>/dev/null)

    if [ -z "$EncryptedString" ]; then
        echo "Encryption failed" >&2
        return 1
    fi

    # Return the result in the format: EncryptedString|Key|IV
    echo "$EncryptedString|$SaltKey|$InitVector"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -Destination)
            Destination="$2"
            shift 2
            ;;
        -InstallType)
            InstallType="$2"
            shift 2
            ;;
        -LicenseKey)
            LicenseKey="$2"
            shift 2
            ;;
        -AppName)
            AppName="$2"
            shift 2
            ;;
        -ForceUpdate)
            ForceUpdate=true
            shift 1
            ;;
        -Help)
            Help=true
            shift 1
            ;;
        -IgnoreFolderPermission)
            IgnoreFolderPermission=true
            shift 1
            ;;
        -IsBehindProxy)
            IsBehindProxy=true
            shift 1
            ;;
        -ProxyHost)
            ProxyHost="$2"
            shift 2
            ;;
        -ProxyPort)
            ProxyPort="$2"
            shift 2
            ;;
        -ProxyUser)
            ProxyUser="$2"
            shift 2
            ;;
        -ProxyPassword)
            ProxyPassword="$2"
            shift 2
            ;;
        -DisableAppFilter)
            DisableAppFilter=true
            shift 1
            ;;
        -AutoProfilerInstall)
            AutoProfilerInstall=true
            shift 1
            ;;
        -AutoProfilerHomePath)
            AutoProfilerHomePath="$2"
            shift 2
            ;;
        -OfflineInstall)
            OfflineInstall=true
            shift 1
            ;;
        *)
            echo "Unknown parameter: $1"
            exit 1
            ;;
    esac
done


ValidateParameters
CheckAdminRights
InstallAgent
