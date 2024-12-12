#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include "slog.h"
#include "ini.h"

typedef struct
{
    char* proxyUrl;
    char* apmHostStr;
    char* apmPortStr;
    char* apmHostUrl;
    char* agentMonitorGroupStr;
    char* NewPythonPath;
    char* Preloader;
} configuration;

configuration config;

extern char *__progname;
char *logfilename = "oneagentloader";
bool is_kubernetes_env=false;
char *agent_installation_path = "/opt/site24x7/apmoneagent";
char oneagentconf_filepath[224];
bool configurationsCleared=false;

void check_kubernetes_environment() {
    if (getenv("KUBERNETES_SERVICE_HOST")!= NULL) {
        is_kubernetes_env = true;
    }
}

bool set_agent_installation_path() {
    FILE *file = fopen("/etc/environment", "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file\n");
        return false;
    }

    char line[212];

    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        if (strstr(line, "ONEAGENTPATH") != NULL) {
            sscanf(line, "ONEAGENTPATH=%199[^\n]", agent_installation_path);
        }
        else {
            strcpy(agent_installation_path , "/opt/site24x7/apmoneagent");
        }
        openlog("Oneagent", LOG_PID, LOG_USER);
        syslog(LOG_INFO, "Custom OneAgent installation path found to be %s", agent_installation_path);
        closelog();
    }
    fclose(file);
    return true;
}

void get_file_path(char *filepath_string, char *extension) {
    strcpy(filepath_string, agent_installation_path);
    strcat(filepath_string, extension);
}

bool get_node_options_val(char *node_options){
    char node_file_path[234];
    if (is_kubernetes_env==false) {
        get_file_path(node_file_path, "/lib/NODE/agent_minified/index.js");
    }
    else {
        get_file_path(node_file_path, "/agent_minified/index.js");
    }
    strcat(node_options, node_file_path);
    return access(node_file_path, F_OK) == 0;

}

bool get_java_tool_options_val(char *java_tool_options) {
    char java_agent_path[234];
    if (is_kubernetes_env==false) {
        get_file_path(java_agent_path, "/lib/JAVA/apminsight-javaagent.jar");
    }
    else {
        get_file_path(java_agent_path, "/apminsight-javaagent.jar");
    }
    strcat(java_tool_options, java_agent_path);
    return access(java_agent_path, F_OK) == 0;
}

void initialize_logger() {
    slog_config_t cfg;
    slog_init(logfilename, SLOG_FLAGS_ALL, 0);
    slog_config_get(&cfg);
    cfg.nToScreen = 0;
    cfg.nToFile = 1;
    cfg.eDateControl = SLOG_DATE_FULL;
    char logfolderpath[205];
    get_file_path(logfolderpath, "/logs");
    strcpy(cfg.sFilePath, logfolderpath);
    cfg.eColorFormat = SLOG_COLORING_DISABLE;
    slog_config_set(&cfg);
    
}

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    configuration* pconfig = (configuration*)user;

    #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
    if (MATCH("ApminsightOneAgent", "APMINSIGHT_PROXY_URL")) {
        pconfig->proxyUrl = strdup(value);
    } else if (MATCH("ApminsightOneAgent", "APMINSIGHT_HOST")) {
        pconfig->apmHostStr = strdup(value);
    } else if (MATCH("ApminsightOneAgent", "APMINSIGHT_PORT")) {
        pconfig->apmPortStr = strdup(value);
    } else if (MATCH("ApminsightOneAgent", "APMINSIGHT_HOST_URL")) {
        pconfig->apmHostUrl = strdup(value);
    } else if (MATCH("ApminsightOneAgent", "APMINSIGHT_MONITOR_GROUP")) {
        pconfig->agentMonitorGroupStr = strdup(value);
    } else if (MATCH("ApminsightOneAgent", "NEW_PYTHON_PATH")) {
        pconfig->NewPythonPath = strdup(value);
    } else if (MATCH("ApminsightOneAgent", "PRELOADER")) {
        pconfig->Preloader = strdup(value);
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}

void read_config(){
    config.proxyUrl=NULL;
    config.apmHostStr=NULL;
    config.apmPortStr=NULL;
    config.apmHostUrl=NULL;
    config.agentMonitorGroupStr=NULL;
    config.NewPythonPath=NULL;
    config.Preloader=NULL;
    get_file_path(oneagentconf_filepath, "/conf/oneagentconf.ini");
    if (ini_parse(oneagentconf_filepath, handler, &config) < 0) {
            slog_error("Cannot load the config file %s", oneagentconf_filepath);
        }
    slog_info("Successfully read the configuration from oneagentconf.ini file");
}

void set_env(char *key, char *val, char *process_type, int pid){
    if (val!=NULL){
        if (setenv(key, val, 1) != 0){
            slog_error("Error setting %s env into the %s process with pid: %d", key, process_type, pid);
        }
        slog_info("Succesfully set %s to the %s process %d", key, process_type, pid);
    }   
}

void free_config(){
    if (configurationsCleared==true)
        return;
    if (config.proxyUrl)
        free((void*)config.proxyUrl);
    if (config.apmHostStr)
        free((void*)config.apmHostStr);
    if (config.apmPortStr)
        free((void*)config.apmPortStr);
    if (config.apmHostUrl)
        free((void*)config.apmHostUrl);
    if (config.agentMonitorGroupStr)
        free((void*)config.agentMonitorGroupStr);
    if (config.NewPythonPath)
        free((void*)config.NewPythonPath);
    if (config.Preloader)
        free((void*)config.Preloader);
    configurationsCleared=true;
}

void pass_apminsight_configurations(char *process_type, int pid){
    set_env("APMINSIGHT_PROXY_URL", config.proxyUrl, process_type, pid);
    set_env("APMINSIGHT_HOST", config.apmHostStr, process_type, pid);
    set_env("APMINSIGHT_PORT", config.apmPortStr, process_type, pid);
    char agent_home_path[215];
    char path_extension[20]="/agents/";
    strcat(path_extension, process_type);
    get_file_path(agent_home_path, path_extension);
    set_env("APMINSIGHT_AGENT_HOMEPATH", agent_home_path, process_type, pid);
    set_env("APMINSIGHT_MONITOR_GROUP", config.agentMonitorGroupStr, process_type, pid);
    set_env("APMINSIGHT_ONEAGENT_CONF_FILEPATH", oneagentconf_filepath, process_type, pid);
    free_config();
}

int __attribute__((constructor)) my_constructor(int argc, char *argv[]) {
    check_kubernetes_environment();
    size_t total_length = 0;
    int i;
    for (i = 0; i < argc; i++) {
        total_length += strlen(argv[i]) + 1;
    }
    char *cmdline = malloc(total_length);
    if (cmdline == NULL) {
        perror("malloc");
        return 0;
    }
    cmdline[0] = '\0';
    for (i = 0; i < argc; i++) {
        strcat(cmdline, argv[i]);
        if (i < argc - 1) {
            strcat(cmdline, " ");
        }
    }
    if (strcmp(__progname, "node")==0 && argc > 1 && strcmp(argv[0], "node" ) == 0 && access("package.json", F_OK) == 0) {
        pid_t pid;
        pid = getpid();
        /*set_agent_installation_path();*/
        initialize_logger();
        read_config();
        if (strcmp(config.Preloader,"UNSET")==0) {
            slog_info("PRELOADER UNSET");
            return 0;
        }
        slog_info("NODE process detected with pid: %d", pid);

        char node_options[237] = "-r ";
        if (get_node_options_val(node_options)==false) {
            slog_warn("Agent minified file is missing, Ignoring the NODE process with pid: %d", pid);
            return 0;
        }
        set_env("NODE_OPTIONS", node_options, "NODE", pid);
        pass_apminsight_configurations("NODE", pid);
    }

    else if (strstr(__progname, "java")!=NULL) {
        if ((cmdline!=NULL) && strstr(cmdline, "jboss.home.dir")!=NULL || strstr(cmdline, "jboss.home")!=NULL || strstr(cmdline, "com.sun.aas.installRoot")!=NULL || strstr(cmdline, "jetty.home")!=NULL || strstr(cmdline, "weblogic.home")!=NULL || strstr(cmdline, "jboss.home.dir")!=NULL || strstr(cmdline, "wlp.install.dir")!=NULL || strstr(cmdline, "resin.home")!=NULL || strstr(cmdline, "catalina.home")!=NULL || strstr(cmdline, "java -jar ")!=NULL){
            pid_t pid;
            pid = getpid();
            /*set_agent_installation_path();*/
            initialize_logger();
            read_config();
            if (strcmp(config.Preloader,"UNSET")==0) {
                slog_info("PRELOADER UNSET");
                return 0;
            }
            slog_info("JAVA process detected with pid: %d", pid);
            if (strstr(cmdline, "apminsight-javaagent.jar")!=0){
                slog_info("Apminsight Java agent argument already found in commandline, Exiting without loading the agent");
            }
            char java_tool_options[245] = "-javaagent:";
            if (get_java_tool_options_val(java_tool_options)==false){
                slog_warn("Agent jarfile file is missing, Ignoring the JAVA process with pid: %d", pid);
                free(cmdline);
                return 0;
            }

            set_env("JAVA_TOOL_OPTIONS", java_tool_options, "JAVA", pid);
            pass_apminsight_configurations("JAVA", pid);
        }
        free(cmdline);
        return 0;
        
    }

    else if ((cmdline!=NULL) && strstr(cmdline, "python ")!=NULL || strstr(cmdline, "python3 ")!=NULL || strstr(cmdline, "gunicorn ")!=NULL || strstr(cmdline, "uvicorn ")!=NULL || strstr(cmdline, "uwsgi ")!=NULL || strstr(cmdline, "daphne ")!=NULL || strstr(cmdline, "hypercorn ")!=NULL || strstr(cmdline, "waitress-serve ")!=NULL || strstr(cmdline, "mod_wsgi-express ")!=NULL || strstr(cmdline, "flask ")!=NULL){
        pid_t pid;
        pid = getpid();
        /*set_agent_installation_path();*/
        initialize_logger();
        slog_info("PYTHON3 process detected with pid: %d", pid);

        read_config();
        if (strcmp(config.Preloader,"UNSET")==0) {
            slog_info("PRELOADER UNSET");
            return 0;
        }
        if (config.NewPythonPath==NULL) {
            slog_info("No python path found in configuration file");
            free_config();
            return 0;
        }
        char *PYTHON_PATH_NEW=strdup(config.NewPythonPath);
        char *PYTHON_PATH_EXISTING = getenv("PYTHONPATH");
        if ( PYTHON_PATH_EXISTING!=NULL ) {
            if (strstr(PYTHON_PATH_EXISTING, "apminsight")==0){
                slog_info("Found Apminsight path already added to PYTHONPATH, Exiting without agent loading the agent");
                goto EndPythonPreload;
            }
            slog_info("Modifying existing PYTHONPATH environment variable");
            PYTHON_PATH_NEW = realloc(PYTHON_PATH_NEW, strlen(PYTHON_PATH_NEW) + strlen(PYTHON_PATH_EXISTING) + 1);
            strcat(PYTHON_PATH_NEW, PYTHON_PATH_EXISTING);
        }
        set_env("PYTHONPATH", PYTHON_PATH_NEW, "PYTHON", pid);
        set_env("APMINSIGHT_MONITOR_GROUP", config.agentMonitorGroupStr, "PYTHON", pid);
        set_env("APMINSIGHT_ONEAGENT_CONF_FILEPATH", oneagentconf_filepath, "PYTHON", pid);
        char agent_home_path[215];
        get_file_path(agent_home_path, "/agents/PYTHON");
        if (setenv("APMINSIGHT_AGENT_HOMEPATH", agent_home_path, 1) != 0) {
            slog_error("Error setting APMINSIGHT_AGENT_HOMEPATH env into the PYTHON process with pid: %d", pid);
        }
        slog_info("Succesfully set APMINSIGHT_AGENT_HOMEPATH to the PYTHON process %d", pid);
        goto EndPythonPreload;
        EndPythonPreload:
            free(PYTHON_PATH_NEW);
            free_config();
        free_config();
    }

    else if (strcmp(__progname, "dotnet")==0 || getenv("ASPNETCORE_ENVIRONMENT")!=NULL || getenv("ASPNETCORE_URLS")!=NULL || access("appsettings.json", F_OK) == 0) {
        pid_t pid;
        pid = getpid();
        /*set_agent_installation_path();*/
        initialize_logger();
        read_config();
        if (strcmp(config.Preloader,"UNSET")==0) {
            slog_info("PRELOADER UNSET");
            return 0;
        }
        slog_info("DOTNETCORE process detected with pid: %d", pid);
        char dotnetcore_clr_path[215];
        get_file_path(dotnetcore_clr_path, "/agents/DOTNETCORE/ApmInsightDotNetCoreAgent");
        set_env("DOTNETCOREAGENT_HOME", dotnetcore_clr_path, "DOTNETCORE", pid);
        set_env("CORECLR_ENABLE_PROFILING", "1", "DOTNETCORE", pid);
        set_env("MANAGEENGINE_COMMUNICATION_MODE", "direct", "DOTNETCORE", pid);
        set_env("PAL_OUTPUTDEBUGSTRING", "1", "DOTNETCORE", pid);
        set_env("CORECLR_PROFILER", "{9D363A5F-ED5F-4AAC-B456-75AFFA6AA0C8}", "DOTNETCORE", pid);
        char coreprofilerpath_64[245];
        get_file_path(coreprofilerpath_64, "/lib/DOTNETCORE/ApmInsightDotNetCoreAgent/x64/libClrProfilerAgent.so");
        set_env("CORECLR_PROFILER_PATH_64", coreprofilerpath_64, "DOTNETCORE", pid);
        char coreprofilerpath_86[245];
        get_file_path(coreprofilerpath_86, "/lib/DOTNETCORE/ApmInsightDotNetCoreAgent/x86/libClrProfilerAgent.so");
        set_env("CORECLR_PROFILER_PATH_32", coreprofilerpath_86, "DOTNETCORE", pid);
        char dotnet_startup_hooks[245];
        get_file_path(dotnet_startup_hooks, "/lib/DOTNETCORE/ApmInsightDotNetCoreAgent//netstandard2.0/DotNetAgent.Loader.dll");
        set_env("DOTNET_STARTUP_HOOKS", dotnet_startup_hooks, "DOTNETCORE", pid);
        pass_apminsight_configurations("DOTNETCORE", pid);
    }
    return 0;
}