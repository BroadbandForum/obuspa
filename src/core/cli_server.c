/*
 *
 * Copyright (C) 2019-2025, Broadband Forum
 * Copyright (C) 2024-2025, Vantiva Technologies SAS
 * Copyright (C) 2016-2024  CommScope, Inc
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * \file cli_server.c
 *
 * Implements a command line interface server
 * Both client and server are USP Agent executables, but the server is running the USP Agent core application,
 * whilst the client is effectively just calling the server to implement the command and return the result to the client.
 * Communication between the client and server is via UNIX domain sockets (hence CLI cannot be run remotely)
 * NOTE: Some commands (eg dbset) are run locally and do not follow the above
 */

#include <stdio.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sqlite3.h>
#include <zlib.h>


#ifdef ENABLE_WEBSOCKETS
#include <libwebsockets.h>
#endif

#ifdef ENABLE_MQTT
#include <mosquitto.h>
#endif

#include "common_defs.h"
#include "cli.h"
#include "data_model.h"
#include "device.h"
#include "database.h"
#include "path_resolver.h"
#include "dm_trans.h"
#include "expr_vector.h"
#include "text_utils.h"
#include "version.h"
#include "stomp.h"
#include "group_get_vector.h"
#include "bdc_exec.h"

#ifndef REMOVE_USP_SERVICE
#include "usp_service.h"
#ifdef ENABLE_UDS
#include "uds.h"
#endif
#endif

#ifndef REMOVE_USP_BROKER
#include "usp_broker.h"
#endif

#ifndef REMOVE_DEVICE_BULKDATA
#include <curl/curl.h>
#endif
//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
void CloseCliServerSock(void);
void SendCliResponse_InvalidValue(str_vector_t *args);
int ExecuteCli_Help(str_vector_t *args);
int ExecuteCli_Version(str_vector_t *args);
int ExecuteCli_Get(str_vector_t *args);
int ExecuteCli_Set(str_vector_t *args);
int ExecuteCli_Add(str_vector_t *args);
int ExecuteCli_Del(str_vector_t *args);
int ExecuteCli_Operate(str_vector_t *args);
int ExecuteCli_Event(str_vector_t *args);
int ExecuteCli_GetInstances(str_vector_t *args);
int ExecuteCli_Show(str_vector_t *args);
int ExecuteCli_Dump(str_vector_t *args);
int ExecuteCli_Role(str_vector_t *args);
int ExecuteCli_Perm(str_vector_t *args);
int ExecuteCli_PermSel(str_vector_t *args);
int ExecuteCli_DbGet(str_vector_t *args);
int ExecuteCli_DbSet(str_vector_t *args);
int ExecuteCli_DbDel(str_vector_t *args);
int ExecuteCli_Verbose(str_vector_t *args);
int ExecuteCli_ProtoTrace(str_vector_t *args);
int ExecuteCli_Stop(str_vector_t *args);
char *SplitOffTrailingNumber(char *s);
int SplitSetExpression(char *expr, char *search_path, int search_path_len, char *param_name, int param_name_len);
void SendCliResponse(char *fmt, ...);
combined_role_t *CalcCliCombinedRole(void);

#ifndef REMOVE_USP_SERVICE
int ExecuteCli_Register(str_vector_t *args);
int ExecuteCli_DeRegister(str_vector_t *args);
#endif

//------------------------------------------------------------------------------
// Socket listening for CLI connections
static int cli_listen_sock = INVALID;

//------------------------------------------------------------------------------
// Socket used to receive CLI command on and respond back with data
static int cli_server_sock = INVALID;

//------------------------------------------------------------------------------
// Buffer used to build up the command to process
static char cmd_buf[MAX_CLI_CMD_LEN];
static int cmd_buf_len = 0;

//------------------------------------------------------------------------------
// Variable used to redirect dump logging back to the CLI client
bool dump_to_cli = false;

//------------------------------------------------------------------------------
// Array containing mapping of CLI commands to processing functions
#define RUN_LOCALLY     true
#define RUN_REMOTELY    false

typedef struct
{
    char *name;
    int min_args;       // bash does not allow the passing of empty string args, so to allow eg SPV to an empty string, min_args allows the missing value arg, and the handler fills in the missing arg as an empty string
    int max_args;
    bool run_locally;
    int (*exec_cmd)(str_vector_t *args);
    char *usage;
} cli_cmd_t;

cli_cmd_t cli_commands[] =
{
//    Name    MinArgs,MaxArgs  RunLocal?  Exec callback     Usage String
    { "help",      0,0, RUN_LOCALLY,  ExecuteCli_Help,  "help" },
    { "version",   0,0, RUN_LOCALLY,  ExecuteCli_Version, "version" },
    { "get",       1,1, RUN_REMOTELY, ExecuteCli_Get,   "get [path-expr]" },
    { "set",       1,2, RUN_REMOTELY, ExecuteCli_Set,   "set [path-expr] [value]"},
    { "add",       1,1, RUN_REMOTELY, ExecuteCli_Add,   "add [object]"},
    { "del",       1,1, RUN_REMOTELY, ExecuteCli_Del,   "del [path-expr]"},
    { "operate",   1,1, RUN_REMOTELY, ExecuteCli_Operate,"operate [operation]"},
    { "event",     1,1, RUN_REMOTELY, ExecuteCli_Event, "event [event]"},
    { "instances", 1,1, RUN_REMOTELY, ExecuteCli_GetInstances,   "instances [path-expr]" },
    { "show",      1,1, RUN_LOCALLY,  ExecuteCli_Show,  "show [ 'database' ]"},
    { "dump",      1,1, RUN_REMOTELY, ExecuteCli_Dump,  "dump ['instances' | 'datamodel' | 'memory' | 'mdelta' | 'subscriptions' ]"},
    { "role",      1,1, RUN_REMOTELY, ExecuteCli_Role,  "role [instance]"},
    { "perm",      1,1, RUN_REMOTELY, ExecuteCli_Perm,  "perm [path]"},
    { "permsel",   1,2, RUN_REMOTELY, ExecuteCli_PermSel,  "permsel [role] [path]"},
    { "dbget",     1,1, RUN_LOCALLY,  ExecuteCli_DbGet, "dbget [parameter]"},
    { "dbset",     1,2, RUN_LOCALLY,  ExecuteCli_DbSet, "dbset [parameter] [value]"},
    { "dbdel",     1,1, RUN_LOCALLY,  ExecuteCli_DbDel, "dbdel [parameter]"},
    { "verbose",   1,1, RUN_REMOTELY, ExecuteCli_Verbose, "verbose [level]"},
    { "prototrace",1,1, RUN_REMOTELY, ExecuteCli_ProtoTrace, "prototrace [enable]"},
#ifndef REMOVE_USP_SERVICE
    { "register",  1,1, RUN_REMOTELY, ExecuteCli_Register,  "register [paths]"},
    { "deregister",0,1, RUN_REMOTELY, ExecuteCli_DeRegister,  "deregister [paths]"},
#endif
#ifndef REMOVE_USP_BROKER
    { "service",   3,4, RUN_REMOTELY, USP_BROKER_ExecuteCli_Service,  "service [endpoint] [command] [path-expr] [optional: value or notify type]"},
#endif
    { "stop",    0,0, RUN_REMOTELY, ExecuteCli_Stop, "stop"},
};

//------------------------------------------------------------------------------
// Saved role to use for the CLI commands
int cli_role_instance = 0;     // 0 denotes INTERNAL_ROLE. Other numbers denote instance number in Device.LocalAgent.ControllerTrust.Role.{i}

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
cli_cmd_t *FindCliCommand(char *command);

/*********************************************************************//**
**
** CLI_SERVER_Init
**
** Initialises the CLI server. Starts a Unix domain socket listening for connections
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int CLI_SERVER_Init(void)
{
    int sock;
    int err;
    struct sockaddr_un sa;
    mode_t current_mask;

    // Exit if unable to create a socket to listen for CLI commands on
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1)
    {
        USP_ERR_ERRNO("socket", errno);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Fill in sockaddr structure
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    USP_STRNCPY(sa.sun_path, cli_uds_file, sizeof(sa.sun_path));

    // Exit if able to connect the socket to the unix domain file
    // In this case the CLI server is already running in another process, so don't attempt to start this one
    err = connect(sock, (struct sockaddr *) &sa, sizeof(struct sockaddr_un));
    if (err == 0)
    {
        USP_LOG_Error("%s: CLI server already running in another process. Aborting", __FUNCTION__);
        close(sock);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Since we have determined that nothing else is providing the CLI server, we're free to create ours
    // Exit if unable to remove the unix domain socket from the filing system (this is necessary to do, otherwise the bind fails)
    err = remove(cli_uds_file);
    if ((err == -1) && (errno != ENOENT))
    {
        USP_ERR_ERRNO("remove", errno);
        USP_LOG_Error("%s: Unable to remove the Unix domain socket file %s", __FUNCTION__, cli_uds_file);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to set socket as non blocking
    err = fcntl(sock, F_SETFL, O_NONBLOCK);
    if (err == -1)
    {
        USP_ERR_ERRNO("fcntl", errno);
        close(sock);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to bind the socket to the unix domain file
    // NOTE: Temporarily change file creation permissions so that this process (running as root) creates a socket that can be accessed by non-root users
    current_mask = umask(0);
    err = bind(sock, (struct sockaddr *) &sa, sizeof(struct sockaddr_un));
    if (err == -1)
    {
        USP_ERR_ERRNO("bind", errno);
        USP_LOG_Error("%s: Unable to bind to Unix domain socket file %s", __FUNCTION__, cli_uds_file);
        close(sock);
        return USP_ERR_INTERNAL_ERROR;
    }
    umask(current_mask);

    // Exit if unable to set the socket in listening mode
    #define CLI_SERVER_BACKLOG  1
    USP_LOG_Info("%s: Starting CLI server on %s", __FUNCTION__, cli_uds_file);
    err = listen(sock, CLI_SERVER_BACKLOG);
    if (err == -1)
    {
        USP_ERR_ERRNO("listen", errno);
        USP_LOG_Error("%s: Unable to listen to Unix domain socket file %s", __FUNCTION__, cli_uds_file);
        close(sock);
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then the socket was successfully setup
    cli_listen_sock = sock;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** CLI_SERVER_UpdateSocketSet
**
** Updates the socket set with the sockets that the CLI server is using
**
** \param   set - pointer to socket set structure to update with sockets to wait for activity on
**
** \return  None
**
**************************************************************************/
void CLI_SERVER_UpdateSocketSet(socket_set_t *set)
{
    if (cli_listen_sock != INVALID)
    {
        SOCKET_SET_AddSocketToReceiveFrom(cli_listen_sock, MAX_SOCKET_TIMEOUT, set);
    }

    if (cli_server_sock != INVALID)
    {
        SOCKET_SET_AddSocketToReceiveFrom(cli_server_sock, MAX_SOCKET_TIMEOUT, set);
    }
}

/*********************************************************************//**
**
** CLI_SERVER_ProcessSocketActivity
**
** Processes any activity on the CLI server sockets
**
** \param   set - pointer to socket set structure containing sockets with activity on them
**
** \return  None (any errors that occur are handled internally)
**
**************************************************************************/
void CLI_SERVER_ProcessSocketActivity(socket_set_t *set)
{
    struct sockaddr sa;
    socklen_t sa_len;
    char buf[MAX_CLI_CMD_LEN];
    int msg_len;
    char *cmd_end;

    // Accept remote connections from CLI clients
    if (cli_listen_sock != INVALID)
    {
        if (SOCKET_SET_IsReadyToRead(cli_listen_sock, set))
        {
            sa_len = sizeof(sa);
            cli_server_sock = accept(cli_listen_sock, &sa, &sa_len);
            if (cli_server_sock == -1)
            {
                // If an error occurred, just log it
                USP_ERR_ERRNO("accept", errno);
            }

            // Exit to allow cli_server_sock to be added to the socket set, before attempting to read it
            return;
        }
    }

    // Exit if no client currently connected
    if (cli_server_sock == INVALID)
    {
        return;
    }

    // Exit if the client has not sent anything to us
    if (SOCKET_SET_IsReadyToRead(cli_server_sock, set) == 0)
    {
        return;
    }

    // Append command fragment from client to buffer
    msg_len = recv(cli_server_sock, &cmd_buf[cmd_buf_len], sizeof(buf)-cmd_buf_len, 0);
    if (msg_len == -1)
    {
        // Exit if an error occurred
        USP_ERR_ERRNO("recv", errno);
        CloseCliServerSock();
        return;
    }
    cmd_buf_len += msg_len;

    // Determine whether a full command has been received (terminated by LF)
    cmd_end = strchr(cmd_buf, '\n');

    // Exit if the full command has not been received yet
    if (cmd_end == NULL)
    {
        // Close the socket if buffer is full, but still no full command received
        if (cmd_buf_len == sizeof(cmd_buf))
        {
            USP_ERR_SetMessage("%s: Received a CLI command that was not terminated by a LF", __FUNCTION__);
            CloseCliServerSock();
        }
        return;
    }

    // If the code gets here, a full command has been received, so process it
    *cmd_end = '\0';            // Make command into a string

    CLI_SERVER_ExecuteCliCommand(cmd_buf);

    // Since we have sent the respone to the command, close the socket
    CloseCliServerSock();
}

/*********************************************************************//**
**
** CLI_SERVER_SendResponse
**
** Sends the specified response fragment to the CLI client
** NOTE: This function may be called many times to build up the response sent back to the client
**
** \param   s - string to send to the CLI client
**
** \return  None
**
**************************************************************************/
void CLI_SERVER_SendResponse(const char *s)
{
    if (dump_to_cli)
    {
        send(cli_server_sock, s, strlen(s), 0);
    }
    else
    {
        printf("%s", s); // NOTE: Do not use USP_LOG_XXX(), as that would cause infinite recursion !
    }
}

/*********************************************************************//**
**
** CLI_SERVER_IsCmdRunLocally
**
** Determines whether the specified CLI command should be run locally or remotely
**
** \param   command
**
** \return  true if the specified command should be run in this executable, otherwise false
**
**************************************************************************/
bool CLI_SERVER_IsCmdRunLocally(char *command)
{
    int i;
    cli_cmd_t *cli_cmd;

    // Iterate over all possible commands, trying to find the one that matches
    for (i=0; i<NUM_ELEM(cli_commands); i++)
    {
        cli_cmd = &cli_commands[i];
        if (strcmp(command, cli_cmd->name)==0)
        {
            return cli_cmd->run_locally;
        }
    }

    // If the code gets here, then the command was not found, so handle it locally
    // where a help messsage will be printed
    return true;
}

/*********************************************************************//**
**
** CLI_SERVER_ExecuteCliCommand
**
** Executes the specified cli command
** NOTE: This function alters the input buffer pointed to by args
**
** \param   cmd_line - string containing the command and it's arguments
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int CLI_SERVER_ExecuteCliCommand(char *cmd_line)
{
    cli_cmd_t *cli_cmd;
    int err = USP_ERR_INVALID_ARGUMENTS;
    str_vector_t args;
    int num_args;
    bool print_help = true;
    char separator[2] = {CLI_SEPARATOR , '\0'};
    char *command;

    // Exit if no command found, after extracting command and args from the input string
    STR_VECTOR_Init(&args);
    TEXT_UTILS_SplitString(cmd_line, &args, separator);
    if (args.num_entries == 0)
    {
        SendCliResponse("ERROR: No command given\n", cmd_line);
        goto exit;
    }
    command = args.vector[0];
    num_args = args.num_entries-1;      // Since the command is at entry [0] in the args string vector

    // Exit if command not found
    cli_cmd = FindCliCommand(command);
    if (cli_cmd == NULL)
    {
        SendCliResponse("ERROR: Unknown command: %s\n", command);
        goto exit;
    }

    // Decide whether output logs should be redirected to remote CLI client
    dump_to_cli = (cli_cmd->run_locally) ? false : true;

    // Exit if not enough arguments provided for command
    if (num_args < cli_cmd->min_args)
    {
        SendCliResponse("ERROR: Missing arguments\n");
        SendCliResponse("Usage: %s\n", cli_cmd->usage);
        print_help = false;
        goto exit;
    }

    // Log a warning if there are too many arguments
    if (num_args > cli_cmd->max_args)
    {
        SendCliResponse("WARNING: Discarding unused args: %s\n", args.vector[cli_cmd->max_args+1]);
    }

    // Process command
    err = cli_cmd->exec_cmd(&args);
    print_help = false;

exit:
    dump_to_cli = false;
    if (print_help)
    {
        ExecuteCli_Help(NULL);
    }

    STR_VECTOR_Destroy(&args);
    return err;
}

/*********************************************************************//**
**
** CloseCliServerSock
**
** Closes the socket on which CLI command is received and the response sent back on
**
** \param   None
**
** \return  None
**
**************************************************************************/
void CloseCliServerSock(void)
{
    close(cli_server_sock);
    cli_server_sock = INVALID;
    cmd_buf[0] = '\0';
    cmd_buf_len = 0;
}

/*********************************************************************//**
**
** SendCliResponse_InvalidValue
**
** Convenience function called when CLI argument's value is invalid for the command
**
** \param   args - command and arguments
**
** \return  None
**
**************************************************************************/
void SendCliResponse_InvalidValue(str_vector_t *args)
{
    cli_cmd_t *cli_cmd;

    cli_cmd = FindCliCommand(args->vector[0]);
    USP_ASSERT(cli_cmd != NULL);

    SendCliResponse("ERROR: Invalid value for argument: %s\n", args->vector[1]);
    SendCliResponse("Usage: %s\n", cli_cmd->usage);
}

/*********************************************************************//**
**
** FindCliCommand
**
** Finds the entry in cli_commands[] matching the specified command
**
** \param   command - command to find
**
** \return  Pointer to entry in cli_commands[] or NULL if no matching command found
**
**************************************************************************/
cli_cmd_t *FindCliCommand(char *command)
{
    int i;
    cli_cmd_t *cli_cmd;

    for (i=0; i<NUM_ELEM(cli_commands); i++)
    {
        cli_cmd = &cli_commands[i];
        if (strcmp(cli_cmd->name, command)==0)
        {
            return cli_cmd;
        }
    }

    return NULL;
}

/*********************************************************************//**
**
** ExecuteCli_Help
**
** Executes the help CLI command
**
** \param   args - unused
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Help(str_vector_t *args)
{
    int i;
    cli_cmd_t *cli_cmd;

    SendCliResponse("Valid commands:\n");

    // Print out the help usage of all commands
    for (i=0; i<NUM_ELEM(cli_commands); i++)
    {
        cli_cmd = &cli_commands[i];
        SendCliResponse("   %s\n", cli_cmd->usage);
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ExecuteCli_Version
**
** Executes the version CLI command
**
** \param   args - unused
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Version(str_vector_t *args)
{
    SendCliResponse("Agent Version=%s\n", AGENT_SOFTWARE_VERSION);
#ifndef REMOVE_DEVICE_SECURITY
    SendCliResponse("OpenSSL Version=%s\n", OPENSSL_VERSION_TEXT);
#endif
    SendCliResponse("Sqlite Version=%s\n", SQLITE_VERSION);
#ifndef REMOVE_DEVICE_BULKDATA
    SendCliResponse("Curl Version=%s\n", curl_version());
#endif
    SendCliResponse("zlib Version=%s\n", ZLIB_VERSION);

#ifdef ENABLE_MQTT
    SendCliResponse("libmosquitto Version=%d.%d.%d\n", LIBMOSQUITTO_MAJOR, LIBMOSQUITTO_MINOR, LIBMOSQUITTO_REVISION);
#endif

#ifdef ENABLE_WEBSOCKETS
    SendCliResponse("libwebsockets Version=%s\n", LWS_LIBRARY_VERSION);
#endif
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ExecuteCli_Get
**
** Executes the get CLI command
**
** \param   args - Entry [1] data model path expression describing parameters to get
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Get(str_vector_t *args)
{
    combined_role_t *combined_role;
#ifndef REMOVE_USP_BROKER
    char *arg1;

    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];

    // Attempt to send and process a single get request to a USP Service, avoiding costly path resolution by the Broker
    combined_role = CalcCliCombinedRole();
    return USP_BROKER_DirectGetForCli(arg1, combined_role);
#else
    int i;
    int err;
    str_vector_t params;
    int_vector_t group_ids;
    group_get_vector_t ggv;
    group_get_entry_t *gge;
    char *arg1;

    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];

    // Exit if unable to get a list of all parameters referenced by the expression
    STR_VECTOR_Init(&params);
    INT_VECTOR_Init(&group_ids);
    combined_role = CalcCliCombinedRole();
    err = PATH_RESOLVER_ResolvePath(arg1, &params, &group_ids, kResolveOp_Get, FULL_DEPTH, combined_role, 0);
    if (err != USP_ERR_OK)
    {
        STR_VECTOR_Destroy(&params);
        INT_VECTOR_Destroy(&group_ids);
        return err;
    }

    // Form the group get vector
    GROUP_GET_VECTOR_Init(&ggv);
    GROUP_GET_VECTOR_AddParams(&ggv, &params, &group_ids);

    // Destroy the params and group_ids vectors (since their contents have been moved to the group get vector)
    USP_SAFE_FREE(params.vector);
    INT_VECTOR_Destroy(&group_ids);

    // Get the values of all the parameters
    GROUP_GET_VECTOR_GetValues(&ggv);

    // Print out the values of all parameters retrieved
    // NOTE: If a parameter is secure, then this will retrieve an empty string
    for (i=0; i < ggv.num_entries; i++)
    {
        gge = &ggv.vector[i];
        if (gge->err_code == USP_ERR_OK)
        {
            USP_ASSERT(gge->value != NULL);
            SendCliResponse("%s => %s\n", gge->path, gge->value);
        }
        else
        {
            SendCliResponse("ERROR: %d retrieving %s (%s)\n", gge->err_code, gge->path, gge->err_msg);
        }
    }

    GROUP_GET_VECTOR_Destroy(&ggv);
    return USP_ERR_OK;
#endif
}

/*********************************************************************//**
**
** ExecuteCli_Set
**
** Executes the set CLI command
**
** \param   args - Entry [1] data model parameter to set
**                 Entry [2] value of data model parameter to set
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Set(str_vector_t *args)
{
    int i;
    int err;
    char path[MAX_DM_PATH];
    dm_trans_vector_t trans;
    str_vector_t objects;
    char param_name[MAX_DM_PATH];
    char search_path[MAX_DM_PATH];
    combined_role_t *combined_role;
    unsigned short permission_bitmask;
    char *arg1;
    char *arg2;

    // Code to handle setting a parameter to an empty string
    // Bash does not pass empty string arguments to executables, even if they are indicated as ""
    if (args->num_entries >= 3)
    {
        arg2 = args->vector[2];
    }
    else
    {
        arg2 = "";
    }

    arg1 = args->vector[1];

    STR_VECTOR_Init(&objects);

    // Exit if unable to split the set expression into search path and parameter name
    // This is necessary to mimic the way that the USP SET message works
    err = SplitSetExpression(arg1, search_path, sizeof(search_path), param_name, sizeof(param_name));
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if unable to get a list of all objects referenced by the expression
    combined_role = CalcCliCombinedRole();
    err = PATH_RESOLVER_ResolvePath(search_path, &objects, NULL, kResolveOp_Set, FULL_DEPTH, combined_role, 0);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if no objects matched
    if (objects.num_entries == 0)
    {
        SendCliResponse("No objects were matched for setting\n");
        err = USP_ERR_OBJECT_DOES_NOT_EXIST;
        goto exit;
    }

    // Exit if unable to start a transaction
    err = DM_TRANS_Start(&trans);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Iterate over all objects to set
    for (i=0; i < objects.num_entries; i++)
    {
        // Exit if failed to get the permissions for this parameter
        USP_SNPRINTF(path, sizeof(path), "%s.%s", objects.vector[i], param_name);
        err = DATA_MODEL_GetPermissions(path, combined_role, &permission_bitmask, 0);
        if (err != USP_ERR_OK)
        {
            DM_TRANS_Abort();
            goto exit;
        }

        // Exit if the parameter is not permitted to be set
        if ((permission_bitmask & PERMIT_SET) == 0)
        {
            SendCliResponse("Parameter %s is not permitted to be set\n", path);
            DM_TRANS_Abort();
            goto exit;
        }

        // Exit if unable to set the value of the parameter
        err = DATA_MODEL_SetParameterValue(path, arg2, CHECK_WRITABLE);
        if (err != USP_ERR_OK)
        {
            DM_TRANS_Abort();
            goto exit;
        }
    }

    // Exit if unable to commit the transaction
    err = DM_TRANS_Commit();
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Activate all STOMP reconnects or scheduled exits
    MTP_EXEC_ActivateScheduledActions();

    // Since successful, send back the value of all parameters set
    for (i=0; i < objects.num_entries; i++)
    {
        SendCliResponse("%s.%s => %s\n", objects.vector[i], param_name, arg2);
    }

    err = USP_ERR_OK;

exit:
    STR_VECTOR_Destroy(&objects);
    return err;
}

/*********************************************************************//**
**
** ExecuteCli_Add
**
** Executes the add CLI command
** NOTE: The CLI command for Add is different from the USP ADD message in that it accepts
**       a fully qualified object with trailing instance number as well as an unqualified object
**
** \param   args - Entry [1] object to add. This can be either with or without instance number to add.
**                          (If without, an instance number will be automatically assigned)
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Add(str_vector_t *args)
{
    int i;
    int err;
    char path[MAX_DM_PATH];
    dm_trans_vector_t trans;
    str_vector_t objects;
    char *instance_str;
    char *search_path;
    int instance_number;
    kv_vector_t unique_key_params;
    char *arg1;
    str_vector_t err_msgs;
    int_vector_t err_codes;
    combined_role_t *combined_role;

    // Initialise all vectors
    STR_VECTOR_Init(&err_msgs);
    INT_VECTOR_Init(&err_codes);
    KV_VECTOR_Init(&unique_key_params);
    STR_VECTOR_Init(&objects);

    // Split the object to add, into search path and (if one exists) instance number
    // NOTE: Trailing instance numbers may only be used on paths that do not contain complex search expressions
    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];
    instance_str = SplitOffTrailingNumber(arg1);
    search_path = arg1;

    // Exit if unable to get a list of all objects referenced by the expression
    combined_role = CalcCliCombinedRole();
    PATH_RESOLVER_AttachErrVector(&err_msgs, &err_codes);
    err = PATH_RESOLVER_ResolvePath(search_path, &objects, NULL, kResolveOp_Add, FULL_DEPTH, combined_role, 0);
    PATH_RESOLVER_AttachErrVector(NULL, NULL);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if there was a permission error
    if (err_msgs.num_entries > 0)
    {
        USP_ASSERT(err_msgs.vector != NULL);
        USP_ASSERT(err_codes.vector != NULL);
        USP_ASSERT(err_codes.num_entries > 0);
        if (usp_log_level == kLogLevel_Off) // The error will have already been printed out to the CLI if the log level was anything higher
        {
            SendCliResponse("%s\n", err_msgs.vector[0]);
        }
        err = err_codes.vector[0];
        goto exit;
    }

    // Exit if no objects matched
    if (objects.num_entries == 0)
    {
        SendCliResponse("No objects were matched for addition\n");
        err = USP_ERR_OBJECT_DOES_NOT_EXIST;
        goto exit;
    }

    // Exit if unable to start a transaction
    err = DM_TRANS_Start(&trans);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Iterate over all objects to add
    for (i=0; i < objects.num_entries; i++)
    {
        if (instance_str != NULL)
        {
            // Argument specifies an object with an instance number, so try to create the specified instance number
            // NOTE: This usage is specific to the CLI - the USP protocol itself does not allow this usage (agent always allocates instance number, never controller)
            // Exit if unable to create specified instance number
            USP_SNPRINTF(path, sizeof(path), "%s.%s", objects.vector[i], instance_str);
            err = DATA_MODEL_AddInstance(path, NULL, CHECK_CREATABLE);  // We need the check, otherwise the validate function is not called for a vendor object
            if (err != USP_ERR_OK)
            {
                DM_TRANS_Abort();
                goto exit;
            }
        }
        else
        {
            // Argument specifies an object without an instance number, so USP Agent allocates instance number
            // Exit if unable to add a new instance number
            err = DATA_MODEL_AddInstance(objects.vector[i], &instance_number, CHECK_CREATABLE);  // We need the check, otherwise the validate function is not called for a vendor object
            if (err != USP_ERR_OK)
            {
                DM_TRANS_Abort();
                goto exit;
            }
            USP_SNPRINTF(path, sizeof(path), "%s.%d", objects.vector[i], instance_number);
        }

        // Exit if unable to retrieve the parameters used as unique keys for this object
        err = DATA_MODEL_GetUniqueKeyParams(path, &unique_key_params, INTERNAL_ROLE);
        if (err != USP_ERR_OK)
        {
            DM_TRANS_Abort();
            goto exit;
        }

        // Exit if any unique keys have been left with a default value which is not unique
        err = DATA_MODEL_ValidateDefaultedUniqueKeys(path, &unique_key_params, NULL);
        if (err != USP_ERR_OK)
        {
            DM_TRANS_Abort();
            goto exit;
        }

    }

    // Exit if unable to commit the transaction
    err = DM_TRANS_Commit();
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Since successful, print out the list of objects created
    for (i=0; i < objects.num_entries; i++)
    {
        if (instance_str != NULL)
        {
            SendCliResponse("Added %s.%s\n", objects.vector[i], instance_str);
        }
        else
        {
            SendCliResponse("Added %s.%d\n", objects.vector[i], instance_number);
        }
    }

    err = USP_ERR_OK;

exit:
    KV_VECTOR_Destroy(&unique_key_params);
    STR_VECTOR_Destroy(&objects);
    STR_VECTOR_Destroy(&err_msgs);
    INT_VECTOR_Destroy(&err_codes);
    return err;
}

/*********************************************************************//**
**
** ExecuteCli_Del
**
** Executes the delete CLI command
**
** \param   args - Entry [1] object to delete
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Del(str_vector_t *args)
{
    int i;
    int err;
    dm_trans_vector_t trans;
    str_vector_t objects;
    char *arg1;
    combined_role_t *combined_role;

    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];

    STR_VECTOR_Init(&objects);

    // Exit if unable to get a list of all objects referenced by the expression
    combined_role = CalcCliCombinedRole();
    err = PATH_RESOLVER_ResolvePath(arg1, &objects, NULL, kResolveOp_Del, FULL_DEPTH, combined_role, 0);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if no objects matched
    if (objects.num_entries == 0)
    {
        SendCliResponse("No objects were matched for deletion\n");
        err = USP_ERR_OBJECT_DOES_NOT_EXIST;
        goto exit;
    }

    // Exit if unable to start a transaction
    err = DM_TRANS_Start(&trans);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Iterate over all objects to delete
    for (i=0; i < objects.num_entries; i++)
    {
        // Exit if unable to delete the specified instance
        err = DATA_MODEL_DeleteInstance(objects.vector[i], CHECK_DELETABLE);  // We need the check, otherwise the validate function is not called for a vendor object
        if (err != USP_ERR_OK)
        {
            DM_TRANS_Abort();
            goto exit;
        }
    }

    // Exit if unable to commit the transaction
    err = DM_TRANS_Commit();
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Since successful, print out the list of objects deleted
    for (i=0; i < objects.num_entries; i++)
    {
        SendCliResponse("Deleted %s\n", objects.vector[i]);
    }

    err = USP_ERR_OK;

exit:
    STR_VECTOR_Destroy(&objects);
    return err;
}

/*********************************************************************//**
**
** ExecuteCli_Operate
**
** Executes the operate CLI command
**
** \param   args - Entry [1] operation (and args) to start
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Operate(str_vector_t *args)
{
    int i, j;
    int err;
    dm_trans_vector_t trans;
    str_vector_t operations;
    kv_vector_t input_args;
    kv_vector_t output_args;
    kv_pair_t *kv;
    int instance;
    char *bracket_start;
    char *bracket_end;
    char path[MAX_DM_PATH];
    expr_op_t valid_ops[] = {kExprOp_Equals};
    expr_vector_t temp_ev;
    char *arg1;
    combined_role_t *combined_role;

    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];

    // Initialise all vectors used by this function
    KV_VECTOR_Init(&input_args);
    KV_VECTOR_Init(&output_args);
    EXPR_VECTOR_Init(&temp_ev);
    STR_VECTOR_Init(&operations);

    // Exit if argument does not contain an opening bracket
    bracket_start = TEXT_UTILS_StrStr(arg1, "(");
    if (bracket_start == NULL)
    {
        SendCliResponse("Missing opening bracket in the argument\n");
        err = USP_ERR_INVALID_ARGUMENTS;
        goto exit;
    }

    // Exit if argument does not contain a closing bracket
    bracket_end = TEXT_UTILS_StrStr(bracket_start, ")");
    if (bracket_end == NULL)
    {
        SendCliResponse("Missing closing bracket (or bracket part of a quoted string embedded in the argument)\n");
        err = USP_ERR_INVALID_ARGUMENTS;
        goto exit;
    }

    // Split off the input arguments for the operation
    *bracket_start = '\0';
    *bracket_end= '\0';
    USP_SNPRINTF(path, sizeof(path), "%s()", arg1);

    // Exit if unable to extract the input args into a temporary expression vector
    err = EXPR_VECTOR_SplitExpressions(&bracket_start[1], &temp_ev, ",", valid_ops, NUM_ELEM(valid_ops), EXPR_FROM_CLI);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Convert the expression vector to a key-value vector, destroying the expression vector
    EXPR_VECTOR_ToKeyValueVector(&temp_ev, &input_args);

    // Exit if unable to get a list of all operations referenced by the expression
    combined_role = CalcCliCombinedRole();
    err = PATH_RESOLVER_ResolvePath(path, &operations, NULL, kResolveOp_Oper, FULL_DEPTH, combined_role, 0);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if no objects matched
    if (operations.num_entries == 0)
    {
        SendCliResponse("No objects were matched for operate\n");
        err = USP_ERR_OBJECT_DOES_NOT_EXIST;
        goto exit;
    }

    // Iterate over all operations to operate on
    for (i=0; i < operations.num_entries; i++)
    {
        // Exit if unable to start a transaction
        err = DM_TRANS_Start(&trans);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }

        // Exit if unable to start the specified operation
        KV_VECTOR_Init(&output_args);
        err = DATA_MODEL_Operate(operations.vector[i], &input_args, &output_args, "CLI-initiated", &instance);
        if (err != USP_ERR_OK)
        {
            SendCliResponse("ERROR: Operation failed");
            DM_TRANS_Abort();
            goto exit;
        }
        else
        {
            if (instance != INVALID)
            {
                // Asynchronous operation started successfully
                SendCliResponse("Asynchronous Operation (%s) Started successfully.\n", operations.vector[i]);
                SendCliResponse("Device.LocalAgent.Request.%d created.\n", instance);
                SendCliResponse("See log for output arguments of operation\n");
            }
            else
            {
                // Synchronous operation completed successfully
                SendCliResponse("Synchronous Operation (%s) completed successfully.\n", operations.vector[i]);
                SendCliResponse("Output Arguments:-\n");
                for (j=0; j<output_args.num_entries; j++)
                {
                    kv = &output_args.vector[j];
                    SendCliResponse("   %s => %s\n", kv->key, kv->value);
                }
            }
        }

        // Exit if unable to commit the transaction
        err = DM_TRANS_Commit();
        if (err != USP_ERR_OK)
        {
            goto exit;
        }
        KV_VECTOR_Destroy(&output_args);

        // Activate all STOMP reconnects or scheduled exits
        MTP_EXEC_ActivateScheduledActions();
    }

    err = USP_ERR_OK;

exit:
    KV_VECTOR_Destroy(&input_args);
    KV_VECTOR_Destroy(&output_args);
    STR_VECTOR_Destroy(&operations);
    EXPR_VECTOR_Destroy(&temp_ev);
    return err;
}

/*********************************************************************//**
**
** ExecuteCli_Event
**
** Executes the event CLI command
** NOTE: A subscription must be in place for the event to be sent
**
** \param   args - Entry [1] event (and args) to emit
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Event(str_vector_t *args)
{
    int i;
    int err;
    str_vector_t events;
    kv_vector_t event_args;
    char *bracket_start;
    char *bracket_end;
    char *pling;
    expr_op_t valid_ops[] = {kExprOp_Equals};
    expr_vector_t temp_ev;
    char *arg1;
    combined_role_t *combined_role;

    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];

    // Initialise all vectors used by this function
    KV_VECTOR_Init(&event_args);
    EXPR_VECTOR_Init(&temp_ev);
    STR_VECTOR_Init(&events);

    // Exit if argument does not contain an exclamation mark
    pling = TEXT_UTILS_StrStr(arg1, "!");
    if (pling == NULL)
    {
        SendCliResponse("Missing exclamation mark in event name\n");
        err = USP_ERR_INVALID_ARGUMENTS;
        goto exit;
    }

    // Skip extracting arguments if none supplied
    bracket_start = TEXT_UTILS_StrStr(arg1, "(");
    if (bracket_start == NULL)
    {
        goto resolved;
    }

    // Exit if closing bracket is not present
    bracket_end = TEXT_UTILS_StrStr(bracket_start, ")");
    if (bracket_end == NULL)
    {
        SendCliResponse("Missing closing bracket around the arguments\n");
        err = USP_ERR_INVALID_ARGUMENTS;
        goto exit;
    }

    // Split off the arguments for the operation
    *bracket_start = '\0';
    *bracket_end= '\0';

    // Exit if unable to extract the event_args into a temporary expression vector
    err = EXPR_VECTOR_SplitExpressions(&bracket_start[1], &temp_ev, ",", valid_ops, NUM_ELEM(valid_ops), EXPR_FROM_CLI);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Convert the expression vector to a key-value vector, destroying the expression vector
    EXPR_VECTOR_ToKeyValueVector(&temp_ev, &event_args);

resolved:
    // Exit if unable to get a list of all events referenced by the expression
    combined_role = CalcCliCombinedRole();
    err = PATH_RESOLVER_ResolvePath(arg1, &events, NULL, kResolveOp_Event, FULL_DEPTH, combined_role, 0);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if no objects matched
    if (events.num_entries == 0)
    {
        SendCliResponse("No objects were matched for event\n");
        err = USP_ERR_OBJECT_DOES_NOT_EXIST;
        goto exit;
    }

    // Iterate over all events to operate on
    for (i=0; i < events.num_entries; i++)
    {
        SendCliResponse("Event (%s) being signalled\n", events.vector[i]);
        DEVICE_SUBSCRIPTION_ProcessAllEventCompleteSubscriptions(events.vector[i], &event_args);
    }

    err = USP_ERR_OK;

exit:
    KV_VECTOR_Destroy(&event_args);
    STR_VECTOR_Destroy(&events);
    EXPR_VECTOR_Destroy(&temp_ev);
    return err;
}

/*********************************************************************//**
**
** ExecuteCli_GetInstances
**
** Executes the get instances CLI command
**
** \param   args - Entry [1] data model path expression describing object instances to get
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_GetInstances(str_vector_t *args)
{
    int i;
    int err;
    str_vector_t obj_paths;
    char *arg1;
    combined_role_t *combined_role;

    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];

    // Exit if unable to get a list of all parameters referenced by the expression
    STR_VECTOR_Init(&obj_paths);
    combined_role = CalcCliCombinedRole();
    err = PATH_RESOLVER_ResolvePath(arg1, &obj_paths, NULL, kResolveOp_Instances, FULL_DEPTH, combined_role, GET_ALL_INSTANCES);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Sort the instances
#ifndef DONT_SORT_GET_INSTANCES
    STR_VECTOR_Sort(&obj_paths);
#endif

    // Iterate over all object instances returned
    for (i=0; i < obj_paths.num_entries; i++)
    {
        SendCliResponse("%s\n", obj_paths.vector[i]);
    }

    err = USP_ERR_OK;

exit:
    STR_VECTOR_Destroy(&obj_paths);
    return err;
}

/*********************************************************************//**
**
** ExecuteCli_Show
**
** Executes the show CLI command
**
** \param   args - Entry [1] enumeration of type of information to show
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Show(str_vector_t *args)
{
    char *arg1;

    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];

    // Show the contents of the database if required
    if (strcmp(arg1, "database")==0)
    {
        DATABASE_Dump();
        return USP_ERR_OK;
    }

    // If the code gets here, there is an unknown value for arg1
    SendCliResponse_InvalidValue(args);
    return USP_ERR_INVALID_ARGUMENTS;
}

/*********************************************************************//**
**
** ExecuteCli_Dump
**
** Executes the dump CLI command
**
** \param   args - Entry [1] enumeration of type of information to show
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Dump(str_vector_t *args)
{
    char *arg1;

    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];

    // Show the data model schema if required
    if (strcmp(arg1, "datamodel")==0)
    {
        DATA_MODEL_DumpSchema();
        return USP_ERR_OK;
    }

    // Show all memory usage
    if (strcmp(arg1, "memory")==0)
    {
        USP_MEM_PrintAll();
        return USP_ERR_OK;
    }

    // Show the change in memory since the last time this was called
    if (strcmp(arg1, "mdelta")==0)
    {
        USP_MEM_Print();
        return USP_ERR_OK;
    }

    // Show the contents of the internal subscription array
    if (strcmp(arg1, "subscriptions")==0)
    {
        DEVICE_SUBSCRIPTION_Dump();
        return USP_ERR_OK;
    }

    // Show the internal list of data model instances, if required
    if (strcmp(arg1, "instances")==0)
    {
        DATA_MODEL_DumpInstances();
        return USP_ERR_OK;
    }

    // If the code gets here, there is an unknown value for arg1
    SendCliResponse_InvalidValue(args);
    return USP_ERR_INVALID_ARGUMENTS;
}

/*********************************************************************//**
**
** ExecuteCli_Role
**
** Executes the role CLI command
**
** \param   args - Entry [1] instance number of role in Device.LocalAgent.ControllerTrust.Role.{i}
**                 or 0 if INTERNAL_ROLE should be used
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Role(str_vector_t *args)
{
    int items_converted;
    int role_instance;
    int role_index;

    USP_ASSERT(args->num_entries >= 1);

    // Exit if instance number cannot be parsed
    items_converted = sscanf(args->vector[1], "%d", &role_instance);
    if (items_converted != 1)
    {
        SendCliResponse("Role instance number ('%s') is not a number\n", args->vector[1]);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if role to use was the internal role
    if (role_instance == 0)
    {
        SendCliResponse("CLI Role set to INTERNAL_ROLE (allow all)\n");
        cli_role_instance = 0;
        return USP_ERR_OK;
    }

    // Exit if unable to convert the role instance number into the internal index number
    role_index = DEVICE_CTRUST_RoleInstanceToIndex(role_instance);
    if (role_index == INVALID)
    {
        SendCliResponse("Role instance number (%d) does not match any of the entries in the Device.LocalAgent.ControllerTrust.Role table\n", role_instance);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Setup CLI to use this role for subsequent commands
    SendCliResponse("CLI Role set to Device.LocalAgent.ControllerTrust.Role.%d\n", role_instance);
    cli_role_instance = role_instance;

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ExecuteCli_Perm
**
** Executes the perm CLI command
**
** \param   args - Entry [1] data model path of parameter or object to get the permissions of
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Perm(str_vector_t *args)
{
    int role_index;
    unsigned short perm;
    combined_role_t combined_role;
    int role_instance;
    int err;
    char *arg1;

    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];

    // Iterate over all roles, getting the permissions for each role
    for (role_index=0; role_index < MAX_CTRUST_ROLES; role_index++)
    {
        // Skip to next role index, if there is no role instance in this slot
        role_instance = DEVICE_CTRUST_RoleIndexToInstance(role_index);
        if (role_instance == INVALID)
        {
            continue;
        }

        // Get the permissions for the specified parameter or object
        combined_role.inherited_index = role_index;
        combined_role.assigned_index = role_index;
        err = DATA_MODEL_GetPermissions(arg1, &combined_role, &perm, 0);
        if (err != USP_ERR_OK)
        {
            continue;
        }

        // Since successful, send back the permissions for the parameter
        #define PERMISSION_CHAR(bitmask, c, mask) ( ((bitmask & mask) == 0) ? '-' : c )
        SendCliResponse("Role.%d   Param(%c%c-%c) Obj(%c%c-%c) InstantiatedObj(%c%c-%c) CommandEvent(%c-%c%c)\n",
                         role_instance,
                         PERMISSION_CHAR(perm, 'r', PERMIT_GET),
                         PERMISSION_CHAR(perm, 'w', PERMIT_SET),
                         PERMISSION_CHAR(perm, 'n', PERMIT_SUBS_VAL_CHANGE),

                         PERMISSION_CHAR(perm, 'r', PERMIT_OBJ_INFO),
                         PERMISSION_CHAR(perm, 'w', PERMIT_ADD),
                         PERMISSION_CHAR(perm, 'n', PERMIT_SUBS_OBJ_ADD),

                         PERMISSION_CHAR(perm, 'r', PERMIT_GET_INST),
                         PERMISSION_CHAR(perm, 'w', PERMIT_DEL),
                         PERMISSION_CHAR(perm, 'n', PERMIT_SUBS_OBJ_DEL),

                         PERMISSION_CHAR(perm, 'r', PERMIT_CMD_INFO),
                         PERMISSION_CHAR(perm, 'x', PERMIT_OPER),
                         PERMISSION_CHAR(perm, 'n', PERMIT_SUBS_EVT_OPER_COMP) );
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ExecuteCli_PermSel
**
** Executes the permsel CLI command
**
** \param   args - Entry [1] instance number of role to get the permission selectors for
**                 Entry [2] data model path of parameter or object to get the permission selectors for
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_PermSel(str_vector_t *args)
{
    int i;
    int role_instance;
    int role_index;
    dm_node_t *node;
    inst_sel_vector_t *isv;
    inst_sel_t *is;
    unsigned short perm;
    int items_converted;
    int perm_instance;
    char *perm_target;

    // Exit if instance number cannot be parsed
    items_converted = sscanf(args->vector[1], "%d", &role_instance);
    if (items_converted != 1)
    {
        SendCliResponse("Role instance number ('%s') is invalid\n", args->vector[1], MAX_CTRUST_ROLES);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if role instance number does not exist
    role_index = DEVICE_CTRUST_RoleInstanceToIndex(role_instance);
    if (role_index == INVALID)
    {
        SendCliResponse("Role instance number (%d) does not exist\n", args->vector[1], role_instance);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to find the path in the data model
    node = DM_PRIV_GetNodeFromPath(args->vector[2], NULL, NULL, 0);
    if (node == NULL)
    {
        SendCliResponse("Unknown data model path '%s'\n", args->vector[2]);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Iterate over all instance selectors, logging them
    isv = &node->permissions[role_index];
    for (i=0; i < isv->num_entries; i++)
    {
        // Write the instance number of this permission into a buffer
        is = isv->vector[i];
        perm_target = DEVICE_CTRUST_InstSelToPermTarget(role_index, is, &perm_instance);
        USP_ASSERT(perm_target != NULL);
        SendCliResponse("Permission.%d", perm_instance);

        // Write the permissions associated with the instance selector into a buffer
        perm = is->permission_bitmask;
        SendCliResponse("   Param(%c%c-%c) Obj(%c%c-%c) InstantiatedObj(%c%c-%c) CommandEvent(%c-%c%c)",
                     PERMISSION_CHAR(perm, 'r', PERMIT_GET),
                     PERMISSION_CHAR(perm, 'w', PERMIT_SET),
                     PERMISSION_CHAR(perm, 'n', PERMIT_SUBS_VAL_CHANGE),

                     PERMISSION_CHAR(perm, 'r', PERMIT_OBJ_INFO),
                     PERMISSION_CHAR(perm, 'w', PERMIT_ADD),
                     PERMISSION_CHAR(perm, 'n', PERMIT_SUBS_OBJ_ADD),

                     PERMISSION_CHAR(perm, 'r', PERMIT_GET_INST),
                     PERMISSION_CHAR(perm, 'w', PERMIT_DEL),
                     PERMISSION_CHAR(perm, 'n', PERMIT_SUBS_OBJ_DEL),

                     PERMISSION_CHAR(perm, 'r', PERMIT_CMD_INFO),
                     PERMISSION_CHAR(perm, 'x', PERMIT_OPER),
                     PERMISSION_CHAR(perm, 'n', PERMIT_SUBS_EVT_OPER_COMP) );

        // Write the target of the permission into the buffer
        SendCliResponse("  %s\n", perm_target);
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ExecuteCli_DbGet
**
** Executes the dbget CLI command
**
** \param   args - Entry [1] data model parameter to get from the database
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_DbGet(str_vector_t *args)
{
    int err;
    dm_hash_t hash;
    char instances[MAX_DM_PATH];
    char value[MAX_DM_VALUE_LEN];
    unsigned path_flags;
    char *param;

    USP_ASSERT(args->num_entries >= 2);
    param = args->vector[1];

    // Exit if parameter path is incorrect
    err = DM_PRIV_FormDB_FromPath(param, &hash, instances, sizeof(instances));
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit, not printing any value, if this parameter is obfuscated (eg containing a password)
    value[0] = '\0';
    path_flags = DATA_MODEL_GetPathProperties(param, INTERNAL_ROLE, NULL, NULL, NULL, 0);
    if (path_flags & PP_IS_SECURE_PARAM)
    {
        goto exit;
    }

    // Exit if unable to get value of parameter from DB
    USP_ERR_ClearMessage();
    err = DATABASE_GetParameterValue(param, hash, instances, value, sizeof(value), 0);
    if (err != USP_ERR_OK)
    {
        USP_ERR_ReplaceEmptyMessage("Parameter %s exists in the schema, but does not exist in the database", param);
        return err;
    }

exit:
    // Since successful, send back the value of the parameter
    SendCliResponse("%s => %s\n", param, value);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ExecuteCli_DbSet
**
** Executes the dbset CLI command
**
** \param   args - Entry [1] data model parameter to set in the database
**                 Entry [2] value of data model parameter to set
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_DbSet(str_vector_t *args)
{
    int err;
    char *param;
    char *value;

    // Code to handle setting a parameter to an empty string
    // Bash does not pass empty string arguments to executables, even if they are indicated as ""
    if (args->num_entries >= 3)
    {
        value = args->vector[2];
    }
    else
    {
        value = "";
    }

    param = args->vector[1];

    // Exit if unable to directly set the parameter in the database
    err = DATA_MODEL_SetParameterInDatabase(param, value);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Since successful, send back the value of the parameter
    SendCliResponse("%s => %s\n", param, value);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ExecuteCli_DbDel
**
** Executes the dbdel CLI command
**
** \param   args - Entry [1] data model parameter to delete from the database
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_DbDel(str_vector_t *args)
{
    int err;
    dm_hash_t hash;
    char instances[MAX_DM_PATH];
    char *param;

    USP_ASSERT(args->num_entries >= 2);
    param = args->vector[1];

    // Exit if parameter path is incorrect
    err = DM_PRIV_FormDB_FromPath(param, &hash, instances, sizeof(instances));
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to delete parameter from DB
    // NOTE: If the parameter already does not exist in the database, then this function will still return success
    err = DATABASE_DeleteParameter(param, hash, instances);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // If the code gets here, deletion was successful
    SendCliResponse("Deleted %s\n", param);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ExecuteCli_Verbose
**
** Executes the verbose CLI command
**
** \param   args - Entry [1] verbosity level
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Verbose(str_vector_t *args)
{
    int err;
    log_level_t level;
    char *arg1;

    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];

    err = TEXT_UTILS_StringToUnsigned(arg1, &level);
    if ((err != USP_ERR_OK) || (level >= kLogLevel_Max))
    {
        SendCliResponse("ERROR: Verbosity level (%s) is invalid or out of range\n", arg1);
        err = USP_ERR_INVALID_ARGUMENTS;
    }
    else
    {
        usp_log_level = level;
        SendCliResponse("Verbosity level set to %d\n", level);
    }

    return err;
}

/*********************************************************************//**
**
** ExecuteCli_ProtoTrace
**
** Executes the prototrace CLI command
**
** \param   args - Entry [1] Value setting whether protocol tracing is enabled or not (0=off, 1 = enabled)
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_ProtoTrace(str_vector_t *args)
{
    int err;
    log_level_t enable;
    char *arg1;

    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];

    err = TEXT_UTILS_StringToUnsigned(arg1, &enable);
    if ((err != USP_ERR_OK) || (enable > 1))
    {
        SendCliResponse("ERROR: Prototrace enable (%s) is invalid\n", arg1);
        err = USP_ERR_INVALID_ARGUMENTS;
    }
    else
    {
        enable_protocol_trace = (bool) enable;
        SendCliResponse("Protocol Tracing has been %s\n", (enable) ? "enabled" : "disabled");
    }

    return err;
}

/*********************************************************************//**
**
** ExecuteCli_Stop
**
** Executes the stop CLI command
**
** \param   args - unused
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Stop(str_vector_t *args)
{
    // Signal that USP Agent should stop, once no queued messages to send
#ifndef REMOVE_DEVICE_BULKDATA
    BDC_EXEC_ScheduleExit();
#endif
    MTP_EXEC_ScheduleExit();
    MTP_EXEC_ActivateScheduledActions();

    SendCliResponse("Stopping USP Agent\n");

    return USP_ERR_OK;
}

#ifndef REMOVE_USP_SERVICE
/*********************************************************************//**
**
** ExecuteCli_Register
**
** Executes the register CLI command, which sends a Register message on the UDS MTP
**
** \param   args - Entry [1] pointer to string containing comma separated list of data model objects to register
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_Register(str_vector_t *args)
{
    int err = USP_ERR_INTERNAL_ERROR;
    char *endpoint_id;
    char *arg1;

    USP_ASSERT(args->num_entries >= 2);
    arg1 = args->vector[1];

    // Exit if not running as a USP Service
    if (RUNNING_AS_USP_SERVICE()==false)
    {
        SendCliResponse("Cannot register. Not running as a USP service.\n");
        goto exit;
    }

    // Exit if no controller found to send the register to
    endpoint_id = DEVICE_CONTROLLER_FindFirstControllerEndpoint();
    if (endpoint_id == NULL)
    {
        goto exit;
    }

    // Queue the register request
    USP_SERVICE_QueueRegisterRequest(endpoint_id, arg1);
    err = USP_ERR_OK;

exit:
    return err;
}

/*********************************************************************//**
**
** ExecuteCli_DeRegister
**
** Executes the deregister CLI command, which sends a Deregister message on the UDS MTP
**
** \param   args - Entry [1] pointer to string containing comma separated list of data model objects to deregister
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteCli_DeRegister(str_vector_t *args)
{
    int err = USP_ERR_INTERNAL_ERROR;
    char *endpoint_id;
    char *arg1;

    // Code to handle sending deregister with an empty string
    // Bash does not pass empty string arguments to executables, even if they are indicated as ""
    if (args->num_entries >= 2)
    {
        arg1 = args->vector[1];
    }
    else
    {
        arg1 = "";
    }

    // Exit if not running as a USP Service
    if (RUNNING_AS_USP_SERVICE()==false)
    {
        SendCliResponse("Cannot deregister. Not running as a USP service.\n");
        goto exit;
    }

    // Exit if no controller found to send the deregister to
    endpoint_id = DEVICE_CONTROLLER_FindFirstControllerEndpoint();
    if (endpoint_id == NULL)
    {
        goto exit;
    }

    // Queue the deregister request
    USP_SERVICE_QueueDeregisterRequest(endpoint_id, arg1);
    err = USP_ERR_OK;

exit:
    return err;
}
#endif

/*********************************************************************//**
**
** SplitOffTrailingNumber
**
** Splits a buffer into two strings, a search path and a trailing number (if present)
**
** \param   s - pointer containing string object to delete
**
** \return  pointer to trailing number, or NULL if no trailing number was found
**
**************************************************************************/
char *SplitOffTrailingNumber(char *s)
{
    int len;
    int i;
    char c;

    // Exit if empty string
    len = strlen(s);
    if (len < 1)
    {
        return NULL;
    }

    // Exit if string does not contain a trailing number at the end
    #define is_not_digit(c) ((c > '9') || (c < '0'))
    c = s[len-1];
    if (is_not_digit(c))
    {
        return NULL;
    }

    // Scan from the end of the string, finding the first non-digit
    for (i=len-1; i>0; i--)
    {
        c = s[i];
        if (is_not_digit(c))
        {
            // Exit if character separating any digits at the end of the path and the search path, was not a '.'
            if (c != '.')
            {
                return NULL;
            }

            // Split the string at the '.'
            s[i] = '\0';

            // Exit if the number is an empty string
            // NOTE: This should be an unneceaary test since we have already determined that there is at least one digit
            if (i == len-1)
            {
                return NULL;
            }

            // Otherwise we have split off a number of digits, so return a pointer to this string
            return &s[i+1];
        }
    }

    // If the code gets here, the whole of the string was composed of digits
    return NULL;
}

/*********************************************************************//**
**
** SplitSetExpression
**
** Splits a set expression into a search path identifying the objects to modify
** and the name of the parameter whose value to modify in the objects
** NOTE: This function is complicated by the fact that the parameter name may be in the middle of
**       the string, if the string contains expression components (ie '::{ }' )
**
** Example: Splits Device.Test.{i}.Param1::{i.Param2 == 50} into
**                 search_path = Device.Test.{i}::{i.Param2 == 50}
**                 param_name  = Param1
**
** \param   expr - pointer to buffer containing the expression to split
** \param   search_path - pointer to buffer in which to return search path to list of objects to set
** \param   param_name - pointer to buffer in which to return the name of the parameter to set
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int SplitSetExpression(char *expr, char *search_path, int search_path_len, char *param_name, int param_name_len)
{
    char *expr_separator;
    char *param_separator;
    int len;

    // Copy the path (excluding expression components) into search_path
    expr_separator = strstr(expr, "::{");
    if (expr_separator != NULL)
    {
        *expr_separator = '\0'; // Temporarily truncate string at expression components
        USP_STRNCPY(search_path, expr, search_path_len);
        *expr_separator = ':'; // Put expression components back the way they were
    }
    else
    {
        USP_STRNCPY(search_path, expr, search_path_len);
    }

    // Exit if search path does not end in a parameter name
    param_separator = strrchr(search_path, '.');
    if (param_separator == NULL)
    {
        SendCliResponse("ERROR: Path (%s) does not end in a parameter\n", search_path);
        return USP_ERR_INVALID_PATH;
    }

    // Now remove the parameter name from search_path[], and copy it into param_name[]
    *param_separator = '\0';
    USP_STRNCPY(param_name, &param_separator[1], param_name_len);

    // Finally append the expression components to search_path, if they were present in the argument
    if (expr_separator != NULL)
    {
        len = strlen(search_path);
        USP_STRNCPY(&search_path[len], expr_separator, search_path_len-len);
    }

    return USP_ERR_OK;
}


/*********************************************************************//**
**
** CalcCliCombinedRole
**
** Calculates the combined_role to use when executing a CLI command
**
** \param   None
**
** \return  pointer to combined_role structure to use, or INTERNAL_ROLE if no permissions should be used
**
**************************************************************************/
combined_role_t *CalcCliCombinedRole(void)
{
    static combined_role_t cli_combined_role;
    int role_index;

    // Exit if role to use was the internal role
    if (cli_role_instance == 0)
    {
        return INTERNAL_ROLE;
    }

    // Exit if unable to convert the role instance number into the current internal index number
    role_index = DEVICE_CTRUST_RoleInstanceToIndex(cli_role_instance);
    if (role_index == INVALID)
    {
        SendCliResponse("CLI Role instance number (%d) does not match any of the entries in the Device.LocalAgent.ControllerTrust.Role table\n", cli_role_instance);
        SendCliResponse("Using INTERNAL_ROLE (allow all) instead\n");
        return INTERNAL_ROLE;
    }

    // Return a combined role that uses the role_index of the specified CLI role
    SendCliResponse("Executing CLI command using Role.%d\n", cli_role_instance);
    cli_combined_role.inherited_index = role_index;
    cli_combined_role.assigned_index = role_index;
    return &cli_combined_role;
}

/*********************************************************************//**
**
** SendCliResponse
**
** Sends the printf-style formatted message back to the CLI client. In the
** event that the buffer is too small, truncate the response, and make it
** clear that it has been truncated
**
** \param   fmt - printf style format
**
** \return  None
**
**************************************************************************/
void SendCliResponse(char *fmt, ...)
{
    #define MAX_CLI_RSP_LEN 4096
    va_list ap;
    char buf[MAX_CLI_RSP_LEN];
    int chars_written;

    // Write the message into the local store
    va_start(ap, fmt);
    chars_written = vsnprintf(buf, sizeof(buf), fmt, ap);
    buf[sizeof(buf)-1] = '\0';
    va_end(ap);

    // Ensure that if the message has been truncated, that it is reported
    if (chars_written >= sizeof(buf)-1)
    {
        #define TRUNCATED_STR "...[truncated]...\n"
        memcpy(&buf[sizeof(buf)-sizeof(TRUNCATED_STR)], TRUNCATED_STR, sizeof(TRUNCATED_STR));
    }

    CLI_SERVER_SendResponse(buf);
}

//------------------------------------------------------------------------------------------
// Code to test the SplitOffTrailingNumber() function
#if 0
char *split_off_trailing_test_cases[] =
{
    // Test case               // SearchPath          // InstanceNumber
    "Device.Object.",          "Device.Object.",      NULL,
    "Device.Object.10",        "Device.Object",       "10",
    "99",                      "99",                  NULL,
    "",                        "",                    NULL,
    "Device.Object10",         "Device.Object10",     NULL,
    "Device.Object,10",        "Device.Object,10",    NULL,

};

void TestSplitOffTrailingNumber(void)
{
    int i;
    char buf[256];
    char *instance_number;

    for (i=0; i < NUM_ELEM(split_off_trailing_test_cases); i+=3)
    {
        strcpy(buf, split_off_trailing_test_cases[i]);

        printf("[%d] %s\n", i/3, buf);
        instance_number = SplitOffTrailingNumber(buf);
        if (strcmp(buf, split_off_trailing_test_cases[i+1]) != 0)
        {
            printf("ERROR: Expected search path=%s, got %s\n", split_off_trailing_test_cases[i+1], buf);
        }

        if (instance_number == NULL)
        {
            if (split_off_trailing_test_cases[i+2] != NULL)
            {
                printf("ERROR: Expected instance number=%s, got NULL\n", split_off_trailing_test_cases[i+1]);
            }
        }
        else
        {
            if (split_off_trailing_test_cases[i+2] == NULL)
            {
                printf("ERROR: Expected instance number=NULL, got %s\n", instance_number);
            }
            else
            {
                if (strcmp(instance_number, split_off_trailing_test_cases[i+2]) != 0)
                {
                    printf("ERROR: Expected instance number=%s, got %s\n", split_off_trailing_test_cases[i+2], instance_number);
                }
            }
        }
    }
}
#endif

