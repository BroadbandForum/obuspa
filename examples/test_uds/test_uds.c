/*
 *
 * Copyright (C) 2025, Broadband Forum
 * Copyright (C) 2025, Vantiva Technologies SAS
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
 * \file test_uds.c
 *
 * Contains USP Commands for testing authentication over UDS and registration ACLs
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <obuspa/usp_err_codes.h>
#include <obuspa/vendor_defs.h>
#include <obuspa/core/common_defs.h>
#include <obuspa/vendor_api.h>
#include <obuspa/usp_api.h>
#include <obuspa/core/os_utils.h>
#include <obuspa/core/socket_set.h>
#include <obuspa/protobuf-c/usp-msg.pb-c.h>
#include <obuspa/protobuf-c/usp-record.pb-c.h>
#include <obuspa/core/text_utils.h>
#include <obuspa/core/msg_handler.h>
#include <obuspa/core/str_vector.h>
#include <obuspa/core/usp_service.h>

//------------------------------------------------------------------------------
// Misc Defines
#define SHORT_UDS_FRAME_PAYLOAD_LEN (64*1024)
#define SEND_TIMEOUT 5
#define FRAME_HEADER_SIZE   (sizeof(uds_frame_sync_bytes) + 4)   // Frame header is sync bytes + frame length
#define TLV_HEADER_SIZE 5                                        // TLV header contains 1 byte type + 4 byte length

//------------------------------------------------------------------------------
// Enumeration for type of UDS frame received. Do not modify the values of each entry - these are defined in the USP Specification
enum
{
    kUdsFrameType_Handshake = 1,
    kUdsFrameType_Error = 2,
    kUdsFrameType_UspRecord = 3,
    kUdsFrameType_Password = 4,
};

//------------------------------------------------------------------------------------
// Input and output args for Device.TestUDS.Auth()
static char *test_auth_input_args[] =
{
    "UdsPath",
    "Password",
    "EndpointID",
};

static char *test_auth_output_args[] =
{
    "Status",
};

//------------------------------------------------------------------------------------
// Input and output args for Device.TestUDS.Register()
static char *test_reg_input_args[] =
{
    "UdsPath",
    "Password",
    "EndpointID",
    "AllowPartial",
    "RegisterPaths",
};

static char *test_reg_output_args[] =
{
    "Status",
};

//------------------------------------------------------------------------------------
// Input conditions and output results for UDS Auth test
typedef struct
{
    int request_instance;   // Instance number of this operation in the Device.LocalAgent.Request table
    bool use_password;      // Determines whether the password should be put in the UDS frame or not
    char uds_path[512];
    char password[512];
    char endpoint_id[512];
} test_uds_auth_input_cond_t;

//------------------------------------------------------------------------------------
// Input conditions and output results for UDS Register test
typedef struct
{
    int request_instance;   // Instance number of this operation in the Device.LocalAgent.Request table
    bool use_password;      // Determines whether the password should be put in the UDS frame or not
    char uds_path[512];
    char password[512];
    char endpoint_id[512];
    bool allow_partial;
    char register_paths[MAX_DM_VALUE_LEN];
    str_vector_t registered_paths;
    str_vector_t failed_paths;
} test_uds_reg_input_cond_t;

//------------------------------------------------------------------------------
// Sync bytes at the start of every UDS frame
const unsigned char uds_frame_sync_bytes[4] = { 0x5F, 0x55, 0x53, 0x50 };

//------------------------------------------------------------------------------
// Global variables used by the tests
static pthread_mutex_t test_access_mutex;  // Protects access to variables below

int test_sock = -1;   // Socket that connects to the USP Broker
int cur_conn_id = 0;   // Counter used to determine whether test_sock refers to the current connection or not

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
int TestUdsAuth_Operate(dm_req_t *req, kv_vector_t *input_args, int instance);
void *TestUdsAuthThreadMain(void *param);
int TestUdsRegister_Operate(dm_req_t *req, kv_vector_t *input_args, int instance);
void *TestUdsRegThreadMain(void *param);
int UdsConnect(char *path, char *status, int status_len);
void CloseTestSock(void);
void UdsSend(unsigned char *frame, int frame_len, int conn_id, time_t timeout_time, char *status, int status_len);
void DropRxedFrames(int conn_id);
int UdsReceive(unsigned char *buf, int len, int conn_id, time_t timeout_time, char *status, int status_len);
int UdsReceiveFragment(unsigned char *buf, int len, int conn_id, time_t timeout_time, char *status, int status_len);
int CreateRegisterFrame(unsigned char *frame, int max_frame_len, test_uds_reg_input_cond_t *cond, char *broker_eid, char *msg_id, int msg_id_len);
void ValidateHandshakeResponse(unsigned char *frame, int frame_len, char *broker_eid, int broker_eid_len, char *status, int status_len);
int CreateHandshakeFrame(unsigned char *frame, int max_frame_len, char *endpoint_id, char *password, bool use_password);
int DoUdsTestHandshake(char *uds_path, char *endpoint_id, char *password, bool use_password, char *broker_eid, int broker_eid_len, char *status, int status_len);
void DoUdsTestRegister(int conn_id, test_uds_reg_input_cond_t *cond, char *broker_eid, char *status, int status_len);
bool IsRegisterResp(unsigned char *frame, int frame_len, char *msg_id, test_uds_reg_input_cond_t *cond, char *broker_eid, char *status, int status_len);

/*********************************************************************//**
**
** VENDOR_Init
**
** Initialises this component, and registers all parameters and vendor hooks, which it implements
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int VENDOR_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.TestUDS.Auth()", TestUdsAuth_Operate, NULL);
    err |= USP_REGISTER_OperationArguments("Device.TestUDS.Auth()", test_auth_input_args, NUM_ELEM(test_auth_input_args), test_auth_output_args, NUM_ELEM(test_auth_output_args));
    err |= USP_REGISTER_AsyncOperation("Device.TestUDS.Register()", TestUdsRegister_Operate, NULL);
    err |= USP_REGISTER_OperationArguments("Device.TestUDS.Register()", test_reg_input_args, NUM_ELEM(test_reg_input_args), test_reg_output_args, NUM_ELEM(test_reg_output_args));
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to create mutex protecting access to this subsystem
    err = OS_UTILS_InitMutex(&test_access_mutex);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** VENDOR_Start
**
** Called after data model has been registered and after instance numbers have been read from the USP database
** Typically this function is used to seed the data model with instance numbers or
** initialise internal data structures which require the data model to be running to access parameters
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int VENDOR_Start(void)
{
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** VENDOR_Stop
**
** Called when stopping USP agent gracefully, to free up memory and shutdown
** any vendor processes etc
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int VENDOR_Stop(void)
{
    OS_UTILS_LockMutex(&test_access_mutex);
    CloseTestSock();            // Cause the select() call in the thread to return immediately
    cur_conn_id++;              // when it has returned, it will take the mutex and find that the connection has changed, causing the thread to exit
    OS_UTILS_UnlockMutex(&test_access_mutex);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** TestUdsAuth_Operate
**
** Starts the UDS Auth test
** Checks that all mandatory parameters are present and valid, defaults non-mandatory parameters,
** then starts a thread to perform the test
**
** \param   req - pointer to structure identifying the operation in the data model
** \param   input_args - vector containing input arguments and their values
** \param   instance - instance number of this operation in the Device.LocalAgent.Request table
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int TestUdsAuth_Operate(dm_req_t *req, kv_vector_t *input_args, int instance)
{
    int err;
    char *p;
    test_uds_auth_input_cond_t *cond;
    int index;

    // Allocate input conditions to pass to thread
    cond = USP_MALLOC(sizeof(test_uds_auth_input_cond_t));
    memset(cond, 0, sizeof(test_uds_auth_input_cond_t));
    cond->request_instance = instance;

    // Get UdsPath
    p = USP_ARG_Get(input_args, "UdsPath", "/var/run/usp/sockets/authenticated/broker_controller/broker_controller_path");
    if (*p == '\0')
    {
        USP_ERR_SetMessage("%s: Empty UdsPath", __FUNCTION__);
        err = USP_ERR_COMMAND_FAILURE;
        goto exit;
    }
    USP_STRNCPY(cond->uds_path, p, sizeof(cond->uds_path));

    // Get Password
    index = KV_VECTOR_FindKey(input_args, "Password", 0);
    if (index == INVALID)
    {
        cond->use_password = false;
        USP_STRNCPY(cond->password, "Don't provide a password in UDS frame", sizeof(cond->password));  // Only used by debug
    }
    else
    {
        cond->use_password = true;
        USP_STRNCPY(cond->password, input_args->vector[index].value, sizeof(cond->password));
    }

    // Get EndpointID
    p = USP_ARG_Get(input_args, "EndpointID", "");
    USP_STRNCPY(cond->endpoint_id, p, sizeof(cond->endpoint_id));

    // Log the input conditions for the operation
    USP_LOG_Info("=== UDS Auth Test Conditions ===");
    USP_LOG_Info("UdsPath: %s", cond->uds_path);
    USP_LOG_Info("Password: %s", cond->password);
    USP_LOG_Info("EndpointID: %s", cond->endpoint_id);

    // Exit if unable to start a thread to perform this operation
    // NOTE: ownership of input conditions passes to the thread
    err = OS_UTILS_CreateThread("TestUdsAuth", TestUdsAuthThreadMain, cond);
    if (err != USP_ERR_OK)
    {
        err = USP_ERR_COMMAND_FAILURE;
        goto exit;
    }

exit:
    // Exit if an error occurred (freeing the input conditions)
    if (err != USP_ERR_OK)
    {
        USP_FREE(cond);
        return USP_ERR_COMMAND_FAILURE;
    }

    // Ownership of the input conditions has passed to the thread
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** TestUdsAuthThreadMain
**
** Main function for Device.TestUDS.Auth() Asynchronous operation thread
**
** \param   param - pointer to input conditions
**
** \return  NULL
**
**************************************************************************/
void *TestUdsAuthThreadMain(void *param)
{
    int err;
    test_uds_auth_input_cond_t *cond = (test_uds_auth_input_cond_t *) param;
    char status[512] = {0};
    int conn_id = -1;
    kv_vector_t *output_args;
    char *result_msg;

    // Exit if unable to signal that this operation is active
    err = USP_SIGNAL_OperationStatus(cond->request_instance, "Active");
    if (err != USP_ERR_OK)
    {
        USP_SNPRINTF(status, sizeof(status), "%s: USP_SIGNAL_OperationStatus() failed", __FUNCTION__);
        goto exit;
    }

    OS_UTILS_LockMutex(&test_access_mutex);

    conn_id = DoUdsTestHandshake(cond->uds_path, cond->endpoint_id, cond->password, cond->use_password, NULL, 0, status, sizeof(status));

exit:
    // Inform the protocol handler, that the operation has completed
    if (status[0] != '\0')
    {
        // Authentication failed. Store cause of failure in error message
        err = USP_ERR_COMMAND_FAILURE;
        result_msg = status;
        output_args = NULL;
    }
    else
    {
        // Authentication succeeded. Store status in output args
        err = USP_ERR_OK;
        result_msg = NULL;
        output_args = USP_ARG_Create();
        USP_ARG_Add(output_args, "Status", "Authentication successful");
    }

    USP_SIGNAL_OperationComplete(cond->request_instance, err, result_msg, output_args);

    // Free the input conditions
    USP_FREE(cond);

    // If successful, keep this thread running until another invocation comes along
    // Otherwise, a failed handshake should cause a disconnect
    if (status[0] == '\0')
    {
        DropRxedFrames(conn_id);
    }

    // Ensure that socket is closed, unless it's being used by another invocation
    if (conn_id == cur_conn_id)
    {
        CloseTestSock();
    }

    OS_UTILS_UnlockMutex(&test_access_mutex);

    return NULL;
}

/*********************************************************************//**
**
** TestUdsRegister_Operate
**
** Starts the UDS Register test
** Checks that all mandatory parameters are present and valid, defaults non-mandatory parameters,
** then sends a register command
**
** \param   req - pointer to structure identifying the operation in the data model
** \param   input_args - vector containing input arguments and their values
** \param   instance - instance number of this operation in the Device.LocalAgent.Request table
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int TestUdsRegister_Operate(dm_req_t *req, kv_vector_t *input_args, int instance)
{
    int err;
    char *p;
    test_uds_reg_input_cond_t *cond;
    int index;

    // Allocate input conditions to pass to thread
    cond = USP_MALLOC(sizeof(test_uds_reg_input_cond_t));
    memset(cond, 0, sizeof(test_uds_reg_input_cond_t));
    STR_VECTOR_Init(&cond->registered_paths);
    STR_VECTOR_Init(&cond->failed_paths);
    cond->request_instance = instance;

    // Exit if AllowPartial is not a boolean value
    err = USP_ARG_GetBool(input_args, "AllowPartial", false, &cond->allow_partial);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Get UdsPath
    p = USP_ARG_Get(input_args, "UdsPath", "/var/run/usp/sockets/authenticated/broker_controller/broker_controller_path");
    if (*p == '\0')
    {
        USP_ERR_SetMessage("%s: Empty UdsPath", __FUNCTION__);
        err = USP_ERR_COMMAND_FAILURE;
        goto exit;
    }
    USP_STRNCPY(cond->uds_path, p, sizeof(cond->uds_path));

    // Get Password
    index = KV_VECTOR_FindKey(input_args, "Password", 0);
    if (index == INVALID)
    {
        cond->use_password = false;
        USP_STRNCPY(cond->password, "Don't provide a password in UDS frame", sizeof(cond->password));  // Only used by debug
    }
    else
    {
        cond->use_password = true;
        USP_STRNCPY(cond->password, input_args->vector[index].value, sizeof(cond->password));
    }

    // Get EndpointID
    p = USP_ARG_Get(input_args, "EndpointID", "");
    USP_STRNCPY(cond->endpoint_id, p, sizeof(cond->endpoint_id));

    // Get Paths to register
    p = USP_ARG_Get(input_args, "RegisterPaths", "");
    USP_STRNCPY(cond->register_paths, p, sizeof(cond->register_paths));

    // Log the input conditions for the operation
    USP_LOG_Info("=== UDS Register Test Conditions ===");
    USP_LOG_Info("UdsPath: %s", cond->uds_path);
    USP_LOG_Info("Password: %s", cond->password);
    USP_LOG_Info("EndpointID: %s", cond->endpoint_id);
    USP_LOG_Info("AllowPartial: %d", cond->allow_partial);
    USP_LOG_Info("RegisterPaths: %s", cond->register_paths);

    // Exit if unable to start a thread to perform this operation
    // NOTE: ownership of input conditions passes to the thread
    err = OS_UTILS_CreateThread("TestUdsReg", TestUdsRegThreadMain, cond);
    if (err != USP_ERR_OK)
    {
        err = USP_ERR_COMMAND_FAILURE;
        goto exit;
    }

exit:
    // Exit if an error occurred (freeing the input conditions)
    if (err != USP_ERR_OK)
    {
        USP_FREE(cond);
        return USP_ERR_COMMAND_FAILURE;
    }

    // Ownership of the input conditions has passed to the thread
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** TestUdsRegThreadMain
**
** Main function for Device.TestUDS.Register() Asynchronous operation thread
**
** \param   param - pointer to input conditions
**
** \return  NULL
**
**************************************************************************/
void *TestUdsRegThreadMain(void *param)
{
    int err;
    test_uds_reg_input_cond_t *cond = (test_uds_reg_input_cond_t *) param;
    char status[512] = {0};
    char broker_eid[512] = {0};
    int conn_id = -1;
    kv_vector_t *output_args;
    char *result_msg;
    char *failed_paths;
    char *registered_paths;

    // Exit if unable to signal that this operation is active
    err = USP_SIGNAL_OperationStatus(cond->request_instance, "Active");
    if (err != USP_ERR_OK)
    {
        USP_SNPRINTF(status, sizeof(status), "%s: USP_SIGNAL_OperationStatus() failed", __FUNCTION__);
        goto exit;
    }

    OS_UTILS_LockMutex(&test_access_mutex);

    conn_id = DoUdsTestHandshake(cond->uds_path, cond->endpoint_id, cond->password, cond->use_password, broker_eid, sizeof(broker_eid), status, sizeof(status));
    if (conn_id == -1)
    {
        USP_ASSERT(status[0] != '\0');
        goto exit;
    }

    DoUdsTestRegister(conn_id, cond, broker_eid, status, sizeof(status));

exit:
    // Inform the protocol handler, that the operation has completed
    if (status[0] != '\0')
    {
        // Authentication failed. Store cause of failure in error message
        err = USP_ERR_COMMAND_FAILURE;
        result_msg = status;
        output_args = NULL;
    }
    else
    {
        // Registration succeeded. Store status in output args
        err = USP_ERR_OK;
        result_msg = NULL;
        output_args = USP_ARG_Create();
        if (cond->failed_paths.num_entries == 0)
        {
            USP_ARG_Add(output_args, "Status", "Registration successful");
        }
        else
        {
            USP_ARG_Add(output_args, "Status", "Register response received with some failed paths");
        }

        // Store registered and failed paths in output args
        registered_paths = STR_VECTOR_ToList(&cond->registered_paths);
        failed_paths = STR_VECTOR_ToList(&cond->failed_paths);
        USP_ARG_Add(output_args, "RegisteredPaths", registered_paths);
        USP_ARG_Add(output_args, "FailedPaths", failed_paths);
        USP_FREE(registered_paths);
        USP_FREE(failed_paths);
    }

    USP_SIGNAL_OperationComplete(cond->request_instance, err, result_msg, output_args);

    // Free the input conditions
    STR_VECTOR_Destroy(&cond->registered_paths);
    STR_VECTOR_Destroy(&cond->failed_paths);
    USP_FREE(cond);

    // Keep this thread running until another invocation comes along (since a failed register should not cause a disconnect)
    DropRxedFrames(conn_id);

    // Ensure that socket is closed, unless it's being used by another invocation
    if (conn_id == cur_conn_id)
    {
        CloseTestSock();
    }

    OS_UTILS_UnlockMutex(&test_access_mutex);

    return NULL;
}

/*********************************************************************//**
**
** DoUdsTestRegister
**
** Sends a register request and waits for a register response, validating it
**
** \param   conn_id - identifies the test invocation that this frame is meant to be for
** \param   cond - arguments to put in the register request
** \param   broker_eid - Endpoint ID of the USP Broker
** \param   status - pointer to buffer to return an error in
** \param   status_len - length of buffer to return an error in
**
** \return  None (errors are indicated in status)
**
**************************************************************************/
void DoUdsTestRegister(int conn_id, test_uds_reg_input_cond_t *cond, char *broker_eid, char *status, int status_len)
{
    unsigned char frame[SHORT_UDS_FRAME_PAYLOAD_LEN];
    int frame_len;
    char msg_id[64];
    bool is_register_resp = false;
    time_t register_timeout_time;

    // Exit if unable to create Register frame
    frame_len = CreateRegisterFrame(frame, sizeof(frame), cond, broker_eid, msg_id, sizeof(msg_id));
    if (frame_len == -1)
    {
        USP_SNPRINTF(status, status_len, "%s: Handshake frame too large", __FUNCTION__);
        return;
    }

    // Exit if unable to send Register frame
    UdsSend(frame, frame_len, conn_id, time(NULL) + SEND_TIMEOUT, status, status_len);
    if (status[0] != '\0')
    {
        return;
    }

    // Receive all UDS frames, waiting for one containing the register response
    USP_LOG_Info("Waiting for Register response");
    #define REGISTER_TIMEOUT 30
    register_timeout_time = time(NULL) + REGISTER_TIMEOUT;
    while (is_register_resp == false)
    {
        // Exit if timed out waiting for register response
        if (time(NULL) >= register_timeout_time)
        {
            USP_SNPRINTF(status, status_len, "%s: Timed out waiting for register response", __FUNCTION__);
            return;
        }

        // Exit if failed to receive a frame from the USP Broker in response to this register frame
        frame_len = UdsReceive(frame, sizeof(frame)-1, conn_id, END_OF_TIME, status, status_len);  // Minus 1 to allow us to add a terminating '\0' character if the frame contains an error string in ValidateHandshakeResponse()
        if (frame_len == -1)
        {
            USP_ASSERT(status[0] !='\0');
            return;
        }

        // Exit if the frame failed to parse
        is_register_resp = IsRegisterResp(frame, frame_len, msg_id, cond, broker_eid, status, status_len);
        if (status[0] != '\0')
        {
            return;
        }
    }
}

/*********************************************************************//**
**
** IsRegisterResp
**
** Determines whether the specified frame contains a response to the register request
** and parses it if it does
**
** \param   frame - received UDS frame data
** \param   frame_len - size of received UDS frame data
** \param   msg_id - identifier for this response
** \param   cond - arguments to put in the register request
** \param   broker_eid - Endpoint ID of the USP Broker
** \param   status - pointer to buffer to return an error in
** \param   status_len - length of buffer to return an error in
**
** \return  None (errors are indicated in status)
**
**************************************************************************/
bool IsRegisterResp(unsigned char *frame, int frame_len, char *msg_id, test_uds_reg_input_cond_t *cond, char *broker_eid, char *status, int status_len)
{
    int i;
    unsigned char *p;
    int payload_len;
    int tlv_type;
    int tlv_len;
    UspRecord__Record *rec = NULL;
    Usp__Msg *usp = NULL;
    ProtobufCBinaryData *payload;
    Usp__Error *usp_err;
    bool is_register_resp = false;
    Usp__RegisterResp *reg;
    Usp__RegisterResp__RegisteredPathResult *rpr;

    USP_ASSERT(frame_len >= FRAME_HEADER_SIZE + TLV_HEADER_SIZE);

    p = &frame[FRAME_HEADER_SIZE];
    payload_len = frame_len - FRAME_HEADER_SIZE;

    // Exit if frame is not large enough to contain the TLV
    tlv_type = READ_BYTE(p, payload_len);
    tlv_len = READ_4_BYTES(p, payload_len);
    if (FRAME_HEADER_SIZE + TLV_HEADER_SIZE + tlv_len > frame_len)
    {
        USP_LOG_Info("Ignoring received UDS frame: TLV was longer than frame");
        goto exit;
    }

    // Exit if frame received from USP Broker was an error frame (ignoring it)
    if (tlv_type == kUdsFrameType_Error)
    {
        frame[frame_len] = '\0';
        USP_LOG_Info("Ignoring received UDS frame containing ERROR: %s", &frame[FRAME_HEADER_SIZE+TLV_HEADER_SIZE]);
        goto exit;
    }

    // Exit if frame received from USP Broker was not a USP record frame (ignoring it)
    if (tlv_type != kUdsFrameType_UspRecord)
    {
        USP_LOG_Info("Ignoring received UDS frame containing TLV type=%d", tlv_type);
        goto exit;
    }

    // Exit if unable to unpack the USP record
    rec = usp_record__record__unpack(pbuf_allocator, tlv_len, p);
    if (rec == NULL)
    {
        USP_LOG_Info("Ignoring received UDS frame: USP Record corrupted");
        goto exit;
    }

    // Exit if the USP record is not addressed to the test's endpoint
    if (strcmp(rec->to_id, cond->endpoint_id) != 0)
    {
        USP_LOG_Info("Ignoring received USP record: Not addressed to test endpoint (%s)", rec->to_id);
        goto exit;
    }

    // Exit if the USP record is not from the USP Broker
    if (strcmp(rec->from_id, broker_eid) != 0)
    {
        USP_LOG_Info("Ignoring received USP record: Not from USP Broker (%s)", rec->from_id);
        goto exit;
    }

    // Exit if the USP record is not the expected USP record type
    // NOTE: We remove any UDS connect records here
    if (rec->record_type_case != USP_RECORD__RECORD__RECORD_TYPE_NO_SESSION_CONTEXT)
    {
        USP_LOG_Info("Ignoring received USP record: Unwanted Record type (%d)", rec->record_type_case);
        goto exit;
    }

    // Exit if unable to unpack the USP message
    payload = &rec->no_session_context->payload;
    usp = usp__msg__unpack(pbuf_allocator, payload->len, payload->data);
    if (usp == NULL)
    {
        USP_LOG_Info("Ignoring received USP record: USP Message corrupted");
        goto exit;
    }

    // Exit if the USP Message is not a response to the Register request that we sent
    if (strcmp(usp->header->msg_id, msg_id) != 0)
    {
        USP_LOG_Info("Ignoring received USP message: Unwanted msg_id=%s", usp->header->msg_id);
        goto exit;
    }

    // From now on, the register response has been received
    is_register_resp = true;

    // Exit if the response is not one of the expected USP message types
    if ((usp->header->msg_type != USP__HEADER__MSG_TYPE__REGISTER_RESP) && (usp->header->msg_type != USP__HEADER__MSG_TYPE__ERROR))
    {
        USP_LOG_Info("Received USP response: Unexpected Message type (%d)", usp->header->msg_type);
        goto exit;
    }

    // Exit if the response is a USP Error, returning the error in status
    if (usp->header->msg_type == USP__HEADER__MSG_TYPE__ERROR)
    {
        if (usp->body->msg_body_case != USP__BODY__MSG_BODY_ERROR)
        {
            USP_LOG_Info("Ignoring received USP response: Received Error but msg_body_case=%d", usp->body->msg_body_case);
            goto exit;
        }

        usp_err = usp->body->error;
        USP_SNPRINTF(status, status_len, "Received USP Error response (err=%d): %s", usp_err->err_code, usp_err->err_msg);
        goto exit;
    }

    // Exit if Register response is badly formed
    USP_ASSERT(usp->header->msg_type == USP__HEADER__MSG_TYPE__REGISTER_RESP);
    if (usp->body->msg_body_case != USP__BODY__MSG_BODY_RESPONSE)
    {
        USP_LOG_Info("Ignoring received USP response: Received RegisterResponse but msg_body_case=%d", usp->body->msg_body_case);
        goto exit;
    }

    // Log all registration errors
    reg = usp->body->response->register_resp;
    for (i=0; i < reg->n_registered_path_results; i++)
    {
        rpr = reg->registered_path_results[i];
        switch (rpr->oper_status->oper_status_case)
        {
            case USP__REGISTER_RESP__REGISTERED_PATH_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_FAILURE:
                STR_VECTOR_Add(&cond->failed_paths, rpr->requested_path);
                break;

            case USP__REGISTER_RESP__REGISTERED_PATH_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_SUCCESS:
                STR_VECTOR_Add(&cond->registered_paths, rpr->requested_path);
                break;

            default:
            case USP__REGISTER_RESP__REGISTERED_PATH_RESULT__OPERATION_STATUS__OPER_STATUS__NOT_SET:
                USP_LOG_Info("Received USP Register response contains unknown oper_status_case for requested_path=%s'", rpr->requested_path);
                break;
        }
    }

exit:
    // Free Protobuf structures
    if (usp != NULL)
    {
        usp__msg__free_unpacked(usp, pbuf_allocator);
    }

    if (rec != NULL)
    {
        usp_record__record__free_unpacked(rec, pbuf_allocator);
    }

    return is_register_resp;
}

/*********************************************************************//**
**
** DoUdsTestHandshake
**
** Connects to the specified UDS path, Sends a handshake and waits for a handshake response, validating it
**
** \param   uds_path - Unix domain socket path to connect to
** \param   endpoint_id - EndpointID of this component in the test
** \param   password - password to authenticate this USP Service
** \param   use_password - determines whether the password should be placed in the UDS frame
** \param   broker_eid - pointer to buffer in which to return the broker's endpoint_id, or NULL if this is not required
** \param   broker_eid_len - size of buffer in which to return the broker's endpoint_id
** \param   status - pointer to buffer to return an error in
** \param   status_len - length of buffer to return an error in
**
** \return  conn_id or -1 if an error occurred
**
**************************************************************************/
int DoUdsTestHandshake(char *uds_path, char *endpoint_id, char *password, bool use_password, char *broker_eid, int broker_eid_len, char *status, int status_len)
{
    int conn_id;
    int frame_len;
    unsigned char frame[SHORT_UDS_FRAME_PAYLOAD_LEN];

    // Close the socket left connected from any previous test
    CloseTestSock();

    // Exit if unable to create the socket
    conn_id = UdsConnect(uds_path, status, status_len);
    if (status[0] !='\0')
    {
        return -1;
    }

    // Exit if we can't form the Handshake frame because it's too large
    frame_len = CreateHandshakeFrame(frame, sizeof(frame), endpoint_id, password, use_password);
    if (frame_len > sizeof(frame))
    {
        USP_SNPRINTF(status, status_len, "%s: Handshake frame too large", __FUNCTION__);
        return -1;
    }

    // Exit if unable to send the frame
    USP_LOG_Info("Sending UDS Handshake");
    UdsSend(frame, frame_len, conn_id, time(NULL) + SEND_TIMEOUT, status, status_len);
    if (status[0] != '\0')
    {
        return -1;
    }

    // Exit if failed to receive a frame from the USP Broker in response to this handshake frame
    #define HANDSHAKE_TIMEOUT 5
    USP_LOG_Info("Waiting for UDS Handshake response");
    frame_len = UdsReceive(frame, sizeof(frame)-1, conn_id, time(NULL) + HANDSHAKE_TIMEOUT, status, status_len);  // Minus 1 to allow us to add a terminating '\0' character if the frame contains an error string in ValidateHandshakeResponse()
    if (frame_len == -1)
    {
        USP_ASSERT(status[0] !='\0');
        return -1;
    }

    // Exit if frame was not a valid Handshake response
    ValidateHandshakeResponse(frame, frame_len, broker_eid, broker_eid_len, status, status_len);
    if (status[0] != '\0')
    {
        return -1;
    }

    return conn_id;
}

/*********************************************************************//**
**
** CreateHandshakeFrame
**
** Writes a UDS frame containing a Register request into the specified buffer
**
** \param   frame - pointer to buffer in which to write frame
** \param   max_frame_len - length of buffer in which to write frame
** \param   endpoint_id - EndpointID of this component in the test
** \param   password - password to authenticate this USP Service
** \param   use_password - determines whether the password should be placed in the UDS frame
**
** \return  length of UDS frame formed, or -1 if an error occurred
**
**************************************************************************/
int CreateHandshakeFrame(unsigned char *frame, int max_frame_len, char *endpoint_id, char *password, bool use_password)
{
    int eid_len;
    int pw_len = 0;
    int tlv_len;   // length of all TLVs in the frame
    int frame_len;
    unsigned char *p;

    // UDS Client initiates handshake process, so calculate size of handshake frame
    eid_len = strlen(endpoint_id);
    tlv_len = TLV_HEADER_SIZE + eid_len;

    if (use_password)
    {
        pw_len = strlen(password);
        tlv_len += TLV_HEADER_SIZE + pw_len;
    }

    // Exit if we can't form the frame because it's too large
    frame_len = FRAME_HEADER_SIZE + tlv_len;
    if (frame_len > max_frame_len)
    {
        return -1;
    }

    // Construct Handshake frame
    p = frame;
    WRITE_N_BYTES(p, uds_frame_sync_bytes, sizeof(uds_frame_sync_bytes));
    WRITE_4_BYTES(p, tlv_len);
    WRITE_BYTE(p, kUdsFrameType_Handshake);
    WRITE_4_BYTES(p, eid_len);
    WRITE_N_BYTES(p, endpoint_id, eid_len);

    if (use_password)
    {
        WRITE_BYTE(p, kUdsFrameType_Password);
        WRITE_4_BYTES(p, pw_len);
        WRITE_N_BYTES(p, password, pw_len);
    }

    return frame_len;
}

/*********************************************************************//**
**
** CreateRegisterFrame
**
** Writes a UDS frame containing a Register request into the specified buffer
**
** \param   frame - pointer to buffer in which to write frame
** \param   max_frame_len - length of buffer in which to write frame
** \param   broker_eid - Endpoint ID of the USP Broker
** \param   msg_id - pointer to buffer in which to return the identifier for this request
** \param   msg_id_len - length of buffer in which to return the identifier for this request
**
** \return  length of UDS frame formed, or -1 if an error occurred
**
**************************************************************************/
int CreateRegisterFrame(unsigned char *frame, int max_frame_len, test_uds_reg_input_cond_t *cond, char *broker_eid, char *msg_id, int msg_id_len)
{
    Usp__Msg *usp;
    static int count = 0;
    str_vector_t sv;
    int pbuf_len;
    unsigned char *pbuf;
    int size;
    int len;
    int frame_len;
    int tlv_len;   // length of all TLVs in the frame
    UspRecord__NoSessionContextRecord no_session_ctx;
    UspRecord__Record rec;
    unsigned char *p;

    // Create USP Register message
    count++;
    USP_SNPRINTF(msg_id, msg_id_len, "TEST-REGISTER-%d", count);
    TEXT_UTILS_SplitString(cond->register_paths, &sv, ",");
    usp = USP_SERVICE_CreateRegisterReq(msg_id, cond->allow_partial, sv.vector, sv.num_entries);
    STR_VECTOR_Destroy(&sv);

    // Serialize the USP message into a buffer
    pbuf_len = usp__msg__get_packed_size(usp);
    pbuf = USP_MALLOC(pbuf_len);
    size = usp__msg__pack(usp, pbuf);
    usp__msg__free_unpacked(usp, pbuf_allocator);    // Free the message structure, since we've serialized it

    USP_ASSERT(size == pbuf_len);          // If these are not equal, then we may have had a buffer overrun, so terminate

    // Fill in No session context structure
    usp_record__no_session_context_record__init(&no_session_ctx);
    no_session_ctx.payload.data = pbuf;
    no_session_ctx.payload.len = pbuf_len;
    USP_ASSERT(no_session_ctx.payload.len > 0);  // A NoSessionContext MUST have content

    // Fill in the USP Record structure
    // NOTE: This is all statically allocated (or owned elsewhere), so no need to free
    usp_record__record__init(&rec);
    rec.version = AGENT_CURRENT_PROTOCOL_VERSION;
    rec.to_id = broker_eid;
    rec.from_id = cond->endpoint_id;
    rec.payload_security = USP_RECORD__RECORD__PAYLOAD_SECURITY__PLAINTEXT;
    rec.record_type_case = USP_RECORD__RECORD__RECORD_TYPE_NO_SESSION_CONTEXT;
    rec.no_session_context = &no_session_ctx;

    // Exit if frame would be too large for the supplied buffer
    len = usp_record__record__get_packed_size(&rec);
    tlv_len = TLV_HEADER_SIZE + len;
    frame_len = FRAME_HEADER_SIZE + tlv_len;
    if (frame_len > max_frame_len)
    {
        USP_FREE(pbuf);
        return -1;
    }

    // Write frame and TLV headers
    p = frame;
    WRITE_N_BYTES(p, uds_frame_sync_bytes, sizeof(uds_frame_sync_bytes));
    WRITE_4_BYTES(p, tlv_len);
    WRITE_BYTE(p, kUdsFrameType_UspRecord);
    WRITE_4_BYTES(p, len);

    // Serialize the protobuf record structure directly into the frame
    size = usp_record__record__pack(&rec, p);
    USP_ASSERT(size == len);  // If these are not equal, then we may have had a buffer overrun, so terminate

    // Free the serialized USP Message because it is now encapsulated in USP Record messages.
    USP_FREE(pbuf);

    return frame_len;
}

/*********************************************************************//**
**
** ValidateHandshakeResponse
**
** Validates that the farme is a handshake frame and extracts the EndpointID of the USP Broker from it
**
** \param   frame - received UDS frame data
** \param   frame_len - size of received UDS frame data
** \param   broker_eid - pointer to buffer in which to return the broker's endpoint_id, or NULL if this is not required
** \param   broker_eid_len - size of buffer in which to return the broker's endpoint_id
** \param   status - pointer to buffer to return an error in
** \param   status_len - length of buffer to return an error in
**
** \return  None (errors are indicated in status)
**
**************************************************************************/
void ValidateHandshakeResponse(unsigned char *frame, int frame_len, char *broker_eid, int broker_eid_len, char *status, int status_len)
{
    unsigned char *p;
    int payload_len;
    int tlv_type;
    int tlv_len;

    USP_ASSERT(frame_len >= FRAME_HEADER_SIZE + TLV_HEADER_SIZE);

    p = &frame[FRAME_HEADER_SIZE];
    payload_len = frame_len - FRAME_HEADER_SIZE;

    // Exit if frame received from USP Broker was an error frame
    tlv_type = READ_BYTE(p, payload_len);
    if (tlv_type == kUdsFrameType_Error)
    {
        USP_LOG_Info("Received UDS ERROR response");
        frame[frame_len] = '\0';
        USP_SNPRINTF(status, status_len, "%s: Received ERROR frame: %s", __FUNCTION__, &frame[FRAME_HEADER_SIZE+TLV_HEADER_SIZE]);
        return;
    }

    // Exit if frame received from USP Broker was not a handshake frame
    if (tlv_type != kUdsFrameType_Handshake)
    {
        USP_SNPRINTF(status, status_len, "%s: First frame received was not Handshake (type=%d)", __FUNCTION__, tlv_type);
        return;
    }

    USP_LOG_Info("Received UDS Handshake response");

    // Exit if not interested in the Broker's Endpoint ID
    if (broker_eid == NULL)
    {
        return;
    }

    // Exit if TLV length (or frame length) is badly formed
    tlv_len = READ_4_BYTES(p, payload_len);
    if (FRAME_HEADER_SIZE + TLV_HEADER_SIZE + tlv_len > frame_len)
    {
        USP_SNPRINTF(status, status_len, "%s: Length of Broker's EID is longer than the size of the received frame", __FUNCTION__);
        return;
    }

    // Extract the Broker's EndpointID from the handshake frame
    tlv_len = MIN(tlv_len, broker_eid_len-1);
    memcpy(broker_eid, p, tlv_len);
    broker_eid[tlv_len] = '\0';
}

/*********************************************************************//**
**
** UdsConnect
**
** Main function for TestUdsAuth Asynchronous operation thread
**
** \param   path - Filesystem path to unix domain socket to connect to
** \param   status - pointer to buffer to return an error in
** \param   status_len - length of buffer to return an error in
**
** \return  conn_id or -1 if an error occurred
**
**************************************************************************/
int UdsConnect(char *path, char *status, int status_len)
{
    int err;
    struct sockaddr_un addr;
    int conn_id;
    fd_set writefds;
    struct timeval timeout;
    int num_sockets;
    int so_err;
    int result;
    socklen_t so_len = sizeof(so_err);

    // Save the count of the number of tests started. If cur_conn_id changes from this value, then this test should stop running
    cur_conn_id++;
    conn_id = cur_conn_id;

    // Exit if unable to create a UDS socket
    test_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (test_sock == -1)
    {
        USP_SNPRINTF(status, status_len, "%s: cannot create socket %s", __FUNCTION__, path);
        return -1;
    }

    // Exit if unable to set the socket as non blocking
    // We do this before connecting so that we can timeout on connect taking too long
    result = fcntl(test_sock, F_SETFL, O_NONBLOCK);
    if (result == -1)
    {
        USP_SNPRINTF(status, status_len, "%s: cannot set socket %s to non-blocking", __FUNCTION__, path);
        return -1;
    }

    // Fill in the unix domain socket path
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    USP_STRNCPY(addr.sun_path, path, sizeof(addr.sun_path));

    // Exit if unable to connect
    result = connect(test_sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
    if ((result == -1) && (errno != EINPROGRESS))
    {
        USP_SNPRINTF(status, status_len, "%s: cannot connect to socket path %s", __FUNCTION__, path);
        CloseTestSock();
        return -1;
    }

    // Set up arguments for the select() call
    #define CONNECT_TIMEOUT 5
    FD_ZERO(&writefds);
    FD_SET(test_sock, &writefds);
    timeout.tv_sec = CONNECT_TIMEOUT;
    timeout.tv_usec = 0;

    // Exit if the connect timed out
    OS_UTILS_UnlockMutex(&test_access_mutex);
    num_sockets = select(test_sock + 1, NULL, &writefds, NULL, &timeout);
    OS_UTILS_LockMutex(&test_access_mutex);
    if (num_sockets == 0)
    {
        USP_SNPRINTF(status, status_len, "%s: connect timed out", __FUNCTION__);
        CloseTestSock();
        return -1;
    }

    // Exit if unable to determine whether the connect was successful or not
    err = getsockopt(test_sock, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
    if (err == -1)
    {
        USP_SNPRINTF(status, status_len, "%s: getsockopt failed", __FUNCTION__);
        CloseTestSock();
        return -1;
    }

    // Exit if connect was not successful
    if (so_err != 0)
    {
        USP_SNPRINTF(status, status_len, "%s: async connect failed", __FUNCTION__);
        CloseTestSock();
        return -1;
    }

    return conn_id;
}

/*********************************************************************//**
**
** UdsSend
**
** Sends a UDS frame
**
** \param   frame - pointer to buffer containing the frame to send
** \param   frame_len - length of the frame to send
** \param   conn_id - identifies the test invocation that this frame is meant to be for
** \param   timeout_time - absolute time at which to abort the send
** \param   status - pointer to buffer to return an error in
** \param   status_len - length of buffer to return an error in
**
** \return  None (errors are indicated in status)
**
**************************************************************************/
void UdsSend(unsigned char *frame, int frame_len, int conn_id, time_t timeout_time, char *status, int status_len)
{
    int num_bytes;
    int offset = 0;
    int num_sockets;
    socket_set_t set;

    // Read until fragment buffer is full
    while (offset < frame_len)
    {
        #define SELECT_WRITE_TIMEOUT_MS 200
        SOCKET_SET_Clear(&set);
        SOCKET_SET_AddSocketToSendTo(test_sock, SELECT_WRITE_TIMEOUT_MS, &set);

        // Perform the select (with timeout)
        OS_UTILS_UnlockMutex(&test_access_mutex);
        num_sockets = SOCKET_SET_Select(&set);
        OS_UTILS_LockMutex(&test_access_mutex);

        // Exit if we're now running a different test invocation
        if (conn_id != cur_conn_id)
        {
            USP_SNPRINTF(status, status_len, "%s: Test terminated due to newer invocation", __FUNCTION__);
            return;
        }

        // Exit if an error occurred performing the select
        if (num_sockets == -1)
        {
            USP_SNPRINTF(status, status_len, "%s: Select failed: %s", __FUNCTION__, strerror(errno));
            CloseTestSock();
            return;
        }

        // Exit if timeout occurred
        if (time(NULL) >= timeout_time)
        {
            USP_SNPRINTF(status, status_len, "%s: Failed to send: Timeout", __FUNCTION__);
            CloseTestSock();
            return;
        }

        // Write bytes if possible
        if (num_sockets == 1)
        {
            num_bytes = send(test_sock, &frame[offset], frame_len - offset, 0);
            if (num_bytes == -1)
            {
                if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
                {
                    // Exit if an error occurred during sending
                    USP_SNPRINTF(status, status_len, "%s: Failed to send: %s", __FUNCTION__, strerror(errno));
                    CloseTestSock();
                    return;
                }
            }
            else
            {
                offset += num_bytes;
            }
        }

    }
}

/*********************************************************************//**
**
** UdsReceive
**
** Receives a UDS frame
**
** \param   buf - pointer to buffer in which to return the frame
** \param   len - length of the buffer in which to return the frame
** \param   conn_id - identifies the test invocation that this frame is meant to be for
** \param   timeout_time - absolute time at which to abort the receive
** \param   res - pointer to structure containing the test's results
** \param   status - pointer to buffer to return an error in
** \param   status_len - length of buffer to return an error in
**
** \return  Number of bytes in the frame stored in the buffer if successful, otherwise -1 if an error occurred
**
**************************************************************************/
int UdsReceive(unsigned char *buf, int len, int conn_id, time_t timeout_time, char *status, int status_len)
{
    int bytes_read;
    unsigned char *p;
    int payload_len;

    USP_ASSERT(len > FRAME_HEADER_SIZE);

    // Exit if failed to read frame header
    bytes_read = UdsReceiveFragment(buf, FRAME_HEADER_SIZE, conn_id, timeout_time, status, status_len);
    if (bytes_read == -1)
    {
        return -1;
    }
    USP_ASSERT(bytes_read == FRAME_HEADER_SIZE);

    // Exit if frame sync bytes are incorrect
    if (memcmp(buf, uds_frame_sync_bytes, sizeof(uds_frame_sync_bytes)) != 0)
    {
        USP_SNPRINTF(status, status_len, "%s: Sync bytes incorrect", __FUNCTION__);
        CloseTestSock();
        return -1;
    }

    // Exit if payload length is greater than the remaining buffer to return it in
    p = &buf[sizeof(uds_frame_sync_bytes)];
    payload_len = CONVERT_4_BYTES(p);
    if (payload_len > len - FRAME_HEADER_SIZE)
    {
        USP_SNPRINTF(status, status_len, "%s: Payload length too large (%d)", __FUNCTION__, payload_len);
        CloseTestSock();
        return -1;
    }

    // Exit if payload length is too small for even a single TLV
    if (payload_len < TLV_HEADER_SIZE)
    {
        USP_SNPRINTF(status, status_len, "%s: Payload length too small (%d)", __FUNCTION__, payload_len);
        CloseTestSock();
        return -1;
    }

    // Exit if failed to read frame payload (ie series of TLVs)
    bytes_read = UdsReceiveFragment( &buf[FRAME_HEADER_SIZE], payload_len, conn_id, timeout_time, status, status_len);
    if (bytes_read == -1)
    {
        return -1;
    }
    USP_ASSERT(bytes_read == payload_len);

    return FRAME_HEADER_SIZE + payload_len;
}

/*********************************************************************//**
**
** UdsReceiveFragment
**
** Receives the specified number of bytes from a UDS frame
**
** \param   buf - pointer to buffer in which to return the fragment
** \param   len - length of the buffer in which to return the fragment
** \param   conn_id - identifies the test invocation that this fragment is meant to be for
** \param   timeout_time - absolute time at which to abort the receive
** \param   status - pointer to buffer to return an error in
** \param   status_len - length of buffer to return an error in
**
** \return  Number of bytes read if successful, otherwise -1 if an error occurred
**
**************************************************************************/
int UdsReceiveFragment(unsigned char *buf, int len, int conn_id, time_t timeout_time, char *status, int status_len)
{
    int num_bytes = 0;
    int offset = 0;
    int num_sockets;
    socket_set_t set;

    // Read until fragment buffer is full
    while (offset < len)
    {
        #define SELECT_READ_TIMEOUT_MS 200
        SOCKET_SET_Clear(&set);
        SOCKET_SET_AddSocketToReceiveFrom(test_sock, SELECT_READ_TIMEOUT_MS, &set);

        // Perform the select (with timeout)
        OS_UTILS_UnlockMutex(&test_access_mutex);
        num_sockets = SOCKET_SET_Select(&set);
        OS_UTILS_LockMutex(&test_access_mutex);

        // Exit if we're now running a different test invocation
        if (conn_id != cur_conn_id)
        {
            USP_SNPRINTF(status, status_len, "%s: Test terminated due to newer invocation", __FUNCTION__);
            return -1;
        }

        // Exit if an error occurred performing the select
        if (num_sockets == -1)
        {
            USP_SNPRINTF(status, status_len, "%s: Select failed: %s", __FUNCTION__, strerror(errno));
            CloseTestSock();
            return -1;
        }

        // Exit if timeout occurred
        if (time(NULL) >= timeout_time)
        {
            USP_SNPRINTF(status, status_len, "%s: Failed to read: Timeout", __FUNCTION__);
            CloseTestSock();
            return -1;
        }

        // Read bytes if any were received
        if (num_sockets == 1)
        {
            num_bytes = recv(test_sock, &buf[offset], len-offset, 0);
            if (num_bytes == -1)
            {
                // Exit if an error occurred performing the recv
                if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
                {
                    USP_SNPRINTF(status, status_len, "%s: Failed to read: %s", __FUNCTION__, strerror(errno));
                    CloseTestSock();
                    return -1;
                }
            }
            else
            {
                offset += num_bytes;
            }
        }

    }

    // Successfully read all bytes in the fragment
    USP_ASSERT(len == offset);
    return len;
}

/*********************************************************************//**
**
** CloseTestSock
**
** Closes the socket used by this component to send to the USP Broker
**
** \param   None
**
** \return  None
**
**************************************************************************/
void CloseTestSock(void)
{
    if (test_sock != -1)
    {
        // NOTE: shutdown() is needed to ensure that the socket is actually closed by the subsequent close(), rather than linering
        // If the socket lingers, then in the case of a new invocation closing an old invocation, both are connected at the same time,
        // and this causes the handshake to fail if both connections are from the same endpoint_id
        shutdown(test_sock, SHUT_RDWR);
        close(test_sock);
        test_sock = -1;
    }
}

/*********************************************************************//**
**
** DropRxedFrames
**
** Reads and drops all received UDS frames for the current test invocation
**
** \param   conn_id - identifies the test invocation that we want to drop received frames from
**
** \return  None
**
**************************************************************************/
void DropRxedFrames(int conn_id)
{
    unsigned char frame[SHORT_UDS_FRAME_PAYLOAD_LEN];
    char status[256];
    int num_bytes;

    while (1)
    {
        num_bytes = UdsReceive(frame, sizeof(frame), conn_id, END_OF_TIME, status, sizeof(status));
        if (num_bytes == -1)
        {
            return;
        }

        // Exit if we're now running a different test invocation
        if (conn_id != cur_conn_id)
        {
            return;
        }
    }
}





