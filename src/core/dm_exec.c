/*
 *
 * Copyright (C) 2019-2021, Broadband Forum
 * Copyright (C) 2016-2021  CommScope, Inc
 * Copyright (C) 2020,  BT PLC
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
 * \file dm_exec.c
 *
 * Main loop for data model thread
 *
 */

#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>

#include "common_defs.h"
#include "mtp_exec.h"
#include "dm_exec.h"
#include "data_model.h"
#include "sync_timer.h"
#include "cli.h"
#include "data_model.h"
#include "dm_access.h"
#include "device.h"
#include "msg_handler.h"
#include "os_utils.h"
#include "database.h"
#include "dm_trans.h"
#include "nu_ipaddr.h"
#include "stomp.h"

#ifdef ENABLE_COAP
#include "usp_coap.h"
#endif

#ifdef ENABLE_WEBSOCKETS
#include "wsclient.h"
#include "wsserver.h"
#endif

//------------------------------------------------------------------------------
// Unix domain socket pair used to implement a message queue
// One socket is always used for sending, and the other always used for receiving
static int dm_mq_sockets[2] = {-1, -1};

#define mq_rx_socket  dm_mq_sockets[0]
#define mq_tx_socket  dm_mq_sockets[1]

//-------------------------------------------------------------------------
// Type of message on data model's message queue
typedef enum
{
    kDmExecMsg_OperComplete,       // Sent from a thread performing an operation to signal that the operation has completed
    kDmExecMsg_OperStatus,         // Sent from a thread performing an operation to signal the new value for the status of the operation (the data model thread performs the actual update of this value)
    kDmExecMsg_EventComplete,      // Sent from a thread to signal that an event has occurred
    kDmExecMsg_ObjAdded,           // Sent from a thread to signal that an object has been added by the vendor
    kDmExecMsg_ObjDeleted,         // Sent from a thread to signal that an object has been deleted by the vendor
    kDmExecMsg_ProcessUspRecord,   // Sent from the MTP thread with a USP Record to process
    kDmExecMsg_StompHandshakeComplete, // Sent from the MTP thread to notify the controller trust role to use for all controllers connected to the specified stomp connection
    kDmExecMsg_MtpThreadExited,    // Sent to signal that the MTP thread has exited as requested by a scheduled exit
    kDmExecMsg_BdcTransferResult,  // Sent to signal that the BDC thread has sent (or failed to send) a report
    kDmExecMsg_MqttHandshakeComplete, // Sent from the MTP thread to notify the controller trust role to use for all controllers connected to the specified mqtt client
} dm_exec_msg_type_t;


// Operation complete parameters in data model handler message
typedef struct
{
    int instance;
    int err_code;
    char *err_msg;
    kv_vector_t *output_args;
} oper_complete_msg_t;

// Event complete parameters in data model message
typedef struct
{
    char *event_name;
    kv_vector_t *output_args;
} event_complete_msg_t;

// Operation status parameters in data model message
typedef struct
{
    int instance;
    char *status;
} oper_status_msg_t;


// Process USP Record parameters in data model message
typedef struct
{
    unsigned char *pbuf;
    int pbuf_len;
    ctrust_role_t role;
    mtp_reply_to_t mtp_reply_to;    // destination to send the USP message response to
} process_usp_record_msg_t;

// Notify controller trust role for all controllers connected to the specified STOMP connection
typedef struct
{
    int stomp_instance;
    ctrust_role_t role;
} stomp_complete_msg_t;

// Notify controller trust role for all controllers connected to the specified MQTT client
typedef struct
{
    int mqtt_instance;
    ctrust_role_t role;
} mqtt_complete_msg_t;


// Object added parameters in data model message
typedef struct
{
    char *path;
} obj_added_msg_t;

// Object deleted parameters in data model message
typedef struct
{
    char *path;
} obj_deleted_msg_t;

// Management IP address changed parameters in data model message
typedef struct
{
    char ip_addr[NU_IPADDRSTRLEN];
} mgmt_ip_addr_msg_t;

// MTP Thread exited
typedef struct
{
    unsigned flags;         // Bitmask indicating which thread exited
} mtp_thread_exited_msg_t;

// Bulk Data Collection thread sent (or failed to send) a report
typedef struct
{
    int profile_id;         // Instance number of profile in Device.Bulkdata.Profile.{i}
    bdc_transfer_result_t transfer_result;   // Result code of sending the report
} bdc_transfer_result_msg_t;


// Structure of data model message
typedef struct
{
    dm_exec_msg_type_t type;
    union
    {
        oper_complete_msg_t oper_complete;
        event_complete_msg_t event_complete;
        oper_status_msg_t oper_status;
        obj_added_msg_t obj_added;
        obj_deleted_msg_t obj_deleted;
        process_usp_record_msg_t usp_record;
        stomp_complete_msg_t stomp_complete;
        mqtt_complete_msg_t mqtt_complete;
        mgmt_ip_addr_msg_t mgmt_ip_addr;
        mtp_thread_exited_msg_t mtp_thread_exited;
        bdc_transfer_result_msg_t bdc_transfer_result;
    } params;

} dm_exec_msg_t;

//------------------------------------------------------------------------------------
// Mutex used to protect access to this component
// This mutex is only really necessary for an orderly shutdown, to ensure the thread isn't doing anything when we free it's memory
static pthread_mutex_t dm_access_mutex;

//------------------------------------------------------------------------------
// Bitmask of MTP threads that have exited. Used to only shutdown the datamodel when all MTP threads have exited
unsigned cumulative_mtp_threads_exited = 0;

//------------------------------------------------------------------------------
// Boolean which is set once the MTP has been connected to successfully
// The purpose of this flag is to avoid USP notifications getting enqueued before the MTP has been connected to successfully
// for the first time after bootup
static bool is_notifications_enabled = false;

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
void UpdateSockSet(socket_set_t *set);
void ProcessSocketActivity(socket_set_t *set);
void ProcessMessageQueueSocketActivity(socket_set_t *set);
void ProcessBinaryUspRecord(unsigned char *pbuf, int pbuf_len, ctrust_role_t role, mtp_reply_to_t *mrt);

/*********************************************************************//**
**
** DM_EXEC_Init
**
** Initialises the functionality in this module
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DM_EXEC_Init(void)
{
    int err;

    // Exit if unable to initialize the unix domain socket pair used to implement a message queue
    err = socketpair(AF_UNIX, SOCK_DGRAM, 0, dm_mq_sockets);
    if (err != 0)
    {
        USP_ERR_ERRNO("socketpair", errno);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to create mutex protecting access to this subsystem
    err = OS_UTILS_InitMutex(&dm_access_mutex);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DM_EXEC_Destroy
**
** Frees all memory used by the data model thread
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void DM_EXEC_Destroy(void)
{
    DATA_MODEL_Stop();
    DATABASE_Destroy();
    SYNC_TIMER_Destroy();
}

/*********************************************************************//**
**
** USP_SIGNAL_OperationComplete
**
** Posts an operation complete message on the data model's message queue
** NOTE: Ownership of the (dynamically allocated by caller) output_args passes to data model
**       But err_msg is copied by this function (ie ownership of err_msg does not pass to this function)
** NOTE: Error messages in this function are only logged rather than writing in the error message buffer (USP_ERR_SetMessage())
**       because this function is normally called from a non core thread and if they did write, this might cause corruption of
**       the core agent error message buffer
**
** \param   instance - instance number of operation in Device.LocalAgent.Request table
** \param   err_code - error code of the operation (USP_ERR_OK indicates success)
** \param   err_msg - error message if the operation failed, or NULL if operation was successful
** \param   output_args - results of the completed operation (if successful)
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_SIGNAL_OperationComplete(int instance, int err_code, char *err_msg, kv_vector_t *output_args)
{
    dm_exec_msg_t  msg;
    oper_complete_msg_t *ocm;
    int bytes_sent;

    // Exit if this function has been called with a mismatch between err_code and err_msg
    if ( ((err_code == USP_ERR_OK) && (err_msg != NULL)) ||
         ((err_code != USP_ERR_OK) && (err_msg == NULL)) )
    {
        USP_LOG_Error("%s: Mismatch in calling arguments err_code=%d, but err_msg='%s'", __FUNCTION__, err_code, err_msg);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if message queue is not setup yet
    if (mq_tx_socket == -1)
    {
        USP_LOG_Error("%s is being called before data model has been initialised", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Form message
    memset(&msg, 0, sizeof(msg));
    msg.type = kDmExecMsg_OperComplete;
    ocm = &msg.params.oper_complete;
    ocm->instance = instance;
    ocm->err_code = err_code;
    ocm->err_msg = (err_msg==NULL) ? NULL : USP_STRDUP(err_msg);
    ocm->output_args = output_args;

    // Send the message
    bytes_sent = send(mq_tx_socket, &msg, sizeof(msg), 0);
    if (bytes_sent != sizeof(msg))
    {
        char buf[USP_ERR_MAXLEN];
        USP_LOG_Error("%s(%d): send failed : (err=%d) %s", __FUNCTION__, __LINE__, errno, USP_ERR_ToString(errno, buf, sizeof(buf)) );
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** USP_SIGNAL_DataModelEvent
**
** Posts an event message on the data model's message queue
** NOTE: Ownership of the (dynamically allocated by caller) output_args passes to data model
**       But event_name is copied by this function (ie ownership of event_name does not pass to this function)
** NOTE: Error messages in this function are only logged rather than writing in the error message buffer (USP_ERR_SetMessage())
**       because this function is normally called from a non core thread and if they did write, this might cause corruption of
**       the core agent error message buffer
**
** \param   event_name - name of the event
** \param   output_args - arguments for the event
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_SIGNAL_DataModelEvent(char *event_name, kv_vector_t *output_args)
{
    dm_exec_msg_t  msg;
    event_complete_msg_t *ecm;
    int bytes_sent;

    // Exit if message queue is not setup yet
    if (mq_tx_socket == -1)
    {
        USP_LOG_Error("%s is being called before data model has been initialised", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Form message
    memset(&msg, 0, sizeof(msg));
    msg.type = kDmExecMsg_EventComplete;
    ecm = &msg.params.event_complete;
    ecm->event_name = USP_STRDUP(event_name);
    ecm->output_args = output_args;

    // Send the message
    bytes_sent = send(mq_tx_socket, &msg, sizeof(msg), 0);
    if (bytes_sent != sizeof(msg))
    {
        char buf[USP_ERR_MAXLEN];
        USP_LOG_Error("%s(%d): send failed : (err=%d) %s", __FUNCTION__, __LINE__, errno, USP_ERR_ToString(errno, buf, sizeof(buf)) );
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** USP_SIGNAL_OperationStatus
**
** Posts an operation status message on the data model's message queue
** This function can be used by an operation thread to set the value of Device.LocalAgent.Request.{i}.Status in a thread-safe way
** NOTE: Error messages in this function are only logged rather than writing in the error message buffer (USP_ERR_SetMessage())
**       because this function is normally called from a non core thread and if they did write, this might cause corruption of
**       the core agent error message buffer
**
** \param   instance - instance number of operation in Device.LocalAgent.Request table
** \param   status - status string to set
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_SIGNAL_OperationStatus(int instance, char *status)
{
    dm_exec_msg_t  msg;
    oper_status_msg_t *osm;
    int bytes_sent;

    // Exit if this function has been called with invalid parameters
    if (status == NULL)
    {
        USP_LOG_Error("%s: status input argument must point to a string", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if message queue is not setup yet
    if (mq_tx_socket == -1)
    {
        USP_LOG_Error("%s is being called before data model has been initialised", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Form message
    memset(&msg, 0, sizeof(msg));
    msg.type = kDmExecMsg_OperStatus;
    osm = &msg.params.oper_status;
    osm->instance = instance;
    osm->status = USP_STRDUP(status);

    // Send the message
    bytes_sent = send(mq_tx_socket, &msg, sizeof(msg), 0);
    if (bytes_sent != sizeof(msg))
    {
        char buf[USP_ERR_MAXLEN];
        USP_LOG_Error("%s(%d): send failed : (err=%d) %s", __FUNCTION__, __LINE__, errno, USP_ERR_ToString(errno, buf, sizeof(buf)) );
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** USP_SIGNAL_ObjectAdded
**
** Signals to USP core that the vendor has added an object instance to the data model
** This function may be called from any vendor thread
**
** \param   path - path of object that has been added
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_SIGNAL_ObjectAdded(char *path)
{
    dm_exec_msg_t  msg;
    obj_added_msg_t *oam;
    int bytes_sent;

    // Exit if this function has been called with invalid parameters
    if (path == NULL)
    {
        USP_LOG_Error("%s: path input argument must point to a string", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if message queue is not setup yet
    if (mq_tx_socket == -1)
    {
        USP_LOG_Error("%s is being called before data model has been initialised", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Form message
    memset(&msg, 0, sizeof(msg));
    msg.type = kDmExecMsg_ObjAdded;
    oam = &msg.params.obj_added;
    oam->path = USP_STRDUP(path);

    // Send the message
    bytes_sent = send(mq_tx_socket, &msg, sizeof(msg), 0);
    if (bytes_sent != sizeof(msg))
    {
        char buf[USP_ERR_MAXLEN];
        USP_LOG_Error("%s(%d): send failed : (err=%d) %s", __FUNCTION__, __LINE__, errno, USP_ERR_ToString(errno, buf, sizeof(buf)) );
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** USP_SIGNAL_ObjectDeleted
**
** Signals to USP core that the vendor has deleted an object instance from the data model
** This function may be called from any vendor thread
**
** \param   path - path of object that has been deleted
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_SIGNAL_ObjectDeleted(char *path)
{
    dm_exec_msg_t  msg;
    obj_deleted_msg_t *odm;
    int bytes_sent;

    // Exit if this function has been called with invalid parameters
    if (path == NULL)
    {
        USP_LOG_Error("%s: path input argument must point to a string", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if message queue is not setup yet
    if (mq_tx_socket == -1)
    {
        USP_LOG_Error("%s is being called before data model has been initialised", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Form message
    memset(&msg, 0, sizeof(msg));
    msg.type = kDmExecMsg_ObjDeleted;
    odm = &msg.params.obj_deleted;
    odm->path = USP_STRDUP(path);

    // Send the message
    bytes_sent = send(mq_tx_socket, &msg, sizeof(msg), 0);
    if (bytes_sent != sizeof(msg))
    {
        char buf[USP_ERR_MAXLEN];
        USP_LOG_Error("%s(%d): send failed : (err=%d) %s", __FUNCTION__, __LINE__, errno, USP_ERR_ToString(errno, buf, sizeof(buf)) );
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DM_EXEC_PostUspRecord
**
** Posts a USP record to be processed by the data model thread
**
** \param   pbuf - pointer to buffer containing protobuf encoded USP record
**                 NOTE: This is part of larger buffer (with STOMP), so must be copied before sending to the data model thread)
** \param   pbuf_len - length of protobuf encoded message
** \param   role - Controller Trust Role allowed for this message
** \param   mrt - details of where response to this USP message should be sent
**
** \return  None
**
**************************************************************************/
void DM_EXEC_PostUspRecord(unsigned char *pbuf, int pbuf_len, ctrust_role_t role, mtp_reply_to_t *mrt)
{
    dm_exec_msg_t  msg;
    process_usp_record_msg_t *pur;
    int bytes_sent;

    // Exit if message queue is not setup yet
    if (mq_tx_socket == -1)
    {
        USP_LOG_Error("%s is being called before data model has been initialised", __FUNCTION__);
        return;
    }

    // Form message
    memset(&msg, 0, sizeof(msg));
    msg.type = kDmExecMsg_ProcessUspRecord;
    pur = &msg.params.usp_record;
    pur->pbuf = USP_MALLOC(pbuf_len);
    memcpy(pur->pbuf, pbuf, pbuf_len);
    pur->pbuf_len = pbuf_len;
    pur->role = role;
    pur->mtp_reply_to.protocol = mrt->protocol;
    pur->mtp_reply_to.is_reply_to_specified = mrt->is_reply_to_specified;
    pur->mtp_reply_to.stomp_dest = USP_STRDUP(mrt->stomp_dest);
    pur->mtp_reply_to.stomp_instance = mrt->stomp_instance;
    pur->mtp_reply_to.stomp_err_id = USP_STRDUP(mrt->stomp_err_id);
    pur->mtp_reply_to.coap_host = USP_STRDUP(mrt->coap_host);
    pur->mtp_reply_to.coap_port = mrt->coap_port;
    pur->mtp_reply_to.coap_resource = USP_STRDUP(mrt->coap_resource);
    pur->mtp_reply_to.coap_encryption = mrt->coap_encryption;
    pur->mtp_reply_to.coap_reset_session_hint = mrt->coap_reset_session_hint;
    pur->mtp_reply_to.mqtt_topic = USP_STRDUP(mrt->mqtt_topic);
    pur->mtp_reply_to.mqtt_instance = mrt->mqtt_instance;
    pur->mtp_reply_to.wsclient_cont_instance = mrt->wsclient_cont_instance;
    pur->mtp_reply_to.wsclient_mtp_instance = mrt->wsclient_mtp_instance;
    pur->mtp_reply_to.wsserv_conn_id = mrt->wsserv_conn_id;

    // Send the message
    bytes_sent = send(mq_tx_socket, &msg, sizeof(msg), 0);
    if (bytes_sent != sizeof(msg))
    {
        char buf[USP_ERR_MAXLEN];
        USP_LOG_Error("%s(%d): send failed : (err=%d) %s", __FUNCTION__, __LINE__, errno, USP_ERR_ToString(errno, buf, sizeof(buf)) );
        return;
    }
}

/*********************************************************************//**
**
** DM_EXEC_PostStompHandshakeComplete
**
** Posts the role associated with a Stomp connection, after the STOMP initial TLS handshake has completed
** This notifies the DataModel of the role to use for each controller connected to a STOMP broker
** This message will unblock processing of Boot! event and subscriptions, which are held up until the controller
** trust role associated with each controller is known (otherwise they would use the wrong role when getting data)
** Note: Restarting of async operations are also held up, because we want them to occur after the Boot! event
**
** \param   stomp_instance - instance number of STOMP connection in Device.STOMP.Connection.{i}
** \param   role - Role to use for controllers connected to the specified STOMP connection
**
** \return  None
**
**************************************************************************/
void DM_EXEC_PostStompHandshakeComplete(int stomp_instance, ctrust_role_t role)
{
    dm_exec_msg_t  msg;
    stomp_complete_msg_t *scm;
    int bytes_sent;

    // Exit if message queue is not setup yet
    if (mq_tx_socket == -1)
    {
        USP_LOG_Error("%s is being called before data model has been initialised", __FUNCTION__);
        return;
    }

    // Form message
    memset(&msg, 0, sizeof(msg));
    msg.type = kDmExecMsg_StompHandshakeComplete;
    scm = &msg.params.stomp_complete;
    scm->stomp_instance = stomp_instance;
    scm->role = role;

    // Send the message
    bytes_sent = send(mq_tx_socket, &msg, sizeof(msg), 0);
    if (bytes_sent != sizeof(msg))
    {
        char buf[USP_ERR_MAXLEN];
        USP_LOG_Error("%s(%d): send failed : (err=%d) %s", __FUNCTION__, __LINE__, errno, USP_ERR_ToString(errno, buf, sizeof(buf)) );
        return;
    }
}

/*********************************************************************//**
**
** DM_EXEC_PostMqttHandshakeComplete
**
** Posts the role associated with an MQTT connection, after the TLS handshake has completed
** This notifies the DataModel of the role to use for each controller connected to an MQTT broker
** This message will unblock processing of Boot! event and subscriptions, which are held up until the controller
** trust role associated with each controller is known (otherwise they would use the wrong role when getting data)
** Note: Restarting of async operations are also held up, because we want them to occur after the Boot! event
**
** \param   stomp_instance - instance number of STOMP connection in Device.STOMP.Connection.{i}
** \param   role - Role to use for controllers connected to the specified STOMP connection
**
** \return  None
**
**************************************************************************/
void DM_EXEC_PostMqttHandshakeComplete(int mqtt_instance, ctrust_role_t role)
{
    dm_exec_msg_t  msg;
    mqtt_complete_msg_t *mcm;
    int bytes_sent;

    // Exit if message queue is not setup yet
    if (mq_tx_socket == -1)
    {
        USP_LOG_Error("%s is being called before data model has been initialised", __FUNCTION__);
        return;
    }

    // Form message
    memset(&msg, 0, sizeof(msg));
    msg.type = kDmExecMsg_MqttHandshakeComplete;
    mcm = &msg.params.mqtt_complete;
    mcm->mqtt_instance = mqtt_instance;
    mcm->role = role;

    // Send the message
    bytes_sent = send(mq_tx_socket, &msg, sizeof(msg), 0);
    if (bytes_sent != sizeof(msg))
    {
        char buf[USP_ERR_MAXLEN];
        USP_LOG_Error("%s(%d): send failed : (err=%d) %s", __FUNCTION__, __LINE__, errno, USP_ERR_ToString(errno, buf, sizeof(buf)) );
        return;
    }
}


/*********************************************************************//**
**
** DM_EXEC_PostMtpThreadExited
**
** Signals that the MTP thread has exited, this will be because an exit was scheduled
** (either due to the controller requesting a reboot, or factory reset, or a stop CLI command being sent)
**
** \param   flags - flags determining which stomp thread exited
**
** \return  None
**
**************************************************************************/
void DM_EXEC_PostMtpThreadExited(unsigned flags)
{
    dm_exec_msg_t  msg;
    int bytes_sent;
    mtp_thread_exited_msg_t *tem;

    // Exit if message queue is not setup yet
    if (mq_tx_socket == -1)
    {
        USP_LOG_Error("%s is being called before data model has been initialised", __FUNCTION__);
        return;
    }

    // Form message
    memset(&msg, 0, sizeof(msg));
    msg.type = kDmExecMsg_MtpThreadExited;
    tem = &msg.params.mtp_thread_exited;
    tem->flags = flags;

    // Send the message
    bytes_sent = send(mq_tx_socket, &msg, sizeof(msg), 0);
    if (bytes_sent != sizeof(msg))
    {
        char buf[USP_ERR_MAXLEN];
        USP_LOG_Error("%s(%d): send failed : (err=%d) %s", __FUNCTION__, __LINE__, errno, USP_ERR_ToString(errno, buf, sizeof(buf)) );
        return;
    }
}



/*********************************************************************//**
**
** DM_EXEC_NotifyBdcTransferResult
**
** Posts a message that signals to data model thread that the specified Bulk Data Collection
** report has been sent, or failed to send
**
** \param   profile_id - Instance number of profile in Device.Bulkdata.Profile.{i}
** \param   transfer_result - result code of the transfer
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DM_EXEC_NotifyBdcTransferResult(int profile_id, bdc_transfer_result_t transfer_result)
{
    dm_exec_msg_t  msg;
    bdc_transfer_result_msg_t *btr;
    int bytes_sent;

    // Exit if message queue is not setup yet
    if (mq_tx_socket == -1)
    {
        USP_LOG_Error("%s is being called before data model has been initialised", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Form message
    memset(&msg, 0, sizeof(msg));
    msg.type = kDmExecMsg_BdcTransferResult;
    btr = &msg.params.bdc_transfer_result;
    btr->profile_id = profile_id;
    btr->transfer_result = transfer_result;

    // Send the message
    bytes_sent = send(mq_tx_socket, &msg, sizeof(msg), 0);
    if (bytes_sent != sizeof(msg))
    {
        char buf[USP_ERR_MAXLEN];
        USP_LOG_Error("%s(%d): send failed : (err=%d) %s", __FUNCTION__, __LINE__, errno, USP_ERR_ToString(errno, buf, sizeof(buf)) );
        return USP_ERR_INTERNAL_ERROR;
    }


    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DM_EXEC_EnableNotifications
**
** Unblocks processing of Boot! event and subscriptions, which are held up until the controller
** trust role associated with each controller is known (otherwise they would use the wrong role when getting data)
** Note: Restarting of async operations are also held up, because we want them to occur after the Boot! event
**
** \param   None
**
** \return  None
**
**************************************************************************/
void DM_EXEC_EnableNotifications(void)
{
    // Exit if the notifications are already enabled
    if (is_notifications_enabled)
    {
        return;
    }

    // Then start the parts of the data model which were held up, waiting for the controller's role to be known


    // Queue object creation/deletion notifications
    DEVICE_SUBSCRIPTION_ProcessAllObjectLifeEventSubscriptions();

    // Send out initial Boot NotifyReq, and determine the initial values of all value change parameters
    // This also starts the sync timer to poll for value change notifications
    DEVICE_SUBSCRIPTION_Update(0);

    // Restart all asynchronous operations that did not complete (and that are meant to be restarted after a reboot)
    // NOTE: This also sends out events for all operations that required a reboot to complete them
    DEVICE_REQUEST_RestartAsyncOperations();

    // Set flag, so that subsequent calls to this function (eg stomp reconnections) do not start the data model again
    is_notifications_enabled = true;
}

/*********************************************************************//**
**
** DM_EXEC_IsNotificationsEnabled
**
** Returns whether USP notifications may be generated.
** NOTE: USP notifications are not generated before the Boot! event has been sent
**       This function is called to avoid a large queue of USP notifications in the case of MTP connection failure
**
** \param   None
**
** \return  true if USP notifications can be sent
**
**************************************************************************/
bool DM_EXEC_IsNotificationsEnabled(void)
{
    return is_notifications_enabled;
}

/*********************************************************************//**
**
** DM_EXEC_Main
**
** Main loop of the data model thread
**
** \param   args - arguments (currently unused)
**
** \return  None
**
**************************************************************************/
void *DM_EXEC_Main(void *args)
{
    int err;
    int num_sockets;
    socket_set_t set;
    int enabled_connections = 0;

    // Exit if unable to connect to the unix domain socket used to implement the CLI server
    err = CLI_SERVER_Init();
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: CLI_SERVER_Init() failed. Aborting Data Model thread", __FUNCTION__);
        return NULL;
    }

    // Determine whether we have to wait for a STOMP or MQTT connection, before enabling notifications
    // This is necessary because the contents of the Boot! event may be dependant on the permissions that the USP Controller has, and we'll only know this after connecting to it
#ifndef DISABLE_STOMP
    enabled_connections += DEVICE_STOMP_CountEnabledConnections();
#endif

#ifdef ENABLE_MQTT
    enabled_connections += DEVICE_MQTT_CountEnabledConnections();
#endif

    // Enable notifications now, if we don't have to wait for a STOMP or MQTT connection before generating a Boot! notification
    if (enabled_connections == 0)
    {
        DM_EXEC_EnableNotifications();
    }

    OS_UTILS_LockMutex(&dm_access_mutex);

    while(FOREVER)
    {
        // Create the socket set to receive/transmit on (with timeout)
        UpdateSockSet(&set);

        // Unlock the mutex around the select()
        OS_UTILS_UnlockMutex(&dm_access_mutex);

        // Wait for read/write activity on sockets or timeout
        num_sockets = SOCKET_SET_Select(&set);

        OS_UTILS_LockMutex(&dm_access_mutex);

        // Execute all timers which are ready to fire
        SYNC_TIMER_Execute();

        // Process socket activity
        switch(num_sockets)
        {
            case -1:
                // An unrecoverable error has occurred
                USP_LOG_Error("%s: Unrecoverable socket select() error. Aborting Data Model thread", __FUNCTION__);
                return NULL;
                break;

            case 0:
                // No controllers with any activity, but we still may need to process a timeout, so fall-through
            default:
                // Controllers with activity
                ProcessSocketActivity(&set);
                break;
        }

        // Queue any object creation/deletion events which have been generated by the message or timer callbacks
        DEVICE_SUBSCRIPTION_ProcessAllObjectLifeEventSubscriptions();

        // Print out any memory allocations that got added for this time around the loop
        //USP_MEM_Print();
    }
}

/*********************************************************************//**
**
** UpdateSockSet
**
** Adds all sockets to wait for activity on, into the socket set
** Also updates the associated timeout for activity
** This function must be called every time before the call to select(), as select alters the socket set
**
** \param   set - pointer to socket set structure to update with sockets to wait for activity on
**
** \return  None
**
**************************************************************************/
void UpdateSockSet(socket_set_t *set)
{
    int delay_ms;

    SOCKET_SET_Clear(set);

    // Add the CLI server socket to the socket set
    CLI_SERVER_UpdateSocketSet(set);

    // Add the message queue receiving socket to the socket set
    SOCKET_SET_AddSocketToReceiveFrom(mq_rx_socket, MAX_SOCKET_TIMEOUT, set);

    // Update socket timeout time with the time to the next timer
    delay_ms = SYNC_TIMER_TimeToNext();
    SOCKET_SET_UpdateTimeout(delay_ms, set);
}

/*********************************************************************//**
**
** ProcessSocketActivity
**
** Processes all activity on sockets (ie receiving messages and sending messages)
**
** \param   set - pointer to socket set structure containing sockets with activity on them
**
** \return  None
**
**************************************************************************/
void ProcessSocketActivity(socket_set_t *set)
{
    // Process any pending message queue activity first - this allows internal state to be updated before controllers query it
    ProcessMessageQueueSocketActivity(set);

    // Process the socket, if there is any activity from a CLI client
    CLI_SERVER_ProcessSocketActivity(set);
}

/*********************************************************************//**
**
** ProcessMessageQueueSocketActivity
**
** Processes any activity on the message queue receiving socket
**
** \param   set - pointer to socket set structure containing sockets with activity on them
**
** \return  None (any errors that occur are handled internally)
**
**************************************************************************/
void ProcessMessageQueueSocketActivity(socket_set_t *set)
{
    int err;
    int bytes_read;
    dm_exec_msg_t  msg;
    oper_complete_msg_t *ocm;
    event_complete_msg_t *ecm;
    oper_status_msg_t *osm;
    obj_added_msg_t *oam;
    obj_deleted_msg_t *odm;
    process_usp_record_msg_t *pur;
    mtp_thread_exited_msg_t *tem;
    unsigned all_mtp_exited = 0;
    bdc_transfer_result_msg_t *btr;
    mtp_reply_to_t *mrt;

    // Exit if there is no activity on the message queue socket
    if (SOCKET_SET_IsReadyToRead(mq_rx_socket, set) == 0)
    {
        return;
    }

    // Exit if unable to read the full message received
    bytes_read = recv(mq_rx_socket, &msg, sizeof(msg), 0);
    if (bytes_read != sizeof(msg))
    {
        USP_LOG_Error("%s: recv() did not return a full message", __FUNCTION__);
        return;
    }

    switch(msg.type)
    {
        case kDmExecMsg_ProcessUspRecord:
            pur = &msg.params.usp_record;
            mrt = &pur->mtp_reply_to;

            ProcessBinaryUspRecord(pur->pbuf, pur->pbuf_len, pur->role, mrt);

            // Free all arguments passed in this message
            USP_FREE(pur->pbuf);
            USP_SAFE_FREE(mrt->stomp_dest);
            USP_SAFE_FREE(mrt->stomp_err_id);
            USP_SAFE_FREE(mrt->coap_host);
            USP_SAFE_FREE(mrt->coap_resource);
            USP_SAFE_FREE(mrt->mqtt_topic);
            break;

#ifndef DISABLE_STOMP
        case kDmExecMsg_StompHandshakeComplete:
        {
            stomp_complete_msg_t *scm;
            scm = &msg.params.stomp_complete;
            DEVICE_CONTROLLER_SetRolesFromStomp(scm->stomp_instance, scm->role);
            DM_EXEC_EnableNotifications();
        }
            break;
#endif

#ifdef ENABLE_MQTT
        case kDmExecMsg_MqttHandshakeComplete:
        {
            mqtt_complete_msg_t *mcm;
            mcm = &msg.params.mqtt_complete;
            DEVICE_CONTROLLER_SetRolesFromMqtt(mcm->mqtt_instance, mcm->role);
            DM_EXEC_EnableNotifications();
        }
            break;
#endif
        case kDmExecMsg_OperComplete:
            ocm = &msg.params.oper_complete;
            DEVICE_REQUEST_OperationComplete(ocm->instance, ocm->err_code, ocm->err_msg, ocm->output_args);

            // Free all arguments passed in this message
            if (ocm->output_args != NULL)
            {
                KV_VECTOR_Destroy(ocm->output_args);
                USP_SAFE_FREE(ocm->output_args);
            }

            USP_SAFE_FREE(ocm->err_msg);
            break;

        case kDmExecMsg_EventComplete:
            ecm = &msg.params.event_complete;
            DEVICE_SUBSCRIPTION_ProcessAllEventCompleteSubscriptions(ecm->event_name, ecm->output_args);

            // Free all arguments passed in this message
            if (ecm->output_args != NULL)
            {
                KV_VECTOR_Destroy(ecm->output_args);
                USP_SAFE_FREE(ecm->output_args);
            }

            USP_SAFE_FREE(ecm->event_name);
            break;

        case kDmExecMsg_OperStatus:
            osm = &msg.params.oper_status;
            USP_ASSERT(osm->status != NULL);
            DEVICE_REQUEST_UpdateOperationStatus(osm->instance, osm->status);

            // Free all arguments passed in this message
            USP_FREE(osm->status);
            break;


        case kDmExecMsg_ObjAdded:
            oam = &msg.params.obj_added;
            err = DATA_MODEL_NotifyInstanceAdded(oam->path);
            if (err == USP_ERR_OK)
            {
                // Send Object creation notifications if object existed in the schema
                DEVICE_SUBSCRIPTION_NotifyObjectLifeEvent(oam->path, kSubNotifyType_ObjectCreation);
            }

            // Free all arguments passed in this message
            USP_FREE(oam->path);
            break;

        case kDmExecMsg_ObjDeleted:
            odm = &msg.params.obj_deleted;
            err = DATA_MODEL_NotifyInstanceDeleted(odm->path);
            if (err == USP_ERR_OK)
            {
                // Send Object deletion notifications, if object existed
                DEVICE_SUBSCRIPTION_NotifyObjectLifeEvent(odm->path, kSubNotifyType_ObjectDeletion);
            }

            // Free all arguments passed in this message
            USP_FREE(odm->path);
            break;

        case kDmExecMsg_MtpThreadExited:
            tem = &msg.params.mtp_thread_exited;
            cumulative_mtp_threads_exited |= tem->flags;

            // Form bitmask of all MTP threads which must exit before a scheduled exit can be handled
            #ifndef DISABLE_STOMP
            all_mtp_exited |= STOMP_EXITED;
            #endif

            #ifdef ENABLE_COAP
            all_mtp_exited |= COAP_EXITED;
            #endif

            #ifdef ENABLE_MQTT
            all_mtp_exited |= MQTT_EXITED;
            #endif

            #ifdef ENABLE_WEBSOCKETS
            all_mtp_exited |= WSCLIENT_EXITED;
            all_mtp_exited |= WSSERVER_EXITED;
            #endif

            all_mtp_exited |= BDC_EXITED;

            if (cumulative_mtp_threads_exited == all_mtp_exited)
            {
                DM_EXEC_HandleScheduledExit();
            }
            break;

        case kDmExecMsg_BdcTransferResult:
            btr = &msg.params.bdc_transfer_result;
            DEVICE_BULKDATA_NotifyTransferResult(btr->profile_id, btr->transfer_result);
            break;

        default:
            TERMINATE_BAD_CASE(msg.type);
            break;
    }
}

/*********************************************************************//**
**
** DM_EXEC_HandleScheduledExit
**
** If this function is called, then USP Agent will stop running in this function
** after possibly signalling to the vendor that the CPE should reboot, or perform a factory reset
** NOTE: This function will call exit() in the vendor hooks or at the end of the function
**
** \param   None
**
** \return  None
**
**************************************************************************/
void DM_EXEC_HandleScheduledExit(void)
{
    exit_action_t exit_action;
    dm_vendor_reboot_cb_t   reboot_cb;
    dm_vendor_factory_reset_cb_t   factory_reset_cb;

    // Determine whether to just exit, reboot, or perform a factory reset
    exit_action = DEVICE_LOCAL_AGENT_GetExitAction();

    switch(exit_action)
    {
        case kExitAction_Exit:
            USP_LOG_Info("Performing CLI initiated Stop.");
            MAIN_Stop();
            break;

        case kExitAction_Reboot:
            // NOTE: If reboot is scheduled, then the default for the vendor hook (in Test mode) is to exit here
            // The vendor hook may return or may exit the executable itself
            USP_LOG_Info("Performing Controller initiated Reboot.");
            reboot_cb = vendor_hook_callbacks.reboot_cb;
            MAIN_Stop();
            if (reboot_cb != NULL)
            {
                reboot_cb();
            }
            break;

        case kExitAction_FactoryReset:
            USP_LOG_Info("Performing Controller initiated FactoryReset");
            // If a file exists containing the factory reset database, then copy it, and modify the reboot cause
            // NOTE: This must be called before the data model is shutdown, as programmatic factory reset validates the parameter paths against the data model
            DATABASE_PerformFactoryReset_ControllerInitiated();

            MAIN_Stop();

            // NOTE: If factory reset is scheduled, then the default is to exit here
            // The vendor hook may return or may exit the executable itself
            factory_reset_cb = vendor_hook_callbacks.factory_reset_cb;
            if (factory_reset_cb != NULL)
            {
                factory_reset_cb();
            }
            break;

        default:
            MAIN_Stop();
            break;
    }

    // If nothing else has exited yet, then exit
    usleep(100000); // Sleep for 100us, just to allow all other threads to exit (that sent the kDmExecMsg_MtpThreadExited message)
    exit(0);
}

/*********************************************************************//**
**
** ProcessBinaryUspRecord
**
** Process a USP record, potentially sending back a 'usp-err-id' STOMP frame if failed to parse the USP record
**
** \param   pbuf - pointer to buffer containing protobuf encoded USP record
** \param   pbuf_len - length of protobuf encoded message
** \param   role - Role allowed for this message
** \param   mrt - details of where response to this USP message should be sent
**
** \return  None - Errors are handled by either sending back a 'usp-err-id' frame (for STOMP MTP) or by ignoring the USP record (for CoAP MTP)
**
**************************************************************************/
void ProcessBinaryUspRecord(unsigned char *pbuf, int pbuf_len, ctrust_role_t role, mtp_reply_to_t *mrt)
{
    int err;

    // Exit if handled the USP record successfully
    err = MSG_HANDLER_HandleBinaryRecord(pbuf, pbuf_len, role, mrt);
    if (err == USP_ERR_OK)
    {
        return;
    }

    // If the code gets here, there was a USP parsing error
    // Handle the error differently, based on each protocol
    switch(mrt->protocol)
    {
#ifndef DISABLE_STOMP
        case kMtpProtocol_STOMP:
        {
            char *agent_queue;
            char *buf;
            int len;
            char *err_msg;
            mtp_send_item_t mtp_send_item = MTP_SEND_ITEM_INIT;

            // Exit if the controller did not send a 'usp-err-id' STOMP header to identify this broken USP record
            // (We can't send back a response unless they did)
            if ((mrt->stomp_err_id == NULL) || (mrt->stomp_err_id[0] == '\0'))
            {
                break;
            }

            // Form the payload of the 'usp-err-id' STOMP frame
            #define MAX_ERR_ID_PAYLOAD_LEN   (USP_ERR_MAXLEN+32)  // Plus 32 to include "err_code:" and "err_msg:" headers and trailing NULL
            buf = USP_MALLOC(MAX_ERR_ID_PAYLOAD_LEN);
            err_msg = USP_ERR_GetMessage();
            len = USP_SNPRINTF(buf, MAX_ERR_ID_PAYLOAD_LEN, "err_code:%d\nerr_msg:%s", err, err_msg);

            mtp_send_item.usp_msg_type = USP__HEADER__MSG_TYPE__ERROR;
            mtp_send_item.pbuf = (unsigned char *)buf;
            mtp_send_item.pbuf_len = len;
            mtp_send_item.content_type = kMtpContentType_Text;

            // Send a 'usp-err-id' STOMP frame
            // NOTE: The trailing NULL in the pbuf contents is not part of the final STOMP frame but is necessary for printing out the pbuf contents in MSG_HANDLER_LogMessageToSend
            agent_queue = DEVICE_MTP_GetAgentStompQueue(mrt->stomp_instance);

            err = STOMP_QueueBinaryMessage(&mtp_send_item, mrt->stomp_instance, mrt->stomp_dest, agent_queue, mrt->stomp_err_id, END_OF_TIME);
            if (err != USP_ERR_OK)
            {
                USP_FREE(buf);  // Free the payload, if ownership did not pass to STOMP MTP
            }
        }
            break;
#endif

#ifdef ENABLE_COAP
        case kMtpProtocol_CoAP:
            // Just ignore the protobuf parsing error. CoAP does not have a way of indicating this back to the Controller.
            break;
#endif

#ifdef ENABLE_MQTT
        case kMtpProtocol_MQTT:
            // Just ignore the protobuf parsing error. MQTT does not currently indicate this back to the Controller.
            break;
#endif

#ifdef ENABLE_WEBSOCKETS
        case kMtpProtocol_WebSockets:
        {
            // Tell the MTP to close the connection, because there was a protobuf parsing error
            // or the USP Record was received on the agent's websocket server, but the controller was already connected
            // via the agent's websocket client (only one connection to a controller is allowed)
            char *err_msg = USP_STRDUP( USP_ERR_GetMessage());

            mtp_send_item_t mtp_send_item = MTP_SEND_ITEM_INIT;
            mtp_send_item.usp_msg_type = USP__HEADER__MSG_TYPE__ERROR;
            mtp_send_item.pbuf = (unsigned char *)err_msg;
            mtp_send_item.pbuf_len = strlen(err_msg);
            mtp_send_item.content_type = kMtpContentType_Text;

            if (mrt->wsserv_conn_id == INVALID)
            {
                WSCLIENT_QueueBinaryMessage(&mtp_send_item, mrt->wsclient_cont_instance, mrt->wsclient_mtp_instance, END_OF_TIME);
            }
            else
            {
                WSSERVER_QueueBinaryMessage(&mtp_send_item, mrt->wsserv_conn_id, END_OF_TIME);
            }
        }
            break;
#endif

        default:
            // Just ignore the protobuf parsing error
            break;

    } // end of switch
}


