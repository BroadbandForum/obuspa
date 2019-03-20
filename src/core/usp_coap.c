/*
 *
 * Copyright (C) 2017-2019  ARRIS Enterprises, LLC
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
 * \file usp_coap.c
 *
 * Implements Constrained Application Protocol transport for USP
 *
 */

#ifdef ENABLE_COAP  // NOTE: This isn't strictly necessary as this file is not included in the build if CoAP is disabled


#define WITH_POSIX 1            // Must be defined before libcoap header is included

#include <coap/coap.h>
#include <coap/debug.h>

#include <stdlib.h>

#include <stdio.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>


#include "common_defs.h"
#include "usp_api.h"
#include "usp-msg.pb-c.h"
#include "msg_handler.h"
#include "nu_ipaddr.h"
#include "iso8601.h"
#include "os_utils.h"
#include "dllist.h"
#include "dm_exec.h"
#include "retry_wait.h"

#ifdef ENABLE_COAP
#include "usp_coap.h"
#endif
//------------------------------------------------------------------------
// Structure representing the CoAP servers that USP Agent exports
typedef struct
{
    int instance;           // Instance number of the CoAP server in Device.LocalAgent.MTP.{i}, or INVALID if this slot is unused
                            // NOTE: There may be more than one CoAP server per instance, because each instance can exist on multiple interfaces
    coap_context_t *coap_server_ctx;
    coap_resource_t *res;   // Pointer to libcoap resource. Libcoap does not automatically free this when it frees the context

    unsigned char *rxbuf;   // pointer to buffer, used to concatenate message fragments until a complete message has been received
    int rxbuf_msglen;       // number of message bytes copied into rxbuf
    int rxbuf_maxlen;       // size of rxbuf allocated 

    unsigned char token[8]; // Token received in the first block. The server must use the same token for the reson of the blocks.
    int token_len;
    int last_block;         // Last block nunber receieved, or -1 if we are expecting block number 0
                            // This is used to check that a controller sends us all blocks in order
    int last_message_id;    // CoAP message id of the last received packet. Used to ignore duplicates in the case of us taking too long to ACK a packet

    char *listen_addr;      // Our address that the controller sends to
                            // 2DO RH: This code does not cope with a change in our IP address
    int listen_port;        // Our port that the controller sends to
    char *listen_resource;  // Our resource that the controller sends to

} coap_server_t;

coap_server_t coap_servers[MAX_COAP_SERVERS];

//------------------------------------------------------------------------
// Enumeration representing CoAP Block sizes
// NOTE: This is just used to make the code easier to read. The size is just  1 << (4 + enum)
typedef enum
{
    kCoapBlockSize_16 = 0,
    kCoapBlockSize_32 = 1,
    kCoapBlockSize_64 = 2,
    kCoapBlockSize_128 = 3,
    kCoapBlockSize_256 = 4,
    kCoapBlockSize_512 = 5,
    kCoapBlockSize_1024 = 6,
} coap_block_size_t;

// Structure representing the CoAP controllers that USP Agent sends to (ie when acting as a client)
typedef struct
{
    int cont_instance;           // Instance number of the controller in Device.LocalAgent.Controller.{i}
    int mtp_instance;            // Instance number of the MTP in Device.LocalAgent.Controller.{i}.MTP.{i}

    coap_context_t *coap_client_ctx; // Content of our coap client

    // State variables for the current USP message being sent
    coap_tid_t tid;             // libcoap assigned transaction id for current block PDU being sent out
    int block_num;              // The number of the block that we are currently trying to send out (counts from 0)
    coap_block_size_t block_size; // The size of each block that we are sending (the controller may ask for a smaller block size)
    unsigned token;

    double_linked_list_t send_queue;    // Queue of messages to send on this STOMP connection
    time_t retry_time;          // Time at which we should attempt to start sending the first queued USP message, or 0 if retrying is not required
                                // This is only required if we failed to send the initial block. If we sent the first block, then retries are handled by libcoap and us

} coap_controller_t;


coap_controller_t coap_controllers[MAX_COAP_CONNECTIONS];

//------------------------------------------------------------------------------
// USP Message to send in queue
typedef struct
{
    double_link_t link;     // Doubly linked list pointers. These must always be first in this structure
    Usp__Header__MsgType usp_msg_type;  // Type of USP message contained within pbuf
    unsigned char *pbuf;    // Protobuf format message to send in binary format
    int pbuf_len;           // Length of protobuf message to send
    char *host;             // Hostname of the controller to send to
    int port;               // Port to send to, on the controller
    char *resource;         // Name of resource on controller to Post to
} coap_send_item_t;

//------------------------------------------------------------------------------------
// Mutex used to protect access to this component
static pthread_mutex_t coap_access_mutex;

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
void HandleCoapPost(coap_context_t *ctx, struct coap_resource_t *resource, const coap_endpoint_t *local_interface,
                    coap_address_t *peer, coap_pdu_t *request, str *token, coap_pdu_t *response);

void HandleCoapAck(struct coap_context_t *ctx,
                   const coap_endpoint_t *local_interface, const coap_address_t *remote,
                   coap_pdu_t *sent, coap_pdu_t *received, const coap_tid_t id);

coap_pdu_t *CreateSendBlock(coap_controller_t *cc, coap_send_item_t *csi);
int ResolveCoapAddress(char *hostname, int port, struct sockaddr *dst);
void StartSendingToController(coap_controller_t *cc);
coap_server_t *FindUnusedCoapServer(void);
coap_server_t *FindCoapServerByContext(coap_context_t *ctx);
coap_server_t *FindCoapServerByInstance(int instance);
coap_controller_t *FindUnusedCoapController(void);
coap_controller_t *FindCoapControllerByInstance(int cont_instance, int mtp_instance);
coap_controller_t *FindCoapControllerByContext(coap_context_t *ctx);

/*********************************************************************//**
**
** COAP_Init
**
** Initialises this component
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int COAP_Init(void)
{
    int i;
    int err;
    coap_server_t *cs;
    coap_controller_t *cc;
    
    // Initialise the CoAP server array
    memset(coap_servers, 0, sizeof(coap_servers));
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        cs->instance = INVALID;
    }

    // Initialise the CoAP controllers array
    memset(coap_controllers, 0, sizeof(coap_controllers));
    for (i=0; i<MAX_COAP_CONNECTIONS; i++)
    {
        cc = &coap_controllers[i];
        cc->cont_instance = INVALID;
    }

    // Turn off debug from libcoap as it only goes to stdout
    coap_set_log_level((coap_log_t) -1);

    // Exit if unable to create mutex protecting access to this subsystem
    err = OS_UTILS_InitMutex(&coap_access_mutex);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** COAP_Destroy
**
** Frees all memory used by this component
**
** \param   None
**
** \return  None
**
**************************************************************************/
void COAP_Destroy(void)
{
    int i;
    coap_server_t *cs;
    coap_controller_t *cc;
    
    OS_UTILS_LockMutex(&coap_access_mutex);

    // Free all CoAP controllers
    for (i=0; i<MAX_COAP_CONNECTIONS; i++)
    {
        cc = &coap_controllers[i];
        if (cc->cont_instance != INVALID)
        {
            COAP_StopClient(cc->cont_instance, cc->mtp_instance);
        }
    }

    // Free all CoAP servers
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if (cs->instance != INVALID)
        {
            COAP_StopServer(cs->instance);
        }
    }

    OS_UTILS_UnlockMutex(&coap_access_mutex);
}

/*********************************************************************//**
**
** COAP_StartServer
**
** Starts a CoAP Server on the specified interface and port
**
** \param   instance - instance number in Device.LocalAgent.MTP.{i} for this server
** \param   ip_protocol - internet protocol to use eg AF_INET
** \param   intf_addr - IP address of the interface to listen on (0.0.0.0 indicates listen on all addresses)
** \param   port - IP port to listen on
** \param   resource - Name of the CoAP resource for this server
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int COAP_StartServer(int instance, int ip_protocol, char *intf_addr, int port, char *resource)
{
    coap_context_t *ctx;
    coap_address_t ca;
    coap_resource_t *res;
    coap_server_t *cs;
    int err;

    USP_LOG_Info("%s: Starting CoAP server [%d] on ip_addr=%s, port=%d, resource=%s", __FUNCTION__, instance, intf_addr, port, resource);

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return USP_ERR_OK;
    }

    USP_ASSERT(FindCoapServerByInstance(instance)==NULL);

    // Exit if unable to find a free CoAP server slot
    cs = FindUnusedCoapServer();
    if (cs == NULL)
    {
        USP_LOG_Error("%s: Out of CoAP servers when trying to add CoAP server for interface %s, port %d", __FUNCTION__, intf_addr, port);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Fill in structure describing what to listen on
    ca.addr.sa.sa_family = ip_protocol;
    inet_pton(ip_protocol, intf_addr, &ca.addr.sin.sin_addr.s_addr);
    ca.addr.sin.sin_port = htons(port);
    ca.size = sizeof(struct sockaddr_in);

    // Exit if unable to create the CoAP server context
    ctx = coap_new_context(&ca);
    if (ctx == NULL)
    {
        USP_LOG_Error("%s: Unable to create CoAP server for interface %s, port %d", __FUNCTION__, intf_addr, port);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Exit if unable to create the CoAP resource for this interface
    res = coap_resource_init((unsigned char *)resource, strlen(resource), COAP_RESOURCE_FLAGS_NOTIFY_CON);
    if (res == NULL)
    {
        coap_free_context(ctx);
        USP_LOG_Error("%s: Unable to create CoAP resource for interface %s", __FUNCTION__, intf_addr);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Add a handler for POST messages
    coap_register_handler(res, COAP_REQUEST_POST, HandleCoapPost);
    coap_add_resource(ctx, res);

    // Since we have successfully created this coap server, mark it as in-use, and finish initialising it
    cs->instance = instance;
    cs->coap_server_ctx = ctx;
    cs->res = res;
    cs->rxbuf = NULL;
    cs->rxbuf_msglen = 0;
    cs->rxbuf_maxlen = 0;
    cs->token_len = 0;
    cs->last_block = -1;
    cs->last_message_id = INVALID;
    memset(cs->token, 0, sizeof(cs->token));
    cs->listen_addr = USP_STRDUP(intf_addr);
    cs->listen_port = port;
    cs->listen_resource = USP_STRDUP(resource);

    err = USP_ERR_OK;

exit:
    OS_UTILS_UnlockMutex(&coap_access_mutex);

    // If successful, cause the MTP thread to wakeup from select().
    // We do this outside of the mutex lock to avoid an unnecessary task switch
    if (err == USP_ERR_OK)
    {
        MTP_EXEC_Wakeup();
    }

    return err;
}

/*********************************************************************//**
**
** COAP_StopServer
**
** Stops all matching CoAP Servers
** NOTE: It is safe to call this function, if the instance has already been stopped
**
** \param   instance - instance number in Device.LocalAgent.MTP.{i} for this server
**
** \return  None
**
**************************************************************************/
void COAP_StopServer(int instance)
{
    int i;
    coap_server_t *cs;

    USP_LOG_Info("%s: Stopping CoAP server [%d]", __FUNCTION__, instance);

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return;
    }

    // Iterate over all CoAP servers, stopping all matching severs
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if (cs->instance == instance)
        {
            // Found a matching server, so free it
            cs->instance = INVALID;
            coap_delete_resource(cs->coap_server_ctx, cs->res->key);
            coap_free_context(cs->coap_server_ctx);
            USP_SAFE_FREE(cs->rxbuf);
            USP_SAFE_FREE(cs->listen_addr);
            USP_SAFE_FREE(cs->listen_resource);
    
            cs->rxbuf_msglen = 0;
            cs->rxbuf_maxlen = 0;
        }
    }

    OS_UTILS_UnlockMutex(&coap_access_mutex);

    // Cause the MTP thread to wakeup from select().
    // We do this outside of the mutex lock to avoid an unnecessary task switch
    MTP_EXEC_Wakeup();
}

/*********************************************************************//**
**
** COAP_GetServerStatus
**
** Function called to get the value of Device.LocalAgent.MTP.{i}.Status
**
** \param   instance - instance number in Device.LocalAgent.MTP.{i} for this server
**
** \return  Status of this CoAP server
**
**************************************************************************/
mtp_status_t COAP_GetServerStatus(int instance)
{
    coap_server_t *cs;
    mtp_status_t status;

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return kMtpStatus_Down;
    }

    // Exit if we cannot find a CoAP server with this instance - creation of the server had previously failed
    cs = FindCoapServerByInstance(instance);
    if (cs == NULL)
    {
        status = kMtpStatus_Down;
        goto exit;
    }

    // If creation of the server had previously completed, then this CoAP server is up and running
    status = kMtpStatus_Up;

exit:
    OS_UTILS_UnlockMutex(&coap_access_mutex);
    return status;
}

/*********************************************************************//**
**
** COAP_StartClient
**
** Starts a CoAP Client to send USP messages to the specified controller
**
** \param   cont_instance -  Instance number of the controller in Device.LocalAgent.Controller.{i}
** \param   mtp_instance -   Instance number of this MTP in Device.LocalAgent.Controller.{i}.MTP.{i}
** \param   endpoint_id - endpoint of controller (used only for debug)
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int COAP_StartClient(int cont_instance, int mtp_instance, char *endpoint_id)
{
    coap_context_t *ctx;
    coap_controller_t *cc;
    coap_address_t ca;
    int err;

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return USP_ERR_OK;
    }

    // Exit if unable to find a free CoAP controller slot
    cc = FindUnusedCoapController();
    if (cc == NULL)
    {
        USP_LOG_Error("%s: Out of CoAP clients for controller endpoint %s (Device.LocalAgent.Controller.%d.MTP.%d.CoAP)", __FUNCTION__, endpoint_id, cont_instance, mtp_instance);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Fill in details of network interface we want to listen for CoAP ACKs from controller on    
    memset(&ca, 0, sizeof(ca));
    ca.addr.sa.sa_family = AF_INET;
    ca.addr.sin.sin_addr.s_addr = INADDR_ANY;   // Listen on all interfaces
    ca.size = sizeof(struct sockaddr_in);

    // Create a client context bound to the source interface we want to receive CoAP ACKs on
    ctx = coap_new_context(&ca);
    if (ctx == NULL)
    {
        USP_LOG_Error("%s: coap_new_context() failed for controller endpoint %s", __FUNCTION__, endpoint_id);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Register the client's handler for processing received acknowledgement messages
    coap_register_response_handler(ctx, HandleCoapAck);

    // Since successfully started this controller's client connection, mark it as so, and finish initialising it
    cc->cont_instance = cont_instance;
    cc->mtp_instance = mtp_instance;
    cc->coap_client_ctx = ctx;
    cc->block_num = 0;
    cc->block_size = kCoapBlockSize_1024;
    cc->token = 0;
    cc->tid = COAP_INVALID_TID;
    cc->retry_time = 0;
    err = USP_ERR_OK;

exit:
    OS_UTILS_UnlockMutex(&coap_access_mutex);

    // If successful, cause the MTP thread to wakeup from select().
    // We do this outside of the mutex lock to avoid an unnecessary task switch
    if (err == USP_ERR_OK)
    {
        MTP_EXEC_Wakeup();
    }

    return err;
}

/*********************************************************************//**
**
** COAP_StopClient
**
** Stops the specified CoAP client
** NOTE: It is safe to call this function, if the instance has already been stopped
**
** \param   cont_instance -  Instance number of the controller in Device.LocalAgent.Controller.{i}
** \param   mtp_instance -   Instance number of this MTP in Device.LocalAgent.Controller.{i}.MTP.{i}
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int COAP_StopClient(int cont_instance, int mtp_instance)
{
    coap_controller_t *cc;
    coap_send_item_t *csi;
    coap_send_item_t *next;
    int err;

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return USP_ERR_OK;
    }

    // Exit if the Coap controller has already been stopped - nothing more to do
    cc = FindCoapControllerByInstance(cont_instance, mtp_instance);
    if (cc == NULL)
    {
        err = USP_ERR_OK;
        goto exit;
    }

    // Free the coap controller
    cc->cont_instance = INVALID;        // Mark the entry as unused
    coap_free_context(cc->coap_client_ctx);

    cc->mtp_instance = INVALID;
    cc->tid = COAP_INVALID_TID;
    cc->block_num = 0;
    cc->block_size = kCoapBlockSize_1024;
    cc->token = 0;

    // Drain the queue of outstanding messages to send
    csi = (coap_send_item_t *) cc->send_queue.head;
    while (csi != NULL)
    {
        next = (coap_send_item_t *) csi->link.next;
        USP_FREE(csi->pbuf);
        USP_FREE(csi->host);
        USP_FREE(csi->resource);
        USP_FREE(csi);

        // Move to next item in queue
        csi = next;
    }

    err = USP_ERR_OK;

exit:
    OS_UTILS_UnlockMutex(&coap_access_mutex);

    // If successful, cause the MTP thread to wakeup from select().
    // We do this outside of the mutex lock to avoid an unnecessary task switch
    if ((err == USP_ERR_OK) && (cc != NULL))
    {
        MTP_EXEC_Wakeup();
    }

    return err;
}

/*********************************************************************//**
**
** COAP_UpdateAllSockSet
**
** Updates the set of all COAP socket fds to read/write from
**
** \param   set - pointer to socket set structure to update with sockets to wait for activity on
**
** \return  None
**
**************************************************************************/
void COAP_UpdateAllSockSet(socket_set_t *set)
{
    int i;
    coap_server_t *cs;
    coap_controller_t *cc;
    int timeout;

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    // NOTE: This check should be unnecessary, as this function is only called from the MTP thread
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return;
    }

    // Add all CoAP server sockets (these receive USP request packets from the controller)
    #define DEFAULT_COAP_TIMEOUT_MS 90000
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if (cs->instance != INVALID)
        {
            SOCKET_SET_AddSocketToReceiveFrom(cs->coap_server_ctx->sockfd, DEFAULT_COAP_TIMEOUT_MS, set);
        }
    }

    // Add all CoAP controller sockets (these receive CoAP ACK packets from the controller)
    for (i=0; i<MAX_COAP_CONNECTIONS; i++)
    {
        cc = &coap_controllers[i];
        if (cc->cont_instance != INVALID)
        {
            SOCKET_SET_AddSocketToReceiveFrom(cc->coap_client_ctx->sockfd, DEFAULT_COAP_TIMEOUT_MS, set);
        }

        // Update the timeout until the time to retry sending a USP message, which we failed to start sending last time
        if (cc->retry_time != 0)
        {
            timeout = cc->retry_time - time(NULL);
            timeout = (timeout < 0) ? 0 : timeout;
            SOCKET_SET_UpdateTimeout(timeout*1000, set);
        }
    }

    // 2DO RH: Code for reboot needs adding here (like code in STOMP_UpdateAllSockSet)
    OS_UTILS_UnlockMutex(&coap_access_mutex);
}

/*********************************************************************//**
**
** COAP_ProcessAllSocketActivity
**
** Processes the socket for the specified controller
**
** \param   set - pointer to socket set structure containing the sockets which need processing
**
** \return  Nothing
**
**************************************************************************/
void COAP_ProcessAllSocketActivity(socket_set_t *set)
{
    int i;
    coap_server_t *cs;
    coap_controller_t *cc;
    time_t now;

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    // NOTE: This check should be unnecessary, as this function is only called from the MTP thread
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return;
    }

    // Service all CoAP server sockets (these receive USP request packets from the controller)
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if (cs->instance != INVALID)
        {
            if (SOCKET_SET_IsReadyToRead(cs->coap_server_ctx->sockfd, set))
            {
                coap_read(cs->coap_server_ctx);
            }
        }
    }

    // Service all CoAP controller sockets (these receive CoAP ACK packets from the controller)
    for (i=0; i<MAX_COAP_CONNECTIONS; i++)
    {
        cc = &coap_controllers[i];
        if (cc->cont_instance != INVALID)
        {
            if (SOCKET_SET_IsReadyToRead(cc->coap_client_ctx->sockfd, set))
            {
                coap_read(cc->coap_client_ctx);
            }
        }

        // See if it is time to retry sending a USP message, which we failed to start sending last time
        if (cc->retry_time != 0)
        {
            now = time(NULL);
            if (now >= cc->retry_time)
            {
                StartSendingToController(cc);
            }
        }
    }

    OS_UTILS_UnlockMutex(&coap_access_mutex);
}

/*********************************************************************//**
**
** COAP_QueueBinaryMessage
**
** Function called to queue a message to send to the specified controller (over CoAP)
**
** \param   usp_msg_type - Type of USP message contained in pbuf. This is used for debug logging when the message is sent by the MTP.
** \param   cont_instance -  Instance number of the controller in Device.LocalAgent.Controller.{i}
** \param   mtp_instance -   Instance number of this MTP in Device.LocalAgent.Controller.{i}.MTP.{i}
** \param   pbuf - pointer to buffer containing binary protobuf message. Ownership of this buffer passes to this code, if successful
** \param   pbuf_len - length of buffer containing protobuf binary message
** \param   host - DNS host name of controller
** \param   port - port number which the controller is listening on
** \param   resource - resource on the controller to post the message to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int COAP_QueueBinaryMessage(Usp__Header__MsgType usp_msg_type, int cont_instance, int mtp_instance, unsigned char *pbuf, int pbuf_len, char *host, int port, char *resource)
{
    coap_controller_t *cc;
    coap_send_item_t *csi;
    int err;

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    // NOTE: This check should be unnecessary, as this function is only called from the MTP thread
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return USP_ERR_OK;
    }

    // Exit if unable to find the controller MTP queue for this message
    cc = FindCoapControllerByInstance(cont_instance, mtp_instance);
    if (cc == NULL)
    {
        USP_LOG_Error("%s: FindCoapControllerByInstance() failed for controller=%d (mtp=%d)", __FUNCTION__, cont_instance, mtp_instance);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // 2DO RH: Do not add this message to the queue, if it is already present in the queue
    // This situation could occur if a notify is being retried to be sent, but is already held up in the queue pending sending
    csi = USP_MALLOC(sizeof(coap_send_item_t));
    csi->usp_msg_type = usp_msg_type;
    csi->pbuf = pbuf;
    csi->pbuf_len = pbuf_len;
    csi->host = USP_STRDUP(host);
    csi->port = port;
    csi->resource = USP_STRDUP(resource);

    DLLIST_LinkToTail(&cc->send_queue, csi);

    // If the queue was empty, then this will be the first item in the queue
    // So send out this item, this kick starts the libcoap state machine
    if (cc->send_queue.head == (void *)csi)
    {
        StartSendingToController(cc);
    }
    
    err = USP_ERR_OK;

exit:
    OS_UTILS_UnlockMutex(&coap_access_mutex);

    // If successful, cause the MTP thread to wakeup from select().
    // We do this outside of the mutex lock to avoid an unnecessary task switch
    if (err == USP_ERR_OK)
    {
        MTP_EXEC_Wakeup();
    }

    return err;
}

/*********************************************************************//**
**
** StartSendingToController
**
** Function called to start sending the first queued message for the specified controller
** NOTE: This function handles all internal errors by scheduling a retry of this function in the future
**
** \param   cc - pointer to structure describing controller to send to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void StartSendingToController(coap_controller_t *cc)
{
    coap_pdu_t  *pdu;
    coap_address_t ca;
    unsigned new_token;
    coap_send_item_t *csi;
    
    // Store state for this communication
    csi = (coap_send_item_t *) cc->send_queue.head;
    cc->block_num = 0;
    cc->block_size = kCoapBlockSize_1024;

    // Generate a new token which is different from the last token
    new_token = rand_r(&mtp_thread_random_seed);
    while (new_token == cc->token)
    {
        new_token = rand_r(&mtp_thread_random_seed);
    }
    cc->token = new_token;

    // Print protocol trace debug
    MSG_HANDLER_LogMessageToSend(csi->usp_msg_type, csi->pbuf, csi->pbuf_len, kMtpProtocol_CoAP, csi->host, NULL);

    // Exit if unable to create the initial packet to send
    #define COAP_RETRY_FIRST_BLOCK_TIME 5
    pdu = CreateSendBlock(cc, csi);
    if (pdu == NULL)
    {
        USP_LOG_Error("%s: coap_block_pdu() failed. Retrying in %d seconds.", __FUNCTION__, COAP_RETRY_FIRST_BLOCK_TIME);
        cc->retry_time = time(NULL) + COAP_RETRY_FIRST_BLOCK_TIME;
        return;
    }

    // Exit if unable to resolve the hostname of the CoAP controller
    memset(&ca, 0, sizeof(ca));
    ca.size = ResolveCoapAddress(csi->host, csi->port, &ca.addr.sa);
    if (ca.size == 0)
    {
        USP_LOG_Error("%s: Failed to resolve address for %s. Retrying in %d seconds.", __FUNCTION__, csi->host, COAP_RETRY_FIRST_BLOCK_TIME);
        cc->retry_time = time(NULL) + COAP_RETRY_FIRST_BLOCK_TIME;
        return;
    }

    // Exit if unable to send the packet
    cc->tid = coap_send_confirmed(cc->coap_client_ctx, cc->coap_client_ctx->endpoint, &ca, pdu);
    if (cc->tid == COAP_INVALID_TID)
    {
        USP_LOG_Error("%s: coap_send_confirmed() failed. Retrying in %d seconds.", __FUNCTION__, COAP_RETRY_FIRST_BLOCK_TIME);
        cc->retry_time = time(NULL) + COAP_RETRY_FIRST_BLOCK_TIME;
        return;
    }

    // Since we successfully sent the first block, we do not have to schedule a retry
    cc->retry_time = 0;
}

/*********************************************************************//**
**
** HandleCoapPost
**
** Handles received CoAP USP packets containing POST messages
**
** \param   ctx - 
** \param   resource - 
** \param   local_interface - 
** \param   peer - 
** \param   request - 
** \param   token - 
** \param   response - 
**
** \return  Nothing
**
**************************************************************************/
void HandleCoapPost(coap_context_t *ctx, struct coap_resource_t *resource, const coap_endpoint_t *local_interface,
                    coap_address_t *peer, coap_pdu_t *request, str *token, coap_pdu_t *response)
{
    size_t bufsize;
    unsigned char buf[4];
    char host[INET6_ADDRSTRLEN] = { 0 };
    char time_buf[MAX_ISO8601_LEN];
    coap_opt_t *block_opt = NULL;
    coap_opt_iterator_t opt_iter;
    unsigned char *fragment;
    size_t fragment_size;
    unsigned blknum = 0;  // Assume that the message did not contain any blocks
    unsigned blksize = 0;
    unsigned blksize_code = 0;
    unsigned more = 0;   // Assume that this is the last block, or that the message does not contain any blocks (just payload)
    int offset;
    int new_len;
    int len;
    coap_server_t *cs;

    // Exit if unable to find the coap server that sent this CoAP PDU
    cs = FindCoapServerByContext(ctx);

    // Exit if this is a duplicate CoAP packet (same message ID as the last).
    // This could occur if the controller has retried sending the packet to us, before the controller received our ACK
    if (cs->last_message_id == request->hdr->id)
    {
        // Silently ignore this packet, if we have already sent an ACK for it
        return;
    }

    // Since all exits from this function process the packet and send an ACK, save this message id
    cs->last_message_id = request->hdr->id;

    // NOTE: We do not check the content format of the payload, because some clients (eg Coapthon) do not set this option

    // Extract block meta-data, if this is a block-wise transfer
    block_opt = coap_check_option(request, COAP_OPTION_BLOCK1, &opt_iter);
    if (block_opt)
    {
        // Extract block fields
        blknum = coap_opt_block_num(block_opt);
        blksize_code = COAP_OPT_BLOCK_SZX(block_opt);
        more = COAP_OPT_BLOCK_MORE(block_opt);

        // Exit if we have not received the block we expected (which is either a duplicate of the last block, or the next block)
        // Discard the transfer, and send back a 4.00 Bad Request
        if ((blknum != cs->last_block) && (blknum != cs->last_block + 1))
        {
            USP_LOG_Warning("%s: Dropping a received CoAP message because we received an out of order block", __FUNCTION__);
            cs->rxbuf_msglen = 0;
            cs->last_block = -1;
            response->hdr->code = COAP_RESPONSE_CODE(400);
            return;
        }
        cs->last_block = blknum;
    }

    // Determine response to send back
    if (more == 0)
    {
        // This is the last block, or the payload fully contained the message (ie non-blockwise transfer)
        response->hdr->code = COAP_RESPONSE_CODE(204);
    }
    else
    {
        // This is not the last block
        USP_ASSERT(block_opt);
        response->hdr->code = COAP_RESPONSE_CODE(231);
        bufsize = coap_encode_var_bytes(buf, (blknum << 4) | more | blksize_code);
        coap_add_option(response, COAP_OPTION_BLOCK1, bufsize, buf);
    }

    // Check the token
    if (blknum == 0)
    {
        // If this is the first block, then save off the token for the block-wise transfer, so we can check it next time
        len = MIN(token->length, sizeof(cs->token));
        cs->token_len = len;
        memcpy(&cs->token, token->s, len);
    }
    else
    {
        // For subsequent blocks in the transfer, check that the token matches that given in the first block
        // If it doesn't then discard the transfer, and send back a 4.00 Bad Request
        len = MIN(token->length, sizeof(cs->token));
        if ((len != cs->token_len) || (memcmp(token->s, cs->token, len) != 0))
        {
            USP_LOG_Warning("%s: Dropping a received CoAP message because we received a changed token", __FUNCTION__);
            cs->rxbuf_msglen = 0;
            cs->last_block = -1;
            response->hdr->code = COAP_RESPONSE_CODE(400);
            return;
        }
    }

    // Exit if there is no payload to append - this is an error
    // Discard the transfer, and send back a 4.00 Bad Request
    coap_get_data(request, &fragment_size, &fragment);
    if (fragment == NULL)
    {
        USP_LOG_Warning("%s: Dropping a received CoAP message because we received a packet without a payload", __FUNCTION__);
        cs->rxbuf_msglen = 0;
        cs->last_block = -1;
        response->hdr->code = COAP_RESPONSE_CODE(400);
        return;
    }

    // Append the payload to that already received from this controller
    // NOTE: This code works irrespective of whether the PDU is a blockwise transfer or not
    // This code does not cope with missing block numbers. These will be caught by USP protobuf message parsing if they occur.
    // (It's the responsibility of coap clients to ensure they send each block, and get an acknowledgement for each block, before sending the next block)
    blksize = 1 << (blksize_code + 4);
    offset = blknum*blksize;
    new_len = offset + fragment_size;

    // Prevent rogue controllers from crashing agent by setting an arbitrary message size limit
    // Discard the transfer, and send back a 4.00 Bad Request
    if (new_len > MAX_USP_MSG_LEN)
    {
        USP_LOG_Warning("%s: Dropping a received CoAP message >%d bytes long.", __FUNCTION__, MAX_USP_MSG_LEN);
        cs->rxbuf_msglen = 0;
        cs->last_block = -1;
        response->hdr->code = COAP_RESPONSE_CODE(400);
        return;
    }
    
    // Increase receive buffer size, if it isn't large enough to hold this extra fragment
    if (new_len > cs->rxbuf_maxlen)
    {
        cs->rxbuf = USP_REALLOC(cs->rxbuf, new_len);
        cs->rxbuf_maxlen = new_len;
    }

    // Copy into the receive buffer
    // In the case of duplicates, the latter will just overwrite the former
    memcpy(&cs->rxbuf[offset], fragment, fragment_size);

    // Update the length of message stored in the receive buffer
    if (new_len > cs->rxbuf_msglen)
    {
        cs->rxbuf_msglen = new_len;
    }

    // If we have fully received a message, then process it
    if (more == 0)
    {
        // Log the message
        inet_ntop(peer->addr.sin.sin_family, &peer->addr.sin.sin_addr, host, sizeof(host));
        iso8601_cur_time(time_buf, sizeof(time_buf));
        USP_PROTOCOL("\n");
        USP_LOG_Info("Message received at time %s, from host %s over CoAP", time_buf, host);

        // Process the message
        DM_EXEC_PostUspRecord(cs->rxbuf, cs->rxbuf_msglen, ROLE_COAP, NULL, NULL, INVALID);

        // Reset the CoAP receive buffer
        cs->rxbuf_msglen = 0;
        cs->last_block = -1;
    }
}

/*********************************************************************//**
**
** CreateSendBlock
**
** Creates a CoAP USP packet containing a POST message
** This function deals with fragmenting the message into blocks
**
** \param   cc - Pointer to state variables for the controller sending the message
**
** \return  pointer to PDU to send, or NULL if failed to create
**
**************************************************************************/
coap_pdu_t *CreateSendBlock(coap_controller_t *cc, coap_send_item_t *csi)
{
    coap_pdu_t *pdu;
    unsigned short id;
    unsigned char option[4];
    unsigned char *p;
    unsigned int block_option;
    int option_len;
    int more_blocks;
    int err;
    char uri_query[256];
    coap_server_t *cs;
  
    // Exit if unable to create a new PDU
    id = coap_new_message_id(cc->coap_client_ctx);
    pdu = coap_pdu_init(COAP_MESSAGE_CON,  COAP_REQUEST_POST,  id,  COAP_MAX_PDU_SIZE);
    if (pdu == NULL)
    {
        return NULL;
    }
  
    // Exit if unable to add our token
    err = coap_add_token(pdu, sizeof(cc->token), (unsigned char *)&cc->token);
    if (err == 0)
    {
        return NULL;
    }

    // Form the reply_to string
    // 2DO RH: How do we deal with more than one CoAP MTP listener - which do we choose ?
    uri_query[0] = '\0';

    // Add Options (must be in numerical order)
    // Add Host (that we're sending to) option
    coap_add_option(pdu, COAP_OPTION_URI_HOST, strlen(csi->host), (unsigned char *)csi->host);

    // Add URI port (that we're sending to) option
    p = &option[0];
    WRITE_2_BYTES(p, csi->port);
    coap_add_option(pdu, COAP_OPTION_URI_PORT, 2, option);

    // Add URI path (that we're sending to) option
    coap_add_option(pdu, COAP_OPTION_URI_PATH, strlen(csi->resource), (unsigned char *)csi->resource);

    // Add ContentType option
    option_len = coap_encode_var_bytes(option, COAP_MEDIATYPE_APPLICATION_OCTET_STREAM);
    coap_add_option(pdu, COAP_OPTION_CONTENT_TYPE, option_len, option);

    // Add the URI query option
    cs = &coap_servers[0];
    if (cs->instance != INVALID)
    {
        // 2DO RH: The following string needs to deal with escaping characters
        // 2DO RH: Currently the listen-address is on all interfaces (ie 0.0.0.0), this needs changing to a specific interface
        USP_SNPRINTF(uri_query, sizeof(uri_query), "reply-to=coap://%s:%d/%s", cs->listen_addr, cs->listen_port, cs->listen_resource);
        coap_add_option(pdu, COAP_OPTION_URI_QUERY, strlen(uri_query), (unsigned char *)uri_query);
    }
    
    // Add Block1 option
    more_blocks = coap_more_blocks(csi->pbuf_len, cc->block_num, cc->block_size);
    block_option = (cc->block_num << 4) | (more_blocks << 3) | cc->block_size;
    option_len = coap_encode_var_bytes(option, block_option);
    coap_add_option(pdu, COAP_OPTION_BLOCK1, option_len, option);

    // Add Size1 option
    p = &option[0];
    WRITE_4_BYTES(p, csi->pbuf_len);
    coap_add_option(pdu, COAP_OPTION_SIZE1, 4, option);

    // Add the payload
    coap_add_block(pdu, csi->pbuf_len, csi->pbuf, cc->block_num, cc->block_size);
  
    return pdu;
}

/*********************************************************************//**
**
** ResolveCoapAddress
**
** Wrapper function called to resolve a hostname into a sockaddr structure
**
** \param   hostname - DNS hostname of the controller we want to contact
** \param   dst - pointer to structure to return the sockaddr in
**
** \return  length of the sockaddr structure filled in, or -1 on error
**
**************************************************************************/
int ResolveCoapAddress(char *hostname, int port, struct sockaddr *dst)
{
    int err;
    nu_ipaddr_t resolved_ip_addr;
    socklen_t len;

    // Exit if unable to resolve the given hostname
    // 2DO RH: Add code to include our ipv6 preference
    err = tw_ulib_diags_lookup_host(hostname, AF_UNSPEC, false, NULL, &resolved_ip_addr);
    if (err != USP_ERR_OK)
    {
        return 0;
    }

    // Exit if an error occurred converting back to a struct sockaddr
    // NOTE: This should never happen if the nu_ipaddr code is correct
    err = nu_ipaddr_to_sockaddr(&resolved_ip_addr, port, (struct sockaddr_storage *) dst, &len);
    if (err != USP_ERR_OK)
    {
        return 0;
    }

    return len;
}

/*********************************************************************//**
**
** HandleCoapAck
**
** Function called whenever an acknowledgment message is received back from a controller
** (the controller will be sending the ACK, because we send it a BLOCK message)
** This function will send the next block
**
** \param   ctx - 
** \param   local_interface - 
** \param   remote - 
** \param   sent - 
** \param   received - 
** \param   id - libcoap assigned transaction id identifying the USP message that this is an acknowledgement for
**
** \return  None
**
**************************************************************************/
void HandleCoapAck(struct coap_context_t *ctx,
                   const coap_endpoint_t *local_interface, const coap_address_t *remote,
                   coap_pdu_t *sent, coap_pdu_t *received, const coap_tid_t id)
{
    coap_pdu_t *pdu = NULL;
    coap_opt_t *block_opt;
    coap_opt_iterator_t opt_iter;
    unsigned int req_block_size;
    coap_controller_t *cc;
    coap_send_item_t *csi;
    unsigned blksize;

    // Exit if unable to find the controller who sent the ACK message - just ignore these
    // NOTE: This should never happen if our software is correct
    cc = FindCoapControllerByContext(ctx);
    if (cc == NULL)
    {
        USP_LOG_Warning("%s: Received a CoAP ACK from an unknown context", __FUNCTION__);
        return;
    }

    csi = (coap_send_item_t *)cc->send_queue.head;

    // Exit if token in response does not match the one we sent in the request, attempting to resend the current message
    if ((received->hdr->token_length != sizeof(cc->token)) || 
        (memcmp(received->hdr->token, &cc->token, sizeof(cc->token)) != 0))
    {
        USP_LOG_Warning("%s: Received a CoAP ACK with unexpected token. Attempting to resend.", __FUNCTION__);
        sleep(3); // 2DO RH: The retry needs to occur with exponential backoff, not a fixed inline delay
        StartSendingToController(cc);
        return;
    }
  
    // Exit if got a reset response, attempting to resend the current message
    if (received->hdr->type == COAP_MESSAGE_RST)
    {
        USP_LOG_Warning("%s: Received a CoAP RST. Attempting to resend.", __FUNCTION__);
        sleep(3); // 2DO RH: The retry needs to occur with exponential backoff, not a fixed inline delay
        StartSendingToController(cc);
        return;
    }
  
    // Exit if got an error response code, attempting to resend the current message
    if (COAP_RESPONSE_CLASS(received->hdr->code) == 4)
    {
        USP_LOG_Warning("%s: Received a CoAP Error response code. Attempting to resend.", __FUNCTION__);
        sleep(3); // 2DO RH: The retry needs to occur with exponential backoff, not a fixed inline delay
        StartSendingToController(cc);
        return;
    }
  
    // Exit if the response code received was not the one expected based on our current state
    // Response codes expected for blockwise transfers are 2.31 (Continue) and 2.04 (Changed)
    if (COAP_RESPONSE_CLASS(received->hdr->code) != 2)
    {
        USP_LOG_Warning("%s: Received an unexpected CoAP response code (got %d.%d - expected 2.XX). Attempting to resend.", __FUNCTION__, COAP_RESPONSE_CLASS(received->hdr->code), COAP_RESPONSE_CODE(received->hdr->code));
        sleep(3); // 2DO RH: The retry needs to occur with exponential backoff, not a fixed inline delay
        StartSendingToController(cc);
        return;
    }
  
    // If the acknowledge included a block option then see if the controller requested a different size
    // NOTE: We ignore the request, because we are allowed to by the spec, and processing it throws up a
    // number of complex corner cases which are not easy to cope with
    block_opt = coap_check_option(received, COAP_OPTION_BLOCK1, &opt_iter);
    if (block_opt != NULL)
    {
        req_block_size = COAP_OPT_BLOCK_SZX(block_opt);
        if (req_block_size != cc->block_size)
        {
            USP_LOG_Warning("%s: Ignoring CoAP controller request to change block size", __FUNCTION__);
        }
    }
  
    // Move to sending out next block
    cc->block_num++;
  
    // Exit if we've already sent everything
    blksize = 1 << (cc->block_size + 4);
    if (csi->pbuf_len <= cc->block_num * blksize)
    {
        // Free the current message from the send queue
        USP_FREE(csi->pbuf);
        USP_FREE(csi->host);
        USP_FREE(csi->resource);
        DLLIST_Unlink(&cc->send_queue, csi);
        USP_FREE(csi);

        // If there is still another message in the queue, then start sending it
        csi = (coap_send_item_t *)cc->send_queue.head;
        if (csi != NULL)
        {
            StartSendingToController(cc);
        }
        return;
    }
  
    // Exit if unable to create the next PDU block to send
    pdu = CreateSendBlock(cc, csi);
    if (pdu == NULL)
    {
       return;
    }
  
    // Exit if unable to send the next PDU  in the block-wise transfer
    cc->tid = coap_send_confirmed(ctx, local_interface, remote, pdu);
    if (cc->tid == COAP_INVALID_TID)
    {
        USP_LOG_Error("%s: coap_send_confirmed() failed", __FUNCTION__);
        coap_delete_pdu(pdu);   // Delete the PDU (since it will not have been saved in a resend queue)
        return;
    }
  
    // If the code gets here, the PDU was sent successfully
}

/*********************************************************************//**
**
** FindUnusedCoapServer
**
** Finds an unused CoAP server slot
**
** \param   None
**
** \return  pointer to free CoAP server, or NULL if none found
**
**************************************************************************/
coap_server_t *FindUnusedCoapServer(void)
{
    int i;
    coap_server_t *cs;

    // Iterte over all CoAP servers, trying to find a free slot
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if (cs->instance == INVALID)
        {
            return cs;
        }
    }

    // If the code gets here, then no free CoAP servers were found
    return NULL;
}

/*********************************************************************//**
**
** FindCoapServerByContext
**
** Finds the coap server entry with the specified libcoap context
**
** \param   None
**
** \return  pointer to matching CoAP server, or NULL if none found
**
**************************************************************************/
coap_server_t *FindCoapServerByContext(coap_context_t *ctx)
{
    int i;
    coap_server_t *cs;

    // Iterate over all CoAP servers, trying to find a matching slot
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if ((cs->instance != INVALID) && (cs->coap_server_ctx == ctx))
        {
            return cs;
        }
    }

    // If the code gets here, then no matching CoAP servers were found
    return NULL;
}

/*********************************************************************//**
**
** FindCoapServerByInstance
**
** Finds the coap server entry with the specified instance number (from Device.LocalAgent.MTP.{i})
**
** \param   instance - instance number in Device.LocalAgent.MTP.{i} for this server
**
** \return  pointer to matching CoAP server, or NULL if none found
**
**************************************************************************/
coap_server_t *FindCoapServerByInstance(int instance)
{
    int i;
    coap_server_t *cs;

    // Iterate over all CoAP servers, trying to find a matching slot
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if (cs->instance == instance)
        {
            return cs;
        }
    }

    // If the code gets here, then no matching CoAP servers were found
    return NULL;
}

/*********************************************************************//**
**
** FindUnusedCoapController
**
** Finds an unused CoAP controller slot
**
** \param   None
**
** \return  pointer to free CoAP controller, or NULL if none found
**
**************************************************************************/
coap_controller_t *FindUnusedCoapController(void)
{
    int i;
    coap_controller_t *cc;
    
    // Iterate over all CoAP controllers, trying to find a free slot
    for (i=0; i<MAX_COAP_CONNECTIONS; i++)
    {
        cc = &coap_controllers[i];
        if (cc->cont_instance == INVALID)
        {
            return cc;
        }
    }

    // If the code gets here, then no free CoAP controllers were found
    return NULL;
}


/*********************************************************************//**
**
** FindCoapControllerByInstance
**
** Finds a controller by it's instance numbers
**
** \param   cont_instance -  Instance number of the controller in Device.LocalAgent.Controller.{i}
** \param   mtp_instance -   Instance number of this MTP in Device.LocalAgent.Controller.{i}.MTP.{i}
**
** \return  pointer to matching CoAP controller, or NULL if none found
**
**************************************************************************/
coap_controller_t *FindCoapControllerByInstance(int cont_instance, int mtp_instance)
{
    int i;
    coap_controller_t *cc;
    
    // Iterate over all CoAP controllers, trying to find a match
    for (i=0; i<MAX_COAP_CONNECTIONS; i++)
    {
        cc = &coap_controllers[i];
        if ((cc->cont_instance == cont_instance) && (cc->mtp_instance == mtp_instance))
        {
            return cc;
        }
    }

    // If the code gets here, then no match was found
    return NULL;
}

/*********************************************************************//**
**
** FindCoapControllerByContext
**
** Finds a coap controller by the libcoap context
**
** \param   ctx - libcoap context
**
** \return  pointer to matching CoAP controller, or NULL if none found
**
**************************************************************************/
coap_controller_t *FindCoapControllerByContext(coap_context_t *ctx)
{
    int i;
    coap_controller_t *cc;
    
    // Iterate over all CoAP controllers, trying to find a match
    for (i=0; i<MAX_COAP_CONNECTIONS; i++)
    {
        cc = &coap_controllers[i];
        if ((cc->cont_instance != INVALID) && (cc->coap_client_ctx == ctx))
        {
            return cc;
        }
    }

    // If the code gets here, then no match was found
    return NULL;
}


#endif // ENABLE_COAP
