/*
 *
 * Copyright (C) 2023, Broadband Forum
 * Copyright (C) 2023  CommScope, Inc
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
 * \file usp_service.c
 *
 * Contains functions for a USP Endpoint cating as a USP Service
 *
 */

#include <stdlib.h>
#include <string.h>

#include "common_defs.h"
#include "data_model.h"
#include "msg_handler.h"
#include "msg_utils.h"
#include "text_utils.h"
#include "iso8601.h"
#include "usp_broker.h"
#include "os_utils.h"
#include "usp_api.h"

#include <semaphore.h>

#ifndef REMOVE_USP_SERVICE
//------------------------------------------------------------------------
// Comma separated list containing the endpoint_id of the USP Broker, followed by the top-level data model objects to register
// This string is set by the value of the '-R' option and is not changed by subsequent '-c register' or '-c deregister' CLI invocations
char *usp_service_objects = NULL;

//------------------------------------------------------------------------------
// Message ID of the register message upon which we are waiting for a response (and Broker's endpoint_id)
static char *register_msg_id = NULL;

// The endpoint of the broker as an agent when service running as a controller
static char *usp_broker_agent_endpoint_id = NULL;

// The endpoint of the broker as a controller when service acting as a data model provider
static char *usp_broker_controller_endpoint_id = NULL;

// Identifies the MTP to use when acting as a controller sending to the Endpoint's agent
static mtp_conn_t usp_broker_agent_mtpc;

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
Usp__Msg *CreateUspServiceRegisterReq(char *msg_id, char **paths, int num_paths);
Usp__Msg *CreateUspServiceDeregisterReq(char *msg_id, char **paths, int num_paths);
Usp__Msg *CreateUspServiceGetReq(kv_vector_t *kvv);
Usp__Msg *CreateUspServiceSetReq(kv_vector_t *kvv);
void CalcUspServiceMessageId(char *msg_id, int len);
int ProcessUspServiceGetResponse(Usp__Msg *resp, kv_vector_t *kvv);
void HandleUspServiceControllerMessageResponseTimeout(int id);
void QueueUspServiceRequest(void *arg1, void *arg2);

//------------------------------------------------------------------------------

// Outgoing messages and their responses are sent and received asynchronously using the datamodel thread
// In order to accomplish this we post the following structure into USP_PROCESS_DoWork() which calls us
// back from the datamodel thread.  We handle all interaction with MSG_HANDLER_QueueMessage from within
// that thread.  When an outgoing message is sent to the broker, we store the message ID in the list below
// and filter for a matching response in USP_SERVICE_AsController_IsExpectedResponse.  If a response is
// not received within the specified time then a timeout will fire and return an error.

// Outgoing USP control message and incoming USP response parameters
typedef struct
{
    double_link_t    link;        // linked list node structure
    Usp__Msg        *req;         // the USP message to send
    sem_t            semaphore;   // A semphore to signal to the sender when the response has arrived or a timeout occurred
    kv_vector_t     *params;      // A key/value pair vector to contain the results
    int              timeout;     // The time to wait before failing and returning an error
    int              err_code;    // USP_ERR_xxx indicting success of failure of the request
    char            *err_msg;     // pointer to buffer in which to return an error message (only used if error code is failed)
    int              err_msg_len; // length of buffer in which to return an error message (only used if error code is failed)
    int              timeout_id;  // Each request has a corresponding timeout
} request_t;

// The list of outstanding message responses we are filtering for
static double_linked_list_t usp_service_ctrler_pending_msg_list = { NULL, NULL };

/*********************************************************************//**
**
** USP_SERVICE_SetBrokerAgent
**
** Configures the USP broker connection to use when acting as a controller
** Must be called from the datamodel thread
**
** \param  endpoint_id - endpoint of the broker agent path
** \param  mtp_conn - connection parameters to use for the broker
**
** \return  USP_ERR_OK if okay, or an error
**
**************************************************************************/
int USP_SERVICE_SetBrokerAgent(char *endpoint_id, mtp_conn_t *mtp_conn)
{
    USP_LOG_Debug("%s: Setting broker agent endpoint to : %s", __FUNCTION__, endpoint_id);

    USP_ASSERT(mtp_conn->protocol == kMtpProtocol_UDS);
    USP_ASSERT(mtp_conn->uds.conn_id != INVALID);

    // Free the string if function called twice (typically this function is expected to be called only once).
    USP_SAFE_FREE(usp_broker_agent_endpoint_id);

    usp_broker_agent_endpoint_id = USP_STRDUP(endpoint_id);
    usp_broker_agent_mtpc = *mtp_conn;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** USP_SERVICE_AsController_IsExpectedResponse
**
** Called from Datamodel thread hook in message handler HandleUspMessage()
** Determines whether the specified USP message is a response to a request sent by this USP Service acting as a Controller
** If it is, then the USP response message is processed here
**
** \param  usp - a received USP message buffer
**
** \return bool - true if the message matches a response to an outgoing control message otherwise false
**
**************************************************************************/
bool USP_SERVICE_AsController_IsExpectedResponse(Usp__Msg *usp)
{
    int failure_index;
    int err = USP_ERR_OK;
    char *usp_err_msg;
    request_t *queued_msg;

    USP_ASSERT(usp != NULL);

    // Exit if we received a request message, these aren't expected to be processed here, yet
    if (usp->body->msg_body_case == USP__BODY__MSG_BODY_REQUEST)
    {
        return false;
    }

    // Exit if we're not waiting for any responses
    queued_msg = (request_t *)usp_service_ctrler_pending_msg_list.head;
    if (queued_msg == NULL)
    {
        return false;
    }

    // Exit if message was a response and type of response was not one of the ones we handle here
    if (usp->body->msg_body_case == USP__BODY__MSG_BODY_RESPONSE)
    {
        USP_ASSERT(usp->body->response != NULL);
        if ((usp->body->response->resp_type_case != USP__RESPONSE__RESP_TYPE_GET_RESP) &&
            (usp->body->response->resp_type_case != USP__RESPONSE__RESP_TYPE_SET_RESP))
        {
            return false;
        }
    }

    // iterate through all control messages that are waiting for a response
    while (queued_msg != NULL)
    {
        request_t *next_msg;
        next_msg = (request_t *)queued_msg->link.next;

        // check the incoming message ID against the list of pending messages waiting for a response
        if ((usp->header->msg_id != NULL) && (strcmp(usp->header->msg_id, queued_msg->req->header->msg_id) == 0))
        {
            // Any errors detected in the USP response will be captured by USP_ERR.  Note that though errors
            // this does not imply total failure, and it may be that the response contains some values and not others
            USP_ERR_ClearMessage();

            // Process response based on message type of original request, as we could have received an ERROR response
            // we must process USP response here as the calling thread has ownership and will free it
            switch (queued_msg->req->header->msg_type)
            {
                case USP__HEADER__MSG_TYPE__GET:
                    err = ProcessUspServiceGetResponse(usp, queued_msg->params);
                    break;

                case USP__HEADER__MSG_TYPE__SET:
                    err = MSG_UTILS_ProcessSetResponse(usp, queued_msg->params, &failure_index);
                    break;

                default:
                    break;
            }

            // if we encounter any errors during processing, add them to the request/response structure
            if (err != USP_ERR_OK)
            {
                queued_msg->err_code = err;
                if (queued_msg->err_msg != NULL)
                {
                    usp_err_msg = USP_ERR_GetMessage();
                    USP_SNPRINTF(queued_msg->err_msg, queued_msg->err_msg_len , "%s", usp_err_msg);
                }
            }

            // cancel any active timeout associated with this control message
            SYNC_TIMER_Remove(HandleUspServiceControllerMessageResponseTimeout, queued_msg->timeout_id);

            // remove the message from the pending message response list
            DLLIST_Unlink(&usp_service_ctrler_pending_msg_list, queued_msg);

            // post the semaphore to unblock the vendor thread
            sem_post(&queued_msg->semaphore);

            return true;
        }
        queued_msg = next_msg;
    }

    // If the code gets here, then the USP message was not a response to a request from this USP Service acting as a Controller
    return false;
}

/*********************************************************************//**
**
** USP_SERVICE_Get_AsController
**
** Queues a USP GET request to send to the broker
**
** \param   params - A list of parameter paths to GET
** \param   timeout - maximum length of time (seconds) to wait for a response before returning
** \param   err_code - pointer to variable in which to return an error code
** \param   err_msg - pointer to buffer in which to return an error message (only used if error code is failed)
** \param   err_msg_len - length of buffer in which to return an error message (only used if error code is failed)
**
** \return  USP_ERR_OK if okay, or an error
**
**************************************************************************/
int USP_SERVICE_Get_AsController(kv_vector_t *params, int timeout, char *err_msg, int err_msg_len)
{
    int err = USP_ERR_OK;

    USP_ASSERT(params != NULL);
    USP_ASSERT(err_msg != NULL);
    *err_msg = '\0';

    // only allow requests if we have a valid USP agent endpoint
    if (usp_broker_agent_endpoint_id == NULL)
    {
       USP_LOG_Error("%s: USP broker agent endpoint has not been set", __FUNCTION__);
       return USP_ERR_INTERNAL_ERROR;
    }

    request_t request;
    request.err_code = USP_ERR_OK;
    request.err_msg = err_msg;
    request.err_msg_len = err_msg_len;
    request.timeout = timeout;
    request.req = CreateUspServiceGetReq(params);

    // clear the input parameters as we don't want to return these in the result
    KV_VECTOR_Destroy(params);
    KV_VECTOR_Init(params);
    request.params  = params;

    sem_init(&request.semaphore,0,0);

    USP_PROCESS_DoWork( QueueUspServiceRequest, (void *)&request, (void*)NULL);

    sem_wait(&request.semaphore);

    err = request.err_code;
    usp__msg__free_unpacked(request.req, pbuf_allocator);
    sem_destroy(&request.semaphore);

    return err;
}

/*********************************************************************//**
**
** USP_SERVICE_Set_AsController
**
** Queues a USP SET request to send to the broker
**
** \param   params - A list of parameter paths and corresponding values to SET
** \param   timeout - maximum length of time (seconds) to wait for a response before returning
** \param   err_code - pointer to variable in which to return an error code
** \param   err_msg - pointer to buffer in which to return an error message (only used if error code is failed)
** \param   err_msg_len - length of buffer in which to return an error message (only used if error code is failed)
**
** \return  USP_ERR_OK if okay, or an error
**
**************************************************************************/
int USP_SERVICE_Set_AsController(kv_vector_t *params, int timeout, char *err_msg, int err_msg_len)
{
    int err = USP_ERR_OK;

    USP_ASSERT(params != NULL);
    USP_ASSERT(err_msg != NULL);
    *err_msg = '\0';

    // only allow requests if we have a valid USP agent endpoint
    if (usp_broker_agent_endpoint_id == NULL)
    {
       USP_LOG_Error("%s: USP broker agent endpoint has not been set", __FUNCTION__);
       return USP_ERR_INTERNAL_ERROR;
    }

    request_t request;
    request.err_code = USP_ERR_OK;
    request.err_msg = err_msg;
    request.err_msg_len = err_msg_len;
    request.timeout = timeout;
    request.req = CreateUspServiceSetReq(params);
    request.params  = params;
    sem_init(&request.semaphore,0,0);

    USP_PROCESS_DoWork(QueueUspServiceRequest, (void *)&request, (void*)NULL);

    sem_wait(&request.semaphore);

    err = request.err_code;
    usp__msg__free_unpacked(request.req, pbuf_allocator);
    sem_destroy(&request.semaphore);

    return err;
}

/*********************************************************************//**
**
** USP_SERVICE_QueueRegisterRequest
**
** Queues a USP Register Request to register parts of the data model provided by this endpoint with the USP Broker
**
** \param   endpoint_id - Endpoint ID of the Broker to send the message to
** \param   objects - comma separated list of objects to register
**
** \return  None
**
**************************************************************************/
void USP_SERVICE_QueueRegisterRequest(char *endpoint_id, char *objects)
{
    int i;
    char *path;
    str_vector_t sv;
    Usp__Msg *msg;
    dm_node_t *node;
    dm_instances_t inst;
    mtp_conn_t mtpc = {0};
    char msg_id[MAX_MSG_ID_LEN];

    USP_ASSERT(objects != NULL);
    mtpc.is_reply_to_specified = false;   // Force DEVICE_CONTROLLER_QueueBinaryMessage() to calculate an MRT destination for the request

    // Iterate over all paths, validating them
    TEXT_UTILS_SplitString(objects, &sv, ",");
    for (i=0; i < sv.num_entries; i++)
    {
        // Exit if path does not exist in the data model (of this endpoint)
        path = sv.vector[i];
        node = DM_PRIV_GetNodeFromPath(path, &inst, NULL, 0);
        if (node == NULL)
        {
            USP_LOG_Error("%s: Cannot register path '%s' with USP Broker as it is not present in the data model", __FUNCTION__, path);
            goto exit;
        }

        // Exit if path contains instance numbers
        if (inst.order > 0)
        {
            USP_LOG_Error("%s: Cannot register path '%s' with USP Broker as it contains instance numbers", __FUNCTION__, path);
            goto exit;
        }
    }

    // Create a register request
    CalcUspServiceMessageId(msg_id, sizeof(msg_id));
    msg = CreateUspServiceRegisterReq(msg_id, sv.vector, sv.num_entries);
    MSG_HANDLER_QueueMessage(endpoint_id, msg, &mtpc);

    // Save off the message_id and endpoint_id, in order that we can check the register response against them
    USP_SAFE_FREE(register_msg_id);
    USP_SAFE_FREE(usp_broker_controller_endpoint_id);
    register_msg_id = USP_STRDUP(msg_id);
    usp_broker_controller_endpoint_id = USP_STRDUP(endpoint_id);

    usp__msg__free_unpacked(msg, pbuf_allocator);

exit:
    STR_VECTOR_Destroy(&sv);
}

/*********************************************************************//**
**
** USP_SERVICE_HandleRegisterResp
**
** Handles a USP Register response message
** NOTE: This function just validates and logs the response.
**       No action is taken upon registration failures. It is expected that the USP Broker won't query the USP Service if it failed to register
**
** \param   usp - pointer to parsed USP message structure. This is always freed by the caller (not this function)
** \param   endpoint_id - endpoint of USP broker which sent this message
** \param   mtpc - details of where this USP message came from
**
** \return  None
**
**************************************************************************/
void USP_SERVICE_HandleRegisterResp(Usp__Msg *usp, char *endpoint_id, mtp_conn_t *mtpc)
{
    int i;
    Usp__RegisterResp *reg;
    Usp__RegisterResp__RegisteredPathResult *rpr;
    Usp__RegisterResp__RegisteredPathResult__OperationStatus__OperationFailure *oper_failure;

    // NOTE: All errors in parsing response messages should be ignored according to R-MTP.5 (they should not send a USP ERROR response)

    // Exit, if not currently waiting for a register response
    if ((usp_broker_controller_endpoint_id == NULL) || (register_msg_id == NULL))
    {
        USP_LOG_Error("%s: Ignoring response that we were not expecting (msg_id=%s from endpoint=%s)", __FUNCTION__, usp->header->msg_id, endpoint_id);
        return;
    }

    // Exit if the response is not from the Broker we sent it to
    if (strcmp(endpoint_id, usp_broker_controller_endpoint_id) != 0)
    {
        USP_LOG_Error("%s: Incoming Register Response is from an unexpected endpoint (%s, expected %s)", __FUNCTION__, endpoint_id, usp_broker_controller_endpoint_id);
        return;
    }

    // Exit if the msg_id of this register response does not match the one we sent in our request
    if (strcmp(usp->header->msg_id, register_msg_id) != 0)
    {
        USP_LOG_Error("%s: Ignoring register response from endpoint '%s' because msg_id='%s' (expected '%s')", __FUNCTION__, endpoint_id, usp->header->msg_id, register_msg_id);
        return;
    }

    // Since we've determined that the response message was expected, reset the saved message_id and endpoint_id, as we're not expecting any other responses
    USP_FREE(register_msg_id);
    USP_FREE(usp_broker_controller_endpoint_id);
    register_msg_id = NULL;
    usp_broker_controller_endpoint_id = NULL;

    // Exit, if we received an ERROR response to the Register request
    if (usp->header->msg_type == USP__HEADER__MSG_TYPE__ERROR)
    {
        if ((usp->body == NULL) || (usp->body->msg_body_case != USP__BODY__MSG_BODY_ERROR) ||
            (usp->body->error == NULL) || (usp->body->error->err_msg == NULL))
        {
            USP_LOG_Error("%s: Incoming message (msg_id=%s) is invalid or inconsistent", __FUNCTION__, usp->header->msg_id);
            return;
        }

        USP_LOG_Error("%s: Received an ERROR Response to Register message (err_code=%d, err_msg='%s')", __FUNCTION__, usp->body->error->err_code, usp->body->error->err_msg);
        return;
    }

    // Exit if we did not receive a response message, or the message is invalid or failed to parse
    // This code checks the parsed message enums and pointers for expectations and validity
    if ((usp->body == NULL) || (usp->body->msg_body_case != USP__BODY__MSG_BODY_RESPONSE) ||
        (usp->body->response == NULL) || (usp->body->response->resp_type_case != USP__RESPONSE__RESP_TYPE_REGISTER_RESP) ||
        (usp->body->response->register_resp == NULL) )
    {
        USP_LOG_Error("%s: Incoming message (msg_id=%s) is invalid or inconsistent", __FUNCTION__, usp->header->msg_id);
        return;
    }

    // Log all registration errors
    reg = usp->body->response->register_resp;
    for (i=0; i < reg->n_registered_path_results; i++)
    {
        rpr = reg->registered_path_results[i];
        switch (rpr->oper_status->oper_status_case)
        {
            case USP__REGISTER_RESP__REGISTERED_PATH_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_FAILURE:
                oper_failure = rpr->oper_status->oper_failure;
                USP_LOG_Error("%s: Failed to register path %s (err_code=%d, err_msg='%s')", __FUNCTION__, rpr->requested_path, oper_failure->err_code, oper_failure->err_msg);
                break;

            case USP__REGISTER_RESP__REGISTERED_PATH_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_SUCCESS:
                USP_LOG_Info("%s: Successfully registered path '%s'", __FUNCTION__, rpr->requested_path);
                break;

            default:
            case USP__REGISTER_RESP__REGISTERED_PATH_RESULT__OPERATION_STATUS__OPER_STATUS__NOT_SET:
                USP_LOG_Error("%s: Error when registering path '%s'", __FUNCTION__, rpr->requested_path);
                break;
        }
    }
}

/*********************************************************************//**
**
** USP_SERVICE_QueueDeregisterRequest
**
** Queues a USP Deregister Request to deregister parts of the data model provided by this endpoint with the USP Broker
**
** \param   endpoint_id - Endpoint ID of the Broker to send the message to
** \param   mtpc - details of where the deregister message should be sent (i.e. Broker's controller socket)
** \param   objects - comma separated list of objects to deregister
**
** \return  None
**
**************************************************************************/
void USP_SERVICE_QueueDeregisterRequest(char *endpoint_id, char *objects)
{
    int i;
    char *path;
    str_vector_t sv;
    Usp__Msg *msg = NULL;
    dm_node_t *node;
    dm_instances_t inst;
    mtp_conn_t mtpc = {0};
    char msg_id[MAX_MSG_ID_LEN];

    // Exit if no top-level objects are to be deregistered
    if (objects == NULL)
    {
        return;
    }

    mtpc.is_reply_to_specified = false;   // Force DEVICE_CONTROLLER_QueueBinaryMessage() to calculate an MRT destination for the request

    // Special case of deregistering all paths
    STR_VECTOR_Init(&sv);
    CalcUspServiceMessageId(msg_id, sizeof(msg_id));
    if (*objects == '\0')
    {
        msg = CreateUspServiceDeregisterReq(msg_id, &objects, 1);
        MSG_HANDLER_QueueMessage(endpoint_id, msg, &mtpc);
        goto exit;
    }

    // Iterate over all paths, validating them
    TEXT_UTILS_SplitString(objects, &sv, ",");
    for (i=0; i < sv.num_entries; i++)
    {
        // Exit if path does not exist in the data model (of this endpoint)
        path = sv.vector[i];
        node = DM_PRIV_GetNodeFromPath(path, &inst, NULL, 0);
        if (node == NULL)
        {
            USP_LOG_Error("%s: Cannot deregister path '%s' as it is not present in the data model", __FUNCTION__, path);
            goto exit;
        }

        // Exit if path contains instance numbers
        if (inst.order > 0)
        {
            USP_LOG_Error("%s: Cannot deregister path '%s' as it contains instance numbers", __FUNCTION__, path);
            goto exit;
        }
    }

    // Create a deregister request
    msg = CreateUspServiceDeregisterReq(msg_id, sv.vector, sv.num_entries);
    MSG_HANDLER_QueueMessage(endpoint_id, msg, &mtpc);

exit:
    if (msg != NULL)
    {
        usp__msg__free_unpacked(msg, pbuf_allocator);
    }

    STR_VECTOR_Destroy(&sv);
}

/*********************************************************************//**
**
** USP_SERVICE_HandleDeRegisterResp
**
** Handles a USP Deregister response message
**
** \param   usp - pointer to parsed USP message structure. This is always freed by the caller (not this function)
** \param   endpoint_id - endpoint of USP broker which sent this message
** \param   mtpc - details of where this USP message came from
**
** \return  None
**
**************************************************************************/
void USP_SERVICE_HandleDeRegisterResp(Usp__Msg *usp, char *endpoint_id, mtp_conn_t *mtpc)
{
    // NOTE: This function is only called when using the CLI 'deregister' command, which is only intended for testing purposes
    // and hence, this function currently does nothing
    USP_LOG_Info("%s: Intentionally ignoring Deregister Response", __FUNCTION__);
}

/*********************************************************************//**
**
** USP_Service_Stop
**
** Frees up all memory associated with this module
** Must be called from datamodel thread
**
** \param   None
**
** \return  None
**
**************************************************************************/
void USP_SERVICE_Stop(void)
{
    request_t *queued_msg = NULL;

    // iterate through all control messages and flush and pending message responses
    queued_msg = (request_t *) usp_service_ctrler_pending_msg_list.head;
    while (queued_msg != NULL)
    {
        request_t *next_msg = NULL;
        next_msg = (request_t *)queued_msg->link.next;

        USP_LOG_Warning("%s: Cancelling pending response : %s", __FUNCTION__, queued_msg->req->header->msg_id);

        // remove the message from the pending message response list
        DLLIST_Unlink(&usp_service_ctrler_pending_msg_list, queued_msg);
        queued_msg->err_code = USP_ERR_INTERNAL_ERROR;
        USP_SNPRINTF(queued_msg->err_msg, queued_msg->err_msg_len, "Cancelled pending response from agent");
        // post the semaphore to unblock any waiting vendor thread
        sem_post(&queued_msg->semaphore);

        queued_msg = next_msg;
    }

    // Free the dynamically allocated agent endpoint string if set
    USP_SAFE_FREE(usp_broker_agent_endpoint_id);

}

/*********************************************************************//**
**
** HandleUspServiceControllerMessageResponseTimeout
**
** This function is called if a response message is not received within the
** specified timeout.  It is called in the context of datamodel thread
**
** \param   id - A unique ID identifying the pending message response
**
** \return  void
**
**************************************************************************/
void HandleUspServiceControllerMessageResponseTimeout(int id)
{
    request_t *queued_msg = NULL;

    // iterate through all control messages to find the one matching this timeout id
    queued_msg = (request_t *) usp_service_ctrler_pending_msg_list.head;
    while (queued_msg != NULL)
    {
        request_t *next_msg = NULL;
        next_msg = (request_t *)queued_msg->link.next;
        if (queued_msg->timeout_id == id)
        {
            USP_LOG_Warning("%s: Timed out waiting for msg id : %s", __FUNCTION__, queued_msg->req->header->msg_id);
            USP_ERR_ReplaceEmptyMessage("%s: Timed out waiting for response from agent", __FUNCTION__);

            // remove the message from the pending message response list
            DLLIST_Unlink(&usp_service_ctrler_pending_msg_list, queued_msg);
            queued_msg->err_code = USP_ERR_INTERNAL_ERROR;
            USP_SNPRINTF(queued_msg->err_msg, queued_msg->err_msg_len, "Timed out waiting for response from agent");
            // post the semaphore to unblock the vendor thread
            sem_post(&queued_msg->semaphore);
            break;
        }
        queued_msg = next_msg;
   }

   return;
}

/*********************************************************************//**
**
** QueueUspServiceRequest
**
** Called from Datamodel thread in response to calling USP_PROCESS_DoWork()
** This function queues a USP Request message to send to the Broker
** when this USP Service is acting as a Controller
**
** \param  arg1 - The request structure containing input and output parameters
** \param  arg2 - Not used
**
** \return  void
**
**************************************************************************/
void QueueUspServiceRequest(void *arg1, void *arg2)
{
    // use a rolling label to identify a response timeout uniquely
    static int label = 1;
    time_t timer_timeout;
    request_t *request;

    USP_ASSERT(arg1 != NULL);

    request = (request_t*)arg1;

    MSG_HANDLER_QueueMessage(usp_broker_agent_endpoint_id, request->req, &usp_broker_agent_mtpc);

    // The timeout_id is a unique integer used to correlate timeouts with messages.
    request->timeout_id = label++;

    DLLIST_LinkToTail(&usp_service_ctrler_pending_msg_list, request);

    timer_timeout = time(NULL) + request->timeout;
    SYNC_TIMER_Add(HandleUspServiceControllerMessageResponseTimeout, request->timeout_id, timer_timeout);
}

/*********************************************************************//**
**
** CreateUspServiceRegisterReq
**
** Create a USP Register request message
**
** \param   msg_id - MessageId to put in the message
** \param   paths- array of paths to register
** \param   num_paths - num
**
** \return  Pointer to a Register Request object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__Msg *CreateUspServiceRegisterReq(char *msg_id, char **paths, int num_paths)
{
    int i;
    Usp__Msg *msg;
    Usp__Register *reg;
    Usp__Register__RegistrationPath *rp;

    // Create Register Request
    msg =  MSG_HANDLER_CreateRequestMsg(msg_id, USP__HEADER__MSG_TYPE__REGISTER, USP__REQUEST__REQ_TYPE_REGISTER);
    reg = USP_MALLOC(sizeof(Usp__Register));
    usp__register__init(reg);
    msg->body->request->register_ = reg;

    // Copy the paths into the Register
    reg->n_reg_paths = num_paths;
    reg->reg_paths = USP_MALLOC(num_paths*sizeof(void *));
    for (i=0; i<num_paths; i++)
    {
        rp = USP_MALLOC(sizeof(Usp__Register__RegistrationPath));
        usp__register__registration_path__init(rp);
        rp->path = USP_STRDUP(paths[i]);
        reg->reg_paths[i] = rp;
    }

    // Fill in the flags in the Register
    reg->allow_partial = false;

    return msg;
}

/*********************************************************************//**
**
** CreateUspServiceDeregisterReq
**
** Create a USP Deregister request message
**
** \param   msg_id - MessageId to put in the message
** \param   paths- array of paths to register
** \param   num_paths - num
**
** \return  Pointer to a Register Request object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__Msg *CreateUspServiceDeregisterReq(char *msg_id, char **paths, int num_paths)
{
    int i;
    Usp__Msg *msg;
    Usp__Deregister *dreg;

    // Create Deegister Request
    msg =  MSG_HANDLER_CreateRequestMsg(msg_id, USP__HEADER__MSG_TYPE__DEREGISTER, USP__REQUEST__REQ_TYPE_DEREGISTER);
    dreg = USP_MALLOC(sizeof(Usp__Deregister));
    usp__deregister__init(dreg);
    msg->body->request->deregister = dreg;

    // Copy the paths into the Deregister
    dreg->n_paths = num_paths;
    dreg->paths = USP_MALLOC(num_paths*sizeof(void *));
    for (i=0; i<num_paths; i++)
    {
        dreg->paths[i] = USP_STRDUP(paths[i]);
    }

    return msg;
}

/*********************************************************************//**
**
** CalcUspServiceMessageId
**
** Creates a unique message id for messages sent from this USP Service to a USP Broker
**
** \param   msg_id - pointer to buffer in which to write the message id
** \param   len - length of buffer
**
** \return  None
**
**************************************************************************/
void CalcUspServiceMessageId(char *msg_id, int len)
{
    static unsigned count = 0;
    char buf[MAX_ISO8601_LEN];
    char *endpoint_id;

    count++;               // Pre-increment before forming message, because we want to count from 1

    endpoint_id = DEVICE_LOCAL_AGENT_GetEndpointID();

    // Form a message id string which is unique.
    {
        // In production, the string must be unique because we don't want the USP Service receiving stale responses
        // and treating them as fresh (in the case of the USP Service crashing and restarting)
        USP_SNPRINTF(msg_id, len, "%s-%d-%s", endpoint_id, count, iso8601_cur_time(buf, sizeof(buf)) );
    }
}

/*********************************************************************//**
**
** CreateUspServiceGetReq
**
** Private function to construct a GET request USP message from a list of keys
**
** \param   kvv - key value vector containing the keys and values to get
**
** \return  Pointer to a Usp__Msg structure- ownership passes to the caller
**
**************************************************************************/
Usp__Msg *CreateUspServiceGetReq(kv_vector_t *kvv)
{
    int i;
    int num_paths;
    Usp__Msg *msg;
    Usp__Get *get;
    char msg_id[MAX_MSG_ID_LEN];

    // Create Get Request
    CalcUspServiceMessageId(msg_id, sizeof(msg_id));

    msg =  MSG_HANDLER_CreateRequestMsg(msg_id, USP__HEADER__MSG_TYPE__GET, USP__REQUEST__REQ_TYPE_GET);
    get = USP_MALLOC(sizeof(Usp__Get));
    usp__get__init(get);
    msg->body->request->get = get;

    // Copy the paths into the Get
    num_paths = kvv->num_entries;
    get->n_param_paths = num_paths;
    get->param_paths = USP_MALLOC(num_paths*sizeof(char *));
    for (i=0; i<num_paths; i++)
    {
        get->param_paths[i] = USP_STRDUP(kvv->vector[i].key);
    }

    get->max_depth = 0;

    return msg;
}

/*********************************************************************//**
**
** CreateUspServiceSetReq
**
** Private function to construct a SET request USP message from set of keys/values
**
** \param   kvv - key value vector containing the keys/values to set
**
** \return  Pointer to a Usp__Msg structure- ownership passes to the caller
**
**************************************************************************/
Usp__Msg *CreateUspServiceSetReq(kv_vector_t *kvv)
{
    int i;
    Usp__Msg *msg;
    Usp__Set *set;
    char msg_id[MAX_MSG_ID_LEN];
    kv_pair_t *kv;

    // Create Get Request
    CalcUspServiceMessageId(msg_id, sizeof(msg_id));
    msg =  MSG_HANDLER_CreateRequestMsg(msg_id, USP__HEADER__MSG_TYPE__SET, USP__REQUEST__REQ_TYPE_SET);
    set = USP_MALLOC(sizeof(Usp__Set));
    usp__set__init(set);
    msg->body->request->set = set;

    // Initialise the set with initially no UpdateObjects
    set->allow_partial = false;
    set->n_update_objs = 0;
    set->update_objs = NULL;

    // Iterate over all parameters, adding them to the Set request
    for (i=0; i < kvv->num_entries; i++)
    {
        kv = &kvv->vector[i];
        MSG_UTILS_AddSetReq_Param(set, kv->key, kv->value);
    }

    return msg;
}

/*********************************************************************//**
**
** ProcessUspServiceGetResponse
**
** Processes a Get Response that we have received from a USP Service.  This
** function populates the returned kvv structure with all response parameters
** found in the USP response message without performing any filtering.
**
** \param   resp - USP response message in protobuf-c structure
** \param   kvv - key-value vector in which to return the parameter values
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ProcessUspServiceGetResponse(Usp__Msg *resp, kv_vector_t *kvv)
{
    int i;
    int objIndex;
    int paramIndex;
    int err = USP_ERR_OK;
    Usp__GetResp *get;
    Usp__GetResp__RequestedPathResult *rpr;
    Usp__GetResp__ResolvedPathResult *res;
    Usp__GetResp__ResolvedPathResult__ResultParamsEntry *rpe;
    char path[MAX_DM_PATH];

    // Exit if failed to validate that the Message body contains a Get Response (eg if the Message Body is an Error response)
    // NOTE: It is possible for the USP Service to send back an Error response instead of a GetResponse, but only if the GetRequest was not understood
    err = MSG_UTILS_ValidateUspResponse(resp, USP__RESPONSE__RESP_TYPE_GET_RESP, NULL);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if get response is missing
    get = resp->body->response->get_resp;
    if (get == NULL)
    {
        USP_ERR_SetMessage("%s: Missing get response", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Iterate over all requested path results
    USP_ASSERT((get->n_req_path_results==0) || (get->req_path_results != NULL));
    for (i=0; i < get->n_req_path_results; i++)
    {
        rpr = get->req_path_results[i];
        USP_ASSERT(rpr != NULL)

        // Skip if we received an error for this path
        if (rpr->err_code != USP_ERR_OK)
        {
            if (rpr->err_msg != NULL)
            {
                USP_ERR_ReplaceEmptyMessage("%s", rpr->err_msg);
            }
            else
            {
                USP_ERR_ReplaceEmptyMessage("Failed to get %s", rpr->requested_path);
            }
            err = rpr->err_code;
            KV_VECTOR_Destroy(kvv);
            goto exit;
        }

        // Iterate over all data model objects resolved for this path
        for (objIndex = 0 ; objIndex < rpr->n_resolved_path_results ; objIndex++)
        {
             // Iterate over all data model parameters resolved for this object
            res  = rpr->resolved_path_results[objIndex];
            for (paramIndex = 0 ; paramIndex < res->n_result_params ; paramIndex++)
            {
                rpe = res->result_params[paramIndex];
                USP_ASSERT((rpe != NULL) && (rpe->value != NULL));

                // Add the full path and parameter value in the returned key-value vector
                USP_SNPRINTF(path, MAX_DM_PATH, "%s%s", res->resolved_path, rpe->key);
                KV_VECTOR_Add(kvv, path, rpe->value);
            }
        }
    }

    // If the code gets here, then no errors were found in the Get Response
    err = USP_ERR_OK;

exit:
    return err;
}

#endif // REMOVE_USP_SERVICE
