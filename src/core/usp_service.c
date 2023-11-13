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
#include "text_utils.h"
#include "iso8601.h"


#ifndef REMOVE_USP_SERVICE
//------------------------------------------------------------------------
// Comma separated list containing the endpoint_id of the USP Broker, followed by the top-level data model objects to register
// This string is set by the value of the '-R' option and is not changed by subsequent '-c register' or '-c deregister' CLI invocations
char *usp_service_objects = NULL;

//------------------------------------------------------------------------------
// Message ID of the register message upon which we are waiting for a response (and Broker's endpoint_id)
static char *register_msg_id = NULL;
static char *usp_broker_endpoint_id = NULL;

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
Usp__Msg *CreateUspServiceRegisterReq(char *msg_id, char **paths, int num_paths);
void CalcUspServiceMessageId(char *msg_id, int len);
Usp__Msg *CreateUspServiceDeregisterReq(char *msg_id, char **paths, int num_paths);

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
    USP_SAFE_FREE(usp_broker_endpoint_id);
    register_msg_id = USP_STRDUP(msg_id);
    usp_broker_endpoint_id = USP_STRDUP(endpoint_id);

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
    if ((usp_broker_endpoint_id == NULL) || (register_msg_id == NULL))
    {
        USP_LOG_Error("%s: Ignoring response that we were not expecting (msg_id=%s from endpoint=%s)", __FUNCTION__, usp->header->msg_id, endpoint_id);
        return;
    }

    // Exit if the response is not from the Broker we sent it to
    if (strcmp(endpoint_id, usp_broker_endpoint_id) != 0)
    {
        USP_LOG_Error("%s: Incoming Register Response is from an unexpected endpoint (%s, expected %s)", __FUNCTION__, endpoint_id, usp_broker_endpoint_id);
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
    USP_FREE(usp_broker_endpoint_id);
    register_msg_id = NULL;
    usp_broker_endpoint_id = NULL;

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

#endif // REMOVE_USP_SERVICE
