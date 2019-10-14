/*
 *
 * Copyright (C) 2019, Broadband Forum
 * Copyright (C) 2016-2019  CommScope, Inc
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
 * \file handle_set.c
 *
 * Handles the SetRequest message, creating a SetResponse
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <protobuf-c/protobuf-c.h>

#include "usp-msg.pb-c.h"
#include "common_defs.h"
#include "msg_handler.h"
#include "proto_trace.h"
#include "dm_trans.h"
#include "path_resolver.h"
#include "device.h"

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
int UpdateExpressionObjects(Usp__SetResp *set_resp, Usp__Set__UpdateObject *up, bool allow_partial);
int UpdateObject_Trans(char *obj_path, 
                        Usp__SetResp *set_resp,
                        Usp__Set__UpdateObject *up, bool allow_partial);
int UpdateObject(char *obj_path, 
                 Usp__SetResp *set_resp,
                 Usp__Set__UpdateObject *up);
Usp__Msg *CreateSetResp(char *msg_id);
Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationFailure *AddSetResp_OperFailure(Usp__SetResp *set_resp, char *path, int err_code, char *err_msg);
Usp__SetResp__UpdatedInstanceFailure *
AddOperFailure_UpdatedInstFailure(Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationFailure *oper_failure, char *path);
Usp__SetResp__ParameterError *
AddUpdatedInstFailure_ParamErr(Usp__SetResp__UpdatedInstanceFailure *updated_inst_failure, char *path, int err_code, char *err_msg);
Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationSuccess *AddSetResp_OperSuccess(Usp__SetResp *set_resp, char *path);
Usp__SetResp__UpdatedInstanceResult *AddOperSuccess_UpdatedInstRes(Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationSuccess *oper_success, char *path);
Usp__SetResp__UpdatedInstanceResult__UpdatedParamsEntry *AddUpdatedInstRes_ParamsEntry(Usp__SetResp__UpdatedInstanceResult *updated_inst_result, char *key, char *value);
Usp__SetResp__ParameterError *AddUpdatedInstRes_ParamErr(Usp__SetResp__UpdatedInstanceResult *updated_inst_result, char *path, int err_code, char *err_msg);
void RemoveSetResp_LastUpdateObjResult(Usp__SetResp *set_resp);
int ParamError_FromSetRespToErrResp(Usp__Msg *set_msg, Usp__Msg *err_msg);

/*********************************************************************//**
**
** MSG_HANDLER_HandleSet
**
** Handles a USP Set message
**
** \param   usp - pointer to parsed USP message structure. This is always freed by the caller (not this function)
** \param   controller_endpoint - endpoint which sent this message
** \param   mrt - details of where response to this USP message should be sent
**
** \return  None - This code must handle any errors by sending back error messages
**
**************************************************************************/
void MSG_HANDLER_HandleSet(Usp__Msg *usp, char *controller_endpoint, mtp_reply_to_t *mrt)
{
    int i;
    int err;
    Usp__Set__UpdateObject *up;
    Usp__Set *set;
    Usp__Msg *resp = NULL;
    dm_trans_vector_t trans;
    int count;

    // Exit if message is invalid or failed to parse
    // This code checks the parsed message enums and pointers for expectations and validity
    USP_ASSERT(usp->header != NULL);
    if ((usp->body == NULL) || (usp->body->msg_body_case != USP__BODY__MSG_BODY_REQUEST) ||
        (usp->body->request == NULL) || (usp->body->request->req_type_case != USP__REQUEST__REQ_TYPE_SET) ||
        (usp->body->request->set == NULL) )
    {
        USP_ERR_SetMessage("%s: Incoming message is invalid or inconsistent", __FUNCTION__);
        resp = ERROR_RESP_CreateSingle(usp->header->msg_id, USP_ERR_MESSAGE_NOT_UNDERSTOOD, resp, NULL);
        goto exit;
    }

    // Create a Set Response
    resp = CreateSetResp(usp->header->msg_id);

    // Exit if there are no parameters to set
    set = usp->body->request->set;
    if ((set->update_objs == NULL) || (set->n_update_objs == 0))
    {
        goto exit;
    }

    // Start a transaction here, if allow_partial is at the global level
    if (set->allow_partial == false)
    {
        err = DM_TRANS_Start(&trans);
        if (err != USP_ERR_OK)
        {
            // If failed to start a transaction, delete the SetResponse message, and send an error message instead
            resp = ERROR_RESP_CreateSingle(usp->header->msg_id, err, resp, NULL);
            goto exit;
        }
    }

    // Iterate over all update objects in the message
    for (i=0; i < set->n_update_objs; i++)
    {
        // Update the specified object
        up = set->update_objs[i];
        err = UpdateExpressionObjects(resp->body->response->set_resp, up, set->allow_partial);

        // If allow_partial is at the global level, and an error occurred, then fail this
        if ((set->allow_partial == false) && (err != USP_ERR_OK))
        {
            // A required object failed to update
            // So delete the SetResponse message, and send an error message instead
            count = ParamError_FromSetRespToErrResp(resp, NULL);
            err = ERROR_RESP_CalcOuterErrCode(count, err);
            resp = ERROR_RESP_CreateSingle(usp->header->msg_id, err, resp, ParamError_FromSetRespToErrResp);
    
            // Abort the global transaction, only logging errors (the message we want to send back over USP is above)
            DM_TRANS_Abort();
            goto exit;
        }
    }

    // Commit transaction here, if allow_partial is at the global level
    if (set->allow_partial == false)
    {
        err = DM_TRANS_Commit();
        if (err != USP_ERR_OK)
        {
            // If failed to commit, delete the SetResponse message, and send an error message instead
            resp = ERROR_RESP_CreateSingle(usp->header->msg_id, err, resp, NULL);
            goto exit;
        }
    }


exit:
    MSG_HANDLER_QueueMessage(controller_endpoint, resp, mrt);
    usp__msg__free_unpacked(resp, pbuf_allocator);
}

/*********************************************************************//**
**
** UpdateExpressionObjects
**
** Updates all the objects of the specified path expressions
** Always fills in an OperFailure or OperSuccess for this data model object
**
** \param   set_resp - pointer to USP set response object, which is updated with the results of this operation
** \param   up - pointer to parsed object to update
** \param   allow_partial - set to true if failures one object do not affect all others.
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int UpdateExpressionObjects(Usp__SetResp *set_resp, Usp__Set__UpdateObject *up, bool allow_partial)
{
    int i;
    int err;
    str_vector_t obj_paths;
    combined_role_t combined_role;
    char err_msg[128];

    // Return OperFailure if there is no expression
    STR_VECTOR_Init(&obj_paths);
    if ((up->obj_path == NULL) || (up->obj_path[0] == '\0'))
    {
        USP_SNPRINTF(err_msg, sizeof(err_msg), "%s: Expression missing in SetRequest", __FUNCTION__);
        AddSetResp_OperFailure(set_resp, up->obj_path, USP_ERR_INVALID_ARGUMENTS, err_msg);
        err = USP_ERR_OK;
        goto exit;
    }

    // Return OperFailure if there are no parameters
    if ((up->n_param_settings == 0) || (up->param_settings == NULL))
    {
        USP_SNPRINTF(err_msg, sizeof(err_msg), "%s: Parameter names missing in SetRequest", __FUNCTION__);
        AddSetResp_OperFailure(set_resp, up->obj_path, USP_ERR_INVALID_ARGUMENTS, err_msg);
        err = USP_ERR_OK;
        goto exit;
    }

    // Return OperFailure if an internal error occurred
    MSG_HANDLER_GetMsgRole(&combined_role);
    err = PATH_RESOLVER_ResolveDevicePath(up->obj_path, &obj_paths, kResolveOp_Set, NULL, &combined_role, 0);
    if (err != USP_ERR_OK)
    {
        AddSetResp_OperFailure(set_resp, up->obj_path, err, USP_ERR_GetMessage());
        goto exit;
    }

    // Return OperFailure if none of the specified objects exist in the schema
    if (obj_paths.num_entries == 0)
    {
        USP_SNPRINTF(err_msg, sizeof(err_msg), "%s: Expression does not reference any objects", __FUNCTION__);
        AddSetResp_OperFailure(set_resp, up->obj_path, USP_ERR_OBJECT_DOES_NOT_EXIST, err_msg);
        err = USP_ERR_OK;
        goto exit;
    }

    // Iterate over all object paths specified for this 'Object'
    for (i=0; i < obj_paths.num_entries; i++)
    {
        err = UpdateObject_Trans(obj_paths.vector[i], set_resp, up, allow_partial);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }
    }

    // If the code gets here, then all parameters of all objects have been set successfully
    err = USP_ERR_OK;

exit:
    STR_VECTOR_Destroy(&obj_paths);
    return err;
}

/*********************************************************************//**
**
** UpdateObject_Trans
**
** Wrapper around UpdateObject() which performs a transaction at this level, if allow_partial is true
**
** \param   obj_path - path to the object to update
** \param   set_resp - USP Message OperationSuccess Object to add the result of the set to
** \param   up - pointer to parsed USP UpdateObject message
** \param   allow_partial - set to true if failures in this object do not affect all others.
**                          If allow_partial is set then we perform a transaction at this level
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int UpdateObject_Trans(char *obj_path, 
                        Usp__SetResp *set_resp,
                        Usp__Set__UpdateObject *up, bool allow_partial)
{
    int err;
    dm_trans_vector_t trans;
    
    // Start a transaction here, if allow_partial is at the object level
    if (allow_partial == true)
    {
        // Return OperFailure, if failed to start a transaction
        err = DM_TRANS_Start(&trans);
        if (err != USP_ERR_OK)
        {
            AddSetResp_OperFailure(set_resp, up->obj_path, err, USP_ERR_GetMessage());
            return err;
        }
    }

    // Update the specified object
    err = UpdateObject(obj_path, set_resp, up);

    // Commit/Abort transaction here, if allow_partial is at the object level
    if (allow_partial == true)
    {
        if (err == USP_ERR_OK)
        {
            err = DM_TRANS_Commit();
            if (err != USP_ERR_OK)
            {
                // If transaction failed, then replace the OperSuccess with OperFailure
                // To do this, we remove the last OperSuccessObject from the USP message
                RemoveSetResp_LastUpdateObjResult(set_resp);
                AddSetResp_OperFailure(set_resp, up->obj_path, err, USP_ERR_GetMessage());
            }
        }
        else
        {
            // Because allow_partial=true, we rollback the creation of this object, but do not fail the entire message
            DM_TRANS_Abort();
            err = USP_ERR_OK;                             
        }
    }

    return err;
}

/*********************************************************************//**
**
** UpdateObject
**
** Updates all the objects of the specified path expressions
**
** \param   obj_path - path to the object to update
** \param   set_resp - USP Message OperationSuccess Object to add the result of the set to
** \param   up - pointer to parsed USP UpdateObject message
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int UpdateObject(char *obj_path, 
                        Usp__SetResp *set_resp,
                        Usp__Set__UpdateObject *up)
{
    int err;
    int i;
    Usp__Set__UpdateParamSetting *ps;
    Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationSuccess *oper_success;
    Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationFailure *oper_failure;
    Usp__SetResp__UpdatedInstanceResult *updated_inst_res;
    Usp__SetResp__UpdatedInstanceFailure *updated_inst_failure = NULL;
    char full_path[MAX_DM_PATH];
    int result;     // This stores the cumulative result of all sets
                    // If we fail to set a required parameter, then this causes the code to switch from 
                    // adding non-required failed parameters to the success message, to adding failed required 
                    // parameters to the failure message

    // Assume OperSuccess and add the UpdatedInstRes object
    result = USP_ERR_OK;    // Assume that the cumulative result was successful
    oper_success = AddSetResp_OperSuccess(set_resp, up->obj_path);
    updated_inst_res = AddOperSuccess_UpdatedInstRes(oper_success, obj_path);

    // So iterate over all parameters, trying to set their values for this object
    // NOTE: This code reports ** ALL ** failing required parameters
    for (i=0; i < up->n_param_settings; i++)
    {
        // Create the full path to the parameter
        ps = up->param_settings[i];
        USP_SNPRINTF(full_path, sizeof(full_path), "%s.%s", obj_path, ps->param);
        full_path[sizeof(full_path)-1] = '\0';

        // Attempt to set the parameter
        err = DATA_MODEL_SetParameterValue(full_path, ps->value, CHECK_WRITABLE);
        if (err != USP_ERR_OK)
        {
            // The parameter was not set successfully
            if (ps->required)
            {
                if (result == USP_ERR_OK)
                {
                    // This is the first required parameter which has failed to be set
                    // So replace the OperSuccess with OperFailure
                    // To do this, we remove the last OperSuccessObject from the USP message
                    result = err;
                    RemoveSetResp_LastUpdateObjResult(set_resp);
                    oper_failure = AddSetResp_OperFailure(set_resp, up->obj_path, USP_ERR_REQUIRED_PARAM_FAILED, "Failed to set required parameters");
                    updated_inst_failure = AddOperFailure_UpdatedInstFailure(oper_failure, obj_path);
                    AddUpdatedInstFailure_ParamErr(updated_inst_failure, ps->param, err, USP_ERR_GetMessage());
                }
                else
                {
                    // This is a subsequent required parameter which has failed to be set
                    // So add it to the list of failed required parameters
                    if (updated_inst_failure != NULL)  // NOTE: This test is not necessary because if result!=USP_ERR_OK, then updated_inst_failure will be set (last code block). However we leave this test in because using -O2, some compilers incorrectly think that the code can get here without updated_inst_failure being set.
                    {
                        AddUpdatedInstFailure_ParamErr(updated_inst_failure, ps->param, err, USP_ERR_GetMessage());
                    }
                }
            }
            else
            {
                // This parameter failed to be set, but was not required
                // So add it to the ParamErr list, if we have not encountered a fatal error
                if (result == USP_ERR_OK)
                {
                    AddUpdatedInstRes_ParamErr(updated_inst_res, ps->param, err, USP_ERR_GetMessage());
                }
            }

        }
        else
        {
            // The parameter was set successfully, so add it to the ParamMap, if we have not encountered a fatal error
            if (result == USP_ERR_OK)
            {
                AddUpdatedInstRes_ParamsEntry(updated_inst_res, ps->param, ps->value);
            }
        }
    }

    return result;
}

/*********************************************************************//**
**
** CreateSetResp
**
** Dynamically creates an GetResponse object
** NOTE: The object is created without any updated_obj_results
** NOTE: The object should be deleted using usp__msg__free_unpacked()
**
** \param   msg_id - string containing the message id of the set request, which initiated this response
**
** \return  Pointer to a SetResponse object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__Msg *CreateSetResp(char *msg_id)
{
    Usp__Msg *resp;
    Usp__Header *header;
    Usp__Body *body;
    Usp__Response *response;
    Usp__SetResp *set_resp;

    // Allocate and initialise memory to store the parts of the USP message
    resp = USP_MALLOC(sizeof(Usp__Msg));
    usp__msg__init(resp);

    header = USP_MALLOC(sizeof(Usp__Header));
    usp__header__init(header);

    body = USP_MALLOC(sizeof(Usp__Body));
    usp__body__init(body);

    response = USP_MALLOC(sizeof(Usp__Response));
    usp__response__init(response);

    set_resp = USP_MALLOC(sizeof(Usp__SetResp));
    usp__set_resp__init(set_resp);

    // Connect the structures together
    resp->header = header;
    header->msg_id = USP_STRDUP(msg_id);
    header->msg_type = USP__HEADER__MSG_TYPE__SET_RESP;

    resp->body = body;
    body->msg_body_case = USP__BODY__MSG_BODY_RESPONSE;
    body->response = response;
    response->resp_type_case = USP__RESPONSE__RESP_TYPE_SET_RESP;
    response->set_resp = set_resp;
    set_resp->n_updated_obj_results = 0;    // Start from an empty list
    set_resp->updated_obj_results = NULL;

    return resp;
}    

/*********************************************************************//**
**
** AddSetResp_OperFailure
**
** Dynamically adds an operation failure object to the SetResponse object
**
** \param   resp - pointer to GetResponse object
** \param   path - requested path of object which failed to update
** \param   err_code - numeric code indicating reason object failed to be set
** \param   err_msg - error message indicating reason object failed to be set
**
** \return  Pointer to dynamically allocated operation failure object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationFailure *
AddSetResp_OperFailure(Usp__SetResp *set_resp, char *path, int err_code, char *err_msg)
{
    Usp__SetResp__UpdatedObjectResult *updated_obj_res;
    Usp__SetResp__UpdatedObjectResult__OperationStatus *oper_status;
    Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationFailure *oper_failure;
    int new_num;    // new number of entries in the updated object result array
    
    // Allocate memory to store the updated object result
    updated_obj_res = USP_MALLOC(sizeof(Usp__SetResp__UpdatedObjectResult));
    usp__set_resp__updated_object_result__init(updated_obj_res);

    oper_status = USP_MALLOC(sizeof(Usp__SetResp__UpdatedObjectResult__OperationStatus));
    usp__set_resp__updated_object_result__operation_status__init(oper_status);    

    oper_failure = USP_MALLOC(sizeof(Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationFailure));
    usp__set_resp__updated_object_result__operation_status__operation_failure__init(oper_failure);

    // Increase the size of the vector
    new_num = set_resp->n_updated_obj_results + 1;
    set_resp->updated_obj_results = USP_REALLOC(set_resp->updated_obj_results, new_num*sizeof(void *));
    set_resp->n_updated_obj_results = new_num;
    set_resp->updated_obj_results[new_num-1] = updated_obj_res;

    // Connect all objects together, and fill in their members
    updated_obj_res->requested_path = USP_STRDUP(path);
    updated_obj_res->oper_status = oper_status;

    oper_status->oper_status_case = USP__SET_RESP__UPDATED_OBJECT_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_FAILURE;
    oper_status->oper_failure = oper_failure;

    oper_failure->err_code = err_code;
    oper_failure->err_msg = USP_STRDUP(err_msg);
    oper_failure->n_updated_inst_failures = 0;
    oper_failure->updated_inst_failures = NULL;

    return oper_failure;
}

/*********************************************************************//**
**
** AddOperFailure_UpdatedInstFailure
**
** Dynamically adds an updated instance failure entry to an OperationFailure object
**
** \param   oper_failure - pointer to operation failure object to add this entry to
** \param   path - path to object which failed to be updated
**
** \return  Pointer to dynamically allocated updated instance result entry
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__SetResp__UpdatedInstanceFailure *
AddOperFailure_UpdatedInstFailure(Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationFailure *oper_failure, char *path)
{
    Usp__SetResp__UpdatedInstanceFailure *updated_inst_failure;
    int new_num;    // new number of entries in the updated instance failure array
    int len;

    // Allocate memory to store the updated instance failure entry
    updated_inst_failure = USP_MALLOC(sizeof(Usp__SetResp__UpdatedInstanceFailure));
    usp__set_resp__updated_instance_failure__init(updated_inst_failure);

    // Increase the size of the vector
    new_num = oper_failure->n_updated_inst_failures + 1;
    oper_failure->updated_inst_failures = USP_REALLOC(oper_failure->updated_inst_failures, new_num*sizeof(void *));
    oper_failure->n_updated_inst_failures = new_num;
    oper_failure->updated_inst_failures[new_num-1] = updated_inst_failure;

    // Initialise the updated instance failure
    updated_inst_failure->n_param_errs = 0;
    updated_inst_failure->param_errs = NULL;

    // Add the object path with a trailing '.'
    len = strlen(path) + 2;   // Plus 2 to allow for adding a trailing '.' and NULL terminator
    updated_inst_failure->affected_path = USP_MALLOC(len);
    USP_SNPRINTF(updated_inst_failure->affected_path, len, "%s.", path);

    return updated_inst_failure;
}

/*********************************************************************//**
**
** AddUpdatedInstFailure_ParamErr
**
** Dynamically adds a param err entry to an updated instance failure object
**
** \param   updated_inst_failure - pointer to updated instance failure object to add this entry to
** \param   path - name of parameter which failed to update
** \param   err_code - error code representing the cause of the failure to update
** \param   err_msg - string representing the cause of the error
**
** \return  Pointer to dynamically allocated parameter_error entry
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__SetResp__ParameterError *
AddUpdatedInstFailure_ParamErr(Usp__SetResp__UpdatedInstanceFailure *updated_inst_failure, char *path, int err_code, char *err_msg)
{
    Usp__SetResp__ParameterError *param_err_entry;
    int new_num;    // new number of entries in the param_err array

    // Allocate memory to store the param_err entry
    param_err_entry = USP_MALLOC(sizeof(Usp__SetResp__ParameterError));
    usp__set_resp__parameter_error__init(param_err_entry);

    // Increase the size of the vector
    new_num = updated_inst_failure->n_param_errs + 1;
    updated_inst_failure->param_errs = USP_REALLOC(updated_inst_failure->param_errs, new_num*sizeof(void *));
    updated_inst_failure->n_param_errs = new_num;
    updated_inst_failure->param_errs[new_num-1] = param_err_entry;

    // Initialise the param_err_entry
    param_err_entry->param = USP_STRDUP(path);
    param_err_entry->err_code = err_code;
    param_err_entry->err_msg = USP_STRDUP(err_msg);

    return param_err_entry;
}

/*********************************************************************//**
**
** ParamError_FromSetRespToErrResp
**
** Extracts the parameters in error from the OperFailure object of the SetResponse
** and adds them as ParamError objects to an ErrResponse object if supplied.
** If not supplied, it just counts the number of ParamError objects that would be added.
**
** \param   set_msg - pointer to SetResponse object
** \param   err_msg - pointer to ErrResponse object. If NULL, this indicates that the purpose of this function is just
**                    to return the count of ParamErr objects that would be added
**
** \return  Number of ParamErr objects that were (or would be) added to an ErrResponse
**
**************************************************************************/
int ParamError_FromSetRespToErrResp(Usp__Msg *set_msg, Usp__Msg *err_msg)
{
    Usp__Body *body;
    Usp__Response *response;
    Usp__SetResp *set_resp;
    Usp__SetResp__UpdatedObjectResult *updated_obj_res;
    Usp__SetResp__UpdatedObjectResult__OperationStatus *oper_status;
    Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationFailure *oper_failure;
    Usp__SetResp__UpdatedInstanceFailure *updated_inst_failure;
    Usp__SetResp__ParameterError *param_err_entry;

    int i, j, k;
    int num_objs;
    int num_failures;
    int num_params;
    int count = 0;

    char path[MAX_DM_PATH];
    int offset;
    int err_code;
    char *err_str;

    // Navigate to the SetResponse object within the AddResponse message
    body = set_msg->body;
    USP_ASSERT(body != NULL);

    response = body->response;
    USP_ASSERT(response != NULL);

    set_resp = response->set_resp;
    USP_ASSERT(set_resp != NULL);

    // Iterate over all object failures
    num_objs = set_resp->n_updated_obj_results;
    for (i=0; i < num_objs; i++)
    {
        updated_obj_res = set_resp->updated_obj_results[i];
        USP_ASSERT(updated_obj_res != NULL);
        
        oper_status = updated_obj_res->oper_status;
        USP_ASSERT(oper_status != NULL);
        
        // Convert an OperFailure object
        if (oper_status->oper_status_case == USP__SET_RESP__UPDATED_OBJECT_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_FAILURE)
        {
            oper_failure = oper_status->oper_failure;
            USP_ASSERT(oper_failure != NULL);

            // Iterate over all updated_inst_failure objects
            num_failures = oper_failure->n_updated_inst_failures;
            for (j=0; j<num_failures; j++)
            {
                updated_inst_failure = oper_failure->updated_inst_failures[j];
                USP_ASSERT(updated_inst_failure != NULL);

                // Copy the object path into path[] array. Each Param error will update this
                USP_STRNCPY(path, updated_inst_failure->affected_path, sizeof(path));
                offset = strlen(path);

                num_params = updated_inst_failure->n_param_errs;
                for (k=0; k<num_params; k++)
                {
                    if (err_msg != NULL)
                    {
                        param_err_entry = updated_inst_failure->param_errs[k];
                        USP_ASSERT(param_err_entry != NULL);
    
                        // Extract the ParamError fields (forming the full parameter path)
                        USP_STRNCPY(&path[offset], param_err_entry->param, sizeof(path)-offset);
                        err_code = param_err_entry->err_code;
                        err_str = param_err_entry->err_msg;

                        ERROR_RESP_AddParamError(err_msg, path, err_code, err_str);
                    }

                    // Increment the number of param err fields
                    count++;
                }
            }
        }
    }

    return count;
}

/*********************************************************************//**
**
** AddSetResp_OperSuccess
**
** Dynamically adds an operation success object to the SetResponse object
**
** \param   resp - pointer to GetResponse object
** \param   path - requested path
**
** \return  Pointer to dynamically allocated operation success object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationSuccess *
AddSetResp_OperSuccess(Usp__SetResp *set_resp, char *path)
{
    Usp__SetResp__UpdatedObjectResult *updated_obj_res;
    Usp__SetResp__UpdatedObjectResult__OperationStatus *oper_status;
    Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationSuccess *oper_success;
    int new_num;    // new number of entries in the updated object result array
    
    // Allocate memory to store the updated object result
    updated_obj_res = USP_MALLOC(sizeof(Usp__SetResp__UpdatedObjectResult));
    usp__set_resp__updated_object_result__init(updated_obj_res);

    oper_status = USP_MALLOC(sizeof(Usp__SetResp__UpdatedObjectResult__OperationStatus));
    usp__set_resp__updated_object_result__operation_status__init(oper_status);    
    
    oper_success = USP_MALLOC(sizeof(Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationSuccess));
    usp__set_resp__updated_object_result__operation_status__operation_success__init(oper_success);

    // Increase the size of the vector
    new_num = set_resp->n_updated_obj_results + 1;
    set_resp->updated_obj_results = USP_REALLOC(set_resp->updated_obj_results, new_num*sizeof(void *));
    set_resp->n_updated_obj_results = new_num;
    set_resp->updated_obj_results[new_num-1] = updated_obj_res;

    // Connect all objects together, and fill in their members
    updated_obj_res->requested_path = USP_STRDUP(path);
    updated_obj_res->oper_status = oper_status;

    oper_status->oper_status_case = USP__SET_RESP__UPDATED_OBJECT_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_SUCCESS;
    oper_status->oper_success = oper_success;

    oper_success->n_updated_inst_results = 0;
    oper_success->updated_inst_results = NULL;

    return oper_success;
}

/*********************************************************************//**
**
** RemoveSetResp_LastUpdateObjResult
**
** Removes the last UpdateObjResult object from the SetResp object
** The UpdateObjResult object will contain either an OperSuccess or an OperFailure
**
** \param   set_resp - pointer to set response object to modify
**
** \return  None
**
**************************************************************************/
void RemoveSetResp_LastUpdateObjResult(Usp__SetResp *set_resp)
{
    int index;
    Usp__SetResp__UpdatedObjectResult *updated_obj_res;

    // Free the memory associated with the last updated obj_result
    index = set_resp->n_updated_obj_results - 1;
    updated_obj_res = set_resp->updated_obj_results[index];
    protobuf_c_message_free_unpacked ((ProtobufCMessage*)updated_obj_res, pbuf_allocator);

    // Fix the SetResp object, so that it does not reference the obj_result we have just removed
    set_resp->updated_obj_results[index] = NULL;
    set_resp->n_updated_obj_results--;
}

/*********************************************************************//**
**
** AddOperSuccess_UpdatedInstRes
**
** Dynamically adds an updated instance result entry to an OperationSuccess object
**
** \param   oper_success - pointer to operation success object to add this entry to
** \param   path - path to object which was updated
**
** \return  Pointer to dynamically allocated updated instance result entry
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__SetResp__UpdatedInstanceResult *
AddOperSuccess_UpdatedInstRes(Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationSuccess *oper_success, char *path)
{
    Usp__SetResp__UpdatedInstanceResult *updated_inst_result;
    int new_num;    // new number of entries in the updated instance result array
    int len;

    // Allocate memory to store the updated instance result entry
    updated_inst_result = USP_MALLOC(sizeof(Usp__SetResp__UpdatedInstanceResult));
    usp__set_resp__updated_instance_result__init(updated_inst_result);

    // Increase the size of the vector
    new_num = oper_success->n_updated_inst_results + 1;
    oper_success->updated_inst_results = USP_REALLOC(oper_success->updated_inst_results, new_num*sizeof(void *));
    oper_success->n_updated_inst_results = new_num;
    oper_success->updated_inst_results[new_num-1] = updated_inst_result;

    // Initialise the updated instance result
    updated_inst_result->n_updated_params = 0;
    updated_inst_result->updated_params = NULL;
    updated_inst_result->n_param_errs = 0;
    updated_inst_result->param_errs = NULL;

    // Add the object path with a trailing '.'
    len = strlen(path) + 2;   // Plus 2 to allow for adding a trailing '.' and NULL terminator
    updated_inst_result->affected_path = USP_MALLOC(len);
    USP_SNPRINTF(updated_inst_result->affected_path, len, "%s.", path);

    return updated_inst_result;
}

/*********************************************************************//**
**
** AddUpdatedInstRes_ParamsEntry
**
** Dynamically adds a param map entry to an updated instance result object
**
** \param   updated_inst_result - pointer to updated instance result object to add this entry to
** \param   key - name of the parameter which was updated successfully
** \param   value - value of the parameter which was updated
**
** \return  Pointer to dynamically allocated updated instance result entry
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__SetResp__UpdatedInstanceResult__UpdatedParamsEntry *
AddUpdatedInstRes_ParamsEntry(Usp__SetResp__UpdatedInstanceResult *updated_inst_result, char *key, char *value)
{
    Usp__SetResp__UpdatedInstanceResult__UpdatedParamsEntry *entry;
    int new_num;    // new number of entries in the updated instance result array

    // Allocate memory to store the updated instance result entry
    entry = USP_MALLOC(sizeof(Usp__SetResp__UpdatedInstanceResult__UpdatedParamsEntry));
    usp__set_resp__updated_instance_result__updated_params_entry__init(entry);

    // Increase the size of the vector
    new_num = updated_inst_result->n_updated_params + 1;
    updated_inst_result->updated_params = USP_REALLOC(updated_inst_result->updated_params , new_num*sizeof(void *));
    updated_inst_result->n_updated_params = new_num;
    updated_inst_result->updated_params[new_num-1] = entry;

    // Initialise the result param map entry
    entry->key = USP_STRDUP(key);
    entry->value = USP_STRDUP(value);

    return entry;
}

/*********************************************************************//**
**
** AddUpdatedInstRes_ParamErr
**
** Dynamically adds a param err entry to an updated instance result object
**
** \param   updated_inst_result - pointer to updated instance result object to add this entry to
** \param   path - name of parameter which failed to update
** \param   err_code - error code representing the cause of the failure to update
** \param   err_msg - string representing the cause of the error
**
** \return  Pointer to dynamically allocated parameter_error entry
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__SetResp__ParameterError *
AddUpdatedInstRes_ParamErr(Usp__SetResp__UpdatedInstanceResult *updated_inst_result, char *path, int err_code, char *err_msg)
{
    Usp__SetResp__ParameterError *param_err_entry;
    int new_num;    // new number of entries in the param_err array

    // Allocate memory to store the param_err entry
    param_err_entry = USP_MALLOC(sizeof(Usp__SetResp__ParameterError));
    usp__set_resp__parameter_error__init(param_err_entry);

    // Increase the size of the vector
    new_num = updated_inst_result->n_param_errs + 1;
    updated_inst_result->param_errs = USP_REALLOC(updated_inst_result->param_errs, new_num*sizeof(void *));
    updated_inst_result->n_param_errs = new_num;
    updated_inst_result->param_errs[new_num-1] = param_err_entry;

    // Initialise the param_err_entry
    param_err_entry->param = USP_STRDUP(path);
    param_err_entry->err_code = err_code;
    param_err_entry->err_msg = USP_STRDUP(err_msg);

    return param_err_entry;
}

