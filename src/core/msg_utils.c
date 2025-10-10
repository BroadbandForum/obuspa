/*
 *
 * Copyright (C) 2023-2025, Broadband Forum
 * Copyright (C) 2024-2025, Vantiva Technologies SAS
 * Copyright (C) 2023-2024  CommScope, Inc
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
 * \file msg_utils.c
 *
 * Common message handling utility functions called by USP Broker and/or USP Service functionality
 *
 */

#include "common_defs.h"
#include "msg_utils.h"
#include "text_utils.h"
#include "msg_handler.h"
#include "path_resolver.h"

#if !defined(REMOVE_USP_BROKER) || !defined(REMOVE_USP_SERVICE)
//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
Usp__Set__UpdateObject *FindUpdateObject(Usp__Set *set, char *obj_path);
Usp__Set__UpdateObject *AddSetReq_UpdateObject(Usp__Set *set, char *obj_path);
Usp__Set__UpdateParamSetting *AddUpdateObject_ParamSettings(Usp__Set__UpdateObject *update_object, char *param_name, char *value);
void AddSetReq_Param(Usp__Set *set, char *path, char *value);
char * ParamTypeToUspServiceString(Usp__GetSupportedDMResp__ParamValueType value_type);

/*********************************************************************//**
**
** MSG_UTILS_AddSetReq_Param
**
** Adds the specified parameter to the Set Request
**
** \param   set - pointer to Set request to add the parameter to
** \param   path - data model path of the parameter
** \param   value - new value of the parameter to set
**
** \return  None
**
**************************************************************************/
void MSG_UTILS_AddSetReq_Param(Usp__Set *set, char *path, char *value)
{
    char obj_path[MAX_DM_PATH];
    char *param_name;
    Usp__Set__UpdateObject *update_object;

    // Split the parameter into the parent object path and the name of the parameter within the object
    param_name = TEXT_UTILS_SplitPath(path, obj_path, sizeof(obj_path));

    // Add an update object, if we don't already have one for the specified parent object
    update_object = FindUpdateObject(set, obj_path);
    if (update_object == NULL)
    {
        update_object = AddSetReq_UpdateObject(set, obj_path);
    }

    // Add the parameter to the param settings
    AddUpdateObject_ParamSettings(update_object, param_name, value);
}

/*********************************************************************//**
**
** MSG_UTILS_ValidateUspResponse
**
** Validates that the USP Message received from the USP Service was of the expected type
** This function is called as part of the group get/set/add/delete handlers for querying USP services
**
** \param   resp - USP response message in protobuf-c structure
** \param   response_type - type of USP response expected
** \param   param_errs_path - pointer to variable in which to return a pointer to the first path that failed (if the USP Message was an Error response)
**                            or NULL if the caller does not require this information
**                            NOTE: Ownership of the pointer returned in this variable stays with the parsed USP Message
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int MSG_UTILS_ValidateUspResponse(Usp__Msg *resp, Usp__Response__RespTypeCase response_type, char **param_errs_path)
{
    int err;
    Usp__Body *body;
    Usp__Response *response;
    Usp__Error__ParamError *pe;
    char *err_msg;

    // NOTE: Message header has already been validated by DM_EXEC_SendRequestAndWaitForResponse(), so not doing it again here
    if (param_errs_path != NULL)
    {
        *param_errs_path = NULL;        // Set default return value
    }

    // Exit if body is missing
    body = resp->body;
    if (body == NULL)
    {
        USP_ERR_SetMessage("%s: Missing message body", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if the USP Service returned an ERROR to our request
    if (body->msg_body_case == USP__BODY__MSG_BODY_ERROR)
    {
        err = USP_ERR_INTERNAL_ERROR;  // default error code, if none present in error object

        // Use error code from error object, if present
        if ((body->error != NULL) && (body->error->err_code != USP_ERR_OK))
        {
            err = body->error->err_code;
            err_msg = body->error->err_msg;

            // Use more specific error code from param_errs object, if present
            if ((body->error->n_param_errs > 0) && (body->error->param_errs != NULL) && (body->error->param_errs[0] != NULL))
            {
                pe = body->error->param_errs[0];
                err = pe->err_code;
                if (pe->err_msg != NULL)
                {
                    err_msg = pe->err_msg;
                }

                if (param_errs_path != NULL)
                {
                    *param_errs_path = pe->param_path;
                }
            }

            USP_ERR_SetMessage("%s", err_msg);
        }

        return err;
    }

    // Exit if the USP Service didn't return a Response message to our request
    if (body->msg_body_case != USP__BODY__MSG_BODY_RESPONSE)
    {
        USP_ERR_SetMessage("%s: Received Unexpected message type %d (Expected a Response)", __FUNCTION__, body->msg_body_case);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if response is missing
    response = body->response;
    if (response == NULL)
    {
        USP_ERR_SetMessage("%s: Missing response", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }


    // Exit if response is the expected type response
    if (response->resp_type_case != response_type)
    {
        USP_ERR_SetMessage("%s: Received Unexpected response type %d (Expected %d)", __FUNCTION__, response->resp_type_case, response_type);
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** MSG_UTILS_Create_GetReq
**
** Private function to construct a GET request USP message from a list of keys
**
** \param   msg_id - string containing unique USP message ID to use for the request
** \param   kvv - key value vector containing the keys and values to get
** \param   depth - limit the tree depth of the get response (0 or FULL_DEPTH for unlimited))
**
** \return  Pointer to a Usp__Msg structure- ownership passes to the caller
**
**************************************************************************/
Usp__Msg *MSG_UTILS_Create_GetReq(char *msg_id, kv_vector_t *kvv, int depth)
{
    int i;
    int num_paths;
    Usp__Msg *msg;
    Usp__Get *get;

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

    if (depth == FULL_DEPTH)
    {
        depth = 0;
    }
    get->max_depth = depth;

    return msg;
}

/*********************************************************************//**
**
** MSG_UTILS_Create_SetReq
**
** Create a USP Set request message
**
** \param   msg_id - string containing unique USP message ID to use for the request
** \param   kvv - pointer to key-value vector containing the parameters to get as the key, and the values to set as the value
**
** \return  Pointer to a Set Request object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__Msg *MSG_UTILS_Create_SetReq(char *msg_id, kv_vector_t *kvv)
{
    int i;
    Usp__Msg *msg;
    Usp__Set *set;
    kv_pair_t *kv;

    // Create Set Request
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
        AddSetReq_Param(set, kv->key, kv->value);
    }

    return msg;
}

/*********************************************************************//**
**
** MSG_UTILS_Create_AddReq
**
** Create a USP Add request message
**
** \param   msg_id - string containing unique USP message ID to use for the request
** \param   path - unqualified path of the object to add an instance to
** \param   params - Array containing initial values of the object's child parameters, or NULL if there are none to set
** \param   num_params - Number of child parameters to set
**
** \return  Pointer to an Add Request object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__Msg *MSG_UTILS_Create_AddReq(char *msg_id, char *path, group_add_param_t *params, int num_params)
{
    Usp__Msg *msg;
    Usp__Add *add;
    Usp__Add__CreateObject *create_obj;
    Usp__Add__CreateParamSetting *cps;
    group_add_param_t *p;
    int i;

    // Create Add Request
    msg =  MSG_HANDLER_CreateRequestMsg(msg_id, USP__HEADER__MSG_TYPE__ADD, USP__REQUEST__REQ_TYPE_ADD);
    add = USP_MALLOC(sizeof(Usp__Add));
    usp__add__init(add);
    msg->body->request->add = add;

    // Fill in Add object
    add->allow_partial = false;
    add->n_create_objs = 1;
    add->create_objs = USP_MALLOC(sizeof(void *));

    create_obj = USP_MALLOC(sizeof(Usp__Add__CreateObject));
    usp__add__create_object__init(create_obj);
    add->create_objs[0] = create_obj;

    create_obj->obj_path = USP_STRDUP(path);

    // Exit if there are no parameters to set in this object
    if ((params==NULL) || (num_params == 0))
    {
        create_obj->n_param_settings = 0;
        create_obj->param_settings = NULL;
        return msg;
    }

    // Add all of the objects parameters initial values
    create_obj->n_param_settings = num_params;
    create_obj->param_settings = USP_MALLOC(num_params * sizeof(void *));

    for (i=0; i<num_params; i++)
    {
        cps = USP_MALLOC(sizeof(Usp__Add__CreateParamSetting));
        usp__add__create_param_setting__init(cps);
        create_obj->param_settings[i] = cps;

        p = &params[i];
        cps->param = USP_STRDUP(p->param_name);
        cps->value = USP_STRDUP(p->value);
        cps->required = p->is_required;
    }

    return msg;
}

/*********************************************************************//**
**
** MSG_UTILS_Extend_AddReq
**
** Adds another object to create, to a USP Add request message
**
** \param   msg - pointer to USP message structure to add to
** \param   path - unqualified path of the object to add an instance to
** \param   params - Array containing initial values of the object's child parameters, or NULL if there are none to set
** \param   num_params - Number of child parameters to set
**
** \return  None
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
void MSG_UTILS_Extend_AddReq(Usp__Msg *msg, char *path, group_add_param_t *params, int num_params)
{
    Usp__Add *add;
    Usp__Add__CreateObject *create_obj;
    Usp__Add__CreateParamSetting *cps;
    group_add_param_t *p;
    int i;
    int index;
    int new_size;

    USP_ASSERT((msg != NULL) && (msg->body != NULL) && (msg->body->request != NULL));
    add = msg->body->request->add;
    USP_ASSERT(add != NULL);

    // Extend the Add object with an extra create object
    index = add->n_create_objs;
    add->n_create_objs++;
    new_size = add->n_create_objs * sizeof(void *);
    add->create_objs = USP_REALLOC(add->create_objs, new_size);

    // Fill in the new create object
    create_obj = USP_MALLOC(sizeof(Usp__Add__CreateObject));
    usp__add__create_object__init(create_obj);
    add->create_objs[index] = create_obj;

    create_obj->obj_path = USP_STRDUP(path);

    // Exit if there are no parameters to set in this object
    if ((params==NULL) || (num_params == 0))
    {
        create_obj->n_param_settings = 0;
        create_obj->param_settings = NULL;
        return;
    }

    // Add all of the objects parameters initial values
    create_obj->n_param_settings = num_params;
    create_obj->param_settings = USP_MALLOC(num_params * sizeof(void *));

    for (i=0; i<num_params; i++)
    {
        cps = USP_MALLOC(sizeof(Usp__Add__CreateParamSetting));
        usp__add__create_param_setting__init(cps);
        create_obj->param_settings[i] = cps;

        p = &params[i];
        cps->param = USP_STRDUP(p->param_name);
        cps->value = USP_STRDUP(p->value);
        cps->required = p->is_required;
    }
}

/*********************************************************************//**
**
** MSG_UTILS_Create_DeleteReq
**
** Create a USP Delete request message containing multiple instances to delete
**
** \param   msg_id - string containing unique USP message ID to use for the request
** \param   paths - pointer to vector containing the list of data model objects to delete
**                  NOTE: All object paths must be absolute (no wildcards etc)
** \param   allow_partial - if set to true, then a failure to delete any object in the vector should result in no objects being deleted
**
** \return  Pointer to a Delete Request object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__Msg *MSG_UTILS_Create_DeleteReq(char *msg_id, str_vector_t *paths, bool allow_partial)
{
    int i;
    Usp__Msg *msg;
    Usp__Delete *del;
    int num_entries;

    // Create Delete Request
    msg =  MSG_HANDLER_CreateRequestMsg(msg_id, USP__HEADER__MSG_TYPE__DELETE, USP__REQUEST__REQ_TYPE_DELETE);
    del = USP_MALLOC(sizeof(Usp__Delete));
    usp__delete__init(del);
    msg->body->request->delete_ = del;

    // Fill in Delete object
    num_entries = paths->num_entries;
    del->allow_partial = allow_partial;
    del->n_obj_paths = num_entries;
    del->obj_paths = USP_MALLOC(num_entries*sizeof(char *));

    // Copy across the object instances to delete
    for (i=0; i<num_entries; i++)
    {
        del->obj_paths[i] = USP_STRDUP(paths->vector[i]);
    }

    return msg;
}

/*********************************************************************//**
**
** MSG_UTILS_Create_OperateReq
**
** Create a USP Operate request message
**
** \param   msg_id - string containing the message id to use for the request
** \param   path - data model path of USP command
** \param   command_key - Key identifying the command in the Request table of the USP Service
** \param   input_args - pointer to key-value vector containing the input arguments and their values, or NULL if none required
**
** \return  Pointer to a Operate Request object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__Msg *MSG_UTILS_Create_OperateReq(char *msg_id, char *path, char *command_key, kv_vector_t *input_args)
{
    int i;
    Usp__Msg *msg;
    Usp__Operate *oper;
    int num_entries;
    Usp__Operate__InputArgsEntry *arg;
    kv_pair_t *kv;

    // Create Operate Request
    msg =  MSG_HANDLER_CreateRequestMsg(msg_id, USP__HEADER__MSG_TYPE__OPERATE, USP__REQUEST__REQ_TYPE_OPERATE);
    oper = USP_MALLOC(sizeof(Usp__Operate));
    usp__operate__init(oper);
    msg->body->request->operate = oper;

    // Fill in Operate object
    oper->command = USP_STRDUP(path);
    oper->command_key = USP_STRDUP(command_key);
    oper->send_resp = true;

    // Create input args
    num_entries = (input_args != NULL) ? input_args->num_entries : 0;
    oper->n_input_args = num_entries;
    oper->input_args = USP_MALLOC(num_entries*sizeof(Usp__Operate__InputArgsEntry *));

    // Copy across the input args
    for (i=0; i<num_entries; i++)
    {
        kv = &input_args->vector[i];
        arg = USP_MALLOC(sizeof(Usp__Operate__InputArgsEntry));
        usp__operate__input_args_entry__init(arg);

        arg->key = USP_STRDUP(kv->key);
        arg->value = USP_STRDUP(kv->value);
        oper->input_args[i] = arg;
    }

    return msg;
}

/*********************************************************************//**
**
** CreateBroker_GetInstancesReq
**
** Create a USP GetInstances request message
**
** \param   msg_id - string containing the message id to use for the request
** \param   sv - pointer to string vector containing the top level data model object paths to recursively get all child instances of
**
** \return  Pointer to a GetInstances Request object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__Msg *MSG_UTILS_Create_GetInstancesReq(char *msg_id, str_vector_t *sv)
{
    int i;
    Usp__Msg *msg;
    Usp__GetInstances *geti;
    int num_entries;

    // Create GetInstances Request
    msg =  MSG_HANDLER_CreateRequestMsg(msg_id, USP__HEADER__MSG_TYPE__GET_INSTANCES, USP__REQUEST__REQ_TYPE_GET_INSTANCES);
    geti = USP_MALLOC(sizeof(Usp__GetInstances));
    usp__get_instances__init(geti);
    msg->body->request->get_instances = geti;

    // Copy the paths into the GetInstances
    num_entries = sv->num_entries;
    geti->n_obj_paths = num_entries;
    geti->obj_paths = USP_MALLOC(num_entries*sizeof(char *));
    for (i=0; i<num_entries; i++)
    {
        geti->obj_paths[i] = USP_STRDUP(sv->vector[i]);
    }

    // Get all child instances
    geti->first_level_only = false;

    return msg;
}

/*********************************************************************//**
**
** MSG_UTILS_Create_GetSupportedDMReq
**
** Create a USP GetSupportedDM request message
**
** \param   msg_id - string containing the message id to use for the request
** \param   sv - pointer to string vector containing the paths to query
**
** \return  Pointer to a GetSupportedDM Request object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__Msg *MSG_UTILS_Create_GetSupportedDMReq(char *msg_id, str_vector_t *sv)
{
    int i;
    int num_paths;
    Usp__Msg *msg;
    Usp__GetSupportedDM *gsdm;

    // Create GSDM Request
    msg =  MSG_HANDLER_CreateRequestMsg(msg_id, USP__HEADER__MSG_TYPE__GET_SUPPORTED_DM, USP__REQUEST__REQ_TYPE_GET_SUPPORTED_DM);
    gsdm = USP_MALLOC(sizeof(Usp__GetSupportedDM));
    usp__get_supported_dm__init(gsdm);
    msg->body->request->get_supported_dm = gsdm;

    // Copy the paths into the GSDM
    num_paths = sv->num_entries;
    gsdm->n_obj_paths = num_paths;
    gsdm->obj_paths = USP_MALLOC(num_paths*sizeof(char *));
    for (i=0; i<num_paths; i++)
    {
        gsdm->obj_paths[i] = USP_STRDUP(sv->vector[i]);
    }

    // Fill in the flags in the GSDM
    gsdm->first_level_only = false;
    gsdm->return_commands = true;
    gsdm->return_events = true;
    gsdm->return_params = true;
    gsdm->return_unique_key_sets = true;

    return msg;
}

/*********************************************************************//**
**
** MSG_UTILS_ProcessUspService_GetResponse
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
int MSG_UTILS_ProcessUspService_GetResponse(Usp__Msg *resp, kv_vector_t *kvv)
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

    // Exit if the Message body contained an Error response, or the response failed to validate
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

        // Exit if we received an error for this path
        if (rpr->err_code != USP_ERR_OK)
        {
            USP_ERR_SetMessage("Failed to get '%s' (err_msg=%s)", rpr->requested_path, rpr->err_msg);
            KV_VECTOR_Destroy(kvv);
            err = rpr->err_code;
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

exit:
    return err;
}

/*********************************************************************//**
**
** MSG_UTILS_ProcessUspService_SetResponse
**
** Processes a Set Response that we have received from a USP Service
**
** \param   resp - USP response message in protobuf-c structure
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int MSG_UTILS_ProcessUspService_SetResponse(Usp__Msg *resp)
{
    int i;
    int err = USP_ERR_OK;
    Usp__SetResp *set;
    Usp__SetResp__UpdatedObjectResult *obj_result;
    Usp__SetResp__UpdatedObjectResult__OperationStatus *oper_status;
    Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationFailure *oper_failure;

    // Exit if the Message body contained an Error response, or the response failed to validate
    err = MSG_UTILS_ValidateUspResponse(resp, USP__RESPONSE__RESP_TYPE_SET_RESP, NULL);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if set response object is missing
    set = resp->body->response->set_resp;
    if (set == NULL)
    {
        USP_ERR_SetMessage("%s: Missing set response", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Iterate over all UpdatedObjResults, checking that all were successful
    // NOTE: We expect all of them to be successful if the code gets here since the Set Request has allow_partial=false and
    // all parameters are required to set, so we should have received an ERROR response if any failed to set
    for (i=0; i < set->n_updated_obj_results; i++)
    {
        obj_result = set->updated_obj_results[i];
        oper_status = obj_result->oper_status;
        switch(oper_status->oper_status_case)
        {
            case USP__SET_RESP__UPDATED_OBJECT_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_SUCCESS:
                break;

            case USP__SET_RESP__UPDATED_OBJECT_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_FAILURE:
                oper_failure = oper_status->oper_failure;
                USP_ERR_SetMessage("%s", oper_failure->err_msg);
                err = oper_failure->err_code;
                break;

            default:
                TERMINATE_BAD_CASE(oper_status->oper_status_case);
                break;
        }
    }

    return err;
}

/*********************************************************************//**
**
** MSG_UTILS_ProcessUspService_AddResponse
**
** Processes a Add Response that we have received from a USP Service.  This
** function populates the returned kvv structure with all the unique keys
** found in the USP response message without performing any filtering.
**
** \param   resp - USP response message in protobuf-c structure
** \param   unique_keys - key-value vector in which to return the unique keys of the instantiated object
** \param   instance - pointer to integer in which to return the instance number of the instantiated object
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int MSG_UTILS_ProcessUspService_AddResponse(Usp__Msg *resp, kv_vector_t *unique_keys, int *instance)
{
    int i;
    int err = USP_ERR_OK;
    Usp__AddResp *add;
    Usp__AddResp__CreatedObjectResult *created_obj_result;
    Usp__AddResp__CreatedObjectResult__OperationStatus *oper_status;
    Usp__AddResp__CreatedObjectResult__OperationStatus__OperationFailure *oper_failure;
    Usp__AddResp__CreatedObjectResult__OperationStatus__OperationSuccess *oper_success;
    Usp__AddResp__CreatedObjectResult__OperationStatus__OperationSuccess__UniqueKeysEntry *uk;
    str_vector_t sv_params;

    STR_VECTOR_Init(&sv_params);

    // Exit if the Message body contained an Error response, or the response failed to validate
    err = MSG_UTILS_ValidateUspResponse(resp, USP__RESPONSE__RESP_TYPE_ADD_RESP, NULL);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if get response is missing
    add = resp->body->response->add_resp;
    if (add == NULL)
    {
        USP_ERR_SetMessage("%s: Missing add response", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if there isn't exactly 1 created_obj_result (since the USP_SERVICE_Add API supports returning the instance number of only one object)
    if (add->n_created_obj_results != 1)
    {
        USP_ERR_SetMessage("%s: Too many objects created (%d). USP_SERVICE_Add() can only return a single instance number.", __FUNCTION__, (int)add->n_created_obj_results);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Determine whether the object was created successfully or failed
    created_obj_result = add->created_obj_results[0];
    oper_status = created_obj_result->oper_status;
    switch(oper_status->oper_status_case)
    {
        case USP__ADD_RESP__CREATED_OBJECT_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_FAILURE:
            oper_failure = oper_status->oper_failure;
            USP_ERR_SetMessage("%s", oper_failure->err_msg);
            err = oper_failure->err_code;
            break;

        case USP__ADD_RESP__CREATED_OBJECT_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_SUCCESS:
            oper_success = oper_status->oper_success;

            TEXT_UTILS_SplitString(oper_success->instantiated_path, &sv_params, ".");

            // typically we would expect at least 3 entries - i.e. "Device.<path>.<instance>."
            if (sv_params.num_entries < 1)
            {
                USP_ERR_SetMessage("%s: Unable to determine instance of instantiated object : %s", __FUNCTION__, oper_success->instantiated_path);
                err = USP_ERR_INTERNAL_ERROR;
                goto exit;
            }

            err = TEXT_UTILS_StringToInteger(sv_params.vector[sv_params.num_entries-1], instance);
            if (err != USP_ERR_OK)
            {
               goto exit;
            }

            // output key vector should contain name and value of each unique key
            for (i=0; i < oper_success->n_unique_keys; i++)
            {
                uk = oper_success->unique_keys[i];
                KV_VECTOR_Add(unique_keys, uk->key, uk->value);
            }
            break;

        default:
            TERMINATE_BAD_CASE(oper_status->oper_status_case);
    }

exit:
    STR_VECTOR_Destroy(&sv_params);

    return err;
}

/*********************************************************************//**
**
** MSG_UTILS_ProcessUspService_DeleteResponse
**
** Processes a Delete Response that we have received from a USP Service
**
** \param   resp - USP response message in protobuf-c structure
** \param   path - pointer to string containing the data model object that we requested to delete
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int MSG_UTILS_ProcessUspService_DeleteResponse(Usp__Msg *resp, char *path)
{
    int err = USP_ERR_OK;
    Usp__DeleteResp *del;
    Usp__DeleteResp__DeletedObjectResult *deleted_obj_result;
    Usp__DeleteResp__DeletedObjectResult__OperationStatus *oper_status;
    Usp__DeleteResp__DeletedObjectResult__OperationStatus__OperationFailure *oper_failure;
    char *param_errs_path = NULL;
    int i;

    // Exit if the Message body contained an Error response, or the response failed to validate
    err = MSG_UTILS_ValidateUspResponse(resp, USP__RESPONSE__RESP_TYPE_DELETE_RESP, &param_errs_path);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if delete response is missing
    del = resp->body->response->delete_resp;
    if (del == NULL)
    {
        USP_ERR_SetMessage("%s: Missing delete response", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // iterate over all deleted objects
    for (i = 0 ; i < del->n_deleted_obj_results ; i++)
    {
       deleted_obj_result = del->deleted_obj_results[i];

       // Exit if this response is for a different requested path
       if (strcmp( path, deleted_obj_result->requested_path ))
       {
           USP_ERR_SetMessage("%s: Unexpected requested path in DeleteResponse (%s)", __FUNCTION__,  deleted_obj_result->requested_path);
           return USP_ERR_INTERNAL_ERROR;
       }

       // Determine whether the object was deleted successfully or failed
       oper_status = deleted_obj_result->oper_status;
       switch(oper_status->oper_status_case)
       {
           case USP__DELETE_RESP__DELETED_OBJECT_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_FAILURE:
               // NOTE: The USP Service should have sent an Error response instead of an OperFailure, because we sent the Delete request with allow_partial=false
               oper_failure = oper_status->oper_failure;
               USP_ERR_SetMessage("Failed to delete %s (err_msg=%s)", deleted_obj_result->requested_path, oper_failure->err_msg);
               err = oper_failure->err_code;
               goto exit;
               break;

           case USP__DELETE_RESP__DELETED_OBJECT_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_SUCCESS:
               break;

           default:
               TERMINATE_BAD_CASE(oper_status->oper_status_case);
               break;
       }
    }

exit:
    return err;
}

/*********************************************************************//**
**
** MSG_UTILS_ProcessUspService_OperateResponse
**
** Processes a Operate Response that we have received from a USP Service
**
** \param   resp - USP response message in protobuf-c structure
** \param   path - USP command that was attempted
** \param   output_args - pointer to key-value vector to fill in with the output arguments parsed from the USP esponse message
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int MSG_UTILS_ProcessUspService_OperateResponse(Usp__Msg *resp, char *path, kv_vector_t *output_args)
{
    int i;
    int err = USP_ERR_OK;
    Usp__OperateResp *oper;
    Usp__OperateResp__OperationResult *res;
    Usp__OperateResp__OperationResult__OutputArgs *args;
    Usp__OperateResp__OperationResult__CommandFailure *fail;
    Usp__OperateResp__OperationResult__OutputArgs__OutputArgsEntry *entry;

    // Initialise default output arguments
    KV_VECTOR_Init(output_args);

    // Exit if the Message body contained an Error response, or the response failed to validate
    err = MSG_UTILS_ValidateUspResponse(resp, USP__RESPONSE__RESP_TYPE_OPERATE_RESP, NULL);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if operate response is missing
    oper = resp->body->response->operate_resp;
    if (oper == NULL)
    {
        USP_ERR_SetMessage("%s: Missing operate response", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if the number of operation_results does not match the expected number
    // The implementation currently expects a single operation path (without wildcards)
    if (oper->n_operation_results != 1)
    {
        USP_ERR_SetMessage("%s: Too many operation results (%d). USP_SERVICE_Operate() can only return the output args of a single USP command", __FUNCTION__, (int)oper->n_operation_results);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if the operation wasn't the one we requested
    res = oper->operation_results[0];
    if (strcmp(res->executed_command, path) != 0)
    {
        USP_ERR_SetMessage("%s: Unexpected operation in response (got='%s', expected=%s')", __FUNCTION__, res->executed_command, path);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Determine if the operation was successful (for sync command) or successfully started (for async commands)
    switch(res->operation_resp_case)
    {
        case USP__OPERATE_RESP__OPERATION_RESULT__OPERATION_RESP_REQ_OBJ_PATH:
            // Async Operation started
            err = USP_ERR_OK;
            break;

        case USP__OPERATE_RESP__OPERATION_RESULT__OPERATION_RESP_REQ_OUTPUT_ARGS:
            // Operation succeeded: Copy across output arguments
            args = res->req_output_args;
            for (i=0; i < args->n_output_args; i++)
            {
                entry = args->output_args[i];
                KV_VECTOR_Add(output_args, entry->key, entry->value);
            }

            err = USP_ERR_OK;
            break;

        case USP__OPERATE_RESP__OPERATION_RESULT__OPERATION_RESP_CMD_FAILURE:
            // Operation failed
            fail = res->cmd_failure;
            USP_ERR_SetMessage("%s", fail->err_msg);
            err = fail->err_code;
            break;

        default:
            break;
    }

    return err;
}

/*********************************************************************//**
**
** MSG_UTILS_ProcessUspService_GetInstancesResponse
**
** Processes a GetInstances Response that we have received from a USP Service
**
** \param   resp - USP response message in protobuf-c structure
** \param   sv - pointer to string vector to return paths of all instances
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int MSG_UTILS_ProcessUspService_GetInstancesResponse(Usp__Msg *resp, str_vector_t *sv)
{
    int i, j;
    int err = USP_ERR_OK;
    Usp__GetInstancesResp *geti;
    Usp__GetInstancesResp__RequestedPathResult *rpr;
    Usp__GetInstancesResp__CurrInstance *ci;
    char *path;

    // Exit if failed to validate that the Message body contains a GetInstances Response
    err = MSG_UTILS_ValidateUspResponse(resp, USP__RESPONSE__RESP_TYPE_GET_INSTANCES_RESP, NULL);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if get instances response is missing
    geti = resp->body->response->get_instances_resp;
    if (geti == NULL)
    {
        USP_ERR_SetMessage("%s: Missing get instances response", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Iterate over all requested path results
    USP_ASSERT((geti->n_req_path_results==0) || (geti->req_path_results != NULL));
    for (i=0; i < geti->n_req_path_results; i++)
    {
        // Skip this result if it is not filled in. NOTE: This should never happen
        rpr = geti->req_path_results[i];
        if (rpr == NULL)
        {
            continue;
        }

        // Exit if we received an error for this object
        if (rpr->err_code != USP_ERR_OK)
        {
            USP_ERR_SetMessage("%s: Failed to get instances for object '%s' (err_msg=%s)", __FUNCTION__, rpr->requested_path, rpr->err_msg);
            STR_VECTOR_Destroy(sv);
            return rpr->err_code;
        }

        // Iterate over all current instance objects
        for (j=0; j < rpr->n_curr_insts; j++)
        {
            ci = rpr->curr_insts[j];
            if (ci != NULL)
            {
                path = ci->instantiated_obj_path;
                if ((path != NULL) && (*path != '\0'))
                {
                    if (strncmp(path, dm_root, dm_root_len) != 0)
                    {
                        USP_ERR_SetMessage("%s: Response contains invalid data model path '%s'", __FUNCTION__, path);
                        STR_VECTOR_Destroy(sv);
                        return USP_ERR_INTERNAL_ERROR;
                    }
                    STR_VECTOR_Add(sv, path);
                }
            }
        }
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** MSG_UTILS_ProcessUspService_GetSupportedDMResponse
**
** Processes a GSDM Response that we have received from a USP Service.  This
** function populates the returned sv structure with all paths found in the USP
** response message without performing any filtering.
**
** \param   resp - USP response message in protobuf-c structure
** \param   kvv - key/value vector to return paths of all supported parameters and their type
**
** \return  USP_ERR_OK if successful
**************************************************************************/
int MSG_UTILS_ProcessUspService_GetSupportedDMResponse(Usp__Msg *usp, kv_vector_t *kvv)
{
    int i,j,k;
    int err = USP_ERR_OK;

    Usp__GetSupportedDMResp *gsdm;
    Usp__GetSupportedDMResp__SupportedObjectResult *sor;
    Usp__GetSupportedDMResp__RequestedObjectResult *ror;
    Usp__GetSupportedDMResp__SupportedParamResult *sp;
    Usp__GetSupportedDMResp__SupportedEventResult *se;
    Usp__GetSupportedDMResp__SupportedCommandResult *sc;

    char path[MAX_DM_PATH];
    char *type;

    err = MSG_UTILS_ValidateUspResponse(usp, USP__RESPONSE__RESP_TYPE_GET_SUPPORTED_DM_RESP, NULL);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if get response is missing
    gsdm = usp->body->response->get_supported_dm_resp;
    if (gsdm == NULL)
    {
        USP_ERR_SetMessage("%s: Missing get response", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Iterate over all requested objects
    for (i=0; i < gsdm->n_req_obj_results; i++)
    {
        ror = gsdm->req_obj_results[i];

        // Exit if the USP Service encountered an error providing the supported data model for this path
        if (ror->err_code != USP_ERR_OK)
        {
            USP_ERR_SetMessage("%s: USP broker did not provide data model for '%s' (err_code=%d, err_msg='%s')", __FUNCTION__, ror->req_obj_path, ror->err_code, ror->err_msg);
            return USP_ERR_INTERNAL_ERROR;
        }

        // Iterate over all supported objects and add them to return vector
        for (j=0; j < ror->n_supported_objs; j++)
        {
            sor = ror->supported_objs[j];
            if ((sor->supported_obj_path != NULL) && (*sor->supported_obj_path != '\0'))
            {
                // Exit if the path does not begin with "Device."
                if (strncmp(sor->supported_obj_path, dm_root, dm_root_len) != 0)
                {
                    USP_ERR_SetMessage("%s: Response contains invalid data model path '%s'", __FUNCTION__, path);
                    return USP_ERR_INTERNAL_ERROR;
                }

                // Iterate over paramaters, adding them to the returned vector
                for (k=0; k < sor->n_supported_params; k++)
                {
                    sp = sor->supported_params[k];
                    USP_SNPRINTF(path, MAX_DM_PATH, "%s%s", sor->supported_obj_path,  sp->param_name);
                    type = ParamTypeToUspServiceString(sp->value_type);
                    KV_VECTOR_Add(kvv, path, type);
                }

                // Iterate over events, adding them to the returned vector
                for (i=0; i < sor->n_supported_events; i++)
                {
                    se = sor->supported_events[i];
                    USP_SNPRINTF(path, MAX_DM_PATH, "%s%s", sor->supported_obj_path,  se->event_name);
                    KV_VECTOR_Add(kvv, path, "event");
                }

                // Iterate over operations, adding them to the returned vector
                for (i=0; i < sor->n_supported_commands; i++)
                {
                    sc = sor->supported_commands[i];
                    USP_SNPRINTF(path, MAX_DM_PATH, "%s%s", sor->supported_obj_path,  sc->command_name);
                    switch(sc->command_type)
                    {
                        case USP__GET_SUPPORTED_DMRESP__CMD_TYPE__CMD_SYNC:
                            KV_VECTOR_Add(kvv, path, "sync_cmd");
                            break;

                        case USP__GET_SUPPORTED_DMRESP__CMD_TYPE__CMD_ASYNC:
                        default:
                            KV_VECTOR_Add(kvv, path, "async_cmd");
                            break;
                    }
                }
            }
        }
    }

    return err;
}

/*********************************************************************//**
**
** ParamTypeToUspServiceString
**
** Convert from the protobuf parameter type enumeration to a string
**
** \param   value_type - protobuf parameter type enumeration to convert
**
** \return  string representing parameter type
**
**************************************************************************/
char *ParamTypeToUspServiceString(Usp__GetSupportedDMResp__ParamValueType value_type)
{
    char *ret = "\0";

    (void)ret;      // Stop clang static analyser complaining about unnecessary variable initialization
                    // Whilst it should be unnecessary in this case, some other static analysers and compilers complain if ret is not
                    // initialized, since they examine the case of nothing matching in the switch statement

    switch(value_type)
    {
        case USP__GET_SUPPORTED_DMRESP__PARAM_VALUE_TYPE__PARAM_BASE_64:
            ret = "base64";
            break;

        case USP__GET_SUPPORTED_DMRESP__PARAM_VALUE_TYPE__PARAM_BOOLEAN:
            ret = "boolean";
            break;

        case USP__GET_SUPPORTED_DMRESP__PARAM_VALUE_TYPE__PARAM_DATE_TIME:
            ret = "date_time";
            break;

        case USP__GET_SUPPORTED_DMRESP__PARAM_VALUE_TYPE__PARAM_DECIMAL:
            ret = "decimal";
            break;

        case USP__GET_SUPPORTED_DMRESP__PARAM_VALUE_TYPE__PARAM_HEX_BINARY:
            ret = "hex_binary";
            break;

        case USP__GET_SUPPORTED_DMRESP__PARAM_VALUE_TYPE__PARAM_INT:
            ret = "int";
            break;

        case USP__GET_SUPPORTED_DMRESP__PARAM_VALUE_TYPE__PARAM_LONG:
            ret = "long";
            break;

        case USP__GET_SUPPORTED_DMRESP__PARAM_VALUE_TYPE__PARAM_UNSIGNED_INT:
            ret = "int";
            break;

        case USP__GET_SUPPORTED_DMRESP__PARAM_VALUE_TYPE__PARAM_UNSIGNED_LONG:
            ret = "ulong";
            break;

        default:
        case USP__GET_SUPPORTED_DMRESP__PARAM_VALUE_TYPE__PARAM_STRING:
            ret = "string";
            break;
    }

    return ret;
}

/*********************************************************************//**
**
** FindUpdateObject
**
** Searches for the update object in a Set Request, for the specified object_path
**
** \param   set - pointer to Set request to look for the specified object path in
** \param   obj_path - path to object in data model
**
** \return  Pointer to a ResolvedPath object, or NULL if no match was found
**
**************************************************************************/
Usp__Set__UpdateObject *FindUpdateObject(Usp__Set *set, char *obj_path)
{
    int i;
    int num_entries;
    int index;
    Usp__Set__UpdateObject *update_object;

    // Determine limits of backwards search for matching object path
    #define UPDATE_OBJECT_SEARCH_LIMIT 3
    num_entries = set->n_update_objs;
    index = num_entries - UPDATE_OBJECT_SEARCH_LIMIT;
    if (index < 0)
    {
        index = 0;
    }

    // Search backwards, trying to find the one which matches the specified object path
    for (i=num_entries-1; i>=index; i--)
    {
        update_object = set->update_objs[i];
        if (strcmp(update_object->obj_path, obj_path)==0)
        {
            return update_object;
        }
    }

    // If the code gets here, then no matching object path was found
    return NULL;
}

/*********************************************************************//**
**
** AddSetReq_UpdateObject
**
** Dynamically adds an update_object entry to a set request
**
** \param   set - pointer to Set request to add this entry to
** \param   obj_path - path to object in data model
**
** \return  Pointer to dynamically allocated update_object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__Set__UpdateObject *AddSetReq_UpdateObject(Usp__Set *set, char *obj_path)
{
    Usp__Set__UpdateObject *update_object;

    int new_num;    // new number of entries in the set request

    // Allocate memory to store the update object
    update_object = USP_MALLOC(sizeof(Usp__Set__UpdateObject));
    usp__set__update_object__init(update_object);

    // Increase the size of the vector containing pointers to the update objects
    new_num = set->n_update_objs + 1;
    set->update_objs = USP_REALLOC(set->update_objs, new_num*sizeof(void *));
    set->n_update_objs = new_num;
    set->update_objs[new_num-1] = update_object;

    // Initialise the update object
    update_object->obj_path = USP_STRDUP(obj_path);
    update_object->n_param_settings = 0;
    update_object->param_settings = NULL;

    return update_object;
}

/*********************************************************************//**
**
** AddUpdateObject_ParamSettings
**
** Dynamically adds a param_settings entry to a update_object
**
** \param   update_object - pointer to update_ object to add this entry to
** \param   param_name - name of the parameter (not including object path) of the parameter to add
** \param   value - value of the parameter
**
** \return  Pointer to dynamically allocated param_settings object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__Set__UpdateParamSetting *AddUpdateObject_ParamSettings(Usp__Set__UpdateObject *update_object, char *param_name, char *value)
{
    Usp__Set__UpdateParamSetting *param_settings;

    int new_num;    // new number of entries in the param_settings

    // Allocate memory to store the param_settings entry
    param_settings = USP_MALLOC(sizeof(Usp__Set__UpdateParamSetting));
    usp__set__update_param_setting__init(param_settings);

    // Increase the size of the vector containing pointers to the map entries
    new_num = update_object->n_param_settings + 1;
    update_object->param_settings = USP_REALLOC(update_object->param_settings, new_num*sizeof(void *));
    update_object->n_param_settings = new_num;
    update_object->param_settings[new_num-1] = param_settings;

    // Initialise the param_settings entry
    param_settings->param = USP_STRDUP(param_name);
    param_settings->value = USP_STRDUP(value);
    param_settings->required = true;

    return param_settings;
}


/*********************************************************************//**
**
** AddSetReq_Param
**
** Adds the specified parameter to the Set Request
**
** \param   set - pointer to Set request to add the parameter to
** \param   path - data model path of the parameter
** \param   value - new value of the parameter to set
**
** \return  None
**
**************************************************************************/
void AddSetReq_Param(Usp__Set *set, char *path, char *value)
{
    char obj_path[MAX_DM_PATH];
    char *param_name;
    Usp__Set__UpdateObject *update_object;

    // Split the parameter into the parent object path and the name of the parameter within the object
    param_name = TEXT_UTILS_SplitPath(path, obj_path, sizeof(obj_path));

    // Add an update object, if we don't already have one for the specified parent object
    update_object = FindUpdateObject(set, obj_path);
    if (update_object == NULL)
    {
        update_object = AddSetReq_UpdateObject(set, obj_path);
    }

    // Add the parameter to the param settings
    AddUpdateObject_ParamSettings(update_object, param_name, value);
}
#endif // !defined(REMOVE_USP_BROKER) && !defined(REMOVE_USP_SERVICE)
