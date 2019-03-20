/*
 *
 * Copyright (C) 2016-2019  ARRIS Enterprises, LLC
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
 * \file handle_get.c
 *
 * Handles the GetRequest message, creating a GetResponse
 *
 */

#include <stdlib.h>
#include <string.h>
#include <protobuf-c/protobuf-c.h>

#include "common_defs.h"
#include "usp-msg.pb-c.h"
#include "msg_handler.h"
#include "data_model.h"
#include "dm_access.h"
#include "path_resolver.h"
#include "device.h"
#include "text_utils.h"

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
void GetSinglePath(Usp__Msg *resp, char *path_expression);
void AddResolvedPathResult(Usp__GetResp__RequestedPathResult *req_path_result, char *path, char *value, int separator_split);
Usp__GetResp__ResolvedPathResult *FindResolvedPath(Usp__GetResp__RequestedPathResult *req_path_result, char *obj_path);
Usp__Msg *CreateGetResp(char *msg_id);
Usp__GetResp__RequestedPathResult *AddGetResp_ReqPathRes(Usp__Msg *resp, char *requested_path, int err_code, char *err_msg);
Usp__GetResp__ResolvedPathResult *AddReqPathRes_ResolvedPathResult(Usp__GetResp__RequestedPathResult *req_path_result, char *obj_path);

Usp__GetResp__ResolvedPathResult__ResultParamsEntry *
AddResolvedPathRes_ParamsEntry(Usp__GetResp__ResolvedPathResult *resolved_path_res, char *param_name, char *value);
void DestroyCurReqPathResult(Usp__Msg *resp, Usp__GetResp__RequestedPathResult *expected_req_path_result);
void DestroyResolvedPathResult(Usp__GetResp__ResolvedPathResult *resolved_path_res_entry);

/*********************************************************************//**
**
** MSG_HANDLER_HandleGet
**
** Handles a USP Get message
**
** \param   usp - pointer to parsed USP message structure. This is always freed by the caller (not this function)
** \param   controller_endpoint - endpoint which sent this message
** \param   stomp_dest - STOMP destination to send the reply to (or NULL if none setup in received message)
** \param   stomp_instance - STOMP instance (in Device.STOMP.Connection table) to send the reply to
**
** \return  None - This code must handle any errors by sending back error messages
**
**************************************************************************/
void MSG_HANDLER_HandleGet(Usp__Msg *usp, char *controller_endpoint, char *stomp_dest, int stomp_instance)
{
    int i;
    char **param_paths;
    int num_param_paths;
    Usp__Msg *resp = NULL;

    // Exit if message is invalid or failed to parse
    // This code checks the parsed message enums and pointers for expectations and validity
    if ((usp->header == NULL) || 
        (usp->body == NULL) || (usp->body->msg_body_case != USP__BODY__MSG_BODY_REQUEST) ||
        (usp->body->request == NULL) || (usp->body->request->req_type_case != USP__REQUEST__REQ_TYPE_GET) ||
        (usp->body->request->get == NULL) )
    {
        USP_ERR_SetMessage("%s: Incoming message is invalid or inconsistent", __FUNCTION__);
        resp = ERROR_RESP_CreateSingle(usp->header->msg_id, USP_ERR_MESSAGE_NOT_UNDERSTOOD, resp, NULL);
        goto exit;
    }

    // Create a Get Response message
    resp = CreateGetResp(usp->header->msg_id);

    // Exit if there are no parameters to get
    param_paths = usp->body->request->get->param_paths;
    num_param_paths = usp->body->request->get->n_param_paths;
    if ((param_paths == NULL) || (num_param_paths == 0))
    {
        goto exit;
    }

    // Iterate over all parameter paths in the get
    for (i=0; i<num_param_paths; i++)
    {
        GetSinglePath(resp, param_paths[i]);
    }

exit:
    MSG_HANDLER_QueueMessage(controller_endpoint, resp, stomp_dest, stomp_instance);
    usp__msg__free_unpacked(resp, pbuf_allocator);
}

/*********************************************************************//**
**
** GetSinglePath
**
** Resolves the specified path expression into multiple parameters, and gets the value of each,
** adding the results to the GetResponse object
**
** \param   resp - pointer to GetResponse object
** \param   path_expression - pointer to a path expression string to resolve
**
** \return  None - This function handles all erors by putting error messages in the get response
**
**************************************************************************/
void GetSinglePath(Usp__Msg *resp, char *path_expression)
{
    int i;
    int err;
    str_vector_t params;
    Usp__GetResp__RequestedPathResult *req_path_result;
    char value[MAX_DM_VALUE_LEN];
    int separator_split;
    combined_role_t combined_role;

    // Exit if the search path is not in the schema or the search path was invalid or an error occured in evaluating the search path (eg a parameter get failed)
    // The get response will contain an error message in this case
    STR_VECTOR_Init(&params);
    MSG_HANDLER_GetMsgRole(&combined_role);
    err = PATH_RESOLVER_ResolveDevicePath(path_expression, &params, kResolveOp_Get, &separator_split, &combined_role, 0);
    if (err != USP_ERR_OK)
    {
        req_path_result = AddGetResp_ReqPathRes(resp, path_expression, err, USP_ERR_GetMessage());
        goto exit;
    }

    // Add a requested path result to the Get Response message
    req_path_result = AddGetResp_ReqPathRes(resp, path_expression, USP_ERR_OK, "");

    // Exit if no matching parameters were found in the data model
    if (params.num_entries==0)
    {
        // The get response should contain an empty results list in this case
        // So do not set the error message
        //USP_ERR_SetMessage("%s: Invalid instance number or no instances found of '%s'", __FUNCTION__, path_expression);
        goto exit;
    }

    // Iterate over all resolved params adding their value to the result_params
    for (i=0; i < params.num_entries; i++)
    {
        // Exit if unable to get the value of a parameter
        // The get response will contain only an error message in this case
        err = DATA_MODEL_GetParameterValue(params.vector[i], value, sizeof(value), 0);
        if (err != USP_ERR_OK)
        {
            DestroyCurReqPathResult(resp, req_path_result);
            req_path_result = AddGetResp_ReqPathRes(resp, path_expression, err, USP_ERR_GetMessage());
            goto exit;
        }

        // Add a param map entry to the requested path result
        AddResolvedPathResult(req_path_result, params.vector[i], value, separator_split);
    }


exit:
    STR_VECTOR_Destroy(&params);
}

/*********************************************************************//**
**
** AddResolvedPathResult
**
** Adds the specified path to the resolved_path_result list
** This function creates a resolved_path_result entry for the parent object
** of the parameter, before adding the parameter to the result_params
**
** \param   req_path_result - pointer to requested_path_result to add this entry to
** \param   path - full data model path of the parameter
** \param   value - value of the parameter
** \param   separator_split - denotes where to split the parameter path based on the number of separators for the object that required resolution
**                            The path is split into an object (that required resolution),
**                            and a sub path which did not require resolution
**
** \return  None
**
**************************************************************************/
void AddResolvedPathResult(Usp__GetResp__RequestedPathResult *req_path_result, char *path, char *value, int separator_split)
{
    char obj_path[MAX_DM_PATH];
    char *param_name;
    Usp__GetResp__ResolvedPathResult *resolved_path_res;

    // Split the parameter into the parent object path and the name of the parameter within the object
    param_name = TEXT_UTILS_SplitPathAtSeparator(path, obj_path, sizeof(obj_path), separator_split);

    // Add a resolved path result, if we don't alredy have one for the specified parent object
    resolved_path_res = FindResolvedPath(req_path_result, obj_path);
    if (resolved_path_res == NULL)
    {
        resolved_path_res = AddReqPathRes_ResolvedPathResult(req_path_result, obj_path);
    }

    // Add the parameter to the params
    AddResolvedPathRes_ParamsEntry(resolved_path_res, param_name, value);
}

/*********************************************************************//**
**
** FindResolvedPath
**
** Searches for the resolved path object which represents the specified object_path
**
** \param   req_path_result - pointer to requested_path_result to look for the specified object path in
** \param   obj_path - path to object in data model
**
** \return  Pointer to a ResolvedPath object, or NULL if no match was found
**
**************************************************************************/
Usp__GetResp__ResolvedPathResult *FindResolvedPath(Usp__GetResp__RequestedPathResult *req_path_result, char *obj_path)
{
    int i;
    int num_entries;
    Usp__GetResp__ResolvedPathResult *resolved_path_result;

    // Iterate over all resolved path results, trying to find the one which matches the specified object path
    num_entries = req_path_result->n_resolved_path_results;
    for (i=0; i<num_entries; i++)
    {
        resolved_path_result = req_path_result->resolved_path_results[i];
        if (strcmp(resolved_path_result->resolved_path, obj_path)==0)
        {
            return resolved_path_result;
        }
    }

    // If the code gets here, then no matching object path was found
    return NULL;
}

/*********************************************************************//**
**
** CreateGetResp
**
** Dynamically creates an GetResponse object
** NOTE: The object is created without any requested_path_results
** NOTE: The object should be deleted using usp__msg__free_unpacked()
**
** \param   msg_id - string containing the message id of the get request, which initiated this response
**
** \return  Pointer to a GetResponse object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__Msg *CreateGetResp(char *msg_id)
{
    Usp__Msg *resp;
    Usp__Header *header;
    Usp__Body *body;
    Usp__Response *response;
    Usp__GetResp *get_resp;

    // Allocate memory to store the USP message
    resp = USP_MALLOC(sizeof(Usp__Msg));
    usp__msg__init(resp);

    header = USP_MALLOC(sizeof(Usp__Header));
    usp__header__init(header);

    body = USP_MALLOC(sizeof(Usp__Body));
    usp__body__init(body);

    response = USP_MALLOC(sizeof(Usp__Response));
    usp__response__init(response);

    get_resp = USP_MALLOC(sizeof(Usp__GetResp));
    usp__get_resp__init(get_resp);

    // Connect the structures together
    resp->header = header;
    header->msg_id = USP_STRDUP(msg_id);
    header->msg_type = USP__HEADER__MSG_TYPE__GET_RESP;

    resp->body = body;
    body->msg_body_case = USP__BODY__MSG_BODY_RESPONSE;
    body->response = response;
    response->resp_type_case = USP__RESPONSE__RESP_TYPE_GET_RESP;
    response->get_resp = get_resp;
    get_resp->n_req_path_results = 0;    // Start from an empty response list
    get_resp->req_path_results = NULL;

    return resp;
}    

/*********************************************************************//**
**
** AddGetResp_ReqPathRes
**
** Dynamically adds a requested path result to the GetResponse object
** NOTE: The object is created without any entries in the result_params
**
** \param   resp - pointer to GetResponse object
** \param   requested_path - string containing one of the path expresssions from the Get request
** \param   err_code - numeric code indicating reason the get failed
** \param   err_msg - error message indicating reason the get failed
**
** \return  Pointer to dynamically allocated requested path result
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__GetResp__RequestedPathResult *
AddGetResp_ReqPathRes(Usp__Msg *resp, char *requested_path, int err_code, char *err_msg)
{
    Usp__GetResp *get_resp;
    Usp__GetResp__RequestedPathResult *req_path_result;
    int new_num;    // new number of requested_path_results

    // Allocate memory to store the requested_path_result
    req_path_result = USP_MALLOC(sizeof(Usp__GetResp__RequestedPathResult));
    usp__get_resp__requested_path_result__init(req_path_result);

    // Increase the size of the vector containing pointers to the requested_path_results
    get_resp = resp->body->response->get_resp;
    new_num = get_resp->n_req_path_results + 1;
    get_resp->req_path_results = USP_REALLOC(get_resp->req_path_results, new_num*sizeof(void *));
    get_resp->n_req_path_results = new_num;
    get_resp->req_path_results[new_num-1] = req_path_result;

    // Initialise the requested_path_result
    req_path_result->requested_path = USP_STRDUP(requested_path);
    req_path_result->err_code = err_code;
    req_path_result->err_msg = USP_STRDUP(err_msg);
    req_path_result->n_resolved_path_results = 0;     // Start from an empty list
    req_path_result->resolved_path_results = NULL;

    return req_path_result;
}

/*********************************************************************//**
**
** AddReqPathRes_ResolvedPathResult
**
** Dynamically adds a resolved_path_result object to a requested_path_result object
**
** \param   req_path_result - pointer to requested_path_result to add this entry to
** \param   obj_path - data model path of the object to add to the map
**
** \return  Pointer to dynamically allocated resolved_path_result
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__GetResp__ResolvedPathResult *AddReqPathRes_ResolvedPathResult(Usp__GetResp__RequestedPathResult *req_path_result, char *obj_path)
{
    Usp__GetResp__ResolvedPathResult *resolved_path_res_entry;

    int new_num;    // new number of entries in the result_params

    // Allocate memory to store the resolved_path_result entry
    resolved_path_res_entry = USP_MALLOC(sizeof(Usp__GetResp__ResolvedPathResult));
    usp__get_resp__resolved_path_result__init(resolved_path_res_entry);

    // Increase the size of the vector containing pointers to the map entries
    new_num = req_path_result->n_resolved_path_results + 1;
    req_path_result->resolved_path_results = USP_REALLOC(req_path_result->resolved_path_results, new_num*sizeof(void *));
    req_path_result->n_resolved_path_results = new_num;
    req_path_result->resolved_path_results[new_num-1] = resolved_path_res_entry;

    // Initialise the resolved_path_result
    resolved_path_res_entry->resolved_path = USP_STRDUP(obj_path);
    resolved_path_res_entry->n_result_params = 0;
    resolved_path_res_entry->result_params = NULL;

    return resolved_path_res_entry;
}

/*********************************************************************//**
**
** AddResolvedPathRes_ParamsEntry
**
** Dynamically adds a result_params entry to a resolved_path_result object
**
** \param   resolved_path_res - pointer to resolved_oath_result to add this entry to
** \param   param_name - name of the parameter (not including object path) of the parameter to add to the map
** \param   value - value of the parameter
**
** \return  Pointer to dynamically allocated result_params
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
Usp__GetResp__ResolvedPathResult__ResultParamsEntry *
AddResolvedPathRes_ParamsEntry(Usp__GetResp__ResolvedPathResult *resolved_path_res, char *param_name, char *value)
{
    Usp__GetResp__ResolvedPathResult__ResultParamsEntry *res_params_entry;

    int new_num;    // new number of entries in the result_params

    // Allocate memory to store the result_params entry
    res_params_entry = USP_MALLOC(sizeof(Usp__GetResp__ResolvedPathResult__ResultParamsEntry));
    usp__get_resp__resolved_path_result__result_params_entry__init(res_params_entry);

    // Increase the size of the vector containing pointers to the map entries
    new_num = resolved_path_res->n_result_params + 1;
    resolved_path_res->result_params = USP_REALLOC(resolved_path_res->result_params, new_num*sizeof(void *));
    resolved_path_res->n_result_params = new_num;
    resolved_path_res->result_params[new_num-1] = res_params_entry;

    // Initialise the result_params_entry
    res_params_entry->key = USP_STRDUP(param_name);
    res_params_entry->value = USP_STRDUP(value);

    return res_params_entry;
}

/*********************************************************************//**
**
** Frees all memory assocaited with the current (last) Requested Path Result
** and removes it from response object
**
** \param   resp - pointer to GetResponse object
** \param   expected_req_path_result - pointer to requested_path_result to delete (This is used purely for checking that the code is correct)
**
** \return  None
**
**************************************************************************/
void DestroyCurReqPathResult(Usp__Msg *resp, Usp__GetResp__RequestedPathResult *expected_req_path_result)
{
    int i;
    Usp__GetResp *get_resp;
    Usp__GetResp__RequestedPathResult *req_path_result;
    Usp__GetResp__ResolvedPathResult *resolved_path_res_entry;

    // Remove the last requested path result from the list array
    get_resp = resp->body->response->get_resp;
    req_path_result = get_resp->req_path_results[ get_resp->n_req_path_results - 1];
    USP_ASSERT(expected_req_path_result == req_path_result);
    get_resp->req_path_results[ get_resp->n_req_path_results - 1] = NULL;
    get_resp->n_req_path_results--;

    // Iterate over all resolved path results for this requested path result
    for (i=0; i < req_path_result->n_resolved_path_results; i++)
    {
        resolved_path_res_entry = req_path_result->resolved_path_results[i];
        DestroyResolvedPathResult(resolved_path_res_entry);
    }

    // Destroy the requested path result itself
    USP_FREE(req_path_result->resolved_path_results);
    USP_FREE(req_path_result->err_msg);
    USP_FREE(req_path_result->requested_path);
    USP_FREE(req_path_result);
}

/*********************************************************************//**
**
** Destroys the specified Resolved Path Result
**
** \param   resolved_path_res_entry - Resolved path result to destroy
**
** \return  None
**
**************************************************************************/
void DestroyResolvedPathResult(Usp__GetResp__ResolvedPathResult *resolved_path_res_entry)
{
    int i;
    Usp__GetResp__ResolvedPathResult__ResultParamsEntry *res_params_entry;

    // Iterate over all result param map entries, destroying them
    for (i=0; i<resolved_path_res_entry->n_result_params; i++)
    {
        res_params_entry = resolved_path_res_entry->result_params[i];
        USP_FREE(res_params_entry->key);
        USP_FREE(res_params_entry->value);
        USP_FREE(res_params_entry);
    }

    // Destroy the Resolved Path Result Entry
    USP_FREE(resolved_path_res_entry->resolved_path);
    USP_FREE(resolved_path_res_entry->result_params);
    USP_FREE(resolved_path_res_entry);
}


























