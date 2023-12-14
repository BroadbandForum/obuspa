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
 * \file msg_utils.c
 *
 * Common message handling utility functions called from multiple locations
 *
 */

#include "common_defs.h"
#include "msg_utils.h"
#include "text_utils.h"

#if !defined(REMOVE_USP_BROKER) || !defined(REMOVE_USP_SERVICE)
//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
int CalcFailureIndex(Usp__Msg *resp, kv_vector_t *params, int *modified_err);
bool CheckSetResponse_OperSuccess(Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationSuccess *oper_success, kv_vector_t *params);
void LogSetResponse_OperFailure(Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationFailure *oper_failure);
Usp__Set__UpdateObject *FindUpdateObject(Usp__Set *set, char *obj_path);
Usp__Set__UpdateObject *AddSetReq_UpdateObject(Usp__Set *set, char *obj_path);
Usp__Set__UpdateParamSetting *AddUpdateObject_ParamSettings(Usp__Set__UpdateObject *update_object, char *param_name, char *value);

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
** MSG_UTILS_ProcessSetResponse
**
** Processes a Set Response that we have received from a USP Service
**
** \param   resp - USP response message in protobuf-c structure
** \param   params - key-value vector containing the parameter names as keys and the parameter values as values
** \param   failure_index - pointer to value in which to return the index of the first parameter in the params vector
**                          that failed to be set. This value is only consulted if an error is returned.
**                          Setting it to INVALID indicates that all parameters failed (e.g. communications failure)
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int MSG_UTILS_ProcessSetResponse(Usp__Msg *resp, kv_vector_t *params, int *failure_index)
{
    int i;
    int err;
    Usp__SetResp *set;
    Usp__SetResp__UpdatedObjectResult *obj_result;
    Usp__SetResp__UpdatedObjectResult__OperationStatus *oper_status;
    bool is_success = false;

    // Default to indicating that all parameters failed
    *failure_index = INVALID;

    // Exit if the Message body contained an Error response, or the response failed to validate
    err = MSG_UTILS_ValidateUspResponse(resp, USP__RESPONSE__RESP_TYPE_SET_RESP, NULL);
    if (err != USP_ERR_OK)
    {
        *failure_index = CalcFailureIndex(resp, params, &err);
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
                // Check that the parameters and values reported as being set, match the ones we requested
                // NOTE: This code does not verify that we got a success response for EVERY param that we requested, only that the ones indicated in the response were ones we requested
                is_success = CheckSetResponse_OperSuccess(oper_status->oper_success, params);
                break;

            case USP__SET_RESP__UPDATED_OBJECT_RESULT__OPERATION_STATUS__OPER_STATUS_OPER_FAILURE:
                // Log all failures. NOTE: We should have received an Error response instead, if the USP Service was implemented correctly
                is_success = false;
                LogSetResponse_OperFailure(oper_status->oper_failure);
                break;

            default:
                TERMINATE_BAD_CASE(oper_status->oper_status_case);
                break;
        }
    }

    err = (is_success) ? USP_ERR_OK : USP_ERR_INTERNAL_ERROR;

    return err;
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
** CalcFailureIndex
**
** Calculates the index of the first parameter found that failed to set
**
** \param   resp - USP response message in protobuf-c structure
** \param   params - key-value vector containing the parameter names as keys and the parameter values as values
** \param   modified_err - pointer to error code to modify with the more specific error given for the first parameter which failed (if available)
**
** \return  index of the first parameter in the params vector that failed to be set
**          INVALID indicates that all parameters failed or that we do not know which parameter failed first
**
**************************************************************************/
int CalcFailureIndex(Usp__Msg *resp, kv_vector_t *params, int *modified_err)
{
    int i;
    Usp__Error *err_obj;
    int index;
    int lowest_index;
    char *path;
    int first_err;       // This is the error code given for the first parameter that failed, which may be different than the holistic error for all of the params that failed

    // Exit if cause of error was something other than an error response
    if ((resp->body == NULL) || (resp->body->msg_body_case != USP__BODY__MSG_BODY_ERROR) || (resp->body->error == NULL))
    {
        return INVALID;
    }

    // Exit if the Error response does not contain details of which parameter(s) were in error
    err_obj = resp->body->error;
    if ((err_obj->n_param_errs == 0) || (err_obj->param_errs == NULL))
    {
        return INVALID;
    }

    // Iterate over all parameters in error, finding the first one in the list of parameters to set, that failed
    lowest_index = INT_MAX;
    first_err = *modified_err;
    for (i=0; i< err_obj->n_param_errs; i++)
    {
        path = err_obj->param_errs[i]->param_path;
        index = KV_VECTOR_FindKey(params, path, 0);
        if (index < lowest_index)
        {
            lowest_index = index;
            first_err = err_obj->param_errs[i]->err_code;
        }
    }

    // Exit if none of the parameters in the error matched those that we were trying to set
    // NOTE: This should never happen, because we expect that at least one of the params in error was one that we were trying to set
    if (lowest_index == INT_MAX)
    {
        return INVALID;
    }

    // Return the index of the first parameter which failed, and it's associated, more specific, error code
    *modified_err = first_err;
    return lowest_index;
}


/*********************************************************************//**
**
** CheckSetResponse_OperSuccess
**
** Checks the OperSucces object in the SetResponse, ensuring that the parameters were set to the expected values
**
** \param   oper_success - OperSuccess object to check
** \param   params - key-value vector containing the parameters (and values) that we expected to be set
**
** \return  true if no errors were detected in the set response
**
**************************************************************************/
bool CheckSetResponse_OperSuccess(Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationSuccess *oper_success, kv_vector_t *params)
{
    int i, j;
    Usp__SetResp__UpdatedInstanceResult *updated_inst_result;
    Usp__SetResp__UpdatedInstanceResult__UpdatedParamsEntry *updated_param;
    Usp__SetResp__ParameterError *param_err;
    char path[MAX_DM_PATH];
    bool is_success = true;
    int index;
    char *expected_value;

    for (i=0; i < oper_success->n_updated_inst_results; i++)
    {
        updated_inst_result = oper_success->updated_inst_results[i];

        // Log all errors (for non-required parameters)
        // NOTE: We should not get any of these, as we marked all params as required in the request
        for (j=0; j < updated_inst_result->n_param_errs; j++)
        {
            param_err = updated_inst_result->param_errs[j];
            USP_ERR_SetMessage("%s: SetResponse returned err=%d for param=%s%s but should have returned ERROR Response", __FUNCTION__, param_err->err_code, updated_inst_result->affected_path, param_err->param);
            is_success = false;
        }

        // Check that the USP Service hasn't set the wrong value for any params
        for (j=0; j < updated_inst_result->n_updated_params; j++)
        {
            updated_param = updated_inst_result->updated_params[j];
            USP_SNPRINTF(path, sizeof(path), "%s%s", updated_inst_result->affected_path, updated_param->key);

            // Skip if this param was not one we requested to be set
            index = KV_VECTOR_FindKey(params, path, 0);
            if (index == INVALID)
            {
                USP_ERR_SetMessage("%s: SetResponse contained a success entry for param=%s but we never requested it to be set", __FUNCTION__, path);
                is_success = false;
                continue;
            }

            // Check that the parameter was set to the expected value
            expected_value = params->vector[index].value;
            if (strcmp(expected_value, updated_param->value) != 0)
            {
                USP_ERR_SetMessage("%s: SetResponse contained the wrong value for param=%s (expected='%s', got='%s')", __FUNCTION__, path, expected_value, updated_param->key);
                is_success = false;
            }
        }
    }

    return is_success;
}


/*********************************************************************//**
**
** LogSetResponse_OperFailure
**
** Logs all errors indicated by an OperFailure object in the SetResponse
** NOTE: We do not expect any OperFailures, because allow_partial=false and all parameters are required to set
**       If any parameter failed to set, an ERROR response would have been received instead
**
** \param   oper_failure - OperFailure object to og all errors from
**
** \return  None
**
**************************************************************************/
void LogSetResponse_OperFailure(Usp__SetResp__UpdatedObjectResult__OperationStatus__OperationFailure *oper_failure)
{
    int i, j;
    Usp__SetResp__UpdatedInstanceFailure *updated_inst_failure;
    Usp__SetResp__ParameterError *param_err;

    for (i=0; i < oper_failure->n_updated_inst_failures; i++)
    {
        updated_inst_failure = oper_failure->updated_inst_failures[i];
        for (j=0; j < updated_inst_failure->n_param_errs; j++)
        {
            param_err = updated_inst_failure->param_errs[j];
            USP_LOG_Error("%s: SetResponse returned err=%d for param=%s%s but should have returned ERROR Response", __FUNCTION__, param_err->err_code, updated_inst_failure->affected_path, param_err->param);
        }
    }
}

#endif // !defined(REMOVE_USP_BROKER) || !defined(REMOVE_USP_SERVICE)
