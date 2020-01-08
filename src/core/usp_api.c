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
 * \file usp_api.c
 *
 * Implements the API exposed to the vendor
 * In many cases these functions are just a facade around internal core functionality
 *
 */

#include "common_defs.h"
#include "data_model.h"
#include "usp_api.h"
#include "iso8601.h"
#include "os_utils.h"
#include "device.h"

/*********************************************************************//**
**
** USP_DM_GetParameterValue
**
** Gets a single named parameter from the data model
** Wrapper function around data model API, that ensures the function is only called from the data model thread
**
** \param   path - pointer to string containing complete data model path to the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_DM_GetParameterValue(char *path, char *buf, int len)
{
    // Exit if this function is not being called from the data model thread
    if (OS_UTILS_IsDataModelThread(__FUNCTION__, PRINT_WARNING)==false)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    return DATA_MODEL_GetParameterValue(path, buf, len, 0);
}

/*********************************************************************//**
**
** USP_DM_SetParameterValue
**
** Sets a single named parameter in the data model
** Wrapper function around data model API, that ensures the function is only called from the data model thread
**
** \param   path - pointer to string containing complete path
** \param   new_value - pointer to buffer containing value to set
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_DM_SetParameterValue(char *path, char *new_value)
{
    // Exit if this function is not being called from the data model thread
    if (OS_UTILS_IsDataModelThread(__FUNCTION__, PRINT_WARNING)==false)
    {
        return USP_ERR_INTERNAL_ERROR;
    }
    
    return DATA_MODEL_SetParameterValue(path, new_value, 0);
}

/*********************************************************************//**
**
** USP_DM_DeleteInstance
**
** Deletes the specified instance from the data model
** Wrapper function around data model API, that ensures the function is only called from the data model thread
**
** \param   path - path of the object instance to delete
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_DM_DeleteInstance(char *path)
{
    // Exit if this function is not being called from the data model thread
    if (OS_UTILS_IsDataModelThread(__FUNCTION__, PRINT_WARNING)==false)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    return DATA_MODEL_DeleteInstance(path, IGNORE_NO_INSTANCE);
}

/*********************************************************************//**
**
** USP_DM_InformInstance
**
** Synchronously notifies USP Agent core that a vendor controlled object is present
** This function should only be called from the data model thread.
** Typically this function is called at startup from VENDOR_Start() to seed the data model with vendor object instances
**
** \param   path - path of the object instance to delete
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_DM_InformInstance(char *path)
{
    // Exit if this function is not being called from the data model thread
    if (OS_UTILS_IsDataModelThread(__FUNCTION__, PRINT_WARNING)==false)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    return DATA_MODEL_NotifyInstanceAdded(path);
}

/*********************************************************************//**
**
** USP_DM_GetInstances
**
** Gets a vector of instance numbers for the specified object
** Wrapper function around data model API, that ensures the function is only called from the data model thread
**
** \param   path - path of the object
** \param   iv - pointer to structure in which to return the instance numbers
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_DM_GetInstances(char *path, int_vector_t *iv)
{
    // Exit if this function is not being called from the data model thread
    if (OS_UTILS_IsDataModelThread(__FUNCTION__, PRINT_WARNING)==false)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    return DATA_MODEL_GetInstances(path, iv);
}

/*********************************************************************//**
**
** USP_ARG_Create
**
** Dynamically allocates a key-value pair structure and initialises it
**
** \param   kvv - pointer to structure to initialise
**
** \return  None
**
**************************************************************************/
kv_vector_t *USP_ARG_Create(void)
{
    kv_vector_t *kvv;
    kvv = USP_MALLOC(sizeof(kv_vector_t));
    KV_VECTOR_Init(kvv);

    return kvv;
}

/*********************************************************************//**
**
** USP_ARG_Init
**
** Initialises a key-value pair vector structure
**
** \param   kvv - pointer to structure to initialise
**
** \return  None
**
**************************************************************************/
void USP_ARG_Init(kv_vector_t *kvv)
{
    KV_VECTOR_Init(kvv);
}

/*********************************************************************//**
**
** USP_ARG_Add
**
** Adds a key value pair into the vector, where the value is specified as a string
**
** \param   kvv - pointer to structure to add the string to
** \param   key - pointer to string to copy
** \param   value - pointer to string to copy
**
** \return  None
**
**************************************************************************/
void USP_ARG_Add(kv_vector_t *kvv, char *key, char *value)
{
    KV_VECTOR_Add(kvv, key, value);
}

/*********************************************************************//**
**
** USP_ARG_AddUnsigned
**
** Adds a key value pair into the vector, where the value is specified as an unsigned number
**
** \param   kvv - pointer to structure to add the string to
** \param   key - pointer to string to copy
** \param   value - value to convert to a string and add to the vector
**
** \return  None
**
**************************************************************************/
void USP_ARG_AddUnsigned(kv_vector_t *kvv, char *key, unsigned value)
{
    KV_VECTOR_AddUnsigned(kvv, key, value);
}

/*********************************************************************//**
**
** USP_ARG_AddBool
**
** Adds a key value pair into the vector, where the value is specified as a boolean
**
** \param   kvv - pointer to structure to add the string to
** \param   key - pointer to string to copy
** \param   value - value to convert to a string and add to the vector
**
** \return  None
**
**************************************************************************/
void USP_ARG_AddBool(kv_vector_t *kvv, char *key, bool value)
{
    KV_VECTOR_AddBool(kvv, key, value);
}

/*********************************************************************//**
**
** USP_ARG_AddDateTime
**
** Adds a key value pair into the vector, where the value is specified as a date-time
**
** \param   kvv - pointer to structure to add the string to
** \param   key - pointer to string to copy
** \param   value - value to convert to a string and add to the vector
**
** \return  None
**
**************************************************************************/
void USP_ARG_AddDateTime(kv_vector_t *kvv, char *key, time_t value)
{
    KV_VECTOR_AddDateTime(kvv, key, value);
}

/*********************************************************************//**
**
** USP_ARG_Get
**
** Returns a pointer to the value associated with the specified key or the specified default value
**
** \param   kvv - pointer to key-value pair vector structure
** \param   key - pointer to name of key to get the value of
** \param   key - pointer to default value to return (this could be NULL if we want a return indicator that the key did not exist)
**
** \return  pointer to value
**
**************************************************************************/
char *USP_ARG_Get(kv_vector_t *kvv, char *key, char *default_value)
{
    return KV_VECTOR_Get(kvv, key, default_value, 0);
}

/*********************************************************************//**
**
** USP_ARG_GetUnsigned
**
** Gets the value of the specified parameter from the vector as an unsigned integer
**
** \param   kvv - pointer to key-value pair vector structure
** \param   key - pointer to name of key to get the value of
** \param   default_value - default value, if not present in the vector
** \param   value - pointer to variable in which to return the value 
**
** \return  USP_ERR_OK if successful
**          USP_ERR_INVALID_TYPE if unable to convert the key's value (given in the vector) to an unsigned integer
**
**************************************************************************/
int USP_ARG_GetUnsigned(kv_vector_t *kvv, char *key, unsigned default_value, unsigned *value)
{
    return KV_VECTOR_GetUnsigned(kvv, key, default_value, value);
}

/*********************************************************************//**
**
** USP_ARG_GetUnsignedWihinRange
**
** Gets the value of the specified parameter from the vector as an unsigned integer,
** checking that it is within the specified range
**
** \param   kvv - pointer to key-value pair vector structure
** \param   key - pointer to name of key to get the value of
** \param   default_value - default value, if not present in the vector
** \param   min - minimum allowed value
** \param   min - maximum allowed value
** \param   value - pointer to variable in which to return the value 
**
** \return  USP_ERR_OK if successful
**          USP_ERR_INVALID_TYPE if unable to convert the key's value (given in the vector) to an unsigned integer
**          USP_ERR_INVALID_VALUE if value is out of range
**
**************************************************************************/
int USP_ARG_GetUnsignedWithinRange(kv_vector_t *kvv, char *key, unsigned default_value, unsigned min, unsigned max, unsigned *value)
{
    return KV_VECTOR_GetUnsignedWithinRange(kvv, key, default_value, min, max, value);
}

/*********************************************************************//**
**
** USP_ARG_GetBool
**
** Gets the value of the specified parameter from the vector as a bool
**
** \param   kvv - pointer to key-value pair vector structure
** \param   key - pointer to name of key to get the value of
** \param   default_value - default value, if not present in the vector
** \param   value - pointer to variable in which to return the value 
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_ARG_GetBool(kv_vector_t *kvv, char *key, bool default_value, bool *value)
{
    return KV_VECTOR_GetBool(kvv, key, default_value, value);
}

/*********************************************************************//**
**
** USP_ARG_GetDateTime
**
** Gets the value of the specified parameter from the vector as a time_t
**
** \param   kvv - pointer to key-value pair vector structure
** \param   key - pointer to name of key to get the value of
** \param   default_value - default value, if not present in the vector
** \param   value - pointer to variable in which to return the value
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_ARG_GetDateTime(kv_vector_t *kvv, char *key, char *default_value, time_t *value)
{
    return KV_VECTOR_GetDateTime(kvv, key, default_value, value);
}

/*********************************************************************//**
**
** USP_ARG_Destroy
**
** Deallocates all memory associated with the key-value pair vector
** This is the opposite of USP_ARG_Create()
**
** \param   kvv - pointer to structure to destroy all dynmically allocated memory it contains
**
** \return  None
**
**************************************************************************/
void USP_ARG_Destroy(kv_vector_t *kvv)
{
    KV_VECTOR_Destroy(kvv);
}

/*********************************************************************//**
**
** USP_CONVERT_DateTimeToUnixTime
**
** Converts an ISO8601 string time into a UTC-based unix time
**
** \param   date - pointer to ISO8601 string to convert
**          
** \return  Number of seconds since the UTC unix epoch, or INVALID_TIME if the conversion failed
**
**************************************************************************/
time_t USP_CONVERT_DateTimeToUnixTime(char *date)
{
    return iso8601_to_unix_time(date);
}

/*********************************************************************//**
**
** USP_CONVERT_UnixTimeToDateTime
**
** Given a time_t converts it to an ISO8601 string
**
** \param   unix_time - time in seconds since the epoch (UTC)
** \param   buf - pointer to buffer in which to return the string
** \param   len - length of buffer. Must be at least MAX_ISO8601_LEN bytes long.
**
** \return  pointer to string (i.e. supplied buffer). This is useful if this function is called within a printf()
**
**************************************************************************/
char *USP_CONVERT_UnixTimeToDateTime(time_t unix_time, char *buf, int len)
{
    return iso8601_from_unix_time(unix_time, buf, len);
}

/*********************************************************************//**
**
** USP_DM_RegisterRoleName
**
** Sets the name of a role
**
** \param   role - role to which we want to assign a name
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_DM_RegisterRoleName(ctrust_role_t role, char *name)
{
    // Exit if role is out of bounds
    if ((role < kCTrustRole_Min) || (role >= kCTrustRole_Max))
    {
        USP_ERR_SetMessage("%s: Supplied role (%d) is out of bounds (expected < %d)", __FUNCTION__, role, kCTrustRole_Max);
        return USP_ERR_INTERNAL_ERROR;
    }

    DEVICE_CTRUST_RegisterRoleName(role, name);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** USP_DM_AddControllerTrustPermission
**
** Adds additional permissions for the specified role and data model nodes
**
** \param   role - role whose data model permissions are being changed
** \param   path - pointer to path expression specifying which data model nodes are modified
**                 Currently this only supports partial paths, full paths and wildcards
** \param   permission_bitmask - bitmask of permissions to apply to the data model nodes
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int USP_DM_AddControllerTrustPermission(ctrust_role_t role, char *path, unsigned short permission_bitmask)
{
    char schema_path[MAX_DM_PATH];
    char *in;
    char *out;
    dm_node_t *node;
    dm_instances_t inst;    // Discarded (it will contain all '1', since wildcards are replaced with '1')
    bool is_qualified_instance; // Discarded
    
    // Exit if role is out of bounds
    if ((role < kCTrustRole_Min) || (role >= kCTrustRole_Max))
    {
        USP_ERR_SetMessage("%s: Supplied role (%d) is out of bounds (expected < %d)", __FUNCTION__, role, kCTrustRole_Max);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Convert the data model path to an instantiated path that can be searched by replacing wildcards with '1'
    // NOTE: This is a bit of a hack, because we do not have a function that finds a schema path
    // Instead we do have a function that finds an instantiated path, but does not check the instance numbers
    in = path;
    out = schema_path;
    while (*in != '\0')
    {
        if (*in == '*')
        {
            *out++ = '1';
        }
        else
        {
            *out++ = *in;
        }

        // Mve to next character in path
        in++;
    }
    *out = '\0';    // Zero terminate the schema path

    // Exit if path is not a data model path
    node =  DM_PRIV_GetNodeFromPath(schema_path, &inst, &is_qualified_instance);
    if (node == NULL)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // Apply the permissions
    DM_PRIV_ApplyPermissions(node, role, permission_bitmask);

    // Add the permissions used to the permissions table
    return DEVICE_CTRUST_AddPermissions(role, path, permission_bitmask);
}

/*********************************************************************//**
**
** USP_HOOK_DenyAddInstance
**
** Callback that must be registered for read only tables, to prevent a controller from creating entries in the table
** NOTE: If this exact callback is not registered, then GetSupportedDM may incorrectly report that the object is read-write
**
** \param   req - pointer to structure containing path information
**
** \return  USP_ERR_OBJECT_NOT_CREATABLE always
**
**************************************************************************/
int USP_HOOK_DenyAddInstance(dm_req_t *req)
{
    USP_ERR_SetMessage("%s: Cannot add instances to a read only table", __FUNCTION__);
    return USP_ERR_OBJECT_NOT_CREATABLE;
}

/*********************************************************************//**
**
** USP_HOOK_DenyDeleteInstance
**
** Callback that must be registered for read only tables, to prevent a controller from deleting entries from the table
** NOTE: If this exact callback is not registered, then GetSupportedDM may incorrectly report that the object is read-write
**
** \param   req - pointer to structure containing path information
**
** \return  USP_EUSP_ERR_OBJECT_NOT_DELETABLE always
**
**************************************************************************/
int USP_HOOK_DenyDeleteInstance(dm_req_t *req)
{
    USP_ERR_SetMessage("%s: Cannot delete instances from a read only table", __FUNCTION__);
    return USP_ERR_OBJECT_NOT_DELETABLE;
}

