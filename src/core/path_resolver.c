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
 * \file path_resolver.c
 *
 * Resolves path expressions into individual parameters or objects which exist in the data model
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "common_defs.h"
#include "data_model.h"
#include "dm_inst_vector.h"
#include "path_resolver.h"
#include "dm_access.h"
#include "kv_vector.h"
#include "expr_vector.h"
#include "text_utils.h"


//-------------------------------------------------------------------------
// State variable associated with the resolver. This is passed to all recursive resolver functions
typedef struct
{
    str_vector_t *sv;       // pointer to string vector to return the resolved paths in
                            // or NULL if we are only interested in whether the expression exists in the schema
    resolve_op_t op;        // operation being performed that requires path resolution
    int separator_count;    // Count of the number of separators before the last resolved part of the path
    combined_role_t *combined_role;  // pointer to role to use when performing the path resolution.
                            // If the search path resolves to an object or param which there is no permission for,
                            // then a error will be generated (or the path forgivingly ignored in the case of a get)
    unsigned flags;         // flags controlling resolving of the path eg GET_ALL_INSTANCES
} resolver_state_t;

//-------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
int ExpandPath(char *resolved, char *unresolved, resolver_state_t *state);
int ExpandWildcard(char *resolved, char *unresolved, resolver_state_t *state);
int ResolveReferenceFollow(char *resolved, char *unresolved, resolver_state_t *state);
int ResolveUniqueKey(char *resolved, char *unresolved, resolver_state_t *state);
int DoesInstanceMatchUniqueKey(char *object, int instance, expr_vector_t *keys, bool *is_match, resolver_state_t *state);
int ResolvePartialPath(char *path, resolver_state_t *state);
int GetChildParams(char *path, int path_len, dm_node_t *node, dm_instances_t *inst, resolver_state_t *state);
int GetChildParams_MultiInstanceObject(char *path, int path_len, dm_node_t *node, dm_instances_t *inst, resolver_state_t *state);
int DoesInstanceMatchExpr(char *object, int instance, char *expr_variable, resolver_state_t *state, bool *is_match);
int AddPathFound(char *path, resolver_state_t *state);
int CountPathSeparator(char *path);
int ExpandNextSubPath(char *resolved, char *unresolved, resolver_state_t *state);
int CheckPathProperties(char *path, resolver_state_t *state, bool *add_to_vector, unsigned *path_properties);

/*********************************************************************//**
**
** PATH_RESOLVER_ResolveDevicePath
**
** Wrapper around PATH_RESOLVER_ResolvePath() which ensures that the path starts with 'Device.'
** This function therefore does not allow querying of 'Internal.' database parameters
** This function should be used by all USP protocol message handlers (since 'Internal.' is not exposed to controllers)
** However CLI commands can directly use PATH_RESOLVER_ResolvePath()
**
** \param   path - pointer to path expression identifying parameters in the data model
** \param   sv - pointer to string vector to return the resolved paths in
**               or NULL if we are only interested in whether the expression exists in the schema
**               NOTE: As this function can be used to append to a string vector, it does not initialise
**                     the vector, so the caller must initialise the vector.
**                     Also, the caller must destroy the vector, even if an error is returned
** \param   op - operation being performed that requires path resolution
** \param   separator_split - pointer to variable in which to return where to split the resolved paths
**                            This argument is used to split a path into an object (that required resolution),
**                            and a sub path which did not require resolution
**                            NOTE: This argument may be NULL if the caller is not interested in the value
** \param   combined_role - role to use when performing the resolution. If set to INTERNAL_ROLE, then permissions are ignored (used internally)
*  \param   flags - flags controlling resolving of the path eg GET_ALL_INSTANCES
**
** \return  USP_ERR_OK if successful, or no instances found
**
**************************************************************************/
int PATH_RESOLVER_ResolveDevicePath(char *path, str_vector_t *sv, resolve_op_t op, int *separator_split, combined_role_t *combined_role, unsigned flags)
{
    int err;
    int len;

    // Exit if the path does not begin with "Device."
    #define DEVICE_ROOT_STR "Device."
    if (strncmp(path, DEVICE_ROOT_STR, sizeof(DEVICE_ROOT_STR)-1) != 0)
    {
        USP_ERR_SetMessage("%s: Expression does not start in '%s'", __FUNCTION__, DEVICE_ROOT_STR);
        return USP_ERR_INVALID_PATH;
    }

    // Perform checks on whether the path is terminated correctly (by '.' or not)
    len = strlen(path);
    if (path[len-1] == '.')
    {
        // Path ends in '.'
        // Exit if the path should not end in '.'
        if ((op==kResolveOp_Oper) || (op==kResolveOp_Event))
        {
            USP_ERR_SetMessage("%s: Path should not end in '.'", __FUNCTION__);
            return USP_ERR_INVALID_PATH_SYNTAX;
        }
    }
    else
    {
        // Path does not end in '.'
        // Exit if the path should end in '.'
        if ((op==kResolveOp_Del) || (op==kResolveOp_Instances))
        {
            USP_ERR_SetMessage("%s: Path must end in '.'", __FUNCTION__);
            return USP_ERR_INVALID_PATH_SYNTAX;
        }
    }

    err = PATH_RESOLVER_ResolvePath(path, sv, op, separator_split, combined_role, flags);
    return err;
}

/*********************************************************************//**
**
** PATH_RESOLVER_ResolvePath
**
** Resolves the specified path expression into a vector of parameter paths which exist in the data model
** Resolution involves resolving wildcarded, key based addressing, reference following and expression based searching based expressions
** Resolution takes account of permissions, potentially failing the resolution if sufficient permissions are not available for the specified role
** NOTE: The string vector is assumed to be initialised before this function is called, allowing this function to append to the list
**
** \param   path - pointer to path expression identifying parameters in the data model
** \param   sv - pointer to string vector to return the resolved paths in
**               or NULL if we are only interested in whether the expression exists in the schema
**               NOTE: As this function can be used to append to a string vector, it does not initialise
**                     the vector, so the caller must initialise the vector.
**                     Also, the caller must destroy the vector, even if an error is returned
** \param   op - operation being performed that requires path resolution
** \param   separator_split - pointer to variable in which to return where to split the resolved paths
**                            This argument is used to split a path into an object (that required resolution),
**                            and a sub path which did not require resolution
**                            NOTE: This argument may be NULL if the caller is not interested in the value
** \param   combined_role - role to use when performing the resolution
*  \param   flags - flags controlling resolving of the path eg GET_ALL_INSTANCES
**
** \return  USP_ERR_OK if successful, or no instances found
**
**************************************************************************/
int PATH_RESOLVER_ResolvePath(char *path, str_vector_t *sv, resolve_op_t op, int *separator_split, combined_role_t *combined_role, unsigned flags)
{
    char resolved[MAX_DM_PATH];
    char unresolved[MAX_DM_PATH];
    int err;
    resolver_state_t state;

    // Exit if path contains any path separators with no intervening objects 
    if (strstr(path, "..") != NULL)
    {
        USP_ERR_SetMessage("%s: Path should not contain '..'", __FUNCTION__);
        return USP_ERR_INVALID_PATH_SYNTAX;
    }
    
    // Take a copy of the path expression, so that the code below may alter the unresolved buffer
    USP_STRNCPY(unresolved, path, sizeof(unresolved));

    // Set up state variables for resolving the path, then resolve it
    resolved[0] = '\0';  // Start from an empty string for the resolved portion of the path
    state.sv = sv;
    state.op = op;
    state.separator_count = 0;
    state.combined_role = combined_role;
    state.flags = flags;

    err = ExpandPath(resolved, unresolved, &state);

    // Return the point at which to split the path
    if (separator_split != NULL)
    {
        *separator_split = state.separator_count;
    }

    return err;
}

/*********************************************************************//**
**
** ExpandPath
**
** Iterates over all unresolved aspects of the path, resolving them into a path
** NOTE: This function is recursive
**
** \param   resolved - pointer to buffer containing data model path that has been resolved so far
** \param   unresolved - pointer to rest of search path to resolve
** \param   state - pointer to structure containing state variables to use with this resolution
**
** \return  USP_ERR_OK if successful, or no instances found
**
**************************************************************************/
int ExpandPath(char *resolved, char *unresolved, resolver_state_t *state)
{
    int len;
    int err;
    char c;

    // Exit if path is too long
    len = strlen(resolved);
    if (len >= MAX_DM_PATH-1)
    {
        USP_ERR_SetMessage("%s(%d): path expansion too long. Aborting at %s", __FUNCTION__, __LINE__, resolved);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Then iterate over 'unresolved', appending to the buffer in 'resolved', until we hit one of the addressing operators (ie '*', '[', or '+')
    c = *unresolved;
    while (c != '\0')
    {
        // If hit a wildcard, handle it (and rest of unresolved), then exit
        if (c == '*')
        {
            resolved[len] = '\0';
            err = ExpandWildcard(resolved, &unresolved[1], state);
            return err;
        }

        // If hit a reference follow, handle it (and rest of unresolved), then exit
        if (c == '+')
        {
            resolved[len] = '\0';
            err = ResolveReferenceFollow(resolved, &unresolved[1], state);
            return err;
        }

        // If hit a unique key address, handle it (and rest of unresolved), then exit
        if (c == '[')
        {
            resolved[len] = '\0';
            err = ResolveUniqueKey(resolved, &unresolved[1], state);
            return err;
        }

        // Exit if unable to append any more characters to 'resolved'
        if (len >= MAX_DM_PATH-1)
        {
            resolved[len] = '\0';
            USP_ERR_SetMessage("%s(%d): path expansion too long. Aborting at %s", __FUNCTION__, __LINE__, resolved);
            return USP_ERR_INTERNAL_ERROR;
        }

        // Append this character to the path
        resolved[len++] = c;

        // Move to the next character
        unresolved++;
        c = *unresolved;
    }
    
    // If the code gets here, then we have finished parsing the search path
    // So turn it into a string
    resolved[len] = '\0';

    // Remove trailing '.' from the path
    if (resolved[len-1] == '.')
    {
        switch(state->op)
        {
            case kResolveOp_Get:
            case kResolveOp_SubsValChange:
            case kResolveOp_GetBulkData:
            case kResolveOp_SubsOper:
            case kResolveOp_SubsEvent:
                // These cases allow a partial path for parameters
                resolved[len-1] = '\0';
                err = ResolvePartialPath(resolved, state);
                return err;
                break;

            case kResolveOp_Add:
            case kResolveOp_Del:
            case kResolveOp_Set:
            case kResolveOp_Instances:
            case kResolveOp_SubsAdd:
            case kResolveOp_SubsDel:
            case kResolveOp_Any:
                // These cases do not process a partial path - just remove any trailing '.'
                resolved[len-1] = '\0';
                break;

            default:
            case kResolveOp_Oper:
            case kResolveOp_Event:
                // These cases should never occur (as code in PATH_RESOLVER_ResolveDevicePath prevents this case)
                USP_ASSERT(false);
                break;

        }
    }

    // Exit if an error occurred with this path, which halts further path resolution
    err = AddPathFound(resolved, state);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ExpandWildcard
**
** Expands the wildcard that exists inbetween 'resolved' and 'unresolved' parts of the path
** then reurses to resolve the rest of the path
** NOTE: This function is recursive
**
** \param   resolved - pointer to buffer containing object that we need to search all instances of
** \param   unresolved - pointer to rest of search path to resolve
** \param   state - pointer to structure containing state variables to use with this resolution
**
** \return  USP_ERR_OK if successful, or no instances found
**
**************************************************************************/
int ExpandWildcard(char *resolved, char *unresolved, resolver_state_t *state)
{
    int_vector_t iv;
    int i;
    int err;
    int len;
    int len_left;
    char *p;

    // Exit if unable to get the instances of this object
    err = DATA_MODEL_GetInstances(resolved, &iv);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if there are no instances of this object
    if (iv.num_entries == 0)
    {
        goto exit;
    }

    // Exit if no space left in the buffer to append the instance number
    len = strlen(resolved);
    len_left = MAX_DM_PATH - len;
    if (len_left < 2)       // 2 to include a single digit and NULL terminator
    {
        resolved[len] = '\0';
        USP_ERR_SetMessage("%s(%d): path expansion too long. Aborting at %s", __FUNCTION__, __LINE__, resolved);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Expand the wildcard and recurse to expand the unresolved part of the path
    p = &resolved[len];
    for (i=0; i < iv.num_entries; i++)
    {
        USP_SNPRINTF(p, len_left, "%d", iv.vector[i]);
        err = ExpandNextSubPath(resolved, unresolved, state);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }
    }

    err = USP_ERR_OK;

exit:
    INT_VECTOR_Destroy(&iv);
    return err;
}

/*********************************************************************//**
**
** ResolveReferenceFollow
**
** De-references the specified data model path, then recurses to resolve the rest of the path
** NOTE: This function is recursive
**
** \param   resolved - pointer to buffer containing data model path to de-reference
** \param   unresolved - pointer to rest of search path to resolve
** \param   state - pointer to structure containing state variables to use with this resolution
**
** \return  USP_ERR_OK if successful, or no instances found
**
**************************************************************************/
int ResolveReferenceFollow(char *resolved, char *unresolved, resolver_state_t *state)
{
    char dereferenced[MAX_DM_PATH];
    int err;
    unsigned flags;
    unsigned short permission_bitmask;

    // Exit if this is a Bulk Data collection operation, which does not allow reference following
    // (because the alt-name reduction rules in TR-157 do not support it)
    if (state->op == kResolveOp_GetBulkData)
    {
        USP_ERR_SetMessage("%s: Bulk Data collection does not allow reference following in search expressions", __FUNCTION__);
        return USP_ERR_INVALID_PATH_SYNTAX;
    }

    // Exit if unable to determine whether we are allowed to read the reference
    err = DATA_MODEL_GetPermissions(resolved, state->combined_role, &permission_bitmask);
    if (err != USP_ERR_OK)
    {
        return err;
    }
    
    // Exit if not permitted to read the reference
    if ((permission_bitmask & PERMIT_GET) == 0)
    {
        // Get operations are forgiving of permissions, so just give up further resolution here
        if ((state->op == kResolveOp_Get) || (state->op == kResolveOp_SubsValChange))
        {
            return USP_ERR_OK;
        }
    
        // Other operations are not forgiving, so return an error
        USP_ERR_SetMessage("%s: Not permitted to read reference follow %s", __FUNCTION__, resolved);
        return USP_ERR_PERMISSION_DENIED;
    }

    // Exit if unable to get the path for the dereferenced object    
    err = DATA_MODEL_GetParameterValue(resolved, dereferenced, sizeof(dereferenced), 0);
    if (err != USP_ERR_OK)
    {
        USP_ERR_SetMessage("%s: Unable to get the value of the dereferenced path contained in %s", __FUNCTION__, resolved);
        return err;
    }

    // Exit if the dereferenced path is not a fully qualified object
    // NOTE: We do not check permissions here, since there may be further parts of the path to resolve after this reference follow
    flags = DATA_MODEL_GetPathProperties(dereferenced, INTERNAL_ROLE, NULL);
    if ( ((flags & PP_IS_OBJECT) == 0) || ((flags & PP_IS_OBJECT_INSTANCE) ==0) )
    {
        USP_ERR_SetMessage("%s: The dereferenced path contained in %s was not an object instance (got the value '%s')", __FUNCTION__, resolved, dereferenced);
        return USP_ERR_INVALID_PATH_SYNTAX;
    }

    // Exit if the dereferenced path does not have instance numbers that exist
    // NOTE: On its own, this is not an error. A get parameter value is forgiving in this case.
    // Whilst a set parameter value will eventually fail because the path resolves to nothing
    // So we just don't recurse further down this path further.
    if ((flags & PP_INSTANCE_NUMBERS_EXIST) == 0)
    {
        return USP_ERR_OK;
    }

    // If the code gets here then the resolved path has been successfully dereferenced, 
    // so continue resolving the path, using the dereferened path
    err = ExpandNextSubPath(dereferenced, unresolved, state);

    return err;
}

/*********************************************************************//**
**
** ResolveUniqueKey
**
** Resolves the unique key
** NOTE: This function is recursive
**
** \param   resolved - pointer to data model object that we want to lookup by unique key
** \param   unresolved - pointer to unique key and rest of search path to resolve
** \param   state - pointer to structure containing state variables to use with this resolution
**
** \return  USP_ERR_OK if successful, or no instances found
**
**************************************************************************/
int ResolveUniqueKey(char *resolved, char *unresolved, resolver_state_t *state)
{
    str_vector_t key_expressions;
    expr_vector_t keys;
    int i;
    int err;
    char *p;
    int len;
    int_vector_t iv;
    char temp[MAX_DM_PATH];
    bool is_match;
    int instance;
    expr_op_t valid_ops[] = {kExprOp_Equal, kExprOp_NotEqual, kExprOp_LessThanOrEqual, kExprOp_GreaterThanOrEqual, kExprOp_LessThan, kExprOp_GreaterThan};

    // Exit if this is a Bulk Data collection operation, which does not allow unique key addressing
    // (because the alt-name reduction rules in TR-157 do not support it)
    if (state->op == kResolveOp_GetBulkData)
    {
        USP_ERR_SetMessage("%s: Bulk Data collection does not allow unique key addressing in search expressions", __FUNCTION__);
        return USP_ERR_INVALID_PATH_SYNTAX;
    }
    
    // Initialise vectors used by this function
    STR_VECTOR_Init(&key_expressions);
    EXPR_VECTOR_Init(&keys);

    // Exit if unable to get the instances of this object
    err = DATA_MODEL_GetInstances(resolved, &iv);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if there are no instances of this object
    if (iv.num_entries == 0)
    {
        err = USP_ERR_OK;
        goto exit;
    }

    // Exit if unable to find the end of the unique key
    p = strchr(unresolved, ']');
    if (p == NULL)
    {
        USP_ERR_SetMessage("%s: Unterminated Unique Key (%s) in search path", __FUNCTION__, unresolved);
        err = USP_ERR_INVALID_PATH_SYNTAX;
        goto exit;
    }

    // Exit if the unique key is too long
    len = p - unresolved;
    if (len > MAX_DM_PATH-1)
    {
        USP_ERR_SetMessage("%s: Unique Key too long (%s) in search path", __FUNCTION__, unresolved);
        err = USP_ERR_INVALID_PATH_SYNTAX;
        goto exit;
    }

    // Copy the unique key expressions (ie the expression within []) into temp
    memcpy(temp, unresolved, len);
    temp[len] = '\0';
    unresolved = &p[1];

    // If the code gets here, unresolved points to the character after ']', and temp contains the unique key expression

    // Exit if an error occurred whilst parsing the key expressions
    err = EXPR_VECTOR_SplitExpressions(temp, &keys, "&&", valid_ops, NUM_ELEM(valid_ops), EXPR_FROM_USP);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }
    
    // Exit if no key expressions were found
    if (keys.num_entries == 0)
    {
        USP_ERR_SetMessage("%s: No unique key found in search path before %s", __FUNCTION__, unresolved);
        err = USP_ERR_INVALID_PATH_SYNTAX;
        goto exit;
    }

    // Iterate over all instances of the object present in the data model
    for (i=0; i < iv.num_entries; i++)
    {
        // Exit if an error occurred whilst trying to determine whether this instance matched the unique key
        instance = iv.vector[i];
        err = DoesInstanceMatchUniqueKey(resolved, instance, &keys, &is_match, state);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }

        // If found an instance which matches, continue resolving the path recursively, selecting this instance
        if (is_match)
        {
            USP_SNPRINTF(temp, sizeof(temp), "%s%d", resolved, instance);
            err = ExpandNextSubPath(temp, unresolved, state);
            if (err != USP_ERR_OK)
            {
                goto exit;
            }
        }
    }

    // If the code gets here, then no matching unique key has been found
    // It is not a parse error to find no instances of an object.
    // The caller (USP message handler) will deal with the case of no objects found appropriately.
    err = USP_ERR_OK;

exit:
    // Ensure that the key expressions and key-values are deleted
    // NOTE: This is safe to do again here, even if they have already been deleted in the body of the function
    INT_VECTOR_Destroy(&iv);
    STR_VECTOR_Destroy(&key_expressions);
    EXPR_VECTOR_Destroy(&keys);
    return err;
}

/*********************************************************************//**
**
** ExpandNextSubPath
**
** Called after one part of the path has been resolved to update the separator
** count. This function, then continues resolution of the path.
** Iterates over all unresolved aspects of the path, resolving them into a path
** NOTE: This function is recursive
**
** \param   resolved - pointer to buffer containing data model path that has been resolved so far
** \param   unresolved - pointer to rest of search path to resolve
** \param   state - pointer to structure containing state variables to use with this resolution
**
** \return  USP_ERR_OK if successful, or no instances found
**
**************************************************************************/
int ExpandNextSubPath(char *resolved, char *unresolved, resolver_state_t *state)
{
    int err;
    int separator_count;
    
    // Determine the point at which the last resolution occurred in the path
    separator_count = CountPathSeparator(resolved) + 1;     // Plus 1 because we want to include the instance number that the caller has just resolved
    
    // Update the point at which the last resolution occurred in the path
    if (separator_count > state->separator_count)
    {
        state->separator_count = separator_count;
    }

    // Exit if an error occurred in resolving the path further
    err = ExpandPath(resolved, unresolved, state);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ResolvePartialPath
**
** Gets a vector of the full path names of all the child parameters of the specified object
** that are instantiated in the data model (ie partial path->param list)
** NOTE: This function does not take 'op' as a parameter (unlike the other resolve functions) because it is only applicable to get operations
**
** \param   path - path of the root object. NOTE: Must not include trailing '.' !
** \param   state - pointer to structure containing state variables to use with this resolution
**
** \return  USP_ERR_OK if successful, or no instances found
**
**************************************************************************/
int ResolvePartialPath(char *path, resolver_state_t *state)
{
    dm_instances_t inst;
    dm_node_t *node;
    bool exists;
    char child_path[MAX_DM_PATH];
    int len;
    int err;
    bool is_qualified_instance;
    int separator_count;

    // Exit if unable to find node representing this object
    node = DM_PRIV_GetNodeFromPath(path, &inst, &is_qualified_instance);
    if (node == NULL)
    {
        return USP_ERR_INVALID_PATH;
    }

    // Exit if this is not an object
    if (IsObject(node) == false)
    {
        USP_ERR_SetMessage("%s: Partial Path %s is not an object", __FUNCTION__, path);
        return USP_ERR_INVALID_PATH;
    }

    // Exit if the object instances in the path do not exist
    exists = DM_INST_VECTOR_IsExist(&inst);
    if (exists == false)
    {
        return USP_ERR_OK;
    }

    // Determine the point at which the last resolution occurred in the path, and update
    separator_count = CountPathSeparator(path) + 1; // Plus 1 to add back in the partial path trailing '.'
    if (separator_count > state->separator_count)
    {
        state->separator_count = separator_count;
    }

    len = strlen(path);
    USP_STRNCPY(child_path, path, sizeof(child_path));

    if (is_qualified_instance)
    {
        // Object is specified with trailing instance number or is a single instance object
        err = GetChildParams(child_path, len, node, &inst, state);
    }
    else
    {
        // Object is specified without trailing instance number
        USP_ASSERT(node->type == kDMNodeType_Object_MultiInstance); // SingleInstance objects should have (is_qualified_instance==true), and hence shouldn't have got here
        err = GetChildParams_MultiInstanceObject(child_path, len, node, &inst, state);
    }
    
    return err;
}

/*********************************************************************//**
**
** DoesInstanceMatchUniqueKey
**
** Determines whether the specified object instance matches the specified unique key
**
** \param   object - data model path of object to see if it matches the unique key
** \param   instance - instance number of the object to see if it matches the unique key
** \param   keys - vector of key expressions that specify the unique key
** \param   is_match - pointer to boolean in which to return whether this instance matched the unique key
** \param   state - pointer to structure containing state variables to use with this resolution
**
** \return  USP_ERR_OK if no errors occurred
**
**************************************************************************/
int DoesInstanceMatchUniqueKey(char *object, int instance, expr_vector_t *keys, bool *is_match, resolver_state_t *state)
{
    int err;
    int i;
    expr_comp_t *ec;
    char path[MAX_DM_PATH];
    bool result;
    unsigned short permission_bitmask;

    // Assume that this instance does not match
    *is_match = false;

    // Iterate over all key expressions to match, exiting on the first one which isn't true
    for (i=0; i < keys->num_entries; i++)
    {
        // Form parameter path of the unique key to check
        ec = &keys->vector[i];
        USP_SNPRINTF(path, sizeof(path), "%s%d.%s", object, instance, ec->param);

        // Exit if unable to determine whether we are allowed to read the unique key
        err = DATA_MODEL_GetPermissions(path, state->combined_role, &permission_bitmask);
        if (err != USP_ERR_OK)
        {
            return err;
        }
        
        // Exit if not permitted to read the parameter in the unique key
        if ((permission_bitmask & PERMIT_GET) == 0)
        {
            // Get operations are forgiving of permissions, so just give up further resolution here, 
            // returning that this instance does not match
            // NOTE: BulkData get operations are not forgiving of permissions, so will return an error
            if ((state->op == kResolveOp_Get) || (state->op == kResolveOp_SubsValChange))
            {
                return USP_ERR_OK;
            }
        
            // Other operations are not forgiving, so return an error
            USP_ERR_SetMessage("%s: Not permitted to read unique key %s", __FUNCTION__, path);
            return USP_ERR_PERMISSION_DENIED;
        }

        // Exit if unable to compare the value of the parameter in the expression
        err = DATA_MODEL_CompareParameterValue(path, ec->op, ec->value, &result);
        if (err != USP_ERR_OK)
        {
            return err;
        }

        // Exit if the unique key did not match the value we want
        if (result != true)
        {
            return USP_ERR_OK;
        }
    }

    // If the code gets here, then the instance matches all key expressions in the compound unique key
    *is_match = true;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetChildParams
**
** Adds the names of all instantiated child parameters of the specified node to the vector
** This function is called when processing a get using a partial path
** NOTE: This function is recursive
**
** \param   path - path of the object instance to get the child parameters of
** \param   path_len - length of path (position to append child node names)
** \param   node - Node to get children of
** \param   inst - pointer to instance structure locating the parent node
** \param   state - pointer to structure containing state variables to use with this resolution
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetChildParams(char *path, int path_len, dm_node_t *node, dm_instances_t *inst, resolver_state_t *state)
{
    int err;
    dm_node_t *child;
    unsigned short permission_bitmask;
    bool add_to_vector;
    
    // Iterate over list of children
    child = (dm_node_t *) node->child_nodes.head;
    while (child != NULL)
    {
        add_to_vector = false;
        switch(child->type)
        {
            // For single instance child object nodes, recurse to find all child parameters
            case kDMNodeType_Object_SingleInstance:
                {
                    int len;
                    len = USP_SNPRINTF(&path[path_len], MAX_DM_PATH-path_len, ".%s", child->name);
                    err = GetChildParams(path, path_len+len, child, inst, state);
                    if (err != USP_ERR_OK)
                    {
                        return err;
                    }
                }
                break;

            // For multi-instance child objects, ensure that all instances of all of their children are recursed into
            case kDMNodeType_Object_MultiInstance:
                {
                    int len;
                    len = USP_SNPRINTF(&path[path_len], MAX_DM_PATH-path_len, ".%s", child->name);
                    err = GetChildParams_MultiInstanceObject(path, path_len+len, child, inst, state);
                    if (err != USP_ERR_OK)
                    {
                        return err;
                    }
                }
                break;
                
            case kDMNodeType_DBParam_ReadOnly:
            case kDMNodeType_DBParam_ReadOnlyAuto:
            case kDMNodeType_DBParam_ReadWriteAuto:
            case kDMNodeType_VendorParam_ReadOnly:
            case kDMNodeType_VendorParam_ReadWrite:
            case kDMNodeType_Param_ConstantValue:
            case kDMNodeType_Param_NumEntries:
            case kDMNodeType_DBParam_ReadWrite:
            case kDMNodeType_DBParam_Secure:
                {
                    // Deal with GetBulkData operations
                    permission_bitmask = DM_PRIV_GetPermissions(child, state->combined_role);
                    if (state->op == kResolveOp_GetBulkData)
                    {
                        USP_SNPRINTF(&path[path_len], MAX_DM_PATH-path_len, ".%s", child->name);
                        if (permission_bitmask & PERMIT_GET)
                        {
                            add_to_vector = true;
                        }
                        else
                        {
                            // Exit if permissions do not allow a bulk data get of this parameter
                            USP_SNPRINTF(&path[path_len], MAX_DM_PATH-path_len, ".%s", child->name);
                            USP_ERR_SetMessage("%s: Controller's role permissions do not allow a bulk data read of %s", __FUNCTION__, path);
                            return USP_ERR_PERMISSION_DENIED;
                        }
                    }

                    // If permissions allow it, append the name of this parameter to the parent path and add to the vector
                    // NOTE: If permissions don't allow it, then just forgivingly leave the path out of the vector
                    if ( ((state->op == kResolveOp_Get) && (permission_bitmask & PERMIT_GET)) ||
                         ((state->op == kResolveOp_SubsValChange) && (permission_bitmask & PERMIT_SUBS_VAL_CHANGE)) )
                    {
                        add_to_vector = true;
                    }
                }
                break;

            case kDMNodeType_AsyncOperation:
                permission_bitmask = DM_PRIV_GetPermissions(child, state->combined_role);
                if ((state->op == kResolveOp_SubsOper) && (permission_bitmask & PERMIT_SUBS_EVT_OPER_COMP))
                {
                    add_to_vector = true;
                }
                break;


            case kDMNodeType_Event:
                permission_bitmask = DM_PRIV_GetPermissions(child, state->combined_role);
                if ((state->op == kResolveOp_SubsEvent) && (permission_bitmask & PERMIT_SUBS_EVT_OPER_COMP))
                {
                    add_to_vector = true;
                }
                break;

            case kDMNodeType_SyncOperation:
                // Cannot subscribe to synchronous operations
                break;

            default:
                TERMINATE_BAD_CASE(child->type);
                break;
        }


        // Add this node, if permissions have allowed it and we are returning a vector
        if ((add_to_vector) && (state->sv != NULL))
        {
            USP_SNPRINTF(&path[path_len], MAX_DM_PATH-path_len, ".%s", child->name);
            STR_VECTOR_Add(state->sv, path);
        }

        // Move to next sibling in the data model tree
        child = (dm_node_t *) child->link.next;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetChildParams_MultiInstanceObject
**
** Iterates over all instances of the specified object, adding the names of all instantiated child
** parameters of the specified node to the vector
** This function is called when processing a get using a partial path
** NOTE: This function is recursive
**
** \param   path - path of the object instance to get the child parameters of
** \param   path_len - length of path (position to append child node names)
** \param   node - Node to get children of
** \param   inst - pointer to instance structure locating the parent node
** \param   state - pointer to structure containing state variables to use with this resolution
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetChildParams_MultiInstanceObject(char *path, int path_len, dm_node_t *node, dm_instances_t *inst, resolver_state_t *state)
{
    int_vector_t iv;
    int instance;
    int len;
    int order;
    int i;
    int err;

    // Get an array of instances for this specific object
    err = DM_INST_VECTOR_GetInstances(node, inst, &iv);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Update instance structure in readiness to populate it with the instance number
    order = inst->order;
    USP_ASSERT(order < MAX_DM_INSTANCE_ORDER);
    inst->nodes[order] = node;
    inst->order = order+1;

    // Iterate over all instances of this object
    for (i=0; i < iv.num_entries; i++)
    {
        // Form the path to this instance
        instance = iv.vector[i];
        len = USP_SNPRINTF(&path[path_len], MAX_DM_PATH-path_len, ".%d", instance);

        // Get all child parameters of this object
        inst->instances[order] = instance;
        err = GetChildParams(path, path_len+len, node, inst, state);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }
    }

    // Put the instance structure back to the way it was
    inst->nodes[order] = NULL;
    inst->instances[order] = 0;
    inst->order = order;
    err = USP_ERR_OK;

exit:
    INT_VECTOR_Destroy(&iv);
    return err;
}

/*********************************************************************//**
**
** AddPathFound
**
** Adds the path to the vector of resolved parameters, after checking that
** the path meets the criteria for inclusion for the specified operation being performed by this USP message
**
** \param   path - pointer to path expression identifying objects in the data model
** \param   state - pointer to structure containing state variables to use with this resolution
**
** \return  USP_ERR_OK if path resolution should continue
**          
**          NOTE: With forgiving operations such as get and delete, path resolution
**                continues, even if this path is not suitable for inclusion in the result vector
**
**************************************************************************/
int AddPathFound(char *path, resolver_state_t *state)
{
    int index;
    int err;
    bool add_to_vector;
    unsigned path_properties;

    // Exit if the path did not match the properties we expected of it
    err = CheckPathProperties(path, state, &add_to_vector, &path_properties);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if we are gracefully ignoring this path (eg for a get of a parameter which the controller does not have permission for)
    if (add_to_vector==false)
    {
        return USP_ERR_OK;
    }

    // Exit if we are just validating the search path, and don't actually want to add the path to the returned vector
    if (state->sv == NULL)
    {
        return USP_ERR_OK;
    }

    // Handle a Subscription ReferenceList which just references the name of the multi-instance object (unqualified)
    // NOTE: If it references a single specific object instance then the normal code at the end of the function is run instead
    if ( ((state->op == kResolveOp_SubsAdd) || (state->op == kResolveOp_SubsDel)) &&
         ((path_properties & PP_IS_OBJECT_INSTANCE) == 0) )
    {
        USP_ASSERT(path_properties & PP_IS_MULTI_INSTANCE_OBJECT);
        err = DATA_MODEL_GetInstancePaths(path, state->sv, INTERNAL_ROLE);  // NOTE: We can use internal role because we've already checked permissions on this object
                                                                            //       and we don't want it to check get object instance permissions anyway for subscription add/delete paths
        return err;
    }

    // Handle resolving GetInstances
    if (state->op == kResolveOp_Instances)
    {
        if (state->flags & GET_ALL_INSTANCES)
        {
            err = DATA_MODEL_GetAllInstancePaths(path, state->sv, state->combined_role);
        }
        else
        {
            err = DATA_MODEL_GetInstancePaths(path, state->sv, state->combined_role);
        }
        return err;
    }

    // Normal execution path below
    // Exit if the path already exists in the vector
    index = STR_VECTOR_Find(state->sv, path);
    if (index != INVALID)
    {        
        return USP_ERR_OK;
    }

    // Finally add the single path to the vector
    STR_VECTOR_Add(state->sv, path);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** CheckPathProperties
**
** Check that the resolved path has the properties which we expect of it
**
** \param   path - pointer to path expression identifying objects in the data model
** \param   state - pointer to structure containing state variables to use with this resolution
** \param   add_to_vector - pointer to variable in which to return if the path should be added to the vector of resolved objects/parameters
** \param   path_properties - pointer to variable in which to return the properties of the resolved object/parameter
**
** \return  USP_ERR_OK if path resolution should continue
**          
**          NOTE: With forgiving operations such as get and delete, path resolution
**                continues, even if this path is not suitable for inclusion in the result vector
**
**************************************************************************/
int CheckPathProperties(char *path, resolver_state_t *state, bool *add_to_vector, unsigned *path_properties)
{
    unsigned flags;
    int err;
    unsigned short permission_bitmask;

    // Assume that the path should be added to the vector
    *add_to_vector = false;

    // Exit if the path does not exist in the schema
    flags = DATA_MODEL_GetPathProperties(path, state->combined_role, &permission_bitmask);
    *path_properties = flags;
    if ((flags & PP_EXISTS_IN_SCHEMA)==0)
    {
        USP_ERR_SetMessage("%s: Path (%s) does not exist in the schema", __FUNCTION__, path);
        return USP_ERR_INVALID_PATH;
    }

    // ===
    // Check that path represents the type of node we are expecting for this operation
    switch(state->op)
    {
        case kResolveOp_Get:
        case kResolveOp_SubsValChange:
        case kResolveOp_GetBulkData:
            // Exit if the path does not represent a parameter
            if ((flags & PP_IS_PARAMETER)==0)
            {
                USP_ERR_SetMessage("%s: Path (%s) is not a parameter", __FUNCTION__, path);
                return USP_ERR_INVALID_PATH;
            }
            break;

        case kResolveOp_Set:
        case kResolveOp_Add:
        case kResolveOp_Del:
        case kResolveOp_Instances:
        case kResolveOp_SubsAdd:
        case kResolveOp_SubsDel:
            // Exit if the path does not represent an object
            if ((flags & PP_IS_OBJECT)==0)
            {
                USP_ERR_SetMessage("%s: Path (%s) is not an object", __FUNCTION__, path);
                err = (state->op == kResolveOp_Add) ? USP_ERR_OBJECT_NOT_CREATABLE : USP_ERR_NOT_A_TABLE;
                return err;
            }
            break;

        case kResolveOp_Oper:
        case kResolveOp_SubsOper:
            // Exit if the path does not represent an operation
            if ((flags & PP_IS_OPERATION)==0)
            {
                USP_ERR_SetMessage("%s: Path (%s) is not an operation", __FUNCTION__, path);
                err = USP_ERR_COMMAND_FAILURE;
                return err;
            }
            break;

        case kResolveOp_Event:
        case kResolveOp_SubsEvent:
            // Exit if the path does not represent an event
            if ((flags & PP_IS_EVENT)==0)
            {
                USP_ERR_SetMessage("%s: Path (%s) is not an event", __FUNCTION__, path);
                return USP_ERR_INVALID_PATH;
                return err;
            }
            break;

        case kResolveOp_Any:
            // Not applicable, as this operation just validates the expression
            break;
            
        default:
            TERMINATE_BAD_CASE(state->op);
            break;
    }

    // ===
    // Check that path contains (or does not contain) a fully qualified object
    // Check that the path is to (or is not to) a multi-instance object
    switch(state->op)
    {
        case kResolveOp_Get:
        case kResolveOp_Oper:
        case kResolveOp_Event:
        case kResolveOp_SubsValChange:
        case kResolveOp_SubsOper:
        case kResolveOp_SubsEvent:
        case kResolveOp_GetBulkData:
            // Not applicable
            break;

        case kResolveOp_Set:
        case kResolveOp_Del:
            // Exit if the path is not a fully qualified object instance
            if ((flags & PP_IS_OBJECT_INSTANCE)==0)
            {
                USP_ERR_SetMessage("%s: Path (%s) should contain instance number of object", __FUNCTION__, path);
                return USP_ERR_OBJECT_DOES_NOT_EXIST;
            }
            break;

        case kResolveOp_Instances:
            // Whilst they are treated differently, the code allows for a GetInstances on a single instance object,
            // and a GetInstances on a specific, qualified multi instance object - in both recursive and non-recursive cases
            // So nothing to check further here
            break;

        case kResolveOp_SubsAdd:
        case kResolveOp_SubsDel:
            // Exit if the path is not a multi-instance object
            if ((flags & PP_IS_MULTI_INSTANCE_OBJECT)==0)
            {
                USP_ERR_SetMessage("%s: Path (%s) is not a multi-instance object", __FUNCTION__, path);
                return USP_ERR_NOT_A_TABLE;
            }
            break;

        case kResolveOp_Add:
            // Exit if the path is a fully qualified object instance
            if (flags & PP_IS_OBJECT_INSTANCE)
            {
                if (flags & PP_IS_MULTI_INSTANCE_OBJECT)
                {
                    USP_ERR_SetMessage("%s: Path (%s) should not contain instance number of object", __FUNCTION__, path);
                    err = USP_ERR_CREATION_FAILURE;
                }
                else
                {
                    USP_ERR_SetMessage("%s: Path (%s) is not a multi-instance object", __FUNCTION__, path);
                    err = USP_ERR_NOT_A_TABLE;
                }
                return err;
            }
            break;

        case kResolveOp_Any:
            // Not applicable, as this operation just validates the expression
            break;

        default:
            TERMINATE_BAD_CASE(state->op);
            break;
    }



    // ===
    // Exit if the role associated with the USP operation invoking path resolution does not have permission to perform the required operation
    switch(state->op)
    {
        case kResolveOp_Get:
            // It is not an error to not have permissions for a get operation.
            // It is forgiving, so just exit here, without adding the path to the vector
            if ((permission_bitmask & PERMIT_GET)==0)
            {
                return USP_ERR_OK;
            }
            break;

        case kResolveOp_Set:
            if ((permission_bitmask & PERMIT_SET)==0)
            {
                USP_ERR_SetMessage("%s: No permission to write to %s", __FUNCTION__, path);
                return USP_ERR_PERMISSION_DENIED;
            }
            break;

        case kResolveOp_Add:
            if ((permission_bitmask & PERMIT_ADD)==0)
            {
                USP_ERR_SetMessage("%s: No permission to add to %s", __FUNCTION__, path);
                return USP_ERR_PERMISSION_DENIED;
            }
            break;

        case kResolveOp_Del:
            if ((permission_bitmask & PERMIT_DEL)==0)
            {
                USP_ERR_SetMessage("%s: No permission to delete %s", __FUNCTION__, path);
                return USP_ERR_PERMISSION_DENIED;
            }
            break;

        case kResolveOp_Instances:
            // Checking for permission to read instances of this object
            // is performed later by DATA_MODEL_GetAllInstancePaths() or DATA_MODEL_GetInstancePaths()
            break;

        case kResolveOp_Oper:
            if ((permission_bitmask & PERMIT_OPER)==0)
            {
                USP_ERR_SetMessage("%s: No permission to perform operation %s", __FUNCTION__, path);
                return USP_ERR_COMMAND_FAILURE;
            }
            break;

        case kResolveOp_Event:
        case kResolveOp_SubsEvent:
            if ((permission_bitmask & PERMIT_SUBS_EVT_OPER_COMP)==0)
            {
                USP_ERR_SetMessage("%s: No permission to subscribe to event %s", __FUNCTION__, path);
                return USP_ERR_PERMISSION_DENIED;
            }
            break;

        case kResolveOp_SubsOper:
            if ((permission_bitmask & PERMIT_SUBS_EVT_OPER_COMP)==0)
            {
                USP_ERR_SetMessage("%s: No permission to subscribe to operation %s", __FUNCTION__, path);
                return USP_ERR_PERMISSION_DENIED;
            }
            break;

        case kResolveOp_SubsAdd:
            if ((permission_bitmask & PERMIT_SUBS_OBJ_ADD)==0)
            {
                USP_ERR_SetMessage("%s: No permission to subscribe to object creation on %s", __FUNCTION__, path);
                return USP_ERR_PERMISSION_DENIED;
            }
            break;

        case kResolveOp_SubsDel:
            if ((permission_bitmask & PERMIT_SUBS_OBJ_DEL)==0)
            {
                USP_ERR_SetMessage("%s: No permission to subscribe to object deletion on %s", __FUNCTION__, path);
                return USP_ERR_PERMISSION_DENIED;
            }
            break;

        case kResolveOp_SubsValChange:
            if ((permission_bitmask & PERMIT_SUBS_VAL_CHANGE)==0)
            {
                USP_ERR_SetMessage("%s: No permission to subscribe to value change on %s", __FUNCTION__, path);
                return USP_ERR_PERMISSION_DENIED;
            }
            break;

        case kResolveOp_GetBulkData:
            if ((permission_bitmask & PERMIT_GET)==0)
            {
                USP_ERR_SetMessage("%s: No permission to get bulk data on %s", __FUNCTION__, path);
                return USP_ERR_PERMISSION_DENIED;
            }
            break;

        case kResolveOp_Any:
            // Not applicable, as this operation just validates the expression
            break;
            
        default:
            TERMINATE_BAD_CASE(state->op);
            break;
    }

    // ===
    // Exit if the instance numbers in the path are not instantiated (do not currently exist in the data model)
    switch(state->op)
    {
        case kResolveOp_Get:
        case kResolveOp_SubsValChange:
        case kResolveOp_SubsAdd:
        case kResolveOp_SubsDel:
        case kResolveOp_SubsOper:
        case kResolveOp_SubsEvent:
        case kResolveOp_GetBulkData:
            // It is not an error for instance numbers to not be instantiated for a get parameter value
            // or a subscription reference list
            // Both are forgiving, so just exit here, without adding the path to the vector
            if ((flags & PP_INSTANCE_NUMBERS_EXIST)==0)
            {
                return USP_ERR_OK;
            }
            break;

        case kResolveOp_Set:
        case kResolveOp_Add:
        case kResolveOp_Del:
        case kResolveOp_Instances:
        case kResolveOp_Oper:
        case kResolveOp_Event:
            // Instance numbers must be instantiated (exist in data model)
            if ((flags & PP_INSTANCE_NUMBERS_EXIST)==0)
            {
                USP_ERR_SetMessage("%s: Object exists in schema, but instances are invalid: %s", __FUNCTION__, path);
                return USP_ERR_OBJECT_DOES_NOT_EXIST;
            }
            break;

        case kResolveOp_Any:
            // Not applicable, as this operation just validates the expression
            break;
            
        default:
            TERMINATE_BAD_CASE(state->op);
            break;
    }

    // If the code gets here, then the path should be added to the vector of resolved objects/parameters
    *add_to_vector = true;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** CountPathSeparator
**
** Counts the number of path separators ('.') in the specified data model path
**
** \param   path - pointer to string containing data model path
**
** \return  Number of separators in the specified path
**
**************************************************************************/
int CountPathSeparator(char *path)
{
    char *p = path;
    int count = 0;

    // Iterate over all characters in the path, counting the number of '.' characters in the string
    while (*p != '\0')
    {
        if (*p == '.')
        {
            count++;
        }
        p++;
    }

    return count;
}
