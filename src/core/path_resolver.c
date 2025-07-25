/*
 *
 * Copyright (C) 2019-2025, Broadband Forum
 * Copyright (C) 2024-2025, Vantiva Technologies SAS
 * Copyright (C) 2016-2024  CommScope, Inc
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
#include "group_get_vector.h"

//-------------------------------------------------------------------------
// State variable associated with the resolver. This is passed to all recursive resolver functions
typedef struct
{
    str_vector_t *sv;       // pointer to string vector to return the resolved paths in
                            // or NULL if we are only interested in whether the expression exists in the schema
    int_vector_t *gv;       // pointer to integer vector in which to return the group_id of the resolved parameters
                            // or NULL if we are not interesetd in group_id (eg if the expression describes objects not parameters)
    resolve_op_t op;        // operation being performed that requires path resolution
    int depth;              // Number of hierarchical levels to traverse in the data model when performing partial path resolution
    combined_role_t *combined_role;  // pointer to role to use when performing the path resolution.
                            // If the search path resolves to an object or param which there is no permission for,
                            // then a error will be generated (or the path forgivingly ignored in the case of a get)
    unsigned flags;         // flags controlling resolving of the path eg GET_ALL_INSTANCES
    bool is_search_path;    // Set if the path that has been parsed so far contains a search path (ie wildcard or search expression)
                            // This flag is used to differentiate between whether to ignore a resolved path, or generate an error, in the case of instances not existing in the resolved path (R.GET-0)
} resolver_state_t;

// Structure containing unique key search variables
// The indexes in keys[] and ggv_indexes[] refer to the same key
// The indexes in ggv and key_types[] refer to the same key (for keys containing references)
// ggv_indexes maps a key in keys to it's entry in ggv. This is needed because some keys are not in the ggv due to lack of permissions or contain an empty reference
typedef struct
{
    expr_vector_t keys;     // expression keys used for unique key search
    int_vector_t ggv_indexes; // group get index vector, maps to each {instance, key} pair, points to ggv index
                            // or INVALID if controller does not have read permission for that {instance, key} pair
    group_get_vector_t ggv; // group get vector for the valid parameters
    int_vector_t key_types; // integer vector for valid key types
} search_param_t;

//--------------------------------------------------------------------
// Typedef for the compare callback
typedef int (*dm_cmp_cb_t)(char *lhs, expr_op_t op, char *rhs, bool *result);

//--------------------------------------------------------------------
// Globals used to contain error responses for Add requests
str_vector_t *err_str_vec;
int_vector_t *err_int_vec;

//--------------------------------------------------------------------
// Convenience macro to wrap calls to USP_ERR_SetMessage(). Prevents USP_ERR_SetMessage() being called if DONT_LOG_RESOLVER_ERRORS is set
#define USP_ERR_SetMessageIfAllowed(...)      if ((state->flags & DONT_LOG_RESOLVER_ERRORS)==0) { USP_ERR_SetMessage(__VA_ARGS__); }

//--------------------------------------------------------------------
// Convenience macro passed to data model functions to prevent USP_ERR_SetMessage() being called if DONT_LOG_RESOLVER_ERRORS is set
#define DONT_LOG_ERRS_FLAG    (state->flags & DONT_LOG_RESOLVER_ERRORS) ? DONT_LOG_ERRORS : 0

//-------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
int ExpandPath(char *resolved, char *unresolved, resolver_state_t *state);
int ExpandWildcard(char *resolved, char *unresolved, resolver_state_t *state);
int ResolveReferenceFollow(char *resolved, char *unresolved, resolver_state_t *state);
int ResolveUniqueKey(char *resolved, char *unresolved, resolver_state_t *state);
int DoesInstanceMatchUniqueKey(char *object, int instance, expr_vector_t *keys, bool *is_match, resolver_state_t *state);
int ResolvePartialPath(char *path, resolver_state_t *state);
int GetChildParams(char *path, int path_len, dm_node_t *node, dm_instances_t *inst, resolver_state_t *state, int depth_remaining);
int GetChildParams_MultiInstanceObject(char *path, int path_len, dm_node_t *node, dm_instances_t *inst, resolver_state_t *state, int depth_remaining);
int AddPathFound(char *path, resolver_state_t *state);
int CountPathSeparator(char *path);
int CheckPathProperties(char *path, resolver_state_t *state, bool *add_to_vector, unsigned *path_properties, int *group_id);
int DoUniqueKeysMatch(int index, search_param_t *sp, bool *is_match);
int SplitReferenceKeysFromkeys(expr_vector_t *all_keys, expr_vector_t *keys, expr_vector_t *ref_keys);
int ExpandsNonReferencedKeys(char *resolved, resolver_state_t *state, int_vector_t *instances, search_param_t *sp);
int ResolveReferencedKeys(char *resolved, resolver_state_t *state, int_vector_t *instances, search_param_t *sp);
int ResolveIntermediateReferences(str_vector_t *params, resolver_state_t *state, int_vector_t *perm);
int CheckPathPermission(char *path, resolver_state_t *state, int *gid, int *param_type, bool *has_permission);
bool GroupReferencedParameters(str_vector_t *params, resolver_state_t *state, int_vector_t *perm, group_get_vector_t *ggv, int *err);
void InitSearchParam(search_param_t *sp);
void DestroySearchParam(search_param_t *sp);
void RefreshInstances_LifecycleSubscriptionEndingInPartialPath(char *path);
int ValidatePathSegment(int path_segment_index, char *segment, char *previous_segment, subs_notify_t notify_type, char *path);
int GetPermittedInstances(char *obj_path, int_vector_t *iv, resolver_state_t *state);
void FilterPathsByPermission(str_vector_t *sv, unsigned short permission_bitmask, unsigned short required_permission, combined_role_t *combined_role);

/*********************************************************************//**
**
** PATH_RESOLVER_AttachErrVector
**
** Called to specify vectors to be used by the path resolver in which to return errors found
** This function is only called when performing an Add, and the vectors are only added to when op=kResolveOp_Add
** This function avoids adding yet another optional input argument to PATH_RESOLVER_ResolveDevicePath
**
** \param   sv - string vector to return error messages in. NOTE: Use NULL to detach the vector
** \param   iv - int vector to return error codes in. NOTE: Use NULL to detach the vector
**
** \return  None
**
**************************************************************************/
void PATH_RESOLVER_AttachErrVector(str_vector_t *sv, int_vector_t *iv)
{
    err_str_vec = sv;
    err_int_vec = iv;
}

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
** \param   gv - pointer to vector in which to return the group_id of the parameters
**               or NULL if the caller is not interested in this
**               NOTE: values in sv and gv relate by index
** \param   op - operation being performed that requires path resolution
** \param   depth - Number of hierarchical levels to traverse in the data model when performing partial path resolution
** \param   combined_role - role to use when performing the resolution. If set to INTERNAL_ROLE, then permissions are ignored (used internally)
** \param   flags - flags controlling resolving of the path eg GET_ALL_INSTANCES
**
** \return  USP_ERR_OK if successful, or no instances found
**
**************************************************************************/
int PATH_RESOLVER_ResolveDevicePath(char *path, str_vector_t *sv, int_vector_t *gv, resolve_op_t op, int depth, combined_role_t *combined_role, unsigned flags)
{
    int err;
    int len;
    dm_node_t *node;
    dm_instances_t inst;

    // Exit if the path does not begin with "Device."
    if (strncmp(path, dm_root, dm_root_len) != 0)
    {
        USP_ERR_SetMessage("%s: Expression does not start in '%s' (path='%s')", __FUNCTION__, dm_root, path);
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
        if ((op==kResolveOp_Add) || (op==kResolveOp_Del) || (op==kResolveOp_Instances))
        {
            USP_ERR_SetMessage("%s: Path must end in '.'", __FUNCTION__);
            return USP_ERR_INVALID_PATH_SYNTAX;
        }
    }

    // Exit if the path was an absolute path without read permission (implements R-GET.1, R-GET.0)
    if (op == kResolveOp_Get)
    {
        node = DM_PRIV_GetNodeFromPath(path, &inst, NULL, (DONT_LOG_ERRORS|SUBSTITUTE_SEARCH_EXPRS));
        if (node != NULL)
        {
            err = DM_PRIV_CheckGetReadPermissions(node, &inst, combined_role);
            if (err != USP_ERR_OK)
            {
                return err;
            }
        }
    }

    err = PATH_RESOLVER_ResolvePath(path, sv, gv, op, depth, combined_role, flags);
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
** \param   gv - pointer to vector in which to return the group_id of the parameters
**               or NULL if the caller is not interested in this
**               NOTE: values in sv and gv relate by index
** \param   op - operation being performed that requires path resolution
** \param   depth - Number of hierarchical levels to traverse in the data model when performing partial path resolution
** \param   combined_role - role to use when performing the resolution
*  \param   flags - flags controlling resolving of the path eg GET_ALL_INSTANCES
**
** \return  USP_ERR_OK if successful, or no instances found
**
**************************************************************************/
int PATH_RESOLVER_ResolvePath(char *path, str_vector_t *sv, int_vector_t *gv, resolve_op_t op, int depth, combined_role_t *combined_role, unsigned flags)
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
    state.gv = gv;
    state.op = op;
    state.depth = depth;
    state.combined_role = combined_role;
    state.flags = flags;
    state.is_search_path = false;

    err = ExpandPath(resolved, unresolved, &state);

    return err;
}


/*********************************************************************//**
**
** PATH_RESOLVER_ValidatePath
**
** This function attempts to validate the reference list textually without needing the DM elements to
** have been registered by a USP Service
** This function is intended to be called to validate subscription paths, Boot! Parameter paths and Bulk Data Collection parameter paths
**
** \param   path - Data model path to validate
** \param   notify_type - Type of notification that the path refers to
**                        NOTE: If the path is supposed to represent parameters, then use kSubNotifyType_ValueChange
**
** \return  USP_ERR_OK if the path looks valid
**          USP_ERR_INVALID_ARGUMENTS if the path looks invalid
**
**************************************************************************/
int PATH_RESOLVER_ValidatePath(char *path, subs_notify_t notify_type)
{
    int i;
    int err;
    str_vector_t path_segments;
    char *last_segment;
    int len;
    char *p;
    char buf[MAX_DM_PATH];
    bool inside_brackets;

    // Exit if no path setup yet (empty path).
    // NOTE: This is not an error as it could occur if this function is called when NotifType is set before ReferenceList is set
    STR_VECTOR_Init(&path_segments);
    if (*path == '\0')
    {
        err = USP_ERR_OK;
        goto exit;
    }

    // Exit if path is just to 'Device.' This is only supported for OperationComplete and USP Events
    if (strcmp(path, dm_root)==0)
    {
        switch(notify_type)
        {
            case kSubNotifyType_OperationComplete:
            case kSubNotifyType_Event:
            case kSubNotifyType_None:    // NOTE: 'None' could occur if this function is called when ReferenceList is set before NotifType
                err = USP_ERR_OK;
                break;

            default:
            case kSubNotifyType_ValueChange:
                USP_ERR_SetMessage("%s: ReferenceList '%s' is not supported for NotifType=%s", __FUNCTION__, path, TEXT_UTILS_EnumToString(notify_type, notify_types, NUM_ELEM(notify_types)) );
                err = USP_ERR_RESOURCES_EXCEEDED;
                break;

            case kSubNotifyType_ObjectCreation:
            case kSubNotifyType_ObjectDeletion:
                USP_ERR_SetMessage("%s: Path (%s) is not a multi-instance object", __FUNCTION__, path);
                err = USP_ERR_NOT_A_TABLE;
                break;
        }

        goto exit;
    }

    // Exit if the path does not start with "Device."
    if (strncmp(path, dm_root, dm_root_len) != 0)
    {
        USP_ERR_SetMessage("%s: Expression does not start in 'Device.' (path='%s')", __FUNCTION__, path);
        err = USP_ERR_INVALID_PATH;
        goto exit;
    }

    // Exit if path contains an empty path segment
    if (strstr(path, "..") != NULL)
    {
        USP_ERR_SetMessage("%s: ReferenceList '%s' contains empty path segment '..'", __FUNCTION__, path);
        err = USP_ERR_INVALID_PATH_SYNTAX;
        goto exit;
    }

    // Exit if the path contains whitespace either side of any '.' path separator
    p = path;
    while (*p != '\0')
    {
        if (p[0] == '.')
        {
            if ((p[-1] == ' ') || (p[-1] == '\t') || (p[1] == ' ') || (p[1] == '\t'))
            {
                USP_ERR_SetMessage("%s: ReferenceList '%s' contains whitespace where it shouldn't", __FUNCTION__, path);
                err = USP_ERR_INVALID_PATH_SYNTAX;
                goto exit;
            }
        }
        p++;
    }

    // Workaround a problem that the inside of a search expression could contain '.', and this causes TEXT_UTILS_SplitString() to go wrong
    // We replace '.' within '[' and ']' with a different character
    // NOTE: This workaround is suitable, because we don't validate within a search expression
    USP_STRNCPY(buf, path, sizeof(buf));
    p = buf;
    inside_brackets = false;
    while (*p != '\0')
    {
        if (*p == '[')
        {
            inside_brackets = true;
        }
        else if (*p == ']')
        {
            inside_brackets = false;
        }
        else if ((*p == '.') && (inside_brackets == true))
        {
            *p = 'X';
        }
        p++;
    }

    // Split the string into path segments
    TEXT_UTILS_SplitString(buf, &path_segments, ".");
    USP_ASSERT(path_segments.num_entries != 0);    // This shouldn't occur, as we already tested that the string wasn't empty

    // Ensure the last segment ends correctly, removing any trailing '!' or '()'
    last_segment = path_segments.vector[ path_segments.num_entries-1 ];
    len = strlen(last_segment);

    switch(notify_type)
    {
        case kSubNotifyType_OperationComplete:
            // OperationComplete subscriptions must end in '()'
            if (strcmp(&last_segment[len-2], "()") != 0)
            {
                USP_ERR_SetMessage("%s: ReferenceList '%s' should end in '()' for NotifType=OperationComplete", __FUNCTION__, path);
                err = USP_ERR_INVALID_PATH;
                goto exit;
            }

            // Remove the trailing '()'
            last_segment[len-2] = '\0';
            break;

        case kSubNotifyType_Event:
            // USP Event subscriptions must end in '!'
            if (last_segment[len-1] != '!')
            {
                USP_ERR_SetMessage("%s: ReferenceList '%s' should end in '!' for NotifType=Event", __FUNCTION__, path);
                err = USP_ERR_INVALID_PATH;
                goto exit;
            }

            // Remove the trailing '!'
            last_segment[len-1] = '\0';
            break;

        case kSubNotifyType_ValueChange:
            // These subscriptions must not end in '()' or '!'
            if ((strcmp(&last_segment[len-2], "()") == 0) || (last_segment[len-1] == '!'))
            {
                USP_ERR_SetMessage("%s: Path '%s' is not a parameter or object partial path", __FUNCTION__, path);
                err = USP_ERR_INVALID_PATH;
                goto exit;
            }
            break;

        case kSubNotifyType_ObjectCreation:
        case kSubNotifyType_ObjectDeletion:
            // These subscriptions must not end in '()' or '!'
            if ((strcmp(&last_segment[len-2], "()") == 0) || (last_segment[len-1] == '!'))
            {
                USP_ERR_SetMessage("%s: Path '%s' is not an object", __FUNCTION__, path);
                err = USP_ERR_NOT_A_TABLE;
                goto exit;
            }
            break;

        case kSubNotifyType_None:
            // Remove any trailing '()' or '!' to allow ReferenceList to refer to USP commands or events before NotifType is set
            if (strcmp(&last_segment[len-2], "()") == 0)
            {
                last_segment[len-2] = '\0';
            }
            else if (last_segment[len-1] == '!')
            {
                // Remove the trailing '!'
                last_segment[len-1] = '\0';
            }
            break;

        default:
            // Validation of path ending not required
            break;
    }


    // Iterate over all path segments after the first ('Device'), exiting if any look invalid
    for (i=1; i < path_segments.num_entries; i++)
    {
        err = ValidatePathSegment(i, path_segments.vector[i], path_segments.vector[i-1], notify_type, path);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }
    }

    // If the code gets here, then all path segments looked OK
    err = USP_ERR_OK;

exit:
    STR_VECTOR_Destroy(&path_segments);
    return err;
}

/*********************************************************************//**
**
** ValidatePathSegment
**
** This function attempts to validate a segment of a path in a subscription reference list
** (A segment is the text in between each '.' separating each segment) and can be either
**    - wildcard
**    - search expression
**    - instance number
**    - name of an parameter/object (possibly ending in reference follow '+')
** NOTE: Not all of these segment types are supported for all notify types
**
** \param   path_segment_index - Position of this path segment within the path eg. [0] == "Device"
** \param   segment - pointer to string containing the segment to check
**                    NOTE: This string may have a trailing '+' truncated by the checking code in the course of checking
** \param   previous_segment - pointer to string containing the preceeding segment to the segment under consideration
**                    NOTE: This string is used to check that the path doesn't contain wildcards or search expressions next to one another
** \param   notify_type - Type of notification that the path refers to
** \param   path - path which the segment is part of (used for error reporting)
**
** \return  USP_ERR_OK if the segment looks valid
**          USP_ERR_INVALID_ARGUMENTS if the segment looks invalid
**
**************************************************************************/
int ValidatePathSegment(int path_segment_index, char *segment, char *previous_segment, subs_notify_t notify_type, char *path)
{
    int i;
    int len;
    char c;

    // Exit if segment is empty. NOTE: TEXT_UTILS_SplitString() should have ensured that this doesn't happen
    len = strlen(segment);
    if (len == 0)
    {
        USP_ERR_SetMessage("%s: Reference List '%s' contains '..'", __FUNCTION__, path);
        return USP_ERR_INVALID_PATH;
    }

    // Exit if segment is a wildcard
    if (strcmp(segment, "*")==0)
    {
        // Wildcards aren't allowed immediately after "Device."
        if (path_segment_index == 1)
        {
            USP_ERR_SetMessage("%s: Path (%s) is not a multi-instance object", __FUNCTION__, path);
            return USP_ERR_NOT_A_TABLE;
        }

        // Wildcards expressions aren't allowed immediately after a search expression or another wildcard
        if ((previous_segment[0] == '[') || (previous_segment[0] == '*'))
        {
            USP_ERR_SetMessage("%s: Path (%s) contains search expressions or wildcards next to one another", __FUNCTION__, path);
            return USP_ERR_INVALID_PATH_SYNTAX;
        }

        return USP_ERR_OK;
    }

    // Exit if segment is a search expression
    if (segment[0] == '[')
    {
        // Exit if search expression is not terminated correctly
        if (segment[len-1] != ']')
        {
            USP_ERR_SetMessage("%s: Search expression in '%s' is not terminated correctly", __FUNCTION__, path);
            return USP_ERR_INVALID_PATH_SYNTAX;
        }

        // Search expressions aren't allowed immediately after "Device."
        if (path_segment_index == 1)
        {
            USP_ERR_SetMessage("%s: Path (%s) is not a multi-instance object", __FUNCTION__, path);
            return USP_ERR_NOT_A_TABLE;
        }

        // Search expressions aren't allowed immediately after a wildcard or another search expression
        if ((previous_segment[0] == '*') || (previous_segment[0] == '['))
        {
            USP_ERR_SetMessage("%s: Path (%s) contains search expressions or wildcards next to one another", __FUNCTION__, path);
            return USP_ERR_INVALID_PATH_SYNTAX;
        }

        return USP_ERR_OK;
    }

    // Exit if segment is an instance number
    if (IS_NUMERIC(segment[0]))
    {
        // Instance numbers aren't allowed immediately after "Device."
        if (path_segment_index == 1)
        {
            USP_ERR_SetMessage("%s: Path (%s) is not a multi-instance object", __FUNCTION__, path);
            return USP_ERR_NOT_A_TABLE;
        }

        // Exit if the rest of the segment is not also numeric (which it needs to be for an instance number)
        for (i=1; i<len; i++)
        {
            c = segment[i];
            if (IS_NUMERIC(c) == false)
            {
                USP_ERR_SetMessage("%s: Instance number '%s' contains invalid characters in ReferenceList '%s'", __FUNCTION__, segment, path);
                return USP_ERR_INVALID_PATH;
            }
        }

        return USP_ERR_OK;
    }

    // Truncate string if it is a reference follow, removing the trailing '+',
    // in order to make the path segment into just the name of a parameter
    if (segment[len-1] == '+')
    {
        segment[len-1] = '\0';
        len--;

        // Exit if path segment contained only '+'
        if (len == 0)
        {
            USP_ERR_SetMessage("%s: ReferenceList '%s' contains reference follow '+' without preceding parameter name", __FUNCTION__, path);
            return USP_ERR_INVALID_PATH_SYNTAX;
        }

        // Reference following is not supported for USP Events or OperationComplete notifications
        // This is because the Broker cannot set the subscription on the USP Service because reference following is always implemented only by the Broker
        if ((notify_type == kSubNotifyType_OperationComplete) || (notify_type == kSubNotifyType_Event))
        {
            USP_ERR_SetMessage("%s: Reference following in '%s' is not supported for NotifType=%s", __FUNCTION__, path, TEXT_UTILS_EnumToString(notify_type, notify_types, NUM_ELEM(notify_types)) );
            return USP_ERR_RESOURCES_EXCEEDED;
        }
    }

    // Iterate over all characters in the path segment, checking them for validity
    // NOTE: If the code gets here, the path segment can only be the name portion of a DM element
    for (i=0; i<len; i++)
    {
        c = segment[i];
        if ((IS_ALPHA_NUMERIC(c) == false) && (c != '-') && (c != '_'))
        {
            USP_ERR_SetMessage("%s: Unexpected character '%c' in ReferenceList '%s'", __FUNCTION__, c, path);
            return USP_ERR_INVALID_PATH;
        }
    }

    return USP_ERR_OK;
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
    bool check_refresh_instances = false;

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
            state->is_search_path = true;
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
            state->is_search_path = true;
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

            case kResolveOp_SubsAdd:
            case kResolveOp_SubsDel:
                // Remove any trailing '.'  The partial path may potentially call a refresh instances vendor hook to be called
                resolved[len-1] = '\0';
                check_refresh_instances = true;
                break;

            case kResolveOp_Add:
            case kResolveOp_Del:
            case kResolveOp_Set:
            case kResolveOp_Instances:
            case kResolveOp_Any:
            case kResolveOp_StrictRef:
            case kResolveOp_ForgivingRef:
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

    // Partial path for add/delete object subscriptions must ensure that object instances are refreshed
    // Do this by getting the instances for this object (all sub objects are also refreshed in the process)
    if (check_refresh_instances)
    {
        RefreshInstances_LifecycleSubscriptionEndingInPartialPath(resolved);
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** RefreshInstances_LifecycleSubscriptionEndingInPartialPath
**
** Refreshes the instance numbers of a top level object referenced by an object lifetime subscription
**
** The code in RefreshInstancesForObjLifetimeSubscriptions() periodically
** refreshes all instances which have object lifetime subscriptions on them
** in order to determine whether the subscription should fire.
** This function is called if the ReferenceList of the subscription is a partial path.
** It ensures that the refresh instances vendor hook is called, if it wouldn't have been
** already during path resolution. The only time it wouldn't have been called is if the
** path resolver resolves to a partial path of a top level multi-instance object
**
** \param   path - path of the object to potentially refresh
**
** \return  None
**
**************************************************************************/
void RefreshInstances_LifecycleSubscriptionEndingInPartialPath(char *path)
{
    dm_node_t *node;
    bool is_qualified_instance;
    dm_object_info_t *info;
    dm_instances_t inst;

    // Exit if unable to find node representing this object. NOTE: This should never occur, as caller should have ensured path exists in schema
    node = DM_PRIV_GetNodeFromPath(path, &inst, &is_qualified_instance, 0);
    if (node == NULL)
    {
        return;
    }

    // Exit if this is not a top level multi-instance object with a refresh instances vendor hook
    // NOTE: If path is to a child object whose parent has a refresh instances vendor hook,
    //       then the vendor hook will already have been called as part of resolving the path, so no need to refresh here
    // NOTE: The path resolver disallows object lifecycle subscriptions on partial paths that are not multi-instance objects
    //       so this code does not have to cope with calling the refresh instances vendor hook for a child object of the given path.
    info = &node->registered.object_info;
    if ((node->type != kDMNodeType_Object_MultiInstance) || (node->order != 1) || (info->refresh_instances_cb == NULL))
    {
        return;
    }

    // Exit if this object is already a fully qualified instance
    // NOTE: This may be the case if the subscription ReferenceList terminated in wildcard or instance number before the partial path dot character
    // If so, the refresh instances vendor hook would already have been called
    if (is_qualified_instance)
    {
        return;
    }

    // NOTE: This function may be called recursively if it is time to call the refresh instances vendor hook
    // The first time DM_INST_VECTOR_RefreshTopLevelObjectInstances() is called, if it calls the refresh instances vendor hook,
    // then afterwards it will determine if any of the instances caused the subscription to fire.
    // It does this by calling the path resolver, which will end up in this function again.
    // The second time that DM_INST_VECTOR_RefreshTopLevelObjectInstances() is called, the instances cache
    // will not need refreshing, hence DM_INST_VECTOR_RefreshTopLevelObjectInstances() will return the second time it is called.
    DM_INST_VECTOR_RefreshTopLevelObjectInstances(node);
}

/*********************************************************************//**
**
** ExpandWildcard
**
** Expands the wildcard that exists inbetween 'resolved' and 'unresolved' parts of the path
** then recurses to resolve the rest of the path
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

    // Exit if unable to get the permitted instances of this object
    INT_VECTOR_Init(&iv);
    err = GetPermittedInstances(resolved, &iv, state);
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
        err = ExpandPath(resolved, unresolved, state);
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
    char *p;

    // Exit if this is a Bulk Data collection operation, which does not allow reference following
    // (because the alt-name reduction rules in TR-157 do not support it)
    if (state->op == kResolveOp_GetBulkData)
    {
        USP_ERR_SetMessage("%s: Bulk Data collection does not allow reference following in search expressions", __FUNCTION__);
        return USP_ERR_INVALID_PATH_SYNTAX;
    }

    // Exit if unable to determine whether we are allowed to read the reference
    err = DATA_MODEL_GetPermissions(resolved, state->combined_role, &permission_bitmask, DONT_LOG_ERRS_FLAG);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if not permitted to read the reference
    if ((permission_bitmask & PERMIT_GET) == 0)
    {
        // Get operations are forgiving of permissions, so just give up further resolution here
        #define IS_FORGIVING(op) ((op == kResolveOp_Get) || (op == kResolveOp_SubsValChange) || (op == kResolveOp_ForgivingRef))
        #define IS_STRICT(op)    ((op != kResolveOp_Get) && (op != kResolveOp_SubsValChange) && (op != kResolveOp_ForgivingRef))
        if (IS_FORGIVING(state->op))
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

    // Exit if the reference was empty
    // NOTE: A get parameter value is forgiving in this case, whilst a set fails
    if (dereferenced[0] == '\0')
    {
        if (IS_STRICT(state->op))
        {
            USP_ERR_SetMessage("%s: The dereferenced path contained in %s was empty", __FUNCTION__, resolved);
            return USP_ERR_OBJECT_DOES_NOT_EXIST;
        }
        return USP_ERR_OK;
    }

    // Truncate string to just the first reference, if the reference contains a list of references
    // The USP Spec says that only the first reference should be used if the '#' operator is omitted before the '+' operator
    p = strchr(dereferenced, ',');
    if (p != NULL)
    {
        *p = '\0';
    }

    // Resolve the reference if it contains a search expression, reference following or wildcard
    if (strpbrk(dereferenced, "[+#*]") != NULL)
    {
        str_vector_t sv;
        resolve_op_t op;

        // Determine resolve operation to use when resolving the reference
        op = IS_FORGIVING(state->op) ? kResolveOp_ForgivingRef : kResolveOp_StrictRef;

        // Exit if unable to resolve any search expressions contained in the reference
        STR_VECTOR_Init(&sv);
        err = PATH_RESOLVER_ResolvePath(dereferenced, &sv, NULL, op, FULL_DEPTH, state->combined_role, 0);
        if (err != USP_ERR_OK)
        {
            return err;
        }

        // Exit if the reference resolved to zero paths
        // NOTE: This may be the case. For example, if the reference contains unique key based addressing and the role does not have permissions to read them
        if (sv.num_entries == 0)
        {
            // NOTE: No need to destroy sv, as we already know that number of entries is zero
            if (IS_STRICT(state->op))
            {
                USP_ERR_SetMessage("%s: The dereferenced path contained in %s (%s) resolved to empty", __FUNCTION__, resolved, dereferenced);
                return USP_ERR_OBJECT_DOES_NOT_EXIST;
            }
            return USP_ERR_OK;
        }

        // Replace the value of the reference parameter with its first resolved path
        USP_STRNCPY(dereferenced, sv.vector[0], sizeof(dereferenced));
        STR_VECTOR_Destroy(&sv);
    }

    // Exit if the dereferenced path is not a fully qualified object
    // NOTE: We do not check permissions here, since there may be further parts of the path to resolve after this reference follow
    flags = DATA_MODEL_GetPathProperties(dereferenced, INTERNAL_ROLE, NULL, NULL, NULL, 0);
    if ( ((flags & PP_IS_OBJECT) == 0) || ((flags & PP_IS_OBJECT_INSTANCE) ==0) )
    {
        USP_ERR_SetMessage("%s: The dereferenced path contained in %s was not an object instance (got the value '%s')", __FUNCTION__, resolved, dereferenced);
        return USP_ERR_INVALID_PATH_SYNTAX;
    }

    // Exit if the dereferenced path does not have instance numbers that exist
    // NOTE: A get parameter value is forgiving in this case, whilst a set fails
    if ((flags & PP_INSTANCE_NUMBERS_EXIST) == 0)
    {
        if (IS_STRICT(state->op))
        {
            USP_ERR_SetMessage("%s: The dereferenced object %s does not exist", __FUNCTION__, dereferenced);
            return USP_ERR_OBJECT_DOES_NOT_EXIST;
        }
        return USP_ERR_OK;
    }

    // If the code gets here then the resolved path has been successfully dereferenced,
    // so continue resolving the path, using the dereferenced path
    err = ExpandPath(dereferenced, unresolved, state);

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
    expr_vector_t keys;
    int i;
    int err;
    char *p;
    int len;
    int_vector_t instances;
    search_param_t sp;
    search_param_t ref_sp;
    char temp[MAX_DM_PATH];
    bool is_match;
    bool is_ref_match;
    expr_op_t valid_ops[] = {kExprOp_Equal, kExprOp_NotEqual, kExprOp_LessThanOrEqual, kExprOp_GreaterThanOrEqual, kExprOp_LessThan, kExprOp_GreaterThan};

    // Exit if unable to find the end of the unique key
    p = TEXT_UTILS_StrStr(unresolved, "]");
    if (p == NULL)
    {
        USP_ERR_SetMessage("%s: Unterminated Unique Key (%s) in search path", __FUNCTION__, unresolved);
        return USP_ERR_INVALID_PATH_SYNTAX;
    }

    // Initialise vectors used by this function
    EXPR_VECTOR_Init(&keys);
    INT_VECTOR_Init(&instances);
    InitSearchParam(&sp);
    InitSearchParam(&ref_sp);

    // Exit if unable to get the permitted instances of this object
    err = GetPermittedInstances(resolved, &instances, state);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if there are no instances of this object
    if (instances.num_entries == 0)
    {
        err = USP_ERR_OK;
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

    // split the keys in referenced unique keys and non-referenced unique keys, this is required as the permissions info
    // for the non-referenced unique keys available in schema but for referenced keys, it depends on the value of
    // referenced parameter keys
    err = SplitReferenceKeysFromkeys(&keys, &sp.keys, &ref_sp.keys);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // once the keys are divided in non-referenced keys and referenced keys, keys not required for further
    // operations
    EXPR_VECTOR_Destroy(&keys);

    // Update the group get vector for non-referenced unique key parameters, this also checks that we have permissions to read the parameters
    // If we don't have permissions, then the path resolution may fail either with an error (eg for SET) or silently (eg for GET)
    err = ExpandsNonReferencedKeys(resolved, state, &instances, &sp);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Update the group get vector for referenced unique key parameters, this also checks that we have permissions to
    // read the referenced parameters, If we don't have permissions, then the path resolution may fail either with an
    // error (eg for SET) or silently (eg for GET)
    err = ResolveReferencedKeys(resolved, state, &instances, &ref_sp);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // For optimisation call the group gets on non-referenced keys and referenced-keys only after permission validation
    // has been done
    GROUP_GET_VECTOR_GetValues(&sp.ggv);
    GROUP_GET_VECTOR_GetValues(&ref_sp.ggv);

    // Iterate over all instances of the object present in the data model
    for (i=0; i < instances.num_entries; i++)
    {
        // Exit if an error occurred whilst trying to determine whether this instance matched the unique key
        err = DoUniqueKeysMatch(i, &sp, &is_match);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }

        // Exit if an error occurred whilst trying to determine whether this instance matched the unique key
        // it is okay to have no ref_keys present in query, in case of that is_ref_match will be marked as true
        err = DoUniqueKeysMatch(i, &ref_sp, &is_ref_match);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }

        // If found an instance which matches, continue resolving the path recursively, selecting this instance
        if (is_match & is_ref_match)
        {
            USP_SNPRINTF(temp, sizeof(temp), "%s%d", resolved, instances.vector[i]);
            err = ExpandPath(temp, unresolved, state);
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
    INT_VECTOR_Destroy(&instances);
    EXPR_VECTOR_Destroy(&keys);
    DestroySearchParam(&sp);
    DestroySearchParam(&ref_sp);
    return err;
}

/*********************************************************************//**
**
** SplitReferenceKeysFromkeys
**
** Split expression keys in all_keys with reference parameters and non-referenced parameters
**
** \param   all_keys - Pointer to all expression keys
** \param   keys - pointer to expression keys which does not have a referenced parameter
** \param   ref_keys - pointer to expression keys with referenced parameter
**
** \return  USP_ERR_OK if split succeed, or err if reference keys doesn't have an object
**
**************************************************************************/
int SplitReferenceKeysFromkeys(expr_vector_t *all_keys, expr_vector_t *keys, expr_vector_t *ref_keys)
{
    int i;
    expr_comp_t *ec;
    char *is_ref;
    size_t param_len;

    EXPR_VECTOR_Init(keys);
    EXPR_VECTOR_Init(ref_keys);

    for (i=0; i < all_keys->num_entries; i++)
    {
        ec = &all_keys->vector[i];
        is_ref = strchr(ec->param, '+');

        if (is_ref)
        {
            param_len = strlen(ec->param);
            // Error if reference follow does not have a key after the reference object
            if (ec->param[param_len - 1] == '+')
            {
                USP_ERR_SetMessage("%s: Key (%s) does not terminate in a parameter name. References must be to objects.", __FUNCTION__, ec->param);
                return USP_ERR_INVALID_PATH_SYNTAX;
            }

            EXPR_VECTOR_Add(ref_keys, ec->param, ec->op, ec->value);
        }
        else
        {
            EXPR_VECTOR_Add(keys, ec->param, ec->op, ec->value);
        }
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ExpandsNonReferencedKeys
**
** Expands keys over instances to create a group get vector for the non
** referenced keys present in unique key search
**
** \param   resolved - pointer to data model object that we want to lookup by unique key
** \param   state - pointer to structure containing state variables to use with this resolution
** \param   instances - instances of base object to get
** \param   sp - pointer to search parameter structure to return ggv_index, ggv and key_types for each valid {instance, key} pair
**
** \return  USP_ERR_OK if successful, or no non-referenced keys present
**
**************************************************************************/
int ExpandsNonReferencedKeys(char *resolved, resolver_state_t *state, int_vector_t *instances, search_param_t *sp)
{
    int err;
    int i, j;
    expr_comp_t *ec;
    char path[MAX_SEARCH_KEYS][MAX_DM_PATH];
    int param_group_id[MAX_SEARCH_KEYS];
    int param_type_flags[MAX_SEARCH_KEYS];
    bool has_permission;
    int instance;

    // Exit if there are no keys that need expanding. Nothing to do in this case.
    if (sp->keys.num_entries == 0)
    {
        return USP_ERR_OK;
    }

    // Exit if there are more keys than this code can handle
    if (sp->keys.num_entries > MAX_SEARCH_KEYS)
    {
        USP_ERR_SetMessage("%s: More than %d parameters in search expression", __FUNCTION__, MAX_SEARCH_KEYS);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Iterate over all instances
    for (i=0; i < instances->num_entries; i++)
    {
        instance = instances->vector[i];

        // Iterate over all (non-reference following) unique keys for this instance
        // Forming the path and determining whether there is read permission for them
        has_permission = false;
        for (j=0; j < sp->keys.num_entries; j++)
        {
            // Exit if unique key parameter does not exist in the data model
            ec = &sp->keys.vector[j];
            USP_SNPRINTF(&path[j][0], MAX_DM_PATH, "%s%d.%s", resolved, instance, ec->param);
            err = CheckPathPermission(&path[j][0], state, &param_group_id[j], &param_type_flags[j], &has_permission);
            if (err != USP_ERR_OK)
            {
                return err;
            }

            // Exit the loop if any parameter does not have read permission for this instance
            // In this case, we should not bother getting any of the parameters in the key for this instance
            if (has_permission == false)
            {
                break;
            }
        }

        if (has_permission)
        {
            // If there was permission to read all keys for this instance, then add them all to the group get vector and reference them from the ggv_index
            for (j=0; j < sp->keys.num_entries; j++)
            {
                INT_VECTOR_Add(&sp->ggv_indexes, sp->ggv.num_entries);  // Set index to point to entry about to be added to group get vector
                GROUP_GET_VECTOR_Add(&sp->ggv, &path[j][0], param_group_id[j]);
                INT_VECTOR_Add(&sp->key_types, param_type_flags[j]);
            }
        }
        else
        {
            // If there wasn't permission to read one of the parameters in the search expression for this instance
            // then indicate this in the ggv_indexes by marking all parameters in this instance with invalid
            for (j=0; j < sp->keys.num_entries; j++)
            {
                INT_VECTOR_Add(&sp->ggv_indexes, INVALID);
            }
        }
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ResolveReferencedKeys
**
** Resolves the intermediate references to form a group get vector of final parameters to get
**
** \param   resolved - pointer to data model object that we want to lookup by unique key
** \param   state - pointer to structure containing state variables to use with this resolution
** \param   instances - instances of base object to get
** \param   sp - pointer to search parameter structure to return ggv_index, ggv and key_types for each valid {instance, key} pair
**
** \return  USP_ERR_OK if successful, or no referenced unique keys present
**
**************************************************************************/
int ResolveReferencedKeys(char *resolved, resolver_state_t *state, int_vector_t *instances, search_param_t *sp)
{
    char temp[MAX_DM_PATH];
    int err, i, j;
    expr_comp_t *ec;
    str_vector_t params;
    int_vector_t perm;
    int ggv_index;
    int group_id;
    int param_type;
    bool has_permission;

    // Exit if there are no keys containing reference following that need expanding. Nothing to do in this case.
    if (sp->keys.num_entries == 0)
    {
        return USP_ERR_OK;
    }

    STR_VECTOR_Init(&params);
    INT_VECTOR_Init(&perm);

    // Create a string vector containing the paths of all keys of all instances to get
    for (i = 0; i < instances->num_entries; i++)
    {
        for (j = 0; j < sp->keys.num_entries; j++)
        {
            ec = &sp->keys.vector[j];
            USP_SNPRINTF(temp, sizeof(temp), "%s%d.%s", resolved, instances->vector[i], ec->param);
            STR_VECTOR_Add(&params, temp);
            // Initialise each {instance, key} pair with valid permission, later on if any reference doesn't
            // have read permission, it will be updated to Invalid
            INT_VECTOR_Add(&perm, true);
        }
    }

    // Resolve all references within params vector inline, to leave only final parameter to get
    // this will only have list of parameter for which controller has read permission
    err = ResolveIntermediateReferences(&params, state, &perm);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // This checks permission on the fully resolved parameter list and also gets
    // group_ids and key_types of the parameters.
    ggv_index = 0;
    for (i = 0; i < params.num_entries; i++)
    {
        // mark permission vector as invalid if intermediate nodes do not have permissions
        if (perm.vector[i] == false)
        {
            INT_VECTOR_Add(&sp->ggv_indexes, INVALID);
        }
        else
        {
            // Check permission of final parameter list, mark ggv_index as invalid if controller
            // does not have read permission of that parameter,
            // or it should point to the valid ggv index which shall be used to do compare in DoUniqueKeysMatch
            err = CheckPathPermission(params.vector[i], state, &group_id, &param_type, &has_permission);
            if (err != USP_ERR_OK)
            {
                goto exit;
            }

            if (has_permission == true)
            {
                GROUP_GET_VECTOR_Add(&sp->ggv, params.vector[i], group_id);
                INT_VECTOR_Add(&sp->ggv_indexes, ggv_index);
                INT_VECTOR_Add(&sp->key_types, param_type);
                ggv_index++;
            }
            else
            {
                INT_VECTOR_Add(&sp->ggv_indexes, INVALID);
            }
        }
    }

exit:
    STR_VECTOR_Destroy(&params);
    INT_VECTOR_Destroy(&perm);

    return err;
}

/*********************************************************************//**
**
** ResolveIntermediateReferences
**
** De-references paths of params vector in place
**
** \param   params - pointer to path vectors with referenced parameters
** \param   state - pointer to structure containing state variables to use with this resolution
** \param   perm - pointer to vector, containing a boolean specifying whether the associated path (in params vector) has permission
**
** \return  USP_ERR_OK if successful, or no prams with referenced keys
**
**************************************************************************/
int ResolveIntermediateReferences(str_vector_t *params, resolver_state_t *state, int_vector_t *perm)
{
    int i;
    int index;
    int err;
    char temp[MAX_DM_PATH];
    char *ref;
    group_get_vector_t ggv;
    group_get_entry_t *gge;

    // Initialise with default values
    GROUP_GET_VECTOR_Init(&ggv);

    // Loop until all path references(+) of params vector resolved, or error occurred
    while (GroupReferencedParameters(params, state, perm, &ggv, &err))
    {
        index = 0;
        // exit if error occurred in GroupReferencedParameters call
        if (err != USP_ERR_OK)
        {
            goto exit;
        }

        // Get the values of referenced paths only
        GROUP_GET_VECTOR_GetValues(&ggv);
        for (i = 0; i < params->num_entries; i++)
        {
            // Update the params vector in-place with the new referenced path value and rest of the key
            // if the index has get permission
            ref = strchr(params->vector[i], '+');
            if ((ref != NULL) && (perm->vector[i] == true))
            {
                gge = &ggv.vector[index];
                index++;

                // Exit if an error occurred when getting the unique key param, or no parameter was provided
                if (gge->err_code != USP_ERR_OK)
                {
                    USP_ERR_SetMessage("%s: Failed when defererencing %s (%s)", __FUNCTION__, gge->path, gge->err_msg);
                    err = gge->err_code;
                    goto exit;
                }
                USP_ASSERT(gge->value != NULL);     // GROUP_GET_VECTOR_GetValues() should have set an error message if the vendor hook didn't set a value for the parameter
                ref[0] = '\0';

                // If the dereferenced path is not a fully qualified object, mark permission as false for this instance
                // to avoid further processing.
                // NOTE: This applies to both gets and sets. Sets are forgiving if ANY instance matches, when using keys containing references
                if(strlen(gge->value) == 0)
                {
                    if (IS_STRICT(state->op))
                    {
                        USP_ERR_SetMessage("%s: The dereferenced path contained in '%s' was not an object instance (got the value '%s')", __FUNCTION__, gge->path, gge->value);
                    }
                    perm->vector[i] = false;
                    continue;
                }
                USP_SNPRINTF(temp, sizeof(temp), "%s%s", gge->value, &ref[1]);

                // Free the previous value and update the new resolved path
                USP_FREE(params->vector[i]);
                params->vector[i] = USP_STRDUP(temp);
            }
        }
        GROUP_GET_VECTOR_Destroy(&ggv);
    }

exit:
    GROUP_GET_VECTOR_Destroy(&ggv);
    return err;
}

/*********************************************************************//**
**
** GroupReferencedParameters
**
** Create group get vector with referenced path present in params vector,
** and check permission for the considered parameters.
**
** \param   params - pointer to path vectors with referenced parameters
** \param   state - pointer to structure containing state variables to use with this resolution
** \param   perm - pointer to permission vector, containing permissions of the params
** \param   ggv - pointer to group get vector to populate with the intermediate referenced key
** \param   err - pointer to error variable, err in case controller does not have permission on referenced keys
**
** \return  True if params vector still have path with references
**
**************************************************************************/
bool GroupReferencedParameters(str_vector_t *params, resolver_state_t *state, int_vector_t *perm, group_get_vector_t *ggv, int *err)
{
    int i;
    char *path;
    char *ref;
    bool is_ref_found;
    int param_group_id;
    bool has_permission;

    // Initialise with default values
    is_ref_found = false;
    *err = USP_ERR_OK;

    // Form a vector containing the paths to the next set of references to resolve (ie the parameters to read containing references)
    for (i = 0; i < params->num_entries; i++)
    {
        path = params->vector[i];

        // No need to resolve this path further as controller does not have permission
        if (perm->vector[i] == false)
        {
            continue;
        }

        ref = strchr(path, '+');
        if (ref != NULL)
        {
            ref[0] = '\0';      // Temporarily truncate at the '+'
            *err = CheckPathPermission(path, state, &param_group_id, NULL, &has_permission);
            if (*err != USP_ERR_OK)
            {
                ref[0] = '+';
                goto exit;
            }

            // Only add the path to ggv, if the current object+key has permission
            // along with previous object+key pair
            if (has_permission == true)
            {
                is_ref_found = true;
                GROUP_GET_VECTOR_Add(ggv, path, param_group_id);
            }
            else
            {
                perm->vector[i] = false;
            }
            ref[0] = '+';      // Restore the '+'
        }
    }

exit:
    return is_ref_found;
}

/*********************************************************************//**
**
** CheckPathPermission
**
** Checks permission of the datamodel object path for unique key search
**
** \param   path - Datamodel parameter path
** \param   state - pointer to structure containing state variables to use with this resolution
** \param   gid - pointer to group_id variable to get the group_id of path object
** \param   param_type - pointer to type_flags to get the parameter type of path object
** \param   has_permission - pointer to varaibale in which to return whether there is permission to read this parameter
**
** \return  USP_ERR_OK if key exists in the DM
**
**************************************************************************/
int CheckPathPermission(char *path, resolver_state_t *state, int *gid, int *param_type, bool *has_permission)
{
    unsigned flags;
    unsigned short permission_bitmask;
    unsigned param_type_flags;
    int param_group_id;

    // Initialize with default values
    *has_permission = true;

    // Exit if the path is not a parameter
    flags = DATA_MODEL_GetPathProperties(path, state->combined_role, &permission_bitmask, &param_group_id, &param_type_flags, 0);
    if ((flags & PP_IS_PARAMETER) == 0)
    {
        USP_ERR_SetMessage("%s: Search key '%s' is not a parameter", __FUNCTION__, path);
        return USP_ERR_INVALID_PATH;
    }

    if ((permission_bitmask & PERMIT_GET) == 0)
    {
        *has_permission = false;
    }

    *gid = param_group_id;
    if (param_type)
    {
        *param_type = (int)param_type_flags;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetPermittedInstances
**
** Determines the instance numbers of a table that are permitted to be read
**
** \param   obj_path - path to a multi-instance object (unqualified)
** \param   iv - pointer to int vector in which to return the instance numbers of the object that are permitted to be read
** \param   state - pointer to structure containing state variables to use with this resolution
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetPermittedInstances(char *obj_path, int_vector_t *iv, resolver_state_t *state)
{
    int err;

    // Exit if unable to get the instances of this object
    err = DATA_MODEL_GetInstances(obj_path, iv);
    if (err != USP_ERR_OK)
    {
        // According to R.GET-0, if the path contains a search path (eg unique key), it acts as a filter, and should not generate an error if instance numbers do not exist
        if ((state->op == kResolveOp_Get) && (err == USP_ERR_OBJECT_DOES_NOT_EXIST))
        {
            err = USP_ERR_OK;
        }
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DoUniqueKeysMatch
**
** Determines whether a set of unique keys match
**
** \param   index - current instance index number for which unique key match is performed
** \param   sp - pointer to search parameter structure containing ggv_index, ggv and key_types for each valid {instance, key} pair
** \param   is_match - pointer to variable in which to return whether the unique keys match
**
** \return  USP_ERR_OK if no errors occurred
**
**************************************************************************/
int DoUniqueKeysMatch(int index, search_param_t *sp, bool *is_match)
{
    int i;
    int err;
    expr_comp_t *ec;
    group_get_entry_t *gge;
    bool result;
    unsigned type_flags;
    dm_cmp_cb_t cmp_cb;
    int perm_index;
    int ggv_index;

    // Assume that this instance does not match
    *is_match = false;
    perm_index = index * sp->keys.num_entries;

    // Iterate over all key expressions to match, exiting on the first one which isn't true
    for (i=0; i < sp->keys.num_entries; i++)
    {
        ggv_index = sp->ggv_indexes.vector[perm_index + i];

        // Exit if we previously determined that this instantiated key could not be used to match the instance because
        // either the controller did not have permissions, or the key pointed to an empty reference
        if (ggv_index == INVALID)
        {
            return USP_ERR_OK;
        }

        ec = &sp->keys.vector[i];
        gge = &sp->ggv.vector[ggv_index];
        type_flags = (unsigned) sp->key_types.vector[ggv_index];

        // Exit if an error occurred when getting the unique key param, or no parameter was provided
        if (gge->err_code != USP_ERR_OK)
        {
            USP_ERR_SetMessage("%s", gge->err_msg);
            return gge->err_code;
        }
        USP_ASSERT(gge->value != NULL);     // GROUP_GET_VECTOR_GetValues() should have set an error message if the vendor hook didn't set a value for the parameter

        // Determine the function to call to perform the comparison
        if (type_flags & (DM_INT | DM_UINT | DM_ULONG | DM_LONG | DM_DECIMAL))
        {
            cmp_cb = DM_ACCESS_CompareNumber;
        }
        else if (type_flags & DM_BOOL)
        {
            cmp_cb = DM_ACCESS_CompareBool;
        }
        else if (type_flags & DM_DATETIME)
        {
            cmp_cb = DM_ACCESS_CompareDateTime;
        }
        else
        {
            // Default, and also for DM_STRING, DM_BASE64, DM_HEXBIN
            cmp_cb = DM_ACCESS_CompareString;
        }

        // Exit if an error occurred when comparing the values
        // This could occur if the operator was invalid for the specified type, or type conversion failed
        err = cmp_cb(gge->value, ec->op, ec->value, &result);
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

    // Exit if unable to find node representing this object
    node = DM_PRIV_GetNodeFromPath(path, &inst, &is_qualified_instance, DONT_LOG_ERRS_FLAG);
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

    // Exit if unable to determine whether the object instances in the path exist
    err = DM_INST_VECTOR_IsExist(&inst, &exists);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if the object instances in the path do not exist
    if (exists == false)
    {
        return USP_ERR_OK;
    }

    len = strlen(path);
    USP_STRNCPY(child_path, path, sizeof(child_path));

    if (is_qualified_instance)
    {
        // Object is specified with trailing instance number or is a single instance object
        err = GetChildParams(child_path, len, node, &inst, state, state->depth);
    }
    else
    {
        // Object is specified without trailing instance number
        USP_ASSERT(node->type == kDMNodeType_Object_MultiInstance); // SingleInstance objects should have (is_qualified_instance==true), and hence shouldn't have got here
        err = GetChildParams_MultiInstanceObject(child_path, len, node, &inst, state, state->depth);
    }

    return err;
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
** \param   depth_remaining - number of hierarchical levels to continue to traverse in the data model
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetChildParams(char *path, int path_len, dm_node_t *node, dm_instances_t *inst, resolver_state_t *state, int depth_remaining)
{
    int err;
    dm_node_t *child;
    unsigned short permission_bitmask;
    bool add_to_vector;

    // Exit if we should abort recursing any further into the data model
    if (depth_remaining <= 0)
    {
        return USP_ERR_OK;
    }

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
                    err = GetChildParams(path, path_len+len, child, inst, state, depth_remaining-1);
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
                    err = GetChildParams_MultiInstanceObject(path, path_len+len, child, inst, state, depth_remaining-1);
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
                    permission_bitmask = DM_PRIV_GetPermissions(child, inst, state->combined_role, 0);
                    if (state->op == kResolveOp_GetBulkData)
                    {
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
                    else if (state->op == kResolveOp_SubsValChange)
                    {
                        // Only include parameters that are permitted and are not supposed to be ignored by value change
                        if ((permission_bitmask & PERMIT_SUBS_VAL_CHANGE) &&
                            ((child->registered.param_info.type_flags & DM_VALUE_CHANGE_WILL_IGNORE) == 0))
                        {
                            add_to_vector = true;
                        }
                    }
                    else if (state->op == kResolveOp_Get)
                    {
                        if (permission_bitmask & PERMIT_GET)
                        {
                            add_to_vector = true;
                        }
                    }
                }
                break;

            case kDMNodeType_AsyncOperation:
                permission_bitmask = DM_PRIV_GetPermissions(child, inst, state->combined_role, 0);
                if ((state->op == kResolveOp_SubsOper) && (permission_bitmask & PERMIT_SUBS_EVT_OPER_COMP))
                {
                    add_to_vector = true;
                }
                break;


            case kDMNodeType_Event:
                permission_bitmask = DM_PRIV_GetPermissions(child, inst, state->combined_role, 0);
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
        if (add_to_vector)
        {
            if (state->sv != NULL)
            {
                USP_SNPRINTF(&path[path_len], MAX_DM_PATH-path_len, ".%s", child->name);
                STR_VECTOR_Add(state->sv, path);
            }

            if (state->gv != NULL)
            {
                INT_VECTOR_Add(state->gv, child->group_id);
            }
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
** \param   depth_remaining - number of hierarchical levels to continue to traverse in the data model
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetChildParams_MultiInstanceObject(char *path, int path_len, dm_node_t *node, dm_instances_t *inst, resolver_state_t *state, int depth_remaining)
{
    int_vector_t iv;
    int instance;
    int len;
    int order;
    int i;
    int err;

    // Exit if we should abort recursing any further into the data model
    if (depth_remaining <= 0)
    {
        return USP_ERR_OK;
    }

    // Get an array of instances for this specific object
    INT_VECTOR_Init(&iv);
    err = DM_INST_VECTOR_GetInstances(node, inst, &iv);
    if (err != USP_ERR_OK)
    {
        err = USP_ERR_OK;   // Since this function is called when resolving partial paths for 'get' style requests, errors translate into no instances found
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
        inst->instances[order] = instance;

        // Get all child parameters of this object
        err = GetChildParams(path, path_len+len, node, inst, state, depth_remaining);
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
    int group_id;

    // Exit if the path did not match the properties we expected of it
    err = CheckPathProperties(path, state, &add_to_vector, &path_properties, &group_id);
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
        err = DATA_MODEL_GetInstancePaths(path, state->sv);
        return err;
    }

    // Handle resolving GetInstances
    if (state->op == kResolveOp_Instances)
    {
        if (state->flags & GET_ALL_INSTANCES)
        {
            err = DATA_MODEL_GetAllInstancePaths(path, state->sv);
        }
        else
        {
            err = DATA_MODEL_GetInstancePaths(path, state->sv);
        }
        FilterPathsByPermission(state->sv, PERMIT_GET_INST, 0, state->combined_role);  // Remove paths that don't have the PERMIT_GET_INST permission
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

    // And add the group_id (if required)
    if (state->gv != NULL)
    {
        INT_VECTOR_Add(state->gv, group_id);
    }

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
** \param   group_id - pointer to variable in which to return the group_id, or NULL if this is not required
**
** \return  USP_ERR_OK if path resolution should continue
**
**          NOTE: With forgiving operations such as get and delete, path resolution
**                continues, even if this path is not suitable for inclusion in the result vector
**
**************************************************************************/
int CheckPathProperties(char *path, resolver_state_t *state, bool *add_to_vector, unsigned *path_properties, int *group_id)
{
    unsigned property_flags;
    int err;
    unsigned short permission_bitmask;
    unsigned exec_flags;

    // Assume that the path should not be added to the vector
    *add_to_vector = false;

    // Calculate the flags controlling execution of DATA_MODEL_GetPathProperties()
    exec_flags = DONT_LOG_ERRS_FLAG;
    if (state->op == kResolveOp_Add)
    {
        exec_flags |= CALC_ADD_PERMISSIONS;
    }

    // Exit if the path does not exist in the schema
    property_flags = DATA_MODEL_GetPathProperties(path, state->combined_role, &permission_bitmask, group_id, NULL, exec_flags);
    *path_properties = property_flags;
    if ((property_flags & PP_EXISTS_IN_SCHEMA)==0)
    {
        USP_ERR_SetMessageIfAllowed("%s: Path (%s) does not exist in the schema", __FUNCTION__, path);
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
            if ((property_flags & PP_IS_PARAMETER)==0)
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
            if ((property_flags & PP_IS_OBJECT)==0)
            {
                USP_ERR_SetMessage("%s: Path (%s) is not an object", __FUNCTION__, path);
                err = (state->op == kResolveOp_Add) ? USP_ERR_OBJECT_NOT_CREATABLE : USP_ERR_NOT_A_TABLE;
                return err;
            }
            break;

        case kResolveOp_Oper:
        case kResolveOp_SubsOper:
            // Exit if the path does not represent an operation
            if ((property_flags & PP_IS_OPERATION)==0)
            {
                USP_ERR_SetMessage("%s: Path (%s) is not an operation", __FUNCTION__, path);
                err = USP_ERR_COMMAND_FAILURE;
                return err;
            }
            break;

        case kResolveOp_Event:
        case kResolveOp_SubsEvent:
            // Exit if the path does not represent an event
            if ((property_flags & PP_IS_EVENT)==0)
            {
                USP_ERR_SetMessage("%s: Path (%s) is not an event", __FUNCTION__, path);
                return USP_ERR_INVALID_PATH;
            }
            break;

        case kResolveOp_Any:
        case kResolveOp_StrictRef:
        case kResolveOp_ForgivingRef:
            // Not applicable, as this operation just validates the expression
            break;

        default:
            TERMINATE_BAD_CASE(state->op);
            break;
    }

    // Exit if the parameter should be ignored by value change subscriptions
    if ((state->op == kResolveOp_SubsValChange) && (property_flags & PP_VALUE_CHANGE_WILL_IGNORE))
    {
        return USP_ERR_OK;
    }

    // ===
    // Check that path contains (or does not contain) a fully qualified object
    // Check that the path is to (or is not to) a multi-instance object
    switch(state->op)
    {
        case kResolveOp_Get:
        case kResolveOp_Set:
        case kResolveOp_Oper:
        case kResolveOp_Event:
        case kResolveOp_SubsValChange:
        case kResolveOp_SubsOper:
        case kResolveOp_SubsEvent:
        case kResolveOp_GetBulkData:
            // Not applicable
            break;

        case kResolveOp_Del:
            // Exit if the path is not a fully qualified object instance
            if ((property_flags & PP_IS_OBJECT_INSTANCE)==0)
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
            if ((property_flags & PP_IS_MULTI_INSTANCE_OBJECT)==0)
            {
                USP_ERR_SetMessage("%s: Path (%s) is not a multi-instance object", __FUNCTION__, path);
                return USP_ERR_NOT_A_TABLE;
            }
            break;

        case kResolveOp_Add:
            // Exit if the path is a fully qualified object instance
            if (property_flags & PP_IS_OBJECT_INSTANCE)
            {
                if (property_flags & PP_IS_MULTI_INSTANCE_OBJECT)
                {
                    USP_ERR_SetMessage("%s: Path (%s) should not end in an instance number", __FUNCTION__, path);
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
        case kResolveOp_StrictRef:
        case kResolveOp_ForgivingRef:
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
            // Exit if the instance numbers do not exit, deciding whether this should be ignored or generate an error
            if ((property_flags & PP_INSTANCE_NUMBERS_EXIST)==0)
            {
                // If the path didn't contain a search path, then according to R-GET.0, it should return an error
                if (state->is_search_path == false)
                {
                    USP_ERR_SetMessage("%s: Invalid instance numbers in path %s", __FUNCTION__, path);
                    return USP_ERR_INVALID_PATH;
                }

                // Otherwise, the path did contain a search path, so gracefully ignore this resolved path
                return USP_ERR_OK;
            }
            break;

        case kResolveOp_Del:
        case kResolveOp_SubsValChange:
        case kResolveOp_SubsAdd:
        case kResolveOp_SubsDel:
        case kResolveOp_SubsOper:
        case kResolveOp_SubsEvent:
        case kResolveOp_GetBulkData:
            // It is not an error for instance numbers to not be instantiated for a delete or a subscription reference list
            // Both are forgiving, so just exit here, without adding the path to the vector
            if ((property_flags & PP_INSTANCE_NUMBERS_EXIST)==0)
            {
                return USP_ERR_OK;
            }
            break;

        case kResolveOp_Set:
        case kResolveOp_Add:
        case kResolveOp_Instances:
        case kResolveOp_Oper:
        case kResolveOp_Event:
            // Instance numbers must be instantiated (exist in data model)
            if ((property_flags & PP_INSTANCE_NUMBERS_EXIST)==0)
            {
                USP_ERR_SetMessage("%s: Object exists in schema, but instances are invalid: %s", __FUNCTION__, path);
                return USP_ERR_OBJECT_DOES_NOT_EXIST;
            }
            break;

        case kResolveOp_Any:
        case kResolveOp_StrictRef:
        case kResolveOp_ForgivingRef:
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
            // kResolveOp_Set resolves to objects, not parameters
            // So checking for permission to write is performed later in GROUP_SET_VECTOR_Add() when the parameter to set is known
            break;

        case kResolveOp_Add:
            // Permission Errors when performing a wildcarded Add request and allow_partial=true need to be included in the AddResponse
            // because each instance in the wildcard should be treated individually
            if ((permission_bitmask & PERMIT_ADD)==0)
            {
                if ( ((state->flags & DONT_LOG_RESOLVER_ERRORS)==0) && (err_str_vec != NULL) && (err_int_vec != NULL) )
                {
                    USP_ERR_SetMessageIfAllowed("%s: No permission to add to %s", __FUNCTION__, path);
                    STR_VECTOR_Add(err_str_vec, USP_ERR_GetMessage());
                    INT_VECTOR_Add(err_int_vec, USP_ERR_PERMISSION_DENIED);
                }
                return USP_ERR_OK;
            }
            break;

        case kResolveOp_Del:
            {
                str_vector_t child_objs;
                char parent_path[MAX_DM_PATH];

                // Exit if unable to get a vector of paths containing this object and all nested child objects to delete
                STR_VECTOR_Init(&child_objs);
                USP_SNPRINTF(parent_path, sizeof(parent_path), "%s.", path);
                err = PATH_RESOLVER_ResolveDevicePath(parent_path, &child_objs, NULL, kResolveOp_Instances, FULL_DEPTH, INTERNAL_ROLE, GET_ALL_INSTANCES);
                if (err != USP_ERR_OK)
                {
                    return err;
                }

                // Remove all paths which we have permission to delete, leaving only the paths that we do not have permission to delete
                FilterPathsByPermission(&child_objs, PERMIT_DEL, PERMIT_DEL, state->combined_role);

                // Exit if there isn't permission to delete this object and all nested child instances which currently exist
                if (child_objs.num_entries > 0)
                {
                    USP_ERR_SetMessageIfAllowed("%s: No permission to delete %s", __FUNCTION__, child_objs.vector[0]);
                    STR_VECTOR_Destroy(&child_objs);
                    return USP_ERR_PERMISSION_DENIED;
                }

                STR_VECTOR_Destroy(&child_objs);
            }
            break;

        case kResolveOp_Instances:
            // Checking for permission to read instances of this object
            // is performed later by DATA_MODEL_GetAllInstancePaths() or DATA_MODEL_GetInstancePaths()
            break;

        case kResolveOp_Oper:
            if ((permission_bitmask & PERMIT_OPER)==0)
            {
                USP_ERR_SetMessageIfAllowed("%s: No permission to perform operation %s", __FUNCTION__, path);
                return USP_ERR_COMMAND_FAILURE;
            }
            break;

        case kResolveOp_Event:
            if ((permission_bitmask & PERMIT_SUBS_EVT_OPER_COMP)==0)
            {
                USP_ERR_SetMessageIfAllowed("%s: No permission to subscribe to event %s", __FUNCTION__, path);
                return USP_ERR_PERMISSION_DENIED;
            }
            break;

        case kResolveOp_SubsEvent:
        case kResolveOp_SubsOper:
            if ((permission_bitmask & PERMIT_SUBS_EVT_OPER_COMP)==0)
            {
                return USP_ERR_OK;  // Ignore this path, if there is no permission
            }
            break;

        case kResolveOp_SubsAdd:
            if ((permission_bitmask & PERMIT_SUBS_OBJ_ADD)==0)
            {
                return USP_ERR_OK;  // Ignore this path, if there is no permission
            }
            break;

        case kResolveOp_SubsDel:
            if ((permission_bitmask & PERMIT_SUBS_OBJ_DEL)==0)
            {
                return USP_ERR_OK;  // Ignore this path, if there is no permission
            }
            break;

        case kResolveOp_SubsValChange:
            if ((permission_bitmask & PERMIT_SUBS_VAL_CHANGE)==0)
            {
                return USP_ERR_OK;  // Ignore this path, if there is no permission
            }
            break;

        case kResolveOp_GetBulkData:
            if ((permission_bitmask & PERMIT_GET)==0)
            {
                return USP_ERR_OK;  // Ignore this path, if there is no permission
            }
            break;

        case kResolveOp_Any:
        case kResolveOp_StrictRef:
        case kResolveOp_ForgivingRef:
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
** FilterPathsByPermission
**
** Filters the paths in the specified string vector, removing those that match the specified permission value
**
** \param   sv - string vector of paths to filter
** \param   permission_bitmask - bitmask of permission bits to test
** \param   required_permission - required value of permission bits to cause removal of the path from the string vector
** \param   combined_role - role to use when performing the filtering
**
** \return  None
**
**************************************************************************/
void FilterPathsByPermission(str_vector_t *sv, unsigned short permission_bitmask, unsigned short required_permission, combined_role_t *combined_role)
{
    int i;
    dm_node_t *node;
    dm_instances_t inst;
    unsigned short permission;

    // Iterate over all paths
    for (i=0; i < sv->num_entries; i++)
    {
        // Mark all paths which match the specified permission as NULL
        node = DM_PRIV_GetNodeFromPath(sv->vector[i], &inst, NULL, 0);
        permission = DM_PRIV_GetPermissions(node, &inst, combined_role, 0);
        if ((permission & permission_bitmask) == required_permission)
        {
            USP_FREE(sv->vector[i]);
            sv->vector[i] = NULL;
        }
    }

    STR_VECTOR_RemoveUnusedEntries(sv);
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

/*********************************************************************//**
**
** InitSearchParam
**
** Initialize search parameter set
**
** \param   sp - pointer to search parameter sets
**
** \return  None
**
**************************************************************************/
void InitSearchParam(search_param_t *sp)
{
    EXPR_VECTOR_Init(&sp->keys);
    INT_VECTOR_Init(&sp->ggv_indexes);
    GROUP_GET_VECTOR_Init(&sp->ggv);
    INT_VECTOR_Init(&sp->key_types);
}

/*********************************************************************//**
**
** DestroySearchParam
**
** Destroy search parameter set
**
** \param   sp - pointer to search parameter sets
**
** \return  None
**
**************************************************************************/
void DestroySearchParam(search_param_t *sp)
{
    EXPR_VECTOR_Destroy(&sp->keys);
    INT_VECTOR_Destroy(&sp->ggv_indexes);
    GROUP_GET_VECTOR_Destroy(&sp->ggv);
    INT_VECTOR_Destroy(&sp->key_types);
}

//------------------------------------------------------------------------------------------
// Code to test the PATH_RESOLVER_ValidatePath() function
#if 0
typedef struct
{
    char *path;
    subs_notify_t notify_type;
    int expected_err;
} validate_path_test_case_t;


validate_path_test_case_t validate_path_test_cases[] =
{
    {"",                                                                kSubNotifyType_ValueChange,         USP_ERR_OK },
    {"Device.",                                                         kSubNotifyType_OperationComplete,   USP_ERR_OK },
    {"Device.",                                                         kSubNotifyType_Event,               USP_ERR_OK },
    {"Device.",                                                         kSubNotifyType_None,                USP_ERR_OK },
    {"Device.",                                                         kSubNotifyType_ValueChange,         USP_ERR_RESOURCES_EXCEEDED },
    {"Device.",                                                         kSubNotifyType_ObjectCreation,      USP_ERR_NOT_A_TABLE },
    {"Device.",                                                         kSubNotifyType_ObjectDeletion,      USP_ERR_NOT_A_TABLE },
    {"NotDevice.",                                                      kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH },
    {"Device.Reboot",                                                   kSubNotifyType_OperationComplete,   USP_ERR_INVALID_PATH },
    {"Device.Reboot(",                                                  kSubNotifyType_OperationComplete,   USP_ERR_INVALID_PATH },
    {"Device.Reboot)",                                                  kSubNotifyType_OperationComplete,   USP_ERR_INVALID_PATH },
    {"Device.Reboot()",                                                 kSubNotifyType_OperationComplete,   USP_ERR_OK },
    {"Device.Boot",                                                     kSubNotifyType_Event,               USP_ERR_INVALID_PATH },
    {"Device.Boot!",                                                    kSubNotifyType_Event,               USP_ERR_OK },
    {"Device.Boot!",                                                    kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH },
    {"Device.Reboot()",                                                 kSubNotifyType_ObjectCreation,      USP_ERR_NOT_A_TABLE },
    {"Device.LocalAgent.Subscription.*.Enable",                         kSubNotifyType_ValueChange,         USP_ERR_OK },
    {"Device.LocalAgent.TransferComplete!",                             kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH },
    {"Device.DeviceInfo.FirmwareImage.*.Download()",                    kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH },
    {"Device.LocalAgent.Subscription.[Enable==\"true\"].Enable",        kSubNotifyType_ValueChange,         USP_ERR_OK },
    {"Device.LocalAgent.Subscription.[Enable==\"true\".Enable",         kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH_SYNTAX },
    {"Device.DeviceInfo.FirmwareImage.[Status==\"Available\"].Download()", kSubNotifyType_OperationComplete,USP_ERR_RESOURCES_EXCEEDED },
    {"Device.BulkData.Profile.[Enable==\"true\"].Push!",                kSubNotifyType_Event,               USP_ERR_RESOURCES_EXCEEDED },
    {"Device.LocalAgent.Subscription.ParamB+.Event!",                   kSubNotifyType_Event,               USP_ERR_RESOURCES_EXCEEDED },
    {"Device.DeviceInfo.ActiveFirmwareImage+.Download()",               kSubNotifyType_OperationComplete,   USP_ERR_RESOURCES_EXCEEDED },
    {"Device.BulkData.Profile.12X.Push!",                               kSubNotifyType_Event,               USP_ERR_INVALID_PATH },
    {"Device.BulkData.Profile.132.Push!",                               kSubNotifyType_Event,               USP_ERR_OK },
    {"Device.BulkData.Profile.1Enable",                                 kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH },
    {"Device.DeviceInfo.ActiveFirmwareImage+.Name",                     kSubNotifyType_ValueChange,         USP_ERR_OK },
    {"Device.LocalAgent.Subscription.*.+.Enable",                       kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH_SYNTAX },
    {"Device.DeviceInfo.ActiveFirmwareImage+Name",                      kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH },
    {"Device.DeviceInfo.ActiveFirmwareImage.+NameB",                    kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH },
    {"Device.BulkData.Profile.132.Push$!",                              kSubNotifyType_Event,               USP_ERR_INVALID_PATH },
    {"Device.DeviceInfo.ActiveFirmwareImage",                           kSubNotifyType_ValueChange,         USP_ERR_OK },
    {"Device.STOMP.Connection.1.X_ARRS-COM_EnableEncryption",           kSubNotifyType_ValueChange,         USP_ERR_OK },
    {"Device.BulkData.Profile.1.X_ARRS-COM_FailureCount.Connect",       kSubNotifyType_ValueChange,         USP_ERR_OK },
    {"Device.BulkData.Profile.*X_ARRS-COM_FailureCount.Connect",        kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH },
    {"Device.DeviceInfo..ActiveFirmwareImage",                          kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH_SYNTAX },
    {"Device*",                                                         kSubNotifyType_ObjectCreation,      USP_ERR_INVALID_PATH },
    {"Device.*.",                                                       kSubNotifyType_ObjectCreation,      USP_ERR_NOT_A_TABLE },
    {"Device.1.",                                                       kSubNotifyType_ObjectCreation,      USP_ERR_NOT_A_TABLE },
    {"Device.[ParamA==\"MyValue\"].ParamA",                             kSubNotifyType_ValueChange,         USP_ERR_NOT_A_TABLE },
    {"Device. LocalAgent.Subscription.9.Enable",                        kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH_SYNTAX },
    {"Device.LocalAgent.Subscription .8.Enable",                        kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH_SYNTAX },
    {"Device.\tLocalAgent.Subscription.*.Enable",                       kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH_SYNTAX },
    {"Device.LocalAgent.Subscription\t.*.Enable",                       kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH_SYNTAX },
    {"Device.LocalAgent.Subscription.[ID==\"boot\"].",                  kSubNotifyType_ObjectCreation,      USP_ERR_OK },
    {"Device.Reboot()",                                                 kSubNotifyType_None,                USP_ERR_OK },
    {"Device.Boot!",                                                    kSubNotifyType_None,                USP_ERR_OK },
    {"Device.Obj.[ObjB.ParamC==\"1\"].ParamA",                          kSubNotifyType_ValueChange,         USP_ERR_OK },
    {"Device.Obj.[ObjB.ParamC+.ParamD==\"1\"].ParamA",                  kSubNotifyType_ValueChange,         USP_ERR_OK },
    {"Device.Obj.*.*.",                                                 kSubNotifyType_ObjectCreation,      USP_ERR_INVALID_PATH_SYNTAX },
    {"Device.Obj.*.*.",                                                 kSubNotifyType_ObjectDeletion,      USP_ERR_INVALID_PATH_SYNTAX },
    {"Device.Obj.*.*.",                                                 kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH_SYNTAX },
    {"Device.Obj.[ObjB.ParamC+.ParamD==\"1\"].*.",                      kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH_SYNTAX },
    {"Device.Obj.*.[ObjB.ParamC+.ParamD==\"1\"].",                      kSubNotifyType_ValueChange,         USP_ERR_INVALID_PATH_SYNTAX },
    {"Device.Obj.[ObjB.ParamC+.ParamD==\"1\"].[ObjB.ParamC+.ParamD==\"1\"].",  kSubNotifyType_ValueChange,  USP_ERR_INVALID_PATH_SYNTAX },

};


void TestValidatePath(void)
{
    int i;
    int err;
    validate_path_test_case_t *test;
    int count = 0;

    for (i=0; i < NUM_ELEM(validate_path_test_cases); i++)
    {
        test = &validate_path_test_cases[i];
        printf("[%d] Testing '%s' (notify_type=%s)\n", i, test->path, TEXT_UTILS_EnumToString(test->notify_type, notify_types, NUM_ELEM(notify_types)) );
        err = PATH_RESOLVER_ValidatePath(test->path, test->notify_type);
        if (err != test->expected_err)
        {
            printf("ERROR: [%d] Test case result for '%s' is %d (expected %d)\n", i, test->path, err, test->expected_err);
            count++;
        }
    }

    printf("Failure count = %d\n", count);
}
#endif

