/**
 * \file inst_sel_vector.c
 * Copyright (C) 2025, Broadband Forum
 * Copyright (C) 2025, Vantiva Technologies SAS
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

#include "common_defs.h"
#include "data_model.h"
#include "inst_sel_vector.h"


//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
bool DoPermissionInstancesMatch(inst_sel_t *sel, dm_instances_t *inst, bool *again, unsigned flags);

/*********************************************************************//**
**
** INST_SEL_VECTOR_Init
**
** Initialises an permission instance vector structure
**
** \param   piv - pointer to structure to initialise
**
** \return  None
**
**************************************************************************/
void INST_SEL_VECTOR_Init(inst_sel_vector_t *isv)
{
    isv->vector = NULL;
    isv->num_entries = 0;
}

/*********************************************************************//**
**
** INST_SEL_VECTOR_Destroy
**
** Deinitialises the permission instance vector
**
** \param   isv - pointer to structure to free
** \param   destroy_entries - flag to determine whether to destroy the individual entries in the vector.
**                            If set to false, they are not owned by this vector and must not be freed
**
** \return  None
**
**************************************************************************/
void INST_SEL_VECTOR_Destroy(inst_sel_vector_t *isv, bool destroy_entries)
{
    int i;

    // Exit if vector is already empty
    if (isv->vector == NULL)
    {
        goto exit;
    }

    // Free all entries, but only if they are owned by this vector
    if (destroy_entries)
    {
        for (i=0; i < isv->num_entries; i++)
        {
            USP_FREE(isv->vector[i]);
        }
    }

    // Free the vector itself
    USP_SAFE_FREE(isv->vector);

exit:
    // Ensure structure is re-initialised
    isv->vector = NULL;
    isv->num_entries = 0;
}


/*********************************************************************//**
**
** INST_SEL_VECTOR_Fill
**
** Fills a permission vector with the specified number of entries
** Each entry is set to a default value containing wildcards for all of the instance numbers, and using the specified permission bitmask
**
** \param   isv - pointer to structure to initialise
** \param   num_entries - number of entries to fill the vector with
** \param   permission_bitmask - bitmask of permissions to initialize each entry with
**
** \return  None
**
**************************************************************************/
void INST_SEL_VECTOR_Fill(inst_sel_vector_t *isv, int num_entries, unsigned short permission_bitmask)
{
    int i;
    inst_sel_t *sel;

    USP_ASSERT(isv->vector==NULL);

    // Allocate the vector to fill in with entries
    isv->vector = USP_MALLOC(num_entries*sizeof(inst_sel_t *));
    isv->num_entries = num_entries;

    for (i=0; i<num_entries; i++)
    {
        // Allocate each entry, adding it to the vector
        sel = USP_MALLOC(sizeof(inst_sel_t));
        isv->vector[i] = sel;

        // Initialize each entry
        memset(sel, 0, sizeof(inst_sel_t));
        sel->permission_bitmask = permission_bitmask;
    }
}

/*********************************************************************//**
**
** INST_SEL_VECTOR_Add
**
** Adds the specified permission instance selector to the specified vector
**
** \param   isv - pointer to structure to initialise
** \param   sel - instance selector to add to the vector
**                NOTE: The vector contains only a pointer to the instance selector, rather than a copy of it
**
** \return  None
**
**************************************************************************/
void INST_SEL_VECTOR_Add(inst_sel_vector_t *isv, inst_sel_t *sel)
{
    int new_num_entries;

    new_num_entries = isv->num_entries + 1;
    isv->vector = USP_REALLOC(isv->vector, new_num_entries*sizeof(inst_sel_t *));
    isv->vector[ isv->num_entries ] = sel;
    isv->num_entries = new_num_entries;
}

/*********************************************************************//**
**
** INST_SEL_VECTOR_GetPermissionForInstance
**
** Determines the permissions bitmask, given the specified instance numbers
**
** \param   isv - pointer to ordered vector of instance-based permissions (low to high. high beats low)
** \param   inst - instance numbers of the path that we want to determine the permissions for
** \param   flags - Flags controlling execution of this function (eg CALC_ADD_PERMISSIONS)
**
** \return  permission bitmask for the specified instance
**
**************************************************************************/
unsigned short INST_SEL_VECTOR_GetPermissionForInstance(inst_sel_vector_t *isv, dm_instances_t *inst, unsigned flags)
{
    int i;
    bool is_match;
    inst_sel_t *sel;
    bool again = true;
    bool was_matched = false;
    unsigned short cumulative_permissions = PERMIT_ALL;

    USP_ASSERT(inst != NULL);

    // Traverse the vector from highest priority permissions to lowest priority ones
    i = isv->num_entries-1;
    while ((i>=0) && (again==true))
    {
        // Apply this permission's bitmask, if the path matches this selector
        sel = isv->vector[i];
        is_match = DoPermissionInstancesMatch(sel, inst, &again, flags);
        if (is_match)
        {
            cumulative_permissions &= sel->permission_bitmask;
            was_matched = true;
        }

        // Move to next lower priority permission
        i--;
    }

    // Exit if at least one permission matched a selector
    if (was_matched != false)
    {
        return cumulative_permissions;
    }

    // If none of the permissions match, then the default is for no permissions
    return 0;
}

/*********************************************************************//**
**
** DoPermissionInstancesMatch
**
** Determines whether the instances in the path match the selectors in the permission
**
** \param   sel - instance selector for a permission
** \param   inst - instance numbers of the path that we want to see if it is selected by the permission
**                 NOTE: This must contain instance numbers (or a wildcard) for all instances in the path that we're testing this permission against
**                       e.g. If the the path is to a table object, it must be qualified by an instance number or wildcard
** \param   again - pointer to variable in which to return whether the caller needs to continue traversing the permissions vector
** \param   flags - Flags controlling execution of this function (eg CALC_ADD_PERMISSIONS)
**
** \return  true if the permission matches the path's instance numbers, false otherwise
**
**************************************************************************/
bool DoPermissionInstancesMatch(inst_sel_t *sel, dm_instances_t *inst, bool *again, unsigned flags)
{
    int i;
    int selector;
    int order;

    // Assume that this selector will be an exact match, so the caller will not have to traverse any more of the permission vector
    // If it isn't, the code below will change this returned value
    *again = false;

    // Exit if there aren't any instance numbers in the path
    // In this case, we should only match permissions which also have no instance numbers
    if (inst->order == 0)
    {
        if (sel->order == 0)
        {
            return true;
        }
        else
        {
            *again = true;
            return false;
        }
    }

    // If the code gets here, there are instance numbers in the path
    // Iterate over the instance numbers in the path seeing if they match the selector
    order = MIN(sel->order, inst->order);    // We can only match if both the selector and the path cover the same order of instance numbers
    for (i=0; i < order; i++)
    {
        selector = sel->selectors[i];

        // Selector matches this instance, if the path contains a wildcard for instance number here
        if (inst->instances[i] == WILDCARD_INSTANCE)
        {
            if (selector != WILDCARD_INSTANCE)
            {
                *again = true;   // If the selector just matched because it was an instance number, then the caller needs
                                 // to keep collecting the permissions over all instance numbers until it hits a permission that applies to all
            }
            continue;
        }

        // Selector matches this path, if the path contains a wildcard for instance number here
        if (selector == WILDCARD_INSTANCE)
        {
            continue;
        }

        // Exit if the selector does not match this instance number in the path
        if (selector != inst->instances[i])
        {
            *again = true;
            return false;
        }
    }

    // Special exception for Add
    // Deny add permission on ObjA.* needs to deny any addition to ObjA table
    // But deny add permission on ObjA.1 needs to allow addition to ObjA table (it denies permission on any nested sub-tables of ObjA.1)
    // Without the code below, a deny add permission on ObjA.1 also prevents any addition to ObjA table
    if (flags & CALC_ADD_PERMISSIONS)
    {
        USP_ASSERT(inst->order > 0);
        order = inst->order - 1;
        if ((order < sel->order) && (sel->selectors[order] != WILDCARD_INSTANCE))
        {
            *again = true;
            return false;
        }
    }

    // If the code gets here, then the selector for this permission matched all the instance numbers in the path
    return true;
}

