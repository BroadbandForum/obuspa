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
 * \file dm_inst_vector.c
 *
 * Implements a data structure containing a list of dm_inst structures
 * This is basically a list of all object instances instantiated in the data model
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_defs.h"
#include "data_model.h"
#include "int_vector.h"
#include "dm_inst_vector.h"


//--------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
void AddObjectInstanceIfPermitted(dm_instances_t *inst, str_vector_t *sv, combined_role_t *combined_role);


/*********************************************************************//**
**
** DM_INST_VECTOR_Init
**
** Initialises a dm_inst vector
**
** \param   div - pointer to dm_instances vector structure to initialize
**
** \return  None
**
**************************************************************************/
void DM_INST_VECTOR_Init(dm_instances_vector_t *div)
{
    div->vector = NULL;
    div->num_entries = 0;
}

/*********************************************************************//**
**
** DM_INST_VECTOR_Destroy
**
** Frees up all memory used by the specified dm_instances_vector structure
**
** \param   div - pointer to dm_instances vector structure
**
** \return  None
**
**************************************************************************/
void DM_INST_VECTOR_Destroy(dm_instances_vector_t *div)
{
    if (div->vector != NULL)
    {
        USP_FREE(div->vector);
    }

    div->vector = NULL;
    div->num_entries = 0;
}

/*********************************************************************//**
**
** DM_INST_VECTOR_Add
**
** Adds the specified instance numbers and associated nodes to the dm_instances_vector vector
** NOTE: The instance is not added again, if it already exists
**
** \param   inst - pointer to instance structure to add to the dm_instances_vector vector
**                 contained within this structure is the top level multi-instance node which holds the dm_instances_vector
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DM_INST_VECTOR_Add(dm_instances_t *inst)
{
    int i;
    int size;
    dm_instances_t *oi;
    dm_node_t *top_node;
    dm_instances_vector_t *div;

    // Exit if there are no object instances to add
    // This is the case if this function is called for a parameter which does not have any object instances in it's path
    if (inst->order == 0)
    {
        return USP_ERR_OK;
    }

    // Determine which top level multi-instance node's DM instances array to add to
    USP_ASSERT(inst->order > 0);
    top_node = inst->nodes[0];
    USP_ASSERT(top_node != NULL);
    USP_ASSERT(top_node->type == kDMNodeType_Object_MultiInstance);
    div = &top_node->registered.object_info.inst_vector;

    // See if this instance already exists
    for (i=0; i < div->num_entries; i++)
    {
        // If this instance of the object already exists then exit, nothing more to do
        oi = &div->vector[i];
        if (memcmp(oi, inst, sizeof(dm_instances_t)) == 0)
        {
            return USP_ERR_OK;
        }        
    }

    // Otherwise, increase the size of the dm_instances_vector array
    size = (div->num_entries+1) * sizeof(dm_instances_t);
    div->vector = USP_REALLOC(div->vector, size);

    // And store this object instance
    memcpy(&div->vector[div->num_entries], inst, sizeof(dm_instances_t));
    div->num_entries++;

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DM_INST_VECTOR_Remove
**
** Deletes the specified instance numbers and associated nodes from the dm_instances_vector vector
** NOTE: This function deletes the instance number tree starting at the specified instance
** NOTE: The instance is not removed again, if it has already been removed
**
** \param   inst - pointer to instance structure to delete from the dm_instances_vector vector
**                 contained within this structure is the top level multi-instance node which holds the dm_instances_vector
**
** \return  None
**
**************************************************************************/
void DM_INST_VECTOR_Remove(dm_instances_t *inst)
{
    int i;
    int j;
    int order;
    dm_instances_t *oi;
    dm_node_t *top_node;
    dm_instances_vector_t *div;

    // Exit if there is no instance to remove
    if (inst->order == 0)
    {
        return;
    }

    // Determine which top level multi-instance node's DM instances array to remove from
    USP_ASSERT(inst->order > 0);
    top_node = inst->nodes[0];
    USP_ASSERT(top_node != NULL);
    USP_ASSERT(top_node->type == kDMNodeType_Object_MultiInstance);
    div = &top_node->registered.object_info.inst_vector;

    // Find this instance and all child nested instances and delete them
    j = 0;
    order = inst->order;
    for (i=0; i < div->num_entries; i++)
    {
        oi = &div->vector[i];
        if ((oi->order >= order) &&
            (memcmp(oi->nodes, inst->nodes, order*sizeof(dm_node_t *)) == 0) &&
            (memcmp(oi->instances, inst->instances, order*sizeof(int)) == 0))
        {
            // Delete this node. Nothing to do in this iteration of the loop - this value will be overwritten by further 
        }
        else
        {
            // Copy down later entries in the array, over ones which have been removed
            if (j < i)
            {
                memcpy(&div->vector[j], oi, sizeof(dm_instances_t));
            }

            j++;
        }
    }

    // NOTE: Don't bother reallocating the memory for the array (it could now be smaller).
    // It will be resized next time an instance is added.
    div->num_entries = j;
}

/*********************************************************************//**
**
** DM_INST_VECTOR_IsExist
**
** Determines whether the specified object instance exists in the data model
**
** \param   match - pointer to instances structure describing the instances to match against
**                 contained within this structure is the top level multi-instance node which holds the dm_instances_vector
**
** \return  true if the specified object instances exist in the data model
**
**************************************************************************/
bool DM_INST_VECTOR_IsExist(dm_instances_t *match)
{
    int i;
    dm_instances_t *inst;
    dm_node_t *top_node;
    dm_instances_vector_t *div;

    // Exit if the object is a single instance object - these always exist
    if (match->order == 0)
    {
        return true;
    }

    // Determine which top level multi-instance node's DM instances array to search in
    USP_ASSERT(match->order > 0);
    top_node = match->nodes[0];
    USP_ASSERT(top_node != NULL);
    USP_ASSERT(top_node->type == kDMNodeType_Object_MultiInstance);
    div = &top_node->registered.object_info.inst_vector;

    // Iterate over the array of object instances which are present in the data model
    for (i=0; i < div->num_entries; i++)
    {
        inst = &div->vector[i];
        if (inst->order >= match->order)
        {
            if ( (memcmp(inst->nodes, match->nodes, (match->order)*sizeof(dm_node_t *)) == 0) &&
                 (memcmp(inst->instances, match->instances, (match->order)*sizeof(int)) == 0) )
            {
                // All specified object instances match
                return true;
            }
        }
    }

    // If the code gets here, then no instances matched
    return false;
}

/*********************************************************************//**
**
** DM_INST_VECTOR_GetNextInstance
**
** Gets the next numbered instance for the specified object (given it's parent instance numbers)
**
** \param   node - pointer to object in data model
** \param   inst - pointer to instance structure specifying the object's parents and their instance numbers
**                 contained within this structure is the top level multi-instance node which holds the dm_instances_vector
** \param   next_instance - pointer to variable in which to return the next instance number
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DM_INST_VECTOR_GetNextInstance(dm_node_t *node, dm_instances_t *inst, int *next_instance)
{
    int i;
    int order;
    int instance;
    int highest_instance=0;       // highest instance number encountered so far
    dm_instances_t *oi;
    dm_node_t *top_node;
    dm_instances_vector_t *div;

    order = inst->order;            // NOTE: This may be 0 for a top level multi-instance node
    USP_ASSERT(order < MAX_DM_INSTANCE_ORDER);
    inst->nodes[order] = node;

    // Determine which top level multi-instance node's DM instances array to iterate over
    top_node = inst->nodes[0];
    USP_ASSERT(top_node != NULL);
    USP_ASSERT(top_node->type == kDMNodeType_Object_MultiInstance);
    div = &top_node->registered.object_info.inst_vector;

    // Iterate over the table of instance numbers, determining the highest instance number for the specified object
    for (i=0; i < div->num_entries; i++)
    {
        oi = &div->vector[i];
        if ((oi->order == order+1) &&
            (memcmp(oi->nodes, inst->nodes, (order+1)*sizeof(dm_node_t *)) == 0) &&
            (memcmp(oi->instances, inst->instances, order*sizeof(int)) == 0))
        {
            instance = oi->instances[order];
            if (instance > highest_instance)
            {
                highest_instance = instance;
            }
        }
    }

    *next_instance = highest_instance+1;
    inst->nodes[order] = NULL;          // Undo the changes made by this function to the inst array

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DM_INST_VECTOR_GetNumInstances
**
** Gets the number of instances of the specified object (given it's parent instance numbers)
**
** \param   node - pointer to object in data model
** \param   inst - pointer to instance structure specifying the object's parents and their instance numbers
**
** \return  Number of instances of the specified object
**
**************************************************************************/
int DM_INST_VECTOR_GetNumInstances(dm_node_t *node, dm_instances_t *inst)
{
    int i;
    int order;
    int count;
    dm_instances_t *oi;
    dm_node_t *top_node;
    dm_instances_vector_t *div;

    order = inst->order;           // NOTE: This may be 0 for a top level multi-instance node
    USP_ASSERT(order < MAX_DM_INSTANCE_ORDER);
    inst->nodes[order] = node;

    // Determine which top level multi-instance node's DM instances array to iterate over
    top_node = inst->nodes[0];
    USP_ASSERT(top_node != NULL);
    USP_ASSERT(top_node->type == kDMNodeType_Object_MultiInstance);
    div = &top_node->registered.object_info.inst_vector;

    // Iterate over the table of instance numbers, determining the highest instance number for the specified object
    count = 0;
    for (i=0; i < div->num_entries; i++)
    {
        oi = &div->vector[i];
        if ((oi->order == order+1) &&
            (memcmp(oi->nodes, inst->nodes, (order+1)*sizeof(dm_node_t *)) == 0) &&
            (memcmp(oi->instances, inst->instances, order*sizeof(int)) == 0))
        {
            count++;
        }
    }

    inst->nodes[order] = NULL;          // Undo the changes made by this function to the inst array

    return count;
}

/*********************************************************************//**
**
** DM_INST_VECTOR_GetInstances
**
** Gets a vector of the instance numbers for the specified object (given it's parent instance numbers)
**
** \param   node - pointer to object in data model
** \param   inst - pointer to instance structure specifying the object's parents and their instance numbers
** \param   iv - pointer to structure which will be populated with instance numbers by this function
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DM_INST_VECTOR_GetInstances(dm_node_t *node, dm_instances_t *inst, int_vector_t *iv)
{
    int i;
    int order;
    int instance;
    dm_instances_t *oi;
    int index;
    int err;
    dm_node_t *top_node;
    dm_instances_vector_t *div;

    order = inst->order;          // NOTE: This may be 0 for a top level multi-instance node
    USP_ASSERT(order < MAX_DM_INSTANCE_ORDER);
    inst->nodes[order] = node;
    INT_VECTOR_Init(iv);

    // Determine which top level multi-instance node's DM instances array to iterate over
    top_node = inst->nodes[0];
    USP_ASSERT(top_node != NULL);
    USP_ASSERT(top_node->type == kDMNodeType_Object_MultiInstance);
    div = &top_node->registered.object_info.inst_vector;

    // Iterate over the instances array, finding the objects which match, and their instances
    for (i=0; i < div->num_entries; i++)
    {
        oi = &div->vector[i];
        if ((oi->order >= order+1) &&
            (memcmp(oi->nodes, inst->nodes, (order+1)*sizeof(dm_node_t *)) == 0) &&
            (memcmp(oi->instances, inst->instances, order*sizeof(int)) == 0))
        {
            instance = oi->instances[order];

            // Add the instance to the array (if it has not been added already)
            index = INT_VECTOR_Find(iv, instance);
            if (index == INVALID)
            {
                // Exit if array is already full
                err = INT_VECTOR_Add(iv, instance);
                if (err != USP_ERR_OK)
                {
                    goto exit;
                }
            }
        }
    }

    err = USP_ERR_OK;

exit:
    inst->nodes[order] = NULL;          // Undo the changes made by this function to the inst array
    return err;
}

/*********************************************************************//**
**
** DM_INST_VECTOR_Dump
**
** Prints out the Object Instances array
**
** \param   div - pointer to dm_instances vector structure
**
** \return  None
**
**************************************************************************/
void DM_INST_VECTOR_Dump(dm_instances_vector_t *div)
{
    int i;
    dm_instances_t *inst;
    dm_node_t *node;
    char path[MAX_DM_PATH];

    for (i=0; i < div->num_entries; i++)
    {
        inst = &div->vector[i];
        USP_ASSERT(inst->order >= 1);
        node = inst->nodes[inst->order - 1];
        DM_PRIV_FormPath_FromDM(node, inst, path, sizeof(path));

        USP_DUMP("%s", path);
    }
}

/*********************************************************************//**
**
** DM_INST_VECTOR_GetAllInstancePaths_Unqualified
**
** Returns a string vector containing the paths of all instances to the specified 
** unqualified multi-instance object and recursively all child instances
** This function expects the dm_instances_t structure to contain only the node's parents and parent instances
**
** \param   node - pointer to multi-instance object in data model that we want to get the instances of
** \param   inst - pointer to instance structure specifying the object's parents and their instance numbers
** \param   sv - pointer to structure which will be populated with paths to the instances of the object by this function
**               NOTE: The caller must initialise this structure. This function adds to this structure, it does not initialise it.
** \param   combined_role - role to use to check that object instances may be returned.  If set to INTERNAL_ROLE, then full permissions are always returned
**
** \return  None
**
**************************************************************************/
void DM_INST_VECTOR_GetAllInstancePaths_Unqualified(dm_node_t *node, dm_instances_t *inst, str_vector_t *sv, combined_role_t *combined_role)
{
    int i;
    int order;
    dm_instances_t *oi;
    dm_node_t *top_node;
    dm_instances_vector_t *div;

    order = inst->order;          // NOTE: This may be 0 for a top level multi-instance node
    USP_ASSERT(order < MAX_DM_INSTANCE_ORDER);
    inst->nodes[order] = node;

    // Determine which top level multi-instance node's DM instances array to iterate over
    top_node = inst->nodes[0];
    USP_ASSERT(top_node != NULL);
    USP_ASSERT(top_node->type == kDMNodeType_Object_MultiInstance);
    div = &top_node->registered.object_info.inst_vector;

    // Iterate over the instances array, finding all objects which match, and their instances
    for (i=0; i < div->num_entries; i++)
    {
        oi = &div->vector[i];
        if ((oi->order >= order+1) &&
            (memcmp(oi->nodes, inst->nodes, (order+1)*sizeof(dm_node_t *)) == 0) &&
            (memcmp(oi->instances, inst->instances, order*sizeof(int)) == 0))
        {
            AddObjectInstanceIfPermitted(oi, sv, combined_role);
        }
    }

    // Undo the changes made by this function to the inst array
    inst->nodes[order] = NULL;
}

/*********************************************************************//**
**
** DM_INST_VECTOR_GetAllInstancePaths_Qualified
**
** Returns a string vector containing the paths of all instances to the specified 
** qualified multi-instance object and recursively all child instances
** This function expects the dm_instances_t structure to contain the object instances to match
**
** \param   inst - pointer to instance structure specifying the object and instance numbers to match
** \param   sv - pointer to structure which will be populated with paths to the instances of the object by this function
**               NOTE: The caller must initialise this structure. This function adds to this structure, it does not initialise it.
** \param   combined_role - role to use to check that object instances may be returned.  If set to INTERNAL_ROLE, then full permissions are always returned
**
** \return  None
**
**************************************************************************/
void DM_INST_VECTOR_GetAllInstancePaths_Qualified(dm_instances_t *inst, str_vector_t *sv, combined_role_t *combined_role)
{
    int i;
    int order;
    dm_instances_t *oi;
    dm_node_t *top_node;
    dm_instances_vector_t *div;

    order = inst->order;
    USP_ASSERT(order > 0);
    USP_ASSERT(order < MAX_DM_INSTANCE_ORDER);

    // Determine which top level multi-instance node's DM instances array to iterate over
    top_node = inst->nodes[0];
    USP_ASSERT(top_node != NULL);
    USP_ASSERT(top_node->type == kDMNodeType_Object_MultiInstance);
    div = &top_node->registered.object_info.inst_vector;

    // Iterate over the instances array, finding all objects which match, and their instances
    for (i=0; i < div->num_entries; i++)
    {
        oi = &div->vector[i];
        if ((oi->order >= order) &&
            (memcmp(oi->nodes, inst->nodes, order*sizeof(dm_node_t *)) == 0) &&
            (memcmp(oi->instances, inst->instances, order*sizeof(int)) == 0))
        {
            AddObjectInstanceIfPermitted(oi, sv, combined_role);
        }
    }
}

/*********************************************************************//**
**
** AddObjectInstanceIfPermitted
**
** Adds the specified object instance, to the string vector, if the role permits its instance numbers to be read
**
** \param   inst - pointer to instance structure specifying the object and its instance numbers
** \param   sv - pointer to structure which will be populated with paths to the instances of the object by this function
**               NOTE: The caller must initialise this structure. This function adds to this structure, it does not initialise it.
** \param   combined_role - role to use to check that object instances may be returned.  If set to INTERNAL_ROLE, then full permissions are always returned
**
** \return  None
**
**************************************************************************/
void AddObjectInstanceIfPermitted(dm_instances_t *inst, str_vector_t *sv, combined_role_t *combined_role)
{
    dm_node_t *node;
    unsigned short permission_bitmask;
    char path[MAX_DM_PATH];

    // Exit if the current role does not have permission to return this object instance in the string vector
    node = inst->nodes[inst->order-1];
    permission_bitmask = DM_PRIV_GetPermissions(node, combined_role);
    if ((permission_bitmask & PERMIT_GET_INST)==0)
    {
        return;
    }

    // Convert the dm_instances_t structure into a path
    DM_PRIV_FormPath_FromDM(node, inst, path, sizeof(path));
    
    // Add the path to the string vector
    STR_VECTOR_Add(sv, path);
}




