/*
 *
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

/**
 * \file se_cache.c
 *
 * Implements and maintains a cache of instance numbers matching a unique key search expression (SE)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_defs.h"
#include "se_cache.h"
#include "inst_sel_vector.h"
#include "group_get_vector.h"
#include "dm_inst_vector.h"
#include "se_cache.h"
#include "usp_broker.h"


//--------------------------------------------------------------------
// Structure representing the search expression for an instance that we'd like to know the instance number of
typedef struct
{
    char *param_name;                   // Name of the parameter in the search expression to match
    char *param_value;                  // Value of the parameter in the search expression to match
    int last_known_instance;            // Last known instance number in the table which matches this search expression or UNKNOWN_INSTANCE if this is not known yet
                                        // We remember the last_known_instance rather than immediately setting it back to UNKNOWN_INSTANCE
                                        // to avoid race hazards when the permission is not applied immediely after the instance has been deleted

    bool is_stale;                      // Determines whether we know that the last_known_instance has been deleted

    inst_sel_vector_t  selectors;       // Vector of controller trust permissions which contain this search expression and which should be fixed up when the instance number is known
} se_watch_t;

//--------------------------------------------------------------------
// Vector of search expressions to match for a particular table
typedef struct
{
    se_watch_t *vector;
    int num_entries;
} se_watch_vector_t;

//--------------------------------------------------------------------
// Structure representing a table object which should be watched for instance number changes
typedef struct
{
    char *table_path;               // Full path to this table (excluding trailing dot and no {i})
    int table_path_len;             // length of the table_path string (used to speed up searching this table)
    dm_node_t *table_node;          // Node in the data model matching this table. (This structure does not own the node)
    se_watch_vector_t se_to_watch;  // Vector of search expressions matching instance numbers to watch in this table

#ifndef REMOVE_USP_BROKER
    // Following parameters are only used if the table is implemented by a USP Service
    int watch_subs_instances[2];  // Array containing the Instance numbers of the object creation/deletion watch subscriptions.
                                  // Instances in the array are set to INVALID if no watch subscriptions are set on the USP Service
#endif

} table_watch_t;

//--------------------------------------------------------------------
// Vector containing all tables to watch for instance number changes
typedef struct
{
    table_watch_t *vector;
    int num_entries;
} table_watch_vector_t;

static table_watch_vector_t tables_to_watch;

//------------------------------------------------------------------------------
// Boolean used to hold off search expression resolution until the whole of the data model has been started (ie internal data structures seeded)
static bool allow_SE_resolution = false;

//--------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
void TableWatchVector_Init(table_watch_vector_t *twv);
void TableWatchVector_Destroy(table_watch_vector_t *twv);
table_watch_t *TableWatchVector_Add(table_watch_vector_t *twv, char *path, dm_node_t *node);
table_watch_t *TableWatchVector_FindByTableName(table_watch_vector_t *twv, char *path);
table_watch_t *TableWatchVector_FindByNode(table_watch_vector_t *twv, dm_node_t *node);
void SeWatchVector_Init(se_watch_vector_t *sev);
void SeWatchVector_Destroy(se_watch_vector_t *sev);
se_watch_t *SeWatchVector_Add(se_watch_vector_t *sev, char *param, char *value);
se_watch_t *SeWatchVector_FindByParam(se_watch_vector_t *sev, char *param, char *value);
void TableWatchVector_Remove(table_watch_vector_t *twv, int index);
void SeWatchVector_Remove(se_watch_vector_t *sev, int index);
void AttemptToResolveAllSEOnTable(table_watch_t *tw);
void FixupInstanceNumberForSE(se_watch_t *se, int instance);
table_watch_t *TableWatchVector_FindByInstantiatedPath(table_watch_vector_t *twv, char *path, int *instance);
char *FindFirstInstanceNumber(char *path);
int CalcFirstInstanceNumber(char *p);
void ObtainUnresolvedSEKeys(char *path, table_watch_t *tw, kv_vector_t *keys);
int Memrcmp(char *s1, char *s2, int len);
se_watch_t *SeWatchVector_FindBySelector(se_watch_vector_t *sev, inst_sel_t *sel);
int ResolvePermSE_NonUspService(dm_node_t *node, int group_id, char *table, char *param, char *value);

/*********************************************************************//**
**
** SE_CACHE_Init
**
** Initialises the search expression cache
**
** \param   None
**
** \return  None
**
**************************************************************************/
void SE_CACHE_Init(void)
{
    TableWatchVector_Init(&tables_to_watch);
}

/*********************************************************************//**
**
** SE_CACHE_Destroy
**
** Frees up all memory used by the search expression cache
**
** \param   None
**
** \return  None
**
**************************************************************************/
void SE_CACHE_Destroy(void)
{
    TableWatchVector_Destroy(&tables_to_watch);
}

/*********************************************************************//**
**
** SE_CACHE_WatchUniqueKey
**
** Registers an instance selector associated with the specified search expression based permission
** The instance number in the selector will be updated when the search expression matches (or ceases to match) an instance in the table
** This function attempts to determine the instance number now, but will also update upon future changes until the selector is unwatched
**
** \param   node - data model node representing the table
** \param   table - name of the table to watch (excluding trailing dot and no {i})
** \param   param - name of the unique key parameter to match the instance number of
** \param   value - name of the unique key parameter's value to match the instance number of
** \param   sel - permission instance selector to keep updated
**
** \return  None
**
**************************************************************************/
void SE_CACHE_WatchUniqueKey(dm_node_t *node, char *table, char *param, char *value, inst_sel_t *sel)
{
    table_watch_t *tw;
    se_watch_t *se;
    int instance;

    // Mark this selector as being watched, and its instance number as unknown (it may be resolved later in this function)
    sel->is_watching = true;
    sel->selectors[0] = UNKNOWN_INSTANCE;

    // Find or add the table to watch
    tw = TableWatchVector_FindByNode(&tables_to_watch, node);
    if (tw == NULL)
    {
        tw = TableWatchVector_Add(&tables_to_watch, table, node);
    }

    // Find or add the search expression to watch in this table
    se = SeWatchVector_FindByParam(&tw->se_to_watch, param, value);
    if (se == NULL)
    {
        se = SeWatchVector_Add(&tw->se_to_watch, param, value);
    }

    // Add this permission instance selector to the list of permissions which need updating for this search expression
    USP_ASSERT( INST_SEL_VECTOR_Find(&se->selectors, sel) == INVALID);
    INST_SEL_VECTOR_Add(&se->selectors, sel);

    // Exit if the instance number matching this search expression is known
    if (se->last_known_instance != UNKNOWN_INSTANCE)
    {
        sel->selectors[0] = se->last_known_instance;
        return;
    }

    // Exit if we shouldn't attempt to resolve the instance number yet. It will be done later by calling SE_CACHE_StartSEResolution()
    // (attempting to resolve a part of the data model before it has been started is likely to result in failure)
    if (allow_SE_resolution == false)
    {
        return;
    }

#ifndef REMOVE_USP_BROKER
    if (USP_BROKER_IsUspService(node->group_id))
    {
        // Handle resolving SE based permissions on USP Services here
        instance = USP_BROKER_ResolveSeInstance(node->group_id, table, param, value);
    }
    else
#endif
    {
        // Handle resolving SE based permissions on non-USP Services here
        instance = ResolvePermSE_NonUspService(node, node->group_id, table, param, value);
    }

    // Fixup the selectors, if the search expression was resolved
    if (instance != INVALID)
    {
        FixupInstanceNumberForSE(se, instance);
    }
}

/*********************************************************************//**
**
** SE_CACHE_UnwatchUniqueKey
**
** Deregisters the instance selector from being updated when the search expression matches (or ceases to match) an instance
**
** \param   sel - permission instance selector to stop keeping updated
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void SE_CACHE_UnwatchUniqueKey(inst_sel_t *sel)
{
    int i, j, k;
    table_watch_t *tw;
    se_watch_t *se;

    // Iterate over all selectors, finding the one which matches and removing it
    for (i=0; i < tables_to_watch.num_entries; i++)
    {
        tw = &tables_to_watch.vector[i];

        for (j=0; j < tw->se_to_watch.num_entries; j++)
        {
            se = &tw->se_to_watch.vector[j];

            for (k=0; k < se->selectors.num_entries; k++)
            {
                if (se->selectors.vector[k] == sel)
                {
                    // Remove this selector from watching the table, and mark it as not being watched
                    INST_SEL_VECTOR_Remove(&se->selectors, k, false);
                    sel->is_watching = false;

                    // Remove the search expression, if we've just removed the last permission selector for this search expression
                    if (se->selectors.num_entries == 0)
                    {
                        SeWatchVector_Remove(&tw->se_to_watch, j);

                        // Remove the watch on the table, if we've just removed the last search expression watching this table
                        if (tw->se_to_watch.num_entries == 0)
                        {
#ifndef REMOVE_USP_BROKER
                            // First remove subscriptions on the USP Service, watching for object creation/deletion notifications
                            if (tw->watch_subs_instances[0] != INVALID)
                            {
                                USP_ASSERT(tw->watch_subs_instances[1] != INVALID);
                                USP_BROKER_UnwatchTable(tw->table_path, tw->watch_subs_instances);
                            }
#endif
                            // Then remove from the SE cache structure
                            TableWatchVector_Remove(&tables_to_watch, i);
                        }
                    }
                    return;
                }
            }
        }
    }
}

/*********************************************************************//**
**
** SE_CACHE_StartSEResolution
**
** Starts resolving the search expressions used by permissions
** This function is called after the data model has been started
** Resolution is not started earlier, because this is likley to result in failure
** as the internal data structures caching the data model do not exist
** Also it's more efficient to resolve multiple permissions that involve the same search expression at the same time (here !)
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void SE_CACHE_StartSEResolution(void)
{
    int i;
    table_watch_t *tw;

    // This function is called after the whole of the internal data model has been started, so we can now allow
    // search expression resolution when a permission is added
    allow_SE_resolution = true;

    // Attempt to resolve all search expressions that were added before the whole of the internal data model had been started
    for (i=0; i < tables_to_watch.num_entries; i++)
    {
        tw = &tables_to_watch.vector[i];
        AttemptToResolveAllSEOnTable(tw);
    }
}

#ifndef REMOVE_USP_BROKER
/*********************************************************************//**
**
** SE_CACHE_WatchAllUniqueKeysOnUspService
**
** Creates object creation/deletion subscriptions on all tables owned by the specified USP Service
** This function is called when a USP Service has registered
**
** \param   group_id - Identifies the USP Service
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void SE_CACHE_WatchAllUniqueKeysOnUspService(int group_id)
{
    int i;
    table_watch_t *tw;
    dm_node_t *node;

    // This function is called after the whole of the internal data model has been started, so we can now allow
    // search expression resoultion when a permission is added
    allow_SE_resolution = true;

    // Attempt to resolve all search expressions that were added before the whole of the internal data model had been started
    for (i=0; i < tables_to_watch.num_entries; i++)
    {
        tw = &tables_to_watch.vector[i];

        node = DM_PRIV_GetNodeFromPath(tw->table_path, NULL, NULL, DONT_LOG_ERRORS);
        if ((node != NULL) && (node->group_id == group_id))
        {
            USP_BROKER_WatchTable(tw->table_path, tw->watch_subs_instances);
        }
    }
}
#endif

/*********************************************************************//**
**
** SE_CACHE_NotifyInstanceAdded
**
** Called when an instance has been added, so that any search expression based permissions matching it can be resolved
**
** \param   path - Path of the instance that has been added (may contain trailing dot after the instance number)
** \param   keys - key value vector containing the unique keys for this instance or NULL if this function should obtain the keys
**
** \return  None
**
**************************************************************************/
void SE_CACHE_NotifyInstanceAdded(char *path, kv_vector_t *keys)
{
    int instance;
    int i;
    table_watch_t *tw;
    se_watch_t *se;
    int index;
    kv_vector_t params;

    // Exit if this path does not match any tables that we're watching, or the path was badly formed
    tw = TableWatchVector_FindByInstantiatedPath(&tables_to_watch, path, &instance);
    if (tw == NULL)
    {
        return;
    }

    // Obtain the unique keys for this instance, if they weren't provided by the caller
    KV_VECTOR_Init(&params);
    if (keys == NULL)
    {
        // Exit if there are no more search expressions that need resolving
        ObtainUnresolvedSEKeys(path, tw, &params);
        if (params.vector == NULL)
        {
            return;
        }
        keys = &params;
    }

    // Iterate over all search expressions that we're watching for on this table
    for (i=0; i < tw->se_to_watch.num_entries; i++)
    {
        se = &tw->se_to_watch.vector[i];

        // Skip this search expression, if we already know it's instance number (and the instance hadn't been deleted)
        if ((se->last_known_instance != UNKNOWN_INSTANCE) && (se->is_stale == false))
        {
            continue;
        }

        // Skip this search expression, if the parameter in the search expression is not one of the unique keys we've been provided with
        se = &tw->se_to_watch.vector[i];
        index = KV_VECTOR_FindKey(keys, se->param_name, 0);
        if (index == INVALID)
        {
            continue;
        }

        // Skip this search expression, if the unique key's value for this instance is not the one we're interested in for this search expression
        if (strcmp(keys->vector[index].value, se->param_value) != 0)
        {
            continue;
        }

        // Update the instance number in all permissions which are watching this search expression
        FixupInstanceNumberForSE(se, instance);
    }

    // Clean up if this function obtained the values of the unique keys
    if (params.vector != NULL)
    {
        KV_VECTOR_Destroy(&params);
    }
}

/*********************************************************************//**
**
** SE_CACHE_NotifyInstanceDeleted
**
** Called when an instance has been deleted, so that any search expression based permissions which had previously matched it
** can be marked as having a stale instance number
** We do this rather than marking the instance as UNKNOWN_INSTANCE to avoid race hazards when the permission should still be applied after the instance has been deleted
** (eg An ObjectDeletion notification for the instance received after watch deletion notification still needs to be blocked from being sent)
**
** \param   path - path to the deleted instance containing instance number (may contain trailing dot after the instance number)
**                 NOTE: This path may contain multiple instance numbers, if the instance deleted was for a nested multi-instance table
**
** \return  None
**
**************************************************************************/
void SE_CACHE_NotifyInstanceDeleted(char *path)
{
    int i;
    table_watch_t *tw;
    se_watch_t *se;
    int instance;

    // Exit if this path does not match any tables that we're watching, or the path was badly formed
    tw = TableWatchVector_FindByInstantiatedPath(&tables_to_watch, path, &instance);
    if (tw == NULL)
    {
        return;
    }

    // Mark the instance number as being stale in all permissions which match this instance number
    for (i=0; i < tw->se_to_watch.num_entries; i++)
    {
        se = &tw->se_to_watch.vector[i];
        if (se->last_known_instance == instance)
        {
            se->is_stale = true;
        }
    }
}

/*********************************************************************//**
**
** SE_CACHE_HandleUspServiceDisconnect
**
** Called when a USP Service has disconnected
** NOTE: This function is more efficient than calling SE_CACHE_UnwatchUniqueKey() multiple times
**       and does not attempt to delete the watch subscriptions on the (now disconnected) USP Service
**
** \param   group_id - Identifies the USP Service
**
** \return  None
**
**************************************************************************/
void SE_CACHE_HandleUspServiceDisconnect(int group_id)
{
    int i, j, k;
    table_watch_t *tw;
    se_watch_t *se;
    inst_sel_t *sel;
    int count = 0;

    // Iterate over all tables being watched, processing those that are owned by the USP Service
    // and moving down any which aren't owned by the USP Service
    for (i=0; i < tables_to_watch.num_entries; i++)
    {
        tw = &tables_to_watch.vector[i];
        if (tw->table_node->group_id == group_id)
        {
            // Iterate over all search expresssions on this table
            for (j=0; j < tw->se_to_watch.num_entries; j++)
            {
                se = &tw->se_to_watch.vector[j];

                // Iterate over all selectors using this search expression, marking them as not being watched
                for (k=0; k < se->selectors.num_entries; k++)
                {
                    sel = se->selectors.vector[k];
                    sel->is_watching = false;
                }

                // Free all memory used by this search expression entry
                // NOTE: We don't need to free any of the selectors in the selectors vector, as ownership of them stays with the ctrust permission
                USP_FREE(se->param_name);
                USP_FREE(se->param_value);
                USP_SAFE_FREE(se->selectors.vector);
            }

            // Free all memory used by this table watch entry
            USP_FREE(tw->table_path);
            USP_SAFE_FREE(tw->se_to_watch.vector);
        }
        else
        {
            // Move down any entries which are still in use, compacting the table watch vector
            if (i != count)
            {
                memmove(&tables_to_watch.vector[count], tw, sizeof(table_watch_t));
            }
            count++;
        }
    }

    // Save the new number of entries in the vector
    tables_to_watch.num_entries = count;
}

/*********************************************************************//**
**
** SE_CACHE_ForceUpdatePermissions
**
** This function resolves all SE based permissions on the specified table, if they have not already been done this message processing cycle
** This function is called only for non USP Service owned tables that use the refresh instances vendor hook
** Because the refresh instances vendor hook is used, we have to resolve SE based permissions for this table on demand
**
** \param   node - pointer to node in the data model representing the table to update
**
** \return  None
**
**************************************************************************/
void SE_CACHE_RefreshPermissions(dm_node_t *node)
{
    int i;
    table_watch_t *tw;
    se_watch_t *se;
    group_get_vector_t ggv;
    char buf[MAX_DM_PATH];
    group_get_entry_t *gge;
    int index;
    int unknown_count;
    bool is_exist;

    // Exit if there are no SE based permissions on this table
    tw = TableWatchVector_FindByNode(&tables_to_watch, node);
    if (tw == NULL)
    {
        return;
    }

    // Iterate over all search expressions to watch, forming a group get vector of all parameters identifying currently resolved permissions
    // We will use this to check if the instance number still matches the search expression by getting the parameter
    GROUP_GET_VECTOR_Init(&ggv);
    for (i=0; i < tw->se_to_watch.num_entries; i++)
    {
        se = &tw->se_to_watch.vector[i];
        if ((se->last_known_instance != UNKNOWN_INSTANCE) && (se->is_stale == false))
        {
            is_exist = DM_INST_VECTOR_DoesFirstLevelInstanceExist(node, se->last_known_instance);
            if (is_exist)
            {
                // The instance still exists, so get the parameter to see if it still matches the search expression
                USP_SNPRINTF(buf, sizeof(buf), "%s.%d.%s", tw->table_path, se->last_known_instance, se->param_name);
                GROUP_GET_VECTOR_Add(&ggv, buf, node->group_id);   // NOTE: We can use the group_id of the table for the group_id of the parameter because it cannot sensibly be owned by a different data model provider component
            }
            else
            {
                // The instance doesn't exist anymore, so mark it as unknown in all selectors using this search expression
                FixupInstanceNumberForSE(se, UNKNOWN_INSTANCE);
            }
        }
    }

    // Get the values of all parameters identifying currently resolved permissions
    if (ggv.num_entries != 0)
    {
        GROUP_GET_VECTOR_GetValues(&ggv);
    }

    // Set all selectors whose instance number doesn't match the SE anymore back to UNKNOWN_INSTANCE
    index = 0;
    unknown_count = 0;
    for (i=0; i < tw->se_to_watch.num_entries; i++)
    {
        se = &tw->se_to_watch.vector[i];
        if ((se->last_known_instance != UNKNOWN_INSTANCE) && (se->is_stale == false))
        {
            USP_ASSERT(index < ggv.num_entries);
            gge = &ggv.vector[index];
            if ((gge->err_code==USP_ERR_OK) && (strcmp(gge->value, se->param_value) != 0))
            {
                FixupInstanceNumberForSE(se, UNKNOWN_INSTANCE);
                unknown_count++;
            }
            index++;
        }
        else
        {
            unknown_count++;
        }
    }
    GROUP_GET_VECTOR_Destroy(&ggv);

    // Exit if there are no unknown instances, in this case the search expressions were still resolving to the same instances, so nothing to update
    if (unknown_count == 0)
    {
        return;
    }

    // Resolve all search expressions with unknown instances
    AttemptToResolveAllSEOnTable(tw);
}

/*********************************************************************//**
**
** SE_CACHE_Dump
**
** Prints out the contents of the SE cache data structure, for logging purposes
** NOTE: The other useful function for debugging purposes is DEVICE_CTRUST_DumpPermissionSelectors()
**
** \param   None
**
** \return  None
**
**************************************************************************/
void SE_CACHE_Dump(void)
{
    int i, j, k;
    table_watch_t *tw;
    se_watch_t *se;
    inst_sel_t *sel;
    int role_instance;
    int perm_instance;
    char buf[128];
    int len;
    dm_node_t *node;

    // Iterate over all tables being watched
    for (i=0; i < tables_to_watch.num_entries; i++)
    {
        tw = &tables_to_watch.vector[i];

        // Iterate over all search expressions for that table
        for (j=0; j < tw->se_to_watch.num_entries; j++)
        {
            se = &tw->se_to_watch.vector[j];

            node = DM_PRIV_GetNodeFromPath(tw->table_path, NULL, NULL, DONT_LOG_ERRORS);
            USP_ASSERT(node != NULL);       // Because we should be maintaining this invariant

            // Build up line to print
            len = USP_SNPRINTF(buf, sizeof(buf), "%s.[%s==\"%s\"]   {i}=", tw->table_path, se->param_name, se->param_value);
            if (se->last_known_instance == UNKNOWN_INSTANCE)
            {
                len += USP_SNPRINTF(&buf[len], sizeof(buf)-len, "?");
            }
            else
            {
                len += USP_SNPRINTF(&buf[len], sizeof(buf)-len, "%d%c", se->last_known_instance, (se->is_stale) ? '?' : ' ');
            }

#ifndef REMOVE_USP_BROKER
            if (node->group_id != NON_GROUPED)
            {
                char *endpoint_id;
                endpoint_id = USP_BROKER_GroupIdToEndpointId(node->group_id);
                if (endpoint_id != NULL)
                {
                    USP_SNPRINTF(&buf[len], sizeof(buf)-len, "  (subscriptions %d+%d on %s)", tw->watch_subs_instances[0], tw->watch_subs_instances[1], endpoint_id);
                }
            }
#endif
            USP_DUMP("%s", buf);

            // Iterate over all selectors
            for (k=0; k < se->selectors.num_entries; k++)
            {
                sel = se->selectors.vector[k];
                USP_ASSERT(sel->selectors[0] == se->last_known_instance);
                USP_ASSERT(sel->is_watching == true);

                role_instance = DEVICE_CTRUST_InstSelToRoleInstance(sel, &perm_instance);
                USP_ASSERT(role_instance != INVALID);

                USP_DUMP("    Role.%d.Permission.%d", role_instance, perm_instance);
            }
        }
    }
}

#ifdef CROSS_CHECK_SE_CACHE
/*********************************************************************//**
**
** SE_CACHE_IsWatchingSelector
**
** Determines whether the specified selector is being watched by the SE cache
** and also checks that it's instance number matches the entry in the SE cache
** NOTE: This function is only used when debugging using DEVICE_CTRUST_CrossCheckSECache()
**       so it is not optimized in any way
**
** \param   sel - permission instance selector to see if it's being watched
**
** \return  true if the selector is being watched, false otherwise
**
**************************************************************************/
bool SE_CACHE_IsWatchingSelector(inst_sel_t *sel)
{
    int i, j, k;
    table_watch_t *tw;
    se_watch_t *se;

    // Iterate over all selectors, finding if one matches
    for (i=0; i < tables_to_watch.num_entries; i++)
    {
        tw = &tables_to_watch.vector[i];

        for (j=0; j < tw->se_to_watch.num_entries; j++)
        {
            se = &tw->se_to_watch.vector[j];

            for (k=0; k < se->selectors.num_entries; k++)
            {
                if ((se->selectors.vector[k] == sel) && (sel->selectors[0] == se->last_known_instance))
                {
                    return true;
                }
            }
        }
    }

    return false;
}
#endif

/*********************************************************************//**
**
** SE_CACHE_IsWatchingNode
**
** Determines whether there are any SE based permissions on the specified table
**
** \param   node - data model node identifying the table
**
** \return  true if the table is being watched, false otherwise
**
**************************************************************************/
bool SE_CACHE_IsWatchingNode(dm_node_t *node)
{
    table_watch_t *tw;

    // Exit if table is not being watched
    tw = TableWatchVector_FindByNode(&tables_to_watch, node);
    if (tw == NULL)
    {
        return false;
    }

    return true;
}

/*********************************************************************//**
**
** SE_CACHE_IsSelectorInstanceStale
**
** Determines whether the instance number in the selector refers to an instance that doesn't exist anymore
**
** \param   node - data model node identifying the table
** \param   sel - permission instance selector to see if its instance has been deleted
**
** \return  true if the instance number in the selector refers to an instance that doesn't exist anymore
**
**************************************************************************/
bool SE_CACHE_IsSelectorInstanceStale(dm_node_t *node, inst_sel_t *sel)
{
    table_watch_t *tw;
    se_watch_t *se;

    // Exit if table is not being watched
    tw = TableWatchVector_FindByNode(&tables_to_watch, node);
    if (tw == NULL)
    {
        return false;
    }

    se = SeWatchVector_FindBySelector(&tw->se_to_watch, sel);
    if (se == NULL)
    {
        return false;
    }

    return se->is_stale;
}

/*********************************************************************//**
**
** AttemptToResolveAllSEOnTable
**
** Attempts to resolve all search expressions on the specified table
** If successful, all permissions dependant on each search expression will be fixed-up with the instance number
**
** \param   tw - pointer to structure identifying search expression to resolve
**
** \return  None
**
**************************************************************************/
void AttemptToResolveAllSEOnTable(table_watch_t *tw)
{
    int i, j;
    se_watch_t *se;
    dm_node_t *node;
    dm_node_t *child;
    dm_instances_t inst;
    bool is_qualified_instance;
    int_vector_t instance_numbers;
    int err;
    int instance;
    group_get_vector_t ggv;
    char buf[MAX_DM_PATH];
    group_get_entry_t *gge;
    str_vector_t keys_to_get;
    int key_index;
    int start_index;
    int end_index;

    // Initialize all vectors used by this function
    INT_VECTOR_Init(&instance_numbers);
    STR_VECTOR_Init(&keys_to_get);
    GROUP_GET_VECTOR_Init(&ggv);

    // Exit if the table is not registered into the data model yet
    node = DM_PRIV_GetNodeFromPath(tw->table_path, &inst, &is_qualified_instance, DONT_LOG_ERRORS);
    if (node == NULL)
    {
        goto exit;
    }

    // Exit if the node is not an unqualified first order multi-instance object
    // This is possible since we allow permission targets to be set before the data model of a USP Service is registered
    // In this case, the permission target is invalid, but we have no way of indicating this, so it is treated as if it is disabled
    if ((node->type != kDMNodeType_Object_MultiInstance) || (is_qualified_instance==true) || (inst.order != 0))
    {
        goto exit;
    }

    // Exit if unable to get the instances of this table
    // NOTE: This may update the instance number in sel and se structures, if the table is owned by a USP Service
    err = DM_INST_VECTOR_GetInstances(node, &inst, &instance_numbers);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Form a vector of the names of the keys in search expressions which are still unresolved
    for (i=0; i < tw->se_to_watch.num_entries; i++)
    {
        se = &tw->se_to_watch.vector[i];

        // Skip if this search expression has already been resolved (and hasn't been deleted since)
        if ((se->last_known_instance != UNKNOWN_INSTANCE) && (se->is_stale == false))
        {
            continue;
        }

        // Skip if this search expression is for a parameter which doesn't exist in the data model
        child = DM_PRIV_FindMatchingChild(node, se->param_name);
        if (child == NULL)
        {
            continue;
        }

        STR_VECTOR_Add_IfNotExist(&keys_to_get, se->param_name);
    }

    // Exit if there are no search expressions to resolve anymore
    if (keys_to_get.num_entries == 0)
    {
        goto exit;
    }

    // Form a group get vector which gets the value of the unique keys in the seach expression for all instances in the table
    // This vector is ordered by blocks of each parameter in keys_to_get[]. Doing this avoids us later having to compare the parameter name in the ggv with the parameter name in the search expression
    // Likewise each block is ordered by instance numbers in instance_numbers[]. Doing this avoids us having to extract the instance number from the path in the ggv
    for (i=0; i < keys_to_get.num_entries; i++)
    {
        for (j=0; j < instance_numbers.num_entries; j++)
        {
            instance = instance_numbers.vector[j];
            USP_SNPRINTF(buf, sizeof(buf), "%s.%d.%s", tw->table_path, instance, keys_to_get.vector[i]);
            GROUP_GET_VECTOR_Add(&ggv, buf, node->group_id);     // NOTE: We can use the group_id of the table for the group_id of the parameter because it cannot sensibly be owned by a different data model provider component
        }
    }
    USP_ASSERT(ggv.num_entries == instance_numbers.num_entries * keys_to_get.num_entries);

    // Get all unique keys for all instances in the table
    GROUP_GET_VECTOR_GetValues(&ggv);

    // Iterate over all search expressions attached to this table
    for (i=0; i < tw->se_to_watch.num_entries; i++)
    {
        se = &tw->se_to_watch.vector[i];

        // Skip if this search expression has already been resolved (and hasn't been deleted since)
        if ((se->last_known_instance != UNKNOWN_INSTANCE) && (se->is_stale == false))
        {
            continue;
        }

        // Skip if this search expression is for a parameter which doesn't exist in the data model
        child = DM_PRIV_FindMatchingChild(node, se->param_name);
        if (child == NULL)
        {
            continue;
        }

        // Calculate which block of parameter values to search for a match in the group get vector
        key_index = STR_VECTOR_Find(&keys_to_get, se->param_name);
        USP_ASSERT(key_index != INVALID);
        start_index = key_index * instance_numbers.num_entries;
        end_index = start_index + instance_numbers.num_entries;

        // Search for the matching instance in the table
        for (j=start_index; j < end_index; j++)
        {
            gge = &ggv.vector[j];
            if ((gge->err_code==USP_ERR_OK) && (strcmp(gge->value, se->param_value) == 0))
            {
                // Fix up the instance number in all permission selectors that are watching this search expression
                instance = instance_numbers.vector[j-start_index];
                FixupInstanceNumberForSE(se, instance);
                break;
            }
        }
    }

exit:
    // Clean up
    INT_VECTOR_Destroy(&instance_numbers);
    STR_VECTOR_Destroy(&keys_to_get);
    GROUP_GET_VECTOR_Destroy(&ggv);
}

/*********************************************************************//**
**
** TableWatchVector_Init
**
** Initializes a table watch vector
**
** \param   twv - pointer to vector to initialize
**
** \return  None
**
**************************************************************************/
void TableWatchVector_Init(table_watch_vector_t *twv)
{
    twv->vector = NULL;
    twv->num_entries = 0;
}

/*********************************************************************//**
**
** TableWatchVector_Destroy
**
** Frees all memory associated with a table watch vector
**
** \param   twv - pointer to vector to free all memory of
**
** \return  None
**
**************************************************************************/
void TableWatchVector_Destroy(table_watch_vector_t *twv)
{
    int i;
    table_watch_t *tw;

    // Iterate over all entries, freeing them
    for (i=0; i < twv->num_entries; i++)
    {
        tw = &twv->vector[i];
        USP_FREE(tw->table_path);
        SeWatchVector_Destroy(&tw->se_to_watch);
    }

    // Finally free the actual vector and re-initialize it
    USP_SAFE_FREE(twv->vector);
    twv->num_entries = 0;
}

/*********************************************************************//**
**
** TableWatchVector_Add
**
** Adds the specified table into the list of tables to watch
**
** \param   twv - vector to add the table to
** \param   path - name of the table to add to the vector (excluding trailing dot and no {i})
** \param   node - data model node representing the table
**
** \return  pointer to entry that has been added
**
**************************************************************************/
table_watch_t *TableWatchVector_Add(table_watch_vector_t *twv, char *path, dm_node_t *node)
{
    int new_num_entries;
    table_watch_t *tw;

    // Increase size of vector
    new_num_entries = twv->num_entries + 1;
    twv->vector = USP_REALLOC(twv->vector, new_num_entries*sizeof(table_watch_t));

    // Initialize new entry
    tw = &twv->vector[ twv->num_entries ];
    tw->table_path = USP_STRDUP(path);
    tw->table_path_len = strlen(path);
    tw->table_node = node;
    SeWatchVector_Init(&tw->se_to_watch);

    twv->num_entries = new_num_entries;

#ifndef REMOVE_USP_BROKER
    // Further initialization
    tw->watch_subs_instances[0] = INVALID;
    tw->watch_subs_instances[1] = INVALID;

    // Add object creation and deletion subscriptions, if this table is implemented by a USP Service
    USP_BROKER_WatchTable(path, tw->watch_subs_instances);
#endif

    return tw;
}

/*********************************************************************//**
**
** TableWatchVector_Remove
**
** Removes the specified entry from the vector
**
** \param   twv - vector to remove the entry from
** \param   index - index of the entry to remove
**
** \return  None
**
**************************************************************************/
void TableWatchVector_Remove(table_watch_vector_t *twv, int index)
{
    int size;
    table_watch_t *tw;

    // Free the memory owned by the entry
    tw = &twv->vector[index];
    USP_FREE(tw->table_path);
    USP_ASSERT((tw->se_to_watch.num_entries==0) && (tw->se_to_watch.vector==NULL));

    // Move down the rest of the entries
    size = (twv->num_entries-index-1)*sizeof(table_watch_t);
    if (size > 0)
    {
        memmove(tw, &tw[1], size);
    }

    // Realloc the array
    twv->num_entries--;
    size = (twv->num_entries)*sizeof(table_watch_t);
    if (size > 0)
    {
        twv->vector = USP_REALLOC(twv->vector, size);
    }
    else
    {
        USP_SAFE_FREE(twv->vector);
    }
}

/*********************************************************************//**
**
** TableWatchVector_FindByInstantiatedPath
**
** Finds the table being watched given the specified path to an instance that has been added or deleted
**
** \param   twv - pointer to vector of tables to search
** \param   path - Path of the instance that has been added or deleted (may contain trailing dot after the instance number)
** \param   instance - pointer to variable in which to return the instance number extracted from the path in the table being watched
**
** \return  Pointer to table being watched
**
**************************************************************************/
table_watch_t *TableWatchVector_FindByInstantiatedPath(table_watch_vector_t *twv, char *path, int *instance)
{
    char *p;        // Pointer to character immediately before the instance number
    table_watch_t *tw;

    // Exit if no instance number found in the path
    p = FindFirstInstanceNumber(path);
    if (p == NULL)
    {
        return NULL;
    }
    USP_ASSERT(*p == '.');

    // Exit if this path was for a nested multi-instance object (or was badly formed)
    *instance = CalcFirstInstanceNumber(&p[1]);
    if (*instance == INVALID)
    {
        return NULL;
    }

    // Exit if we are not watching this table (ie no search expression based permissions on it)
    *p = '\0';      // Temporarily truncate path to obtain table name
    tw = TableWatchVector_FindByTableName(twv, path);
    *p = '.';       // Restore full path

    return tw;
}

/*********************************************************************//**
**
** TableWatchVector_FindByTableName
**
** Finds the specified table in the vector
**
** \param   twv - pointer to vector of tables to search
** \param   path - name of the data model table to find in the vector (excluding trailing dot and no {i})
**
** \return  Pointer to matching entry, or NULL if the entry is not currently being watched
**
**************************************************************************/
table_watch_t *TableWatchVector_FindByTableName(table_watch_vector_t *twv, char *path)
{
    int i;
    table_watch_t *tw;
    int len;

    len = strlen(path);
    for (i=0; i < twv->num_entries; i++)
    {
        tw = &twv->vector[i];
        if ((tw->table_path_len == len) && (Memrcmp(tw->table_path, path, len)==0))
        {
            return tw;
        }
    }

    return NULL;
}

/*********************************************************************//**
**
** TableWatchVector_FindByNode
**
** Finds the specified table in the vector
**
** \param   twv - pointer to vector of tables to search
** \param   node - pointer to node in the data model representing the table to find in the vector
**
** \return  Pointer to matching entry, or NULL if the entry is not currently being watched
**
**************************************************************************/
table_watch_t *TableWatchVector_FindByNode(table_watch_vector_t *twv, dm_node_t *node)
{
    int i;
    table_watch_t *tw;

    for (i=0; i < twv->num_entries; i++)
    {
        tw = &twv->vector[i];
        if (tw->table_node == node)
        {
            return tw;
        }
    }

    return NULL;
}

/*********************************************************************//**
**
** FindFirstInstanceNumber
**
** Returns a pointer to the character before the first instance number in the string
**
** \param   path - path to an instance in a table, ending in the instance number (or instance number then '.')
**
** \return  pointer to '.' character before the first instance number in the string
**          or NULL if none found
**
**************************************************************************/
char *FindFirstInstanceNumber(char *path)
{
    char *p;

    // Iterate over all characters in the path, stopping when we find the first instance number
    p = path;
    while (*p != '\0')
    {
        if ((*p == '.') && (IS_NUMERIC(p[1])))
        {
            return p;
        }

        // Move to next character in the path
        p++;
    }

    // Reached the end of the string wihout finding an instance number
    return NULL;
}

/*********************************************************************//**
**
** CalcFirstInstanceNumber
**
** Determines whether this path is for a top level multi-instance table
** and if so returns the instance number
**
** \param   p - pointer to the rest of the path, starting at the instance number
**
** \return  instance number extracted from the path, or INVALID if the path was for a nested multi-instance table
**
**************************************************************************/
int CalcFirstInstanceNumber(char *p)
{
    int instance = 0;

    // Iterate over the characters forming the first instance number
    while (IS_NUMERIC(*p))
    {
        // Build up instance number
        instance = instance*10 + p[0] - '0';

        // Move to next character in the path
        p++;

        // Exit if the string ended in this instance number. In this case, the path is a top level multi-instance object
        if (*p == '\0')
        {
            return instance;
        }

        if (*p == '.')
        {
            // Exit if the string ended in this instance number followed by '.'. In this case, the path is a top level multi-instance object
            if (p[1] == '\0')
            {
                return instance;
            }

            // Exit if the string did not end in this instance number. In this case, the path is a nested multi-instance object (or incorrectly ended in a '.')
            return INVALID;
        }
    }

    // The path is badly formed (first instance number contains non numeric characters)
    return INVALID;
}

/*********************************************************************//**
**
** SeWatchVector_Init
**
** Initializes a search expression watch vector
**
** \param   sev - pointer to vector to initialize
**
** \return  None
**
**************************************************************************/
void SeWatchVector_Init(se_watch_vector_t *sev)
{
    sev->vector = NULL;
    sev->num_entries = 0;
}

/*********************************************************************//**
**
** SeWatchVector_Destroy
**
** Frees all memory associated with a search expression watch vector
**
** \param   sev - pointer to vector to free all memory of
**
** \return  None
**
**************************************************************************/
void SeWatchVector_Destroy(se_watch_vector_t *sev)
{
    int i;
    se_watch_t *se;

    // Iterate over all entries, freeing them
    for (i=0; i < sev->num_entries; i++)
    {
        se = &sev->vector[i];
        USP_FREE(se->param_name);
        USP_FREE(se->param_value);
        INST_SEL_VECTOR_Destroy(&se->selectors, false);  // NOTE: The individual entries in the inst_sel_vector are not freed as they are owned by the permissions table, however the vector itself is freed
    }

    // Finally free the actual vector and re-initialize it
    USP_SAFE_FREE(sev->vector);
    sev->num_entries = 0;
}

/*********************************************************************//**
**
** SeWatchVector_Add
**
** Adds the specified search expression into the list of search expressions to watch for a table
**
** \param   sev - vector to add the search expression to
** \param   param - name of the unique key parameter in the search expression
** \param   value - value to match for the unique key parameter in the search expression
**
** \return  pointer to entry that has been added
**
**************************************************************************/
se_watch_t *SeWatchVector_Add(se_watch_vector_t *sev, char *param, char *value)
{
    int new_num_entries;
    se_watch_t *se;

    // Increase size of vector
    new_num_entries = sev->num_entries + 1;
    sev->vector = USP_REALLOC(sev->vector, new_num_entries*sizeof(se_watch_t));

    // Initialize new entry
    se = &sev->vector[ sev->num_entries ];
    se->param_name = USP_STRDUP(param);
    se->param_value = USP_STRDUP(value);
    se->last_known_instance = UNKNOWN_INSTANCE;
    se->is_stale = false;
    INST_SEL_VECTOR_Init(&se->selectors);

    sev->num_entries = new_num_entries;

    return se;
}

/*********************************************************************//**
**
** SeWatchVector_Remove
**
** Removes the specified entry from the vector
**
** \param   sev - vector to remove the entry from
** \param   index - index of the entry to remove
**
** \return  None
**
**************************************************************************/
void SeWatchVector_Remove(se_watch_vector_t *sev, int index)
{
    int size;
    se_watch_t *se;

    // Free the memory owned by the entry
    se = &sev->vector[index];
    USP_FREE(se->param_name);
    USP_FREE(se->param_value);
    USP_ASSERT((se->selectors.num_entries==0) && (se->selectors.vector==NULL));

    // Move down the rest of the entries
    size = (sev->num_entries-index-1)*sizeof(se_watch_t);
    if (size > 0)
    {
        memmove(se, &se[1], size);
    }

    // Realloc the array
    sev->num_entries--;
    size = (sev->num_entries)*sizeof(se_watch_t);
    if (size > 0)
    {
        sev->vector = USP_REALLOC(sev->vector, size);
    }
    else
    {
        USP_SAFE_FREE(sev->vector);
    }
}

/*********************************************************************//**
**
** SeWatchVector_FindByParam
**
** Finds the search expression in the vector containing the specified parameter and value
**
** \param   sev - pointer to vector to search
** \param   param - name of the unique key parameter to match in the search expression
** \param   value - value to match for the unique key parameter in the search expression
**
** \return  Pointer to matching entry, or NULL if the entry is not currently being watched
**
**************************************************************************/
se_watch_t *SeWatchVector_FindByParam(se_watch_vector_t *sev, char *param, char *value)
{
    int i;
    se_watch_t *se;

    for (i=0; i < sev->num_entries; i++)
    {
        se = &sev->vector[i];
        if ((strcmp(se->param_name, param)==0) && (strcmp(se->param_value, value)==0))
        {
            return se;
        }
    }

    return NULL;
}

/*********************************************************************//**
**
** SeWatchVector_FindBySelector
**
** Finds the search expression in the vector that the specified selector uses
**
** \param   sev - pointer to vector to search
** \param   sel - permission instance selector that we want to find
**
** \return  Pointer to matching entry, or NULL if unable to find the search expression associated with the selector
**
**************************************************************************/
se_watch_t *SeWatchVector_FindBySelector(se_watch_vector_t *sev, inst_sel_t *sel)
{
    int i;
    se_watch_t *se;
    int index;

    for (i=0; i < sev->num_entries; i++)
    {
        se = &sev->vector[i];
        index = INST_SEL_VECTOR_Find(&se->selectors, sel);
        if (index != INVALID)
        {
            return se;
        }
    }

    return NULL;
}

/*********************************************************************//**
**
** ObtainUnresolvedSEKeys
**
** Obtains the values of all keys which are present in unresolved search expression permissions
**
** \param   path - Path of the instance that has been added or deleted
** \param   tw - pointer to data model table to obtain keys for
** \param   keys - pointer to key value vector in which to return the values of all unique keys that are referenced by search expression based permissions on this table
**
** \return  None
**
**************************************************************************/
void ObtainUnresolvedSEKeys(char *path, table_watch_t *tw, kv_vector_t *keys)
{
    #define UNKNOWN_GROUP_ID (-2)
    int i;
    se_watch_t *se;
    int index;
    char buf[MAX_DM_PATH];
    group_get_vector_t ggv;
    group_get_entry_t *gge;
    kv_pair_t *kv;
    int group_id = UNKNOWN_GROUP_ID;
    dm_node_t *node;

    KV_VECTOR_Init(keys);
    GROUP_GET_VECTOR_Init(&ggv);

    // Iterate over all search expressions on this table, finding those whose instance number has not been resolved yet
    for (i=0; i < tw->se_to_watch.num_entries; i++)
    {
        se = &tw->se_to_watch.vector[i];
        if ((se->last_known_instance == UNKNOWN_INSTANCE) || (se->is_stale == true))
        {
            // Calculate the group_id for the table (and hence it's children), if we haven't done it already
            if (group_id == UNKNOWN_GROUP_ID)
            {
                // Exit if the path does not exist in the data model yet
                node = DM_PRIV_GetNodeFromPath(path, NULL, NULL, DONT_LOG_ERRORS);
                if (node == NULL)
                {
                    GROUP_GET_VECTOR_Destroy(&ggv);
                    KV_VECTOR_Destroy(keys);
                    return;
                }

                group_id = node->group_id;
            }

            // Form a group get vector of the parameters to get that are needed to fixup all unresolved search expressions
            // and a key value vector of the names of the keys
            USP_SNPRINTF(buf, sizeof(buf), "%s.%s", path, se->param_name);
            index = GROUP_GET_VECTOR_FindParam(&ggv, se->param_name);
            if (index == INVALID)
            {
                GROUP_GET_VECTOR_Add(&ggv, buf, group_id);
                KV_VECTOR_Add(keys, se->param_name, NULL);
            }
        }
    }

    // Exit if there aren't any unique keys to get (ie there are no unresolved search expressions)
    USP_ASSERT(ggv.num_entries == keys->num_entries);
    if (ggv.num_entries == 0)
    {
        return;
    }

    // Get all unique key parameters
    GROUP_GET_VECTOR_GetValues(&ggv);

    // Move the parameter values from the group get vector to the key value vector
    for (i=0; i < ggv.num_entries; i++)
    {
        gge = &ggv.vector[i];
        if ((gge->err_code == USP_ERR_OK) && (gge->value != NULL))
        {
            kv = &keys->vector[i];
            kv->value = gge->value;
            gge->value = NULL;
        }
    }

    GROUP_GET_VECTOR_Destroy(&ggv);
}

/*********************************************************************//**
**
** ResolvePermSE_NonUspService
**
** Attempts to resolve the specified search expression, when the table is owned by a non-USP Service
**
** \param   node - data model node representing the table
** \param   table - name of the table to watch (excluding trailing dot and no {i})
** \param   param - name of the unique key parameter to match the instance number of
** \param   value - name of the unique key parameter's value to match the instance number of
**
** \return  resolved instance number, or INVALID if not resolved
**
**************************************************************************/
int ResolvePermSE_NonUspService(dm_node_t *node, int group_id, char *table, char *param, char *value)
{
    int i;
    dm_instances_t inst = { 0 };
    int_vector_t instance_numbers;
    int err;
    int instance;
    group_get_vector_t ggv;
    group_get_entry_t *gge;
    char buf[MAX_DM_PATH];

    // Exit if unable to get the instances
    INT_VECTOR_Init(&instance_numbers);
    err = DM_INST_VECTOR_GetInstances(node, &inst, &instance_numbers);
    if (err != USP_ERR_OK)
    {
        return INVALID;
    }

    // Form a group get vector which gets the value of the unique key in the search expression for all instances in the table
    // Each block is ordered by instance numbers in instance_numbers[]. Doing this avoids us having to extract the instance number from the path in the ggv
    GROUP_GET_VECTOR_Init(&ggv);
    for (i=0; i < instance_numbers.num_entries; i++)
    {
        instance = instance_numbers.vector[i];
        USP_SNPRINTF(buf, sizeof(buf), "%s.%d.%s", table, instance, param);
        GROUP_GET_VECTOR_Add(&ggv, buf, group_id);   // NOTE: We can use the group_id of the table for the group_id of the parameter because it cannot sensibly be owned by a different data model provider component
    }
    USP_ASSERT(ggv.num_entries == instance_numbers.num_entries);

    // Get the unique key for all instances in the table
    GROUP_GET_VECTOR_GetValues(&ggv);

    // Search for the matching instance in the table
    instance = INVALID;
    for (i=0; i < ggv.num_entries; i++)
    {
        gge = &ggv.vector[i];
        if ((gge->err_code==USP_ERR_OK) && (strcmp(gge->value, value) == 0))
        {
            instance = instance_numbers.vector[i];
            break;
        }
    }

    // Clean up
    INT_VECTOR_Destroy(&instance_numbers);
    GROUP_GET_VECTOR_Destroy(&ggv);

    return instance;
}

/*********************************************************************//**
**
** FixupInstanceNumberForSE
**
** Updates the instance number in all permissions which are affected by the specified search expression
**
** \param   se - pointer to search expression that we know the matching instance number for
** \param   instance - instance number in the table matching the search expression
**
** \return  None
**
**************************************************************************/
void FixupInstanceNumberForSE(se_watch_t *se, int instance)
{
    int i;
    inst_sel_t *sel;

    se->last_known_instance = instance;
    se->is_stale = false;
    for (i=0; i < se->selectors.num_entries; i++)
    {
        sel = se->selectors.vector[i];
        sel->selectors[0] = instance;
    }
}

/*********************************************************************//**
**
** Compares two memory buffers for equality, performing the test in revere order
** ie the last byte of the buffers is compared first
**
** \param   s1 - First buffer to compare
** \param   s2 - Second buffer to compare
** \param   len - length of the buffers to compare (in bytes)
**
** \return  0 if the buffers are equal, otherwise 1
**
**************************************************************************/
int Memrcmp(char *s1, char *s2, int len)
{
    len--;
    s1 += len;
    s2 += len;
    while (len >= 0)
    {
        if (*s1 != *s2)
        {
            return 1;
        }

        s1--;
        s2--;
        len--;
    }

    return 0;
}
