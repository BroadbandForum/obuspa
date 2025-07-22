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
 * \file se_cache.h
 *
 * Implements and maintains a cache of instance numbers matching a unique key search expression
 *
 */


#ifndef SE_CACHE_H
#define SE_CACHE_H

#include "inst_sel_vector.h"

//-------------------------------------------------------------------------
// API
void SE_CACHE_Init(void);
void SE_CACHE_Destroy(void);
void SE_CACHE_WatchUniqueKey(dm_node_t *node, char *table, char *param, char *value, inst_sel_t *sel);
void SE_CACHE_UnwatchUniqueKey(inst_sel_t *sel);
void SE_CACHE_StartSEResolution(void);
void SE_CACHE_WatchAllUniqueKeysOnUspService(int group_id);
void SE_CACHE_NotifyInstanceAdded(char *path, kv_vector_t *keys);
void SE_CACHE_NotifyInstanceDeleted(char *path);
void SE_CACHE_RefreshPermissions(dm_node_t *node);
void SE_CACHE_HandleUspServiceDisconnect(int group_id);
void SE_CACHE_Dump(void);
bool SE_CACHE_IsWatchingSelector(inst_sel_t *sel);
bool SE_CACHE_IsWatchingNode(dm_node_t *node);
bool SE_CACHE_IsSelectorInstanceStale(dm_node_t *node, inst_sel_t *sel);

#endif
