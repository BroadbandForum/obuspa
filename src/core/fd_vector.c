/*
 *
 * Copyright (C) 2019-2025, Broadband Forum
 * Copyright (C) 2024-2025, Vantiva Technologies SAS
 * Copyright (C) 2016-2024  CommScope, Inc
 * Copyright (C) 2025,  Inango
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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

#include <obuspa/core/usp_mem.h>
#include <obuspa/core/usp_err.h>
#include <obuspa/core/usp_log.h>
#include <obuspa/vendor_defs.h>
#include <obuspa/core/os_utils.h>

#ifdef FD_PASSING_EXPERIMENTAL
#include "fd_vector.h"

// Global vector to store file descriptor buffers
static fd_vector_t global_vector = {
    NULL,
    0
};

// Stores key of last added file descriptor buffer in "global vector"
static unsigned int global_fd_id = 0;

static pthread_mutex_t fd_vector_mutex;

/*********************************************************************//**
**
** FD_VECTOR_Close
**
** Closes and free given buffer of file descriptors
**
** \param   fd_buffer - pointer to the file descriptors buffer
** \param   fd_count - number of descriptors in the buffer
**
** \return  None
**
**************************************************************************/
void FD_VECTOR_Close(int* fd_buffer, int fd_count)
{
    if (fd_buffer != NULL)
    {
        while (fd_count > 0)
        {
            close(fd_buffer[--fd_count]);
        }
    }
    USP_SAFE_FREE(fd_buffer);
}

/*********************************************************************//**
**
** FD_VECTOR_New_Key
**
** Take new key from global counter
**
** \return new key
**
**************************************************************************/
unsigned int FD_VECTOR_New_Key()
{
    int key = 0;
    int count = 0;

    if (global_vector.num_entries >= MAX_FD_VECTOR_ENTRIES)
    {
        return 0;
    }

    if (global_fd_id == UINT32_MAX)
    {
        global_fd_id = 0;
    }

    do
    {
        key = ++global_fd_id;
        if (key == 0)
        {
            continue;
        }
        FD_VECTOR_Get(key, &count);
    }
    while (count != 0);

    return key;
}

/*********************************************************************//**
**
** FD_VECTOR_Add
**
** Add given buffer of file descriptors to global map under given key
**
** \param   key - key to assign file descriptors buffer in map
** \param   fd_buffer - pointer to the file descriptors buffer
** \param   fd_count - number of descriptors in the buffer
**
** \return  None
**
**************************************************************************/
void FD_VECTOR_Add(const unsigned int key, int *buffer, int count)
{
    OS_UTILS_LockMutex(&fd_vector_mutex);
    int new_num_entries;
    fd_pair_t *pair;

    new_num_entries = global_vector.num_entries + 1;
    global_vector.vector = USP_REALLOC(global_vector.vector, new_num_entries * sizeof(fd_pair_t));

    pair = &global_vector.vector[ global_vector.num_entries ];
    pair->key = key;
    pair->fd_buffer = buffer;
    pair->fd_count = count;
    pair->ref_count = 1;

    global_vector.num_entries = new_num_entries;
    OS_UTILS_UnlockMutex(&fd_vector_mutex);
}

/*********************************************************************//**
**
** FD_VECTOR_Get
**
** Get file descriptors buffer and number of file descriptors in that
** buffer from global map by the key
**
** Note: count output must be checked after retrieving buffer as it may
** contain -1 which indicate that some descriptors was received, but din't
** fit into buffer/file descriptors table.
** Descriptors at this point already closed, but error should be handled
** appropriately.
**
** \param   key - key to search for file descriptors buffer in map
** \param   fd_count - pointer to output number of descriptors found
**
** \return  pointer to file descriptors buffer or NULL if not available
**
**************************************************************************/
int *FD_VECTOR_Get(const unsigned int key, int *count)
{
    OS_UTILS_LockMutex(&fd_vector_mutex);
    int i;
    fd_pair_t *pair;

    // Iterate from start to end of array
    for (i=0; i < global_vector.num_entries; i++)
    {
        pair = &global_vector.vector[i];
        if (pair->key == key)
        {
            (*count) = pair->fd_count;
            OS_UTILS_UnlockMutex(&fd_vector_mutex);
            return pair->fd_buffer;
        }
    }

    OS_UTILS_UnlockMutex(&fd_vector_mutex);
    return NULL;
}

/*********************************************************************//**
**
** FD_VECTOR_Remove
**
** Remove file descriptors from global map by the given key
**
** Note: file descriptors must be taken out of map before
** removing and closed/freed separately as this function does not
** handle this
**
** \param   key - key to assign file descriptors buffer in map
**
** \return  None
**
**************************************************************************/
void FD_VECTOR_Remove(const unsigned int key)
{
    OS_UTILS_LockMutex(&fd_vector_mutex);
    int i, num_entries_after, new_num_entries;
    fd_pair_t *pair;

    // Iterate from start to end of array
    for (i=0; i < global_vector.num_entries; i++)
    {
        pair = &global_vector.vector[i];
        if (pair->key == key)
        {
            new_num_entries = global_vector.num_entries - 1;
            num_entries_after = new_num_entries - i;
            if (num_entries_after > 0) {
                memmove(&global_vector.vector[i], &global_vector.vector[i + 1], sizeof(fd_pair_t) * num_entries_after);
            }
            if (new_num_entries > 0) {
                global_vector.vector = USP_REALLOC(global_vector.vector, new_num_entries * sizeof(fd_pair_t));
            } else {
                USP_FREE(global_vector.vector);
                global_vector.vector = NULL;
            }
            global_vector.num_entries = new_num_entries;
            OS_UTILS_UnlockMutex(&fd_vector_mutex);
            return;
        }
    }
    OS_UTILS_UnlockMutex(&fd_vector_mutex);
}

/*********************************************************************//**
**
** FD_VECTOR_IncRef
**
** Increase amount of references for given entry
**
** \param   key - key to assign file descriptors buffer in map
**
** \return  amount of references to given buffer
**
**************************************************************************/
int FD_VECTOR_IncRef(const unsigned int key)
{
    OS_UTILS_LockMutex(&fd_vector_mutex);
    int i;
    fd_pair_t *pair;

    for (i=0; i < global_vector.num_entries; i++)
    {
        pair = &global_vector.vector[i];
        if (pair->key == key)
        {
            pair->ref_count++;
            OS_UTILS_UnlockMutex(&fd_vector_mutex);
            return pair->ref_count;
        }
    }
    OS_UTILS_UnlockMutex(&fd_vector_mutex);
    return 0;
}

/*********************************************************************//**
**
** FD_VECTOR_DecRef
**
** Decrease amount of references for given entry
**
** \param   key - key to assign file descriptors buffer in map
**
** \return  amount of references to given buffer
**
**************************************************************************/
int FD_VECTOR_DecRef(const unsigned int key)
{
    OS_UTILS_LockMutex(&fd_vector_mutex);
    int i;
    fd_pair_t *pair;

    for (i=0; i < global_vector.num_entries; i++)
    {
        pair = &global_vector.vector[i];
        if (pair->key == key)
        {
            pair->ref_count--;
            OS_UTILS_UnlockMutex(&fd_vector_mutex);
            return pair->ref_count;
        }
    }
    OS_UTILS_UnlockMutex(&fd_vector_mutex);
    return 0;
}
#endif
