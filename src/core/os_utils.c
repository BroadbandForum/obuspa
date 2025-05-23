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
 * \file os_utils.c
 *
 * Implements wrapper functions around POSIX Operating System functions, such as creating threads
 *
 */

#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "common_defs.h"

//-------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them

//------------------------------------------------------------------------
// Handle used to verify that all USP API functions are called only from the USP Core thread (and not a vendor thread)
pthread_t usp_core_thread;

/*********************************************************************//**
**
** OS_UTILS_CreateThread
**
** Wrapper function to start a POSIX thread
**
** \param   name - 16-chars NULL-terminated name to give to the thread.
** \param   start_routine - function pointer to the 'main' function for the thread
** \param   args - pointer to input conditions for the operation
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int OS_UTILS_CreateThread(const char* name, void *(* start_routine)(void *), void *args)
{
    int err;
    pthread_t thread;
    pthread_attr_t attr;

    // Exit if unable to create thread attributes
    err = pthread_attr_init(&attr);
    if (err != 0)
    {
        USP_ERR_ERRNO("pthread_attr_init", err);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to create the thread as detached (as we do not need to wait for it to terminate)
    err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (err != 0)
    {
        USP_ERR_ERRNO("pthread_attr_setdetachstate", err);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Exit if unable to start a new thread to perform the operation
    err = pthread_create(&thread, &attr, start_routine, args);
    if (err != 0)
    {
        USP_ERR_ERRNO("pthread_create", err);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    err = pthread_setname_np(thread, name);
    if (err != 0)
    {
        USP_ERR_ERRNO("pthread_setname_np", err);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    err = USP_ERR_OK;

exit:
    pthread_attr_destroy(&attr);
    return err;
}

/*********************************************************************//**
**
** OS_UTILS_SetDataModelThread
**
** Gets a handle for the data model thread
** This handle is then later used to verify that all USP API functions are called
** only from the data model thread (and not a vendor thread or the MTP thread)
**
** \param   None
**
** \return  None
**
**************************************************************************/
void OS_UTILS_SetDataModelThread(void)
{
    usp_core_thread = pthread_self();
}

/*********************************************************************//**
**
** OS_UTILS_IsDataModelThread
**
** Returns true if this function is being called from USP Agent's data model thread
** If not called from the data model thread, then it sets an error message
**
** \param   caller - name of calling function (used for debug)
** \param   print_warning - log a warning that the caller is being called from a non data model thread
**
** \return  true if this function is being called from the data model thread
**
**************************************************************************/
bool OS_UTILS_IsDataModelThread(const char *caller, bool print_warning)
{
    pthread_t this_thread;

    // Exit if this function is not being called from the data model thread
    this_thread = pthread_self();
    if ( ! pthread_equal(this_thread, usp_core_thread))
    {
        if (print_warning)
        {
            USP_LOG_Error("WARNING: Calling %s from non-data model thread", caller);
        }
        return false;
    }

    return true;
}

/*********************************************************************//**
**
** OS_UTILS_InitMutex
**
** Initialises a mutex for use
**
** \param   mutex - pointer to structure containing mutex
**
** \return  USP_ERR_OK if mutex has been created successfully
**
**************************************************************************/
int OS_UTILS_InitMutex(pthread_mutex_t *mutex)
{
    int err;
    pthread_mutexattr_t attr;

    // Initialise mutex
    err = pthread_mutexattr_init(&attr);
    if (err != 0)
    {
        USP_ERR_ERRNO("pthread_mutexattr_init", err);
        return USP_ERR_INTERNAL_ERROR;
    }

    err = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    if (err != 0)
    {
        USP_ERR_ERRNO("pthread_mutexattr_settype", err);
        return USP_ERR_INTERNAL_ERROR;
    }

    err = pthread_mutex_init(mutex, &attr);
    if (err != 0)
    {
        USP_ERR_ERRNO("pthread_mutex_init", err);
        return USP_ERR_INTERNAL_ERROR;
    }

    pthread_mutexattr_destroy(&attr);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** OS_UTILS_LockMutex
**
** Wrapper function to take a mutex
**
** \param   mutex - pointer to structure containing mutex
**
** \return  None
**
**************************************************************************/
void OS_UTILS_LockMutex(pthread_mutex_t *mutex)
{
    pthread_mutex_lock(mutex);
}

/*********************************************************************//**
**
** OS_UTILS_UnlockMutex
**
** Wrapper function to release a mutex
**
** \param   None
**
** \return  None
**
**************************************************************************/
void OS_UTILS_UnlockMutex(pthread_mutex_t *mutex)
{
    pthread_mutex_unlock(mutex);
}

/*********************************************************************//**
**
** OS_UTILS_CreateDirFromFilename
**
** Creates all parent directories of the given filename, if they haven't been created already
**
** \param   filename - absolute path to the file, which we would like all parent directories to exist
**
** \return  USP_ERR_OK if all parent directories of the given filename have been created or exist already
**
**************************************************************************/
int OS_UTILS_CreateDirFromFilename(char *filename)
{
    struct stat info;
    char path[PATH_MAX];
    char *p;
    int err;

    USP_ASSERT(filename[0] == '/');  // This function supports only absolute paths from root

    // Take a temporary copy of the filename, as we are going to modify the buffer in place
    USP_STRNCPY(path, filename, sizeof(path));

    // Iterate over all directory path segments, creating them if they do not exist already
    p = strchr(&path[1], '/');
    while (p != NULL)
    {
        *p = '\0';  // Temporarily truncate the string at the directory

        err = stat(path, &info);
        if ((err != 0) && (errno == ENOENT))
        {
            // Since dir does not exist, attempt to create it
            err = mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
            if (err != 0)
            {
                USP_ERR_ERRNO("mkdir", errno);
                return USP_ERR_INTERNAL_ERROR;
            }
        }

        *p = '/';   // Make back into full path

        p = strchr(&p[1], '/');
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** OS_UTILS_TimeNow
**
** Returns the current time. Ideally using the monotonic clock which will not have discontinuities in it when NTP time is acquired
**
** \param   None
**
** \return  time in seconds since some fixed starting point
**
**************************************************************************/
time_t OS_UTILS_TimeNow(void)
{
    int err;
    struct timespec ts;

    // Exit if able to get the monotonic clock time
    err = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (err == 0)
    {
        return ts.tv_sec;
    }

    // Otherwise return the real time clock
    return time(NULL);
}
