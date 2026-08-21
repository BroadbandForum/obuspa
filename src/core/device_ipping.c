/*
 *
 * Copyright (C) 2019-2025, Broadband Forum
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
 * \file device_ipping.c
 *
 * Implements Device.IP.Diagnostics.IPPing() as an asynchronous USP Operate command.
 * Runs the system ping utility and returns TR-181-style output arguments.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "common_defs.h"
#include "usp_api.h"
#include "os_utils.h"

#ifndef REMOVE_IPPING_DIAG

//------------------------------------------------------------------------------------
// Input conditions for IPPing
typedef struct
{
    int request_instance;   // Instance number of this operation in the Device.LocalAgent.Request table
    char host[256];
    unsigned number_of_repetitions;
    unsigned timeout_ms;
} ipping_input_cond_t;

//------------------------------------------------------------------------------------
// Output results of IPPing
typedef struct
{
    unsigned success_count;
    unsigned failure_count;
    unsigned average_response_time;
    unsigned minimum_response_time;
    unsigned maximum_response_time;
    char err_msg[256];
} ipping_output_res_t;

//------------------------------------------------------------------------------------
// Array of valid input arguments
static char *ipping_input_args[] =
{
    "Host",
    "NumberOfRepetitions",
    "Timeout",
};

//------------------------------------------------------------------------------------
// Array of valid output arguments
static char *ipping_output_args[] =
{
    "SuccessCount",
    "FailureCount",
    "AverageResponseTime",
    "MinimumResponseTime",
    "MaximumResponseTime",
};

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
int DEVICE_IPPING_Operate(dm_req_t *req, kv_vector_t *input_args, int instance);
void *IPPingThreadMain(void *param);
int ExecuteIPPing(ipping_input_cond_t *cond, ipping_output_res_t *res);
int HostIsSafe(const char *host);

/*********************************************************************//**
**
** DEVICE_IPPING_Init
**
** Initialises this component, and registers Device.IP.Diagnostics.IPPing()
**
** \param   None
**
** \return  USP_ERR_OK if successful
**          USP_ERR_INTERNAL_ERROR if any other error occurred
**
**************************************************************************/
int DEVICE_IPPING_Init(void)
{
    int err = USP_ERR_OK;

    err |= USP_REGISTER_AsyncOperation("Device.IP.Diagnostics.IPPing()", DEVICE_IPPING_Operate, NULL);
    err |= USP_REGISTER_AsyncOperation_MaxConcurrency("Device.IP.Diagnostics.IPPing()", 1);
    err |= USP_REGISTER_OperationArguments("Device.IP.Diagnostics.IPPing()",
                                           ipping_input_args, NUM_ELEM(ipping_input_args),
                                           ipping_output_args, NUM_ELEM(ipping_output_args));

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** HostIsSafe
**
** Validates that Host contains only characters safe to pass to ping
**
** \param   host - host name or IP address
**
** \return  USP_ERR_OK if safe, USP_ERR_INVALID_ARGUMENTS otherwise
**
**************************************************************************/
int HostIsSafe(const char *host)
{
    size_t i;
    size_t len;

    if (host == NULL)
    {
        return USP_ERR_INVALID_ARGUMENTS;
    }

    len = strlen(host);
    if ((len == 0) || (len >= 256))
    {
        return USP_ERR_INVALID_ARGUMENTS;
    }

    for (i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char) host[i];
        if (!(isalnum(c) || (c == '.') || (c == '-') || (c == ':')))
        {
            return USP_ERR_INVALID_ARGUMENTS;
        }
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_IPPING_Operate
**
** Starts the asynchronous IPPing operation
**
** \param   req - pointer to structure identifying the operation in the data model
** \param   input_args - vector containing input arguments and their values
** \param   instance - instance number of this operation in the Device.LocalAgent.Request table
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_IPPING_Operate(dm_req_t *req, kv_vector_t *input_args, int instance)
{
    int err;
    char *host;
    ipping_input_cond_t *cond;

    (void) req;

    // Allocate input conditions to pass to thread
    cond = USP_MALLOC(sizeof(ipping_input_cond_t));
    memset(cond, 0, sizeof(ipping_input_cond_t));
    cond->request_instance = instance;

    host = USP_ARG_Get(input_args, "Host", NULL);
    if ((host == NULL) || (host[0] == '\0'))
    {
        USP_ERR_SetMessage("%s: Host input argument is required", __FUNCTION__);
        err = USP_ERR_INVALID_ARGUMENTS;
        goto exit;
    }

    err = HostIsSafe(host);
    if (err != USP_ERR_OK)
    {
        USP_ERR_SetMessage("%s: Host contains invalid characters", __FUNCTION__);
        goto exit;
    }

    USP_STRNCPY(cond->host, host, sizeof(cond->host));

    #define DEFAULT_IPPING_REPETITIONS 4
    #define MAX_IPPING_REPETITIONS     20
    err = USP_ARG_GetUnsignedWithinRange(input_args, "NumberOfRepetitions",
                                         DEFAULT_IPPING_REPETITIONS, 1, MAX_IPPING_REPETITIONS,
                                         &cond->number_of_repetitions);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // TR-181 Timeout is in milliseconds
    #define DEFAULT_IPPING_TIMEOUT_MS 5000
    #define MIN_IPPING_TIMEOUT_MS     1000
    #define MAX_IPPING_TIMEOUT_MS     60000
    err = USP_ARG_GetUnsignedWithinRange(input_args, "Timeout",
                                         DEFAULT_IPPING_TIMEOUT_MS, MIN_IPPING_TIMEOUT_MS, MAX_IPPING_TIMEOUT_MS,
                                         &cond->timeout_ms);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    USP_LOG_Info("=== IPPing Conditions ===");
    USP_LOG_Info("host: %s", cond->host);
    USP_LOG_Info("number_of_repetitions: %u", cond->number_of_repetitions);
    USP_LOG_Info("timeout_ms: %u", cond->timeout_ms);

    // NOTE: ownership of input conditions passes to the thread
    err = OS_UTILS_CreateThread("IPPing", IPPingThreadMain, cond);
    if (err != USP_ERR_OK)
    {
        err = USP_ERR_COMMAND_FAILURE;
        goto exit;
    }

exit:
    if (err != USP_ERR_OK)
    {
        USP_FREE(cond);
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** IPPingThreadMain
**
** Main function for IPPing operation thread
**
** \param   param - pointer to input conditions
**
** \return  NULL
**
**************************************************************************/
void *IPPingThreadMain(void *param)
{
    ipping_input_cond_t *cond = (ipping_input_cond_t *) param;
    ipping_output_res_t results;
    ipping_output_res_t *res = &results;
    kv_vector_t *output_args;
    char *err_msg;
    int err = USP_ERR_OK;

    memset(&results, 0, sizeof(results));

    err = USP_SIGNAL_OperationStatus(cond->request_instance, "Active");
    if (err != USP_ERR_OK)
    {
        USP_SNPRINTF(res->err_msg, sizeof(res->err_msg), "%s: USP_SIGNAL_OperationStatus() failed", __FUNCTION__);
        goto exit;
    }

    err = ExecuteIPPing(cond, res);

exit:
    USP_LOG_Info("=== IPPing completed with result=%d ===", err);
    USP_LOG_Info("SuccessCount: %u", res->success_count);
    USP_LOG_Info("FailureCount: %u", res->failure_count);
    USP_LOG_Info("AverageResponseTime: %u", res->average_response_time);
    USP_LOG_Info("MinimumResponseTime: %u", res->minimum_response_time);
    USP_LOG_Info("MaximumResponseTime: %u", res->maximum_response_time);

    output_args = USP_ARG_Create();
    USP_ARG_AddUnsigned(output_args, "SuccessCount", res->success_count);
    USP_ARG_AddUnsigned(output_args, "FailureCount", res->failure_count);
    USP_ARG_AddUnsigned(output_args, "AverageResponseTime", res->average_response_time);
    USP_ARG_AddUnsigned(output_args, "MinimumResponseTime", res->minimum_response_time);
    USP_ARG_AddUnsigned(output_args, "MaximumResponseTime", res->maximum_response_time);

    err_msg = (err != USP_ERR_OK) ? res->err_msg : NULL;
    USP_SIGNAL_OperationComplete(cond->request_instance, err, err_msg, output_args);

    USP_FREE(cond);

    return NULL;
}

/*********************************************************************//**
**
** ExecuteIPPing
**
** Runs the system ping utility and parses Success/Failure counts and RTT
**
** \param   cond - pointer to input conditions
** \param   res - pointer to output results
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ExecuteIPPing(ipping_input_cond_t *cond, ipping_output_res_t *res)
{
    char cmd[384];
    FILE *fp;
    char line[512];
    unsigned timeout_sec;

    res->success_count = 0;
    res->failure_count = 0;
    res->average_response_time = 0;
    res->minimum_response_time = 0;
    res->maximum_response_time = 0;
    res->err_msg[0] = '\0';

    // TR-181 Timeout is milliseconds; common ping -W expects seconds
    timeout_sec = (cond->timeout_ms + 999) / 1000;
    if (timeout_sec < 1)
    {
        timeout_sec = 1;
    }
    if (timeout_sec > 60)
    {
        timeout_sec = 60;
    }

    USP_SNPRINTF(cmd, sizeof(cmd), "ping -c %u -W %u %s 2>&1",
                 cond->number_of_repetitions, timeout_sec, cond->host);

    fp = popen(cmd, "r");
    if (fp == NULL)
    {
        USP_SNPRINTF(res->err_msg, sizeof(res->err_msg), "%s: popen(ping) failed: %s", __FUNCTION__, strerror(errno));
        return USP_ERR_COMMAND_FAILURE;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        unsigned tx = 0;
        unsigned rx = 0;
        double min_ms = 0;
        double avg_ms = 0;
        double max_ms = 0;

        if ((sscanf(line, "%u packets transmitted, %u packets received", &tx, &rx) == 2) ||
            (sscanf(line, "%u packets transmitted, %u received", &tx, &rx) == 2))
        {
            res->success_count = rx;
            if (tx >= rx)
            {
                res->failure_count = tx - rx;
            }
            else
            {
                res->failure_count = 0;
            }
            continue;
        }

        if ((sscanf(line, "round-trip min/avg/max = %lf/%lf/%lf", &min_ms, &avg_ms, &max_ms) == 3) ||
            (sscanf(line, "rtt min/avg/max/mdev = %lf/%lf/%lf", &min_ms, &avg_ms, &max_ms) == 3))
        {
            res->minimum_response_time = (unsigned)(min_ms + 0.5);
            res->average_response_time = (unsigned)(avg_ms + 0.5);
            res->maximum_response_time = (unsigned)(max_ms + 0.5);
        }
    }

    pclose(fp);

    if ((res->success_count == 0) && (res->failure_count == 0))
    {
        res->failure_count = cond->number_of_repetitions;
    }

    return USP_ERR_OK;
}

#endif // REMOVE_IPPING_DIAG
