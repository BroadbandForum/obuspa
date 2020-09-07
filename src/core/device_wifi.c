/*
 *
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
 * \file device_wifi.c
 *
 * Implements the Device.WiFi data model object
 *
 */

#include <stdio.h>
#include <time.h>
#include <string.h>

#include "common_defs.h"
#include "data_model.h"
#include "usp_api.h"
#include "dm_access.h"
#include "device.h"
#include "os_utils.h"
#include "usp_log.h"

#define DEVICE_WIFI_ROOT "Device.WiFi"

static int sResetCounter = 0; 

/************************************************************************
**
** DEVICE_WIFI_NeighboringWiFiDiagnostic_Operate
**
** Sample implementation of WiFi USP method 
** 
** \param   req - pointer to structure of the request
** \param   key -  
** \param   input_args - input arguments, kv_vector: key value vectors
** \param   output_args - output arguments
**
** \return  USP_ERR_OK if successful
**          USP_ERR_INTERNAL_ERROR if any other error occurred
**
**************************************************************************/
int DEVICE_WIFI_NeighboringWiFiDiagnostic_Operate(dm_req_t *req, char *key, kv_vector_t *input_args, kv_vector_t *output_args)
{
   int err = USP_ERR_OK;

   USP_ARG_Init(output_args);
   KV_VECTOR_Add(output_args, "Diag Result", "Passed");
   //USP_LOG_Info("Shibu: Inside of %s\n", __FUNCTION__);
   return err;
}

/************************************************************************
**
** DEVICE_WIFI_Reset_Operate 
**
** Sample implementation of Operate method callback of an async operation
** 
** \param   req - pointer to structure of the request
** \param   input_args - input arguments, kv_vector: key value vectors
** \param   instance - 
**
** \return  USP_ERR_OK if successful
**          USP_ERR_INTERNAL_ERROR if any other error occurred
**
**************************************************************************/
int DEVICE_WIFI_Reset_Operate(dm_req_t *req, kv_vector_t *input_args, int instance)
{
   int err = USP_ERR_OK;

   //USP_LOG_Info("Shibu: Inside of %s\n", __FUNCTION__);
   return err;
}

/************************************************************************
**
** GetResetCounter
**
** Sample implementation of callback to return transient data to
** controller
** 
** \param   req - pointer to structure of the request
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**          USP_ERR_INTERNAL_ERROR if any other error occurred
**
**************************************************************************/
int GetResetCounter(dm_req_t *req, char *buf, int len)
{
   USP_SNPRINTF(buf, len, "%d", sResetCounter++);
   return  USP_ERR_OK;
}

/************************************************************************
**
** DEVICE_WIFI_Init
**
** Initialises this component, and registers all parameters which it implements
**
** \param   None
**
** \return  USP_ERR_OK if successful
**          USP_ERR_INTERNAL_ERROR if any other error occurred
**
**************************************************************************/
int DEVICE_WIFI_Init(void)
{
    int err = USP_ERR_OK;

    // Register NeighbouringWiFiDiagnostic method as Sync operation 
    err |= USP_REGISTER_SyncOperation("Device.WiFi.NeighboringWiFiDiagnostic()", DEVICE_WIFI_NeighboringWiFiDiagnostic_Operate);

    // Register WiFi Reset method  as Async operation
    err |= USP_REGISTER_AsyncOperation("Device.WiFi.Reset()", DEVICE_WIFI_Reset_Operate, NULL);


    err |= USP_REGISTER_Object(DEVICE_WIFI_ROOT, NULL, NULL, NULL, NULL, NULL, NULL); 

	// Following parameters are stored in DB
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_WIFI_ROOT ".RadioNumberOfEntries", "1", NULL, NULL, DM_INT);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_WIFI_ROOT ".SSIDNumberOfEntries", "0", NULL, NULL, DM_INT);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_WIFI_ROOT ".AccessPointNumberOfEntries", "2", NULL,  NULL, DM_INT);
	err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_WIFI_ROOT ".EndPointNumberOfEntries", "1", NULL, NULL, DM_INT);

	// VendorParam method is to register data which is not stored in DB but
	// generated in run time by method, e.g. here GetResetCounter()
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_WIFI_ROOT ".ResetCounter", GetResetCounter, DM_INT);

	// Example of registering multi-instance object
    err |= USP_REGISTER_Object(DEVICE_WIFI_ROOT ".Radio.{i}", NULL, NULL, NULL, NULL, NULL, NULL);
	// Example of multi instance object parameter registration
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_WIFI_ROOT ".Radio.{i}.Enable", "1", NULL, NULL, DM_BOOL);

    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }
    return USP_ERR_OK;
}

/************************************************************************
**
** DEVICE_WIFI_Start
**
** Read from the Database and store it in cache or initialize local
** data structure
**
** \param   None
**
** \return  USP_ERR_OK if successful
**          USP_ERR_INTERNAL_ERROR if any other error occurred
**
**************************************************************************/
int DEVICE_WIFI_Start(void)
{
	int err;

	USP_LOG_Info("%s: Info: Inside ", __FUNCTION__);
	char value[10];
	err = DATA_MODEL_GetParameterValue("Device.WiFi.AccessPointNumberOfEntries", (char *)&value, sizeof(value), 0);
   	USP_LOG_Info("%s: AccessPointNumberOfEntries: %s\n", __FUNCTION__, value);
	return err;
}
