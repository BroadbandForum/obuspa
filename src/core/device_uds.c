/*
 *
 * Copyright (C) 2023-2025, Broadband Forum
 * Copyright (C) 2024-2025, Vantiva Technologies SAS
 * Copyright (C) 2023-2024  CommScope, Inc
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
 * \file device_uds.c
 *
 * Implements the Device.UDS data model object
 *
 */

#ifdef ENABLE_UDS

#include <time.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "common_defs.h"
#include "data_model.h"
#include "usp_api.h"
#include "dm_access.h"
#include "dm_trans.h"
#include "dm_access.h"
#include "kv_vector.h"
#include "mtp_exec.h"
#include "device.h"
#include "text_utils.h"
#include "uds.h"
#include "iso8601.h"
#include "database.h"

//------------------------------------------------------------------------------
// Location of the UDS connection table within the data model
#define DEVICE_UDS_CONN_ROOT "Device.UnixDomainSockets.UnixDomainSocket"
const char *device_uds_conn_root = DEVICE_UDS_CONN_ROOT;

// Location of the UDS authentication table within the data model
#define DEVICE_UDS_AUTH_ROOT "Device.UnixDomainSockets.Authentication"
static const char device_uds_auth_root[] = DEVICE_UDS_AUTH_ROOT;

// Location of UDS MTP password for this endpoint within the data model
static const char *dm_uds_self_password_path = "Internal.UDS.SelfPassword";
//------------------------------------------------------------------------------
// Cache of the parameters in the Device.UnixDomainSockets table
static uds_conn_params_t uds_conn_params[MAX_UDS_SERVERS];

//------------------------------------------------------------------------------
// Internal data structure reporesenting the Device.UnixDomainSockets.Authentication.{i} table
typedef struct
{
    int instance;       // Instance number in Device.UxixDomainSockets.Authentication.{i} or INVALID if this slot is not used
    bool enable;        // Device.UxixDomainSockets.Authentication.{i}.Enable
    char *endpoint_id;  // Device.UxixDomainSockets.Authentication.{i}.EndpointID
    char *password;     // Device.UxixDomainSockets.Authentication.{i}.Password
} uds_auth_t;

uds_auth_t *uds_auths = NULL;
int num_uds_auths;

//------------------------------------------------------------------------------
// Table used to convert from an enumeration of a UDS mode to a textual representation
const enum_entry_t uds_modes[] =
{
    { kUdsConnType_Server,  "Listen" },
    { kUdsConnType_Client,  "Connect" },
};

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
uds_conn_params_t *FindUnusedUdsParams(void);
int ValidateAdd_UdsConn(dm_req_t *req);
int Validate_UdsMode(dm_req_t *req, char *value);
int Validate_UdsPath(dm_req_t *req, char *value);
int ProcessUdsConnAdded(int instance);
void DestroyUdsConn(uds_conn_params_t *ucp);
int Notify_UdsConnAdded(dm_req_t *req);
int Notify_UdsConnDeleted(dm_req_t *req);
int Notify_UdsAuthAdded(dm_req_t *req);
int Notify_UdsAuthDeleted(dm_req_t *req);
int NotifyChange_UdsMode(dm_req_t *req, char *value);
int NotifyChange_UdsPath(dm_req_t *req, char *value);
uds_conn_params_t *FindUdsParamsByInstance(int instance);
int NotifyChange_UdsAuthRequired(dm_req_t *req, char *value);
int NotifyChange_UdsRegistrationRestricted(dm_req_t *req, char *value);
int NotifyChange_UdsAuthEnable(dm_req_t *req, char *value);
int NotifyChange_UdsAuthEndpointID(dm_req_t *req, char *value);
int NotifyChange_UdsAuthPassword(dm_req_t *req, char *value);
int Validate_UdsAuthEndpointID(dm_req_t *req, char *value);
uds_auth_t *FindUdsAuthByInstance(int instance);
uds_auth_t *FindUdsAuthByEndpointId(char *endpoint_id);
void RemoveUdsAuth(uds_auth_t *ua);
int ProcessUdsAuthAdded(int instance);
int NotifyChange_UdsSelfPassword(dm_req_t *req, char *value);

/*********************************************************************//**
**
** DEVICE_UDS_Init
**
** Initialises this component, and registers all parameters which it implements
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_UDS_Init(void)
{
    int i;
    int err = USP_ERR_OK;
    uds_conn_params_t *ucp;

    // Exit if unable to initialise the lower level UDS component
    err = UDS_Init();
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Mark all UDS params slots as unused
    memset(uds_conn_params, 0, sizeof(uds_conn_params));
    for (i=0; i<NUM_ELEM(uds_conn_params); i++)
    {
        ucp = &uds_conn_params[i];
        ucp->instance = INVALID;
        ucp->path = NULL;
        ucp->mode = kUdsConnType_Invalid;
        ucp->path_type = kUdsPathType_Invalid;
    }

    // Register Device.UnixDomainSockets.UnixDomainSocket.{i} table
    err |= USP_REGISTER_Object(DEVICE_UDS_CONN_ROOT ".{i}", ValidateAdd_UdsConn, NULL, Notify_UdsConnAdded, NULL, NULL, Notify_UdsConnDeleted);
    err |= USP_REGISTER_Param_NumEntries("Device.UnixDomainSockets.UnixDomainSocketNumberOfEntries", DEVICE_UDS_CONN_ROOT ".{i}");
    err |= USP_REGISTER_DBParam_Alias(DEVICE_UDS_CONN_ROOT ".{i}.Alias", NULL);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_UDS_CONN_ROOT ".{i}.Mode", "", Validate_UdsMode, NotifyChange_UdsMode, DM_STRING);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_UDS_CONN_ROOT ".{i}.Path", "", Validate_UdsPath, NotifyChange_UdsPath, DM_STRING);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_UDS_CONN_ROOT ".{i}.AuthRequired", "false", NULL, NotifyChange_UdsAuthRequired, DM_BOOL);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_UDS_CONN_ROOT ".{i}.RegistrationRestricted", "false", NULL, NotifyChange_UdsRegistrationRestricted, DM_BOOL);

    // Register Device.UnixDomainSockets.Authentication.{i} table
    err |= USP_REGISTER_Object(DEVICE_UDS_AUTH_ROOT ".{i}", NULL, NULL, Notify_UdsAuthAdded, NULL, NULL, Notify_UdsAuthDeleted);
    err |= USP_REGISTER_Param_NumEntries("Device.UnixDomainSockets.AuthenticationNumberOfEntries", DEVICE_UDS_AUTH_ROOT ".{i}");
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_UDS_AUTH_ROOT ".{i}.Enable", "false", NULL, NotifyChange_UdsAuthEnable, DM_BOOL);
    err |= USP_REGISTER_DBParam_ReadWriteAuto(DEVICE_UDS_AUTH_ROOT ".{i}.EndpointID", DM_ACCESS_PopulateEndpointIDParam, Validate_UdsAuthEndpointID, NotifyChange_UdsAuthEndpointID, DM_STRING);
    err |= USP_REGISTER_DBParam_Secure(DEVICE_UDS_AUTH_ROOT ".{i}.Password", "", NULL, NotifyChange_UdsAuthPassword);

    // Register parameter storing this Endpoint's UDS password
    err |= USP_REGISTER_DBParam_Secure((char *)dm_uds_self_password_path, "", NULL, NotifyChange_UdsSelfPassword);

    // Exit if any errors occurred
    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_UDS_Start
**
** Initialises the UDS connection array from the DB and starts connections
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_UDS_Start(void)
{
    int i;
    int err;
    int_vector_t iv;
    int instance;
    char path[MAX_DM_PATH];
    char buf[MAX_DM_VALUE_LEN];
    uds_conn_params_t *ucp;

    // Get the UDS MTP password that this endpoint uses and set it in the MTP layer
    err = DATA_MODEL_GetParameterValue((char *)dm_uds_self_password_path, buf, sizeof(buf), SHOW_PASSWORD);
    if (err != USP_ERR_OK)
    {
        buf[0] = '\0';
    }
    NotifyChange_UdsSelfPassword(NULL, buf);

    // Exit if unable to get the object instance numbers for Device.UnixDomainSockets.UnixDomainSocket.{i}
    INT_VECTOR_Init(&iv);
    err = DATA_MODEL_GetInstances((char *)device_uds_conn_root, &iv);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Add all DM UDS connections to the uds_conn_params array
    for (i=0; i < iv.num_entries; i++)
    {
        instance = iv.vector[i];
        err = ProcessUdsConnAdded(instance);
        if (err != USP_ERR_OK)
        {
            // Exit if unable to delete a UDS connection with bad parameters from the DB
            USP_SNPRINTF(path, sizeof(path), "%s.%d", device_uds_conn_root, instance);
            USP_LOG_Warning("%s: Deleting %s as it contained invalid parameters.", __FUNCTION__, path);
            err = DATA_MODEL_DeleteInstance(path, 0);
            if (err != USP_ERR_OK)
            {
                goto exit;
            }
        }
    }

    // Enable all UDS connections in the uds_conn_params array
    for (i=0; i<NUM_ELEM(uds_conn_params); i++)
    {
        ucp = &uds_conn_params[i];
        if (ucp->instance != INVALID)
        {
            err = UDS_EnableConnection(ucp);
            if (err != USP_ERR_OK)
            {
                goto exit;
            }
        }
    }

    // Exit if unable to get the object instance numbers for Device.UnixDomainSockets.Authentication.{i}
    INT_VECTOR_Destroy(&iv);
    err = DATA_MODEL_GetInstances((char *)device_uds_auth_root, &iv);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Add all entries to the uds_auths vector
    for (i=0; i < iv.num_entries; i++)
    {
        instance = iv.vector[i];
        err = ProcessUdsAuthAdded(instance);
        if (err != USP_ERR_OK)
        {
            // Exit if unable to delete a UDS auth with bad parameters from the DB
            USP_SNPRINTF(path, sizeof(path), "%s.%d", device_uds_auth_root, instance);
            USP_LOG_Warning("%s: Deleting %s as it contained invalid parameters.", __FUNCTION__, path);
            err = DATA_MODEL_DeleteInstance(path, 0);
            if (err != USP_ERR_OK)
            {
                goto exit;
            }
        }
    }

    err = USP_ERR_OK;

exit:
    // Destroy the vector of instance numbers for the table
    INT_VECTOR_Destroy(&iv);
    return err;
}

/*********************************************************************//**
**
** DEVICE_UDS_Stop
**
** Stops all UDS connections and frees all dynamically allocated memory
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void DEVICE_UDS_Stop(void)
{
    int i;
    uds_conn_params_t *ucp;
    uds_auth_t *ua;

    // Iterate over all UDS connections, freeing all memory used by it
    for (i=0; i<NUM_ELEM(uds_conn_params); i++)
    {
        ucp = &uds_conn_params[i];
        if (ucp->instance != INVALID)
        {
            DestroyUdsConn(ucp);
        }
    }

    // Iterate over all UDS auths, freeing all memory used
    for (i=0; i<num_uds_auths; i++)
    {
        ua = &uds_auths[i];
        USP_FREE(ua->endpoint_id);
        USP_FREE(ua->password);
    }
    USP_SAFE_FREE(uds_auths);
    num_uds_auths = 0;
}

/*********************************************************************//**
**
** DEVICE_UDS_DoRegistrationRestrictionsApply
**
** Determines whether the data model registration permissions in Device.USPServices.Trust.{i}
** are to be applied to USP Services connecting to the specified UDS instance
**
** \param   instance - Instance number in Device.UnixDomainSockets.UnixDomainSocket.{i}
**
** \return  true if DM registration restrictions apply, false if the USP Service can register any DM element
**
**************************************************************************/
bool DEVICE_UDS_DoRegistrationRestrictionsApply(int instance)
{
    uds_conn_params_t *ucp;

    // Exit if instance was not found. In this case we return that registration restrictions apply
    ucp = FindUdsParamsByInstance(instance);
    if (ucp == NULL)
    {
        return true;
    }

    return ucp->registration_restricted;
}

/*********************************************************************//**
**
** DEVICE_UDS_IsAuthRequired
**
** Determines whether the specified UDS instance requires authentication or not
**
** \param   instance - Instance number in Device.UnixDomainSockets.UnixDomainSocket.{i}
**
** \return  true if authentication is required, false otherwise
**
**************************************************************************/
bool DEVICE_UDS_IsAuthRequired(int instance)
{
    uds_conn_params_t *ucp;

    // Exit if instance was not found. In this case we return that authentication is required
    ucp = FindUdsParamsByInstance(instance);
    if (ucp == NULL)
    {
        return true;
    }

    return ucp->auth_required;
}

/*********************************************************************//**
**
** ValidateAdd_UdsConn
**
** Function called to determine whether a new UDS connection may be added
**
** \param   req - pointer to structure identifying the UDS connection
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ValidateAdd_UdsConn(dm_req_t *req)
{
    uds_conn_params_t *ucp;

    // Exit if unable to find a free UDS connection slot
    ucp = FindUnusedUdsParams();
    if (ucp == NULL)
    {
        USP_ERR_SetMessage("%s: Only %d UDS connections are supported.", __FUNCTION__, (int) NUM_ELEM(uds_conn_params));
        return USP_ERR_RESOURCES_EXCEEDED;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Validate_UdsMode
**
** Validates Device.UnixDomainSockets.UnixDomainSocket.{i}.Mode
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Validate_UdsMode(dm_req_t *req, char *value)
{
    uds_connection_type_t mode;

    // Exit if mode was invalid
    mode = TEXT_UTILS_StringToEnum(value, uds_modes, NUM_ELEM(uds_modes));
    if (mode == kUdsConnType_Invalid)
    {
        USP_ERR_SetMessage("%s: Invalid mode (%s) for %s.", __FUNCTION__, value, req->path);
        return USP_ERR_INVALID_VALUE;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Validate_UdsPath
**
** Validates Device.UnixDomainSockets.UnixDomainSocket.{i}.Path
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Validate_UdsPath(dm_req_t *req, char *value)
{
    int max_len;

    max_len = sizeof(((struct sockaddr_un *)NULL)->sun_path) - 1;  // Minus 1 to include NULL terminator
    if (strlen(value) > max_len)
    {
        USP_ERR_SetMessage("%s: UDS socket path too long", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Validate_UdsAuthEndpointID
**
** Validates new values of Device.UnixDomainSockets.Authentication.{i}.EndpointID
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of the parameter for this instance which the controller would like to set
**
** \return  USP_ERR_OK if retrieved successfully
**
**************************************************************************/
int Validate_UdsAuthEndpointID(dm_req_t *req, char *value)
{
    uds_auth_t *ua;
    char buf[MAX_DM_SHORT_VALUE_LEN];

    // Exit if an empty endpoint_id was given
    if (*value == '\0')
    {
        USP_ERR_SetMessage("%s: EndpointID should not be an empty string", __FUNCTION__);
        return USP_ERR_INVALID_ARGUMENTS;
    }

    // Exit if this instance already has an EndpointID setup (because we don't allow it to be changed, once created)
    USP_SNPRINTF(buf, sizeof(buf), AUTO_EID_PREFIX "%d", inst1);
    ua = FindUdsAuthByInstance(inst1);
    if ((ua != NULL) && (strcmp(ua->endpoint_id, buf) != 0))
    {
        USP_ERR_SetMessage("%s: EndpointID cannot be changed from %s", __FUNCTION__, ua->endpoint_id);
        return USP_ERR_INVALID_ARGUMENTS;
    }

    // Exit if a list of EndpointIDs were given
    if (strchr(value, ',') != NULL)
    {
        USP_ERR_SetMessage("%s: EndpointID ('%s') should not be a list", __FUNCTION__, value);
        return USP_ERR_INVALID_ARGUMENTS;
    }

    // Exit if this Endpoint already exists in the table
    ua = FindUdsAuthByEndpointId(value);
    if (ua != NULL)
    {
        USP_ERR_SetMessage("%s: Entry already exists for EndpointID='%s'", __FUNCTION__, value);
        return USP_ERR_INVALID_ARGUMENTS;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_UdsConnAdded
**
** Function called when a Uds Connection has been added to Device.UnixDomainSockets.UnixDomainSocket.{i}
**
** \param   req - pointer to structure identifying the UDS connection
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_UdsConnAdded(dm_req_t *req)
{
    int err;
    uds_conn_params_t *ucp;

    // Exit if failed to copy from DB into UDS_connection array
    err = ProcessUdsConnAdded(inst1);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Start the connection (if enabled)
    ucp = FindUdsParamsByInstance(inst1);
    USP_ASSERT(ucp != NULL);         // As we had just successfully added it

    // Exit if no free slots to enable the connection. (Enable is successful, even if the connection is trying to reconnect)
    err = UDS_EnableConnection(ucp);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_UdsConnDeleted
**
** Function called when a UDS Connection has been deleted from Device.UnixDomainSockets.UnixDomainSocket.{i}
**
** \param   req - pointer to structure identifying the connection
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_UdsConnDeleted(dm_req_t *req)
{
    uds_conn_params_t *ucp;

    // Exit if connection already deleted
    // NOTE: We might not find it if it was never added. This could occur if deleting from the DB at startup when we detected that the database params were invalid
    ucp = FindUdsParamsByInstance(inst1);
    if (ucp == NULL)
    {
        return USP_ERR_OK;
    }

    // Delete the connection from the array, and tell the lower level MTP to disconnect
    DestroyUdsConn(ucp);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_UdsAuthAdded
**
** Function called when an instance has been added to Device.UnixDomainSockets.Authentication.{i}
**
** \param   req - pointer to structure identifying the instance
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_UdsAuthAdded(dm_req_t *req)
{
    int err;

    // Exit if failed to copy from DB into UDS_connection array
    err = ProcessUdsAuthAdded(inst1);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_UdsAuthDeleted
**
** Function called when an instance has been deleted from Device.UnixDomainSockets.Authentication.{i}
**
** \param   req - pointer to structure identifying the instance
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_UdsAuthDeleted(dm_req_t *req)
{
    uds_auth_t *ua;

    // Exit if auth already deleted
    // NOTE: We might not find it if it was never added. This could occur if deleting from the DB at startup when we detected that the database params were invalid
    ua = FindUdsAuthByInstance(inst1);
    if (ua == NULL)
    {
        return USP_ERR_OK;
    }

    // Inform the UDS MTP of the change
    UDS_RemoveAuthPassword(ua->endpoint_id);

    // Delete the auth
    RemoveUdsAuth(ua);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** NotifyChange_UdsMode
**
** Function called when Device.UnixDomainSockets.UnixDomainSocket.{i}.Mode is modified
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int NotifyChange_UdsMode(dm_req_t *req, char *value)
{
    uds_conn_params_t *ucp;
    uds_connection_type_t new_mode;
    bool schedule_reconnect = false;

    // Determine UDS connection to be updated
    ucp = FindUdsParamsByInstance(inst1);
    USP_ASSERT(ucp != NULL);

    // Determine whether to schedule a reconnect
    new_mode = TEXT_UTILS_StringToEnum(value, uds_modes, NUM_ELEM(uds_modes));
    if (new_mode != ucp->mode)
    {
        schedule_reconnect = true;
    }

    // Set the new value. This must be done before scheduling a reconnect, so that the reconnect uses the correct values
    ucp->mode = new_mode;

    // Schedule a reconnect after the present response has been sent, if the value has changed
    if (schedule_reconnect)
    {
        UDS_ScheduleReconnect(ucp);
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** NotifyChange_UdsPath
**
** Function called when Device.UnixDomainSockets.UnixDomainSocket.{i}.Mode is changed
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int NotifyChange_UdsPath(dm_req_t *req, char *value)
{
    uds_conn_params_t *ucp;
    bool schedule_reconnect = false;

    // Determine UDS connection to be updated
    ucp = FindUdsParamsByInstance(inst1);
    USP_ASSERT(ucp != NULL);

    // Determine whether to schedule a reconnect
    if (strcmp(ucp->path, value) != 0)
    {
        schedule_reconnect = true;
    }

    // Set the new value. This must be done before scheduling a reconnect, so that the reconnect uses the correct values
    USP_SAFE_FREE(ucp->path);
    ucp->path = USP_STRDUP(value);
    ucp->path_type = DEVICE_MTP_CalcUdsPathType(inst1);

    // Schedule a reconnect after the present response has been sent, if the value has changed
    if (schedule_reconnect)
    {
        UDS_ScheduleReconnect(ucp);
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** NotifyChange_UdsAuthRequired
**
** Function called when Device.UnixDomainSockets.UnixDomainSocket.{i}.AuthRequired is changed
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int NotifyChange_UdsAuthRequired(dm_req_t *req, char *value)
{
    uds_conn_params_t *ucp;
    bool schedule_reconnect = false;

    // Determine UDS connection to be updated
    ucp = FindUdsParamsByInstance(inst1);
    USP_ASSERT(ucp != NULL);

    // Determine whether to schedule a reconnect
    if (val_bool != ucp->auth_required)
    {
        schedule_reconnect = true;
    }

    // Set the new value. This must be done before scheduling a reconnect, so that the reconnect uses the correct values
    ucp->auth_required = val_bool;

    // Schedule a reconnect after the present response has been sent, if the value has changed
    if (schedule_reconnect)
    {
        UDS_ScheduleReconnect(ucp);
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** NotifyChange_UdsRegistrationRestricted
**
** Function called when Device.UnixDomainSockets.UnixDomainSocket.{i}.RegistrationRestricted is changed
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int NotifyChange_UdsRegistrationRestricted(dm_req_t *req, char *value)
{
    uds_conn_params_t *ucp;
    bool schedule_reconnect = false;

    // Determine UDS connection to be updated
    ucp = FindUdsParamsByInstance(inst1);
    USP_ASSERT(ucp != NULL);

    // Determine whether to schedule a reconnect
    if (val_bool != ucp->registration_restricted)
    {
        schedule_reconnect = true;
    }

    // Set the new value. This must be done before scheduling a reconnect, so that the reconnect uses the correct values
    ucp->registration_restricted = val_bool;

    // Schedule a reconnect after the present response has been sent, if the value has changed
    if (schedule_reconnect)
    {
        UDS_ScheduleReconnect(ucp);
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** NotifyChange_UdsAuthEnable
**
** Function called when Device.UnixDomainSockets.Authentication.{i}.Enable is changed from the auto-assigned default
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int NotifyChange_UdsAuthEnable(dm_req_t *req, char *value)
{
    uds_auth_t *ua;

    ua = FindUdsAuthByInstance(inst1);
    USP_ASSERT(ua != NULL);

    UDS_RemoveAuthPassword(ua->endpoint_id);

    ua->enable = val_bool;

    if (ua->enable == true)
    {
        UDS_AddAuthPassword(ua->endpoint_id, ua->password);
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** NotifyChange_UdsAuthEndpointID
**
** Function called when Device.UnixDomainSockets.Authentication.{i}.EndpointID is changed from the auto-assigned default
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int NotifyChange_UdsAuthEndpointID(dm_req_t *req, char *value)
{
    uds_auth_t *ua;

    ua = FindUdsAuthByInstance(inst1);
    USP_ASSERT(ua != NULL);

    UDS_RemoveAuthPassword(ua->endpoint_id);

    USP_SAFE_FREE(ua->endpoint_id);
    ua->endpoint_id = USP_STRDUP(value);

    if (ua->enable == true)
    {
        UDS_AddAuthPassword(ua->endpoint_id, ua->password);
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** NotifyChange_UdsAuthPassword
**
** Function called when Device.UnixDomainSockets.Authentication.{i}.Password is changed
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int NotifyChange_UdsAuthPassword(dm_req_t *req, char *value)
{
    uds_auth_t *ua;

    ua = FindUdsAuthByInstance(inst1);
    USP_ASSERT(ua != NULL);

    USP_SAFE_FREE(ua->password);
    ua->password = USP_STRDUP(value);

    // Inform MTP of the change
    UDS_ModifyAuthPassword(ua->endpoint_id, ua->password);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** NotifyChange_UdsSelfPassword
**
** Function called when Internal.UDS.SelfPassword is changed
**
** \param   req - pointer to structure identifying the path (unused)
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int NotifyChange_UdsSelfPassword(dm_req_t *req, char *value)
{
    int err;
    char buf[MAX_DM_VALUE_LEN];
    dm_vendor_get_uds_password_cb_t  get_uds_password_cb;

    // Override the password from the DB with one from a vendor hook if registered
    get_uds_password_cb = vendor_hook_callbacks.get_uds_password_cb;
    if (get_uds_password_cb != NULL)
    {
        err = get_uds_password_cb(buf, sizeof(buf));
        if (err == USP_ERR_OK)
        {
            value = buf;
        }
    }

    // Inform MTP of the change
    UDS_SetSelfPassword(value);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DestroyUdsConn
**
** Frees all memory associated with the specified UDS connection slot
**
** \param   sp - pointer to UDS connection to free
**
** \return  None
**
**************************************************************************/
void DestroyUdsConn(uds_conn_params_t *ucp)
{
    // Disable the lower level connection
    UDS_DisableConnection(ucp->instance);

    // Free and DeInitialise the slot
    ucp->instance = INVALID;      // Mark slot as free
    USP_SAFE_FREE(ucp->path);
}

/*********************************************************************//**
**
** ProcessUdsConnAdded
**
** Reads the parameters for the specified UDS Connection from the database and processes them
**
** \param   instance - instance number in Device.UnixDomainSockets.UnixDomainSocket.{i}
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ProcessUdsConnAdded(int instance)
{
    uds_conn_params_t *ucp;
    int err;
    char path[MAX_DM_PATH];

    // Exit if unable to add another UDS connection
    ucp = FindUnusedUdsParams();
    if (ucp == NULL)
    {
        USP_ERR_SetMessage("%s: Only %d UDS connections are supported.", __FUNCTION__, (int) NUM_ELEM(uds_conn_params));
        return USP_ERR_RESOURCES_EXCEEDED;
    }

    // Initialise to defaults
    memset(ucp, 0, sizeof(uds_conn_params_t));
    ucp->instance = instance;

    // Get Device.UnixDomainSockets.UnixDomainSocket.{i}.Mode from USP DB
    USP_SNPRINTF(path, sizeof(path), "%s.%d.Mode", device_uds_conn_root, instance);
    err = DM_ACCESS_GetEnum(path, &ucp->mode, uds_modes, NUM_ELEM(uds_modes));
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Get Device.UnixDomainSockets.UnixDomainSocket.{i}.Path from USP DB
    USP_SNPRINTF(path, sizeof(path), "%s.%d.Path", device_uds_conn_root, instance);
    err = DM_ACCESS_GetString(path, &ucp->path);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }
    ucp->path_type = DEVICE_MTP_CalcUdsPathType(instance);

    // Get Device.UnixDomainSockets.UnixDomainSocket.{i}.AuthRequired from USP DB
    USP_SNPRINTF(path, sizeof(path), "%s.%d.AuthRequired", device_uds_conn_root, instance);
    err = DM_ACCESS_GetBool(path, &ucp->auth_required);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Get Device.UnixDomainSockets.UnixDomainSocket.{i}.RegistrationRestricted from USP DB
    USP_SNPRINTF(path, sizeof(path), "%s.%d.RegistrationRestricted", device_uds_conn_root, instance);
    err = DM_ACCESS_GetBool(path, &ucp->registration_restricted);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // If the code gets here, then we successfully retrieved all data about the UDS connection
    err = USP_ERR_OK;

exit:
    if (err != USP_ERR_OK)
    {
        DestroyUdsConn(ucp);
    }

    return err;
}

/*********************************************************************//**
**
** RemoveUdsAuth
**
** Frees all memory associated with the specified UDS auth slot
**
** \param   ua - pointer to UDS authentication to free
**
** \return  None
**
**************************************************************************/
void RemoveUdsAuth(uds_auth_t *ua)
{
    int index;
    int items_to_move;

    // Free memory used by this entry
    USP_SAFE_FREE(ua->endpoint_id);
    USP_SAFE_FREE(ua->password);

    // Move later entries down
    index = ua - uds_auths;
    items_to_move = num_uds_auths - index - 1;
    if (items_to_move > 0)
    {
        memmove(&uds_auths[index], &uds_auths[index+1], items_to_move*sizeof(uds_auth_t));
    }
    num_uds_auths--;

    // Compact the vector
    if (num_uds_auths == 0)
    {
        USP_FREE(uds_auths);
        uds_auths = NULL;
    }
    else
    {
        uds_auths = USP_REALLOC(uds_auths, num_uds_auths*sizeof(uds_auth_t));
    }
}

/*********************************************************************//**
**
** ProcessUdsAuthAdded
**
** Reads the parameters for the specified UDS Authentication from the database and processes them
**
** \param   instance - instance number in Device.UnixDomainSockets.Authentication.{i}
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ProcessUdsAuthAdded(int instance)
{
    uds_auth_t *ua;
    int err;
    char path[MAX_DM_PATH];
    bool enable;
    char *endpoint_id = NULL;
    char *password = NULL;
    int new_num_entries;

    // Get Device.UnixDomainSockets.Authentication.{i}.Enable from USP DB
    USP_SNPRINTF(path, sizeof(path), "%s.%d.Enable", device_uds_auth_root, instance);
    err = DM_ACCESS_GetBool(path, &enable);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Get Device.UnixDomainSockets.Authentication.{i}.EndpointID from USP DB
    USP_SNPRINTF(path, sizeof(path), "%s.%d.EndpointID", device_uds_auth_root, instance);
    err = DM_ACCESS_GetString(path, &endpoint_id);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if EID is an empty string
    if (*endpoint_id == '\0')
    {
        USP_ERR_SetMessage("%s: %s should not be an empty string", __FUNCTION__, path);
        err = USP_ERR_INVALID_ARGUMENTS;
        goto exit;
    }

    // Exit if this EndpointID is already in the table (ie this entry is not unique)
    ua = FindUdsAuthByEndpointId(endpoint_id);
    if (ua != NULL)
    {
        USP_ERR_SetMessage("%s: %s.%d has the same EndpointID as %s.%d", __FUNCTION__, device_uds_auth_root, instance, device_uds_auth_root, ua->instance);
        err = USP_ERR_INVALID_ARGUMENTS;
        goto exit;
    }

    // Get Device.UnixDomainSockets.Authentication.{i}.Password from USP DB
    USP_SNPRINTF(path, sizeof(path), "%s.%d.Password", device_uds_auth_root, instance);
    err = DM_ACCESS_GetPassword(path, &password);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Increase UDS auth array size
    new_num_entries = num_uds_auths + 1;
    uds_auths = USP_REALLOC(uds_auths, new_num_entries*sizeof(uds_auth_t));
    ua = &uds_auths[num_uds_auths];
    num_uds_auths = new_num_entries;

    // Fill in the entry. NOTE: ownership of endpoint_id and password move to the entry
    memset(ua, 0, sizeof(uds_auth_t));
    ua->instance = instance;
    ua->enable = enable;
    ua->endpoint_id = endpoint_id;
    ua->password = password;

    // Update UDS MTP
    if (ua->enable == true)
    {
        UDS_AddAuthPassword(ua->endpoint_id, ua->password);
    }

    err = USP_ERR_OK;

exit:
    if (err != USP_ERR_OK)
    {
        USP_SAFE_FREE(endpoint_id);
        USP_SAFE_FREE(password);
    }

    return err;
}

/*********************************************************************//**
**
** FindUnusedUdsParams
**
** Finds the first free UDS params slot
**
** \param   None
**
** \return  Pointer to first free slot, or NULL if no slot was found
**
**************************************************************************/
uds_conn_params_t *FindUnusedUdsParams(void)
{
    int i;
    uds_conn_params_t *ucp;

    // Iterate over all UDS connections
    for (i=0; i<NUM_ELEM(uds_conn_params); i++)
    {
        // Exit if found an unused slot
        ucp = &uds_conn_params[i];
        if (ucp->instance == INVALID)
        {
            return ucp;
        }
    }

    // If the code gets here, then no free slot has been found
    return NULL;
}

/*********************************************************************//**
**
** FindUdsParamsByInstance
**
** Finds the UDS params slot by it's data model instance number
**
** \param   instance - instance number in Device.UnixDomainSockets.UnixDomainSocket.{i}
**
** \return  pointer to slot, or NULL if slot was not found
**
**************************************************************************/
uds_conn_params_t *FindUdsParamsByInstance(int instance)
{
    int i;
    uds_conn_params_t *ucp;

    // Iterate over all UDS connections
    for (i=0; i<NUM_ELEM(uds_conn_params); i++)
    {
        // Exit if found a uds connection that matches the instance number
        ucp = &uds_conn_params[i];
        if (ucp->instance == instance)
        {
            return ucp;
        }
    }

    // If the code gets here, then no matching slot was found
    return NULL;
}

/*********************************************************************//**
**
** FindUdsAuthByInstance
**
** Finds the UDS auth slot by it's data model instance number
**
** \param   instance - instance number in Device.UnixDomainSockets.Authentication.{i}
**
** \return  pointer to slot, or NULL if slot was not found
**
**************************************************************************/
uds_auth_t *FindUdsAuthByInstance(int instance)
{
    int i;
    uds_auth_t *ua;

    // Iterate over all UDS auth slots
    for (i=0; i<num_uds_auths; i++)
    {
        // Exit if found a uds auth that matches the instance number
        ua = &uds_auths[i];
        if (ua->instance == instance)
        {
            return ua;
        }
    }

    // If the code gets here, then no matching slot was found
    return NULL;
}

/*********************************************************************//**
**
** FindUdsAuthByEndpointId
**
** Finds the UDS auth slot by it's EndpointId
**
** \param   endpoint_id - EndpointID of the entry to match
**
** \return  pointer to slot, or NULL if slot was not found
**
**************************************************************************/
uds_auth_t *FindUdsAuthByEndpointId(char *endpoint_id)
{
    int i;
    uds_auth_t *ua;

    // Iterate over all UDS auth slots
    for (i=0; i<num_uds_auths; i++)
    {
        // Exit if found a uds auth that matches the endpoint_id
        ua = &uds_auths[i];
        if (strcmp(ua->endpoint_id, endpoint_id)==0)
        {
            return ua;
        }
    }

    // If the code gets here, then no matching slot was found
    return NULL;
}


#endif /* ENABLE_UDS */
