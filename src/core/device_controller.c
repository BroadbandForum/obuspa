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
 * \file device_controller.c
 *
 * Implements the Device.Controller data model object
 *
 */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <limits.h>

#include "common_defs.h"
#include "data_model.h"
#include "device.h"
#include "usp_api.h"
#include "dm_access.h"
#include "dm_trans.h"
#include "mtp_exec.h"
#include "msg_handler.h"
#include "text_utils.h"
#include "iso8601.h"
#include "retry_wait.h"

#ifdef ENABLE_COAP
#include "usp_coap.h"
#endif
//------------------------------------------------------------------------------
// Location of the controller table within the data model
#define DEVICE_CONT_ROOT "Device.LocalAgent.Controller"
static const char device_cont_root[] = DEVICE_CONT_ROOT;

//------------------------------------------------------------------------------
// Time at which next periodic notification should fire
static time_t first_periodic_notification_time = (time_t) INT_MAX;

//------------------------------------------------------------------------------
// Structure representing entries in the Device.LocalAgent.Controller.{i}.MTP.{i} table
typedef struct
{
    int instance;         // instance of the MTP in the Device.LocalAgent.Controller.{i}.MTP.{i} table
                          // This value will be marked as INVALID, if the entry is not currently being used
    bool enable;
    mtp_protocol_t protocol;

    // NOTE: The following is not a union, because the data model would allow both MTP.{i}.STOMP and MTP.{i}.CoAP objects to be seeded at the same time - with protocol choosing which one is active
    int stomp_connection_instance;
    char *stomp_controller_queue;

#ifdef ENABLE_COAP
    char *coap_controller_host;
    coap_config_t coap;
#endif

} controller_mtp_t;

//------------------------------------------------------------------------------
// Structure representing entries in the Device.LocalAgent.Controller.{i} table
typedef struct
{
    int instance;      // instance of the controller in the Device.LocalAgent.Controller.{i} table
                       // This value will be marked as INVALID, if the entry is not currently being used
    bool enable;
    char *endpoint_id;
    controller_mtp_t mtps[MAX_CONTROLLER_MTPS];  // Array of controller MTPs

    time_t periodic_base;
    unsigned periodic_interval;
    time_t next_time_to_fire;   // Absolute time at which periodic notification should fire for this controller
    combined_role_t combined_role; // Inherited and Assigned roles to use for this controller

    unsigned subs_retry_min_wait_interval;
    unsigned subs_retry_interval_multiplier;

} controller_t;

// Array of controllers
static controller_t controllers[MAX_CONTROLLERS];

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
void PeriodicNotificationExec(int id);
int ValidateAdd_Controller(dm_req_t *req);
int ValidateAdd_ControllerMtp(dm_req_t *req);
int Notify_ControllerAdded(dm_req_t *req);
int Notify_ControllerDeleted(dm_req_t *req);
int Notify_ControllerMtpAdded(dm_req_t *req);
int Notify_ControllerMtpDeleted(dm_req_t *req);
int Validate_ControllerEndpointID(dm_req_t *req, char *value);
int Validate_ControllerMtpEnable(dm_req_t *req, char *value);
int Validate_ControllerMtpProtocol(dm_req_t *req, char *value);
int Validate_PeriodicNotifInterval(dm_req_t *req, char *value);
int Validate_ControllerRetryMinimumWaitInterval(dm_req_t *req, char *value);
int Validate_ControllerRetryIntervalMultiplier(dm_req_t *req, char *value);
int Notify_ControllerEnable(dm_req_t *req, char *value);
int Notify_ControllerEndpointID(dm_req_t *req, char *value);
int Notify_ControllerMtpEnable(dm_req_t *req, char *value);
int Notify_ControllerMtpProtocol(dm_req_t *req, char *value);
int Notify_ControllerMtpStompReference(dm_req_t *req, char *value);
int Notify_ControllerMtpStompDestination(dm_req_t *req, char *value);
int Notify_PeriodicNotifInterval(dm_req_t *req, char *value);
int Notify_PeriodicNotifTime(dm_req_t *req, char *value);
int Notify_ControllerRetryMinimumWaitInterval(dm_req_t *req, char *value);
int Notify_ControllerRetryIntervalMultiplier(dm_req_t *req, char *value);
int Get_ControllerInheritedRole(dm_req_t *req, char *buf, int len);
int ProcessControllerAdded(int cont_instance);
int ProcessControllerMtpAdded(controller_t *cont, int mtp_instance);
controller_t *FindUnusedController(void);
controller_mtp_t *FindUnusedControllerMtp(controller_t *cont);
controller_mtp_t *FindControllerMtpFromReq(dm_req_t *req, controller_t **p_cont);
controller_t *FindControllerByInstance(int cont_instance);
controller_t *FindControllerByEndpointId(char *endpoint_id);
controller_t *FindEnabledControllerByEndpointId(char *endpoint_id);
controller_mtp_t *FindFirstEnabledMtp(controller_t *cont, mtp_protocol_t preferred_protocol);
controller_mtp_t *FindControllerMtpByInstance(controller_t *cont, int mtp_instance);
void DestroyController(controller_t *cont);
void DestroyControllerMtp(controller_mtp_t *mtp);
int ValidateStompMtpUniquenessReq(dm_req_t *req);
int ValidateStompMtpUniqueness(controller_t *cont, int mtp_instance);
int ValidateEndpointIdUniqueness(char *endpoint_id, int instance);
time_t CalcNextPeriodicTime(time_t cur_time, time_t periodic_base, int periodic_interval);
void UpdateFirstPeriodicNotificationTime(void);
int Validate_ControllerAssignedRole(dm_req_t *req, char *value);
int Notify_ControllerAssignedRole(dm_req_t *req, char *value);
int UpdateAssignedRole(controller_t *cont, char *reference);

#ifdef ENABLE_COAP
int Notify_ControllerMtpCoapHost(dm_req_t *req, char *value);
int Notify_ControllerMtpCoapPort(dm_req_t *req, char *value);
int Notify_ControllerMtpCoapPath(dm_req_t *req, char *value);
int Notify_ControllerMtpCoapEncryption(dm_req_t *req, char *value);
#endif

/*********************************************************************//**
**
** DEVICE_CONTROLLER_Init
**
** Initialises this component, and registers all parameters which it implements
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_CONTROLLER_Init(void)
{
    int err = USP_ERR_OK;
    int i, j;
    controller_t *cont;
    controller_mtp_t *mtp;

    // Add timer to be called back when first periodic notification fires
    first_periodic_notification_time = (time_t) INT_MAX;
    SYNC_TIMER_Add(PeriodicNotificationExec, 0, first_periodic_notification_time);

    // Mark all controller and mtp slots as unused
    memset(controllers, 0, sizeof(controllers));
    for (i=0; i<MAX_CONTROLLERS; i++)
    {
        cont = &controllers[i];
        cont->instance = INVALID;

        for (j=0; j<MAX_CONTROLLER_MTPS; j++)
        {
            mtp = &cont->mtps[j];
            mtp->instance = INVALID;
        }
    }

    // Register parameters implemented by this component
    err |= USP_REGISTER_Object(DEVICE_CONT_ROOT ".{i}", ValidateAdd_Controller, NULL, Notify_ControllerAdded, 
                                                        NULL, NULL, Notify_ControllerDeleted);
    err |= USP_REGISTER_Object(DEVICE_CONT_ROOT ".{i}.MTP.{i}", ValidateAdd_ControllerMtp, NULL, Notify_ControllerMtpAdded, 
                                                                NULL, NULL, Notify_ControllerMtpDeleted);
    err |= USP_REGISTER_DBParam_Alias(DEVICE_CONT_ROOT ".{i}.Alias", NULL); 
    err |= USP_REGISTER_DBParam_Alias(DEVICE_CONT_ROOT ".{i}.MTP.{i}.Alias", NULL); 

    err |= USP_REGISTER_Param_NumEntries("Device.LocalAgent.ControllerNumberOfEntries", DEVICE_CONT_ROOT ".{i}");
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.Enable", "false", NULL, Notify_ControllerEnable, DM_BOOL);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.EndpointID", "", Validate_ControllerEndpointID, Notify_ControllerEndpointID, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CONT_ROOT ".{i}.InheritedRole", Get_ControllerInheritedRole, DM_STRING);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.AssignedRole", "", Validate_ControllerAssignedRole, Notify_ControllerAssignedRole, DM_STRING);

    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.PeriodicNotifInterval", "86400", NULL, Notify_PeriodicNotifInterval, DM_UINT);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.PeriodicNotifTime", UNKNOWN_TIME_STR, NULL, Notify_PeriodicNotifTime, DM_DATETIME);
    err |= USP_REGISTER_Event("Device.LocalAgent.Periodic!");

    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.USPRetryMinimumWaitInterval", "5", Validate_ControllerRetryMinimumWaitInterval, Notify_ControllerRetryMinimumWaitInterval, DM_UINT);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.USPRetryIntervalMultiplier", "2000", Validate_ControllerRetryIntervalMultiplier, Notify_ControllerRetryIntervalMultiplier, DM_UINT);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.ControllerCode", "", NULL, NULL, DM_STRING);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.ProvisioningCode", "", NULL, NULL, DM_STRING);

    err |= USP_REGISTER_Param_NumEntries(DEVICE_CONT_ROOT ".{i}.MTPNumberOfEntries", "Device.LocalAgent.Controller.{i}.MTP.{i}");
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.MTP.{i}.Enable", "false", Validate_ControllerMtpEnable, Notify_ControllerMtpEnable, DM_BOOL);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.MTP.{i}.Protocol", "CoAP", Validate_ControllerMtpProtocol, Notify_ControllerMtpProtocol, DM_STRING);

    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.MTP.{i}.STOMP.Reference", "", DEVICE_MTP_ValidateStompReference, Notify_ControllerMtpStompReference, DM_STRING);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.MTP.{i}.STOMP.Destination", "", NULL, Notify_ControllerMtpStompDestination, DM_STRING);

#ifdef ENABLE_COAP
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.MTP.{i}.CoAP.Host", "", NULL, Notify_ControllerMtpCoapHost, DM_STRING);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.MTP.{i}.CoAP.Port", "5683", DM_ACCESS_ValidatePort, Notify_ControllerMtpCoapPort, DM_UINT);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.MTP.{i}.CoAP.Path", "", NULL, Notify_ControllerMtpCoapPath, DM_STRING);
    err |= USP_REGISTER_DBParam_ReadWrite(DEVICE_CONT_ROOT ".{i}.MTP.{i}.CoAP.EnableEncryption", "true", NULL, Notify_ControllerMtpCoapEncryption, DM_BOOL);

#endif

    // Register unique keys for all tables
    char *cont_unique_keys[] = { "EndpointID" };
    err |= USP_REGISTER_Object_UniqueKey(DEVICE_CONT_ROOT ".{i}", cont_unique_keys, NUM_ELEM(cont_unique_keys));

    char *mtp_unique_keys[] = { "Protocol" };
    err |= USP_REGISTER_Object_UniqueKey(DEVICE_CONT_ROOT ".{i}.MTP.{i}", mtp_unique_keys, NUM_ELEM(mtp_unique_keys));

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
** DEVICE_CONTROLLER_Start
**
** Initialises the controllers array with the values of all controllers from the DB
** NOTE: If the database contains invalid data, then entries will be deleted
**       We need to do this otherwise it would be possible to set bad DB values to good, 
**       but our code would not pick them up because they were not in the internal data structure
**       This function ensures that the database and the internal controller data structure it populates always match
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_CONTROLLER_Start(void)
{
    int i;
    int err;
    int_vector_t iv;
    int cont_instance;
    char path[MAX_DM_PATH];

    // Exit if unable to get the object instance numbers present in the controllers table
    err = DATA_MODEL_GetInstances(DEVICE_CONT_ROOT, &iv);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit, issuing a warning, if no controllers are present in database
    if (iv.num_entries == 0)
    {
        USP_LOG_Warning("%s: WARNING: No instances in %s", __FUNCTION__, device_cont_root);
        err = USP_ERR_OK;
        goto exit;
    }

    // Add all controllers from the controllers table to the controllers array
    for (i=0; i < iv.num_entries; i++)
    {
        cont_instance = iv.vector[i];
        err = ProcessControllerAdded(cont_instance);
        if (err != USP_ERR_OK)
        {
            // Exit if unable to delete a controller with bad parameters from the DB
            USP_SNPRINTF(path, sizeof(path), "%s.%d", device_cont_root, cont_instance);
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
** DEVICE_CONTROLLER_Stop
**
** Frees up all memory associated with this module
**
** \param   None
**
** \return  None
**
**************************************************************************/
void DEVICE_CONTROLLER_Stop(void)
{
    int i;
    controller_t *cont;

    // Iterate over all controllers, freeing all memory used by them
    for (i=0; i<MAX_CONTROLLERS; i++)
    {
        cont = &controllers[i];
        if (cont->instance != INVALID)
        {
            DestroyController(cont);
        }
    }
}

/*********************************************************************//**
**
** DEVICE_CONTROLLER_FindInstanceByEndpointId
** 
** Gets the instance number of the enabled controller (in Device.Controller.{i}) based on the specified endpoint_id
** 
** \param   endpoint_id - controller that we want to find the instance number of
** 
** \return  instance number of controller, or INVALID if unable to find the enabled controller
**
**************************************************************************/
int DEVICE_CONTROLLER_FindInstanceByEndpointId(char *endpoint_id)
{
    controller_t *cont;

    // Exit if no endpoint_id set by caller
    if (endpoint_id == NULL)
    {
        return INVALID;
    }

    // Exit if unable to find a matching, enabled controller
    cont = FindEnabledControllerByEndpointId(endpoint_id);
    if (cont == NULL)
    {
        return INVALID;
    }

    // Found the matching instance
    return cont->instance;
}

/*********************************************************************//**
**
** DEVICE_CONTROLLER_FindEndpointIdByInstance
** 
** Gets the endpoint_id of the specified enabled controller
** 
** \param   instance - instance number of the controller in the Device.Controller.{i} table
** 
** \return  pointer to endpoint_id of the controller, or NULL if no controller found, or controller was disabled
**
**************************************************************************/
char *DEVICE_CONTROLLER_FindEndpointIdByInstance(int instance)
{
    controller_t *cont;

    // Exit if unable to find a matching, enabled controller
    cont = FindControllerByInstance(instance);
    if ((cont == NULL) || (cont->enable == false))
    {
        return NULL;
    }

    // Found the matching instance
    return cont->endpoint_id;
}

/*********************************************************************//**
**
** DEVICE_CONTROLLER_GetSubsRetryParams
** 
** Gets the subscription retry parameters for the specified endpoint_id
** 
** \param   endpoint_id - controller that we want to get the retry parameters for
** \param   min_wait_interval - pointer to variable in which to return the minimum wait interval
** \param   interval_multiplier - pointer to variable in which to return the interval multiplier
** 
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_CONTROLLER_GetSubsRetryParams(char *endpoint_id, unsigned *min_wait_interval, unsigned *interval_multiplier)
{
    controller_t *cont;

    // Exit if unable to find a matching, enabled controller
    cont = FindEnabledControllerByEndpointId(endpoint_id);
    if (cont == NULL)
    {
        USP_LOG_Warning("%s: Unable to find enabled controller with endpoint_id=%s", __FUNCTION__, endpoint_id);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Found the matching instance, so copy the retry params
    *min_wait_interval = cont->subs_retry_min_wait_interval;
    *interval_multiplier = cont->subs_retry_interval_multiplier;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_CONTROLLER_GetCombinedRole
** 
** Gets the inherited and assigned role to use for the specified controller instance
** This is used when resolving paths used by subscriptions
** 
** \param   instance - instance number of the controller in Device.LocalAgent.Controller.{i}
** \param   combined_role - pointer to variable in which to return the combined role
** 
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_CONTROLLER_GetCombinedRole(int instance, combined_role_t *combined_role)
{
    controller_t *cont;

    // Exit if unable to find a matching enabled controller
    cont = FindControllerByInstance(instance);
    if ((cont == NULL) || (cont->enable == false))
    {
        return USP_ERR_INTERNAL_ERROR;
    }


    // Copy across the combined role values    
    *combined_role = cont->combined_role;

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_CONTROLLER_GetCombinedRoleByEndpointId
** 
** Gets the combined role to use for the specified controller endpoint_id, when 
** processing request messages from that controller
** 
** \param   endpoint_id - endpoint_id of the controller
** 
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_CONTROLLER_GetCombinedRoleByEndpointId(char *endpoint_id, combined_role_t *combined_role)
{
    controller_t *cont;

    // Exit if unable to find a matching enabled controller
    cont = FindEnabledControllerByEndpointId(endpoint_id);
    if (cont == NULL)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // Copy across the combined role values    
    *combined_role = cont->combined_role;

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_CONTROLLER_SetRolesFromStomp
** 
** Sets the controller trust role to use for all controllers connected to the specified STOMP controller
** 
** \param   stomp_instance - STOMP instance (in Device.STOMP.Connection table)
** \param   role - Role allowed for this message
** \param   allowed_controllers - URN pattern containing the endpoint_id of allowed controllers
** 
** \return  None
**
**************************************************************************/
void DEVICE_CONTROLLER_SetRolesFromStomp(int stomp_instance, ctrust_role_t role, char *allowed_controllers)
{
    int i, j;
    controller_t *cont;
    controller_mtp_t *mtp;

    // Iterate over all enabled controllers
    for (i=0; i<MAX_CONTROLLERS; i++)
    {
        cont = &controllers[i];
        if ((cont->instance != INVALID) && (cont->enable))
        {
            // Iterate over all enabled MTP slots for this controller
            for (j=0; j<MAX_CONTROLLER_MTPS; j++)
            {
                mtp = &cont->mtps[j];
                if ((mtp->instance != INVALID) && (mtp->enable))
                {
                    // If this controller is connected to the specified STOMP connection, then set its inherited role
                    if ((mtp->protocol == kMtpProtocol_STOMP) && (mtp->stomp_connection_instance == stomp_instance))
                    {
                        cont->combined_role.inherited = role;
                    }
                }
            }
        }
    }
}

/*********************************************************************//**
**
** DEVICE_CONTROLLER_QueueBinaryMessage
** 
** Queues a binary message to be sent to a controller
** 
** \param   usp_msg_type - Type of USP message contained in pbuf. This is used for debug logging when the message is sent by the MTP.
** \param   endpoint_id - controller to send the message to
** \param   pbuf - pointer to buffer containing binary protobuf message. Ownership of this buffer passes to protocol handler, if successful
** \param   pbuf_len - length of buffer containing protobuf binary message
** \param   mrt - details of where this USP response message should be sent
** 
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_CONTROLLER_QueueBinaryMessage(Usp__Header__MsgType usp_msg_type, char *endpoint_id, unsigned char *pbuf, int pbuf_len, mtp_reply_to_t *mrt)
{
    int err = USP_ERR_INTERNAL_ERROR;
    controller_t *cont;
    controller_mtp_t *mtp;
    char *agent_queue;
    mtp_reply_to_t dest;

    // Take a copy of the MTP destination parameters we've been given
    // because we may modify it (and we don't want the caller to free anything we put in it, as they are owned by the data model)
    memcpy(&dest, mrt, sizeof(dest));

    // Exit if unable to find the specified controller
    cont = FindEnabledControllerByEndpointId(endpoint_id);
    if (cont == NULL)
    {
        USP_ERR_SetMessage("%s: Unable to find an enabled controller to send to endpoint_id=%s", __FUNCTION__, endpoint_id);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to find a controller MTP to send this message on
    mtp = FindFirstEnabledMtp(cont, mrt->protocol);
    if (mtp == NULL)
    {
        USP_ERR_SetMessage("%s: Unable to find a valid controller MTP to send to endpoint_id=%s", __FUNCTION__, endpoint_id);
        return USP_ERR_INTERNAL_ERROR;
    }

    // If 'reply-to' was not specified, then use the data model to fill in where the response should be sent
    // This is always the case for notifications, since they are not a response to any incoming USP message
    if (mrt->is_reply_to_specified == false)
    {
        switch(mtp->protocol)
        {
            case kMtpProtocol_STOMP:
                if (mtp->stomp_connection_instance == INVALID)
                {
                    USP_ERR_SetMessage("%s: No Stomp connection in controller MTP to send to endpoint_id=%s", __FUNCTION__, endpoint_id);
                    return USP_ERR_INTERNAL_ERROR;
                }
    
                dest.protocol = kMtpProtocol_STOMP;
                dest.stomp_instance = mtp->stomp_connection_instance;
                dest.stomp_dest = mtp->stomp_controller_queue;
                break;
    
#ifdef ENABLE_COAP
            case kMtpProtocol_CoAP:
                dest.protocol = kMtpProtocol_CoAP;
                dest.coap_host = mtp->coap_controller_host;
                dest.coap_port = mtp->coap.port;
                dest.coap_resource = mtp->coap.resource;
                dest.coap_encryption = mtp->coap.enable_encryption;
                dest.coap_reset_session_hint = false;
                break;
#endif    
            default:
                TERMINATE_BAD_CASE(mtp->protocol);
                break;
        }
    }

    // Send the response
    switch(dest.protocol)
    {
        case kMtpProtocol_STOMP:
            agent_queue = DEVICE_MTP_GetAgentStompQueue(dest.stomp_instance);
            err = DEVICE_STOMP_QueueBinaryMessage(usp_msg_type, dest.stomp_instance, dest.stomp_dest, agent_queue, pbuf, pbuf_len);
            break;

#ifdef ENABLE_COAP
        case kMtpProtocol_CoAP:
            err = COAP_QueueBinaryMessage(usp_msg_type, cont->instance, mtp->instance, pbuf, pbuf_len, &dest);
            break;
#endif
        default:
            TERMINATE_BAD_CASE(mrt->protocol);
            break;
    }

    return err;
}

/*********************************************************************//**
**
** DEVICE_CONTROLLER_NotifyStompConnDeleted
**
** Called when a STOMP connection is deleted
** This code unpicks all references to the STOMP connection existing in the Controller MTP table
**
** \param   stomp_instance - instance in Device.STOMP.Connection which has been deleted
**
** \return  None
**
**************************************************************************/
void DEVICE_CONTROLLER_NotifyStompConnDeleted(int stomp_instance)
{
    int i;
    int j;
    controller_t *cont;
    controller_mtp_t *mtp;
    char path[MAX_DM_PATH];

    // Iterate over all controllers
    for (i=0; i<MAX_CONTROLLERS; i++)
    {
        // Iterate over all MTP slots for this controller, clearing out all references to the deleted STOMP connection
        cont = &controllers[i];
        if (cont->instance != INVALID)
        {
            for (j=0; j<MAX_CONTROLLER_MTPS; j++)
            {
                mtp = &cont->mtps[j];
                if ((mtp->instance != INVALID) && (mtp->protocol == kMtpProtocol_STOMP) && (mtp->stomp_connection_instance == stomp_instance))
                {
                    USP_SNPRINTF(path, sizeof(path), "Device.LocalAgent.Controller.%d.MTP.%d.STOMP.Reference", cont->instance, mtp->instance);
                    DATA_MODEL_SetParameterValue(path, "", 0);
                }
            }
        }
    }
}

/*********************************************************************//**
**
** PeriodicNotificationExec
**
** Sends out periodic notifications (that have fired) for all controllers
** This function is called back from a timer when it is time for a periodic notification to fire
**
** \param   id - (unused) identifier of the sync timer which caused this callback
**
** \return  None
**
**************************************************************************/
void PeriodicNotificationExec(int id)
{
    int i;
    controller_t *cont;
    time_t cur_time;

    // Exit if it's not yet time for any periodic notifications to fire
    cur_time = time(NULL);
    USP_ASSERT(cur_time >= first_periodic_notification_time);

    // Iterate over all controllers
    for (i=0; i<MAX_CONTROLLERS; i++)
    {
        // Skip this entry if it is unused
        cont = &controllers[i];
        if (cont->instance == INVALID)
        {
            continue;
        }

        // Send this notification, if it's time to fire
        if (cur_time >= cont->next_time_to_fire)
        {
            // Send a notification event to the controller (if there are any periodic events subscribed to)
            DEVICE_SUBSCRIPTION_SendPeriodicEvent(cont->instance); // Intentionally ignoring any errors
    
            // Update the time at which this notification next fires
            cont->next_time_to_fire = CalcNextPeriodicTime(cur_time, cont->periodic_base, cont->periodic_interval);
        }
    }

    // Update the time at which the next periodic notification should fire
    UpdateFirstPeriodicNotificationTime();
}

/*********************************************************************//**
**
** ValidateAdd_Controller
**
** Function called to determine whether a controller may be added
**
** \param   req - pointer to structure identifying the request
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ValidateAdd_Controller(dm_req_t *req)
{
    controller_t *cont;

    // Exit if unable to find a free controller slot
    cont = FindUnusedController();
    if (cont == NULL)
    {
        return USP_ERR_RESOURCES_EXCEEDED;        
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ValidateAdd_ControllerMtp
**
** Function called to determine whether an MTP may be added to a controller
**
** \param   req - pointer to structure identifying the controller MTP
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ValidateAdd_ControllerMtp(dm_req_t *req)
{
    controller_t *cont;
    controller_mtp_t *mtp;

    cont = FindControllerByInstance(inst1);
    USP_ASSERT(cont != NULL);

    // Exit if unable to find a free MTP slot
    mtp = FindUnusedControllerMtp(cont);
    if (mtp == NULL)
    {
        return USP_ERR_RESOURCES_EXCEEDED;        
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_ControllerAdded
**
** Function called when a controller has been added to Device.LocalAgent.Controller.{i}
**
** \param   req - pointer to structure identifying the controller
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerAdded(dm_req_t *req)
{
    int err;

    err = ProcessControllerAdded(inst1);

    return err;
}

/*********************************************************************//**
**
** Notify_ControllerDeleted
**
** Function called when a controller has been deleted from Device.LocalAgent.Controller.{i}
**
** \param   req - pointer to structure identifying the controller
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerDeleted(dm_req_t *req)
{
    controller_t *cont;

    // Exit if we cannot find the controller
    // NOTE: We might not find it if it was never added. This could occur if deleting from the DB at startup when we detected that the database params were invalid
    cont = FindControllerByInstance(inst1);
    if (cont == NULL)
    {
        return USP_ERR_OK;
    }

    // Delete the controller from the array
    DestroyController(cont);

    // 2DO RH: All Recipients in the Subscription table referencing this controller should also be cleared

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_ControllerMtpAdded
**
** Function called when an MTP has been added to Device.LocalAgent.Controller.{i}.MTP.{i}
**
** \param   req - pointer to structure identifying the controller
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerMtpAdded(dm_req_t *req)
{
    int err;
    controller_t *cont;

    // Exit if the specified controller is not in the controller array - this could occur on startup if the controller entry in the DB was incorrect
    cont = FindControllerByInstance(inst1);
    if (cont == NULL)
    {
        USP_ERR_SetMessage("%s: Controller instance %d does not exist in internal data structure", __FUNCTION__, inst1);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if an error occurred in processing the MTP
    err = ProcessControllerMtpAdded(cont, inst2);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_ControllerMtpDeleted
**
** Function called when an MTP has been deleted from Device.LocalAgent.Controller.{i}.MTP.{i}
**
** \param   req - pointer to structure identifying the controller
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerMtpDeleted(dm_req_t *req)
{
    controller_t *cont;
    controller_mtp_t *mtp;

    // Exit if we cannot find the controller MTP
    // NOTE: We might not find it, if it was never added. This could occur if deleting from the DB
    // at startup, if we detected that the database params were invalid
    mtp = FindControllerMtpFromReq(req, &cont);
    if (mtp == NULL)
    {
        return USP_ERR_OK;
    }

#ifdef ENABLE_COAP
    // Stop this controller, if it is CoAP
    // (We don't need to do anything if this MTP is STOMP, because all we are deleting is an
    //  address to send to, the STOMP connection itself is separate)
    if ((mtp->protocol == kMtpProtocol_CoAP) && (mtp->enable) && (cont->enable))
    {
        COAP_StopClient(cont->instance, mtp->instance);
    }
#endif

    // Delete the controller MTP from the array
    DestroyControllerMtp(mtp);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Validate_ControllerEndpointID
**
** Validates that the EndpointID is unique across all registered controllers
**
** \param   req - pointer to structure identifying the parameter
** \param   value - value that the controller would like to set the parameter to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Validate_ControllerEndpointID(dm_req_t *req, char *value)
{
    int err;

    // Exit if endpoint_id is not unique
    err = ValidateEndpointIdUniqueness(value, inst1);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Validate_ControllerMtpEnable
**
** Validates Device.LocalAgent.Controller.{i}.MTP.{i}.Enable
** by checking that it is a boolean
** and also checking that setting it to true would not enable more than one STOMP MTP
**
** \param   req - pointer to structure identifying the parameter
** \param   value - value that the controller would like to set the parameter to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Validate_ControllerMtpEnable(dm_req_t *req, char *value)
{
    int err;
    mtp_protocol_t protocol;
    char path[MAX_DM_PATH];

    // Exit if we are disabling this controller MTP. In this case we do not have to check for only one enabled STOMP MTP
    if (val_bool == false)
    {
        return USP_ERR_OK;
    }

    // Exit if this controller MTP is not using STOMP
    // NOTE: We look the value up in the database because this function may be called before the controller MTP has actually been added
    USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP.%d.Protocol", device_cont_root, inst1, inst2);
    err = DM_ACCESS_GetEnum(path, &protocol, mtp_protocols, NUM_ELEM(mtp_protocols));
    if ((err != USP_ERR_OK) || (protocol != kMtpProtocol_STOMP))
    {
        // NOTE: Ignoring any error because the setting of enable may be done before protocol, when performing an AddInstance
        return USP_ERR_OK;
    }

    // Check that only one STOMP MTP is enabled at any one time
    err = ValidateStompMtpUniquenessReq(req);
    return err;
}

/*********************************************************************//**
**
** Validate_ControllerMtpProtocol
**
** Validates Device.LocalAgent.Controller.{i}.MTP.{i}.Protocol
** by checking that it matches the protocols we support
** and also checking that there is not another enabled MTP for this controller with the same protocol assigned
**
** \param   req - pointer to structure identifying the parameter
** \param   value - value that the controller would like to set the parameter to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Validate_ControllerMtpProtocol(dm_req_t *req, char *value)
{
    int err;
    mtp_protocol_t protocol;
    bool enable;
    char path[MAX_DM_PATH];

    // Exit if the protocol was invalid
    protocol = TEXT_UTILS_StringToEnum(value, mtp_protocols, NUM_ELEM(mtp_protocols));
    if (protocol == INVALID)
    {
        USP_ERR_SetMessage("%s: Invalid or unsupported protocol %s", __FUNCTION__, value);
        return USP_ERR_INVALID_VALUE;
    }

    // Exit if the new protocol is not STOMP. In this case we do not have to check for only one enabled STOMP MTP
    if (protocol != kMtpProtocol_STOMP)
    {
        return USP_ERR_OK;
    }

    // Exit if this controller MTP is not enabled
    // NOTE: We look the value up in the database because this function may be called before the controller MTP has actually been added
    USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP.%d.Enable", device_cont_root, inst1, inst2);
    err = DM_ACCESS_GetBool(path, &enable);
    if ((err != USP_ERR_OK) || (enable == false))
    {
        // NOTE: Ignoring any error because the setting of protocol may be done before enable, when performing an AddInstance
        return USP_ERR_OK;
    }

    // Check that only one STOMP MTP is enabled at any one time
    err = ValidateStompMtpUniquenessReq(req);
    return err;
}

/*********************************************************************//**
**
** Validate_ControllerRetryMinimumWaitInterval
**
** Validates Device.LocalAgent.Controller.{i}.USPRetryMinimumWaitInterval
**
** \param   req - pointer to structure identifying the parameter
** \param   value - value that the controller would like to set the parameter to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Validate_ControllerRetryMinimumWaitInterval(dm_req_t *req, char *value)
{
    return DM_ACCESS_ValidateRange_Unsigned(req, 1, 65535);
}

/*********************************************************************//**
**
** Validate_ControllerRetryIntervalMultiplier
**
** Validates Device.LocalAgent.Controller.{i}.USPRetryIntervalMultiplier
**
** \param   req - pointer to structure identifying the parameter
** \param   value - value that the controller would like to set the parameter to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Validate_ControllerRetryIntervalMultiplier(dm_req_t *req, char *value)
{
    return DM_ACCESS_ValidateRange_Unsigned(req, 1000, 65535);
}

/*********************************************************************//**
**
** Validate_ControllerAssignedRole
**
** Validates Device.LocalAgent.Controller.{i}.AssignedRole
**
** \param   req - pointer to structure identifying the parameter
** \param   value - value that the controller would like to set the parameter to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Validate_ControllerAssignedRole(dm_req_t *req, char *value)
{
    int err;
    int instance;

    // Empty String is an allowed value for Assigned Role
    if (*value == '\0')
    {
        return USP_ERR_OK;
    }
    
    err = DM_ACCESS_ValidateReference(value, "Device.LocalAgent.ControllerTrust.Role.{i}", &instance);

    return err;
}

/*********************************************************************//**
**
** Notify_ControllerEnable
**
** Function called when Device.LocalAgent.Controller.{i}.Enable is modified
** This function updates the value of the enable stored in the controllers array
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerEnable(dm_req_t *req, char *value)
{
    controller_t *cont;

    // Determine controller to be updated
    cont = FindControllerByInstance(inst1);
    USP_ASSERT(cont != NULL);

    // Exit if the value has not changed
    if (val_bool == cont->enable)
    {
        return USP_ERR_OK;
    }

    // Save the new value
    cont->enable = val_bool;

#ifdef ENABLE_COAP
    // Iterate over all MTPs for this controller, starting or stopping its associated CoAP MTPs
    int i;
    for (i=0; i<MAX_CONTROLLER_MTPS; i++)
    {
        int err;
        controller_mtp_t *mtp;

        mtp = &cont->mtps[i];
        if ((mtp->instance != INVALID) && (mtp->protocol == kMtpProtocol_CoAP))
        {
            if ((mtp->enable) && (cont->enable))
            {
                // Exit if unable to start client
                err = COAP_StartClient(cont->instance, mtp->instance, cont->endpoint_id);
                if (err != USP_ERR_OK)
                {
                    return err;
                }
            }
            else
            {
                COAP_StopClient(cont->instance, mtp->instance);
            }
        }
    }
#endif

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_ControllerEndpointID
**
** Function called when Device.LocalAgent.Controller.{i}.EndpointID is modified
** This function updates the value of the endpoint_id stored in the controller array
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerEndpointID(dm_req_t *req, char *value)
{
    controller_t *cont;

    // Determine controller to be updated
    cont = FindControllerByInstance(inst1);
    USP_ASSERT(cont != NULL);

    // Set the new value
    USP_SAFE_FREE(cont->endpoint_id);
    cont->endpoint_id = USP_STRDUP(value);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_ControllerAssignedRole
**
** Function called when Device.LocalAgent.Controller.{i}.AssignedRole is modified
** This function updates the value of the assigned_role stored in the controller array
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerAssignedRole(dm_req_t *req, char *value)
{
    int err;
    controller_t *cont;
    
    // Determine controller to be updated
    cont = FindControllerByInstance(inst1);
    USP_ASSERT(cont != NULL);

    err = UpdateAssignedRole(cont, value);

    return err;
}

/*********************************************************************//**
**
** Notify_ControllerMtpEnable
**
** Function called when Device.LocalAgent.Controller.{i}.MTP.{i}.Enable is modified
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerMtpEnable(dm_req_t *req, char *value)
{
    controller_t *cont = NULL;
    controller_mtp_t *mtp;

    // Determine MTP to be updated
    mtp = FindControllerMtpFromReq(req, &cont);
    USP_ASSERT(mtp != NULL);

    // Exit if the value has not changed
    if (val_bool == mtp->enable)
    {
        return USP_ERR_OK;
    }

    // Save the new value
    mtp->enable = val_bool;

#ifdef ENABLE_COAP
    // Start or stop CoAP client based on new value
    int err;
    if (mtp->protocol == kMtpProtocol_CoAP)
    {
        if ((mtp->enable) && (cont->enable))
        {
            // Exit if unable to start client
            err = COAP_StartClient(cont->instance, mtp->instance, cont->endpoint_id);
            if (err != USP_ERR_OK)
            {
                return err;
            }
        }
        else
        {
            COAP_StopClient(cont->instance, mtp->instance);
        }
    }
#endif
    // NOTE: We do not have to do anything for STOMP, as these parameters are only searched when we send

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_ControllerMtpProtocol
**
** Function called when Device.LocalAgent.Controller.{i}.MTP.{i}.Protocol is modified
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerMtpProtocol(dm_req_t *req, char *value)
{
    controller_t *cont;
    controller_mtp_t *mtp;
    mtp_protocol_t new_protocol;

    // Determine MTP to be updated
    mtp = FindControllerMtpFromReq(req, &cont);
    USP_ASSERT(mtp != NULL);

#ifdef ENABLE_COAP
    mtp_protocol_t old_protocol;
    old_protocol = mtp->protocol;
#endif

    // Extract the new value
    new_protocol = TEXT_UTILS_StringToEnum(value, mtp_protocols, NUM_ELEM(mtp_protocols));
    USP_ASSERT(new_protocol != INVALID); // Value must already have validated to have got here

    // Exit if protocol has not changed
    if (new_protocol == mtp->protocol)
    {
        return USP_ERR_OK;
    }

    // Store new protocol
    mtp->protocol = new_protocol;

    // Exit if the MTP is not enabled - nothing more to do
    if ((mtp->enable == false) || (cont->enable == false))
    {
        return USP_ERR_OK;
    }

#ifdef ENABLE_COAP
    int err;

    // Stop the old CoAP server, if we've moved from CoAP
    if (old_protocol == kMtpProtocol_CoAP)
    {
        COAP_StopClient(cont->instance, mtp->instance);
    }

    // Start the new CoAP server, if we've moved to CoAP, exiting if an error occurred
    if (new_protocol == kMtpProtocol_CoAP)
    {
        err = COAP_StartClient(cont->instance, mtp->instance, cont->endpoint_id);
        if (err != USP_ERR_OK)
        {
            return err;
        }
    }
#endif

    // NOTE: We don't need to do anything explicitly for STOMP
    
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_ControllerMtpStompReference
**
** Function called when Device.LocalAgent.Controller.{i}.MTP.{i}.STOMP.Reference is modified
** This function updates the value of the stomp_connection_instance stored in the controller array
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerMtpStompReference(dm_req_t *req, char *value)
{
    controller_t *cont;
    controller_mtp_t *mtp;
    char path[MAX_DM_PATH];
    int err;

    // Determine MTP to be updated
    mtp = FindControllerMtpFromReq(req, &cont);
    USP_ASSERT(mtp != NULL);

    // Set the new value
    USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP.%d.STOMP.Reference", device_cont_root, cont->instance, mtp->instance);

    err = DEVICE_MTP_GetStompReference(path, &mtp->stomp_connection_instance);

    return err;
}

/*********************************************************************//**
**
** Notify_ControllerMtpStompDestination
**
** Function called when Device.LocalAgent.Controller.{i}.MTP.{i}.STOMP.Destination is modified
** This function updates the value of the stomp_controller_queue stored in the controller array
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerMtpStompDestination(dm_req_t *req, char *value)
{
    controller_t *cont;
    controller_mtp_t *mtp;

    // Determine MTP to be updated
    mtp = FindControllerMtpFromReq(req, &cont);
    USP_ASSERT(mtp != NULL);

    // Set the new value
    USP_SAFE_FREE(mtp->stomp_controller_queue);
    mtp->stomp_controller_queue = USP_STRDUP(value);

    return USP_ERR_OK;
}

#ifdef ENABLE_COAP
/*********************************************************************//**
**
** Notify_ControllerMtpCoapHost
**
** Function called when Device.LocalAgent.Controller.{i}.MTP.{i}.CoAP.Host is modified
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerMtpCoapHost(dm_req_t *req, char *value)
{
    controller_t *cont;
    controller_mtp_t *mtp;

    // Determine MTP to be updated
    mtp = FindControllerMtpFromReq(req, &cont);
    USP_ASSERT(mtp != NULL);

    // Set the new value
    USP_SAFE_FREE(mtp->coap_controller_host);
    mtp->coap_controller_host = USP_STRDUP(value);

    // NOTE: We do not need to explicitly propagate this value to the COAP module here, 
    // as each USP message that is queued includes this information
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_ControllerMtpCoapPort
**
** Function called when Device.LocalAgent.Controller.{i}.MTP.{i}.CoAP.Port is modified
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerMtpCoapPort(dm_req_t *req, char *value)
{
    controller_t *cont;
    controller_mtp_t *mtp;

    // Determine MTP to be updated
    mtp = FindControllerMtpFromReq(req, &cont);
    USP_ASSERT(mtp != NULL);

    // Set the new value
    mtp->coap.port = val_uint;

    // NOTE: We do not need to explicitly propagate this value to the COAP module here, 
    // as each USP message that is queued includes this information

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_ControllerMtpCoapPath
**
** Function called when Device.LocalAgent.Controller.{i}.MTP.{i}.CoAP.Path is modified
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerMtpCoapPath(dm_req_t *req, char *value)
{
    controller_t *cont;
    controller_mtp_t *mtp;

    // Determine MTP to be updated
    mtp = FindControllerMtpFromReq(req, &cont);
    USP_ASSERT(mtp != NULL);

    // Set the new value
    USP_SAFE_FREE(mtp->coap.resource);
    mtp->coap.resource = USP_STRDUP(value);

    // NOTE: We do not need to explicitly propagate this value to the COAP module here, 
    // as each USP message that is queued includes this information

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_ControllerMtpCoapEncryption
**
** Function called when Device.LocalAgent.Controller.{i}.MTP.{i}.CoAP.EnableEncryption is modified
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerMtpCoapEncryption(dm_req_t *req, char *value)
{
    controller_t *cont;
    controller_mtp_t *mtp;

    // Determine MTP to be updated
    mtp = FindControllerMtpFromReq(req, &cont);
    USP_ASSERT(mtp != NULL);

    // Set the new value
    USP_SAFE_FREE(mtp->coap.resource);
    mtp->coap.enable_encryption = val_bool;

    // NOTE: We do not need to explicitly propagate this value to the COAP module here, 
    // as each USP message that is queued includes this information

    return USP_ERR_OK;
}
#endif

/*********************************************************************//**
**
** Notify_PeriodicNotifInterval
**
** Function called when Device.LocalAgent.Controller.{i}.PeriodicNotifInterval
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_PeriodicNotifInterval(dm_req_t *req, char *value)
{
    controller_t *cont;
    time_t cur_time;

    // Determine controller to be updated
    cont = FindControllerByInstance(inst1);
    USP_ASSERT(cont != NULL);

    // Set the new value
    cont->periodic_interval = val_uint;

    // Calculate the new next time that this notification should fire
    cur_time = time(NULL);
    cont->next_time_to_fire = CalcNextPeriodicTime(cur_time, cont->periodic_base, cont->periodic_interval);

    // Update the time at which the first periodic notification fires
    UpdateFirstPeriodicNotificationTime();

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_PeriodicNotifTime
**
** Function called when Device.LocalAgent.Controller.{i}.PeriodicNotifTime is modified
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_PeriodicNotifTime(dm_req_t *req, char *value)
{
    controller_t *cont;
    time_t cur_time;

    // Determine controller to be updated
    cont = FindControllerByInstance(inst1);
    USP_ASSERT(cont != NULL);

    // Set the new value
    cont->periodic_base = RETRY_WAIT_UseRandomBaseIfUnknownTime(val_datetime);

    // Calculate the new next time that this notification should fire
    cur_time = time(NULL);
    cont->next_time_to_fire = CalcNextPeriodicTime(cur_time, cont->periodic_base, cont->periodic_interval);

    // Update the time at which the first periodic notification fires
    UpdateFirstPeriodicNotificationTime();

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_ControllerRetryMinimumWaitInterval
**
** Called when Device.LocalAgent.Controller.{i}.USPRetryMinimumWaitInterval is modified
**
** \param   req - pointer to structure identifying the parameter
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerRetryMinimumWaitInterval(dm_req_t *req, char *value)
{
    controller_t *cont;

    // Determine controller to be updated
    cont = FindControllerByInstance(inst1);
    USP_ASSERT(cont != NULL);

    // Update cached value
    cont->subs_retry_min_wait_interval = val_uint;
    
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Notify_ControllerRetryIntervalMultiplier
**
** Called when Device.LocalAgent.Controller.{i}.USPRetryIntervalMultiplier is modified
**
** \param   req - pointer to structure identifying the parameter
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Notify_ControllerRetryIntervalMultiplier(dm_req_t *req, char *value)
{
    controller_t *cont;

    // Determine controller to be updated
    cont = FindControllerByInstance(inst1);
    USP_ASSERT(cont != NULL);

    // Update cached value
    cont->subs_retry_interval_multiplier = val_uint;
    
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Get_ControllerInheritedRole
**
** Gets the value of Device.LocalAgent.Controller.{i}.InheritedRole
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer in which to return the value
** \param   len - length of return buffer
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_ControllerInheritedRole(dm_req_t *req, char *buf, int len)
{
    int err;
    combined_role_t combined_role;
    int instance;

    // Set default inherited role
    *buf = '\0';

    // Exit if this controller is not enabled, or does not have a role setup yet
    err = DEVICE_CONTROLLER_GetCombinedRole(inst1, &combined_role);
    if (err != USP_ERR_OK)
    {
        return USP_ERR_OK;
    }

    // Exit if the controller's role is INVALID_ROLE
    instance = DEVICE_CTRUST_GetInstanceFromRole(combined_role.inherited);
    if (instance == INVALID)
    {
        return USP_ERR_OK;
    }

    // If the code gets here, then we have determined which instance of the Role table is associated with the controller's role
    USP_SNPRINTF(buf, len, "Device.LocalAgent.ControllerTrust.Role.%d", instance);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ProcessControllerAdded
**
** Reads the parameters for the specified controller from the database and processes them
**
** \param   cont_instance - instance number of the controller in the controller table
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ProcessControllerAdded(int cont_instance)
{
    controller_t *cont;
    int err;
    int i;
    int_vector_t iv;
    int mtp_instance;
    time_t cur_time;
    time_t base;
    char path[MAX_DM_PATH];
    char reference[MAX_DM_PATH];

    // Exit if unable to add another controller
    cont = FindUnusedController();
    if (cont == NULL)
    {
        return USP_ERR_RESOURCES_EXCEEDED;        
    }

    // Initialise to defaults
    INT_VECTOR_Init(&iv);
    memset(cont, 0, sizeof(controller_t));
    cont->instance = cont_instance;
    cont->combined_role.inherited = ROLE_DEFAULT;
    cont->combined_role.assigned = ROLE_DEFAULT;
    
    for (i=0; i<MAX_CONTROLLER_MTPS; i++)
    {
        cont->mtps[i].instance = INVALID;
    }

    // Exit if unable to determine whether this controller was enabled or not
    USP_SNPRINTF(path, sizeof(path), "%s.%d.Enable", device_cont_root, cont_instance);
    err = DM_ACCESS_GetBool(path, &cont->enable);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if unable to get the periodic base time for this controller
    USP_SNPRINTF(path, sizeof(path), "%s.%d.PeriodicNotifTime", device_cont_root, cont_instance);
    err = DM_ACCESS_GetDateTime(path, &base);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }
    cont->periodic_base = RETRY_WAIT_UseRandomBaseIfUnknownTime(base);


    // Exit if unable to get the periodic interval for this controller
    USP_SNPRINTF(path, sizeof(path), "%s.%d.PeriodicNotifInterval", device_cont_root, cont_instance);
    err = DM_ACCESS_GetUnsigned(path, &cont->periodic_interval);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Calculate the time at which this notification next fires
    cur_time = time(NULL);
    cont->next_time_to_fire = CalcNextPeriodicTime(cur_time, cont->periodic_base, cont->periodic_interval);

    // Update the time at which the next periodic notification should fire
    UpdateFirstPeriodicNotificationTime();

    // Exit if unable to get the minimum subs retry interval for this controller
    USP_SNPRINTF(path, sizeof(path), "%s.%d.USPRetryMinimumWaitInterval", device_cont_root, cont_instance);
    err = DM_ACCESS_GetUnsigned(path, &cont->subs_retry_min_wait_interval);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if unable to get the subs retry interval multiplier for this controller
    USP_SNPRINTF(path, sizeof(path), "%s.%d.USPRetryIntervalMultiplier", device_cont_root, cont_instance);
    err = DM_ACCESS_GetUnsigned(path, &cont->subs_retry_interval_multiplier);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if unable to get the endpoint ID of this controller
    USP_SNPRINTF(path, sizeof(path), "%s.%d.EndpointID", device_cont_root, cont_instance);
    err = DM_ACCESS_GetString(path, &cont->endpoint_id);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if the endpoint ID of this controller is not unique
    err = ValidateEndpointIdUniqueness(cont->endpoint_id, cont_instance);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if unable to get the assigned role of this controller
    USP_SNPRINTF(path, sizeof(path), "%s.%d.AssignedRole", device_cont_root, cont_instance);
    err = DATA_MODEL_GetParameterValue(path, reference, sizeof(reference), 0);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if the value was incorrectly set
    err = UpdateAssignedRole(cont, reference);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if unable to get the object instance numbers present in this controller's MTP table
    USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP", device_cont_root, cont_instance);
    err = DATA_MODEL_GetInstances(path, &iv);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit, issuing a warning, if no MTPs for this controller are present in database
    if (iv.num_entries == 0)
    {
        USP_LOG_Warning("%s: WARNING: No MTP instances for %s.%d", __FUNCTION__, device_cont_root, cont_instance);
        err = USP_ERR_OK;
        goto exit;
    }

    // Iterate over all MTPs, getting their parameters into the controller structure
    // Or deleting them from the database, if they contain invalid parameters
    // NOTE: We need to delete them to prevent them being modified to good values, which then this code does not pickup (because they are not in our internal array)
    for (i=0; i < iv.num_entries; i++)
    {
        mtp_instance = iv.vector[i];

        err = ProcessControllerMtpAdded(cont, mtp_instance);
        if (err != USP_ERR_OK)
        {
            // Exit if unable to delete a controller MTP with bad parameters from the DB
            USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP.%d", device_cont_root, cont_instance, mtp_instance);
            USP_LOG_Warning("%s: Deleting %s as it contained invalid parameters.", __FUNCTION__, path);
            err = DATA_MODEL_DeleteInstance(path, 0);
            if (err != USP_ERR_OK)
            {
                goto exit;
            }
        }
    }

    // If the code gets here, then we successfully retrieved all data about the controller (even if some of the MTPs were not added)
    err = USP_ERR_OK;

exit:
    if (err != USP_ERR_OK)
    {
        DestroyController(cont);
    }

    INT_VECTOR_Destroy(&iv);
    return err;
}

/*********************************************************************//**
**
** ProcessControllerMtpAdded
**
** Reads the parameters for the specified MTP from the database and processes them
**
** \param   cont - pointer to controller in the controller array, which this MTP is associated with
** \param   mtp_instance - instance number of the MTP for the specified controller
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ProcessControllerMtpAdded(controller_t *cont, int mtp_instance)
{
    int err;
    controller_mtp_t *mtp;
    char path[MAX_DM_PATH];

    // Exit if unable to find a free MTP slot
    mtp = FindUnusedControllerMtp(cont);
    if (mtp == NULL)
    {
        return USP_ERR_RESOURCES_EXCEEDED;        
    }

    // Initialise to defaults
    memset(mtp, 0, sizeof(controller_mtp_t));
    mtp->instance = mtp_instance;

    // Exit if unable to get the protocol for this MTP
    USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP.%d.Protocol", device_cont_root, cont->instance, mtp_instance);
    err = DM_ACCESS_GetEnum(path, &mtp->protocol, mtp_protocols, NUM_ELEM(mtp_protocols));
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if this MTP is not the only STOMP MTP for this controller
    if (mtp->protocol == kMtpProtocol_STOMP)
    {
        err = ValidateStompMtpUniqueness(cont, mtp_instance);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }
    }

    // Exit if unable to get the enable for this MTP
    USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP.%d.Enable", device_cont_root, cont->instance, mtp_instance);
    err = DM_ACCESS_GetBool(path, &mtp->enable);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if there was an error in the reference to the entry in the STOMP connection table
    USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP.%d.STOMP.Reference", device_cont_root, cont->instance, mtp_instance);
    err = DEVICE_MTP_GetStompReference(path, &mtp->stomp_connection_instance);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if unable to get the name of the controller's STOMP queue
    USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP.%d.STOMP.Destination", device_cont_root, cont->instance, mtp_instance);
    USP_ASSERT(mtp->stomp_controller_queue == NULL);
    err = DM_ACCESS_GetString(path, &mtp->stomp_controller_queue);
    if (err != USP_ERR_OK)
    {
        return err;
    }

#ifdef ENABLE_COAP
    // Exit if unable to get the name of the controller's CoAP host name
    USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP.%d.CoAP.Host", device_cont_root, cont->instance, mtp_instance);
    err = DM_ACCESS_GetString(path, &mtp->coap_controller_host);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to get the name of the controller's CoAP resource name
    USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP.%d.CoAP.Path", device_cont_root, cont->instance, mtp_instance);
    err = DM_ACCESS_GetString(path, &mtp->coap.resource);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to get the name of the controller's CoAP port
    USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP.%d.CoAP.Port", device_cont_root, cont->instance, mtp_instance);
    err = DM_ACCESS_GetUnsigned(path, &mtp->coap.port);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to determine whether to send to this controller using encryption
    USP_SNPRINTF(path, sizeof(path), "%s.%d.MTP.%d.CoAP.EnableEncryption", device_cont_root, cont->instance, mtp_instance);
    err = DM_ACCESS_GetBool(path, &mtp->coap.enable_encryption);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Start a CoAP client to this controller (if required)
    if ((mtp->protocol == kMtpProtocol_CoAP) && (mtp->enable) && (cont->enable))
    {
        err = COAP_StartClient(cont->instance, mtp_instance, cont->endpoint_id);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }
    }
#endif

    err = USP_ERR_OK;

exit:
    if (err != USP_ERR_OK)
    {
        DestroyControllerMtp(mtp);
    }

    return err;
}

/*********************************************************************//**
**
** UpdateAssignedRole
**
** Given a reference value, sets the assigned_role stored in the controller array
**
** \param   req - pointer to structure identifying the path
** \param   value - new value of this parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int UpdateAssignedRole(controller_t *cont, char *reference)
{
    int err;
    int instance;
    ctrust_role_t role;

    // Exit if reference is a blank string
    if (*reference == '\0')
    {
        cont->combined_role.assigned = INVALID_ROLE;
        return USP_ERR_OK;
    }
    
    // Exif if the controller trust role instance number does not exist
    err = DM_ACCESS_ValidateReference(reference, "Device.LocalAgent.ControllerTrust.Role.{i}", &instance);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to convert the instance number to its associated role
    role = DEVICE_CTRUST_GetRoleFromInstance(instance);
    if (role == INVALID_ROLE)
    {
        return USP_ERR_INVALID_VALUE;
    }

    cont->combined_role.assigned = role;
    
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** FindUnusedController
**
** Finds the first free controller slot
**
** \param   None
**
** \return  Pointer to first free controller, or NULL if no controller found
**
**************************************************************************/
controller_t *FindUnusedController(void)
{
    int i;
    controller_t *cont;

    // Iterate over all controllers
    for (i=0; i<MAX_CONTROLLERS; i++)
    {
        // Exit if found an unused controller
        cont = &controllers[i];
        if (cont->instance == INVALID)
        {
            return cont;
        }
    }

    // If the code gets here, then no free controller slot has been found
    USP_ERR_SetMessage("%s: Only %d controllers are supported.", __FUNCTION__, MAX_CONTROLLERS);
    return NULL;
}

/*********************************************************************//**
**
** FindUnusedControllerMtp
**
** Finds the first free MTP instance for the specified controller
**
** \param   cont - pointer to controller
**
** \return  Pointer to first free MTP instance, or NULL if no MTP instance found
**
**************************************************************************/
controller_mtp_t *FindUnusedControllerMtp(controller_t *cont)
{
    int i;
    controller_mtp_t *mtp;

    // Iterate over all MTP slots for this controller
    for (i=0; i<MAX_CONTROLLER_MTPS; i++)
    {
        // Exit if found an unused controller MTP
        mtp = &cont->mtps[i];
        if (mtp->instance == INVALID)
        {
            return mtp;
        }
    }

    // If the code gets here, then no free MTP slot has been found for this controller
    USP_ERR_SetMessage("%s: Only %d MTPs are supported per controller.", __FUNCTION__, MAX_CONTROLLER_MTPS);
    return NULL;
}

/*********************************************************************//**
**
** FindControllerMtpFromReq
**
** Gets a pointer to a controller MTP entry in the controllers array
** based on the specified instance numbers
**
** \param   req - pointer to structure identifying the path
** \param   cont - pointer to variable in which to return a pointer to the controller
**
** \return  pointer to MTP entry
**
**************************************************************************/
controller_mtp_t *FindControllerMtpFromReq(dm_req_t *req, controller_t **p_cont)
{
    controller_t *cont;
    controller_mtp_t *mtp;

    // Determine Controller
    // NOTE: We might not find it if it was never added. This could occur if deleting from the DB at startup when we detected that the database params were invalid
    cont = FindControllerByInstance(inst1);
    if (cont == NULL)
    {
        return NULL;
    }

    // Determine Controller MTP
    // NOTE: We might not find it if it was never added. This could occur if deleting from the DB at startup when we detected that the database params were invalid
    mtp = FindControllerMtpByInstance(cont, inst2);
    if (mtp == NULL)
    {
        return NULL;
    }

    // Return the controller and controller MTP referred to by the instance numbers
    *p_cont = cont;
    return mtp;
}

/*********************************************************************//**
**
** FindControllerByInstance
**
** Finds a controller entry by it's data model instance number
**
** \param   cont_instance - instance number of the controller in the data model
**
** \return  pointer to controller entry within the controllers array, or NULL if controller was not found
**
**************************************************************************/
controller_t *FindControllerByInstance(int cont_instance)
{
    int i;
    controller_t *cont;

    // Iterate over all controllers
    for (i=0; i<MAX_CONTROLLERS; i++)
    {
        // Exit if found a controller that matches the instance number
        cont = &controllers[i];
        if (cont->instance == cont_instance)
        {
            return cont;
        }
    }

    // If the code gets here, then no matching controller was found
    return NULL;
}

/*********************************************************************//**
**
** FindControllerByEndpointId
**
** Finds the controller matching the specified endpoint_id
**
** \param   endpoint_id - name of the controller to find
**
** \return  pointer to controller entry within the controllers array, or NULL if controller was not found
**
**************************************************************************/
controller_t *FindControllerByEndpointId(char *endpoint_id)
{
    int i;
    controller_t *cont;

    // Iterate over all controllers
    for (i=0; i<MAX_CONTROLLERS; i++)
    {
        // Exit if found an enabled controller that matches the endpoint_id
        cont = &controllers[i];
        if ((cont->instance != INVALID) && 
            (strcmp(cont->endpoint_id, endpoint_id)==0))
        {
            return cont;
        }
    }

    // If the code gets here, then no matching controller was found
    return NULL;
}

/*********************************************************************//**
**
** FindEnabledControllerByEndpointId
**
** Finds the enabled controller matching the specified endpoint_id
**
** \param   endpoint_id - name of the controller to find
**
** \return  pointer to controller entry within the controllers array, or NULL if controller was not found
**
**************************************************************************/
controller_t *FindEnabledControllerByEndpointId(char *endpoint_id)
{
    int i;
    controller_t *cont;

    // Iterate over all controllers
    for (i=0; i<MAX_CONTROLLERS; i++)
    {
        // Exit if found an enabled controller that matches the endpoint_id
        cont = &controllers[i];
        if ((cont->instance != INVALID) && (cont->enable == true) && 
            (strcmp(cont->endpoint_id, endpoint_id)==0))
        {
            return cont;
        }
    }

    // If the code gets here, then no matching controller was found
    return NULL;
}

/*********************************************************************//**
**
** FindFirstEnabledMtp
**
** Finds the first enabled MTP for the specified controller, if possible matching the preferred MTP protocol
**
** \param   cont - pointer to controller in the controller array, which this MTP is associated with
** \param   preferred_protocol - preferred protocol to use (NOTE: this is unbknown for notification messages and will be set to kMtpProtocol_None)
**
** \return  pointer to controller MTP found, or NULL if none was found
**
**************************************************************************/
controller_mtp_t *FindFirstEnabledMtp(controller_t *cont, mtp_protocol_t preferred_protocol)
{
    int i;
    controller_mtp_t *mtp;
    controller_mtp_t *first_mtp = NULL;
    
    // Iterate over all enabled MTPs for this controller, finding the first enabled MTP for this controller
    for (i=0; i<MAX_CONTROLLER_MTPS; i++)
    {
        mtp = &cont->mtps[i];

        if ((mtp->instance != INVALID) && (mtp->enable == true))
        {
            // Exit if found a matching protocol
            if ((preferred_protocol == kMtpProtocol_None) || (preferred_protocol == mtp->protocol))
            {
                return mtp;
            }

            // Save the first MTP found, which we'll use if no matching protocol found
            if (first_mtp == NULL)
            {
                first_mtp = mtp;
            }
        }
    }

    return first_mtp;
}

/*********************************************************************//**
**
** FindControllerMtpByInstance
**
** Finds an MTP entry by it's data model instance number, for the specified controller
**
** \param   cont - pointer to controller that has this MTP
** \param   mtp_instance - instance number of the MTP in the data model
**
** \return  pointer to controller entry within the controllers array, or NULL if controller was not found
**
**************************************************************************/
controller_mtp_t *FindControllerMtpByInstance(controller_t *cont, int mtp_instance)
{
    int i;
    controller_mtp_t *mtp;

    // Iterate over all MTPs for this controller
    for (i=0; i<MAX_CONTROLLER_MTPS; i++)
    {
        // Exit if found an MTP that matches the instance number
        mtp = &cont->mtps[i];
        if (mtp->instance == mtp_instance)
        {
            return mtp;
        }
    }

    // If the code gets here, then no matching MTP was found
    return NULL;
}

/*********************************************************************//**
**
** DestroyController
**
** Frees all memory associated with the specified controller slot
**
** \param   cont - pointer to controller to free
**
** \return  None
**
**************************************************************************/
void DestroyController(controller_t *cont)
{
    int i;
    controller_mtp_t *mtp;
    
    cont->instance = INVALID;      // Mark controller slot as free
    cont->enable = false;
    USP_SAFE_FREE(cont->endpoint_id);

    for (i=0; i<MAX_CONTROLLER_MTPS; i++)
    {
        mtp = &cont->mtps[i];
        DestroyControllerMtp(mtp);
    }
}

/*********************************************************************//**
**
** DestroyControllerMtp
**
** Frees all memory associated with the specified controller mtp slot
**
** \param   cont - pointer to controller mtp to free
**
** \return  None
**
**************************************************************************/
void DestroyControllerMtp(controller_mtp_t *mtp)
{
    mtp->instance = INVALID;      // Mark controller slot as free
    mtp->protocol = kMtpProtocol_None;
    mtp->enable = false;
    mtp->stomp_connection_instance = INVALID;

    USP_SAFE_FREE(mtp->stomp_controller_queue);
#ifdef ENABLE_COAP
    USP_SAFE_FREE(mtp->coap_controller_host);
    USP_SAFE_FREE(mtp->coap.resource);
    mtp->coap.port = 0;
#endif
}

/*********************************************************************//**
**
** ValidateStompMtpUniquenessReq
**
** Validates that only one STOMP MTP is enabled at any one time
**
** \param   req - pointer to structure identifying the controller MTP
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ValidateStompMtpUniquenessReq(dm_req_t *req)
{
    int err;
    controller_t *cont;

    // Determine the controller entry
    cont = FindControllerByInstance(inst1);
    USP_ASSERT(cont != NULL);

    // Exit if this instance is not the only STOMP MTP for this controller
    err = ValidateStompMtpUniqueness(cont, inst2);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}


/*********************************************************************//**
**
** ValidateStompMtpUniqueness
**
** Validates that only one STOMP MTP is enabled at any one time
**
** \param   cont - controller on which to validate there is only one STOMP MTP
** \param   mtp_instance - Instance number which is expected to be the single STOMP MTP
**                          This instance is skipped when searching.
**                          It is necessary to allow you to set an MTP to use STOMP again.
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ValidateStompMtpUniqueness(controller_t *cont, int mtp_instance)
{
    int i;
    controller_mtp_t *mtp;

    // Iterate over all MTPs, seeing if any (other than the one currently being set) is enabled and a STOMP connection
    for (i=0; i < MAX_CONTROLLER_MTPS; i++)
    {
        mtp = &cont->mtps[i];

        // Skip this entry if not in use
        if (mtp->instance == INVALID)
        {
            continue;
        }

        // Skip the instance currently being validated - we allow the current STOMP MTP to have it's protocol set to STOMP again !
        if (mtp->instance == mtp_instance)
        {
            continue;
        }

        // Exit if another MTP is enabled, and uses STOMP
        if ((mtp->enable == true) && (mtp->protocol == kMtpProtocol_STOMP))
        {
            USP_ERR_SetMessage("%s: Controller can only have one enabled STOMP MTP (matches %s.%d.MTP.%d)", __FUNCTION__, device_cont_root, cont->instance, mtp->instance);
            return USP_ERR_VALUE_CONFLICT;
        }
    }

    // If the code gets here, then only the instance being validated is STOMP and enabled
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ValidateEndpointIdUniqueness
**
** Validates that the EndpointID is unique across all registered controllers
**
** \param   endpoint_id - endpoint_id to determine if it is unique
** \param   cont_instance - Instance number which is expected to match the endpoint_id
**                          This instance is skipped when searching.
**                          It is necessary to allow you to set an endpoint id to be the same value again.
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ValidateEndpointIdUniqueness(char *endpoint_id, int cont_instance)
{
    int i;
    controller_t *cont;

    // Interate over all controllers, checking that none match the new EndpointID
    for (i=0; i<MAX_CONTROLLERS; i++)
    {
        // Skip unused controller slots
        cont = &controllers[i];
        if (cont->instance == INVALID)
        {
            continue;
        }

        // Skip the instance which is having it's EndpointID altered
        if (cont->instance == cont_instance)
        {
            continue;
        }

        // Exit if the specified endpointID is already used by another controller
        if (strcmp(cont->endpoint_id, endpoint_id)==0)
        {
            USP_ERR_SetMessage("%s: EndpointID is not unique (matches %s.%d)", __FUNCTION__, device_cont_root, cont->instance);
            return USP_ERR_UNIQUE_KEY_CONFLICT;
        }
    }

    // If the code gets here, then the specified endpointID is unique among all controllers
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** CalcNextPeriodicTime
**
** Calculates the next absolute time at which a periodic notification event should be sent
**
** \param   cur_time - current time
** \param   periodic_base - time reference which intervals are relative to
** \param   periodic_interval - time interval between each periodic notification event
**
** \return  next absolute time to fire the periodic notification
**
**************************************************************************/
time_t CalcNextPeriodicTime(time_t cur_time, time_t periodic_base, int periodic_interval)
{
    time_t diff;
    time_t offset; 

    if (periodic_base <= cur_time)
    {
        // periodic_base is in the past
        offset = (cur_time - periodic_base) % periodic_interval; // This is the delta to the time of the last inform interval period
        diff = periodic_interval - offset;
    }
    else
    {
        // periodic_base is in the future
        diff = (periodic_base - cur_time) % periodic_interval;
    }

    // Correct for case of currently at a periodic inform interval time
    if (diff == 0)
    {
        diff = periodic_interval;
    }

    return cur_time + diff;
}

/*********************************************************************//**
**
** UpdateFirstPeriodicNotificationTime
**
** Updates the absolute time at which the next periodic notification event should be sent
**
** \param   None
**
** \return  None
**
**************************************************************************/
void UpdateFirstPeriodicNotificationTime(void)
{
    int i;
    controller_t *cont;
    time_t first = INT_MAX;

    // Iterate over all controllers
    for (i=0; i<MAX_CONTROLLERS; i++)
    {
        // Skip this entry if it is unused
        cont = &controllers[i];
        if (cont->instance == INVALID)
        {
            continue;
        }

        // Update time of the first periodic notification
        if (cont->next_time_to_fire < first)
        {
            first = cont->next_time_to_fire;
        }
    }

    // Update the timer. We do this every time because we always want the timer to be reactivated
    first_periodic_notification_time = first;
    SYNC_TIMER_Reload(PeriodicNotificationExec, 0, first_periodic_notification_time);
}

//------------------------------------------------------------------------------------------
// Code to test the CalcNextPeriodicTime() function
// NOTE: In test cases below, the periodic_interval is assumed to be 5 seconds
#if 0
time_t calc_next_periodic_time_test_cases[] =
{
    // cur_time // periodic_base    // next_time
    0,          0,                  10,
    0,          0,                  5,
    1,          0,                  5,
    4,          0,                  5,
    5,          0,                  10,
    
    4,          5,                  5,
    5,          5,                  10,
    
    6,          5,                  10,
    9,          5,                  10,
    10,         5,                  15,
    
    50,         100,                55,
    51,         100,                55,
    52,         100,                55,
    200,        100,                205,
    201,        100,                205,
    204,        100,                205,
    205,        100,                210,
};

void TestCalcNextPeriodicTime(void)
{
    int i;
    time_t *p;
    time_t result;

    p = calc_next_periodic_time_test_cases;
    for (i=0; i < NUM_ELEM(calc_next_periodic_time_test_cases); i+=3)
    {
        
        result = CalcNextPeriodicTime(p[0], p[1], 5);
        if (result != p[2])
        {
            printf("ERROR: [cur_time=%d, periodic_base=%d] Expected %d (got %d)\n", (int)p[0], (int)p[1], (int)p[2], (int)result);
        }
        p += 3;
    }
}
#endif




