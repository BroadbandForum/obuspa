/*
 *
 * Copyright (C) 2019-2021, Broadband Forum
 * Copyright (C) 2020-2021, BT PLC
 * Copyright (C) 2021  CommScope, Inc
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



#ifndef MQTT_H
#define MQTT_H

#include "usp-msg.pb-c.h"
#include "mtp_exec.h"
#include "socket_set.h"

#include <stdbool.h>

typedef struct
{
    unsigned connect_retrytime;
    unsigned interval_multiplier;
    unsigned max_interval;
} mqtt_retry_params_t;

typedef enum
{
    kMqttQos_Worst = 0,
    kMqttQos_MostOnce = 0,       // TCP Fire and forget, the worst QOS
    kMqttQos_AtLeastOnce = 1,    // Acknowledged Message, can be sent more than once
    kMqttQos_ExactlyOnce = 2,    // Fully ackd message, always received once
    kMqttQos_Best = 2,
    kMqttQos_Default = kMqttQos_Best,
} mqtt_qos_t;

typedef enum
{
    kMqttProtocol_3_1,           // Use v3.1 MQTT
    kMqttProtocol_3_1_1,         // Use v3.1.1 MQTT
    kMqttProtocol_5_0,           // Use v5.0 MQTT (recommended)
    kMqttProtocol_Default = kMqttProtocol_5_0,
    kMqttProtocol_Max,
} mqtt_protocolver_t;

typedef enum
{
    kMqttSubState_Unsubscribed = 0,
    kMqttSubState_Subscribing,
    kMqttSubState_Subscribed,
    kMqttSubState_Unsubscribing,
    kMqttSubState_Resubscribing,
    kMqttSubState_Error,
} mqtt_substate_t;

typedef enum
{
    kMqttTSprotocol_tcpip = 0,
    kMqttTSprotocol_tls,
    kMqttTSprotocol_Max,
} mqtt_tsprotocol_t;

typedef struct
{
    int instance;
    mqtt_qos_t qos;
    char* topic;
    bool enabled;
    int mid; // Last mid for subscribe message - to identify the SUBACK
    mqtt_substate_t state;
} mqtt_subscription_t;

typedef struct
{
    char* host;                   // Hostname of the broker
    unsigned int port;            // Port for broker
    int keepalive;                // Keepalive setting for broker connection
    char* username;               // Username to connect to broker
    char* password;               // Password to connect to broker
    int instance;                 // Client instance (Device.MQTT.Client.{i})
    bool enable;

    mqtt_protocolver_t version;      // MQTT protocol version to use

    char* topic; // Topic to publish to - controller should sub to this

    // Response topic, may be used - or not. Agent should sub to this.
    // Depends on the configuration in the broker (in v5.0)
    char* response_topic;
    mqtt_qos_t publish_qos;

    // V5 Params
    char* client_id;

    // mqtt parameters
    char* name;
    mqtt_tsprotocol_t ts_protocol;
    bool clean_session;
    bool clean_start;
    bool request_response_info;
    bool request_problem_info;
    char* response_information;

#if 0
    // These items are not currently used.
    // Most of these items are not really required for essential MQTT
    // operation. Some could be added easily though.
    // TODO: Add these
    unsigned int session_expiry;
    unsigned int receive_max;
    unsigned int max_packet_size;
    unsigned int topic_alias_max;
    bool will_enable;
    unsigned int will_qos;
    bool will_retain;
    unsigned int will_delay_interval;
    unsigned int will_message_expiry;
    char* will_content_type;
    char* will_response_topic;
    char* will_topic;
    char* will_value;
    unsigned int pubmsg_expinterval;
    unsigned int message_retrytime;
    char* auth_method;
#endif
    mqtt_retry_params_t retry;
} mqtt_conn_params_t;

/*********************************************************************//**
** MQTT_Init
**
** Initialise the MQTT component - basically a constructor
**
** \param None
**
** \return USP_ERR_OK on success, USP_ERR_XXX otherwise
**
**************************************************************************/
int MQTT_Init(void);

/*********************************************************************//**
** MQTT_Destroy
**
** Destroy the component - destructor for everything
**
** \param None
** \return None
**
**************************************************************************/
void MQTT_Destroy(void);


/*********************************************************************//**
** MQTT_Start
**
** Called before starting all MQTT connections
**
** \param None
** \return USP_ERR_OK on success, USP_ERR_XXX otherwise
**
**************************************************************************/
int MQTT_Start(void);

/*********************************************************************//**
** MQTT_Stop
**
** Called before starting all MQTT connections
**
** \param None
** \return USP_ERR_OK on success, USP_ERR_XXX otherwise
**
**************************************************************************/
void MQTT_Stop(void);



/*********************************************************************//**
** MQTT_EnableClient
**
** Enable the MQTT client connection to the broker with given params and topic
**
** \param mqtt_params - pointer to data model parameters specifying the mqtt params
** \param subscriptions[MAX_MQTT_SUBSCRIPTIONS] - subscriptions to use for this client
**
**
**************************************************************************/
int MQTT_EnableClient(mqtt_conn_params_t *mqtt_params, mqtt_subscription_t subscriptions[MAX_MQTT_SUBSCRIPTIONS]);


/*********************************************************************//**
**
** MQTT_DisableClient
**
** Disables the specified MQTT client
**
** \param   instance - Instance number in Device.MQTT.Client.{i}
** \param   is_reconnect - Set if this function is called as part of a reconnect sequence
**                         (in which case the send queue is not purged and the next_params are not freed)
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int MQTT_DisableClient(int instance, bool is_reconnect);


/*********************************************************************//**
** MQTT_QueueBinaryMessage
**
** Queue a binary message onto an MQTT connection
**
** \param msi - Information about the content to send. The ownership of
**              the payload buffer is passed to this function, unless an error is returned.
** \param instance - instance number for the client in Device.MQTT.Client.{i}
** \param topic - name of the agent's MQTT topic configured for this connection in the data model
**
** \return USP_ERR_OK on success, USP_ERR_XXX otherwise
**
**************************************************************************/
int MQTT_QueueBinaryMessage(mtp_send_item_t *msi, int instance, char *topic);


/*********************************************************************//**
** MQTT_ScheduleReconnect
**
** Signals that an MQTT reconnect occurs when all queued message have been sent
** See comment header above definition of scheduled_action_t for an explanation of this and why
**
** \param mqtt_params - pointer to data model parameters specifying the MQTT connection
**
** \return USP_ERR_OK on success, USP_ERR_XXX otherwise. If connection fails, it will be retried later
**
**************************************************************************/
void MQTT_ScheduleReconnect(mqtt_conn_params_t *mqtt_params);


/*********************************************************************//**
** MQTT_ActivateScheduledActions
**
** Called when all USP response messages have been queued
** This function activates all scheduled actions which have been signalled
** See comment header above definition of scheduled_action_t for an explanation of how scheduled actions work and why
**
**
** \param None
**
** \return None
**
**************************************************************************/
void MQTT_ActivateScheduledActions(void);


/*********************************************************************//**
** MQTT_GetMtpStatus
**
**
**
** \param instance - the Device.MQTT.Client.{i} number
**
** \return mtp_status_t -
**
**************************************************************************/
mtp_status_t MQTT_GetMtpStatus(int instance);


/*********************************************************************//**
** MQTT_GetClientStatus
**
** Get a string of the connection status for the device model items Device.MQTT.Client.{i}.Status
**
** \param instance - Instance ID from Device.MQTT.Client.{i}
**
** \return char string of connection status
**
**************************************************************************/
const char* MQTT_GetClientStatus(int instance);


/*********************************************************************//**
** MQTT_UpdateRetryParams
**
**
** \param instance - Device.MQTT.Client.{i} number for connection
** \param retry_params - pointer to retry parameters to update to
**
** \return None
**
**************************************************************************/
void MQTT_UpdateRetryParams(int instance, mqtt_retry_params_t *retry_params);

/*********************************************************************//**
** MQTT_AreAllResponsesSent
**
**
** \param  None
**
** \return true if all responses have been sent
**
**************************************************************************/
bool MQTT_AreAllResponsesSent(void);

/*********************************************************************//**
** MMQTT_ProcessAllActivity
**
**
** \param  None
**
** \return None
**
**************************************************************************/
void MQTT_ProcessAllActivity(void);

/*********************************************************************//**
** MQTT_AddSubscription
**
**
** \param instance - Device.MQTT.Client.{i} number for connection
** \param subscription - pointer to subscription to add
**
** \return None
**
**************************************************************************/
int MQTT_AddSubscription(int instance, mqtt_subscription_t* subscription);


/*********************************************************************//**
** MQTT_DeleteSubscription
**
**
** \param instance - Device.MQTT.Client.{i} number for connection
** \param retry_params - pointer to subscription to remove
**
** \return None
**
**************************************************************************/
int MQTT_DeleteSubscription(int instance, int subinstance);

/*********************************************************************//**
** MQTT_ScheduleResubscription
**
**
** \param sub - pointer to subscription to reconnect
**
** \return None
**
**************************************************************************/
int MQTT_ScheduleResubscription(int instance, mqtt_subscription_t *subscription);


/*********************************************************************//**
** MQTT_UpdateAllSockSet
**
**
** \param set - socket set to update
**
** \return None
**
**************************************************************************/
void MQTT_UpdateAllSockSet(socket_set_t *set);

/*********************************************************************//**
** MQTT_ProcessAllSocketActivity
**
**
** \param set -socket set to process activity on
**
** \return None
**
**************************************************************************/
void MQTT_ProcessAllSocketActivity(socket_set_t* set);


/*********************************************************************//**
** MQTT_InitConnParams
**
** Initialise the conn params with the default data
**
** \param params - pointer to connection parameters to initialise
**
** \return None
**
**************************************************************************/
void MQTT_InitConnParams(mqtt_conn_params_t* params);


/*********************************************************************//**
** MQTT_DestroyConnParams
**
** Destroys all data within the params. Will not destroy the actual data
** structure that holds the params.
**
** \param params - pointer to params to free the internal data from
**
** \return None
**
**************************************************************************/
void MQTT_DestroyConnParams(mqtt_conn_params_t* params);


/*********************************************************************//**
** MQTT_SubscriptionReplace
**
**
** \param dest - pointer where the data should be copied into
** \param src - pointer where the data comes from
**
** \return None
**
**************************************************************************/
void MQTT_SubscriptionReplace(mqtt_subscription_t *dest, mqtt_subscription_t *src);


/*********************************************************************//**
** MQTT_SubscriptionDestroy
**
** Destroys the contents of a subscription struct. Does not destroy the actual
** struct.
**
** \param sub - pointer to subscription items to destroy the contents of
**
** \return None
**
**************************************************************************/
void MQTT_SubscriptionDestroy(mqtt_subscription_t *sub);

/*********************************************************************//**
**
** MQTT_GetAgentResponseTopicDiscovered
**
** Reads the value of the CONNACK Response Information property supplied by a MQTT 5.0 broker
** If this is not available (for example not MQTT v5.0 or CONNACK not received yet) then an empty string is returned
**
** \param   instance - instance in Device.MQTT.Client.{i}
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  Always USP_ERR_OK - an empty string is returned if the value cannot be determined
**
**************************************************************************/
int MQTT_GetAgentResponseTopicDiscovered(int instance, char *buf, int len);

#endif
