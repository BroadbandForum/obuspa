/*
 *
 * Copyright (C) 2019-2020, Broadband Forum
 * Copyright (C) 2020, BT PLC
 * Copyright (C) 2020  CommScope, Inc
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
 *
 * \file mqtt.c
 *
 * Called from the ProtocolHandler to implement the MQTT protocol
 *
 */
#include "mqtt.h"
#include "common_defs.h"
#include "dllist.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "device.h"
#include "dm_exec.h"
#include "os_utils.h"
#include <errno.h>
#include <math.h>
#include "retry_wait.h"
#include "text_utils.h"
#include "msg_handler.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#ifdef ENABLE_MQTT

#include <mosquitto.h>

// Defines for MQTT Property Values
#define PUBLISH 0x30
#define CONTENT_TYPE 3
#define RESPONSE_TOPIC 8
#define ASSIGNED_CLIENT_IDENTIFIER 18
#define REQUEST_RESPONSE_INFORMATION 25
#define RESPONSE_INFORMATION 26
#define USER_PROPERTY 38


//------------------------------------------------------------------------------
// State of an MQTT Client Connection
typedef enum
{
    kMqttFailure_None,
    kMqttFailure_Connect,
    kMqttFailure_ReadWrite,
    kMqttFailure_Misconfigured,
    kMqttFailure_OtherError,
} mqtt_failure_t;

typedef enum
{
    kMqttState_Idle,                 // Not yet connected
    kMqttState_SendingConnect,       // Need to send the connect message
    kMqttState_AwaitingConnect,      // Waiting for the connect callback
    kMqttState_Running,              // Normal state
    kMqttState_ErrorRetrying,        // Error in the connection (replace with retrying soon..)

    kMqttState_Max
} mqtt_state_t;

mqtt_state_t mqtt_up_states[] = { kMqttState_Running };
mqtt_state_t mqtt_down_states[] = { kMqttState_Idle, kMqttState_AwaitingConnect, kMqttState_SendingConnect };

typedef struct
{
    mqtt_conn_params_t conn_params;
    mqtt_state_t state;
    struct mosquitto *mosq;
    mqtt_subscription_t subscriptions[MAX_MQTT_SUBSCRIPTIONS];
    double_linked_list_t usp_record_send_queue;

    // From the broker
    mqtt_subscription_t response_subscription;

    int retry_count;
    time_t retry_time;
    time_t last_status_change;
    mqtt_failure_t failure_code;

    ctrust_role_t role;
    char *allowed_controllers;

    // Scheduler
    mqtt_conn_params_t next_params;
    scheduled_action_t scheduled_action;

    STACK_OF(X509) *cert_chain;
    ssl_verify_callback_t *verify_callback;
    int socket_fd;
    SSL_CTX *ssl_ctx;
} mqtt_client_t;


//------------------------------------------------------------------------------------
// Array used by debug to print out the current MQTT client connection state
char *mqtt_state_names[kMqttState_Max] =
{
    "Idle",
    "SendingConnect",
    "AwaitingConnect",
    "Running",
    "Error/Retring"
};

typedef struct
{
    double_link_t link;     // Doubly linked list pointers. These must always be first in this structure
    Usp__Header__MsgType usp_msg_type;  // Type of USP message contained within pbuf
    unsigned char *pbuf;    // Protobuf format message to send in binary format
    int pbuf_len;           // Length of protobuf message to send
    char *topic;            // Name of the MQTT Topic to send to
    mqtt_qos_t qos;         // QOS to request when sending message
    int mid;                // MQTT message ID
} mqtt_send_item_t;

mqtt_client_t mqtt_clients[MAX_MQTT_CLIENTS];
static pthread_mutex_t mqtt_access_mutex;


//------------------------------------------------------------------------------------
// Forward declarations. These are not static, because we need them in the symbol table for USP_LOG_Callstack()
mqtt_client_t *FindMqttClientByInstance(int instance);
void ParamReplace(mqtt_conn_params_t *dest, mqtt_conn_params_t *src);
int EnableMosquitto(mqtt_client_t *client);
#define MoveState(state, to, event) MoveState_Private(state, to, event, __FUNCTION__)
void MoveState_Private(mqtt_state_t *state, mqtt_state_t to, const char *event, const char *func);
void HandleMqttError(mqtt_client_t *client, mqtt_failure_t failure_code, const char* message);

//------------------------------------------------------------------------------------
// Callbacks
void ConnectCallback(struct mosquitto *mosq, void *userdata, int result);
void SubscribeCallback(struct mosquitto *mosq, void *userdata, int mid, int qos_count, const int* granted_qos);
void UnsubscribeCallback(struct mosquitto *mosq, void *userdata, int mid );
void PublishCallback(struct mosquitto* mosq, void *userdata, int mid /*message id*/);
void MessageCallback(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message);
void LogCallback(struct mosquitto *mosq, void *userdata, int level, const char *str);
void DisconnectCallback(struct mosquitto *mosq, void *userdata, int rc);

//------------------------------------------------------------------------------------
// V5 Callbacks
void ConnectV5Callback(struct mosquitto *mosq, void *userdata, int result, int flags, const mosquitto_property *props);
void SubscribeV5Callback(struct mosquitto *mosq, void *userdata, int mid, int qos_count, const int* granted_qos,
        const mosquitto_property* props);
void UnsubscribeV5Callback(struct mosquitto *mosq, void *userdata, int mid, const mosquitto_property* props);
void PublishV5Callback(struct mosquitto *mosq, void *userdata, int mid, int reason_code, const mosquitto_property *props);
void MessageV5Callback(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message, const mosquitto_property *props);

#define DEFINE_MQTT_TrustCertVerifyCallbackIndex(index) \
int MQTT_TrustCertVerifyCallback_##index (int preverify_ok, X509_STORE_CTX *x509_ctx) \
{\
    return DEVICE_SECURITY_TrustCertVerifyCallbackWithCertChain(preverify_ok, x509_ctx, &mqtt_clients[index].cert_chain);\
}

#define MQTT_TrustCertVerifyCallbackIndex(index) MQTT_TrustCertVerifyCallback_##index

DEFINE_MQTT_TrustCertVerifyCallbackIndex(0);
DEFINE_MQTT_TrustCertVerifyCallbackIndex(1);
DEFINE_MQTT_TrustCertVerifyCallbackIndex(2);
DEFINE_MQTT_TrustCertVerifyCallbackIndex(3);
DEFINE_MQTT_TrustCertVerifyCallbackIndex(4);
// Add more, with incrementing indexes here, if you change MAX_MQTT_CLIENTS

//------------------------------------------------------------------------------------
// Global variables
ssl_verify_callback_t* mqtt_verify_callbacks[] = {
    MQTT_TrustCertVerifyCallbackIndex(0),
    MQTT_TrustCertVerifyCallbackIndex(1),
    MQTT_TrustCertVerifyCallbackIndex(2),
    MQTT_TrustCertVerifyCallbackIndex(3),
    MQTT_TrustCertVerifyCallbackIndex(4),
    // Add more, with incrementing indexes here, if you change MAX_MQTT_CLIENTS
};

USP_COMPILEASSERT( ((sizeof(mqtt_verify_callbacks)/sizeof(ssl_verify_callback_t*)) == MAX_MQTT_CLIENTS),
        "There must be MAX_MQTT_CLIENTS callbacks defined");

//------------------------------------------------------------------------------------
// Wrappers around mosquitto functions
int ClientMosquittoSocket(mqtt_client_t *client)
{
    // Will be -1 if failed
    return mosquitto_socket(client->mosq);
}

int AddUserProperties(mosquitto_property **props)
{
    char* endpoint = DEVICE_LOCAL_AGENT_GetEndpointID();
    if (mosquitto_property_add_string_pair(props, USER_PROPERTY, "usp-endpoint-id",
                endpoint) != MOSQ_ERR_SUCCESS)
    {
        USP_LOG_Error("Failed to add user property string to properties");
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

int AddConnectProperties(mosquitto_property **props)
{
    if (AddUserProperties(props) != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    if (mosquitto_property_add_byte(props, REQUEST_RESPONSE_INFORMATION, (uint8_t)1) != MOSQ_ERR_SUCCESS)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

void SetupCallbacks(mqtt_client_t *client)
{
    // Register all the generic callbacks
    // Bear in mind that these callbacks are used for every client
    // Need v5 and v3.1/3.1.1 callbacks registered where needed
    mosquitto_log_callback_set(client->mosq, LogCallback);
    mosquitto_disconnect_callback_set(client->mosq, DisconnectCallback);

    if (client->conn_params.version == kMqttProtocol_5_0)
    {
        mosquitto_connect_v5_callback_set(client->mosq, ConnectV5Callback);
        mosquitto_subscribe_v5_callback_set(client->mosq, SubscribeV5Callback);
        mosquitto_unsubscribe_v5_callback_set(client->mosq, UnsubscribeV5Callback);
        mosquitto_publish_v5_callback_set(client->mosq, PublishV5Callback);
        mosquitto_message_v5_callback_set(client->mosq, MessageV5Callback);
    }
    else
    {
        mosquitto_connect_callback_set(client->mosq, ConnectCallback);
        mosquitto_subscribe_callback_set(client->mosq, SubscribeCallback);
        mosquitto_unsubscribe_callback_set(client->mosq, UnsubscribeCallback);
        mosquitto_publish_callback_set(client->mosq, PublishCallback);
        mosquitto_message_callback_set(client->mosq, MessageCallback);
    }
}

int ConvertToMosquittoVersion(mqtt_protocolver_t version, int* mosquitto_version)
{
    if (mosquitto_version == NULL)
    {
        return USP_ERR_UNSUPPORTED_PARAM;
    }

    switch(version)
    {
        case kMqttProtocol_3_1:
            *mosquitto_version = MQTT_PROTOCOL_V31;
            break;
        case kMqttProtocol_3_1_1:
            *mosquitto_version = MQTT_PROTOCOL_V311;
            break;
        case kMqttProtocol_5_0:
            *mosquitto_version = MQTT_PROTOCOL_V5;
            break;
        default:
            return USP_ERR_UNSUPPORTED_PARAM;
            break;
    }

    return USP_ERR_OK;
}

int EnableMosquitto(mqtt_client_t *client)
{
    // Create a new mosquitto client instance
    // This takes the instance as the (void *) obj argument
    // Allowing us to use the instance number to identify any callbacks
    if (client->mosq != NULL)
    {
        // Destroy the mosquitto client
        // Will be regenerated with the mosquitto_new later
        mosquitto_destroy(client->mosq);
        client->mosq = NULL;
    }

    bool clean = client->conn_params.clean_session; // v3

    // Use clean_start (v5) flag instead
    if (client->conn_params.version == kMqttProtocol_5_0)
    {
        clean = client->conn_params.clean_start;
    }

    char* client_id = NULL;

    if (client->conn_params.client_id == NULL || strlen(client->conn_params.client_id) == 0)
    {
        if (client->conn_params.version != kMqttProtocol_5_0)
        {
            USP_LOG_Debug("Client id is null or 0 length, overriding with endpoint");
            USP_SAFE_FREE(client->conn_params.client_id);
            client->conn_params.client_id = USP_STRDUP(DEVICE_LOCAL_AGENT_GetEndpointID());

            // Got to make sure we do have a client id in v3
            USP_ASSERT(strlen(client->conn_params.client_id) > 0);

            client_id = client->conn_params.client_id;
        }
    }
    else
    {
        client_id = client->conn_params.client_id;
    }

    // If there's no client_id, we wil be requesting a new one,
    // Therefore, we must use a clean request.
    if (client_id == NULL)
    {
        clean = true;
    }

    client->mosq = mosquitto_new((const char*)client_id, clean, &client->conn_params.instance);

    if (client->mosq == NULL)
    {
        // check errno
        USP_LOG_Error("%s: Failed to allocate a new mosquitto client. errno %d", __FUNCTION__, errno);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Ensure we have the thread-safe implementation of mosquitto
    mosquitto_threaded_set(client->mosq, true);

    // Set the mosquitto version in use
    int mosquitto_version = 0;
    if (ConvertToMosquittoVersion(client->conn_params.version, &mosquitto_version) != USP_ERR_OK)
    {
        USP_LOG_Error("%s: Failed to get the mosquitto version from provided client version", __FUNCTION__);
        return USP_ERR_UNSUPPORTED_PARAM;
    }

    if (mosquitto_int_option(client->mosq, MOSQ_OPT_PROTOCOL_VERSION, mosquitto_version) != MOSQ_ERR_SUCCESS)
    {
        USP_LOG_Error("Failed to set mosquitto version %d", mosquitto_version);
        return USP_ERR_UNSUPPORTED_PARAM;
    }

    SetupCallbacks(client);
    return USP_ERR_OK;
}

int ConnectSetEncryption(mqtt_client_t *client)
{
    USP_ASSERT(client->ssl_ctx != NULL);
    int err;

    err = DEVICE_SECURITY_LoadTrustStore(client->ssl_ctx, SSL_VERIFY_PEER, client->verify_callback);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: Failed to load the trust store", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }
    else
    {
        USP_LOG_Debug("%s: Loaded the trust store!", __FUNCTION__);
    }

    err = DEVICE_SECURITY_AddCertHostnameValidationCtx(client->ssl_ctx, client->conn_params.host,
                                                        strlen(client->conn_params.host));
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: Adding SSL hostname validation failed.", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Set TLS using SSL_CTX in lib mosquitto
    if(mosquitto_opts_set(client->mosq, MOSQ_OPT_SSL_CTX, client->ssl_ctx) != MOSQ_ERR_SUCCESS)
    {
        USP_LOG_Error("%s: Failed to set ssl_ctx into mosquitto", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

int ConnectV5(mqtt_client_t *client)
{
    // Setup the proplist
    mosquitto_property *proplist = NULL;
    int mosq_err = MOSQ_ERR_SUCCESS;
    int err = USP_ERR_OK;

    // Add all properties required for the connection
    if (AddConnectProperties(&proplist) != USP_ERR_OK)
    {
        err = USP_ERR_INTERNAL_ERROR;
        goto error;
    }

    mosq_err = mosquitto_connect_bind_v5(client->mosq, client->conn_params.host, client->conn_params.port,
            client->conn_params.keepalive, NULL, proplist);

    if (mosq_err != MOSQ_ERR_SUCCESS)
    {
        USP_LOG_Error("Failed to connect v5 with %s (%d)", mosquitto_strerror(mosq_err), mosq_err);

        err = USP_ERR_INTERNAL_ERROR;
        goto error;
    }

error:
    if (proplist != NULL)
    {
        mosquitto_property_free_all(&proplist);
    }
    return err;
}

int Connect(mqtt_client_t *client)
{
    int err = USP_ERR_OK;
    int version = client->conn_params.version;

    // Set username/ password before connecting
    if (strlen(client->conn_params.username) > 0)
    {
        if (mosquitto_username_pw_set(client->mosq, client->conn_params.username, client->conn_params.password) != MOSQ_ERR_SUCCESS)
        {
            HandleMqttError(client, kMqttFailure_OtherError, "Failed to set username/password");
            return USP_ERR_INTERNAL_ERROR;
        }
    }
    else
    {
        USP_LOG_Debug("%s: No username found - so not using one", __FUNCTION__);
    }

    if (client->conn_params.ts_protocol == kMqttTSprotocol_tls)
    {
        USP_LOG_Debug("Enabling encryption for MQTT client");
        err = ConnectSetEncryption(client);
        if (err != USP_ERR_OK)
        {
            USP_LOG_Error("%s: Failed to set encryption when requested - terminating", __FUNCTION__);

            HandleMqttError(client, kMqttFailure_Misconfigured, "Failed to set SSL");

            return err;
        }
    }

    if (version == kMqttProtocol_5_0)
    {
        err = ConnectV5(client);
        if (err != USP_ERR_OK)
        {
            return err;
        }
    }
    else
    {
        int mosq_err = mosquitto_connect(client->mosq, client->conn_params.host, client->conn_params.port,
                    client->conn_params.keepalive);
        if (mosq_err != MOSQ_ERR_SUCCESS)
        {
            USP_LOG_Error("Failed to connect v3.1.1 with %s (%d)", mosquitto_strerror(mosq_err), mosq_err);
            return USP_ERR_INTERNAL_ERROR;
        }
    }

    // Load the socket in from connect
    client->socket_fd = ClientMosquittoSocket(client);
    USP_ASSERT(client->socket_fd >= 0);
    return err;
}

int SubscribeV5(mqtt_client_t *client, mqtt_subscription_t *sub)
{
    int err = USP_ERR_OK;
    mosquitto_property *proplist = NULL;

    if (AddUserProperties(&proplist) != USP_ERR_OK)
    {
        err = USP_ERR_INTERNAL_ERROR;
        goto error;
    }

    if (mosquitto_subscribe_v5(client->mosq, &sub->mid, sub->topic, sub->qos,
                0 /*Options, default */, proplist) != MOSQ_ERR_SUCCESS)
    {
        USP_LOG_Error("Failed to subscribe to %s with v5", sub->topic);

        err = USP_ERR_INTERNAL_ERROR;
        goto error;
    }

error:
    if (proplist)
    {
        // Free prop list now we're finished with it.
        mosquitto_property_free_all(&proplist);
    }
    return err;
}

int Subscribe(mqtt_client_t *client, mqtt_subscription_t *sub)
{
    USP_ASSERT(client != NULL);
    USP_ASSERT(sub != NULL);

    if (sub->topic == NULL)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    int err = USP_ERR_OK;
    int version = client->conn_params.version;

    sub->state = kMqttSubState_Subscribing;
    USP_LOG_Debug("%s: Sending subscribe to %s %d %d", __FUNCTION__, sub->topic, sub->mid, sub->qos);
    if (version == kMqttProtocol_5_0)
    {
        err = SubscribeV5(client, sub);
    }
    else
    {
        if (mosquitto_subscribe(client->mosq, &sub->mid, sub->topic, sub->qos) != MOSQ_ERR_SUCCESS)
        {
            USP_LOG_Error("Failed to subscribe to %s", sub->topic);
            err = USP_ERR_INTERNAL_ERROR;
        }
    }

    return err;
}

int UnsubscribeV5(mqtt_client_t *client, mqtt_subscription_t *sub)
{
    mosquitto_property *proplist = NULL;
    int err = USP_ERR_OK;

    if (AddUserProperties(&proplist) != USP_ERR_OK)
    {
        err = USP_ERR_INTERNAL_ERROR;
        goto error;
    }

    if (mosquitto_unsubscribe_v5(client->mosq, &sub->mid, sub->topic, proplist) != MOSQ_ERR_SUCCESS)
    {
        USP_LOG_Error("Failed to unsubscribe to %s with v5", sub->topic);
        err = USP_ERR_INTERNAL_ERROR;
    }

error:
    if (proplist)
    {
        // Free all properties now that we're done with them.
        mosquitto_property_free_all(&proplist);
    }
    return err;
}

int Unsubscribe(mqtt_client_t *client, mqtt_subscription_t *sub)
{
    USP_ASSERT(client != NULL);
    USP_ASSERT(sub != NULL);

    if (sub->topic == NULL)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    int version = client->conn_params.version;
    int err = USP_ERR_OK;

    sub->state = kMqttSubState_Unsubscribing;
    if (version == kMqttProtocol_5_0)
    {
        err = UnsubscribeV5(client, sub);
    }
    else
    {
        if (mosquitto_unsubscribe(client->mosq, &sub->mid, sub->topic) != MOSQ_ERR_SUCCESS)
        {
            USP_LOG_Error("Failed to subscribe to %s", sub->topic);
            err = USP_ERR_INTERNAL_ERROR;
        }
    }

    return err;
}

int SubscribeToAll(mqtt_client_t *client)
{
    int err = USP_ERR_OK;
    int i;

    // Let the DM know we're ready for sending messages
    DM_EXEC_PostMqttHandshakeComplete(client->conn_params.instance, client->role, client->allowed_controllers);

    // Now we have the proplist, send the subscribe
    for (i = 0; i < MAX_MQTT_SUBSCRIPTIONS; i++)
    {
        mqtt_subscription_t *sub = &client->subscriptions[i];
        if (sub->enabled == true)
        {
            if (sub->topic == NULL)
            {
                USP_LOG_Error("%s: No to subscribe to, skipping sub %d", __FUNCTION__, i);
                continue;
            }

            if (Subscribe(client, sub) != USP_ERR_OK)
            {
                err = USP_ERR_INTERNAL_ERROR;
            }
        }
    }

    // Subscribe to response topic too
    if (Subscribe(client, &client->response_subscription) != USP_ERR_OK)
    {
        USP_LOG_Error("%s: Failed to subscribe to response topic", __FUNCTION__);
        err = USP_ERR_INTERNAL_ERROR;
    }

    return err;
}

int PublishV5(mqtt_client_t *client, mqtt_send_item_t *msg)
{
    int err = USP_ERR_OK;
    mosquitto_property *proplist = NULL;

    // Setup proplist flags for v5
    if (mosquitto_property_add_string(&proplist, CONTENT_TYPE, "application/vnd.bbf.usp.msg") != MOSQ_ERR_SUCCESS)
    {
        USP_LOG_Error("Failed to add content type string");
        err = USP_ERR_INTERNAL_ERROR;
        goto error;
    }

    if (mosquitto_property_add_string(&proplist, RESPONSE_TOPIC, client->response_subscription.topic) != MOSQ_ERR_SUCCESS)
    {
        USP_LOG_Error("Failed to add response topic string");
        err = USP_ERR_INTERNAL_ERROR;
        goto error;
    }

    // Check all properties
    if (mosquitto_property_check_all(PUBLISH, proplist) != MOSQ_ERR_SUCCESS)
    {
        USP_LOG_Error("property check failed.");
        err = USP_ERR_INTERNAL_ERROR;
        goto error;
    }

    int mosq_err = mosquitto_publish_v5(client->mosq, &msg->mid, msg->topic, msg->pbuf_len, msg->pbuf, msg->qos, false /* retain */, proplist);
    if (mosq_err != MOSQ_ERR_SUCCESS)
    {
        USP_LOG_Error("Failed to publish to v5 with error %d", mosq_err);
        err = USP_ERR_INTERNAL_ERROR;
        goto error;
    }

error:
    // Free all properties now we're done with them.
    mosquitto_property_free_all(&proplist);
    return err;
}

int Publish(mqtt_client_t *client, mqtt_send_item_t *msg)
{
    int err = USP_ERR_OK;

    USP_ASSERT(client != NULL);
    USP_ASSERT(msg != NULL);
    USP_ASSERT(msg->topic != NULL);

    MSG_HANDLER_LogMessageToSend(msg->usp_msg_type, msg->pbuf, msg->pbuf_len, kMtpProtocol_MQTT, client->conn_params.host, NULL, kMtpContentType_UspRecord);

    int version = client->conn_params.version;
    if (version == kMqttProtocol_5_0)
    {
        err = PublishV5(client, msg);
    }
    else
    {
        if (mosquitto_publish(client->mosq, &msg->mid, msg->topic, msg->pbuf_len, msg->pbuf, msg->qos, false /*retain*/) != MOSQ_ERR_SUCCESS)
        {
            USP_LOG_Error("Failed to publish to v3.1.1. Params:\n MID:%d\n topic:%s\n msg->qos:%d\n", msg->mid, msg->topic, msg->qos);
            err = USP_ERR_INTERNAL_ERROR;
        }
    }

    return err;
}

//------------------------------------------------------------------------------
// Private functions

int DisconnectClient(mqtt_client_t *client)
{
    int err = USP_ERR_OK;

    if (client->state != kMqttState_Idle)
    {
        if (mosquitto_disconnect(client->mosq) != MOSQ_ERR_SUCCESS)
        {
            err = USP_ERR_INTERNAL_ERROR;
        }
    }

    // No more socket after disconnect
    client->socket_fd = INVALID;

    return err;
}


void HandleMqttError(mqtt_client_t *client, mqtt_failure_t failure_code, const char* message)
{
    if (client->state != kMqttState_ErrorRetrying)
    {
        ParamReplace(&client->next_params, &client->conn_params);
        MoveState(&client->state, kMqttState_ErrorRetrying, message);
    }

    USP_LOG_Debug("%s: Got error: %d, reason: %s, retry_count: %d", __FUNCTION__, failure_code, message,
            client->retry_count);

    time_t cur_time = time(NULL);
    // Flow is:
    // Set failure code - to something useful. Passed in as arg.
    if (client->failure_code != failure_code)
    {
        client->last_status_change = cur_time;
        client->failure_code = failure_code;
    }

    // Disable the client from connecting again
    if(DisconnectClient(client) != USP_ERR_OK)
    {
        USP_LOG_Warning("%s: Disconnect failed. Already disconnected?\n", __FUNCTION__);
    }

    // Increment retry count
    client->retry_count++;

    // Calculate a wait time until retry
    mqtt_retry_params_t *retry = &client->conn_params.retry;
    time_t wait_time = RETRY_WAIT_Calculate(client->retry_count, retry->connect_retrytime, retry->interval_multiplier);

    if (wait_time > retry->max_interval)
    {
        wait_time = retry->max_interval;
    }

    // Set retry time as time + wait_time
    client->retry_time = cur_time + wait_time;
}



void MoveState_Private(mqtt_state_t *state, mqtt_state_t to, const char *event, const char* func)
{
    USP_LOG_Debug("%s (%s): %s --> [[ %s ]] --> %s", func, __FUNCTION__, mqtt_state_names[*state], event, mqtt_state_names[to]);

    *state = to;
}

void PopClientUspQueue(mqtt_client_t *client)
{
    // Remove the head of the client usp queue
    // Passed the client, not queue to distinguish this from a generic queue pop
    // We make some assumptions as to the type of structure this is

    if (client)
    {
        mqtt_send_item_t *head = (mqtt_send_item_t *) client->usp_record_send_queue.head;
        if (head != NULL)
        {
            USP_SAFE_FREE(head->topic);
            USP_SAFE_FREE(head->pbuf);
            DLLIST_Unlink(&client->usp_record_send_queue, head);
            USP_SAFE_FREE(head);
        }
    }
}

void ReceiveMqttMessage(mqtt_client_t *client, const struct mosquitto_message *message, char *response_topic)
{
    mtp_reply_to_t mrt;
    memset(&mrt, 0, sizeof(mrt));
    mrt.protocol = kMtpProtocol_MQTT;
    if (response_topic != NULL)
    {
        mrt.mqtt_instance = client->conn_params.instance;
        mrt.is_reply_to_specified = true;
        mrt.mqtt_topic = response_topic;
    }

    // Message may not be valid USP
    DM_EXEC_PostUspRecord(message->payload, message->payloadlen, client->role, client->allowed_controllers, &mrt);
}

int SendQueueHead(mqtt_client_t *client)
{
    int err = USP_ERR_OK;

    // Can't be passed a NULL client
    USP_ASSERT(client != NULL);

    mqtt_state_t state = client->state;
    if (state == kMqttState_Running)
    {
        mqtt_send_item_t * q_msg = (mqtt_send_item_t *) client->usp_record_send_queue.head;

        // Check the queue head is ok
        if (q_msg == NULL)
        {
            USP_LOG_Error("%s: Can't send NULL head", __FUNCTION__);
            return USP_ERR_INTERNAL_ERROR;
        }

        err = Publish(client, q_msg);
    }
    else
    {
        USP_LOG_Error("Incorrect state for sending messages %s", mqtt_state_names[state]);
        err = USP_ERR_INTERNAL_ERROR;
    }

    return err;
}

bool IsUspRecordInMqttQueue(mqtt_client_t *client, unsigned char *pbuf, int pbuf_len)
{
    mqtt_send_item_t *q_msg;

    q_msg = (mqtt_send_item_t *) client->usp_record_send_queue.head;
    while (q_msg != NULL)
    {
        if ((q_msg->pbuf_len == pbuf_len) && (memcmp(q_msg->pbuf, pbuf, pbuf_len)==0))
        {
            return true;
        }

        q_msg = (mqtt_send_item_t *) q_msg->link.next;
    }

    return false;
}

mqtt_client_t *FindMqttClientByInstance(int instance)
{
    int i;
    mqtt_client_t *client;

    for (i = 0; i < MAX_MQTT_CLIENTS; i++)
    {
        client = &mqtt_clients[i];

        if (client->conn_params.instance == instance)
        {
            return client;
        }
    }

    return NULL;
}

mqtt_subscription_t *FindMqttSubscriptionByInstance(int clientinstance, int subinstance)
{
    int i;
    mqtt_client_t *client;
    mqtt_subscription_t *subs;

    client = FindMqttClientByInstance(clientinstance);
    USP_ASSERT(client != NULL);

    for (i = 0; i < MAX_MQTT_SUBSCRIPTIONS; i++)
    {
        subs = &client->subscriptions[i];

        if (subs->instance == subinstance)
        {
            return subs;
        }
    }

    return NULL;
}

mqtt_client_t *FindMqttClientByMosquitto(struct mosquitto *mosq)
{
    int i;
    mqtt_client_t *client;

    for (i = 0; i < MAX_MQTT_CLIENTS; i++)
    {
        client = &mqtt_clients[i];
        if (client->mosq == mosq)
        {
            return client;
        }
    }

    return NULL;
}

mqtt_subscription_t *FindSubscriptionByMid(mqtt_client_t *client, int mid)
{
    int i;

    if (client == NULL)
    {
        return NULL;
    }

    for (i = 0; i < MAX_MQTT_SUBSCRIPTIONS; i++)
    {
        if (client->subscriptions[i].mid == mid)
        {
            return &client->subscriptions[i];
        }
    }

    if (client->response_subscription.mid == mid)
    {
        return &client->response_subscription;
    }

    return NULL;
}

mqtt_client_t *FindUnusedMqttClient_Local()
{
    return FindMqttClientByInstance(INVALID);
}

void MQTT_SubscriptionReplace(mqtt_subscription_t *dest, mqtt_subscription_t *src)
{
    MQTT_SubscriptionDestroy(dest);

    *dest = *src;
    dest->topic = USP_STRDUP(src->topic);
}

void MQTT_SubscriptionDestroy(mqtt_subscription_t *sub)
{
    USP_SAFE_FREE(sub->topic);
    memset(sub, 0, sizeof(mqtt_subscription_t));
    sub->instance = INVALID;
}

// Handler to reset the retry counts for backoff
void ResetRetryCount(mqtt_client_t* client)
{
    if (client)
    {
        client->retry_time = 0;
        client->retry_count = 0;
    }
}

void ParamReplace(mqtt_conn_params_t *dest, mqtt_conn_params_t *src)
{
    if (dest == src)
    {
        // This shouldn't really happen,
        // but protect against it anyway
        return;
    }

    // Free the destination, just to simplify
    MQTT_DestroyConnParams(dest);

    *dest = *src;

    // Override all pointers with copies on the heap - must be freed
    dest->host = USP_STRDUP(src->host);
    dest->username = USP_STRDUP(src->username);
    dest->password = USP_STRDUP(src->password);
    dest->topic = USP_STRDUP(src->topic);
    dest->response_topic = USP_STRDUP(src->response_topic);
    dest->client_id = USP_STRDUP(src->client_id);
    dest->name = USP_STRDUP(src->name);
    dest->response_information = USP_STRDUP(src->response_information);

# if 0
    // TODO: Removed as these are not currently used.
    dest->will_content_type = USP_STRDUP(src->will_content_type);
    dest->will_response_topic = USP_STRDUP(src->will_response_topic);
    dest->will_topic = USP_STRDUP(src->will_topic);
    dest->will_value = USP_STRDUP(src->will_value);
    dest->auth_method = USP_STRDUP(src->auth_method);
#endif
}

// Free everything that has been allocated under *params.
void MQTT_DestroyConnParams(mqtt_conn_params_t *params)
{
    // Free all the items in the parameters
    USP_SAFE_FREE(params->host);
    USP_SAFE_FREE(params->username);
    USP_SAFE_FREE(params->password);
    USP_SAFE_FREE(params->topic);
    USP_SAFE_FREE(params->response_topic);
    USP_SAFE_FREE(params->client_id);
    USP_SAFE_FREE(params->name);
    USP_SAFE_FREE(params->response_information);

# if 0
    // TODO: Removed as these are not currently used.
    USP_SAFE_FREE(params->will_content_type);
    USP_SAFE_FREE(params->will_response_topic);
    USP_SAFE_FREE(params->will_topic);
    USP_SAFE_FREE(params->will_value);
    USP_SAFE_FREE(params->auth_method);
#endif

    memset(params, 0, sizeof(mqtt_conn_params_t));

    // Set to invalid as this is the default
    params->instance = INVALID;
}

//------------------------------------------------------------------------------
// V5 Callback
void PublishV5Callback(struct mosquitto *mosq, void *userdata, int mid, int reason_code, const mosquitto_property *props)
{
    // Mutex taken in PublishCallback.
    PublishCallback(mosq, userdata, mid);
}


void MessageV5Callback(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message, const mosquitto_property *props)
{
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    mqtt_client_t *client = NULL;
    int instance = *(int*) userdata;

    client = FindMqttClientByInstance(instance);
    if (client == NULL)
    {
        USP_LOG_Error("%s: Failed to find client instance by id %d", __FUNCTION__, instance);
        goto exit;
    }

    if (message == NULL)
    {
        USP_LOG_Error("%s: NULL message", __FUNCTION__);
    }
    else if (!message->payloadlen)
    {
        USP_LOG_Warning("%s: Empty message on topic: %s", message->topic, __FUNCTION__);
    }
    else
    {
        USP_LOG_Info("%s: Received Message: Topic: %s", __FUNCTION__, message->topic);
        //USP_LOG_Info("%s: Received Message: Payload: %s", __FUNCTION__, (char*)message->payload);

        if (client->state == kMqttState_Running)
        {
            // Now we have a message from somewhere
            char response_info[512] = { 0 };
            char *response_info_ptr = response_info;

            if (mosquitto_property_read_string(props, RESPONSE_TOPIC,
                    &response_info_ptr, false) == NULL)
            {
                USP_LOG_Debug("Failed to read response topic in message info: \"%s\"\n", response_info_ptr);
                response_info_ptr = NULL;
            }

            ReceiveMqttMessage(client, message, response_info_ptr);
        }
        else
        {
            USP_LOG_Warning("%s: Ignoring message received in incorrect state", __FUNCTION__);
        }
    }

exit:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);

}


void SubscribeV5Callback(struct mosquitto *mosq, void *userdata, int mid, int qos_count, const int* granted_qos,
        const mosquitto_property* props)
{
    // Basically the same as the 3.1.1 callback..
    // Mutex will be taken in the function below.
    SubscribeCallback(mosq, userdata, mid, qos_count, granted_qos);
}

void UnsubscribeV5Callback(struct mosquitto *mosq, void *userdata, int mid, const mosquitto_property* props)
{
    // Basically the same as the 3.1.1 callback..
    // Mutex will be taken in the function below.
    UnsubscribeCallback(mosq, userdata, mid);
}

void ConnectV5Callback(struct mosquitto *mosq, void *userdata, int result, int flags, const mosquitto_property *props)
{
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    // Receive the CONNACK here
    // Check the same stuff as the connect callback - but also look at the props values etc
    mqtt_client_t *client = NULL;
    int instance = *(int*)userdata;

    client = FindMqttClientByInstance(instance);
    if (client == NULL)
    {
        USP_LOG_Error("%s: Failed to find client instance by id %d", __FUNCTION__, instance);
        goto exit;
    }

    if (client->state != kMqttState_AwaitingConnect && client->state != kMqttState_ErrorRetrying)
    {
        USP_LOG_Error("%s: Wrong state: %s for client %d", __FUNCTION__, mqtt_state_names[client->state], instance);

        HandleMqttError(client, kMqttFailure_OtherError, "State error in connect v5 callback");
    }
    else if (result != 0)
    {
        // R-MQTT.10
        USP_LOG_Error("%s: Bad result (%d) in connect callback", __FUNCTION__, result);

        HandleMqttError(client, kMqttFailure_OtherError, "Error in connect v5 callback");
    }
    else
    {
        if (client->cert_chain != NULL)
        {
            int err = DEVICE_SECURITY_GetControllerTrust(client->cert_chain, &client->role, &client->allowed_controllers);
            if (err != USP_ERR_OK)
            {
                USP_LOG_Error("Failed to get the controller trust with err: %d", err);
            }
            else
            {
                USP_LOG_Debug("%s: Successfully got the cert chain!", __FUNCTION__);
            }
        }
        else
        {
            USP_LOG_Error("%s: No cert chain, so cannot get controller trust", __FUNCTION__);
        }


        // Pick up client id, as per R-MQTT.9
        // Done as arrays on the stack here so we don't have _even_ more to free from the heap
        char client_id[512] = { 0 };
        char *client_id_ptr = client_id;
        char response_info[512] = { 0 };
        char *response_info_ptr = response_info;
        char subscribe_topic[512] = { 0 };
        char *subscribe_topic_ptr = subscribe_topic;

        mosquitto_property_read_string(props, ASSIGNED_CLIENT_IDENTIFIER,
                &client_id_ptr, false /* skip first */);

        mosquitto_property_read_string(props, RESPONSE_INFORMATION,
                &response_info_ptr, false);

        char* name = "subscribe-topic";
        if (mosquitto_property_read_string_pair(props, USER_PROPERTY,
                &name, &subscribe_topic_ptr, false) != MOSQ_ERR_SUCCESS)
        {
            USP_LOG_Error("Couldn't find subscribe-topic in user properties");
        }

        USP_LOG_Debug("Received subcribe-topic: \"%s\"", subscribe_topic);

        if (strlen(response_info_ptr) > 0)
        {
            // Then replace the response_topic in subscription with this
            USP_SAFE_FREE(client->response_subscription.topic);
            client->response_subscription.topic = USP_STRDUP(response_info_ptr);
        }

        USP_SAFE_FREE(client->conn_params.client_id);
        client->conn_params.client_id = USP_STRDUP(client_id_ptr);
        USP_LOG_Debug("Received client id \"%s\"", client->conn_params.client_id);

        ResetRetryCount(client);

        MoveState(&client->state, kMqttState_Running, "Connect Callback Received");
        SubscribeToAll(client);
    }

exit:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);
}

//------------------------------------------------------------------------------
// Callbacks
void ConnectCallback(struct mosquitto *mosq, void *userdata, int result)
{
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    mqtt_client_t *client = NULL;
    int instance = *(int*)userdata;

    client = FindMqttClientByInstance(instance);
    if (client == NULL)
    {
        USP_LOG_Error("%s: Failed to find client instance by id %d", __FUNCTION__, instance);
        goto exit;
    }

    if (client->state != kMqttState_AwaitingConnect && client->state != kMqttState_ErrorRetrying)
    {
        USP_LOG_Error("%s: Wrong state: %s for client %d", __FUNCTION__, mqtt_state_names[client->state], instance);
    }
    else if (result != 0)
    {
        USP_LOG_Error("%s: Bad result (%d) in connect callback", __FUNCTION__, result);

        HandleMqttError(client, kMqttFailure_OtherError, "Error in connect callback");
    }
    else
    {
        if (client->cert_chain != NULL)
        {
            int err = DEVICE_SECURITY_GetControllerTrust(client->cert_chain, &client->role, &client->allowed_controllers);
            if (err != USP_ERR_OK)
            {
                USP_LOG_Error("Failed to get the controller trust with err: %d", err);
            }
            else
            {
                USP_LOG_Debug("%s: Successfully got the cert chain!", __FUNCTION__);
            }
        }
        else
        {
            USP_LOG_Error("%s: No cert chain, so cannot get controller trust", __FUNCTION__);
        }


        ResetRetryCount(client);

        MoveState(&client->state, kMqttState_Running, "Connect Callback Received");
        SubscribeToAll(client);
    }

exit:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);
}

void SubscribeCallback(struct mosquitto *mosq, void *userdata, int mid, int qos_count, const int* granted_qos)
{
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    mqtt_client_t *client = NULL;
    int instance = *(int*) userdata;

    client = FindMqttClientByInstance(instance);
    if (client == NULL)
    {
        USP_LOG_Error("%s: Failed to find client instance by id %d", __FUNCTION__, instance);
        goto exit;
    }

    // Find the subscriber mid
    mqtt_subscription_t *sub = FindSubscriptionByMid(client, mid);

    if (sub == NULL)
    {
        USP_LOG_Error("%s: Failed to find subscription with mid %d", __FUNCTION__, mid);
        goto exit;
    }

    if (sub->state != kMqttSubState_Subscribing)
    {
        USP_LOG_Error("%s: Wrong state %d", __FUNCTION__, sub->state);
    }
    else
    {
        sub->state = kMqttSubState_Subscribed;
    }

exit:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);

}

void UnsubscribeCallback(struct mosquitto *mosq, void *userdata, int mid )
{
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    mqtt_client_t *client = NULL;
    int instance = *(int*) userdata;

    client = FindMqttClientByInstance(instance);
    if (client == NULL)
    {
        USP_LOG_Error("%s: Failed to find client instance by id %d", __FUNCTION__, instance);
        return;
    }

    // Find the subscriber mid
    mqtt_subscription_t *sub = FindSubscriptionByMid(client, mid);

    if (sub == NULL)
    {
        USP_LOG_Error("%s: Failed to find subscription with mid %d", __FUNCTION__, mid);
        goto exit;
    }

    if (sub->state == kMqttSubState_Unsubscribing)
    {
        sub->state = kMqttSubState_Unsubscribed;
    }
    else if(sub->state == kMqttSubState_Resubscribing)
    {
        if (Subscribe(client, sub) != USP_ERR_OK)
        {
            USP_LOG_Error("%s: Re-Subscribe topic failed", __FUNCTION__);
        }
        else
        {
            USP_LOG_Debug("%s: Resubscribing", __FUNCTION__);
        }
    }
    else
    {
        USP_LOG_Error("%s: Wrong state %d", __FUNCTION__, sub->state);
    }

exit:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);

}

void PublishCallback(struct mosquitto* mosq, void *userdata, int mid /*message id*/)
{
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    mqtt_client_t *client = NULL;
    int instance = *(int*) userdata;

    client = FindMqttClientByInstance(instance);
    if (client == NULL)
    {
        USP_LOG_Error("%s: Failed to find client instance by id %d", __FUNCTION__, instance);
        goto exit;
    }

    if (client->state == kMqttState_Running)
    {
        USP_LOG_Debug("%s: Sent MID %d", __FUNCTION__, mid);
    }
    else
    {
        USP_LOG_Warning("%s: Received publish in wrong state: %s", __FUNCTION__, mqtt_state_names[client->state]);
    }

exit:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);

}

void ReplaceTopicSlash(char* topic)
{
    int i;
    char* sep = "%2F";
    int sep_len = strlen(sep);
    int topic_len = strlen(topic);
    char new_topic[topic_len];
    memset(new_topic, 0, topic_len);
    char* ptr = new_topic;

    USP_ASSERT(topic != NULL);

    // Split the string
    str_vector_t sv;
    TEXT_UTILS_SplitString(topic, &sv, sep);

    // Check start for a sep
    if (strncmp(topic, sep, sep_len) == 0)
    {
        *ptr = '/';
        ptr++;
    }

    // Now do the middle, adding all the string together with / in between
    for (i = 0; i < sv.num_entries; i++)
    {
        strcpy(ptr, sv.vector[i]);
        ptr += strlen(sv.vector[i]);

        if (i+1 < sv.num_entries)
        {
            *ptr = '/';
            ptr++;
        }
    }


    // Now check the end, and add a / if it was there
    if (strncmp(&topic[topic_len-sep_len], sep, sep_len) == 0)
    {
        *ptr = '/';
        ptr++;
    }

    // That's the end. Just to make sure...
    *ptr = '\0';

    strcpy(topic, new_topic);
}

// Will return a non-NULL reply_to_topic if reply-to is found within topic
// Returns bool at the same time if reply_to_topic is non-null
bool FindReplyToTopic(char* topic, char* reply_to_topic)
{
    USP_ASSERT(reply_to_topic != NULL);

    const char* reply_to_string = "/reply-to=";
    char* reply_to = strstr(topic, reply_to_string);

    if (reply_to != NULL)
    {
        reply_to += strlen(reply_to_string);

        strcpy(reply_to_topic, reply_to);
        ReplaceTopicSlash(reply_to_topic);
        return true;
    }
    else
    {
        return false;
    }

}

void MessageCallback(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message)
{
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    mqtt_client_t *client = NULL;
    int instance = *(int*) userdata;

    client = FindMqttClientByInstance(instance);
    if (client == NULL)
    {
        USP_LOG_Error("%s: Failed to find client instance by id %d", __FUNCTION__, instance);
        goto exit;
    }

    if (message == NULL)
    {
        USP_LOG_Error("%s: NULL message", __FUNCTION__);
    }
    else if (!message->payloadlen)
    {
        USP_LOG_Warning("%s: Empty message on topic: %s", message->topic, __FUNCTION__);
    }
    else
    {
        USP_LOG_Info("%s: Received Message: Topic: %s Payload: %s", __FUNCTION__, message->topic, (char*)message->payload);

        if (client->state == kMqttState_Running)
        {
            // Determine if the topic contains "/reply-to="
            char reply_to_topic[strlen(message->topic)];
            memset(reply_to_topic, 0, strlen(message->topic));

            if (FindReplyToTopic(message->topic, reply_to_topic))
            {
                ReceiveMqttMessage(client, message, reply_to_topic);
            }
            else
            {
                ReceiveMqttMessage(client, message, NULL);
            }
        }
        else
        {
            USP_LOG_Warning("%s: Ignoring message received in incorrect state", __FUNCTION__);
        }
    }

exit:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);
}

void DisconnectCallback(struct mosquitto *mosq, void *userdata, int rc)
{
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    // Find client
    int instance = *(int*) userdata;
    mqtt_client_t *client = FindMqttClientByInstance(instance);

    if (client == NULL)
    {
        USP_LOG_Error("%s: Failed to find client instance", __FUNCTION__);
        goto exit;
    }


    if (rc)
    {
        if (client->state != kMqttState_ErrorRetrying)
        {
            HandleMqttError(client, kMqttFailure_OtherError, "Force disconnected from broker");
        }
    }
    else
    {
        if (client->state != kMqttState_ErrorRetrying)
        {
            MoveState(&client->state, kMqttState_Idle, "Disconnected from broker - ok");
        }
        else
        {
            USP_LOG_Debug("%s: Disconnected successfully during retry", __FUNCTION__);
        }
    }

exit:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);
}

void LogCallback(struct mosquitto *mosq, void *userdata, int level, const char *str)
{
    // Don't need a mutex as nothing is currently being accessed in the MQTT data
    // if anything is added that does, a mutex should be added here.
    switch(level)
    {
        case MOSQ_LOG_ERR:
            USP_LOG_Error("MQTT Error: %s", str);
            break;
        case MOSQ_LOG_WARNING:
            USP_LOG_Warning("MQTT Warning: %s", str);
        case MOSQ_LOG_INFO:
            USP_LOG_Info("MQTT Info: %s", str);
            break;
        case MOSQ_LOG_NOTICE:
        case MOSQ_LOG_DEBUG:
        default:
            USP_LOG_Debug("MQTT Debug: %s", str);
            break;

    }
}

//----------------------------------------------------------------------------
// Internal init functions
void InitRetry(mqtt_retry_params_t *retry)
{
    memset(retry, 0, sizeof(mqtt_retry_params_t));
}

void MQTT_InitConnParams(mqtt_conn_params_t *params)
{
    memset(params, 0, sizeof(mqtt_conn_params_t));

    params->instance = INVALID;
    params->version = kMqttProtocol_Default;

    InitRetry(&params->retry);
}

void InitSubscription(mqtt_subscription_t *sub)
{
    memset(sub, 0, sizeof(mqtt_subscription_t));
    sub->qos = kMqttQos_Default;
    sub->enabled = false;
    sub->mid = INVALID;
    sub->state = kMqttSubState_Unsubscribed;
}

void InitClient(mqtt_client_t *client, int index)
{
    int i;

    memset(client, 0, sizeof(mqtt_client_t));

    MQTT_InitConnParams(&client->conn_params);
    MQTT_InitConnParams(&client->next_params);

    client->state = kMqttState_Idle;
    client->mosq = NULL;
    client->role = ROLE_DEFAULT;
    client->scheduled_action = kScheduledAction_Off;
    client->cert_chain = NULL;
    client->verify_callback = mqtt_verify_callbacks[index];
    client->socket_fd = INVALID;
    client->allowed_controllers = NULL;
    client->ssl_ctx = DEVICE_SECURITY_CreateSSLContext(SSLv23_client_method(), SSL_VERIFY_PEER, client->verify_callback);
    ResetRetryCount(client);

    USP_ASSERT(client->ssl_ctx != NULL);

    for (i = 0; i < MAX_MQTT_SUBSCRIPTIONS; i++)
    {
        InitSubscription(&client->subscriptions[i]);
    }

    InitSubscription(&client->response_subscription);
}

void DestroyClient(mqtt_client_t *client)
{
    int i;

    MQTT_DestroyConnParams(&client->conn_params);
    MQTT_DestroyConnParams(&client->next_params);

    for (i = 0; i < MAX_MQTT_SUBSCRIPTIONS; i++)
    {
        MQTT_SubscriptionDestroy(&client->subscriptions[i]);
    }

    MQTT_SubscriptionDestroy(&client->response_subscription);

    USP_SAFE_FREE(client->allowed_controllers);
    if (client->cert_chain != NULL)
    {
        sk_X509_pop_free(client->cert_chain, X509_free);
        client->cert_chain = NULL;
    }

    if (client->mosq != NULL)
    {
        mosquitto_destroy(client->mosq);
    }

    if (client->ssl_ctx)
    {
        SSL_CTX_free(client->ssl_ctx);
    }

    memset(client, 0, sizeof(mqtt_client_t));
}

//------------------------------------------------------------------------------
// Public API functions
int MQTT_Init(void)
{
    int i;
    int err = USP_ERR_OK;
    mosquitto_lib_init();

    for (i = 0; i < MAX_MQTT_CLIENTS; i++)
    {
        InitClient(&mqtt_clients[i], i);
    }

    err = OS_UTILS_InitMutex(&mqtt_access_mutex);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: Failed to initialise MQTT mutex", __FUNCTION__);
    }
    return err;
}

void MQTT_Destroy(void)
{
    int i;

    mqtt_client_t* client = NULL;
    for (i = 0; i < MAX_MQTT_CLIENTS; i++)
    {
        client = &mqtt_clients[i];
        if (client->conn_params.instance != INVALID ||
                client->state != kMqttState_Idle)
        {
            MQTT_DisableClient(client->conn_params.instance, true);
        }

        DestroyClient(client);
    }

    memset(mqtt_clients, 0, sizeof(mqtt_clients));
    mosquitto_lib_cleanup();

}

int MQTT_Start(void)
{
    int err = USP_ERR_OK;
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    // TODO: Handle any additional setup required here

    OS_UTILS_UnlockMutex(&mqtt_access_mutex);

    return err;
}

void MQTT_Stop(void)
{
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    // TODO: Handle any additional teardown required

    OS_UTILS_UnlockMutex(&mqtt_access_mutex);

    return;
}

// Called when you already have the mqtt access mutex and a valid client
int EnableClient(mqtt_client_t* client)
{
    USP_ASSERT(client != NULL);
    client->scheduled_action = kScheduledAction_Off;

    // Add response topic as a new "subscription"
    mqtt_subscription_t resp_sub = { 0 };
    resp_sub.qos = kMqttQos_Best;
    resp_sub.enabled = true;

    resp_sub.topic = USP_STRDUP(client->conn_params.response_topic);

    MQTT_SubscriptionReplace(&client->response_subscription, &resp_sub);

    // No longer need anything from the resp_sub
    MQTT_SubscriptionDestroy(&resp_sub);


    int err = EnableMosquitto(client);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("Failed to enable client.");
    }
    else
    {
        // Start the connection!
        MoveState(&client->state, kMqttState_SendingConnect, "Starting Connection");
    }

    return err;
}

int MQTT_EnableClient(mqtt_conn_params_t *mqtt_params, mqtt_subscription_t subscriptions[MAX_MQTT_SUBSCRIPTIONS])
{
    int i;
    int err = USP_ERR_OK;
    mqtt_client_t *client = NULL;

    OS_UTILS_LockMutex(&mqtt_access_mutex);

    client = FindMqttClientByInstance(mqtt_params->instance);
    if (client == NULL)
    {
        // Look for an unused client instead
        client = FindUnusedMqttClient_Local();
    }

    if (client == NULL)
    {
        USP_LOG_Error("%s: No internal MQTT client matching Device.MQTT.Connection.%d", __FUNCTION__, mqtt_params->instance);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    client->conn_params.instance = mqtt_params->instance;
    if (client->state != kMqttState_Idle && client->state != kMqttState_ErrorRetrying)
    {
        USP_LOG_Error("%s: Unexpected state: %s for client %d. Failing connection..",
            __FUNCTION__, mqtt_state_names[client->state], client->conn_params.instance);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    ParamReplace(&client->conn_params, mqtt_params);
    for (i = 0; i < MAX_MQTT_SUBSCRIPTIONS; i++)
    {
        MQTT_SubscriptionReplace(&client->subscriptions[i], &subscriptions[i]);
    }

    ResetRetryCount(client);

    if (client->conn_params.enable)
    {
        err = EnableClient(client);
    }

exit:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);

    // Wakeup via the socket to handle the actual connect
    if (err == USP_ERR_OK)
    {
        MTP_EXEC_MqttWakeup();
    }

    return err;
}

int MQTT_DisableClient(int instance, bool purge_queued_messages)
{
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    mqtt_client_t *client = NULL;
    client = FindMqttClientByInstance(instance);
    int err = USP_ERR_GENERAL_FAILURE;

    if (!client)
    {
        goto error;
    }

    if (client->conn_params.instance != INVALID && client->state != kMqttState_Idle)
    {
        err = DisconnectClient(client);

        if (purge_queued_messages)
        {
            while(client->usp_record_send_queue.head)
            {
                PopClientUspQueue(client);
            }
        }

        MoveState(&client->state, kMqttState_Idle, "Disable Client");
        client->conn_params.instance = INVALID;
    }

    if (client->cert_chain != NULL)
    {
        sk_X509_pop_free(client->cert_chain, X509_free);
        client->cert_chain = NULL;
    }

    MQTT_DestroyConnParams(&client->conn_params);
    // Next params are required, they will be destroyed on destroy client only

error:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);

    // Wakeup via the socket
    if (err == USP_ERR_OK)
    {
        MTP_EXEC_MqttWakeup();
    }

    return err;
}

int MQTT_QueueBinaryMessage(Usp__Header__MsgType usp_msg_type, int instance, char* topic,
        unsigned char *pbuf, int pbuf_len)
{
    int err = USP_ERR_GENERAL_FAILURE;

    // Add the message to the back of the queue
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    if (is_mqtt_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&mqtt_access_mutex);
        return USP_ERR_OK;
    }

    // Find suitable client to queue on
    mqtt_client_t *client = NULL;
    client = FindMqttClientByInstance(instance);
    if (client == NULL)
    {
        USP_LOG_Error("%s: Failed to find client %d", __FUNCTION__, instance);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Find if this is a duplicate in the queue
    // May have been tried to be resent by the MTP_EXEC thread
    if (IsUspRecordInMqttQueue(client, pbuf, pbuf_len))
    {
        // No error, just return success
        err = USP_ERR_OK;
        goto exit;
    }

    mqtt_send_item_t *send_item;
    send_item = USP_MALLOC(sizeof(mqtt_send_item_t));
    send_item->usp_msg_type = usp_msg_type;

    // pbuf is our responsibility in MTP layer now
    send_item->pbuf = pbuf;
    send_item->pbuf_len = pbuf_len;

    if (topic != NULL)
    {
        send_item->topic = USP_STRDUP(topic);
    }
    else
    {
        send_item->topic = USP_STRDUP(client->conn_params.topic);
    }

    send_item->mid = INVALID;
    send_item->qos = client->conn_params.publish_qos;

    DLLIST_LinkToTail(&client->usp_record_send_queue, send_item);
    err = USP_ERR_OK;

exit:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);

    if (err == USP_ERR_OK)
    {
        MTP_EXEC_MqttWakeup();
    }

    return err;
}

void MQTT_ProcessAllSocketActivity(socket_set_t* set)
{
    int i;

    OS_UTILS_LockMutex(&mqtt_access_mutex);

    if (is_mqtt_mtp_thread_exited)
    {
        goto exit;
    }

    mqtt_client_t* client = NULL;
    for (i = 0; i < MAX_MQTT_CLIENTS; i++)
    {
        client = &mqtt_clients[i];

        if (client->conn_params.instance != INVALID)
        {
            switch(client->state)
            {
                case kMqttState_SendingConnect:
                    if (Connect(client) != USP_ERR_OK)
                    {
                        HandleMqttError(client, kMqttFailure_Connect, "Failed to connect to client");
                    }
                    else
                    {
                        MoveState(&client->state, kMqttState_AwaitingConnect, "Connect sent");
                    }
                    // fall through
                default:
                    if (client->socket_fd != INVALID)
                    {
                        // Send all data on socket - if required
                        if (SOCKET_SET_IsReadyToWrite(client->socket_fd, set) && mosquitto_want_write(client->mosq))
                        {
                            if (mosquitto_loop_write(client->mosq, 1) != MOSQ_ERR_SUCCESS)
                            {
                                USP_LOG_Error("Failed to write to socket");
                            }
                        }

                        if (SOCKET_SET_IsReadyToRead(client->socket_fd, set))
                        {
                            if (mosquitto_loop_read(client->mosq, 1) != MOSQ_ERR_SUCCESS)
                            {
                                USP_LOG_Error("Failed to read from socket");
                            }
                        }

                        if (mosquitto_loop_misc(client->mosq) != MOSQ_ERR_SUCCESS)
                        {
                            USP_LOG_Error("Failed to write misc");
                        }
                    }
                    break;
            }
        }
    }

exit:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);
}

void MQTT_UpdateAllSockSet(socket_set_t *set)
{
    int i;

    OS_UTILS_LockMutex(&mqtt_access_mutex);

    if (is_mqtt_mtp_thread_exited)
    {
        USP_LOG_Error("%s: mtp thread already exited", __FUNCTION__);
        OS_UTILS_UnlockMutex(&mqtt_access_mutex);
        return;
    }

    // Set a default timeout of 500ms
    // Makes sure we ping once per second.
    SOCKET_SET_UpdateTimeout(1*SECONDS, set);

    // Iterate over all mqtt clients currently enabled
    mqtt_client_t* client = NULL;
    for (i = 0; i < MAX_MQTT_CLIENTS; i++)
    {
        client = &mqtt_clients[i];
        if (client->conn_params.instance != INVALID)
        {
            switch (client->state)
            {
                case kMqttState_Running:
                    if (client->usp_record_send_queue.head)
                    {
                        if (SendQueueHead(client) == USP_ERR_OK)
                        {
                            PopClientUspQueue(client);
                        }
                        else
                        {
                            USP_LOG_Error("%s: Failed to send head of the queue, leaving there to try again", __FUNCTION__);
                        }
                    }
                    else if (client->scheduled_action == kScheduledAction_Activated)
                    {
                        // Responses would be sent if here
                        USP_LOG_Debug("%s: Schedule reconnect ready!", __FUNCTION__);

                        // Stop the current client
                        MQTT_DisableClient(client->next_params.instance, true /* purge - will be empty anyway*/);

                        // Copy in the next_params, so that we have the correct
                        // conn_params for the next connection
                        ParamReplace(&client->conn_params, &client->next_params);

                        // Start a connection - through the normal C API
                        EnableClient(client);
                    }
                    break;
                case kMqttState_ErrorRetrying:
                    {
                        time_t cur_time = time(NULL);
                        if (client->scheduled_action == kScheduledAction_Activated)
                        {
                            USP_LOG_Debug("%s: Scheduled reconnect in error due to reconfig.", __FUNCTION__);

                            // Use the correct configuration, and set retry to now
                            // Triggers reconnect straight away
                            ParamReplace(&client->conn_params, &client->next_params);
                            ResetRetryCount(client);
                            client->retry_time = cur_time;
                        }

                        // Retry connection - looking at the retry time
                        if (client->retry_time <= 0)
                        {
                            // failed - no retry time
                            USP_LOG_Error("%s: Retry time not set - failed", __FUNCTION__);
                            HandleMqttError(client, client->failure_code, "Retry error");
                        }
                        else if (client->retry_time - cur_time <= 0)
                        {
                            USP_LOG_Debug("%s: Retrying connection", __FUNCTION__);
                            EnableClient(client);
                        }
                        else
                        {
                            time_t diff = client->retry_time - cur_time;
                            USP_LOG_Debug("%s: Waiting for time to retry: remaining time: %lds retry_time: %ld time: %ld", __FUNCTION__, diff, client->retry_time, cur_time);
                        }
                    }
                    break;
                default:
                    // Incorrect state - nothing to do
                    break;
            }

            if (client->socket_fd >= 0)
            {
                // Add write socket if we want to write
                if (mosquitto_want_write(client->mosq))
                {
                    SOCKET_SET_AddSocketToSendTo(client->socket_fd, SECONDS, set);
                }

                // Always try to read
                SOCKET_SET_AddSocketToReceiveFrom(client->socket_fd, SECONDS, set);
            }
        }
    }

    OS_UTILS_UnlockMutex(&mqtt_access_mutex);
}

void MQTT_ScheduleReconnect(mqtt_conn_params_t *mqtt_params)
{
    mqtt_client_t *client = NULL;
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    if (is_mqtt_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&mqtt_access_mutex);
        return;
    }

    client = FindMqttClientByInstance(mqtt_params->instance);
    if (client == NULL)
    {
        goto exit;
    }

    ParamReplace(&client->next_params, mqtt_params);

    // Make sure we use the same instance
    client->next_params.instance = client->conn_params.instance;

    client->scheduled_action = kScheduledAction_Signalled;

exit:
    OS_UTILS_UnlockMutex(&mqtt_access_mutex);

    // Wakeup the MTP thread from select()
    if (client != NULL)
    {
        return MTP_EXEC_MqttWakeup();
    }

    return;
}

void MQTT_ActivateScheduledActions(void)
{
    int i;
    mqtt_client_t* client;
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    if (is_mqtt_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&mqtt_access_mutex);
        return;
    }

    for (i=0; i < MAX_MQTT_CLIENTS; i++)
    {
        client = &mqtt_clients[i];
        if (client->scheduled_action == kScheduledAction_Signalled)
        {
            client->scheduled_action = kScheduledAction_Activated;

            OS_UTILS_UnlockMutex(&mqtt_access_mutex);
            MTP_EXEC_MqttWakeup();
            return;
        }
    }

    OS_UTILS_UnlockMutex(&mqtt_access_mutex);

    return;
}

mtp_status_t MQTT_GetMtpStatus(int instance)
{
    mtp_status_t status = kMtpStatus_Error;
    mqtt_client_t *client = FindMqttClientByInstance(instance);

    if (client)
    {
        if (client->state == kMqttState_Running)
        {
            status = kMtpStatus_Up;
        }
        else if (client->state != kMqttState_ErrorRetrying)
        {
            status = kMtpStatus_Down;
        }
    }

    return status;
}

const char *MQTT_GetClientStatus(int instance)
{
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    mqtt_client_t *client = NULL;
    client = FindMqttClientByInstance(instance);
    const char *status;

    if (client)
    {
        switch (client->state)
        {
            case kMqttState_SendingConnect:
            case kMqttState_AwaitingConnect:
                status = "Connecting";
                break;
            case kMqttState_Running:
                status = "Running";
                break;
            case kMqttState_ErrorRetrying:
                {
                    switch (client->failure_code)
                    {
                        case kMqttFailure_Misconfigured:
                            status = "Error_Misconfigured";
                            break;
                        case kMqttFailure_Connect:
                            status = "Error_BrokerUnreachable";
                            break;
                        default:
                            status = "Error";
                    }
                }
                break;
            case kMqttState_Idle: // Fallthrough, for completeness
            default:
                status = "Disabled";
                break;
        }
    }
    else
    {
        status = "Disabled";
    }

    OS_UTILS_UnlockMutex(&mqtt_access_mutex);
    return status;
}

bool MQTT_AreAllResponsesSent(void)
{
    int i;
    OS_UTILS_LockMutex(&mqtt_access_mutex);

    bool responses_sent = true;
    bool all_responses_sent = true;

    // Not strictly needed - but to protect against bad calling
    if (is_mqtt_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&mqtt_access_mutex);
        return true;
    }

    mqtt_client_t *client = NULL;

    for (i = 0; i < MAX_MQTT_CLIENTS; i++)
    {
        client = &mqtt_clients[i];
        if (client->conn_params.instance != INVALID)
        {
            // Check if the queue is empty
            responses_sent = (client->usp_record_send_queue.head == NULL);
        }
        if (!responses_sent)
        {
            all_responses_sent = false;
        }
    }


    OS_UTILS_UnlockMutex(&mqtt_access_mutex);
    return all_responses_sent;
}

int MQTT_AddSubscription(int instance, mqtt_subscription_t* subscription)
{
    int err = USP_ERR_OK;
    mqtt_client_t *client = NULL;
    mqtt_subscription_t *sub_dest = NULL;

    client = FindMqttClientByInstance(instance);
    if (client == NULL)
    {
        USP_LOG_Error("%s: No internal MQTT client matching Device.MQTT.Client.%d", __FUNCTION__, instance);
        err = USP_ERR_INTERNAL_ERROR;
        return err;
    }

    sub_dest = FindMqttSubscriptionByInstance(instance, subscription->instance);
    if (sub_dest == NULL)
    {
        // Find an invalid subscription, if can't find the current instance.
        USP_LOG_Debug("%s: Using an empty subscription", __FUNCTION__);
        sub_dest = FindMqttSubscriptionByInstance(instance, INVALID);
    }

    if (sub_dest == NULL)
    {
        USP_LOG_Error("%s: No internal MQTT client subscription remaining for %d", __FUNCTION__, subscription->instance);
        err = USP_ERR_INTERNAL_ERROR;
        return err;
    }

    // Replace the subsription destination with the new subscription
    MQTT_SubscriptionReplace(sub_dest, subscription);

    if (sub_dest->enabled == true && sub_dest->instance != INVALID)
    {
        if (sub_dest->topic == NULL)
        {
            USP_LOG_Error("%s: Topic is invalid", __FUNCTION__);
            return err;
        }
        if (Subscribe(client, sub_dest) != USP_ERR_OK)
        {
            err = USP_ERR_INTERNAL_ERROR;
        }
    }

    // Let the DM know we're ready for sending messages
    DM_EXEC_PostMqttHandshakeComplete(client->conn_params.instance, client->role, client->allowed_controllers);

    return err;
}

int MQTT_DeleteSubscription(int instance, int subinstance)
{
    int err = USP_ERR_OK;
    mqtt_client_t *client = NULL;
    mqtt_subscription_t *sub = NULL;

    client = FindMqttClientByInstance(instance);

    if (client == NULL)
    {
        USP_LOG_Error("%s: No internal MQTT client matching Device.MQTT.Client.%d", __FUNCTION__, instance);
        err = USP_ERR_INTERNAL_ERROR;
        return err;
    }

    sub = FindMqttSubscriptionByInstance(instance, subinstance);

    if (sub == NULL)
    {
        USP_LOG_Error("%s: No internal MQTT subscription matching Device.MQTT.Client.%d.Subscription.%d",
                      __FUNCTION__, instance, subinstance);
        err = USP_ERR_INTERNAL_ERROR;
        return err;
    }

    if (sub->instance != INVALID)
    {
        if (sub->enabled)
        {
            if (Unsubscribe(client, sub) != USP_ERR_OK)
            {
                err = USP_ERR_INTERNAL_ERROR;
            }
        }
        sub->instance = INVALID;
    }

    return err;
}

int MQTT_ScheduleResubscription(int instance, mqtt_subscription_t *subscription)
{
    int err = USP_ERR_INTERNAL_ERROR;
    mqtt_client_t *client = NULL;
    mqtt_subscription_t *sub = NULL;

    client = FindMqttClientByInstance(instance);
    if (client == NULL)
    {
        USP_LOG_Error("%s: No internal MQTT client matching Device.MQTT.Connection.%d", __FUNCTION__, instance);
        err = USP_ERR_INTERNAL_ERROR;
        return err;
    }

    sub = FindMqttSubscriptionByInstance(instance, subscription->instance);
    if (sub == NULL)
    {
        USP_LOG_Error("%s: No internal MQTT client subscription matching %d", __FUNCTION__, subscription->instance);
        err = USP_ERR_INTERNAL_ERROR;
        return err;
    }

    MQTT_SubscriptionReplace(sub, subscription);

    //unsubscribe & subscribe the  topic
    if (sub->instance != INVALID)
    {
        if (sub->topic == NULL)
        {
            USP_LOG_Error("%s: Topic is invalid", __FUNCTION__);
            return err;
        }

        int version = client->conn_params.version;

        if (sub->enabled)
        {
            //set state to resubscribe. This will subscribe on unsubscribe callback.
            sub->state = kMqttSubState_Resubscribing;
        }
        else
        {
            // Disabled, so do not subscribe again in unsubscribe callback.
            sub->state = kMqttSubState_Unsubscribing;
        }

        USP_LOG_Debug("%s: Sending unsub before sub to %s %d %d %d", __FUNCTION__,
                sub->topic, sub->mid, sub->qos, sub->state);

        if (version == kMqttProtocol_5_0)
        {
            err = UnsubscribeV5(client, sub);
        }
        else
        {
            if (mosquitto_unsubscribe(client->mosq, &sub->mid, sub->topic) != MOSQ_ERR_SUCCESS)
            {
                USP_LOG_Error("Failed to unsubscribe from %s", sub->topic);
                err = USP_ERR_INTERNAL_ERROR;
            }
        }
    }

    return err;
}

#endif
