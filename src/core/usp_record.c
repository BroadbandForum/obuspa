/*
 *
 * Copyright (C) 2022, Broadband Forum
 * Copyright (C) 2022, Snom Technology GmbH
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
 * \file usp_record.c
 *
 * Functions to dynamically create and populate a USP Record of Connect or
 * Disconnect type.
 *
 */
#include "usp_record.h"

#include "msg_handler.h"  // For AGENT_CURRENT_PROTOCOL_VERSION

/*********************************************************************//**
**
** USPREC_WebSocketConnect_Create
**
** Dynamically creates an USP Record of WebSocketConnect type.
** NOTE: The generic fields of the USP Record must be filled by the caller.
** NOTE: USP_STRDUP() must be used when filling the USP Record string/bytes fields by the caller.
** NOTE: The object should be deleted using usp_record__record__free_unpacked()
**
** \param   Mone
**
** \return  Pointer to a UspRecord__Record object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
UspRecord__Record *USPREC_WebSocketConnect_Create(void)
{
    UspRecord__WebSocketConnectRecord *ws;
    UspRecord__Record *rec;

    // Allocate memory to store the USP Record
    rec = USP_MALLOC(sizeof(UspRecord__Record));
    ws = USP_MALLOC(sizeof(UspRecord__WebSocketConnectRecord));

    // Fill in the WebSocket Connect Record structure
    usp_record__web_socket_connect_record__init(ws);

    // Fill in the USP Record structure
    usp_record__record__init(rec);
    rec->version = USP_STRDUP(AGENT_CURRENT_PROTOCOL_VERSION);
    rec->payload_security = USP_RECORD__RECORD__PAYLOAD_SECURITY__PLAINTEXT;
    rec->record_type_case = USP_RECORD__RECORD__RECORD_TYPE_WEBSOCKET_CONNECT;
    rec->websocket_connect = ws;

    return rec;
}

/*********************************************************************//**
**
** USPREC_MqttConnect_Create
**
** Dynamically creates an USP Record of MQTTConnect type.
** NOTE: The generic fields of the USP Record must be filled by the caller.
** NOTE: USP_STRDUP() must be used when filling the USP Record string/bytes fields by the caller.
** NOTE: The object should be deleted using usp_record__record__free_unpacked()
**
** \param   version - MQTT protocol version
** \param   topic - topic subscribed to.
**
** \return  Pointer to a UspRecord__Record object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
UspRecord__Record *USPREC_MqttConnect_Create(mqtt_protocolver_t version, char* topic)
{
    UspRecord__MQTTConnectRecord *mqtt;
    UspRecord__Record *rec;

    // Allocate memory to store the USP Record
    rec = USP_MALLOC(sizeof(UspRecord__Record));
    mqtt = USP_MALLOC(sizeof(UspRecord__MQTTConnectRecord));

    // Fill in the MQTT Connect Record structure
    usp_record__mqttconnect_record__init(mqtt);
    mqtt->subscribed_topic = USP_STRDUP(topic);

    switch (version)
    {
        case kMqttProtocol_5_0:
            mqtt->version = USP_RECORD__MQTTCONNECT_RECORD__MQTTVERSION__V5;
            break;

        case kMqttProtocol_3_1_1:
        case kMqttProtocol_3_1:
            mqtt->version = USP_RECORD__MQTTCONNECT_RECORD__MQTTVERSION__V3_1_1;
            break;

        default:
            TERMINATE_BAD_CASE(version);
            break;
    }

    // Fill in the USP Record structure
    usp_record__record__init(rec);
    rec->version = USP_STRDUP(AGENT_CURRENT_PROTOCOL_VERSION);
    rec->payload_security = USP_RECORD__RECORD__PAYLOAD_SECURITY__PLAINTEXT;
    rec->record_type_case = USP_RECORD__RECORD__RECORD_TYPE_MQTT_CONNECT;
    rec->mqtt_connect = mqtt;

    return rec;
}

/*********************************************************************//**
**
** USPREC_StompConnect_Create
**
** Dynamically creates an USP Record of STOMPConnect type.
** NOTE: The generic fields of the USP Record must be filled by the caller.
** NOTE: USP_STRDUP() must be used when filling the USP Record string/bytes fields by the caller.
** NOTE: The object should be deleted using usp_record__record__free_unpacked()
**
** \param   destination - destination subscribed to.
**
** \return  Pointer to a UspRecord__Record object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
UspRecord__Record *USPREC_StompConnect_Create(char* destination)
{
    UspRecord__STOMPConnectRecord *stomp;
    UspRecord__Record *rec;

    // Allocate memory to store the USP Record
    rec = USP_MALLOC(sizeof(UspRecord__Record));
    stomp = USP_MALLOC(sizeof(UspRecord__STOMPConnectRecord));

    // Fill in the STOMP Connect Record structure
    usp_record__stompconnect_record__init(stomp);
    stomp->subscribed_destination = USP_STRDUP(destination);
    stomp->version = USP_RECORD__STOMPCONNECT_RECORD__STOMPVERSION__V1_2;  // Hardcoded to v1.2, the only supported version

    // Fill in the USP Record structure
    usp_record__record__init(rec);
    rec->version = USP_STRDUP(AGENT_CURRENT_PROTOCOL_VERSION);
    rec->payload_security = USP_RECORD__RECORD__PAYLOAD_SECURITY__PLAINTEXT;
    rec->record_type_case = USP_RECORD__RECORD__RECORD_TYPE_STOMP_CONNECT;
    rec->stomp_connect = stomp;

    return rec;
}

/*********************************************************************//**
**
** USPREC_Disconnect_Create
**
** Dynamically creates an USP Record of DisconnectRecord type.
** NOTE: The generic fields of the USP Record must be filled by the caller.
** NOTE: USP_STRDUP() must be used when filling the USP Record string/bytes fields by the caller.
** NOTE: The object should be deleted using usp_record__record__free_unpacked()
**
** \param   reason_code - code of the message number to be printed in the Disconnect record
** \param   reason_str - pointer to the message to be printed in the Disconnect record.
**                       If NULL, the message related to reason_code is used instead.
**
** \return  Pointer to a UspRecord__Record object
**          NOTE: If out of memory, USP Agent is terminated
**
**************************************************************************/
UspRecord__Record *USPREC_Disconnect_Create(uint32_t reason_code, char* reason_str)
{
    UspRecord__DisconnectRecord *disc;
    UspRecord__Record *rec;

    // Allocate memory to store the USP Record
    rec = USP_MALLOC(sizeof(UspRecord__Record));
    disc = USP_MALLOC(sizeof(UspRecord__DisconnectRecord));

    // Fill in the Disconnect Record structure
    usp_record__disconnect_record__init(disc);
    disc->reason = USP_STRDUP(reason_str);
    disc->reason_code = reason_code;

    // Fill in the USP Record structure
    usp_record__record__init(rec);
    rec->version = USP_STRDUP(AGENT_CURRENT_PROTOCOL_VERSION);
    rec->payload_security = USP_RECORD__RECORD__PAYLOAD_SECURITY__PLAINTEXT;
    rec->record_type_case = USP_RECORD__RECORD__RECORD_TYPE_DISCONNECT;
    rec->disconnect = disc;

    return rec;
}
