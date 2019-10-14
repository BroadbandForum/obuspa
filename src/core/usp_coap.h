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
 * \file usp_coap.h
 *
 * Header file for CoAP connection
 *
 */
#ifndef USP_COAP_H
#define USP_COAP_H

#ifdef ENABLE_COAP

#include "socket_set.h"
#include "usp-msg.pb-c.h"

//------------------------------------------------------------------------------
// Structure containing CoAP configuration parameters
typedef struct
{
    unsigned port;                  // port on which this agent listens for CoAP messages
    char *resource;                 // CoAP resource path representing this agent's USP handler
    bool enable_encryption;         // Whether connections to this port are encrypted
} coap_config_t;

//------------------------------------------------------------------------------
// API
int COAP_Init(void);
int COAP_Start(void);
void COAP_Destroy(void);
int COAP_StartServer(int instance, char *interface, coap_config_t *config);
int COAP_StopServer(int instance, char *interface, coap_config_t *unused);
mtp_status_t COAP_GetServerStatus(int instance);
int COAP_StartClient(int cont_instance, int mtp_instance, char *endpoint_id);
void COAP_StopClient(int cont_instance, int mtp_instance);
void COAP_UpdateAllSockSet(socket_set_t *set);
void COAP_ProcessAllSocketActivity(socket_set_t *set);
int COAP_QueueBinaryMessage(Usp__Header__MsgType usp_msg_type, int cont_instance, int mtp_instance, unsigned char *pbuf, int pbuf_len, mtp_reply_to_t *mrt);
bool COAP_AreAllResponsesSent(void);

#endif // ENABLE_COAP
#endif

