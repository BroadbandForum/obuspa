/*
 *
 * Copyright (C) 2019-2021, Broadband Forum
 * Copyright (C) 2016-2021  CommScope, Inc
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
 * \file msg_handler.h
 *
 * Header file for API to the USP message handler
 *
 */
#ifndef MSG_HANDLER_H
#define MSG_HANDLER_H

#include "usp-msg.pb-c.h"
#include "kv_vector.h"
#include "mtp_exec.h"
#include "vendor_defs.h"
#include "device.h"

//--------------------------------------------------------------------
// Agent supported protocol versions
#define AGENT_SUPPORTED_PROTOCOL_VERSIONS "1.0,1.1"
#define AGENT_CURRENT_PROTOCOL_VERSION    "1.1"

//------------------------------------------------------------------------------
// Typedef for callback function, used to extract paramerror fields from a response message, in order to put it in an error message
typedef int (*paramerror_extractor_t)(Usp__Msg *src_msg, Usp__Msg *err_msg);

//------------------------------------------------------------------------------
// API functions
int MSG_HANDLER_HandleBinaryRecord(unsigned char *pbuf, int pbuf_len, ctrust_role_t role, mtp_reply_to_t *mrt);
int MSG_HANDLER_HandleBinaryMessage(unsigned char *pbuf, int pbuf_len, ctrust_role_t role, char *controller_endpoint, mtp_reply_to_t *mrt);
void MSG_HANDLER_LogMessageToSend(mtp_send_item_t *msi, mtp_protocol_t protocol, char *host, unsigned char *stomp_header);
int MSG_HANDLER_QueueMessage(char *endpoint_id, Usp__Msg *usp, mtp_reply_to_t *mrt);
int MSG_HANDLER_QueueUspRecord(usp_send_item_t *usi, char *endpoint_id, char *usp_msg_id, mtp_reply_to_t *mrt, time_t expiry_time);
int MSG_HANDLER_GetMsgControllerInstance(void);
void MSG_HANDLER_GetMsgRole(combined_role_t *combined_role);
void MSG_HANDLER_GetControllerInfo(controller_info_t *controller_info);
char *MSG_HANDLER_GetMsgControllerEndpointId(void);

// Parse message received and handle response
void MSG_HANDLER_HandleGet(Usp__Msg *usp, char *controller_endpoint, mtp_reply_to_t *mrt);
void MSG_HANDLER_HandleSet(Usp__Msg *usp, char *controller_endpoint, mtp_reply_to_t *mrt);
void MSG_HANDLER_HandleAdd(Usp__Msg *usp, char *controller_endpoint, mtp_reply_to_t *mrt);
void MSG_HANDLER_HandleDelete(Usp__Msg *usp, char *controller_endpoint, mtp_reply_to_t *mrt);
void MSG_HANDLER_HandleOperate(Usp__Msg *usp, char *controller_endpoint, mtp_reply_to_t *mrt);
void MSG_HANDLER_HandleGetSupportedProtocol(Usp__Msg *usp, char *controller_endpoint, mtp_reply_to_t *mrt);
void MSG_HANDLER_HandleGetInstances(Usp__Msg *usp, char *controller_endpoint, mtp_reply_to_t *mrt);
void MSG_HANDLER_HandleGetSupportedDM(Usp__Msg *usp, char *controller_endpoint, mtp_reply_to_t *mrt);
void MSG_HANDLER_HandleUnknownMsgType(Usp__Msg *usp, char *controller_endpoint, mtp_reply_to_t *mrt);
char *MSG_HANDLER_UspMsgTypeToString(int msg_type);

// Error response
Usp__Msg *ERROR_RESP_CreateSingle(char *msg_id, int err_code, Usp__Msg *src_msg, paramerror_extractor_t paramerror_extractor);
Usp__Msg *ERROR_RESP_Create(char *msg_id, int err_code, char *err_msg);
Usp__Error__ParamError *ERROR_RESP_AddParamError(Usp__Msg *resp, char *path, int err_code, char *err_msg);
int ERROR_RESP_CalcOuterErrCode(int count, int err);

// Subscriptions request/response
Usp__Msg *MSG_HANDLER_CreateNotifyReq_ValueChange(char *path, char *value, char *subscription_id, bool send_resp);
void MSG_HANDLER_HandleNotifyResp(Usp__Msg *usp, char *controller_endpoint, mtp_reply_to_t *mrt);
Usp__Msg *MSG_HANDLER_CreateEvent_Boot(kv_vector_t *param_values, char *dest_endpoint, char *subscription_id, bool send_resp);
Usp__Msg *MSG_HANDLER_CreateNotifyReq_ObjectCreation(char *obj_path, char *subscription_id, bool send_resp);
Usp__Msg *MSG_HANDLER_CreateNotifyReq_ObjectDeletion(char *obj_path, char *subscription_id, bool send_resp);
Usp__Msg *MSG_HANDLER_CreateNotifyReq_OperCompleteSuccess(kv_vector_t *output_args, char *command, char *command_key,
                                                          char *subscription_id, bool send_resp);
Usp__Msg *MSG_HANDLER_CreateNotifyReq_OperCompleteFailure(int err_code, char *err_msg, char *command, char *command_key,
                                                          char *subscription_id, bool send_resp);
Usp__Msg *MSG_HANDLER_CreateNotifyReq_Event(char *event_name, kv_vector_t *param_values, char *subscription_id, bool send_resp);
Usp__Msg *MSG_HANDLER_CreateNotifyReq_OnBoard(char* oui, char* product_class, char* serial_number, bool send_resp);

#endif

