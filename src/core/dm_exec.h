/*
 *
 * Copyright (C) 2019-2025, Broadband Forum
 * Copyright (C) 2024-2025, Vantiva Technologies SAS
 * Copyright (C) 2016-2024  CommScope, Inc
 * Copyright (C) 2020, BT PLC
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
 * \file dm_exec.h
 *
 * Header file for Main execution loop of data model thread
 *
 */
#ifndef DM_EXEC_H
#define DM_EXEC_H

#include "vendor_defs.h"  // For E2ESESSION_EXPERIMENTAL_USP_V_1_2

#if defined(E2ESESSION_EXPERIMENTAL_USP_V_1_2)
#include "e2e_defs.h"
#endif

#include "device.h"
#include "uds.h"

//------------------------------------------------------------------------------
// Bitmask indicating which thread exited to DM_EXEC_PostMtpThreadExited()
#define STOMP_EXITED    0x00000001
#define COAP_EXITED     0x00000002
#define MQTT_EXITED     0x00000004
#define BDC_EXITED      0x00000008
#define WSCLIENT_EXITED 0x00000010
#define WSSERVER_EXITED 0x00000020
#define UDS_EXITED      0x00000040

//------------------------------------------------------------------------------
// Define for endpoint_id argument of DM_EXEC_PostUspRecord()
#define UNKNOWN_ENDPOINT_ID  NULL

//------------------------------------------------------------------------------
// API functions
int DM_EXEC_Init(void);
void DM_EXEC_Destroy(void);
void DM_EXEC_PostUspRecord(unsigned char *pbuf, int pbuf_len, char *originator, int role_instance, mtp_conn_t *mtpc);
void DM_EXEC_CopyMTPConnection(mtp_conn_t *dst, mtp_conn_t *src);
void DM_EXEC_FreeMTPConnection(mtp_conn_t *mtpc);
void DM_EXEC_PostStompHandshakeComplete(int stomp_instance, char *agent_queue, int role_instance);
void DM_EXEC_PostMqttHandshakeComplete(int mqtt_instance, mqtt_protocolver_t version, char *client_id, int role_instance);
#ifdef ENABLE_WEBSOCKETS
void DM_EXEC_PostWebsockHandshakeComplete(int cont_instance, int role_instance);
#endif
#ifdef ENABLE_UDS
void DM_EXEC_PostUdsHandshakeComplete(char *endpoint_id, uds_path_t path_type, unsigned conn_id);
void DM_EXEC_PostUdsDisconnected(char *endpoint_id, uds_path_t path_type);
#endif
void DM_EXEC_PostMtpThreadExited(unsigned flags);
int DM_EXEC_NotifyBdcTransferResult(int profile_id, bdc_transfer_result_t transfer_result);
#if defined(E2ESESSION_EXPERIMENTAL_USP_V_1_2)
int DM_EXEC_PostE2eEvent(e2e_event_t event, int request_instance, int controller_instance);
#endif
void DM_EXEC_HandleScheduledExit(void);
bool DM_EXEC_IsNotificationsEnabled(void);
void *DM_EXEC_Main(void *args);
#ifndef REMOVE_USP_BROKER
Usp__Msg *DM_EXEC_SendRequestAndWaitForResponse(char *endpoint_id, Usp__Msg *req, mtp_conn_t *mtpc,
                                                Usp__Header__MsgType header_type, int timeout);
#endif
//------------------------------------------------------------------------------

#endif
