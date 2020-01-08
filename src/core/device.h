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
 * \file device.h
 *
 * Header file containing the APIs for the Data model implementation components
 *
 */
#ifndef DEVICE_H
#define DEVICE_H

#include <openssl/ssl.h>
#include <curl/curl.h>

#include "kv_vector.h"
#include "usp_api.h"
#include "subs_vector.h"
#include "mtp_exec.h"
#include "subs_vector.h"
#include "usp-msg.pb-c.h"

//------------------------------------------------------------------------------
// Enumeration of what to do when USP Agent exits gracefully (ie after all USP responses have been sent)
typedef enum
{
    kExitAction_Exit,
    kExitAction_Reboot,
    kExitAction_FactoryReset
} exit_action_t;

//------------------------------------------------------------------------------
// Combined controller trust role consisting of inherited and assigned role
typedef struct
{
    ctrust_role_t inherited;
    ctrust_role_t assigned;
} combined_role_t;

#define INTERNAL_ROLE             NULL   // Role used internally by Data Model. This always permits all operations (Even at bootup, when the permissions table has not been seeded yet)

//------------------------------------------------------------------------------
// Structure containing cause of last boot cycle
typedef struct
{
    char *cause;                     // cause of the last reboot
    char *command_key;               // command_key associated with the last reboot
    char *cur_software_version;      // Current software version that is running
    char *last_software_version;     // Software version before the current boot period
    int request_instance;            // Instance number of the request that initiated the reboot, or INVALID if reboot was not initiated by an operation
    bool is_firmware_updated;       // whether the last reboot caused a different firmware image to run
} reboot_info_t;

//------------------------------------------------------------------------------
// Structure specifying the destination that a response to a USP message must be sent
typedef struct
{
    bool is_reply_to_specified; // Set if reply_to was specified in the received MTP frame
    mtp_protocol_t protocol;    // Protocol on which the USP message was received

    // Following member variables only set if reply_to was specified and USP message was received over STOMP
    char *stomp_dest;
    int stomp_instance;
    char *stomp_err_id;         // if the USP record or USP message are formed incorrectly, this is used to identify the STOMP frame that was in error to the controller

    // Following member variables only set if reply_to was specified and USP message was received over CoAP
    char *coap_host;                    // Percent encoded hostname
    int coap_port;
    char *coap_resource;                // Percent encoded resource name
    bool coap_encryption;
    bool coap_reset_session_hint;       // Set if an existing DTLS session with this host should be reset. 
                                        // If we know that the USP request came in on a new DTLS session, then it is likely 
                                        // that the USP response must be sent back on a new DTLS session also. Wihout this, 
                                        // the CoAP retry mechanism will cause the DTLS session to restart, but it is a while
                                        // before the retry is triggered, so this hint speeds up communications
} mtp_reply_to_t;

//------------------------------------------------------------------------------
// Typedef for SSL verify callback
typedef int ssl_verify_callback_t(int preverify_ok, X509_STORE_CTX *x509_ctx);

//------------------------------------------------------------------------------
// Data model components API
int DEVICE_TIME_Init(void);
int DEVICE_TIME_Start(void);
int DEVICE_LOCAL_AGENT_Init(void);
int DEVICE_LOCAL_AGENT_SetDefaults(void);
int DEVICE_LOCAL_AGENT_Start(void);
int DEVICE_LOCAL_AGENT_ScheduleReboot(exit_action_t exit_action, char *reboot_cause, char *command_key, int request_instance);
exit_action_t DEVICE_LOCAL_AGENT_GetExitAction(void);
int DEVICE_LOCAL_AGENT_SetDefaultRebootCause(void);
char *DEVICE_LOCAL_AGENT_GetEndpointID(void);
void DEVICE_LOCAL_AGENT_GetRebootInfo(reboot_info_t *info);
bool DEVICE_LOCAL_AGENT_GetDualStackPreference(void);
void DEVICE_LOCAL_AGENT_Stop(void);
int DEVICE_CONTROLLER_Init(void);
int DEVICE_CONTROLLER_Start(void);
void DEVICE_CONTROLLER_Stop(void);
int DEVICE_CONTROLLER_FindInstanceByEndpointId(char *endpoint_id);
int DEVICE_CONTROLLER_QueueBinaryMessage(Usp__Header__MsgType usp_msg_type, char *endpoint_id, unsigned char *pbuf, int pbuf_len, char *usp_msg_id, mtp_reply_to_t *mtp_reply_to, time_t expiry_time);
char *DEVICE_CONTROLLER_FindEndpointIdByInstance(int instance);
int DEVICE_CONTROLLER_GetCombinedRole(int instance, combined_role_t *combined_role);
int DEVICE_CONTROLLER_GetCombinedRoleByEndpointId(char *endpoint_id, combined_role_t *combined_role);
void DEVICE_CONTROLLER_SetRolesFromStomp(int stomp_instance, ctrust_role_t role, char *allowed_controllers);
int DEVICE_CONTROLLER_GetSubsRetryParams(char *endpoint_id, unsigned *min_wait_interval, unsigned *interval_multiplier);
void DEVICE_CONTROLLER_NotifyStompConnDeleted(int stomp_instance);
int DEVICE_MTP_Init(void);
int DEVICE_MTP_Start(void);
void DEVICE_MTP_Stop(void);
char *DEVICE_MTP_EnumToString(mtp_protocol_t protocol);
int DEVICE_MTP_ValidateStompReference(dm_req_t *req, char *value);
int DEVICE_MTP_GetStompReference(char *path, int *stomp_reference_instance);
char *DEVICE_MTP_GetAgentStompQueue(int instance);
void DEVICE_MTP_NotifyStompConnDeleted(int stomp_instance);
int DEVICE_STOMP_Init(void);
int DEVICE_STOMP_Start(void);
void DEVICE_STOMP_Stop(void);
int DEVICE_STOMP_StartAllConnections(void);
int DEVICE_STOMP_QueueBinaryMessage(Usp__Header__MsgType usp_msg_type, int instance, char *controller_queue, char *agent_queue, unsigned char *pbuf, int pbuf_len, char *err_id_header, time_t expiry_time);
void DEVICE_STOMP_ScheduleReconnect(int instance);
mtp_status_t DEVICE_STOMP_GetMtpStatus(int instance);
int DEVICE_STOMP_CountEnabledConnections(void);
void DEVICE_STOMP_GetDestinationFromServer(int instance, char *buf, int len);
int DEVICE_SUBSCRIPTION_Init(void);
int DEVICE_SUBSCRIPTION_Start(void);
void DEVICE_SUBSCRIPTION_Stop(void);
void DEVICE_SUBSCRIPTION_Update(int id);
void DEVICE_SUBSCRIPTION_ProcessAllOperationCompleteSubscriptions(char *command, char *command_key, int err_code, char *err_msg, kv_vector_t *output_args);
void DEVICE_SUBSCRIPTION_ResolveObjectDeletionPaths(void);
void DEVICE_SUBSCRIPTION_NotifyObjectLifeEvent(char *obj_path, subs_notify_t notify_type);
void DEVICE_SUBSCRIPTION_ProcessAllObjectLifeEventSubscriptions(void);
void DEVICE_SUBSCRIPTION_ProcessAllEventCompleteSubscriptions(char *event_name, kv_vector_t *output_args);
void DEVICE_SUBSCRIPTION_SendPeriodicEvent(int cont_instance);
void DEVICE_SUBSCRIPTION_Dump(void);
int DEVICE_SECURITY_Init(void);
int DEVICE_SECURITY_Start(void);
void DEVICE_SECURITY_Stop(void);
int DEVICE_SECURITY_GetControllerTrust(STACK_OF(X509) *cert_chain, ctrust_role_t *role, char **allowed_controllers);
bool DEVICE_SECURITY_IsClientCertAvailable(void);
SSL_CTX *DEVICE_SECURITY_CreateSSLContext(const SSL_METHOD *method, int verify_mode, ssl_verify_callback_t verify_callback);
int DEVICE_SECURITY_LoadTrustStore(SSL_CTX *ssl_ctx, int verify_mode, ssl_verify_callback_t verify_callback);
void DEVICE_SECURITY_GetClientCertStatus(bool *available, bool *matches_endpoint);
int DEVICE_SECURITY_TrustCertVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);
int DEVICE_SECURITY_BulkDataTrustCertVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);
int DEVICE_CTRUST_Init(void);
int DEVICE_CTRUST_Start(void);
void DEVICE_CTRUST_Stop(void);
int DEVICE_CTRUST_AddCertRole(int cert_instance, ctrust_role_t role);
ctrust_role_t DEVICE_CTRUST_GetCertRole(int cert_instance);
int DEVICE_CTRUST_GetInstanceFromRole(ctrust_role_t role);
ctrust_role_t DEVICE_CTRUST_GetRoleFromInstance(int instance);
int DEVICE_CTRUST_AddPermissions(ctrust_role_t role, char *path, unsigned short permission_bitmask);
void DEVICE_CTRUST_RegisterRoleName(ctrust_role_t role, char *name);
int DEVICE_REQUEST_Init(void);
int DEVICE_REQUEST_Add(char *path, char *command_key, int *instance);
void DEVICE_REQUEST_OperationComplete(int instance, int err_code, char *err_msg, kv_vector_t *output_args);
void DEVICE_REQUEST_UpdateOperationStatus(int instance, char *status);
int DEVICE_REQUEST_RestartAsyncOperations(void);
int DEVICE_REQUEST_PersistOperationArgs(int instance, kv_vector_t *args, char *prefix);
int DEVICE_BULKDATA_Init(void);
int DEVICE_BULKDATA_Start(void);
void DEVICE_BULKDATA_Stop(void);
void DEVICE_BULKDATA_NotifyTransferResult(int profile_id, bdc_transfer_result_t transfer_result);
#ifndef REMOVE_SELF_TEST_DIAG_EXAMPLE
int DEVICE_SELF_TEST_Init(void);
#endif

//------------------------------------------------------------------------------
// Tables used to convert to/from an enumeration to/from a string
extern const enum_entry_t mtp_protocols[kMtpProtocol_Max];

extern const enum_entry_t notify_types[kSubNotifyType_Max];
//------------------------------------------------------------------------------
// Pointers to strings containing paths in the data model
extern char *device_req_root;

//-----------------------------------------------------------------------------------------------
// Global variables set by command line
extern char *auth_cert_file;
extern char *usp_trust_store_file;

//-----------------------------------------------------------------------------------------------
/*
 *  The maximum number of UDP Echo results that the platform will save
 *  This needs to be limited, because typically UDP echo will be run many thousands of times
 *  and there isn't enough memory to store all results.
 */
#define UDP_ECHO_MAX_RESULTS 25

#endif

