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
 * \file usp_api.h
 *
 * Header file containing the API functions provided by USP Agent core that may be called by a vendor
 *
 */
#ifndef USP_API_H
#define USP_API_H

#include <time.h>
#include <openssl/ssl.h>
#include <stdbool.h>

//-----------------------------------------------------------------------------------------
// Key-value pair type
typedef struct
{
    char *key;
    char *value;
} kv_pair_t;

//-----------------------------------------------------------------------------------------
// Key-value pair vector type
typedef struct
{
    kv_pair_t *vector;
    int num_entries;
} kv_vector_t;

//-----------------------------------------------------------------------------------------
// Fixed-sized vector containing instance numbers
typedef struct
{
    short vector[MAX_DM_INSTANCES];
    int num_entries;
} int_vector_t;

//-------------------------------------------------------------------------
// Enumeration of expression operators
typedef enum
{
    kExprOp_Equal = 0,              // '=='
    kExprOp_NotEqual,               // '!='
    kExprOp_LessThanOrEqual,        // '<='
    kExprOp_GreaterThanOrEqual,     // '>='
    kExprOp_LessThan,               // '<'
    kExprOp_GreaterThan,            // '>'
    kExprOp_Equals,                 // '='

    kExprOp_Max
} expr_op_t;

//-------------------------------------------------------------------------
// Union containing the native value for a parameter in a Get or Set ParameterValue operation
// NOTE: Strings are not transferred by this union, instead, they are transferred using the buf parameter of the vendor hook
typedef union
{
    time_t value_datetime;
    bool value_bool;
    int value_int;
    unsigned value_uint;
    unsigned long long value_ulong;
} dm_val_union_t;

//-------------------------------------------------------------------------
// Structures passed to vendor hooks identifying the data model path
typedef struct
{
    // NOTE: Do not change the order of variables in this structure. They must match dm_instances_t
    int order;    // Number of instance numbers in this array, and hence number of instance separators in the path
    int instances[MAX_DM_INSTANCE_ORDER];
} dm_req_instances_t;

typedef struct
{
    char *path;         // Pointer to full path of the specific parameter or object
    char *schema_path;  // Pointer to schema path of the parameter of object
    dm_req_instances_t *inst;   // Pointer to instances information for the parameter or object
    dm_val_union_t val_union;   // When performing a Set Parameter Value, stores the new value converted to it's native type
} dm_req_t;

//------------------------------------------------------------------------------
// Last cause of STOMP connection failure
typedef enum
{
    kStompFailure_None,                     // No failure. Connection may have been disabled/re-enabled, or connection params changed, or Agent's IP address changed, or Agent switched connection interface
    kStompFailure_ServerDNS,                // Failed to resolve the hostname
    kStompFailure_Authentication,           // Authentication with STOMP server failed (either password or SSL handshake failed).
    kStompFailure_Connect,                  // Failed to connect or network unreachable (CPE has no WAN IP address)
    kStompFailure_ReadWrite,                // Failed whilst sending/receiving
    kStompFailure_Timeout,                  // Failed due to STOMP handshake or server heartbeat timeout
    kStompFailure_Misconfigured,            // Agent or controller queue name not setup, or entry disabled
    kStompFailure_OtherError                // STOMP protocol error or internal error
} stomp_failure_t;

//------------------------------------------------------------------------------
// Enumeration for result of a BulkData Collection HTTP Post
typedef enum
{
    kBDCTransferResult_Success,
    kBDCTransferResult_Failure_DNS,         // DNS failed to lookup the BDC server
    kBDCTransferResult_Failure_Auth,        // Authentication failure - either password or SSL
    kBDCTransferResult_Failure_Connect,     // Failed to connect to the BDC server or network unreachable (CPE has no WAN IP address)
    kBDCTransferResult_Failure_ReadWrite,   // Failed whilst reading or writing to the BDC server
    kBDCTransferResult_Failure_Timeout,     // Timeout waiting for response from BDC server
    kBDCTransferResult_Failure_Other        // Other failures - typically protocol errors or unsuccessful HTTP response codes returned
} bdc_transfer_result_t;

//------------------------------------------------------------------------------------
// Convenience defines which alias variables within the dm_req_t structure
// to make vendor hook code easier to read (if a little more obscure)
// NOTE: By convention, these should only be used in Vendor Hooks
#define inst1   (req->inst->instances[0])
#define inst2   (req->inst->instances[1])
#define inst3   (req->inst->instances[2])
#define inst4   (req->inst->instances[3])
#define inst5   (req->inst->instances[4])
#define inst6   (req->inst->instances[5])

#define val_datetime  req->val_union.value_datetime
#define val_bool      req->val_union.value_bool
#define val_int       req->val_union.value_int
#define val_uint      req->val_union.value_uint
#define val_ulong     req->val_union.value_ulong

//------------------------------------------------------------------------------------
// Enumeration for Device.DeviceInfo.FirmwareImage.{i}.Status
typedef enum
{
    kFirmwareStatus_NoImage = 0,
    kFirmwareStatus_Downloading = 1,
    kFirmwareStatus_Validating = 2,
    kFirmwareStatus_Available = 3,
    kFirmwareStatus_DownloadFailed = 4,
    kFirmwareStatus_ValidationFailed = 5,
    kFirmwareStatus_InstallationFailed = 6,
    kFirmwareStatus_ActivationFailed = 7,
} firmware_status_t;

//------------------------------------------------------------------------------
// Enumeration for SHA algorithm types used by Device.DeviceInfo.FirmwareImage.{i}.Download() operation
// NOTE: If this enumeration is changed, please also update sha_alg_strings[]
typedef enum
{
    kShaAlg_NoneSpecified,

    kShaAlg_1,          // SHA-1
    kShaAlg_224,        // SHA-2 224 bit
    kShaAlg_256,        // SHA-2 256 bit
    kShaAlg_384,        // SHA-2 384 bit
    kShaAlg_512,        // SHA-2 512 bit
} sha_alg_t;

//------------------------------------------------------------------------------
// Bits in bitmask defining permissions. If the bit is set, then the permission is granted
#define PERMIT_GET                0x0001 // Grants the capability to read the value of the Parameter via Get and read the meta-information of the Parameter via GetSupportedDM.
#define PERMIT_SET                0x0002 // Grants the capability to update the value of the Parameter via Add or Set.
#define PERMIT_ADD                0x0004 // Grants no capabilities for Static Objects. Grants the capability to create a new instance of a Multi-Instanced Object via Add
#define PERMIT_DEL                0x0008 // Grants the capability to remove an existing instance of an Instantiated Object via Delete (e.g. Device.LocalAgent.Controller.1.).
#define PERMIT_OPER               0x0010 // Grants the capability to execute the Command via Operate, but grants no capabilities to an Event.

#define PERMIT_SUBS_VAL_CHANGE    0x0020 // Grants the capability to use this Parameter in the ReferenceList of an Event or ValueChange Subscription.
#define PERMIT_SUBS_OBJ_ADD       0x0040 // Grants the capability to use this Object in the ReferenceList of an Event or ObjectCreation (for multi-instance objects only) Subscription.
#define PERMIT_SUBS_OBJ_DEL       0x0100 // Grants the capability to use this Instantiated Object in the ReferenceList of an Event or ObjectDeletion Subscription
#define PERMIT_SUBS_EVT_OPER_COMP 0x0200 // Grants the capability to use this Event or Command in the ReferenceList of an Event or OperationComplete Subscription.

#define PERMIT_GET_INST           0x0080 // Grants the capability to read the instance numbers and unique keys of the Instantiated Object via GetInstances.
#define PERMIT_OBJ_INFO           0x0400 // Grants the capability to read the meta-information of the Object via GetSupportedDM.
#define PERMIT_CMD_INFO           0x0800 // Grants the capability to read the meta-information of the Command (including input and output arguments) and Event (including arguments) via GetSupportedDM.

#define PERMIT_NONE               0x0000 // Grants no capabilities
#define PERMIT_ALL                0xFFFF // Grants all capabilities

#define INVALID_ROLE              kCTrustRole_Max  // Role returned by DEVICE_CTRUST_GetCertRole() if no matching entry in the credential table was found

//---------------------------------------------------------------------
// Structure for each element of trust store array
typedef struct
{
    const unsigned char *cert_data;
    int cert_len;
    ctrust_role_t role;        // Controller Trust role that this certificate permits
} trust_store_t;

//---------------------------------------------------------------------
// Structure describing the certificate and private key for this agent CPE
typedef struct
{
    unsigned char *cert_data;
    int cert_len;
    unsigned char *key_data;
    int key_len;
} agent_cert_info_t;

//------------------------------------------------------------------------------
// Structure for Download() operation input conditions (ie arguments)
typedef struct
{
    int request_instance;   // Instance number of this operation in the Device.LocalAgent.Request table
    char originator[MAX_DM_PATH]; // Data model path of the controller that initiated this operation
    int firmware_slot;      // Firmware slot number to download into. This value is 'i' in Device.DeviceInfo.FirmwareImage.{i}

    char command_key[256];  // The command key comes from the Operate() USP message, rather than being a download input arg
    char url[256];
    char username[128];
    char password[128];
    unsigned file_size;
    bool auto_activate;     // If set, the download operation also activates the image and reboots.

    sha_alg_t   sha_alg;
    unsigned char sha_sum[512/8];        // SHA-2 is up to 512 bit
    int sha_sum_size;
    
} download_input_cond_t;

//-------------------------------------------------------------------------
// Enumeration representing when the CPE is permitted to activate the firmware image
typedef enum
{
    kActivateMode_AnyTime,
    kActivateMode_Immediately,
    kActivateMode_WhenIdle,
    kActivateMode_ConfirmationNeeded,
} activate_mode_t;

//-------------------------------------------------------------------------
// Typedefs for data model callback functions
typedef int (*dm_get_value_cb_t)(dm_req_t *req, char *buf, int len);
typedef int (*dm_set_value_cb_t)(dm_req_t *req, char *buf);
typedef int (*dm_add_cb_t)(dm_req_t *req);
typedef int (*dm_del_cb_t)(dm_req_t *req);

typedef int (*dm_validate_value_cb_t)(dm_req_t *req, char *value);
typedef int (*dm_notify_set_cb_t)(dm_req_t *req, char *value);

typedef int (*dm_validate_add_cb_t)(dm_req_t *req);
typedef int (*dm_notify_add_cb_t)(dm_req_t *req);

typedef int (*dm_validate_del_cb_t)(dm_req_t *req);
typedef int (*dm_notify_del_cb_t)(dm_req_t *req);

typedef int (*dm_sync_oper_cb_t)(dm_req_t *req, char *command_key, kv_vector_t *input_args, kv_vector_t *output_args);
typedef int (*dm_async_oper_cb_t)(dm_req_t *req, kv_vector_t *input_args, int instance);
typedef int (*dm_async_restart_cb_t)(dm_req_t *req, int instance, bool *is_restart, int *err_code, char *err_msg, int err_msg_len, kv_vector_t *output_args);

//-------------------------------------------------------------------------
// Typedefs for core vendor hook callbacks

// Get the serial number of this device
// NOTE: This function returns a value which may be overridden by an entry in the USP database
typedef int (*dm_vendor_get_agent_serial_number_cb_t)(char *buf, int len);

// Get the endpoint_id of this device
// NOTE: This function returns a value which may be overridden by an entry in the USP database
typedef int (*dm_vendor_get_agent_endpoint_id_cb_t)(char *buf, int len);

// Called to signal to the vendor that the CPE should reboot
// By the time this function has been called, all communication channels to controllers will have been closed down
// This function would normally exit the USP Agent process
// However it doesn't have to, if it needs to wait until other actions running in the USP Agent process have completed
typedef int (*dm_vendor_reboot_cb_t)(void);

// Called to signal to the vendor that the CPE should reboot and perform a factory reset
typedef int (*dm_vendor_factory_reset_cb_t)(void);

// Vendor hooks associated with vendor database transactions
typedef int (*dm_vendor_start_trans_cb_t)(void);
typedef int (*dm_vendor_commit_trans_cb_t)(void);
typedef int (*dm_vendor_abort_trans_cb_t)(void);

// Gets the current running software version of the firmware image
// This must match the software version of the active firmware image
typedef int (*get_active_software_version_cb_t)(char *buf, int len);


// Vendor hooks associated with certificates and controller trust
typedef int (*register_controller_trust_cb_t)(void);
typedef bool (*is_system_time_reliable_cb_t)(void);
typedef const trust_store_t *(*get_trust_store_cb_t)(int *num_trusted_certs);
typedef int (*get_agent_cert_cb_t)(agent_cert_info_t *info);


// Miscellaneous vendor hooks
typedef int (*get_hardware_version_cb_t)(char *buf, int len);
typedef unsigned long long (*stats_collection_enable_cb_t)(bool enable, char *interface_name);
typedef int (*dm_vendor_get_mtp_password_cb_t)(int instance, char *buf, int len);
typedef int (*load_agent_cert_cb_t)(SSL_CTX *ctx);
typedef void (*log_message_cb_t)(char *buf);

//-------------------------------------------------------------------------
// Typedef for structure containing core vendor hook callbacks
// IMPORTANT:  DO NOT WRITE CODE THAT DEPENDS ON THE POSITION OF THE CALLBACK WITHIN THIS STRUCTURE !
typedef struct
{
    dm_vendor_get_agent_serial_number_cb_t  get_agent_serial_number_cb;
    dm_vendor_get_agent_endpoint_id_cb_t    get_agent_endpoint_id_cb;
    dm_vendor_reboot_cb_t                   reboot_cb;
    dm_vendor_factory_reset_cb_t            factory_reset_cb;

    // Vendor hooks associated with vendor database transactions
    dm_vendor_start_trans_cb_t              start_trans_cb;
    dm_vendor_commit_trans_cb_t             commit_trans_cb;
    dm_vendor_abort_trans_cb_t              abort_trans_cb;

    // Vendor hooks associated with certificates and controller trust
    register_controller_trust_cb_t          register_controller_trust_cb;
    is_system_time_reliable_cb_t            is_system_time_reliable_cb;
    get_trust_store_cb_t                    get_trust_store_cb;
    get_agent_cert_cb_t                     get_agent_cert_cb;

    // Miscellaneous vendor hooks
#ifndef REMOVE_DEVICE_INFO
    get_active_software_version_cb_t        get_active_software_version_cb;
    get_hardware_version_cb_t               get_hardware_version_cb;
#endif

    dm_vendor_get_mtp_password_cb_t         get_mtp_password_cb;
    load_agent_cert_cb_t                    load_agent_cert_cb;
    log_message_cb_t                        log_message_cb;

} vendor_hook_cb_t;

//-------------------------------------------------------------------------
// Defines for type_flags argument of registration functions
#define DM_STRING       0x00000001
#define DM_DATETIME     0x00000002
#define DM_BOOL         0x00000004
#define DM_INT          0x00000008
#define DM_UINT         0x00000010
#define DM_ULONG        0x00000020

//-------------------------------------------------------------------------
// Functions to register the data model
// These functions may only be called during startup (which for vendor code, means within VENDOR_Init())
int USP_REGISTER_Param_Constant(char *path, char *value, unsigned type_flags);
int USP_REGISTER_DBParam_ReadWrite(char *path, char *value, dm_validate_value_cb_t validator_cb, dm_notify_set_cb_t notify_set_cb, unsigned type_flags);
int USP_REGISTER_Param_NumEntries(char *path, char *table_path);
int USP_REGISTER_VendorParam_ReadOnly(char *path, dm_get_value_cb_t get_cb, unsigned type_flags);
int USP_REGISTER_VendorParam_ReadWrite(char *path, dm_get_value_cb_t get_cb, dm_set_value_cb_t set_cb, dm_notify_set_cb_t notify_set_cb, unsigned type_flags);
int USP_REGISTER_DBParam_ReadOnlyAuto(char *path, dm_get_value_cb_t get_cb, unsigned type_flags);
int USP_REGISTER_DBParam_ReadWriteAuto(char *path, dm_get_value_cb_t get_cb, dm_validate_value_cb_t validator_cb, 
                                      dm_notify_set_cb_t notify_set_cb, unsigned type_flags);
int USP_REGISTER_DBParam_Alias(char *path, dm_notify_set_cb_t notify_set_cb);
int USP_REGISTER_DBParam_ReadOnly(char *path, char *value, unsigned type_flags);
int USP_REGISTER_DBParam_Secure(char *path, char *value, dm_validate_value_cb_t validator_cb, dm_notify_set_cb_t notify_set_cb);
int USP_REGISTER_Object(char *path, dm_validate_add_cb_t validate_add_cb, dm_add_cb_t add_cb, dm_notify_add_cb_t notify_add_cb,
                                   dm_validate_del_cb_t validate_del_cb, dm_del_cb_t del_cb, dm_notify_del_cb_t notify_del_cb);
int USP_REGISTER_Object_UniqueKey(char *path, char **params, int num_params);
int USP_REGISTER_SyncOperation(char *path, dm_sync_oper_cb_t sync_oper_cb);
int USP_REGISTER_AsyncOperation(char *path, dm_async_oper_cb_t async_oper_cb, dm_async_restart_cb_t restart_cb);
int USP_REGISTER_OperationArguments(char *path, char **input_arg_names, int num_input_arg_names, char **output_arg_names, int num_output_arg_names);
int USP_REGISTER_Event(char *path);
int USP_REGISTER_EventArguments(char *path, char **event_arg_names, int num_event_arg_names);
int USP_REGISTER_CoreVendorHooks(vendor_hook_cb_t *callbacks);

//------------------------------------------------------------------------------
// Functions that may be called from vendor hooks to access the data model
// These functions must not be called from any thread other than the data model thread
// If you need to access a data model parameter from another thread, then it must be implemented as a vendor parameter
int USP_DM_GetParameterValue(char *path, char *buf, int len);
int USP_DM_SetParameterValue(char *path, char *new_value);
int USP_DM_DeleteInstance(char *path);
int USP_DM_InformInstance(char *path);
int USP_DM_GetInstances(char *path, int_vector_t *iv);
int USP_DM_RegisterRoleName(ctrust_role_t role, char *name);
int USP_DM_AddControllerTrustPermission(ctrust_role_t role, char *path, unsigned short permission_bitmask);

//------------------------------------------------------------------------------
// Functions that may be called from a thread implementing an asynchronous operation
int USP_SIGNAL_OperationComplete(int instance, int err_code, char *err_msg, kv_vector_t *output_args);
int USP_SIGNAL_DataModelEvent(char *event_name, kv_vector_t *output_args);
int USP_SIGNAL_OperationStatus(int instance, char *status);
int USP_SIGNAL_ObjectAdded(char *path);
int USP_SIGNAL_ObjectDeleted(char *path);

//------------------------------------------------------------------------------
// Functions for argument list data structure
kv_vector_t * USP_ARG_Create(void);
void USP_ARG_Init(kv_vector_t *kvv);
void USP_ARG_Add(kv_vector_t *kvv, char *key, char *value);
void USP_ARG_AddUnsigned(kv_vector_t *kvv, char *key, unsigned value);
void USP_ARG_AddBool(kv_vector_t *kvv, char *key, bool value);
void USP_ARG_AddDateTime(kv_vector_t *kvv, char *key, time_t value);
char *USP_ARG_Get(kv_vector_t *kvv, char *key, char *default_value);
int USP_ARG_GetUnsigned(kv_vector_t *kvv, char *key, unsigned default_value, unsigned *value);
int USP_ARG_GetUnsignedWithinRange(kv_vector_t *kvv, char *key, unsigned default_value, unsigned min, unsigned max, unsigned *value);
int USP_ARG_GetBool(kv_vector_t *kvv, char *key, bool default_value, bool *value);
int USP_ARG_GetDateTime(kv_vector_t *kvv, char *key, char *default_value, time_t *value);
void USP_ARG_Destroy(kv_vector_t *kvv);

//------------------------------------------------------------------------------
// Functions converting data types
#define INVALID_TIME ((time_t)-1)
#define MAX_ISO8601_LEN  32   // 23 characters should be sufficient, so this is overkill
time_t USP_CONVERT_DateTimeToUnixTime(char *date);
char *USP_CONVERT_UnixTimeToDateTime(time_t unix_time, char *buf, int len);

//------------------------------------------------------------------------------
// Functions setting error messages
void USP_ERR_SetMessage(char *fmt, ...)   __attribute__((format(printf, 1, 2)));

//-------------------------------------------------------------------------
// Functions used when registering validate_add and validate_delete vendor hooks, if the multi-instance object is read only
int USP_HOOK_DenyAddInstance(dm_req_t *req);
int USP_HOOK_DenyDeleteInstance(dm_req_t *req);

#ifdef ENABLE_HIDL
// Include the HIDL vendor hook functions, if required
#include "hidl_server.h"
#endif

#endif
