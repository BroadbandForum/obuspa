/*
 *
 * Copyright (C) 2019, Broadband Forum
 * Copyright (C) 2017-2019  CommScope, Inc
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
 * \file usp_coap.c
 *
 * Implements Constrained Application Protocol transport for USP
 *
 */

#ifdef ENABLE_COAP  // NOTE: This isn't strictly necessary as this file is not included in the build if CoAP is disabled

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#include "common_defs.h"
#include "usp_api.h"
#include "usp-msg.pb-c.h"
#include "msg_handler.h"
#include "os_utils.h"
#include "dllist.h"
#include "dm_exec.h"
#include "retry_wait.h"
#include "usp_coap.h"
#include "text_utils.h"
#include "nu_ipaddr.h"
#include "iso8601.h"

//------------------------------------------------------------------------
// Defines whose default is set by RFC7252
#define COAP_VERSION 1                  // The version number of the CoAP protocol, at the start of all CoAP PDUs
#define COAP_MAX_RETRANSMIT 4           // Maximum number of retries. The total number of times the BLOCK message is sent is one more than this.
#define COAP_ACK_TIMEOUT 2              // Minimum initial timeout for receiving an ACK message
#define MAX_COAP_PDU_SIZE  1152         // Maximum size of a CoAP PDU. This is set by the maximum UDP packet size.

#define COAP_HEADER_SIZE 4              // Number of bytes in a CoAP header. This is the smallest number of bytes for a valid CoAP PDU
#define MAX_COAP_PAYLOAD_SIZE 1024      // Maximum size of a payload in a block
#define MAX_COAP_TOKEN_SIZE 8           // Maximum number of bytes in a CoAP token
#define MAX_OPTION_HEADER_SIZE 3        // Maximum number of bytes in an option header (Option + option_delta_ext + option_len_ext)

//------------------------------------------------------------------------
// Defines for this implementation (not set by any RFC)
#define COAP_CLIENT_PAYLOAD_TX_SIZE  MAX_COAP_PAYLOAD_SIZE   // Maximum size of payload that we will send
#define COAP_CLIENT_PAYLOAD_RX_SIZE  MAX_COAP_PAYLOAD_SIZE   // Maximum size of payload that we would like to receive

#define MAX_COAP_URI_PATH  128      // Maximum size of buffer containing the URI path received in the PDU
#define MAX_COAP_URI_QUERY 128      // Maximum size of URI query received in the PDU

#define COAP_SERVER_TIMEOUT 30      // After our CoAP server receives a BLOCK, this is the number of seconds after which we abort reception of further blocks from the current USP record

#define MAX_COAP_RECONNECTS (COAP_MAX_RETRANSMIT) // Maximum number of times that our CoAP client tries to connect to a CoAP server.
                                                  //  Retry occurs if unable to resolve server IP address, or a timeout occurred receiving an ACK on a DTLS session
#define RECONNECT_TIMEOUT   1      // Number of seconds to wait after our CoAP client could not connect to a CoAP server
                                   // (because unable to resolve server IP address, or DTLS failed or peer's server had silently reset the DTLS connection)

#define COAP_CLIENT_LINGER_PERIOD 300     // Number of seconds to keep the CoAP client connected to a USP Controller before disconnecting
#define COAP_SERVER_LINGER_PERIOD 300     // Number of seconds to keep the CoAP server connected to a USP Controller before disconnecting

#define DTLS_READ_TIMEOUT 2   // This corresponds to a total timeout of 5 seconds (1=>2s, 2=>5s, 3=>6s, 4=>11s, 8=>23s, 15=>30s )

//------------------------------------------------------------------------
// Macro to calculate the next CoAP message_id
#define NEXT_MESSAGE_ID(mid)  (((mid) + 1) & 0xFFFF)

//------------------------------------------------------------------------
// Structure representing the CoAP servers that USP Agent exports
typedef struct
{
    int instance;           // Instance number of the CoAP server in Device.LocalAgent.MTP.{i}, or INVALID if this slot is unused

    char interface[IFNAMSIZ]; // Name of network interface that this server if listening to ("any" represents all interfaces)
    char listen_addr[NU_IPADDRSTRLEN]; // Our interface address that the controller sends to
    int listen_port;        // Our port that the controller sends to
    char *listen_resource;  // Our resource that the controller sends to
    bool enable_encryption; // Set if encryption should be enabled for this server

    int socket_fd;          // Socket that we are listening on for USP messages from a controller
    bool is_session_started;// Set if in a session (DTLS or non-DTLS) with a peer
    SSL *ssl;               // SSL connection object used for this CoAP server
    BIO *bio;               // SSL BIO used to DTLS encrypt/decrypt the packets
    bool is_first_usp_msg;  // Set if this is the first USP request message received since the server was reset. 
                            // This is used as a hint to reset our CoAP client sending the USP response 
                            // (because the request was received on a new DTLS session, the response will likely need to be too)

    STACK_OF(X509) *cert_chain; // Full SSL certificate chain for the CoAP connection, collected in the SSL verify callback
    char *allowed_controllers; // pattern describing the endpoint_id of controllers which is granted access to this agent
    ctrust_role_t role;     // role granted by the CA cert in the chain of trust with the CoAP client

    nu_ipaddr_t peer_addr;   // Current peer that sent the first block. Whilst building up a USP Record, only PDUs from this peer are accepted
    uint16_t peer_port;     // Port that peer is using to communicate with us

    unsigned char token[8]; // Token received in the first block. The server must use the same token for the rest of the blocks.
    int token_size;

    int block_count;        // Count of number of blocks received for the current USP message (ie for current CoAP message token)
    int block_size;         // Size of the blocks being received. The server must use the same size of all of the blocks making up a USP record.

    unsigned char *usp_buf; // Pointer to buffer in which the payload is appended, to form the full USP record
    int usp_buf_len;        // Length of the USP record buffer

    int last_message_id;    // CoAP message id of the last received PDU that was handled.
    unsigned char last_message[MAX_COAP_PAYLOAD_SIZE];  // Response that was sent when the last PDU was handled
    int last_message_len;   // Length (in bytes) of the response in last_message[]

    time_t abort_timeout_time; // time at which we abort reception of the current USP record. This is updated each time we receive a block PDU
                               // It is necessary because we wait for one client to finish before allowing another to connect.
                               // This timeout stops one client from preventing another from sending, if it goes offline whilst in the middle of transmitting a USP record

    time_t linger_time;     // time at which we close a DTLS connection (after no activity), allowing other CoAP clients to connect
                            // This timer is needed to disconnect the socket if the controller goes down ungracefully (without sending SSL shutdown)
                            // NOTE: Non-DTLS connections are always reset every time a full USP Record has been received

} coap_server_t;

coap_server_t coap_servers[MAX_COAP_SERVERS];

//------------------------------------------------------------------------
// Structure representing a CoAP client, used to send a USP message to a controller
typedef struct
{
    int cont_instance;           // Instance number of the controller in Device.LocalAgent.Controller.{i}
    int mtp_instance;            // Instance number of the MTP in Device.LocalAgent.Controller.{i}.MTP.{i}
    bool enable_encryption;      // Set if encryption should be enabled for this client
    double_linked_list_t send_queue; // Queue of messages to send on this CoAP connection

    int socket_fd;               // When sending to a controller, this socket sends CoAP BLOCKs and receives CoAP ACKs
    nu_ipaddr_t  peer_addr;      // IP Address of USP controller that socket_fd is sending to
    uint16_t peer_port;          // Port on USP controller that socket_fd is connected to
    SSL *ssl;                    // SSL connection object used for this CoAP client
	BIO *bio;                    // SSL BIO used to DTLS encrypt/decrypt the packets

    unsigned message_id;         // Message ID - unique for the current block being sent
    unsigned char token[4];      // Token to identify the request being sent (same for all blocks encapsulating a single USP message)
    char uri_query_option[128];  // URI query string, telling the recipient what to send the response to

    int cur_block;               // Current block number that we're trying to send
    int block_size;              // Size of blocks (in bytes) that we're sending (the receiver may request that we send a smaller block size)
    int bytes_sent;              // Number of bytes successfully sent of the USP record in BLOCK PDUs.

    int ack_timeout_ms;          // Timeout to receiving next ACK in milliseconds. NOTE: Currently code rounds this down to the nearest number of seconds
    time_t ack_timeout_time;     // Absolute time at which we timeout waiting for an ACK
    int retransmission_counter;  // Number of times that we've retried sending the current block

    int reconnect_timeout_ms;    // Timeout to next trying to reconnect
    time_t reconnect_time;       // Time at which we try to connect the socket again. This is used if we're unable to resolve the server IP address
                                 // This variable is only valid if socket_fd==INVALID
    int reconnect_count;         // Count of number of times that we've tried reconnecting. NOTE: This also includes a count of the retransmission counter
    time_t linger_time;          // time at which we close the connection because we have no more USP Records to send

} coap_client_t;


coap_client_t coap_clients[MAX_COAP_CLIENTS];

//------------------------------------------------------------------------------
// USP Message to send in queue
typedef struct
{
    double_link_t link;     // Doubly linked list pointers. These must always be first in this structure
    Usp__Header__MsgType usp_msg_type;  // Type of USP message contained within pbuf
    unsigned char *pbuf;    // Protobuf format message to send in binary format
    int pbuf_len;           // Length of protobuf message to send
    char *host;             // Hostname of the controller to send to
    coap_config_t config;   // Port, resource and whether encryption is enabled
    bool coap_reset_session_hint;       // Set if an existing DTLS session with this host should be reset. 
                                        // If we know that the USP request came in on a new DTLS session, then it is likely 
                                        // that the USP response must be sent back on a new DTLS session also. Wihout this, 
                                        // the CoAP retry mechanism will cause the DTLS session to restart, but it is a while
                                        // before the retry is triggered, so this hint speeds up communications
} coap_send_item_t;

//------------------------------------------------------------------------------------
// Mutex used to protect access to this component
static pthread_mutex_t coap_access_mutex;

//------------------------------------------------------------------------------------
// The SSL contexts for CoAP (created for use with DTLS)
SSL_CTX *coap_client_ssl_ctx = NULL;
SSL_CTX *coap_server_ssl_ctx = NULL;

//------------------------------------------------------------------------
// Enumeration representing CoAP PDU message type (defined in RFC7252)
typedef enum
{
    kPduType_Confirmable = 0,
    kPduType_NonConfirmable = 1,
    kPduType_Acknowledgement = 2,
    kPduType_Reset = 3,
} pdu_type_t;

//------------------------------------------------------------------------
// Enumeration representing CoAP PDU message class (defined in RFC7252)
typedef enum
{
    kPduClass_Request = 0,
    kPduClass_SuccessResponse = 2,
    kPduClass_ClientErrorResponse = 4,
    kPduClass_ServerErrorResponse = 5,
} pdu_class_t;

//------------------------------------------------------------------------
// Enumeration representing CoAP PDU request methods (defined in RFC7252)
typedef enum
{
    kPduRequestMethod_Get = 1,
    kPduRequestMethod_Post = 2,
    kPduRequestMethod_Put = 3,
    kPduRequestMethod_Delete = 4,
} pdu_request_method_t;

//------------------------------------------------------------------------
// Enumeration representing CoAP PDU success response codes (2.X defined in RFC7252 and RFC7959)
enum
{
    kPduSuccessRespCode_Created = 1,
    kPduSuccessRespCode_Deleted = 2,
    kPduSuccessRespCode_Valid = 3,
    kPduSuccessRespCode_Changed = 4,
    kPduSuccessRespCode_Content = 5,
    kPduSuccessRespCode_Continue = 31,
};

//------------------------------------------------------------------------
// Enumeration representing CoAP PDU client error response codes (4.X defined in RFC7252)
enum
{
    kPduClientErrRespCode_BadRequest = 0,       // We could not understand the request due to invalid syntax
    kPduClientErrRespCode_Unauthorized = 1,
    kPduClientErrRespCode_BadOption = 2,        // We received a 'critical' option which we could not parse
    kPduClientErrRespCode_Forbidden = 3,
    kPduClientErrRespCode_NotFound = 4,         // We received a uri_path which did not match that of our USP resource
    kPduClientErrRespCode_MethodNotAllowed = 5, // We received a PDU that wasn't a POST
    kPduClientErrRespCode_NotAcceptable = 6,
    kPduClientErrRespCode_RequestEntityIncomplete = 8,  // We received a block number which was not the next expected one
    kPduClientErrRespCode_PreconditionFailed = 12,
    kPduClientErrRespCode_RequestEntityTooLarge = 13,   // We received more blocks in a USP Record, than we support
    kPduClientErrRespCode_UnsupportedContentFormat = 15, // We received a content format which was not application/octet-stream
};

//------------------------------------------------------------------------
// Enumeration representing CoAP PDU server error response codes (5.X defined in RFC7252)
enum
{
    kPduServerErrRespCode_InternalServerError = 0,
    kPduServerErrRespCode_NotImplemented = 1,
    kPduServerErrRespCode_BadGateway = 2,
    kPduServerErrRespCode_ServiceUnavailable = 3,
    kPduServerErrRespCode_GatewayTimeout = 4,
    kPduServerErrRespCode_ProxyingNotSupported = 5, // We received the proxy-uri or proxy-scheme options, which we do not support
};

//------------------------------------------------------------------------
// Enumeration representing CoAP PDU Option numbers (defined in RFC7252, RFC7959)
typedef enum
{
    kPduOption_Zero = 0,
    kPduOption_IfMatch = 1,
    kPduOption_UriHost = 3,
    kPduOption_ETag = 4,
    kPduOption_IfNoneMatch = 5,
    kPduOption_UriPort = 7,
    kPduOption_LocationPath = 8,
    kPduOption_UriPath = 11,
    kPduOption_ContentFormat = 12,
    kPduOption_MaxAge = 14,
    kPduOption_UriQuery = 15,
    kPduOption_Accept = 17,
    kPduOption_LocationQuery = 20,
    kPduOption_Block2 = 23,
    kPduOption_Block1 = 27,
    kPduOption_Size2 = 28,
    kPduOption_ProxyUri = 35,
    kPduOption_ProxyScheme = 39,
    kPduOption_Size1 = 60,
} pdu_option_t;

#define PDU_OPTION_END_MARKER 255

//------------------------------------------------------------------------
// Enumeration representing CoAP PDU content format (defined in RFC7252)
typedef enum
{
    kPduContentFormat_Text = 0,         // text/plain
    kPduContentFormat_LinkFormat = 40,  // application/link-format 
    kPduContentFormat_XML = 41,         // application/xml         
    kPduContentFormat_OctetStream = 42, // application/octet-stream // Only this may be used for USP records
    kPduContentFormat_EXI = 47,         // application/exi         
    kPduContentFormat_JSON = 50,        // application/json        
} pdu_content_format_t;

//------------------------------------------------------------------------
// Enumeration representing CoAP Block sizes (defined in RFC7959)
// NOTE: This is just used to make the code easier to read. The size is just  1 << (4 + enum)
typedef enum
{
    kPduBlockSize_16 = 0,
    kPduBlockSize_32 = 1,
    kPduBlockSize_64 = 2,
    kPduBlockSize_128 = 3,
    kPduBlockSize_256 = 4,
    kPduBlockSize_512 = 5,
    kPduBlockSize_1024 = 6,
} pdu_block_size_t;

//------------------------------------------------------------------------------
// Structure used to walk the CoAP option list.
// It is used to maintain state between each CoAP option, and also return the current parsed option
typedef struct
{
    unsigned char *buf;             // On input : pointer to option to parse
                                    // On output: pointer to next option to parse
    int len;                        // On input : length of buffer left for this option and following options
                                    // On output: length of buffer left for next options
    int cur_option;                 // On input : Last option parsed
                                    // On output: Option just parsed
    unsigned char *option_value;    // On input : don't care
                                    // On output: pointer to buffer containing the values for the option just parsed
    int option_len;                 // On input : don't care
                                    // On output: length of the buffer containing the values for the option just parsed
} option_walker_t;

//------------------------------------------------------------------------------
// Bitmask used to specify which options were parsed into the parsed_pdu_t structure
#define BLOCK1_PRESENT              0x00000001
#define URI_PATH_PRESENT            0x00000002
#define URI_QUERY_PRESENT           0x00000004
#define CONTENT_FORMAT_PRESENT      0x00000008
#define SIZE1_PRESENT               0x00000010

//------------------------------------------------------------------------------
// Structure representing a parsed PDU
typedef struct
{
    // CoAP Header
    unsigned coap_version;
    pdu_type_t pdu_type;
    pdu_class_t pdu_class;
    int request_response_code;

    // Token and MessageId
    unsigned token_size;
    unsigned char token[MAX_COAP_TOKEN_SIZE];
    unsigned message_id;

    // Bitmask of options that were parsed
    unsigned options_present;

    // Parsed from the Block1 option
    int rxed_block;     // Block number received in this block (counts from 0)
    int is_more_blocks; // Set to 0 if this is the last block, set to 1 if there are more blocks
    int block_size;     // Size of the received block

    // Other parsed options
    char uri_path[MAX_COAP_URI_PATH];
    char uri_query[MAX_COAP_URI_QUERY];
    mtp_reply_to_t mtp_reply_to;    // NOTE: pointers in this structure point to strings in pp->uri_query
    pdu_content_format_t content_format;
    unsigned total_size;     // total size of the USP record being transferred in blocks

    // Payload
    unsigned char *payload; // Pointer to payload in the buffer that contained the PDU that was parsed
    int payload_len;        // Length of the payload

} parsed_pdu_t;

//------------------------------------------------------------------------------
// Bitmask used to specify what to do in response to receiving a CoAP PDU
#define COAP_NO_ERROR           0x00000000      // No error, and nothing to do (yet)
#define SEND_RST                0x00000001      // Send a RST CoAP PDU
#define SEND_ACK                0x00000002      // Send an ACK CoAP PDU
#define INDICATE_BAD_REQUEST    0x00000004      // Send an ACK containing 4.00 Bad request
#define INDICATE_BAD_OPTION     0x00000008      // Send an ACK containing 4.02 Bad Option
#define INDICATE_NOT_FOUND      0x00000010      // Send an ACK containing 4.04 Not found
#define INDICATE_BAD_METHOD     0x00000020      // Send an ACK containing 4.05 Method not allowed
#define INDICATE_INCOMPLETE     0x00000040      // Send an ACK containing 4.08 Request entity Incomplete
#define INDICATE_TOO_LARGE      0x00000080      // Send an ACK containing 4.13 Request entity too large
#define INDICATE_BAD_CONTENT    0x00000100      // Send an ACK containing 4.15 Unsupported content format
#define INDICATE_WELL_KNOWN     0x00000200      // Send an ACK containing 2.05 Content containing the '.well-known/core' response

#define SEND_NEXT_USP_RECORD    0x02000000      // Starts sending the next USP record to the controller
#define SEND_NEXT_BLOCK         0x04000000      // Send the next block of the USP record to the controller
#define IGNORE_PDU              0x08000000      // Ignore the current PDU that was received
#define RESET_STATE             0x10000000      // Reset the state of the transmission or reception back to the beginning
#define RESEND_LAST_RESPONSE    0x20000000      // Resend the last response PDU, because we've received a duplicate message
#define ABORT_SENDING           0x40000000      // Abort sending any more PDUs, because we've received an RST
#define USP_RECORD_COMPLETE     0x80000000      // Process the USP record in cs->usp_buf

// Compound flag grouping all causes of indicating an error in an ACK
#define INDICATE_ERR_IN_ACK   (INDICATE_BAD_REQUEST | INDICATE_BAD_OPTION | INDICATE_NOT_FOUND | INDICATE_BAD_METHOD | INDICATE_INCOMPLETE | INDICATE_TOO_LARGE | INDICATE_BAD_CONTENT)

//------------------------------------------------------------------------------
// Buffer containing the textual cause of the error - to copy into the payload of an ACK or RST message
char coap_err_message[256];

//------------------------------------------------------------------------------
// Defines for flags used with StartSendingCoapUspRecord()
#define SEND_CURRENT                0            // Opposite of SEND_NEXT. Sends the current queued USP Record
#define SEND_NEXT                   0x00000001   // Drops the current queued USP record, and starts sending the next
#define RETRY_CURRENT               0x00000002   // Retries sending the current queued USP Record

//------------------------------------------------------------------------------
// Defines for flags used with RetryClientSendLater()
#define ZERO_DELAY_FOR_FIRST_RECONNECT 1        // For the first reconnection attempt do not use any delay (because there has already been a delay due to a missing ACK)

//------------------------------------------------------------------------------
// Defines to support OpenSSL's change of API signature for SSL_CTX_set_cookie_verify_cb() between different OpenSSL versions
#if OPENSSL_VERSION_NUMBER >= 0x1010000FL // SSL version 1.1.0
    #define SSL_CONST    const
#else
    #define SSL_CONST
#endif

//------------------------------------------------------------------------------
// Buffer containing the random secret that our CoAP server puts into cookies
static unsigned char coap_hmac_key[16];

//------------------------------------------------------------------------------
// Variables associated with determining whether the listening IP address of our CoAP server has changed (used by UpdateCoapServerInterfaces)
static time_t next_coap_server_if_poll_time = 0;   // Absolute time at which to next poll for IP address change

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
coap_client_t *FindUnusedCoapClient(void);
void HandleNoCoapAck(coap_client_t *cc);
void HandleCoapAck(coap_client_t *cc);
coap_client_t *FindUnusedCoapClient(void);
coap_client_t *FindCoapClientByInstance(int cont_instance, int mtp_instance);
void StopSendingToController(coap_client_t *cc);
int SendCoapBlock(coap_client_t *cc);
int WriteCoapBlock(coap_client_t *cc, unsigned char *buf, int len);
unsigned char *WriteCoapOption(pdu_option_t pdu_option, unsigned char *option_data, int len, unsigned char *buf, pdu_option_t *last_pdu_option);
pdu_block_size_t CalcBlockSize_Int2Pdu(int block_size);
int CalcBlockSize_Pdu2Int(pdu_block_size_t pdu_block_size);
int CalcCoapInitialTimeout(void);
void StartSendingCoapUspRecord(coap_client_t *cc, unsigned flags);
coap_server_t *FindUnusedCoapServer(void);
coap_server_t *FindCoapServerByInstance(int instance, char *interface);
int WalkCoapOption(option_walker_t *ow, parsed_pdu_t *pp);
void ReceiveCoapBlock(coap_server_t *cs);
unsigned ParseCoapPdu(unsigned char *buf, int len, parsed_pdu_t *pp);
unsigned HandleFirstCoapBlock(coap_server_t *cs, parsed_pdu_t *pp);
unsigned HandleSubsequentCoapBlock(coap_server_t *cs, parsed_pdu_t *pp);
unsigned AppendCoapPayload(coap_server_t *cs, parsed_pdu_t *pp);
int ParseCoapOption(int option, unsigned char *buf, int len, parsed_pdu_t *pp);
void LogRxedCoapPdu(parsed_pdu_t *pp);
int SendCoapAck(coap_server_t *cs, parsed_pdu_t *pp, unsigned action_flags);
int WriteCoapAck(coap_server_t *cs, unsigned char *buf, int len, parsed_pdu_t *pp, unsigned action_flags);
void ParseBlock1Option(unsigned char *buf, int len, parsed_pdu_t *pp);
int CalcCoapBlockOption(unsigned char *buf, int cur_block, int is_more_blocks, int block_size);
unsigned ReadUnsignedOptionValue(unsigned char *buf, int len);
void SetCoapErrMessage(char *fmt, ...);
void CalcCoapClassForAck(parsed_pdu_t *pp, unsigned action_flags, int *pdu_class, int *response_code);
int SendCoapRstFromClient(coap_client_t *cc, parsed_pdu_t *pp);
int WriteCoapRst(int message_id, unsigned char *token, int token_len, unsigned char *buf, int len);
void AppendUriPath(char *path, int path_len, char *segment, int seg_len);
void SaveResponseToLastHandledPdu(coap_server_t *cs, int message_id, unsigned char *buf, int len);
int SendCoapRstFromServer(coap_server_t *cs, parsed_pdu_t *pp);
unsigned CalcCoapClientActions(coap_client_t *cc, parsed_pdu_t *pp);
unsigned CalcCoapServerActions(coap_server_t *cs, parsed_pdu_t *pp);
void SendFirstCoapBlock(coap_client_t *cc);
void ResetCoapServer(coap_server_t *cs);
void RetryClientSendLater(coap_client_t *cc, unsigned flags);
int PerformClientDtlsConnect(coap_client_t *cc, struct sockaddr_storage *remote_addr);
int SendCoapPdu(SSL *ssl, int socket_fd, unsigned char *buf, int len);
int ReceiveCoapPdu(SSL *ssl, int socket_fd, unsigned char *buf, int buflen);
int CalcCoapServerCookie(SSL *ssl, unsigned char *buf, unsigned int *p_len);
int VerifyCoapServerCookie(SSL *ssl, SSL_CONST unsigned char *buf, unsigned int len);
void PerformServerConnect(coap_server_t *cs);
void PerformServerDtlsConnect(coap_server_t *cs);
void CloseCoapServerSocket(coap_server_t *cs);
void CloseCoapClientSocket(coap_client_t *cc);
int StartCoapServer(coap_server_t *cs);
int ClientConnectToController(coap_client_t *cc, nu_ipaddr_t *peer_addr, coap_config_t *config);
void FreeFirstCoapSendItem(coap_client_t *cc);
void FreeReceivedUspRecord(coap_server_t *cs);
bool HandleDtlsLinger(coap_server_t *cs);
bool ParseCoapUriQuery(char *uri_query, mtp_reply_to_t *mrt);
coap_server_t *FindFirstCoapServerByInterface(char *interface, bool encryption_preference);
int CalcUriQueryOption(int socket_fd, bool encryption_preference, char *buf, int len);
bool IsReplyToValid(coap_server_t *cs, parsed_pdu_t *pp);
int UpdateCoapServerInterfaces(void);
void SwitchCoapServerToNewPeer(coap_server_t *cs);
void InitCoapServerForNewPeer(coap_server_t *cs);
int AddCoapServerSSL(coap_server_t *cs);
void RemoveCoapServerSSL(coap_server_t *cs);
bool IsUspRecordInCoapQueue(coap_client_t *cc, unsigned char *pbuf, int pbuf_len);

/*********************************************************************//**
**
** COAP_Init
**
** Initialises this component
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int COAP_Init(void)
{
    int i;
    int err;
    coap_server_t *cs;
    coap_client_t *cc;
    
    // Initialise the CoAP server array
    memset(coap_servers, 0, sizeof(coap_servers));
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        cs->instance = INVALID;
    }

    // Initialise the CoAP clients array
    memset(coap_clients, 0, sizeof(coap_clients));
    for (i=0; i<MAX_COAP_CLIENTS; i++)
    {
        cc = &coap_clients[i];
        cc->cont_instance = INVALID;
        cc->socket_fd = INVALID;
    }

    // Exit if unable to create mutex protecting access to this subsystem
    err = OS_UTILS_InitMutex(&coap_access_mutex);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** COAP_Start
**
** Creates the SSL contexts used by this module
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int COAP_Start(void)
{
    int err;

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Calculate a random hmac key which will be used by our CoAP server when generating DTLS cookies
    err = RAND_bytes(coap_hmac_key, sizeof(coap_hmac_key));
    if (err != 1)
    {
        USP_LOG_Error("%s: RAND_bytes() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Create the DTLS client SSL context with trust store and client cert loaded
    coap_client_ssl_ctx = DEVICE_SECURITY_CreateSSLContext(DTLS_client_method(), SSL_VERIFY_PEER, 
                                                           DEVICE_SECURITY_TrustCertVerifyCallback);
    if (coap_client_ssl_ctx == NULL)
    {
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Create the DTLS server SSL context with trust store and client cert loaded
    coap_server_ssl_ctx = DEVICE_SECURITY_CreateSSLContext(DTLS_server_method(), 
                                                           SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE /*| SSL_VERIFY_FAIL_IF_NO_PEER_CERT*/,
                                                           DEVICE_SECURITY_TrustCertVerifyCallback);
    if (coap_server_ssl_ctx == NULL)
    {
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Set the DTLS cookie functions for the CoAP server (only the server uses these)
	SSL_CTX_set_cookie_generate_cb(coap_server_ssl_ctx, CalcCoapServerCookie);
	SSL_CTX_set_cookie_verify_cb(coap_server_ssl_ctx, VerifyCoapServerCookie);
	SSL_CTX_set_session_cache_mode(coap_server_ssl_ctx, SSL_SESS_CACHE_OFF);

    // If code gets here then it was successful
    err = USP_ERR_OK;

exit:
    OS_UTILS_UnlockMutex(&coap_access_mutex);
    return err;
}

/*********************************************************************//**
**
** COAP_Destroy
**
** Frees all memory used by this component
**
** \param   None
**
** \return  None
**
**************************************************************************/
void COAP_Destroy(void)
{
    int i;
    coap_server_t *cs;
    coap_client_t *cc;
    
    OS_UTILS_LockMutex(&coap_access_mutex);

    // Free all CoAP clients
    for (i=0; i<MAX_COAP_CLIENTS; i++)
    {
        cc = &coap_clients[i];
        if (cc->cont_instance != INVALID)
        {
            COAP_StopClient(cc->cont_instance, cc->mtp_instance);
        }
    }

    // Free all CoAP servers
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if (cs->instance != INVALID)
        {
            COAP_StopServer(cs->instance, cs->interface, NULL);
        }
    }

    OS_UTILS_UnlockMutex(&coap_access_mutex);
}

/*********************************************************************//**
**
** COAP_StartServer
**
** Starts a CoAP Server on the specified interface and port
**
** \param   instance - instance number in Device.LocalAgent.MTP.{i} for this server
** \param   interface - Name of network interface to listen on ("any" indicates listen on all interfaces)
** \param   config - Configuration for CoAP server: port, resource and whether encryption is enabled
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int COAP_StartServer(int instance, char *interface, coap_config_t *config)
{
    coap_server_t *cs;
    int err = USP_ERR_OK;

    #define IS_ENCRYPTED_STRING(enc) (enc==true) ? "encrypted" : "unencrypted"
    USP_LOG_Info("%s: Starting CoAP server [%d] on interface=%s, port=%d (%s), resource=%s", __FUNCTION__, instance, interface, config->port, IS_ENCRYPTED_STRING(config->enable_encryption), config->resource);

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return USP_ERR_OK;
    }

    USP_ASSERT(FindCoapServerByInstance(instance, interface)==NULL);

    // Exit if unable to find a free CoAP server slot
    cs = FindUnusedCoapServer();
    if (cs == NULL)
    {
        USP_LOG_Error("%s: Out of CoAP servers when trying to add CoAP server for interface=%s, port %d", __FUNCTION__, interface, config->port);
        err = USP_ERR_RESOURCES_EXCEEDED;
        goto exit;
    }

    // Initialise the coap server structure, marking it as in-use
    memset(cs, 0, sizeof(coap_server_t));
    cs->instance = instance;
    cs->socket_fd = INVALID;
    USP_STRNCPY(cs->interface, interface, sizeof(cs->interface));
    cs->listen_port = config->port;
    cs->listen_resource = USP_STRDUP(config->resource);
    cs->enable_encryption = config->enable_encryption;

    // Start the server, ignoring any errors, as UpdateCoapServerInterfaces() will retry later
    (void)StartCoapServer(cs);
    err = USP_ERR_OK;

exit:
    OS_UTILS_UnlockMutex(&coap_access_mutex);

    // Cause the MTP thread to wakeup from select() so that timeouts get recalculated based on the new state
    // We do this outside of the mutex lock to avoid an unnecessary task switch
    if (err == USP_ERR_OK)
    {
        MTP_EXEC_Wakeup();
    }

    return err;
}

/*********************************************************************//**
**
** COAP_StopServer
**
** Stops all matching CoAP Servers
** NOTE: It is safe to call this function, if the instance has already been stopped
**
** \param   instance - instance number in Device.LocalAgent.MTP.{i} for this server
** \param   interface - Name of network interface to listen on ("any" indicates listen on all interfaces)
** \param   unused - input argumentto make the signature of this function the same as COAP_StartServer
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int COAP_StopServer(int instance, char *interface, coap_config_t *unused)
{
    coap_server_t *cs;

    USP_LOG_Info("%s: Stopping CoAP server [%d]", __FUNCTION__, instance);

    (void)unused;   // Prevent compiler warnings about unused variables
    
    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return USP_ERR_OK;
    }

    // Exit if the Coap server has already been stopped - nothing more to do
    cs = FindCoapServerByInstance(instance, interface);
    if (cs == NULL)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return USP_ERR_OK;
    }

    // Close the socket and any associated SSL, BIO objects
    CloseCoapServerSocket(cs);

    // Free all dynamically allocated buffers    
    USP_SAFE_FREE(cs->listen_resource);
    USP_SAFE_FREE(cs->usp_buf);

    // Put back to init state
    memset(cs, 0, sizeof(coap_server_t));
    cs->instance = INVALID;

    OS_UTILS_UnlockMutex(&coap_access_mutex);

    // Cause the MTP thread to wakeup from select() so that timeouts get recalculated based on the new state
    // We do this outside of the mutex lock to avoid an unnecessary task switch
    MTP_EXEC_Wakeup();

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** COAP_GetServerStatus
**
** Function called to get the value of Device.LocalAgent.MTP.{i}.Status
**
** \param   instance - instance number in Device.LocalAgent.MTP.{i} for this server
**
** \return  Status of this CoAP server
**
**************************************************************************/
mtp_status_t COAP_GetServerStatus(int instance)
{
    coap_server_t *cs;
    mtp_status_t status;

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return kMtpStatus_Down;
    }

    // Exit if we cannot find a CoAP server with this instance - creation of the server had previously failed
    cs = FindCoapServerByInstance(instance, NULL);
    if (cs == NULL)
    {
        status = kMtpStatus_Down;
        goto exit;
    }

    // If creation of the server had previously completed, then this CoAP server is up and running
    status = kMtpStatus_Up;

exit:
    OS_UTILS_UnlockMutex(&coap_access_mutex);
    return status;
}

/*********************************************************************//**
**
** COAP_StartClient
**
** Starts a CoAP Client to send USP messages to the specified controller
**
** \param   cont_instance -  Instance number of the controller in Device.LocalAgent.Controller.{i}
** \param   mtp_instance -   Instance number of this MTP in Device.LocalAgent.Controller.{i}.MTP.{i}
** \param   endpoint_id - endpoint of controller (used only for debug)
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int COAP_StartClient(int cont_instance, int mtp_instance, char *endpoint_id)
{
    coap_client_t *cc;
    int err = USP_ERR_INTERNAL_ERROR;

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return USP_ERR_OK;
    }

    USP_ASSERT(FindCoapClientByInstance(cont_instance, mtp_instance)==NULL);

    // Exit if unable to find a free CoAP client slot
    cc = FindUnusedCoapClient();
    if (cc == NULL)
    {
        USP_LOG_Error("%s: Out of CoAP clients for controller endpoint %s (Device.LocalAgent.Controller.%d.MTP.%d.CoAP)", __FUNCTION__, endpoint_id, cont_instance, mtp_instance);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    cc->ssl = NULL;
    cc->bio = NULL;

    cc->cont_instance = cont_instance;
    cc->mtp_instance = mtp_instance;
    cc->socket_fd = INVALID;
    cc->message_id = rand_r(&mtp_thread_random_seed) & 0xFFFF;
    cc->reconnect_time = INVALID_TIME;
    cc->reconnect_count = 0;
    cc->reconnect_timeout_ms = CalcCoapInitialTimeout();
    
    cc->linger_time = INVALID_TIME;

    err = USP_ERR_OK;

exit:
    OS_UTILS_UnlockMutex(&coap_access_mutex);

    // Cause the MTP thread to wakeup from select() so that timeouts get recalculated based on the new state
    // We do this outside of the mutex lock to avoid an unnecessary task switch
    if (err == USP_ERR_OK)
    {
        MTP_EXEC_Wakeup();
    }

    return err;
}

/*********************************************************************//**
**
** COAP_StopClient
**
** Stops the specified CoAP client
** NOTE: It is safe to call this function, if the instance has already been stopped
**
** \param   cont_instance -  Instance number of the controller in Device.LocalAgent.Controller.{i}
** \param   mtp_instance -   Instance number of this MTP in Device.LocalAgent.Controller.{i}.MTP.{i}
**
** \return  None
**
**************************************************************************/
void COAP_StopClient(int cont_instance, int mtp_instance)
{
    coap_client_t *cc;
    coap_send_item_t *csi;
    coap_send_item_t *next;

    USP_LOG_Info("%s: Stopping CoAP client [controller_instance=%d, mtp_instance=%d]", __FUNCTION__, cont_instance, mtp_instance);

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return;
    }

    // Exit if the Coap controller has already been stopped - nothing more to do
    cc = FindCoapClientByInstance(cont_instance, mtp_instance);
    if (cc == NULL)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return;
    }

    CloseCoapClientSocket(cc);

    // Drain the queue of outstanding messages to send
    csi = (coap_send_item_t *) cc->send_queue.head;
    while (csi != NULL)
    {
        next = (coap_send_item_t *) csi->link.next;
        FreeFirstCoapSendItem(cc);

        // Move to next item in queue
        csi = next;
    }

    // Put back to init state
    memset(cc, 0, sizeof(coap_client_t));
    cc->cont_instance = INVALID;
    cc->socket_fd = INVALID;

    OS_UTILS_UnlockMutex(&coap_access_mutex);

    // Cause the MTP thread to wakeup from select() so that timeouts get recalculated based on the new state
    // We do this outside of the mutex lock to avoid an unnecessary task switch
    MTP_EXEC_Wakeup();
}

/*********************************************************************//**
**
** COAP_UpdateAllSockSet
**
** Updates the set of all COAP socket fds to read/write from
**
** \param   set - pointer to socket set structure to update with sockets to wait for activity on
**
** \return  None
**
**************************************************************************/
void COAP_UpdateAllSockSet(socket_set_t *set)
{
    int i;
    coap_client_t *cc;
    coap_server_t *cs;
    time_t cur_time;
    int timeout;        // timeout in milliseconds

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Determine whether IP address of any of CoAP servers has changed (if time to poll it)
    timeout = UpdateCoapServerInterfaces();
    SOCKET_SET_UpdateTimeout(timeout*SECONDS, set);

    cur_time = time(NULL);
    #define CALC_TIMEOUT(res, t) res = t - cur_time; if (res < 0) { res = 0; }
    
    // Add all CoAP client sockets (these receive CoAP ACK packets from the controller)
    for (i=0; i<MAX_COAP_CLIENTS; i++)
    {
        cc = &coap_clients[i];
        if (cc->cont_instance != INVALID)
        {
            if (cc->socket_fd != INVALID)
            {
                // If keeping socket open in case a new USP Record becomes ready to send...
                timeout = MAX_SOCKET_TIMEOUT_SECONDS;
                if (cc->linger_time != INVALID_TIME)
                {
                    CALC_TIMEOUT(timeout, cc->linger_time);
                }
                else if (cc->ack_timeout_time != INVALID_TIME)
                {
                    // Wait until timeout on receiving an ACK on this socket
                    CALC_TIMEOUT(timeout, cc->ack_timeout_time);
                }

                SOCKET_SET_AddSocketToReceiveFrom(cc->socket_fd, timeout*1000, set);
            }
            else
            {
                // We were unable to connect to the controller last time, so wait until timeout, then try again
                if (cc->reconnect_time != INVALID_TIME)
                {
                    CALC_TIMEOUT(timeout, cc->reconnect_time);
                    SOCKET_SET_UpdateTimeout(timeout*1000, set);
                }
            }
        }
    }

    // Add all CoAP server sockets (these receive CoAP BLOCK packets from the controller)
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if ((cs->instance != INVALID) && (cs->socket_fd != INVALID))
        {
            // Wait until timeout aborting the current USP record reception, or forever (if not in the middle of receiving a USP Record)
            timeout = MAX_SOCKET_TIMEOUT_SECONDS;
            if (cs->abort_timeout_time != INVALID_TIME)
            {
                CALC_TIMEOUT(timeout, cs->abort_timeout_time);
            }
            else if (cs->linger_time != INVALID_TIME)
            {
                CALC_TIMEOUT(timeout, cs->linger_time);
            }

            SOCKET_SET_AddSocketToReceiveFrom(cs->socket_fd, timeout*1000, set);
        }
    }

    OS_UTILS_UnlockMutex(&coap_access_mutex);
}

/*********************************************************************//**
**
** COAP_ProcessAllSocketActivity
**
** Processes the socket for the specified controller
**
** \param   set - pointer to socket set structure containing the sockets which need processing
**
** \return  Nothing
**
**************************************************************************/
void COAP_ProcessAllSocketActivity(socket_set_t *set)
{
    int i;
    coap_client_t *cc;
    coap_server_t *cs;
    time_t cur_time;

    OS_UTILS_LockMutex(&coap_access_mutex);

    cur_time = time(NULL);

    // Exit if MTP thread has exited
    // NOTE: This check should be unnecessary, as this function is only called from the MTP thread
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return;
    }

    // Service all CoAP client sockets (these receive CoAP ACK packets from the controller)
    for (i=0; i<MAX_COAP_CLIENTS; i++)
    {
        cc = &coap_clients[i];
        if (cc->cont_instance != INVALID)
        {
            if (cc->socket_fd != INVALID)
            {
                if (SOCKET_SET_IsReadyToRead(cc->socket_fd, set))
                {
                    // Handle ACK received
                    HandleCoapAck(cc);
                }
                else if ((cc->ack_timeout_time != INVALID_TIME) && (cur_time >= cc->ack_timeout_time))
                {
                    // Handle ACK not received within timeout period
                    HandleNoCoapAck(cc);
                }
                else if ((cc->linger_time != INVALID_TIME) && (cur_time >= cc->linger_time))
                {
                    // Handle closing down socket after linger period
                    USP_PROTOCOL("%s: Closing down CoAP client socket after linger period", __FUNCTION__);
                    StopSendingToController(cc);
                }
            }
            else
            {
                // Retry connecting to controller's CoAP server
                if ((cc->reconnect_time != INVALID_TIME) && (cur_time >= cc->reconnect_time))
                {
                    StartSendingCoapUspRecord(cc, RETRY_CURRENT);
                }
            }
        }
    }

    // Service all CoAP server sockets (these receive CoAP BLOCK packets from the controller)
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if ((cs->instance != INVALID) && (cs->socket_fd != INVALID))
        {
            if (SOCKET_SET_IsReadyToRead(cs->socket_fd, set))
            {
                if (cs->is_session_started==false)
                {
                    if (cs->enable_encryption)
                    {
                        PerformServerDtlsConnect(cs);
                    }
                    else
                    {
                        PerformServerConnect(cs);
                    }
                }
                else
                {
                    ReceiveCoapBlock(cs);
                }
            }
            else if ((cs->abort_timeout_time != INVALID_TIME) && (cur_time >= cs->abort_timeout_time))
            {
                // Handle timing out on receiving a full USP Record
                USP_LOG_Error("%s: CoAP Server timeout. Dropping partially received USP Record (%d bytes)", __FUNCTION__, cs->usp_buf_len);
                ResetCoapServer(cs);
            }
            else if ((cs->linger_time != INVALID_TIME) && (cur_time >= cs->linger_time))
            {
                // Handle case of no communications for a while, closing down the connected (possibly DTLS) UDP socket
                USP_PROTOCOL("%s: Resetting CoAP server socket ([%d] %s) after linger period", __FUNCTION__, cs->instance, cs->interface);
                ResetCoapServer(cs);
            }
        }
    }

    OS_UTILS_UnlockMutex(&coap_access_mutex);
}

/*********************************************************************//**
**
** COAP_QueueBinaryMessage
**
** Function called to queue a message to send to the specified controller (over CoAP)
**
** \param   usp_msg_type - Type of USP message contained in pbuf. This is used for debug logging when the message is sent by the MTP.
** \param   cont_instance -  Instance number of the controller in Device.LocalAgent.Controller.{i}
** \param   mtp_instance -   Instance number of this MTP in Device.LocalAgent.Controller.{i}.MTP.{i}
** \param   pbuf - pointer to buffer containing binary protobuf message. Ownership of this buffer passes to this code, if successful
** \param   pbuf_len - length of buffer containing protobuf binary message
** \param   mrt - pointer to structure containing CoAP parameters describing CoAP destination to send to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int COAP_QueueBinaryMessage(Usp__Header__MsgType usp_msg_type, int cont_instance, int mtp_instance, unsigned char *pbuf, int pbuf_len, mtp_reply_to_t *mrt)
{
    coap_client_t *cc;
    coap_send_item_t *csi;
    int err;
    bool is_duplicate;

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    // NOTE: This check should be unnecessary, as this function is only called from the MTP thread
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return USP_ERR_OK;
    }

    // Exit if unable to find the controller MTP queue for this message
    cc = FindCoapClientByInstance(cont_instance, mtp_instance);
    if (cc == NULL)
    {
        USP_LOG_Error("%s: FindCoapClientByInstance() failed for controller=%d (mtp=%d)", __FUNCTION__, cont_instance, mtp_instance);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Do not add this message to the queue, if it is already present in the queue
    // This situation could occur if a notify is being retried to be sent, but is already held up in the queue pending sending
    is_duplicate = IsUspRecordInCoapQueue(cc, pbuf, pbuf_len);
    if (is_duplicate)
    {
        err = USP_ERR_OK;
        goto exit;
    }

    csi = USP_MALLOC(sizeof(coap_send_item_t));
    csi->usp_msg_type = usp_msg_type;
    csi->pbuf = pbuf;
    csi->pbuf_len = pbuf_len;
    csi->host = USP_STRDUP(mrt->coap_host);
    csi->config.port = mrt->coap_port;
    csi->config.resource = USP_STRDUP(mrt->coap_resource);
    csi->config.enable_encryption = mrt->coap_encryption;
    csi->coap_reset_session_hint = mrt->coap_reset_session_hint;

    DLLIST_LinkToTail(&cc->send_queue, csi);

    // If the queue was empty, then this will be the first item in the queue
    // So send out this item
    if (cc->send_queue.head == (void *)csi)
    {
        StartSendingCoapUspRecord(cc, SEND_CURRENT);
    }

    err = USP_ERR_OK;

exit:
    OS_UTILS_UnlockMutex(&coap_access_mutex);

    // If successful, cause the MTP thread to wakeup from select().
    // We do this outside of the mutex lock to avoid an unnecessary task switch
    if (err == USP_ERR_OK)
    {
        MTP_EXEC_Wakeup();
    }

    return err;
}

/*********************************************************************//**
**
** COAP_AreAllResponsesSent
**
** Determines whether all responses have been sent, and that there are no outstanding incoming messages
**
** \param   None
**
** \return  true if all responses have been sent
**
**************************************************************************/
bool COAP_AreAllResponsesSent(void)
{
    int i;
    coap_client_t *cc;
    coap_server_t *cs;
    bool all_responses_sent = true;  // Assume that all responses have been sent on all connections

    OS_UTILS_LockMutex(&coap_access_mutex);

    // Exit if MTP thread has exited
    // NOTE: This check is not strictly ncessary, as only the MTP thread should be calling this function
    if (is_mtp_thread_exited)
    {
        OS_UTILS_UnlockMutex(&coap_access_mutex);
        return true;
    }

    // Iterate over all CoAP clients, seeing if there are any messages which are still being sent out and have not been fully acknowledged
    for (i=0; i<MAX_COAP_CLIENTS; i++)
    {
        cc = &coap_clients[i];
        if (cc->cont_instance != INVALID)
        {
            if (cc->send_queue.head != NULL)
            {
                all_responses_sent = false;
            }
        }
    }

    // Iterate over all CoAP servers, seeing if any are currently receiving messages
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if (cs->instance != INVALID)
        {
            if (cs->usp_buf_len != 0)
            {
                all_responses_sent = false;
            }
        }
    }

    OS_UTILS_UnlockMutex(&coap_access_mutex);

    return all_responses_sent;
}

/*********************************************************************//**
**
** StartCoapServer
**
** Starts the specified CoAP Server
**
** \param   cs - pointer to coap server to start
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int StartCoapServer(coap_server_t *cs)
{
    nu_ipaddr_t nu_intf_addr;
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    sa_family_t family;
    int result;
    int err;
    bool prefer_ipv6;

    // Get preference for IPv4 or IPv6 WAN address (in case of Dual Stack CPE)
    prefer_ipv6 = DEVICE_LOCAL_AGENT_GetDualStackPreference();

    // Exit if unable to get current IP address for specified network interface
    err = tw_ulib_get_dev_ipaddr(cs->interface, cs->listen_addr, sizeof(cs->listen_addr), prefer_ipv6);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: CoAP server's listening interface on %s is down. Retrying later", __FUNCTION__, cs->interface);
        goto exit;
    }

    // Initialise member variables, so that if this function fails, the coap server structure is in a known state
    cs->socket_fd = INVALID;
    InitCoapServerForNewPeer(cs);

    // Exit if unable to convert the interface address into an nu_ipaddr structure
    err = nu_ipaddr_from_str(cs->listen_addr, &nu_intf_addr);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: Unable to convert IP address (%s)", __FUNCTION__, cs->interface);
        goto exit;
    }

    // Exit if unable to make a socket address structure to bind to
    err = nu_ipaddr_to_sockaddr(&nu_intf_addr, cs->listen_port, &saddr, &saddr_len);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }
    
    // Exit if unable to determine which address family to use when creating the listening socket
    err = nu_ipaddr_get_family(&nu_intf_addr, &family);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if unable to create the listening socket
    cs->socket_fd = socket(family, SOCK_DGRAM, 0);
    if (cs->socket_fd == -1)
    {
        USP_ERR_ERRNO("socket", errno);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Exit if unable to bind to the listening socket
    result = bind(cs->socket_fd, (struct sockaddr *) &saddr, saddr_len);
    if (result != 0)
    {
        // Here we retry to bind again - Linux sometimes doesn't immediately mark the previous UDP bind as closed
        // The alternative to this code would be to use SO_REUSEADDR. However we should never be sharing the bound port, so if we did we'd want an error
        usleep(0);
        result = bind(cs->socket_fd, (struct sockaddr *) &saddr, saddr_len);
        if (result != 0)
        {
            USP_ERR_ERRNO("bind", errno);
            CloseCoapServerSocket(cs);
            err = USP_ERR_INTERNAL_ERROR;
            goto exit;
        }
    }

    // Connect the socket to OpenSSL, if required
    if (cs->enable_encryption)
    {
        err = AddCoapServerSSL(cs);
        if (err != USP_ERR_OK)
        {
            CloseCoapServerSocket(cs);
            goto exit;
        }
    }

    // If the code gets here, then the server was started successfully
    err = USP_ERR_OK;

exit:
    // If an error occurred, mark the server as not listening on any address, this will cause UpdateCoapServerInterfaces() 
    // to periodically try to restart the server, when the interface has an IP address
    if (err != USP_ERR_OK)
    {
        cs->listen_addr[0] = '\0';
    }

    return err;
}

/*********************************************************************//**
**
** InitCoapServerForNewPeer
**
** Initialises the CoAP server structure for receiving from a new peer
** Crucially it does not reset any of the configuration parameters, or the socket
**
** \param   cs - pointer to structure describing coap server
**
** \return  None
**
**************************************************************************/
void InitCoapServerForNewPeer(coap_server_t *cs)
{
    cs->is_session_started = false;
    cs->ssl = NULL;
    cs->bio = NULL;
    cs->is_first_usp_msg = true;
    cs->cert_chain = NULL;
    cs->allowed_controllers = NULL;
    cs->role = ROLE_DEFAULT;    // Set default role, if not determined from SSL certs
    memset(&cs->peer_addr, 0, sizeof(cs->peer_addr));
    cs->peer_port = INVALID;
    memset(&cs->token, 0, sizeof(cs->token));
    cs->token_size = 0;
    cs->block_count = 0;
    cs->block_size = 0;
    cs->usp_buf = NULL;
    cs->usp_buf_len = 0;
    cs->last_message_id = INVALID;
    cs->last_message_len = 0;
    cs->abort_timeout_time = INVALID_TIME;
    cs->linger_time = INVALID_TIME;
}

/*********************************************************************//**
**
** PerformServerConnect
**
** Function called to connect the socket to the remote peer
** This is called only after our CoAP server receives a packet
** This is done to make the code for unencrypted similar to that for encrypted
** It also ensures that we can only receive a USP Record from one controller at a time
**
** \param   cs - pointer to structure describing coap server
**
** \return  None
**
**************************************************************************/
void PerformServerConnect(coap_server_t *cs)
{
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    nu_ipaddr_t peer_addr;
    uint16_t peer_port;
    int len;
    int result;
    int err;
    unsigned char buf[1];

    USP_ASSERT(cs->block_count == 0);

    // Exit if unable to peek the peer's address
    memset(&saddr, 0, sizeof(saddr));
    saddr_len = sizeof(saddr);
    len = recvfrom(cs->socket_fd, buf, sizeof(buf), MSG_PEEK, (struct sockaddr *) &saddr, &saddr_len);
    if (len == -1)
    {
        USP_ERR_ERRNO("recv", errno);
        ResetCoapServer(cs);
        return;
    }

    // Exit if unable to explicitly connect this listening socket to the remote peer
    result = connect(cs->socket_fd, (struct sockaddr *) &saddr, saddr_len);
    if (result != 0)
    {
        USP_ERR_ERRNO("connect", errno);
        ResetCoapServer(cs);
        return;
    }

    // Exit if unable to convert sockaddr structure to IP address and port used by controller that sent us this PDU
    err = nu_ipaddr_from_sockaddr_storage(&saddr, &peer_addr, &peer_port);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: nu_ipaddr_from_sockaddr_storage() failed", __FUNCTION__);
        ResetCoapServer(cs);
        return;
    }
    
    // Store the peer's IP address and port
    memcpy(&cs->peer_addr, &peer_addr, sizeof(peer_addr));
    cs->peer_port = peer_port;

    // Set role to use when processing USP messages received by this CoAP server
    cs->role = ROLE_NON_SSL;

    // Session is successfully established with the remote peer
    cs->is_session_started = true;

    // Now actually handle the block we've received
    ReceiveCoapBlock(cs);
}

/*********************************************************************//**
**
** PerformServerDtlsConnect
**
** Function called to perform the DTLS Handshake when receiving from a controller
** This is called only after our CoAP server receives a packet
**
** \param   cc - pointer to structure describing controller to receive from
**
** \return  None
**
**************************************************************************/
void PerformServerDtlsConnect(coap_server_t *cs)
{
    int result;
    int err;
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    char buf[NU_IPADDRSTRLEN];
    struct timeval timeout;

    // Set timeouts for DTLSv1_listen() and SSL_accept()
    timeout.tv_sec = DTLS_READ_TIMEOUT;
    timeout.tv_usec = 0;
    BIO_ctrl(cs->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    // Exit if an error occurred when listening to the server socket
    // DTLSv1_listen() responds to the 'ClientHello' by sending a 'Hello Verify Request' containing a cookie
    // then waits for the peer to sent back the 'Client Hello' with the cookie
    result = DTLSv1_listen(cs->ssl, (void *) &saddr);
    if (result < 0)
    {
        err = SSL_get_error(cs->ssl, result);
        USP_LOG_ErrorSSL(__FUNCTION__, "DTLSv1_listen() failed. Resetting CoAP server.", result, err);
        ResetCoapServer(cs);
        return;
    }

    // Exit if no packet was received (Note: This shouldn't happen as we should have only got here if a packet was ready to read)
    if (result == 0)
    {
        USP_LOG_Warning("%s: DTLSv1_listen() returned 0. Resetting CoAP server", __FUNCTION__);
        ResetCoapServer(cs);
        return;
    }

    // Exit if unable to get the peer's IP address and port
    err = nu_ipaddr_from_sockaddr_storage(&saddr, &cs->peer_addr, &cs->peer_port);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: nu_ipaddr_from_sockaddr_storage() failed. Resetting CoAP server", __FUNCTION__);
        ResetCoapServer(cs);
        return;
    }

    USP_PROTOCOL("%s: Accepting CoAP DTLS handshake from %s, port %d", __FUNCTION__, nu_ipaddr_str(&cs->peer_addr, buf, sizeof(buf)), cs->peer_port);

    // Exit if unable to convert the peer's IP address back to a sockaddr_storage structure
    err = nu_ipaddr_to_sockaddr(&cs->peer_addr, cs->peer_port, &saddr, &saddr_len);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: nu_ipaddr_to_sockaddr() failed. Resetting CoAP server", __FUNCTION__);
        ResetCoapServer(cs);
        return;
    }
    
    // Exit if unable to explicitly connect this listening socket to the remote peer
    result = connect(cs->socket_fd, (struct sockaddr *) &saddr, saddr_len);
    if (result != 0)
    {
        USP_ERR_ERRNO("connect", errno);
        ResetCoapServer(cs);
        return;
    }

    // Set the SSL BIO object to be connected
    BIO_ctrl(cs->bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &saddr);

    // The following is needed for compatibility with libcoap
    // If not set, then the DTLS handshake takes a number of seconds to complete, as our OpenSSL server tries successively smaller MTUs
    // Also the maximum MTU size must be set after DTLSv1_listen(), because DTLSv1_listen() resets it
    SSL_set_mtu(cs->ssl, MAX_COAP_PDU_SIZE);

    // Exit if unable to finish the DTLS handshake
    // Sends the 'ServerHello' containing server Certificate, client certificate request, and ending in 'ServerHelloDone'
    // Then waits for SSL Handshake message and finally sends a NewSessionTicket
    // NOTE: This agent must have its own cert (same as STOMP client cert), otherwise SSL_accept complains that there's 'no shared cipher'
    result = SSL_accept(cs->ssl);
    if (result < 0)
    {
        err = SSL_get_error(cs->ssl, result);
        USP_LOG_ErrorSSL(__FUNCTION__, "SSL_accept() failed. Resetting CoAP server", result, err);
        ResetCoapServer(cs);
        return;
    }

    // If we have a certificate chain, then determine which role to allow for controllers on this CoAP connection
    if (cs->cert_chain != NULL)
    {
        // Exit if unable to determine the role associated with the trusted root cert that signed the peer cert
        err = DEVICE_SECURITY_GetControllerTrust(cs->cert_chain, &cs->role, &cs->allowed_controllers);
        if (err != USP_ERR_OK)
        {
            USP_LOG_Error("%s: DEVICE_SECURITY_GetControllerTrust() failed. Resetting CoAP server", __FUNCTION__);
            ResetCoapServer(cs);
            return;
        }
    }

    // Handshake has completed successfully and session has been successfully established with the remote peer
    cs->is_session_started = true;
}

/*********************************************************************//**
**
** ReceiveCoapBlock
**
** Reads a CoAP PDU containing part of a USP message, sent from a controller
** This is expected to be a BLOCK or a single CoAP POST message
**
** \param   cs - coap server on which to process the received CoAP PDU
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void ReceiveCoapBlock(coap_server_t *cs)
{
    unsigned char buf[MAX_COAP_PDU_SIZE];
    int len;
    parsed_pdu_t pp;
    unsigned action_flags;
    int err;
    bool from_same_peer;

    USP_ASSERT(cs->is_session_started==true);

    // Exit if whilst an encrypted connection is lingering we received a packet from another peer (or port)
    // In this case, reset the SSL connection and state machine (without consuming the packet), so that the DTLS handshake may proceed
    // This is necessary to handle the case of DTLS CoAP clients which do not shut down gracefully
    from_same_peer = HandleDtlsLinger(cs);
    if (from_same_peer == false)
    {
        SwitchCoapServerToNewPeer(cs);
        return;
    }

    // Exit if the connection has been closed by the peer
    len = ReceiveCoapPdu(cs->ssl, cs->socket_fd, buf, sizeof(buf));
    if (len == -1)
    {
        if (cs->usp_buf_len == 0)
        {
            USP_PROTOCOL("%s: Connection closed gracefully by peer after it finished sending blocks", __FUNCTION__);
        }
        else
        {
            USP_LOG_Error("%s: Connection closed by peer or error. Dropping partially received USP Record (%d bytes)", __FUNCTION__, cs->usp_buf_len);
        }
        ResetCoapServer(cs);
        return;
    }

    // Exit if an error occurred whilst parsing the PDU
    memset(&pp, 0, sizeof(pp));
    pp.message_id = INVALID;
    pp.mtp_reply_to.protocol = kMtpProtocol_CoAP;

    action_flags = ParseCoapPdu(buf, len, &pp);
    if (action_flags != COAP_NO_ERROR)
    {
        goto exit;
    }

    // Determine what actions to take
    action_flags = CalcCoapServerActions(cs, &pp);

exit:
    // Perform the actions set in the action flags

    // Check that code does not set contradictory actions to perform in the action flags
    USP_ASSERT( (action_flags & (SEND_ACK | SEND_RST)) != (SEND_ACK | SEND_RST) );
    USP_ASSERT( ((action_flags & USP_RECORD_COMPLETE) == 0) || ((action_flags & (SEND_RST | INDICATE_ERR_IN_ACK | INDICATE_WELL_KNOWN | RESEND_LAST_RESPONSE | RESET_STATE)) == 0) );

    // Send a CoAP RST if required
    if (action_flags & SEND_RST)
    {
        (void)SendCoapRstFromServer(cs, &pp);   // Intentionlly ignoring error, as we will reset the CoAP server anyway
        action_flags |= RESET_STATE;
    }

    // Resend the last CoAP PDU (ACK or RST) if required
    if (action_flags & RESEND_LAST_RESPONSE)
    {
        err = SendCoapPdu(cs->ssl, cs->socket_fd, cs->last_message, cs->last_message_len);
        if (err != USP_ERR_OK)
        {
            action_flags |= RESET_STATE;        // Reset the connection if client disconnected
        }
    }

    // Send a CoAP ACK if required
    if (action_flags & SEND_ACK)
    {
        err = SendCoapAck(cs, &pp, action_flags);
        if ((err != USP_ERR_OK) || (action_flags & INDICATE_ERR_IN_ACK))
        {
            USP_LOG_Error("%s: Resetting agent's CoAP server after sending ACK indicating error, or unable to send ACK", __FUNCTION__);
            action_flags |= RESET_STATE;
        }
    }

    // Handle a complete USP record being received
    if (action_flags & USP_RECORD_COMPLETE)
    {
        // Log reception of message
        char time_buf[MAX_ISO8601_LEN];
        char addr_buf[NU_IPADDRSTRLEN];
        iso8601_cur_time(time_buf, sizeof(time_buf));
        nu_ipaddr_to_str(&cs->peer_addr, addr_buf, sizeof(addr_buf));
        USP_LOG_Info("Message received at time %s, from host %s over CoAP", time_buf, addr_buf);

        // Post complete USP record to the data model thread (as long as the peer address in the 'reply-to' matches that of the received packet)
        if (IsReplyToValid(cs, &pp))
        {
            // Create a copy of the reply-to details, modifying coap_host to be the IP literal peer address to send the response back to
            // (This is necessary as the peer's reply-to may be a hostname which has both IPv4 and IPv6 DNS records. We want to reply back using the same IP version we received on)
            mtp_reply_to_t mtp_reply_to;
            memcpy(&mtp_reply_to, &pp.mtp_reply_to, sizeof(mtp_reply_to));
            mtp_reply_to.coap_host = addr_buf;

            // The USP response message to this request should be sent back on a new DTLS session, if this USP request was received on a new DTLS session
            mtp_reply_to.coap_reset_session_hint = cs->is_first_usp_msg & cs->enable_encryption; 

            // Post the USP record for processing
            DM_EXEC_PostUspRecord(cs->usp_buf, cs->usp_buf_len, cs->role, cs->allowed_controllers, &mtp_reply_to);
        }
    }

    // Keep DTLS sessions connected if possible after receiving a complete message
    if (action_flags & (USP_RECORD_COMPLETE | INDICATE_WELL_KNOWN))
    {
        // Indicate that the next USP message received will be able to use the same CoAP client DTLS session
        // as the response to this USP message will use
        cs->is_first_usp_msg = false;

        if (cs->enable_encryption==false)
        {
            // If no encryption, then just reset our CoAP server to accept a new connection
            // NOTE: This code is different from when DTLS is enabled ('else' case below) because 
            // in the unencrypted, pure UDP case, we do not get any notification that the peer has disconnected
            action_flags |= RESET_STATE;
        }
        else
        {
            // Leave the connection open until closed down by the peer or the linger timeout or a new connection
            FreeReceivedUspRecord(cs);
            cs->linger_time = time(NULL) + COAP_SERVER_LINGER_PERIOD;

            // If encryption is enabled, then the peer should send an alert when closing gracefully
            // However many peers do not shutdown gracefully, so to allow new connections to take precedence
            // during the linger period, we switch the socket back into unconnected mode and monitor for new connections
            struct sockaddr sa;
            memset(&sa, 0, sizeof(sa));
            sa.sa_family = AF_UNSPEC;
            err = connect(cs->socket_fd, &sa, sizeof(sa));
            if (err != 0)
            {
                // If unable to change the socket back to unconnected, then close down the connection
                USP_ERR_ERRNO("connect", errno);
                action_flags |= RESET_STATE;
            }
        }
    }

    // Reset state back to waiting for first block of a USP record, if peer sent a RST
    // or an error occurred when sending an ACK, or we're listening for a new connection
    if (action_flags & RESET_STATE)
    {
        ResetCoapServer(cs);
    }
}

/*********************************************************************//**
**
** HandleDtlsLinger
**
** Handles packets received whilst lingering on a DTLS socket
** Determines whether a block has been received from a different peer
** whilst DTLS is in the linger period. 
** If it has, then reset the socket, to allow the new peer (after resending) to connect
** Otherwise
**
** \param   cs - coap server on which to process the received CoAP PDU
**
** \return  true if the packet was received from the current peer
**
**************************************************************************/
bool HandleDtlsLinger(coap_server_t *cs)
{
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    nu_ipaddr_t peer_addr;
    uint16_t peer_port;
    int len;
    int err;
    unsigned char buf[1];

    // Exit if the connection is not DTLS and not lingering.
    // In this case the packet will have been received from the current peer as the socket is connected
    if ((cs->enable_encryption == false) || (cs->linger_time == INVALID))
    {
        return true;
    }

    // Exit if unable to peek the peer's address
    memset(&saddr, 0, sizeof(saddr));
    saddr_len = sizeof(saddr);
    len = recvfrom(cs->socket_fd, buf, sizeof(buf), MSG_PEEK, (struct sockaddr *) &saddr, &saddr_len);
    if (len == -1)
    {
        USP_ERR_ERRNO("recv", errno);
        return false;
    }

    // Exit if unable to convert sockaddr structure to IP address and port used by controller that sent us this PDU
    err = nu_ipaddr_from_sockaddr_storage(&saddr, &peer_addr, &peer_port);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: nu_ipaddr_from_sockaddr_storage() failed", __FUNCTION__);
        return false;
    }

    // Exit if the packet didn't come from the port and peer as the SSL connection is on
    if ((peer_port != cs->peer_port) || (memcmp(&peer_addr, &cs->peer_addr, sizeof(peer_addr)) != 0))
    {
        USP_LOG_Warning("%s: Resetting agent's CoAP server after receiving from new peer during DTLS linger period", __FUNCTION__);
        return false;
    }

    // If the code gets here, then we received a packet from the same peer that we are already SSL connected to
    // So put the socket back into connected mode
    err = connect(cs->socket_fd, (struct sockaddr *) &saddr, saddr_len);
    if (err != 0)
    {
        USP_ERR_ERRNO("connect", errno);
        return false;
    }

    // Indicate to caller to process the packet that has just been received
    return true;
}

/*********************************************************************//**
**
** ResetCoapServer
**
** This function resets the state of the CoAP server, discarding any partially received USP record
** and disconnecting from any client. On finishing the (new) listening socket is not connected to any client
** It is called after receiving a full USP Record from a controller or 
** after timing out reception of a partially received USP record
**
** \param   cs - pointer to structure describing coap server to update
**
** \return  None
**
**************************************************************************/
void ResetCoapServer(coap_server_t *cs)
{
    int err;

    // Free the USP record that has been received, setting state back, so that we can start receiving a new one
    FreeReceivedUspRecord(cs);

    // Close down the connected socket and associated SSL, BIO objects
    CloseCoapServerSocket(cs);
    cs->is_session_started = false;

    // Now restart the server, listening for CoAP PDUs
    err = StartCoapServer(cs);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: Unable to reset CoAP server listening on interface %s (port %d). Retrying later.", __FUNCTION__, cs->interface, cs->listen_port);
    }
}

/*********************************************************************//**
**
** SwitchCoapServerToNewPeer
**
** This function switches the coap server to a new peer
**
** \param   cs - pointer to structure describing coap server to update
**
** \return  None
**
**************************************************************************/
void SwitchCoapServerToNewPeer(coap_server_t *cs)
{
    int err;

    // Free any USP record that has been parially received, setting state back, so that we can start receiving a new one
    FreeReceivedUspRecord(cs);

    // Free the SSL object and associated data
    RemoveCoapServerSSL(cs);

    // Initialise member variables, so that if this function fails, the coap server structure is in a known state
    InitCoapServerForNewPeer(cs);

    // Connect the socket to OpenSSL, if required
    if (cs->enable_encryption)
    {
        // If an error occurred, close the server and mark it as not listening on any address, this will cause UpdateCoapServerInterfaces() 
        // to periodically try to restart the server, when the interface has an IP address
        err = AddCoapServerSSL(cs);
        if (err != USP_ERR_OK)
        {
            CloseCoapServerSocket(cs);
            cs->listen_addr[0] = '\0';
        }
    }
}

/*********************************************************************//**
**
** FreeReceivedUspRecord
**
** Frees the USP Record that has been received (or partially received) and sets the block count
** state back to allow reception of a new USP Record
**
** \param   cs - pointer to structure describing coap server to update
**
** \return  action flags determining what actions to take
**
**************************************************************************/
void FreeReceivedUspRecord(coap_server_t *cs)
{
    // Free any partially received USP Record
    if (cs->usp_buf != NULL)
    {
        USP_FREE(cs->usp_buf);
        cs->usp_buf = NULL;
    }

    cs->usp_buf_len = 0;
    cs->block_count = 0;
    cs->block_size = 0;
    cs->abort_timeout_time = INVALID_TIME;
}

/*********************************************************************//**
**
** CalcCoapServerActions
**
** Determines what actions to take after the CoAP server received a PDU
** NOTE: The caller has already checked that the PDU is from the peer sending messages to us
**
** \param   cs - pointer to structure describing coap server to update
** \param   pp - pointer to structure containing the parsed CoAP PDU
**
** \return  action flags determining what actions to take
**
**************************************************************************/
unsigned CalcCoapServerActions(coap_server_t *cs, parsed_pdu_t *pp)
{
    unsigned action_flags;

    // Exit if we've already received this PDU before. Resend the response, because the original response might have gone missing
    // NOTE: This could happen under normal circumstances, so isn't an error
    if (pp->message_id == cs->last_message_id)
    {
        USP_PROTOCOL("%s: Already received CoAP PDU (MID=%d) (Resending response)", __FUNCTION__, pp->message_id);
        return RESEND_LAST_RESPONSE;
    }

    // Exit if we received a RST
    if (pp->pdu_type == kPduType_Reset)
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) was a RST (pdu_type=%d)", __FUNCTION__, pp->message_id, pp->pdu_type);
        return RESET_STATE;
    }

    // Exit if our server received an ACK or a 'Non-Confirmable'
    if ((pp->pdu_type == kPduType_Acknowledgement) || (pp->pdu_type == kPduType_NonConfirmable))
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) was not of the expected type (pdu_type=%d)", __FUNCTION__, pp->message_id, pp->pdu_type);
        return SEND_RST;        // Send RST for unhandled non-confirmable messages (RFC7252 section 4.3, page 23)
    }

    // If the code gets here, then a 'Confirmable' PDU was received
    USP_ASSERT(pp->pdu_type == kPduType_Confirmable);

    // Exit if CoAP PDU wasn't of expected class
    if (pp->pdu_class != kPduClass_Request)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) was not of the expected class (pdu_class=%d)", __FUNCTION__, pp->message_id, pp->pdu_class);
        return SEND_RST;
    }

    // Exit if CoAP PDU was the special case of resource discovery using a GET of '.well-known/core'
    if ((pp->request_response_code == kPduRequestMethod_Get) && (strcmp(pp->uri_path, ".well-known/core")==0))
    {
        SetCoapErrMessage("</%s>;if=\"bbf.usp.a\";rt=\"bbf.usp.endpoint\";title=\"USP Agent\";ct=42", cs->listen_resource);
        return SEND_ACK | INDICATE_WELL_KNOWN;
    }

    // Exit if CoAP PDU wasn't of expected method
    if (pp->request_response_code != kPduRequestMethod_Post)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) was not of the expected method (pdu_method=%d)", __FUNCTION__, pp->message_id, pp->request_response_code);
        return SEND_ACK | INDICATE_BAD_METHOD;
    }

    // Handle the block, updating state and determining what to do at the end of this function
    if (cs->block_count == 0)
    {
        action_flags = HandleFirstCoapBlock(cs, pp);
    }
    else
    {
        action_flags = HandleSubsequentCoapBlock(cs, pp);
    }

    return action_flags;
}

/*********************************************************************//**
**
** HandleFirstCoapBlock
**
** Handles the first block received of a USP record
**
** \param   cs - pointer to CoAP server which received the payload we're appending
** \param   pp - pointer to parsed CoAP PDU
**
** \return  action flags determining what actions to take
**
**************************************************************************/
unsigned HandleFirstCoapBlock(coap_server_t *cs, parsed_pdu_t *pp)
{
    unsigned action_flags = SEND_ACK | USP_RECORD_COMPLETE;     // Assume there is no block option, or no more blocks
    unsigned temp_flags;

    // Exit if content format is incorrect for USP
    if ((pp->options_present & CONTENT_FORMAT_PRESENT) && (pp->content_format != kPduContentFormat_OctetStream))
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has unexpected content format for USP (content_format=%d)", __FUNCTION__, pp->message_id, pp->content_format);
        return SEND_ACK | INDICATE_BAD_CONTENT;
    }

    // Exit if no URI path was specified, or the path did not match our USP resource
    if ( ((pp->options_present & URI_PATH_PRESENT) == 0) || (strcmp(pp->uri_path, cs->listen_resource) != 0) )
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has incorrect URI path for USP (uri_path=%s)", __FUNCTION__, pp->message_id, pp->uri_path);
        return SEND_ACK | INDICATE_NOT_FOUND;
    }

    // Exit if the URI query option is not present
    if ((pp->options_present & URI_QUERY_PRESENT) == 0)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) does not contain URI query option", __FUNCTION__, pp->message_id);
        return SEND_ACK | INDICATE_BAD_REQUEST;
    }

    // Exit if the total size of the USP record being sent is too large for us to accept
    if ((pp->options_present & SIZE1_PRESENT) && (pp->total_size > MAX_USP_MSG_LEN))
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) indicates total USP record size is too large (total_size=%u)", __FUNCTION__, pp->message_id, pp->total_size);
        return SEND_ACK | INDICATE_TOO_LARGE;
    }

    // Copy the token
    // NOTE: Tokens only need to be present if the Block option is present
    memcpy(cs->token, pp->token, pp->token_size);
    cs->token_size = pp->token_size;

    // Handle the block option, if present
    if (pp->options_present & BLOCK1_PRESENT)
    {
        // Exit if the first block we've received isn't block 0
        if (pp->rxed_block != 0)
        {
            SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has unexpected block number (block=%d)", __FUNCTION__, pp->message_id, pp->rxed_block);
            return SEND_ACK | INDICATE_INCOMPLETE;
        }

        // Exit if no token specified
        if (pp->token_size == 0)
        {
            SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has BLOCK1, but no token", __FUNCTION__, pp->message_id);
            return SEND_RST;
        }

        // Exit if the payload is not the same size as that indicated by the block option (if this is the first of many blocks)
        if ((pp->is_more_blocks == 1) && (pp->payload_len != pp->block_size))
        {
            SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has mismatching payload_len=%d and block_size=%d", __FUNCTION__, pp->message_id, pp->payload_len, pp->block_size);
            return SEND_ACK | INDICATE_INCOMPLETE;
        }

        // Store state for subsequent blocks
        cs->block_size = pp->block_size;
        cs->block_count = 0;                // Reset the block count, it will be incremented by AppendCoapPayload

        // If there are more blocks, then the USP record is not complete yet
        if (pp->is_more_blocks == 1)
        {
            action_flags &= (~USP_RECORD_COMPLETE);
        }
    }

    // Copy this block to the end of the USP record buffer
    temp_flags = AppendCoapPayload(cs, pp);
    if (temp_flags != COAP_NO_ERROR)
    {
        return temp_flags;
    }

    LogRxedCoapPdu(pp);

    return action_flags;
}

/*********************************************************************//**
**
** HandleSubsequentCoapBlock
**
** Handles the second and subsequent blocks received of a USP record
**
** \param   cs - pointer to CoAP server which received the payload we're appending
** \param   pp - pointer to parsed CoAP PDU
**
** \return  action flags determining what actions to take
**
**************************************************************************/
unsigned HandleSubsequentCoapBlock(coap_server_t *cs, parsed_pdu_t *pp)
{
    unsigned action_flags = SEND_ACK | USP_RECORD_COMPLETE;     // Assume there is no block option, or no more blocks
    unsigned temp_flags;

    // Exit if the token doesn't match that of the first block
    if ((pp->token_size != cs->token_size) || (memcmp(pp->token, cs->token, cs->token_size) != 0))
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) has different token from first block. Treating this as a new USP Record.", __FUNCTION__, pp->message_id);
        action_flags = HandleFirstCoapBlock(cs, pp);
        return action_flags;
    }

    // Exit if content format is incorrect for USP
    if ((pp->options_present & CONTENT_FORMAT_PRESENT) && (pp->content_format != kPduContentFormat_OctetStream))
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has unexpected content format for USP (content_format=%d)", __FUNCTION__, pp->message_id, pp->content_format);
        return SEND_ACK | INDICATE_BAD_CONTENT;
    }

    // Exit if a URI path was specified and did not match our USP resource
    if ( (pp->options_present & URI_PATH_PRESENT) && (strcmp(pp->uri_path, cs->listen_resource) != 0) )
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has incorrect URI path for USP (uri_path=%s)", __FUNCTION__, pp->message_id, pp->uri_path);
        return SEND_ACK | INDICATE_NOT_FOUND;
    }

    // Exit if the URI query option is not present
    if ((pp->options_present & URI_QUERY_PRESENT) == 0)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) does not contain URI query option", __FUNCTION__, pp->message_id);
        return SEND_ACK | INDICATE_BAD_REQUEST;
    }

    // Exit if a block option is not present but was previously
    if ((pp->options_present & BLOCK1_PRESENT) == 0)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) is a subsequent block, but no Block1 option", __FUNCTION__, pp->message_id);
        return SEND_ACK | INDICATE_BAD_REQUEST;
    }

    // Exit if the payload is larger than that indicated by the block option
    if (pp->payload_len > pp->block_size)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has payload_len=%d larger than block_size=%d", __FUNCTION__, pp->message_id, pp->payload_len, pp->block_size);
        return SEND_ACK | INDICATE_BAD_REQUEST;
    }

    // Exit if this is not the last block and the payload is not the same size as that indicated by the block option
    if ((pp->is_more_blocks == 1) && (pp->payload_len != pp->block_size))
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has mismatching payload_len=%d and block_size=%d", __FUNCTION__, pp->message_id, pp->payload_len, pp->block_size);
        return SEND_ACK | INDICATE_BAD_REQUEST;
    }

    // Exit if sender is trying to increase the block size that they send to us
    if (pp->block_size > cs->block_size)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has dynamically changed larger block size (block_size=%d, previously=%d)", __FUNCTION__, pp->message_id, pp->block_size, cs->block_size);
        return SEND_ACK | INDICATE_INCOMPLETE;
    }

    // Deal with the case of the sender trying to decrease the block size that they send to us
    if (pp->block_size != cs->block_size)
    {
        // Calculate the new count of number of blocks we've received, based on the new block size
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) has dynamically changed block size (block_size=%d, previously=%d)", __FUNCTION__, pp->message_id, pp->block_size, cs->block_size);
        cs->block_size = pp->block_size;
    }

    // Exit if this block is an earlier block that we've already received
    // NOTE: This could happen in practice, so just acknowledge this block, but do nothing with it
    if (pp->rxed_block < cs->block_count)
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) has earlier block number than expected (block=%d, expected=%d)", __FUNCTION__, pp->message_id, pp->rxed_block, cs->block_count);
        return SEND_ACK;
    }

    // Exit if the number of this block is later than we're expecting
    // NOTE: This should never happen, because the client should not send the next block until we've acknowledged the current
    if (pp->rxed_block > cs->block_count)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has later block number than expected (block=%d, expected=%d)", __FUNCTION__, pp->message_id, pp->rxed_block, cs->block_count);
        return SEND_ACK | INDICATE_INCOMPLETE;
    }

    // Copy this block to the end of the USP record buffer
    temp_flags = AppendCoapPayload(cs, pp);
    if (temp_flags != COAP_NO_ERROR)
    {
        return temp_flags;
    }
    LogRxedCoapPdu(pp);

    // If there are more blocks, then the USP record is not complete yet
    if (pp->is_more_blocks == 1)
    {
        action_flags &= (~USP_RECORD_COMPLETE);
    }

    return action_flags;
}

/*********************************************************************//**
**
** AppendCoapPayload
**
** Appends the specified payload to the buffer in which we are building up the received USP record
**
** \param   cs - pointer to CoAP server which received the payload we're appending
** \param   pp - pointer to structure in which the parsed CoAP PDU is stored
**
** \return  action flags determining what actions to take
**
**************************************************************************/
unsigned AppendCoapPayload(coap_server_t *cs, parsed_pdu_t *pp)
{
    int new_len;
    time_t cur_time;

    // Exit if the new size is greater than we allow
    new_len = cs->usp_buf_len + pp->payload_len;
    if (new_len > MAX_USP_MSG_LEN)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) makes received USP record size too large (total_size=%u)", __FUNCTION__, pp->message_id, new_len);
        return SEND_ACK | INDICATE_TOO_LARGE;
    }

    // Increase the size of the USP record buffer
    cs->usp_buf = USP_REALLOC(cs->usp_buf, new_len);

    // Append the payload to the end of the USP record buffer
    memcpy(&cs->usp_buf[cs->usp_buf_len], pp->payload, pp->payload_len);
    cs->usp_buf_len = new_len;

    cs->block_count++;

    // Update the time at which we timeout reception of this USP Record
    cur_time = time(NULL);
    cs->abort_timeout_time = cur_time + COAP_SERVER_TIMEOUT;

    return COAP_NO_ERROR;
}

/*********************************************************************//**
**
** ParseCoapPdu
**
** Parses the specified PDU into a structure
**
** \param   buf - pointer to buffer containing CoAP PDU to parse
** \param   len - length of buffer containing CoAP PDU to parse
** \param   pp - pointer to structure in which to store the parsed CoAP PDU
**
** \return  action flags determining what actions to take
**
**************************************************************************/
unsigned ParseCoapPdu(unsigned char *buf, int len, parsed_pdu_t *pp)
{
    option_walker_t walker;
    unsigned header;
    unsigned action_flags = COAP_NO_ERROR;

    // Exit if size of packet is not large enough for a CoAP packet
    if (len < COAP_HEADER_SIZE)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=?) was too small (len=%d). Ignoring.", __FUNCTION__, len);
        return IGNORE_PDU;
    }

    // Parse the header
    header = READ_4_BYTES(buf, len);
    pp->coap_version = BITS(31, 30, header);
    pp->pdu_type = BITS(29, 28, header);
    pp->token_size = BITS(27, 24, header);
    pp->pdu_class = BITS(23, 21, header);
    pp->request_response_code = BITS(20, 16, header);
    pp->message_id = BITS(15, 0, header);

    // Exit if PDU has incorrect CoAP version
    if (pp->coap_version != COAP_VERSION)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has incorrect CoAP version (version=%d)", __FUNCTION__, pp->message_id, pp->coap_version);
        return SEND_RST;
    }

    // Exit if PDU is using a class reserved for future expansion
    if ((pp->pdu_class == 1) || (pp->pdu_class == 6) || (pp->pdu_class == 7))
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) is using a reserved class (class=%d)", __FUNCTION__, pp->message_id, pp->pdu_class);
        return SEND_RST;
    }

    // Exit if token size is too large or message not large enough to contain the specified token
    if ((pp->token_size > sizeof(pp->token)) || (len < pp->token_size))
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has incorrect token size (token_size=%d, size_left=%d)", __FUNCTION__, pp->message_id, pp->token_size, len);
        return SEND_RST;
    }

    // Copy the token
    READ_N_BYTES(pp->token, buf, pp->token_size, len);
    
    // Parse all options
    memset(&walker, 0, sizeof(walker));
    walker.buf = buf;
    walker.len = len;
    walker.cur_option = kPduOption_Zero;
    while ((walker.len > 0) && (walker.buf[0] != PDU_OPTION_END_MARKER))
    {
        // Exit if unable to parse the TLV metadata of the option
        action_flags = WalkCoapOption(&walker, pp);
        if (action_flags != COAP_NO_ERROR)
        {
            return action_flags;
        }

        // Exit if an error occurred in parsing the option itself
        action_flags = ParseCoapOption(walker.cur_option, walker.option_value, walker.option_len, pp);
        if (action_flags != COAP_NO_ERROR)
        {
            return action_flags;
        }
    }

    // Skip the PDU_OPTION_END_MARKER
    // NOTE: This may not be present after the options if there is no payload
    if ((walker.len > 0) && (walker.buf[0] == PDU_OPTION_END_MARKER))
    {
        buf = walker.buf + 1;
        len = walker.len - 1;
    }

    // Store pointer to the payload and it's size. This is whatever is left in the PDU.
    pp->payload = buf;
    pp->payload_len = len;

    return COAP_NO_ERROR;
}

/*********************************************************************//**
**
** WalkCoapOption
**
** Called to walk through each CoAP option
**
** \param   ow - pointer to parameters which are used to walk the option list
**               On input:  The parameters in this structure point to the option to parse
**               On output: The parameters in this structure point to the next option to parse, and return the current option and it's values
** \param   pp - pointer to parsed CoAP PDU
**
** \return  action flags determining what actions to take
**
**************************************************************************/
int WalkCoapOption(option_walker_t *ow, parsed_pdu_t *pp)
{
    unsigned char *buf;
    int len;
    unsigned option_header;
    int option_delta;
    int option_delta_ext;
    int option_len;
    int option_len_ext;
    int buffer_required;

    // Exit if buffer length left is not enough to include the option header
    buf = ow->buf;
    len = ow->len;
    if (len < 1)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has not enough packet left for option header", __FUNCTION__, pp->message_id);
        return SEND_RST;
    }

    // Read and parse the option header
    option_header = READ_BYTE(buf, len);
    option_delta = BITS(7, 4, option_header);
    option_len = BITS(3, 0, option_header);

    // Exit if Option Delta or option len are encoded incorrectly
    // NOTE: It is an error to call this code for the PDU_OPTION_END_MARKER
    USP_ASSERT(option_header != PDU_OPTION_END_MARKER)
    if ((option_delta == 15) || (option_len==15))
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has invalid option_delta or option_len (=15)", __FUNCTION__, pp->message_id);
        return SEND_RST;
    }

    // Calculate the amount of buffer left needed to parse option_delta_ext and option_len_ext
    buffer_required = 0;
    if (option_delta > 12)
    {
        buffer_required += option_delta - 12;
    }

    if (option_len > 12)
    {
        buffer_required += option_len - 12;
    }

    // Exit if there is not enough buffer left to parse option_delta_ext and option_len_ext
    if (len < buffer_required)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has not enough packet left for option_delta_ext and option_len_ext", __FUNCTION__, pp->message_id);
        return SEND_RST;
    }

    // Parse option_delta_ext, and update option_delta with it
    if (option_delta == 13)
    {
        option_delta_ext = READ_BYTE(buf, len);
        option_delta = option_delta_ext + 13;
    }
    else if (option_delta == 14)
    {
        option_delta_ext = READ_2_BYTES(buf, len);
        option_delta = option_delta_ext + 269;
    }

    // Parse option_len_ext, and update option_len with it
    if (option_len == 13)
    {
        option_len_ext = READ_BYTE(buf, len);
        option_len = option_len_ext + 13;
    }
    else if (option_len == 14)
    {
        option_len_ext = READ_2_BYTES(buf, len);
        option_len = option_len_ext + 269;
    }

    // Exit if there is not enough buffer left for the option's value
    if (len < option_len)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has not enough packet left to contain the option's value (option=%d)", __FUNCTION__, pp->message_id, ow->cur_option + option_delta);
        return SEND_RST;
    }

    // Update the option walker to point to the next option, and return this option
    ow->buf = buf + option_len;
    ow->len = len - option_len;
    ow->cur_option = ow->cur_option + option_delta;
    ow->option_value = buf;
    ow->option_len = option_len;

    return COAP_NO_ERROR;
}

/*********************************************************************//**
**
** ParseCoapOption
**
** Parses the specified coap option
**
** \param   cs - coap server that sent the PDU containing the specified option
** \param   option - coap option
** \param   buf - pointer to buffer containing the value of the coap option
** \param   len - length of the buffer containing the value of the coap option
** \param   pp - pointer to structure in which to store the parsed CoAP PDU
**
** \return  action flags determining what actions to take
**
**************************************************************************/
int ParseCoapOption(int option, unsigned char *buf, int len, parsed_pdu_t *pp)
{
    bool is_wrong_length = false;           // assume that option is correct length
    bool result;

    // Determine if the option's value is the wrong length
    switch(option)
    {
        case kPduOption_UriHost:
        case kPduOption_UriPath:
        case kPduOption_UriQuery:
            if (len == 0)
            {
                is_wrong_length = true;
            }
            break;

        case kPduOption_ContentFormat:
            if (len > 2)
            {
                is_wrong_length = true;
            }
            break;

        case kPduOption_UriPort:
            if (len != 2)
            {
                is_wrong_length = true;
            }
            break;

        case kPduOption_Size1:
            if (len > 4)        // Size1 option is 0 to 4 bytes
            {
                is_wrong_length = true;
            }
            break;

        case kPduOption_Block1:
            if (len > 3)        // Block1 option is 0 to 3 bytes
            {
                is_wrong_length = true;
            }
            break;

        default:
            break;
    }

    // Exit if the option is the wrong length
    if (is_wrong_length)
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) has incorrect length for an option (option=%d, len=%d)", __FUNCTION__, pp->message_id, option, len);
        return SEND_RST;
    }

    // Copy the option's parsed value into the parsed_pdu structure
    switch(option)
    {
        case kPduOption_UriHost:
        case kPduOption_UriPort:
            // NOTE: Ignore these options, as we do not host multiple virtual servers
            break;

        case kPduOption_UriPath:
            pp->options_present |= URI_PATH_PRESENT;
            AppendUriPath(pp->uri_path, sizeof(pp->uri_path), (char *)buf, len);
            break;

        case kPduOption_UriQuery:
            pp->options_present |= URI_QUERY_PRESENT;
            TEXT_UTILS_StrncpyLen(pp->uri_query, sizeof(pp->uri_query), (char *)buf, len);
            USP_PROTOCOL("%s: Received CoAP UriQueryOption='%s'", __FUNCTION__, pp->uri_query);

            result = ParseCoapUriQuery(pp->uri_query, &pp->mtp_reply_to);
            if (result == false)
            {
                SetCoapErrMessage("%s: Received CoAP URI query option (%s) is incorrectly formed", __FUNCTION__, pp->uri_query);
                return SEND_ACK | INDICATE_BAD_OPTION;
            }

            break;

        case kPduOption_ContentFormat:
            pp->options_present |= CONTENT_FORMAT_PRESENT;
            pp->content_format = ReadUnsignedOptionValue(buf, len);
            break;

        case kPduOption_Block1:
            ParseBlock1Option(buf, len, pp);
            break;

        case kPduOption_Block2:
            // Ignore the Block2 option. It is used in requests to suggest a block size for the response. But USP uses POST, without piggybacked responses.
            break;
        
        case kPduOption_Size1:
            pp->options_present |= SIZE1_PRESENT;
            pp->total_size = ReadUnsignedOptionValue(buf, len);
            break;

        default:
            if ((option & 1) == 1)
            {
                // Odd numbered options are 'critical' and must cause the return of a 4.02 (Bad Option) if not handled
                SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) contains an unhandled critical option (option=%d)", __FUNCTION__, pp->message_id, option);
                if (pp->pdu_type == kPduType_Confirmable)
                {
                    return SEND_ACK | INDICATE_BAD_OPTION;
                }
                else
                {
                    return SEND_RST;
                }
            }
            else
            {
                // Even numbered options are 'elective' and can be ignored if we don't parse them
            }
            break;
    }

    return COAP_NO_ERROR;
}

/*********************************************************************//**
**
** AppendUriPath
**
** Appends the specified path segment to the URI path buffer
**
** \param   path - pointer to buffer containing the current URI path that we wish to append to
** \param   path_len - maximum length of the buffer containing the URI path
** \param   segment - pointer to buffer (not NULL terminated) containing the path segment to append
** \param   seg_len - length of the path segment to append
**
** \return  None
**
**************************************************************************/
void AppendUriPath(char *path, int path_len, char *segment, int seg_len)
{
    char buf[MAX_COAP_URI_PATH];
    int len;

    // Exit if this is the first segment, copying it into the buffer without a leading '/' separator
    if (path[0] == '\0')
    {
        TEXT_UTILS_StrncpyLen(path, path_len, segment, seg_len);
        return;
    }

    // Form the path segment as a NULL terminated string, with leading '/' separator in local buffer
    buf[0] = '/';
    TEXT_UTILS_StrncpyLen(&buf[1], sizeof(buf)-1, segment, seg_len);  // Minus 1 because of '/' separator at the beginning
    
    // Append path segment in local buffer to URI path
    len = strlen(path);
    USP_STRNCPY(&path[len], buf, path_len-len);
}

/*********************************************************************//**
**
** ParseBlock1Option
**
** Parses the Block1 option's value
**
** \param   buf - pointer to buffer containing the value of the Block1 option
** \param   len - length of the buffer containing the value of the Block1 option
** \param   pp - pointer to structure in which to store the parsed CoAP PDU
**
** \return  None
**
**************************************************************************/
void ParseBlock1Option(unsigned char *buf, int len, parsed_pdu_t *pp)
{
    unsigned value;
    pdu_block_size_t pdu_block_size;

    pp->options_present |= BLOCK1_PRESENT;

    switch(len)
    {
        default:
        case 0:
            pp->rxed_block = 0;
            pp->is_more_blocks = 0;
            pdu_block_size = kPduBlockSize_16;
            break;

        case 1:
            value = READ_BYTE(buf, len);
            pp->rxed_block = BITS(7, 4, value);
            pp->is_more_blocks = BITS(3, 3, value);
            pdu_block_size = BITS(2, 0, value);
            break;

        case 2:
            value = READ_2_BYTES(buf, len);
            pp->rxed_block = BITS(15, 4, value);
            pp->is_more_blocks = BITS(3, 3, value);
            pdu_block_size = BITS(2, 0, value);
            break;

        case 3:
            value = READ_3_BYTES(buf, len);
            pp->rxed_block = BITS(23, 4, value);
            pp->is_more_blocks = BITS(3, 3, value);
            pdu_block_size = BITS(2, 0, value);
            break;
    }

    // Convert the enumerated block size back into an integer    
    pp->block_size = CalcBlockSize_Pdu2Int(pdu_block_size);
}

/*********************************************************************//**
**
** ParseCoapUriQuery
**
** Parses the URI Query option into an mtp_reply_to structure
** The format of the URI Query option is:
**    reply_to=coap[s]:// hostname [':' port] '/' resource
** 
** NOTE: On exit, the strings in the mtp_reply_to structure will point to within the uri_query (input) buffer
**
** \param   uri_query - pointer to buffer containing the URI query option to parse
**                      NOTE: This buffer will be altered by this function
** \param   mrt - pointer to structure containing the parsed 'reply-to'
**
** \return  true if parsed successfully
**
**************************************************************************/
bool ParseCoapUriQuery(char *uri_query, mtp_reply_to_t *mrt)
{
    char *p;
    char *p_slash;
    char *p_colon;
    char *hostname_end;
    char *endptr;

    // Determine if the reply is to an encrypted port or not (and set the default port based on encryption status)
    #define URI_QUERY_COAP  "reply-to=coap://"
    #define URI_QUERY_COAPS "reply-to=coaps://"
    p = uri_query;
    if (strncmp(p, URI_QUERY_COAP, sizeof(URI_QUERY_COAP)-1) == 0)
    {
        mrt->coap_encryption = false;
        mrt->coap_port = 5683;
        p += sizeof(URI_QUERY_COAP)-1;
    }
    else if (strncmp(p, URI_QUERY_COAPS, sizeof(URI_QUERY_COAPS)-1) == 0)
    {
        mrt->coap_encryption = true;
        mrt->coap_port = 5684;
        p += sizeof(URI_QUERY_COAPS)-1;
    }
    else
    {
        return false;
    }

    // Exit if the rest of the string does not contain a slash character separating the hostname (and possibly port) from the resource
    p_slash = strchr(p, '/');
    if (p_slash == NULL)
    {
        return false;
    }
    hostname_end = p_slash;

    // Determine whether an optional port number is present, before the slash
    p_colon = strchr(p, ':');
    if ((p_colon != NULL) && (p_colon < p_slash))
    {
        // Exit if not all of the characters from the colon to the slash are part of the port value
        mrt->coap_port = strtol(&p_colon[1], &endptr, 10);
        if (endptr != p_slash)
        {
            return false;
        }
        hostname_end = p_colon;
    }

    *hostname_end = '\0';               // Terminate the hostname in the input buffer
    mrt->coap_host = p;
    mrt->coap_resource = &p_slash[1];
    mrt->protocol = kMtpProtocol_CoAP;
    mrt->is_reply_to_specified = true;

    return true;
}

/*********************************************************************//**
**
** ReadUnsignedOptionValue
**
** Reads the value of an option contained in a variable number of bytes in network byte order
**
** \param   buf - pointer to buffer containing the value of the option
** \param   len - length of the buffer containing the value of the option
**
** \return  value of the option
**
**************************************************************************/
unsigned ReadUnsignedOptionValue(unsigned char *buf, int len)
{
    unsigned value = 0;

    switch(len)
    {
        case 0:
            value = 0;
            break;

        case 1:
            value = READ_BYTE(buf, len);
            break;


        case 2:
            value = READ_2_BYTES(buf, len);
            break;

        case 3:
            value = READ_3_BYTES(buf, len);
            break;

        case 4:
            value = READ_4_BYTES(buf, len);
            break;

        default:
            TERMINATE_BAD_CASE(len);
            break;
    }

    return value;
}

/*********************************************************************//**
**
** IsReplyToValid
**
** Validates that the host in the URI query Option's 'reply-to' matches the 
** IP address of the USP controller that sent the message (containing the 'reply-to')
** This is necessary to prevent an errant USP controller using an Agent to perform a DoS attack
**
** \param   cs - pointer to CoAP server which received the payload we're appending
** \param   pp - pointer to parsed CoAP PDU
**
** \return  true if the host in the 'reply-to' is valid
**
**************************************************************************/
bool IsReplyToValid(coap_server_t *cs, parsed_pdu_t *pp)
{
    char *host;
    int err;
    nu_ipaddr_t reply_addr;
    nu_ipaddr_t interface_addr;
    bool prefer_ipv6;
    char buf[NU_IPADDRSTRLEN];

    // Attempt to interpret the host as an IP literal address (ie no DNS lookup required)
    host = pp->mtp_reply_to.coap_host;
    err = nu_ipaddr_from_str(host, &reply_addr);

    // If this fails, then assume that host is a DNS hostname
    if (err != USP_ERR_OK)
    {
        // Get the preference for IPv4 or IPv6, if dual stack
        prefer_ipv6 = DEVICE_LOCAL_AGENT_GetDualStackPreference();

        // Determine address of interface that the packet was received on
        // We want to lookup a hostname on the same IPv4 or IPv6 protocol
        // NOTE: We lookup cs->peer_addr, rather than use cs->listen_addr directly, because we might be listening on "any"
        // (in which case listen_addr does not contain the IP address of the interface which received the packet)
        err = nu_ipaddr_get_interface_addr_from_dest_addr(&cs->peer_addr, &interface_addr);
        if (err != USP_ERR_OK)
        {
            return false;
        }        

        // Exit if unable to lookup hostname
        err = tw_ulib_diags_lookup_host(host, AF_UNSPEC, prefer_ipv6, &interface_addr, &reply_addr);
        if (err != USP_ERR_OK)
        {
            USP_LOG_Error("%s: Ignoring USP message. Unable to lookup Host address in URI Query option (%s)", __FUNCTION__, host);
            return false;
        }
    }

    // Exit if the address given in the reply-to does not match the address of the USP controller 
    // that sent the message containing the reply-to
    if (memcmp(&reply_addr, &cs->peer_addr, sizeof(nu_ipaddr_t)) != 0)
    {
        USP_LOG_Error("%s: Ignoring USP message. Host address in URI Query option (%s) does not match sender (%s)", __FUNCTION__, host, nu_ipaddr_str(&cs->peer_addr, buf, sizeof(buf)) );
        return false;
    }

    // If the code gets here, then the host specified in the reply-to matches that expected
    return true;
}

/*********************************************************************//**
**
** LogRxedCoapPdu
**
** Logs the CoAP PDU that has been received
**
** \param   pp - pointer to parsed CoAP PDU
**
** \return  None
**
**************************************************************************/
void LogRxedCoapPdu(parsed_pdu_t *pp)
{
    if (pp->options_present & BLOCK1_PRESENT)
    {
        char *last_block_str = (pp->is_more_blocks == 0) ? " (last)" : "";
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) block=%d%s (%d bytes)", __FUNCTION__, pp->message_id, pp->rxed_block, last_block_str, pp->payload_len);
    }
    else
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) (%d bytes)", __FUNCTION__, pp->message_id, pp->payload_len);
    }
}

/*********************************************************************//**
**
** SendCoapRstFromServer
**
** Sends a CoAP RST from our CoAP server
**
** \param   cs - pointer to structure describing our CoAP server which is sending this RST
** \param   pp - pointer to structure containing parsed input PDU, that this ACK is responding to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int SendCoapRstFromServer(coap_server_t *cs, parsed_pdu_t *pp)
{
    unsigned char buf[MAX_COAP_PDU_SIZE];
    int len;
    int err;

    // Exit if unable to create the CoAP PDU to send
    // NOTE: CoAP servers always echo the message_id of the received PDU
    len = WriteCoapRst(pp->message_id, pp->token, pp->token_size, buf, sizeof(buf));
    USP_ASSERT(len != 0);

    // Exit if unable to send the CoAP RST packet
    err = SendCoapPdu(cs->ssl, cs->socket_fd, buf, len);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: Failed to send RST", __FUNCTION__);
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** SendCoapAck
**
** Creates and sends a CoAP ACK message to the specified Coap endpoint
**
** \param   cs - pointer to CoAP server which received the message we are acknowledging
** \param   pp - pointer to structure containing block option to include in ACK
** \param   action_flags - Determines whether an error is returned in the ACK
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int SendCoapAck(coap_server_t *cs, parsed_pdu_t *pp, unsigned action_flags)
{
    unsigned char buf[MAX_COAP_PDU_SIZE];
    int len;
    int err;

    // Create an ACK, to respond to the packet
    len = WriteCoapAck(cs, buf, sizeof(buf), pp, action_flags);
    USP_ASSERT(len != 0);

    // Save this response, so that we can send it again, if we receive the same message_id again
    SaveResponseToLastHandledPdu(cs, pp->message_id, buf, len);

    // Exit if unable to send the CoAP ACK packet
    err = SendCoapPdu(cs->ssl, cs->socket_fd, buf, len);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: Failed to send ACK", __FUNCTION__);
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** WriteCoapAck
**
** Writes a CoAP PDU containing an ACK
**
** \param   cc - pointer to structure describing controller to send to
** \param   buf - pointer to buffer in which to write the CoAP PDU
** \param   len - length of buffer in which to write the CoAP PDU
** \param   pp - pointer to structure containing parsed input PDU, that this ACK is responding to
** \param   action_flags - Determines whether an error is returned in the ACK
**
** \return  Number of bytes written to the CoAP PDU buffer
**
**************************************************************************/
int WriteCoapAck(coap_server_t *cs, unsigned char *buf, int len, parsed_pdu_t *pp, unsigned action_flags)
{
    unsigned header = 0;
    unsigned char *p;
    unsigned char option_buf[4];
    int option_len;
    pdu_option_t last_option;
    int pdu_class;
    int response_code;
    int preferred_block_size;

    // Determine the class and response code to put in this PDU
    CalcCoapClassForAck(pp, action_flags, &pdu_class, &response_code);

    // Calculate the header bytes
    // NOTE: We use the parsed message_id, since we need to send the ACK based on the PDU we received rather than that which we expected to receive
    MODIFY_BITS(31, 30, header, COAP_VERSION);
    MODIFY_BITS(29, 28, header, kPduType_Acknowledgement);
    MODIFY_BITS(27, 24, header, pp->token_size);
    MODIFY_BITS(23, 21, header, pdu_class);
    MODIFY_BITS(20, 16, header, response_code);
    MODIFY_BITS(15, 0, header, pp->message_id);

    // Write the CoAP header bytes and token into the output buffer
    // NOTE: We use the parsed token, since we need to send the ACK based on the PDU we received rather than that which we expected to receive
    p = buf;
    WRITE_4_BYTES(p, header);
    memcpy(p, pp->token, pp->token_size);
    p += pp->token_size;
    last_option = kPduOption_Zero;

    // Exit if an error or resource discovery response needs to be sent
    if (action_flags & (INDICATE_ERR_IN_ACK | INDICATE_WELL_KNOWN))
    {
        if (action_flags & INDICATE_WELL_KNOWN)
        {
            option_buf[0] = kPduContentFormat_LinkFormat;
            p = WriteCoapOption(kPduOption_ContentFormat, option_buf, 1, p, &last_option);
        }

        WRITE_BYTE(p, PDU_OPTION_END_MARKER);

        // Copy the textual reason for failure into the payload of the ACK
        len = strlen(coap_err_message);
        memcpy(p, coap_err_message, len);
        p += len;
        goto exit;
    }

    // Add the block option, if it was present in the PDU we're acknowledging, and we want the next block
    // NOTE: Do not put the block option in the ACK unless you want another block to be sent (ie It is not present in the last ACK of a sequence of blocks)
    if ((pp->options_present & BLOCK1_PRESENT) && (pp->is_more_blocks))
    {
        preferred_block_size = MIN(COAP_CLIENT_PAYLOAD_RX_SIZE, pp->block_size);
        option_len = CalcCoapBlockOption(option_buf, pp->rxed_block, pp->is_more_blocks, preferred_block_size);
        p = WriteCoapOption(kPduOption_Block1, option_buf, option_len, p, &last_option);
    }

    // Add the size option (to indicate to the sender the maximum size of USP record we accept)
    if (action_flags & INDICATE_TOO_LARGE)
    {
        STORE_4_BYTES(option_buf, MAX_USP_MSG_LEN);
        p = WriteCoapOption(kPduOption_Size1, option_buf, 4, p, &last_option);
    }

    // NOTE: Not adding an end of options marker, because no payload follows

exit:
    // Log what will be sent
    if (pp->options_present & BLOCK1_PRESENT)
    {
        char *last_block_str = (pp->is_more_blocks == 0) ? " (last)" : "";
        USP_PROTOCOL("%s: Sending CoAP ACK (MID=%d) for block=%d%s. Response code=%d.%02d", __FUNCTION__, pp->message_id, pp->rxed_block, last_block_str, pdu_class, response_code);
    }
    else
    {
        USP_PROTOCOL("%s: Sending CoAP ACK (MID=%d). Response code=%d.%02d", __FUNCTION__, pp->message_id, pdu_class, response_code);
    }

    // Return the number of bytes written to the output buffer
    return p - buf;
}

/*********************************************************************//**
**
** CalcCoapClassForAck
**
** Calculate the class and response code for the CoAP header of the ACK message
**
** \param   pp - pointer to structure containing parsed input PDU, that this ACK is responding to
** \param   action_flags - Determines whether an error is returned in the ACK
** \param   pdu_class - pointer to variable in which to return the class to put in the ACK
** \param   response_code - pointer to variable in which to return the response code to put in the ACK
**
** \return  Nothing
**
**************************************************************************/
void CalcCoapClassForAck(parsed_pdu_t *pp, unsigned action_flags, int *pdu_class, int *response_code)
{
    // Determine class of the ACK message
    if (action_flags & INDICATE_ERR_IN_ACK)
    {
        *pdu_class = kPduClass_ClientErrorResponse;
    }
    else
    {
        *pdu_class = kPduClass_SuccessResponse;
    }

    // Determine response code of the ACK message
    if (action_flags & INDICATE_BAD_REQUEST)
    {
        *response_code = kPduClientErrRespCode_BadRequest;
    }
    else if (action_flags & INDICATE_BAD_OPTION)
    {
        *response_code = kPduClientErrRespCode_BadOption;
    }
    else if (action_flags & INDICATE_NOT_FOUND)
    {
        *response_code = kPduClientErrRespCode_NotFound;
    }
    else if (action_flags & INDICATE_BAD_METHOD)
    {
        *response_code = kPduClientErrRespCode_MethodNotAllowed;
    }
    else if (action_flags & INDICATE_INCOMPLETE)
    {
        *response_code = kPduClientErrRespCode_RequestEntityIncomplete;
    }
    else if (action_flags & INDICATE_TOO_LARGE)
    {
        *response_code = kPduClientErrRespCode_RequestEntityTooLarge;
    }
    else if (action_flags & INDICATE_BAD_CONTENT)
    {
        *response_code = kPduClientErrRespCode_UnsupportedContentFormat;
    }
    else if (action_flags & INDICATE_WELL_KNOWN)
    {
        *response_code = kPduSuccessRespCode_Content;
    }
    else if (action_flags & USP_RECORD_COMPLETE)
    {
        *response_code = kPduSuccessRespCode_Changed;
    }
    else if (pp->options_present & BLOCK1_PRESENT)
    {
        *response_code = kPduSuccessRespCode_Continue;
    }
    else
    {
        // For non USP record packets
        *response_code = kPduSuccessRespCode_Content;
    }
}

/*********************************************************************//**
**
** SaveResponseToLastHandledPdu
**
** Saves the response PDU being sent out for the specified message_id
**
** \param   cs - pointer to CoAP server which received the message we are sending this reponse to
** \param   message_id - message_id of the message this is the response to
** \param   buf - pointer to buffer containing the response PDU
** \param   len - length of buffer containing the response PDU
**
** \return  Number of bytes written to the CoAP PDU buffer
**
**************************************************************************/
void SaveResponseToLastHandledPdu(coap_server_t *cs, int message_id, unsigned char *buf, int len)
{
    // Update the last message state
    cs->last_message_id = message_id;
    memcpy(cs->last_message, buf, len);
    cs->last_message_len = len;
}

/*********************************************************************//**
**
** HandleCoapAck
**
** Called when an ACK message is received back from a controller
**
** \param   cc - pointer to structure describing coap client to update
**
** \return  Nothing
**
**************************************************************************/
void HandleCoapAck(coap_client_t *cc)
{
    int err;
    int len;
    unsigned char buf[MAX_COAP_PDU_SIZE];
    parsed_pdu_t pp;
    unsigned action_flags;
    coap_send_item_t *csi;
    
    // Exit if connection was closed
    len = ReceiveCoapPdu(cc->ssl, cc->socket_fd, buf, sizeof(buf));
    if (len == -1)
    {
        csi = (coap_send_item_t *)cc->send_queue.head;
        if (csi == NULL)
        {
            USP_PROTOCOL("%s: Connection closed gracefully by peer after we finished sending blocks", __FUNCTION__);
            StopSendingToController(cc);
        }
        else
        {
            USP_LOG_Error("%s: Connection closed by peer or error before all blocks have been ack'ed (sent %d bytes).", __FUNCTION__, cc->bytes_sent);
            RetryClientSendLater(cc, 0);
        }
        return;
    }

    // Exit if an error occurred whilst parsing the PDU
    memset(&pp, 0, sizeof(pp));
    pp.message_id = INVALID;
    pp.mtp_reply_to.protocol = kMtpProtocol_CoAP;
    action_flags = ParseCoapPdu(buf, len, &pp);
    if (action_flags != COAP_NO_ERROR)
    {
        goto exit;
    }

    // Determine what actions to take
    action_flags = CalcCoapClientActions(cc, &pp);

exit:
    // Perform the actions set in the action flags
    
    // Handle sending a RST, then go back to retrying to transmit the first block
    // NOTE: Note any errors that might be reported in an ACK, instead send a RST, because this code is a CoAP client, so it doesn't send ACKs
    if (action_flags & (SEND_RST | INDICATE_ERR_IN_ACK))
    {
        (void)SendCoapRstFromClient(cc, &pp); // Intentionally ignoring the error, since we are going back to retrying to send the first block anyway
        RetryClientSendLater(cc, 0);
        return;
    }

    // Handle going back to retransmitting the first block (if we received a RST instead of an ACK)
    if (action_flags & RESET_STATE)
    {
        RetryClientSendLater(cc, 0);
        return;
    }

    // Handle sending the next block
    if (action_flags & SEND_NEXT_BLOCK)
    {
        cc->cur_block++;
        cc->bytes_sent += cc->block_size;
        cc->message_id = NEXT_MESSAGE_ID(cc->message_id);
        cc->ack_timeout_ms = CalcCoapInitialTimeout();
        cc->retransmission_counter = 0;
    
        // Change the size of the next blocks being sent out, if the receiver requested it, 
        //and the size they requested is less than our current (otherwise ignore the request)
        cc->block_size = MIN(cc->block_size, pp.block_size);
    
        // Send the next block
        err = SendCoapBlock(cc);
        if (err != USP_ERR_OK)
        {
            // If failed to send next block, then go back to retrying to transmit the first block
            RetryClientSendLater(cc, 0);
        }
        return;
    }

    // Handle sending next message, either because we've successfully sent the current message, or we're skipping sending the current message because it got an error
    if (action_flags & SEND_NEXT_USP_RECORD)
    {
        StartSendingCoapUspRecord(cc, SEND_NEXT);
        return;
    }
}

/*********************************************************************//**
**
** CalcCoapClientActions
**
** Determines what actions to take after the CoAP client received a PDU
**
** \param   cc - pointer to structure describing coap client to update
** \param   pp - pointer to structure containing the parsed CoAP PDU
**
** \return  action flags determining what actions to take
**
**************************************************************************/
unsigned CalcCoapClientActions(coap_client_t *cc, parsed_pdu_t *pp)
{
    coap_send_item_t *csi;
    bool sent_last_block;

    // Exit if we received a RST. Retry sending the message, starting at the first block
    if (pp->pdu_type == kPduType_Reset)
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) was a RST (pdu_type=%d). Restarting transmission.", __FUNCTION__, pp->message_id, pp->pdu_type);
        return RESET_STATE;
    }

    // Exit if we received a non-ACK. Send a RST in response.
    if ((pp->pdu_type == kPduType_Confirmable) || (pp->pdu_type == kPduType_NonConfirmable))
    {
        SetCoapErrMessage("%s: Received CoAP PDU (MID=%d) was not an ACK (pdu_type=%d)", __FUNCTION__, pp->message_id, pp->pdu_type);
        return SEND_RST;        // Send RST for unhandled non-confirmable messages (RFC7252 section 4.3, page 23)
    }

    // If the code gets here, then an ACK was received
    USP_ASSERT(pp->pdu_type == kPduType_Acknowledgement);

    // Exit if ACK has unexpected CoAP token
    if ((pp->token_size != sizeof(cc->token)) || (memcmp(pp->token, cc->token, sizeof(cc->token)) != 0))
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) has unexpected token.", __FUNCTION__, pp->message_id);
        return SEND_RST;
    }

    // Exit if ACK has unexpected message_id
    // NOTE: This is not an error. It may occur in practice if server sent out more than one ACK, and some got delayed
    if (pp->message_id != cc->message_id)
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) is not an ACK for the current message_id=%d. Ignoring.", __FUNCTION__, pp->message_id, cc->message_id);
        return IGNORE_PDU;
    }

    // Exit if the ACK did not contain a successful response
    if (pp->pdu_class != kPduClass_SuccessResponse)
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) has unexpected response code %d.%02d. Aborting send of this USP Record.", __FUNCTION__, pp->message_id, pp->pdu_class, pp->request_response_code);
        return SEND_NEXT_USP_RECORD;
    }

    // Exit if the response code was not either 'Changed' or 'Continue'
    if ((pp->request_response_code != kPduSuccessRespCode_Changed) && (pp->request_response_code != kPduSuccessRespCode_Continue))
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) has unexpected response code %d.%02d", __FUNCTION__, pp->message_id, pp->pdu_class, pp->request_response_code);
        return SEND_RST;
    }

    // Exit if we received a PDU, but there was no send item in the queue
    csi = (coap_send_item_t *)cc->send_queue.head;
    if (csi == NULL)
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d), but not expecting any", __FUNCTION__, pp->message_id);
        return IGNORE_PDU;
    }

    // Exit if we got a 'Changed' response
    // NOTE: Changed response never contains a BLOCK1 option
    sent_last_block = (cc->bytes_sent + cc->block_size >= csi->pbuf_len) ? true : false;
    if (pp->request_response_code == kPduSuccessRespCode_Changed)
    {
        // Exit if we were not expecting a 'Changed' response, as we haven't sent all of the blocks
        // The USP message has not been sent successfully in this case
        if (sent_last_block == false)
        {
            USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) is a 'Changed' response before we had sent all blocks.", __FUNCTION__, pp->message_id);
            return SEND_RST;
        }

        USP_PROTOCOL("%s: Received CoAP ACK 'Changed' (MID=%d)", __FUNCTION__, pp->message_id);
        USP_PROTOCOL("%s: USP Message sent successfully", __FUNCTION__);
        return SEND_NEXT_USP_RECORD;
    }

    // If the code gets here, then we got a 'Continue' response
    USP_ASSERT(pp->request_response_code == kPduSuccessRespCode_Continue);

    // Exit if we didn't expect a 'Continue' response, as we've just sent out the last block.
    // The USP message has not been sent successfully in this case
    if (sent_last_block)
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) got a 'Continue' response but we've sent all blocks", __FUNCTION__, pp->message_id);
        return RESET_STATE;
    }

    // Exit if the ACK did not contain a BLOCK1 option
    // (since we always send with a BLOCK1 option, we expect to receive one back in the 'Continue' ACK, acknowledging the block)
    if ((pp->options_present & BLOCK1_PRESENT)==0)
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) does not contain BLOCK1 option", __FUNCTION__, pp->message_id);
        return RESET_STATE;
    }
    
    // Exit if the block being acknowledged is not the current block
    // NOTE: This should never occur as the message_id and block number are tied together
    if (pp->rxed_block != cc->cur_block)
    {
        USP_PROTOCOL("%s: Received CoAP PDU (MID=%d) is for a different block than current (rxed_block=%d, expected=%d)", __FUNCTION__, pp->message_id, pp->rxed_block, cc->cur_block);
        return RESET_STATE;
    }
    
    USP_PROTOCOL("%s: Received CoAP ACK 'Continue' (MID=%d)", __FUNCTION__, pp->message_id);
    return SEND_NEXT_BLOCK;
}

/*********************************************************************//**
**
** HandleNoCoapAck
**
** Called if no CoAP ACK message is received within a timeout
**
** \param   cc - pointer to structure describing coap client to update
**
** \return  Nothing
**
**************************************************************************/
void HandleNoCoapAck(coap_client_t *cc)
{
    int err;

    // Exit if we have exhausted the number of retransmission retries for this BLOCK
    // moving on to attempt to send the next USP message
    cc->retransmission_counter++;
    cc->reconnect_count++;
    if (cc->retransmission_counter >= COAP_MAX_RETRANSMIT)
    {
        USP_LOG_Error("%s: USP Message not sent successfully. Dropping this USP Message (retry count reached)", __FUNCTION__);
        StartSendingCoapUspRecord(cc, SEND_NEXT);
        return;
    }

    // If the code gets here, we haven't exhausted the number of retries

    // For encrypted connections, the lack of an ACK probably means that we need to restart the DTLS session
    // (This is required in the case of sending to the same peer as the last USP message, but the peer had silently reset it's CoAP server session in the meantime)
    if (cc->enable_encryption)
    {
        USP_LOG_Error("%s: No ACK received in encrypted session, so restarting DTLS session.", __FUNCTION__);
        RetryClientSendLater(cc, ZERO_DELAY_FOR_FIRST_RECONNECT);
        return;
    }

    // Retry with a longer timeout period for the ACK
    cc->ack_timeout_ms *= 2; 
    err = SendCoapBlock(cc);
    if (err != USP_ERR_OK)
    {
        // If an error occurred when trying to send the block, then retry sending the whole USP Record later
        RetryClientSendLater(cc, 0);
    }
}

/*********************************************************************//**
**
** StartSendingCoapUspRecord
**
** Starts sending the next USP Record, if one is queued
** This function is called after successfully sending a USP message or after failing to send one and deciding to drop it
**
** \param   cc - pointer to structure describing coap client to update
** \param   flags - flags controlling what this function does
**
** \return  Nothing
**
**************************************************************************/
void StartSendingCoapUspRecord(coap_client_t *cc, unsigned flags)
{
    int err;
    coap_send_item_t *csi;
    nu_ipaddr_t csi_peer_addr;
    bool prefer_ipv6;

    // Drop the current queued USP Record (if required)
    if (flags & SEND_NEXT)
    {
        FreeFirstCoapSendItem(cc);
    }

    // Clear all timeouts and failure counts
    cc->ack_timeout_time = INVALID_TIME;
    cc->reconnect_time = INVALID_TIME;
    cc->linger_time = INVALID_TIME;

    // Reset the reconnect count, if this is not a connect retry
    if ((flags & RETRY_CURRENT) == 0)
    {
        cc->reconnect_count = 0;
        cc->reconnect_timeout_ms = CalcCoapInitialTimeout();
    }

    // Exit if no more USP Records to send, starting a linger timer to keep the socket
    // connected for a while, in case a USP Record becomes ready to send soon
    csi = (coap_send_item_t *)cc->send_queue.head;
    if (csi == NULL)
    {
        cc->linger_time = time(NULL) + COAP_CLIENT_LINGER_PERIOD;
        return;
    }

    // Log the message, if we are not resending it
    if ((flags & RETRY_CURRENT) == 0)
    {
        MSG_HANDLER_LogMessageToSend(csi->usp_msg_type, csi->pbuf, csi->pbuf_len, kMtpProtocol_CoAP, csi->host, NULL);
    }

    // Attempt to interpret the host as an IP literal address (ie no DNS lookup required)
    // This will always be the case if sending a USP Response, but might not be the case for USP notifications
    err = nu_ipaddr_from_str(csi->host, &csi_peer_addr);

    // If this fails, then assume that host is a DNS hostname
    if (err != USP_ERR_OK)
    {
        // Get the preference for IPv4 or IPv6, if dual stack
        prefer_ipv6 = DEVICE_LOCAL_AGENT_GetDualStackPreference();
    
        // Exit if unable to lookup the IP address of the USP controller to send to
        err = tw_ulib_diags_lookup_host(csi->host, AF_UNSPEC, prefer_ipv6, NULL, &csi_peer_addr);
        if (err != USP_ERR_OK)
        {
            RetryClientSendLater(cc, 0);
            return;
        }
    }

    // Close the socket, if the next message needs to send to a different IP address/port or the request was received on a new DTLS session
    if ((memcmp(&csi_peer_addr, &cc->peer_addr, sizeof(csi_peer_addr)) != 0) || 
        (csi->config.port != cc->peer_port) || 
        (csi->config.enable_encryption != cc->enable_encryption) ||
        (csi->coap_reset_session_hint==true))
    {
        StopSendingToController(cc);
    }

    // Calculate the initial timeout in ms. This will be doubled for each retry attempt
    cc->ack_timeout_ms = CalcCoapInitialTimeout();
    cc->retransmission_counter = 0;

    // Connect to the controller (if required)
    if (cc->socket_fd == INVALID)
    {
        err = ClientConnectToController(cc, &csi_peer_addr, &csi->config);
        if (err != USP_ERR_OK)
        {
            return;
        }
    }

    // Send the first block
    SendFirstCoapBlock(cc);
}

/*********************************************************************//**
**
** ClientConnectToController
**
** Function called to connect the client to the controller specified in the first queued message to send
**
** \param   cc - pointer to structure describing controller to send to
** \param   peer_addr - IP address of controller to connect to
** \param   config - pointer to structure containing port and whether to use encryption when contacting the controller
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ClientConnectToController(coap_client_t *cc, nu_ipaddr_t *peer_addr, coap_config_t *config)
{
    char buf[NU_IPADDRSTRLEN];
    struct sockaddr_storage saddr;
    socklen_t saddr_len;
    sa_family_t family;
    int err;
    int result;

    // Copy the IP address and port that we are going to connect to into the coap client structure
    memcpy(&cc->peer_addr, peer_addr, sizeof(cc->peer_addr));
    cc->peer_port = config->port;
    cc->enable_encryption = config->enable_encryption;
    USP_PROTOCOL("%s: Connecting to %s, port %d (%s)", __FUNCTION__, nu_ipaddr_str(&cc->peer_addr, buf, sizeof(buf)), cc->peer_port, IS_ENCRYPTED_STRING(cc->enable_encryption));

    // Exit if unable to make a socket address structure to contact the CoAP server
    err = nu_ipaddr_to_sockaddr(&cc->peer_addr, cc->peer_port, &saddr, &saddr_len);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }
    
    // Exit if unable to determine which address family to use to contact the CoAP server
    // NOTE: This shouldn't fail if tw_ulib_diags_lookup_host() is correct
    err = nu_ipaddr_get_family(&cc->peer_addr, &family);
    if (err != USP_ERR_OK)
    {
        goto exit;
    }

    // Exit if unable to create the socket
    cc->socket_fd = socket(family, SOCK_DGRAM, 0);
    if (cc->socket_fd == -1)
    {
        USP_ERR_ERRNO("socket", errno);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Exit if unable to connect to the USP controller
    // NOTE: If the server is down, then no error is returned here. Instead it is returned when calling recv
    result = connect(cc->socket_fd, (struct sockaddr *) &saddr, saddr_len);
    if (result != 0)
    {
        USP_ERR_ERRNO("connect", errno);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Perform the DTLS connect, if enabled
    if (cc->enable_encryption)
    {
        err = PerformClientDtlsConnect(cc, &saddr);
        if (err != USP_ERR_OK)
        {
            goto exit;
        }
    }

    // If the code gets here then the socket was successfully connected (either unencrypted or via DTLS)
    err = USP_ERR_OK;

exit:
    if (err != USP_ERR_OK)
    {
        RetryClientSendLater(cc, 0);
    }

    return err;
}

/*********************************************************************//**
**
** PerformClientDtlsConnect
**
** Function called to perform the DTLS Handshake when sending to a controller
**
** \param   cc - pointer to structure describing controller to send to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int PerformClientDtlsConnect(coap_client_t *cc, struct sockaddr_storage *remote_addr)
{
    int err;
    int result;
    struct timeval timeout;

    USP_ASSERT(cc->ssl == NULL);

    // Exit if unable to create a new SSL connection
    cc->ssl = SSL_new(coap_client_ssl_ctx); 
    if (cc->ssl == NULL)
    {
        USP_LOG_Error("%s: SSL_new() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to connect the socket to an SSL DTLS BIO
    cc->bio = BIO_new_dgram(cc->socket_fd, BIO_CLOSE);
    if (cc->bio == NULL)
    {
        USP_LOG_Error("%s: BIO_new_dgram() failed", __FUNCTION__);
        SSL_free(cc->ssl);
        cc->ssl = NULL;
        return USP_ERR_INTERNAL_ERROR;
    }

    // Set BIO to be used for reading and writing
    BIO_ctrl(cc->bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, remote_addr);
    SSL_set_bio(cc->ssl, cc->bio, cc->bio);

    // Set timeout for SSL_connect()
    timeout.tv_sec = DTLS_READ_TIMEOUT;
    timeout.tv_usec = 0;
    BIO_ctrl(cc->bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    // Set the pointer to the variable in which to point to the certificate chain collected in the verify callback
    // We don't need the certificate chain when we are posting to a controller, only when receiving from a controller (to determine controller trust role)
    SSL_set_app_data(cc->ssl, NULL);

    // Exit if unable to perform the DTLS handshake
    result = SSL_connect(cc->ssl);
    if (result <= 0)
    {
        err = SSL_get_error(cc->ssl, result);
        USP_LOG_ErrorSSL(__FUNCTION__, "SSL_connect() failed", result, err);
        SSL_free(cc->ssl);  // Freeing the SSL object also frees the BIO object
        cc->ssl = NULL;
        cc->bio = NULL;
        return USP_ERR_INTERNAL_ERROR;
    }
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** StopSendingToController
**
** Function called to stop sending to the specified controller
**
** \param   cc - pointer to structure describing controller to stop send to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void StopSendingToController(coap_client_t *cc)
{
    // NOTE: If linger timeout is 0, it is still OK to close the socket after reception of the (first received) final ACK
    // Whilst there may be more final ACKs on their way to our CoAP client, since the server only resends the ACK in response 
    // to receiving a block message. In effect, the server has already assumed that the data has been posted successfully.
    CloseCoapClientSocket(cc);

    memset(&cc->peer_addr, 0, sizeof(cc->peer_addr));
    cc->peer_port = INVALID;
    cc->uri_query_option[0] = '\0';
    
    cc->retransmission_counter = 0;
    cc->ack_timeout_ms = 0;
    memset(cc->token, 0, sizeof(cc->token));
    cc->message_id = 0;
    cc->cur_block = 0;
    cc->block_size = 0;
    cc->bytes_sent = 0;
    cc->ack_timeout_time = INVALID_TIME;
    cc->reconnect_time = INVALID_TIME;
    cc->linger_time = INVALID_TIME;
}

/*********************************************************************//**
**
** RetryClientSendLater
**
** Function called to retry connecting to a CoAP server later
** This function is called if there was an unrecoverable error either connecting to the server or when sending to it
**
** \param   cc - pointer to structure describing controller to send to
** \param   flags - Flags determining how to calculate the timeout
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void RetryClientSendLater(coap_client_t *cc, unsigned flags)
{
    time_t cur_time;
    coap_send_item_t *csi;
    int timeout;

    // Wind back any coap client state to known values
    StopSendingToController(cc);

    // Exit if we've reached the limit of retrying to connect. 
    // If so drop the current USP Record that we're trying to send, and move on to the next one
    cc->reconnect_count++;
    if (cc->reconnect_count >= MAX_COAP_RECONNECTS)
    {
        USP_LOG_Error("%s: USP Message not sent successfully. Dropping this USP Message (retry count exceeded)", __FUNCTION__);
        StartSendingCoapUspRecord(cc, SEND_NEXT);
        return;
    }

    // Otherwise, try to connect again later
    csi = (coap_send_item_t *) cc->send_queue.head;
    if (csi != NULL)
    {
        // Timeout is normally a delay, with the exception of the case where we have already delayed due to a missing ACK
        // (in which case the timeout is 0)
        timeout = (cc->reconnect_timeout_ms) / 1000;
        if ((flags & ZERO_DELAY_FOR_FIRST_RECONNECT) && (cc->reconnect_count == 2))  // Using 2 for reconnect count because we've already incremented it by this time
        {
            timeout =0;
        }

        cur_time = time(NULL);
        cc->reconnect_time = cur_time + timeout;
        USP_LOG_Error("%s: Retrying to send to %s over CoAP in %d seconds (Retry_count=%d/%d)", __FUNCTION__, csi->host, timeout, cc->reconnect_count, MAX_COAP_RECONNECTS);

        // Update the timeout to use next time, in the case of trying to connect again
        cc->reconnect_timeout_ms *= 2;
    }
}

/*********************************************************************//**
**
** SendCoapRstFromClient
**
** Sends a CoAP RST from our CoAP client
**
** \param   cc - pointer to structure describing our CoAP client which is sending this RST
** \param   pp - pointer to structure containing parsed input PDU, that this ACK is responding to
**
** \return  USP_ERR_OK if RST sent successfully
**
**************************************************************************/
int SendCoapRstFromClient(coap_client_t *cc, parsed_pdu_t *pp)
{
    unsigned char buf[MAX_COAP_PDU_SIZE];
    int len;
    int err;

    // CoAP clients always allocate message_ids, so we must allocate a message_id
    // We can use our usual message_id counter because our send has been aborted
    cc->message_id = NEXT_MESSAGE_ID(cc->message_id);
    len = WriteCoapRst(cc->message_id, pp->token, pp->token_size, buf, sizeof(buf));
    USP_ASSERT(len != 0);

    // Exit if unable to send the CoAP RST
    err = SendCoapPdu(cc->ssl, cc->socket_fd, buf, len);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** WriteCoapRst
**
** Writes a CoAP PDU containing a RST of the message to send
**
** \param   message_id - message_id which this RST is a response to, or a message_id allocated by us, if one could not be parsed from the input PDU
** \param   token - pointer to buffer containing token of received PDU that caused this RST
** \param   token_len - length of buffer containing token of received PDU that caused this RST
**                NOTE: if no token could be parsed from the input PDU, then the token will be empty
** \param   buf - pointer to buffer in which to write the CoAP PDU
** \param   len - length of buffer in which to write the CoAP PDU
**
** \return  Number of bytes written to the CoAP PDU buffer
**
**************************************************************************/
int WriteCoapRst(int message_id, unsigned char *token, int token_len, unsigned char *buf, int len)
{
    unsigned header = 0;
    unsigned char *p;
    int size;

    // Calculate the header bytes
    MODIFY_BITS(31, 30, header, COAP_VERSION);
    MODIFY_BITS(29, 28, header, kPduType_Reset);
    MODIFY_BITS(27, 24, header, token_len);
    MODIFY_BITS(23, 21, header, kPduClass_ClientErrorResponse);
    MODIFY_BITS(20, 16, header, kPduClientErrRespCode_BadRequest);
    MODIFY_BITS(15, 0, header, message_id);

    // Write the CoAP header bytes and token into the output buffer
    p = buf;
    WRITE_4_BYTES(p, header);
    memcpy(p, token, token_len);
    p += token_len;

    // Write the end of options marker into the output buffer
    WRITE_BYTE(p, PDU_OPTION_END_MARKER);

    // Copy the textual reason for failure into the payload of the RST
    size = strlen(coap_err_message);
    memcpy(p, coap_err_message, size);
    p += size;

    // Log what is going to be sent
    USP_PROTOCOL("%s: Sending CoAP RST (MID=%d)", __FUNCTION__, message_id);

    // Return the number of bytes written to the output buffer
    return p - buf;
}

/*********************************************************************//**
**
** SendFirstCoapBlock
**
** Sends the first CoAP Block of a USP record
** NOTE: This function resets the state in the coap_client_t structure back to sending the first block
**       But it does not reset the failed transmission counter
**
** \param   cc - pointer to structure describing controller to send to
**
** \return  None
**
**************************************************************************/
void SendFirstCoapBlock(coap_client_t *cc)
{
    int err;
    unsigned token;
    coap_send_item_t *csi;

    // Generate a random token and initial message_id
    token = rand_r(&mtp_thread_random_seed);
    STORE_4_BYTES(cc->token, token);
    cc->message_id = NEXT_MESSAGE_ID(cc->message_id);
    cc->cur_block = 0;
    cc->block_size = COAP_CLIENT_PAYLOAD_TX_SIZE;
    cc->bytes_sent = 0;

    // Exit if unable to determine a CoAP server that the USP controller can send back responses to
    csi = (coap_send_item_t *) cc->send_queue.head;
    err = CalcUriQueryOption(cc->socket_fd, csi->config.enable_encryption, cc->uri_query_option, sizeof(cc->uri_query_option));
    if (err != USP_ERR_OK)
    {
        goto exit;
    }
    USP_PROTOCOL("%s: Sending CoAP UriQueryOption='%s'", __FUNCTION__, cc->uri_query_option);

    // Send the first block
    err = SendCoapBlock(cc);

exit:
    // If failed to send the first block, then retry again later
    if (err != USP_ERR_OK)
    {
        RetryClientSendLater(cc, 0);
    }
}

/*********************************************************************//**
**
** SendCoapBlock
**
** Sends a CoAP Block using the specified CoAP client
**
** \param   cc - pointer to structure describing controller to send to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int SendCoapBlock(coap_client_t *cc)
{
    unsigned char buf[MAX_COAP_PDU_SIZE];
    time_t cur_time;
    int len;
    int err;

    // Exit if unable to create the CoAP PDU to send
    len = WriteCoapBlock(cc, buf, sizeof(buf));
    USP_ASSERT(len != 0);

    // Calculate the absolute time to timeout waiting for an ACK for this packet
    cur_time = time(NULL);
    cc->ack_timeout_time = cur_time + (cc->ack_timeout_ms)/1000;

    // Exit if unable to send the CoAP block
    err = SendCoapPdu(cc->ssl, cc->socket_fd, buf, len);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** WriteCoapBlock
**
** Writes a CoAP PDU containing a block of the message to send
**
** \param   cc - pointer to structure describing controller to send to
** \param   buf - pointer to buffer in which to write the CoAP PDU
** \param   len - length of buffer in which to write the CoAP PDU
**
** \return  Number of bytes written to the CoAP PDU buffer, or 0 if buffer is too small
**
**************************************************************************/
int WriteCoapBlock(coap_client_t *cc, unsigned char *buf, int len)
{
    int err;
    unsigned header = 0;
    unsigned char *p;
    coap_send_item_t *csi;
    int is_more_blocks;
    int bytes_remaining;
    int payload_size;
    unsigned char port_option[2];
    unsigned char content_format_option[1];
    unsigned char block_option[3];
    unsigned char size_option[2];
    pdu_option_t last_option;
    int block_option_len;
    int pdu_size;
    char peer_addr_str[NU_IPADDRSTRLEN];
    str_vector_t uri_path;
    int i;
    int total_uri_path_len;

    // Calculate the port and content format options
    csi = (coap_send_item_t *) cc->send_queue.head;
    STORE_2_BYTES(port_option, csi->config.port);
    STORE_BYTE(content_format_option, kPduContentFormat_OctetStream);

    // Calculate the block option
    bytes_remaining = csi->pbuf_len - cc->bytes_sent;
    is_more_blocks = (bytes_remaining <= cc->block_size) ? 0 : 1; 
    block_option_len = CalcCoapBlockOption(block_option, cc->cur_block, is_more_blocks, cc->block_size);

    // Calculate the size option (this option contains the total size of the message)
    STORE_2_BYTES(size_option, csi->pbuf_len);

    // Exit if unable to convert the destination address to a string literal
    err = nu_ipaddr_to_str(&cc->peer_addr, peer_addr_str, sizeof(peer_addr_str));
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: nu_ipaddr_to_str() failed", __FUNCTION__);
        return 0;
    }

    // Split the resource path into separate components, calculating the total size of the components
    total_uri_path_len = 0;
    TEXT_UTILS_SplitString(csi->config.resource, &uri_path, "/");
    for (i=0; i<uri_path.num_entries; i++)
    {
        total_uri_path_len += strlen(uri_path.vector[i]);
        
    }

    // Exit if the buffer is not large enough to contain everything
    payload_size = (bytes_remaining >= cc->block_size) ? cc->block_size : bytes_remaining;
    #define NUM_OPTIONS 6       // Number of options that this function intends to write (not including the URI path options)
    pdu_size = COAP_HEADER_SIZE + sizeof(cc->token) + 
               (NUM_OPTIONS + uri_path.num_entries)*MAX_OPTION_HEADER_SIZE +
               strlen(peer_addr_str) + sizeof(port_option) + total_uri_path_len + sizeof(content_format_option) +
               strlen(cc->uri_query_option) + block_option_len + sizeof(size_option) +
               1 + payload_size;  // Plus 1 for PDU_OPTION_END_MARKER
    if (pdu_size > len)
    {
        STR_VECTOR_Destroy(&uri_path);
        USP_LOG_Error("%s: Buffer too small to write CoAP Block PDU (pdu_size=%d, buf_len=%d)", __FUNCTION__, pdu_size, len);
        return 0;
    }

    // Calculate the header bytes
    MODIFY_BITS(31, 30, header, COAP_VERSION);
    MODIFY_BITS(29, 28, header, kPduType_Confirmable);
    MODIFY_BITS(27, 24, header, sizeof(cc->token));
    MODIFY_BITS(23, 21, header, kPduClass_Request);
    MODIFY_BITS(20, 16, header, kPduRequestMethod_Post);
    MODIFY_BITS(15, 0, header, cc->message_id);

    // Write the CoAP header bytes and token into the output buffer
    p = buf;
    WRITE_4_BYTES(p, header);
    memcpy(p, cc->token, sizeof(cc->token));
    p += sizeof(cc->token);

    // Write the options into the output buffer
    // NOTE: Do not change the order of the options, they must be in numeric order
    // NOTE: If options are added, update the NUM_OPTIONS define
    csi = (coap_send_item_t *) cc->send_queue.head;
    last_option = kPduOption_Zero;
    p = WriteCoapOption(kPduOption_UriHost, (unsigned char *)peer_addr_str, strlen(peer_addr_str), p, &last_option);
    p = WriteCoapOption(kPduOption_UriPort, port_option, sizeof(port_option), p, &last_option);

    // Write the URI path options
    for (i=0; i<uri_path.num_entries; i++)
    {
        p = WriteCoapOption(kPduOption_UriPath, (unsigned char *)uri_path.vector[i], strlen(uri_path.vector[i]), p, &last_option);
    }

    p = WriteCoapOption(kPduOption_ContentFormat, content_format_option, sizeof(content_format_option), p, &last_option);
    p = WriteCoapOption(kPduOption_UriQuery, (unsigned char *)cc->uri_query_option, strlen(cc->uri_query_option), p, &last_option);
    p = WriteCoapOption(kPduOption_Block1, block_option, block_option_len, p, &last_option);
    p = WriteCoapOption(kPduOption_Size1, size_option, sizeof(size_option), p, &last_option);

    // Write the end of options marker into the output buffer
    WRITE_BYTE(p, PDU_OPTION_END_MARKER);

    // Write the payload into the output buffer
    memcpy(p, &csi->pbuf[cc->bytes_sent], payload_size);
    p += payload_size;

    // Log a message
    USP_PROTOCOL("%s: Sending CoAP PDU (MID=%d) block=%d%s (%d bytes). RetryCount=%d/%d, Timeout=%d ms", __FUNCTION__, cc->message_id, cc->cur_block, (is_more_blocks == 0) ? " (last)" : "", payload_size, cc->retransmission_counter, COAP_MAX_RETRANSMIT, cc->ack_timeout_ms);
    STR_VECTOR_Destroy(&uri_path);

    // Return the number of bytes written to the output buffer
    return p - buf;
}

/*********************************************************************//**
**
** CalcCoapBlockOption
**
** Calculates the value of the Block1 option for this tx
**
** \param   buf - pointer to buffer in which to write the block option's value.
**                It is the callers responsibility to ensure that this is at least 3 bytes long.
** \param   cur_block - Current block number to transmit
** \param   is_more_blocks - Set to 1 if there are more blocks containing the USP record, 0 if this is the last block
** \param   block_size - Size of the blocks containing the USP record
**
** \return  Number of bytes written into the block option's value buffer
**
**************************************************************************/
int CalcCoapBlockOption(unsigned char *buf, int cur_block, int is_more_blocks, int block_size)
{
    pdu_block_size_t pdu_block_size;
    int block_option_len;
    unsigned option = 0;

    // Convert the block size to the PDU enumeration
    pdu_block_size = CalcBlockSize_Int2Pdu(block_size);

    // Determine how many bytes to store in the block
    if (cur_block < 16)
    {
        block_option_len = 1;
    }
    else if (cur_block < 4096)
    {
        block_option_len = 2;
    }
    else
    {
        block_option_len = 3;
    }

    // Write the block option
    switch(block_option_len)
    {
        case 1:
            MODIFY_BITS(7, 4, option, cur_block);
            MODIFY_BITS(3, 3, option, is_more_blocks);
            MODIFY_BITS(2, 0, option, pdu_block_size);
            STORE_BYTE(buf, option);
            break;

        case 2:
            MODIFY_BITS(15, 4, option, cur_block);
            MODIFY_BITS(3, 3, option, is_more_blocks);
            MODIFY_BITS(2, 0, option, pdu_block_size);
            STORE_2_BYTES(buf, option);
            break;

        case 3:
            MODIFY_BITS(23, 4, option, cur_block);
            MODIFY_BITS(3, 3, option, is_more_blocks);
            MODIFY_BITS(2, 0, option, pdu_block_size);
            STORE_3_BYTES(buf, option);
            break;
    }

    return block_option_len;
}

/*********************************************************************//**
**
** WriteCoapOption
**
** Writes the specified CoAP option to the specified buffer
**
** \param   pdu_option - CoAP option to write
** \param   option_data - pointer to buffer containing the data for the option to write
** \param   len - number of bytes of option_data
** \param   buf - pointer to output buffer in which to write option
** \param   last_pdu_option - pointer to variable in which to return the CoAP option written by this function
**                            NOTE: This is necessary as CoAP uses a delta encoding for option numbers
**
** \return  pointer to next byte in the output buffer after writing this option
**
**************************************************************************/
unsigned char *WriteCoapOption(pdu_option_t pdu_option, unsigned char *option_data, int len, unsigned char *buf, pdu_option_t *last_pdu_option)
{
    int option_delta;
    int option_delta_ext = 0;
    int option_len;
    int option_len_ext = 0;
    unsigned option_header = 0;
    unsigned char *p;

    // Calculate option_delta, determining whether option_delta_ext is present
    option_delta = pdu_option - (*last_pdu_option);
    USP_ASSERT(option_delta >= 0);    // Ensure that the caller attempts to write options in numeric order
    if (option_delta > 12)
    {
        USP_ASSERT(option_delta < 268); // This code does not cope with 16 bit option deltas
        option_delta_ext = option_delta - 13;
        option_delta = 13;
    }

    // Calculate option_len, determining whether option_len_ext is present
    option_len = len;
    if (option_len > 12)
    {
        USP_ASSERT(option_len < 268); // This code does not cope with 16 bit option lengths
        option_len_ext = option_len - 13;
        option_len = 13;
    }

    // Calculate the option header
    MODIFY_BITS(7, 4, option_header, option_delta);
    MODIFY_BITS(3, 0, option_header, option_len);

    // Write the option header
    p = buf;
    WRITE_BYTE(p, option_header);

    // Write the option_delta_ext if necessary
    if (option_delta == 13)
    {
        WRITE_BYTE(p, option_delta_ext);
    }

    // Write the option_len_ext if necessary
    if (option_len == 13)
    {
        WRITE_BYTE(p, option_len_ext);
    }

    // Write the option data
    memcpy(p, option_data, len);
    p += len;

    // Update the last pdu option, so that the next call to this function can update the delta from the last option written
    *last_pdu_option = pdu_option;

    return p;
}

/*********************************************************************//**
**
** CalcBlockSize_Int2Pdu
**
** Converts the block size integer into an enumeration suitable to be used in Block option
**
** \param   block_size - size of block in bytes
**
** \return  Enumerated value representing block size
**
**************************************************************************/
pdu_block_size_t CalcBlockSize_Int2Pdu(int block_size)
{
    pdu_block_size_t pdu_block_size = kPduBlockSize_16;

    switch(block_size)
    {
        case 1024:
            pdu_block_size = kPduBlockSize_1024;
            break;

        case 512:
            pdu_block_size = kPduBlockSize_512;
            break;

        case 256:
            pdu_block_size = kPduBlockSize_256;
            break;

        case 128:
            pdu_block_size = kPduBlockSize_128;
            break;

        case 64:
            pdu_block_size = kPduBlockSize_64;
            break;

        case 32:
            pdu_block_size = kPduBlockSize_32;
            break;

        case 16:
            pdu_block_size = kPduBlockSize_16;
            break;
            
        default:
            TERMINATE_BAD_CASE(block_size);
            break;
    }

    return pdu_block_size;
}

/*********************************************************************//**
**
** CalcBlockSize_Pdu2Int
**
** Converts the pdu block size enumeration into an integer
**
** \param   pdu_block_size - size of block in enumeration
**
** \return  Number of bytes in block
**
**************************************************************************/
int CalcBlockSize_Pdu2Int(pdu_block_size_t pdu_block_size)
{
    int block_size;
    block_size = 1 << (4 + pdu_block_size);

    return block_size;
}

/*********************************************************************//**
**
** CalcCoapInitialTimeout
**
** Selects a random initial timeout between ACK_TIMEOUT and ACK_TIMEOUT*ACK_RANDOM_FACTOR
**
** \param   None
**
** \return  initial timeout in milliseconds
**
**************************************************************************/
int CalcCoapInitialTimeout(void)
{
    int ack_random_factor;
    ack_random_factor = rand_r(&mtp_thread_random_seed) % 500;
    return COAP_ACK_TIMEOUT*(1000 + ack_random_factor);
}

/*********************************************************************//**
**
** FindUnusedCoapServer
**
** Finds an unused CoAP server slot
**
** \param   None
**
** \return  pointer to free CoAP server, or NULL if none found
**
**************************************************************************/
coap_server_t *FindUnusedCoapServer(void)
{
    int i;
    coap_server_t *cs;

    // Iterte over all CoAP servers, trying to find a free slot
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if (cs->instance == INVALID)
        {
            return cs;
        }
    }

    // If the code gets here, then no free CoAP servers were found
    return NULL;
}

/*********************************************************************//**
**
** FindCoapServerByInstance
**
** Finds the coap server entry with the specified instance number (from Device.LocalAgent.MTP.{i})
**
** \param   instance - instance number in Device.LocalAgent.MTP.{i} for this server
** \param   interface - Name of network interface to listen on. NULL indicates just find the first
**
** \return  pointer to matching CoAP server, or NULL if none found
**
**************************************************************************/
coap_server_t *FindCoapServerByInstance(int instance, char *interface)
{
    int i;
    coap_server_t *cs;

    // Iterate over all CoAP servers, trying to find a matching slot
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if (cs->instance == instance)
        {
            if ((interface==NULL) || (strcmp(cs->interface, interface)==0))
            {
                return cs;
            }
        }
    }

    // If the code gets here, then no matching CoAP servers were found
    return NULL;
}

/*********************************************************************//**
**
** FindFirstCoapServerByInterface
**
** Finds the first coap server listening on the specified interface
** NOTE: There may be more than one coap server on the specified interface - just listening on a different port
**       In this case, we return the first one
**
** \param   interface - Name of network interface to listen on. NULL indicates just find the first
** \parm    encryption_preference - set if we are sending to the USP Controller using encryption
**                   (in which case we try to find a server that the USP Controller can reply to, which is also encrypted)
**
** \return  pointer to matching CoAP server, or NULL if none found
**
**************************************************************************/
coap_server_t *FindFirstCoapServerByInterface(char *interface, bool encryption_preference)
{
    int i;
    coap_server_t *cs;
    coap_server_t *first_match = NULL;
    coap_server_t *any_match = NULL;

    // Iterate over all CoAP servers, trying to find a slot that matches both interface and encryption preference
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if ((cs->instance != INVALID) && (strcmp(cs->interface, interface)==0))
        {
            if (cs->enable_encryption==encryption_preference)
            {
                return cs;
            }

            // If encryption preference was not met, but interface was, take note of this CoAP server as a fallback
            if (first_match == NULL)
            {
                first_match = cs;
            }
        }
    }

    // If the code gets here, then no perfectly matching CoAP server was found
    // However there might be a server listening on all network interfaces which matches the encryption preference
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if ((cs->instance != INVALID) && (strcmp(cs->interface, "any")==0))
        {
            if (cs->enable_encryption==encryption_preference)
            {
                return cs;
            }

            // If encryption preference was not met, take note of this CoAP server as a fallback
            if (any_match == NULL)
            {
                any_match = cs;
            }
        }
    }

    // If the code gets here, then there was no server which matched the encryption preference
    // So return the first server that matches just by interface
    if (first_match != NULL)
    {
        return first_match;
    }

    if (any_match != NULL)
    {
        return any_match;
    }

    // If the code gets here, then there is no CoAP server which listens on the interface
    return NULL;
}

/*********************************************************************//**
**
** CalcUriQueryOption
**
** Calculates the value of the URI Query option for the specified coap client
**
** \param   socket_fd - connected socket which the CoAP client is using to send to the USP Controller
** \parm    encryption_preference - set if we are sending to the USP Controller using encryption
**                   (in which case we try to find a server that the USP Controller can reply to, which is also encrypted)
** \param   buf - buffer in which to return the URI query option
** \param   len - length of buffer in which to return the URI query option
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int CalcUriQueryOption(int socket_fd, bool encryption_preference, char *buf, int len)
{
    int err;
    char src_addr[NU_IPADDRSTRLEN];
    char interface[IFNAMSIZ];
    coap_server_t *cs;
    char *protocol;

    // Exit if unable to determine the source IP address of the client socket
    USP_ASSERT(socket_fd != INVALID);
    err = nu_ipaddr_get_interface_addr_from_sock_fd(socket_fd, src_addr, sizeof(src_addr));
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: nu_ipaddr_get_interface_addr_from_sock_fd() failed", __FUNCTION__);
        return err;
    }

    // Exit if unable to determine the network interface used by the client socket
    err = nu_ipaddr_get_interface_name_from_src_addr(src_addr, interface, sizeof(interface));
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: nu_ipaddr_get_interface_name_from_src_addr(%s) failed", __FUNCTION__, src_addr);
        return err;
    }

    // Exit if we don't have any coap servers listening on the interface (that our coap client is sending on)
    cs = FindFirstCoapServerByInterface(interface, encryption_preference);
    if (cs == NULL)
    {
        USP_LOG_Error("%s: No CoAP servers listening on interface=%s", __FUNCTION__, interface);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    // Fill in the URI query option. This specifies where the USP controller should send responses to
    // NOTE: We use src_addr instead of cs->listen_addr in the reply-to because our CoAP server might be listening on "any" interface
    protocol = (cs->enable_encryption) ? "coaps" : "coap";
    USP_SNPRINTF(buf, len, "reply-to=%s://%s:%d/%s", protocol, src_addr, cs->listen_port, cs->listen_resource);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** FindUnusedCoapClient
**
** Finds an unused CoAP client slot
**
** \param   None
**
** \return  pointer to free CoAP client, or NULL if none found
**
**************************************************************************/
coap_client_t *FindUnusedCoapClient(void)
{
    int i;
    coap_client_t *cc;
    
    // Iterate over all CoAP controllers, trying to find a free slot
    for (i=0; i<MAX_COAP_CLIENTS; i++)
    {
        cc = &coap_clients[i];
        if (cc->cont_instance == INVALID)
        {
            return cc;
        }
    }

    // If the code gets here, then no free CoAP clients were found
    return NULL;
}


/*********************************************************************//**
**
** FindCoapClientByInstance
**
** Finds a coap client by it's instance numbers
**
** \param   cont_instance -  Instance number of the controller in Device.LocalAgent.Controller.{i}
** \param   mtp_instance -   Instance number of this MTP in Device.LocalAgent.Controller.{i}.MTP.{i}
**
** \return  pointer to matching CoAP client, or NULL if none found
**
**************************************************************************/
coap_client_t *FindCoapClientByInstance(int cont_instance, int mtp_instance)
{
    int i;
    coap_client_t *cc;
    
    // Iterate over all CoAP clients, trying to find a match
    for (i=0; i<MAX_COAP_CLIENTS; i++)
    {
        cc = &coap_clients[i];
        if ((cc->cont_instance == cont_instance) && (cc->mtp_instance == mtp_instance))
        {
            return cc;
        }
    }

    // If the code gets here, then no match was found
    return NULL;
}

/*********************************************************************//**
**
** SetCoapErrMessage
**
** Stores the textual cause of the error, so that it may be copied later into the payload of the ACK or RST message
**
** \param   fmt - printf style format
**
** \return  None
**
**************************************************************************/
void SetCoapErrMessage(char *fmt, ...)
{
    va_list ap;
    
    // Write the error message into the buffer, ensuring it is always zero terminated
    va_start(ap, fmt);
    vsnprintf(coap_err_message, sizeof(coap_err_message), fmt, ap);
    coap_err_message[sizeof(coap_err_message)-1] = '\0';
    va_end(ap);

    USP_PROTOCOL("%s", coap_err_message);
}

/*********************************************************************//**
**
** ReceiveCoapPdu
**
** Reads a CoAP PDU addressed to our CoAP client
** NOTE: This function is called by both CoAP client and server
**
** \param   ssl - pointer to SSL object associated with the socket, or NULL if encryption is not enabled
** \param   socket_fd - socket on which to receive the PDU
** \param   buf - pointer to buffer in which to read CoAP PDU
** \param   buflen - length of buffer in which to read CoAP PDU
**
** \return  Number of bytes read, or -1 if the remote server disconnected
**
**************************************************************************/
int ReceiveCoapPdu(SSL *ssl, int socket_fd, unsigned char *buf, int buflen)
{
    int err;
    int bytes_read;
    int retry_count;
    int ssl_flags;

    if (ssl == NULL)
    {
        // Exit if unable to read the CoAP PDU into the buffer
        bytes_read = recv(socket_fd, buf, buflen, 0);
        if (bytes_read == -1)
        {
            USP_ERR_ERRNO("recv", errno);
        }
        return bytes_read;
    }

    // Code below is complex because a renegotiation could occur, and open SSL requires that we retry the EXACT same SSL call
    // We cope with this by retrying the SSL call until the retry has completed (or failed)
    // This code blocks until the retry has completed, or the retry has timed out
    #define ONE_SECOND_IN_MICROSECONDS (1000000)
    #define SSL_RETRY_SLEEP (ONE_SECOND_IN_MICROSECONDS/20)             // Retry 20 times a second
    #define SSL_RETRY_TIMEOUT  (5*ONE_SECOND_IN_MICROSECONDS)           // Retry for upto 5 seconds
    #define MAX_SSL_RETRY_COUNT  (SSL_RETRY_TIMEOUT/SSL_RETRY_SLEEP)
    retry_count = 0;
    while (retry_count < MAX_SSL_RETRY_COUNT)
    {
        // Exit if read some bytes successfully
        bytes_read = SSL_read(ssl, buf, buflen);
        if (bytes_read > 0)
        {
            return bytes_read;
        }

        // Determine whether to retry this call until the read has occurred - this is needed if a renegotiation occurs
        err = SSL_get_error(ssl, bytes_read);

        // Exit if CoAP peer has gracefully disconnected
	    ssl_flags = SSL_get_shutdown(ssl);
        if ((bytes_read==0) || (ssl_flags & SSL_RECEIVED_SHUTDOWN))
        {
            return -1;
        }

        // Log exceptional failure causes
        USP_LOG_ErrorSSL(__FUNCTION__, "SSL_read() failed", bytes_read, err);

        switch(err)
        {
            case SSL_ERROR_NONE:
                // NOTE: I don't think this case will ever get executed because bytes_read would be >= 0
                // If there was no SSL error or no bytes to read, then assume the CoAP peer has gracefully disconnected
                if (bytes_read <= 0)
                {
                    return -1;
                }

                return bytes_read;
                break;
            
            case SSL_ERROR_ZERO_RETURN:
                // Exit if CoAP server has disconnected
                // NOTE: I don't think this case will ever get executed because it would have been caught earlier at the (bytes_read==0) test
                return -1;
                break;
            
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_CONNECT:
            case SSL_ERROR_WANT_ACCEPT:
            case SSL_ERROR_WANT_X509_LOOKUP:
                usleep(SSL_RETRY_SLEEP);
                retry_count++;
                break;
            
            default:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
                // Exit if any other error occurred. Handle these the same as a disconnect
                return -1;
                break;
        }
    }

    // If the code gets here, then the retry timed out, so perform a disconnect
    USP_LOG_Error("%s: SSL Renegotiation timed out", __FUNCTION__);
    return -1;
}

/*********************************************************************//**
**
** SendCoapPdu
**
** Sends a CoAP PDU
** NOTE: This function is called by both CoAP client and server
**
** \param   ssl - pointer to SSL object associated with the socket, or NULL if encryption is not enabled
** \param   socket_fd - socket on which to send the PDU
** \param   buf - pointer to buffer of data to send
** \param   len - length of buffer of data to send
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int SendCoapPdu(SSL *ssl, int socket_fd, unsigned char *buf, int len)
{
    int bytes_sent = 0;
    int err;
    int retry_count;
    int ssl_flags;

    // Perform a simple send() if connection is not encrypted
    if (ssl == NULL)
    {
        bytes_sent = send(socket_fd, buf, len, 0);
        if (bytes_sent != len)
        {
            // NOTE: We have failed to send the new block. It will be retried by the retry mechanism if this is a client, or the remote client will retry
            USP_ERR_ERRNO("send", errno);
            return USP_ERR_OK;
        }
        return USP_ERR_OK;
    }

    // Code below is complex because a renegotiation could occur, and open SSL requires that we retry the EXACT same SSL call
    // We cope with this by retrying the SSL call until the retry has completed (or failed)
    // This code blocks until the retry has completed, or the retry has timed out
    retry_count = 0;
    while (retry_count < MAX_SSL_RETRY_COUNT)
    {
        // Try sending
        bytes_sent = SSL_write(ssl, buf, len);
        if (bytes_sent > 0)
        {
            return USP_ERR_OK;;
        }

        // Determine whether to retry this call until the write has occurred - this is needed if a renegotiation occurs
        err = SSL_get_error(ssl, bytes_sent);

        // Exit if peer has disconnected
	    ssl_flags = SSL_get_shutdown(ssl);
        if ((bytes_sent==0) || (ssl_flags & SSL_RECEIVED_SHUTDOWN))
        {
            USP_PROTOCOL("%s: Peer has disconnected", __FUNCTION__);
            return USP_ERR_INTERNAL_ERROR;
        }

        // Log exceptional failure causes
        USP_LOG_ErrorSSL(__FUNCTION__, "SSL_write() failed", bytes_sent, err);

        switch(err)
        {
		    case SSL_ERROR_NONE:
            case SSL_ERROR_WANT_READ:
                // NOTE: I don't think these can occur. If they do and nothing was sent out, then the CoAP retry mechanism will fix it anyway.
                return USP_ERR_OK;
                break;

            case SSL_ERROR_WANT_WRITE:
                // Wait a while, then perform the renegotiation
                usleep(SSL_RETRY_SLEEP);
                retry_count++;
				break;

            default:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
                return USP_ERR_INTERNAL_ERROR;
                break;
        }
    }

    // If the code gets here, then SSL renegotiation failed
    USP_LOG_Error("%s: SSL Renegotiation timed out", __FUNCTION__);
    return USP_ERR_INTERNAL_ERROR;
}

/*********************************************************************//**
**
** CloseCoapClientSocket
**
** Closes our CoAP client socket and SSL, BIO objects
**
** \param   cc - Coap Client to close down socket on
**
** \return  None
**
**************************************************************************/
void CloseCoapClientSocket(coap_client_t *cc)
{
    // Exit if no socket to close
    if (cc->socket_fd == INVALID)
    {
        USP_ASSERT(cc->ssl==NULL);
        USP_ASSERT(cc->bio==NULL);
        return;
    }

    USP_PROTOCOL("%s: Closing connection", __FUNCTION__);

    // Free the SSL object
    // NOTE: This also frees the BIO object (if one exists) as it is owned by the SSL object
    if (cc->ssl != NULL)
    {
        SSL_shutdown(cc->ssl);
        SSL_free(cc->ssl);
        cc->ssl = NULL;
        cc->bio = NULL;
    }

    // Close the socket
    close(cc->socket_fd);

    // Zero out all state associated with the socket
    cc->socket_fd = INVALID;
    memset(&cc->peer_addr, 0, sizeof(cc->peer_addr));
    cc->peer_port = INVALID;
}

/*********************************************************************//**
**
** CloseCoapServerSocket
**
** Closes our CoAP server socket and SSL, BIO objects
**
** \param   cs - Coap Server to close down socket on
**
** \return  None
**
**************************************************************************/
void CloseCoapServerSocket(coap_server_t *cs)
{
    // Exit if no socket to close
    if (cs->socket_fd == INVALID)
    {
        USP_ASSERT(cs->ssl==NULL);
        USP_ASSERT(cs->bio==NULL);
        return;
    }

    // Free the SSL object and associated data
    RemoveCoapServerSSL(cs);

    // Close the socket
    close(cs->socket_fd);
    cs->socket_fd = INVALID;
}

/*********************************************************************//**
**
** AddCoapServerSSL
**
** Adds an SSL object to the specified CoAP server
**
** \param   cs - Coap Server to add SSL object to
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int AddCoapServerSSL(coap_server_t *cs)
{
    // Exit if unable to create an SSL object
    cs->ssl = SSL_new(coap_server_ssl_ctx);
    if (cs->ssl == NULL)
    {
        USP_LOG_Error("%s: SSL_new() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Set the pointer to the variable in which to point to the certificate chain collected in the verify callback
    SSL_set_app_data(cs->ssl, &cs->cert_chain);

    // Exit if unable to connect the socket to an SSL DTLS BIO
    cs->bio = BIO_new_dgram(cs->socket_fd, BIO_NOCLOSE);
    if (cs->bio == NULL)
    {
        USP_LOG_Error("%s: BIO_new_dgram() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Set the DTLS bio for reading and writing
    SSL_set_bio(cs->ssl, cs->bio, cs->bio);
    SSL_set_options(cs->ssl, SSL_OP_COOKIE_EXCHANGE);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** RemoveCoapServerSSL
**
** Removes the the CoAP server SSL and BIO objects from the CoAP server object
**
** \param   cs - Coap Server to remove SSL object from
**
** \return  None
**
**************************************************************************/
void RemoveCoapServerSSL(coap_server_t *cs)
{
    // Exit if there is no SSL object currently
    if (cs->ssl == NULL)
    {
        return;
    }

    // Free the certificate chain and allowed controllers list
    if (cs->cert_chain != NULL)
    {
        sk_X509_pop_free(cs->cert_chain, X509_free);
        cs->cert_chain = NULL;
    }
    USP_SAFE_FREE(cs->allowed_controllers);

    // Free the SSL object
    // NOTE: This also frees the BIO object (if one exists) as it is owned by the SSL object
    SSL_shutdown(cs->ssl);
    SSL_free(cs->ssl);
    cs->ssl = NULL;
    cs->bio = NULL;
}

/*********************************************************************//**
**
** FreeFirstCoapSendItem
**
** Freeds the first CoAP send item in the queue of items to send
**
** \param   cc - pointer to structure describing coap client to update
**
** \return  Nothing
**
**************************************************************************/
void FreeFirstCoapSendItem(coap_client_t *cc)
{
    coap_send_item_t *csi;

    // Exit if queue is already empty
    csi = (coap_send_item_t *) cc->send_queue.head;
    if (csi == NULL)
    {
        return;
    }

    // Remove and free the first item in the queue
    USP_FREE(csi->pbuf);
    USP_FREE(csi->host);
    USP_FREE(csi->config.resource);
    DLLIST_Unlink(&cc->send_queue, csi);
    USP_FREE(csi);
}

/*********************************************************************//**
**
** CalcCoapServerCookie
**
** Called by OpenSSL to generate a cookie for a given peer
** The cookie is generated according to RFC 4347: Cookie = HMAC(Secret, Client-IP, Client-Parameters)
**
** \param   ssl - pointer to SSL object, ultimately specifying the peer
** \param   buf - pointer to buffer in which to return the cookie
** \param   p_len - pointer to variable in which to return the length of the cookie
**
** \return  1 if successful, 0 otherwise
**
**************************************************************************/
int CalcCoapServerCookie(SSL *ssl, unsigned char *buf, unsigned int *p_len)
{
    struct sockaddr_storage peer;
    unsigned char *result;
    int err;

    // Exit if unable to extract peer IP address and port
    memset(&peer, 0, sizeof(peer));
    err = BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
    if (err <= 0)
    {
        USP_LOG_Error("%s: BIO_dgram_get_peer() failed", __FUNCTION__);
        return 0;
    }

    // Exit if unable to calculate HMAC of peer address and port using our secret hmac key
    result = HMAC( EVP_sha1(),
                   (const void*) coap_hmac_key, sizeof(coap_hmac_key),
                   (const unsigned char*) &peer, sizeof(peer),
                   buf, p_len);
    if (result == NULL)
    {
        USP_LOG_Error("%s: HMAC() failed", __FUNCTION__);
        return 0;
    }

    return 1;
}

/*********************************************************************//**
**
** VerifyCoapServerCookie
**
** Called by OpenSSL to verify that the cookie being returned by the peer matches the one sent to it
** The cookie is generated according to RFC 4347: Cookie = HMAC(Secret, Client-IP, Client-Parameters)
**
** \param   cc - pointer to structure describing coap client to update
** \param   buf - pointer to buffer containing cookie returned by peer
** \param   len - length of buffer containing cookie returned by peer
**
** \return  1 if cookie is correct, 0 if cookie is incorrect
**
**************************************************************************/
int VerifyCoapServerCookie(SSL *ssl, SSL_CONST unsigned char *buf, unsigned int len)
{
    unsigned char expected[EVP_MAX_MD_SIZE];
    unsigned int expected_len;
    int err;

    // Exit if unable to calculate the cookie that we sent to the peer
    expected_len = sizeof(expected);        // I don't think that this is necessary
    err = CalcCoapServerCookie(ssl, expected, &expected_len);
    if (err != 1)
    {
        USP_LOG_Error("%s: CalcCoapServerCookie() failed", __FUNCTION__);
        return 0;
    }

    // Exit if the received cookie did not match the one sent
    if ((len != expected_len) || (memcmp(buf, expected, len) != 0))
    {
        USP_LOG_Error("%s: Received DTLS cookie did not match that sent", __FUNCTION__);
        return 0;
    }

    // If the code gets here, then the received cookie is correct
    return 1;
}

/*********************************************************************//**
**
** IsUspRecordInCoapQueue
**
** Determines whether the specified USP record is already queued, waiting to be sent
** This is used to avoid duplicate records being placed in the queue, which could occur under notification retry conditions
**
** \param   cc - coap client which has USP records queued to send
** \param   pbuf - pointer to buffer containing USP Record to match against
** \param   pbuf_len - length of buffer containing USP Record to match against
**
** \return  true if the message is already queued
**
**************************************************************************/
bool IsUspRecordInCoapQueue(coap_client_t *cc, unsigned char *pbuf, int pbuf_len)
{
    coap_send_item_t *csi;

    // Iterate over USP Records in the CoAP client's queue
    csi = (coap_send_item_t *) cc->send_queue.head;
    while (csi != NULL)
    {
        // Exit if the USP record is already in the queue
        if ((csi->pbuf_len == pbuf_len) && (memcmp(csi->pbuf, pbuf, pbuf_len)==0))
        {
             return true;
        }

        // Move to next message in the queue
        csi = (coap_send_item_t *) csi->link.next;
    }

    // If the code gets here, then the USP record is not in the queue
    return false;
}

/*********************************************************************//**
**
** UpdateCoapServerInterfaces
**
** Called to determine whether the IP address used for any of our CoAP servers has changed
** NOTE: This function only checks the IP address periodically
**
** \param   None
**
** \return  Number of seconds remaining until next time to poll the interfaces for IP address change
**
**************************************************************************/
int UpdateCoapServerInterfaces(void)
{
    int i;
    coap_server_t *cs;
    bool has_changed;
    time_t cur_time;
    int timeout;
    static bool is_first_time = true; // The first time this function is called, it just sets up the IP address and next_coap_server_if_poll_time
    bool has_addr = false;

    // Exit if it's not yet time to poll the network interface addresses
    cur_time = time(NULL);
    if (is_first_time == false)
    {
        timeout = next_coap_server_if_poll_time - cur_time;
        if (timeout > 0)
        {
            goto exit;
        }
    }

    // Iterate over all CoAP servers that are attached to a single network interface
    for (i=0; i<MAX_COAP_SERVERS; i++)
    {
        cs = &coap_servers[i];
        if ((cs->instance != INVALID) && (strcmp(cs->interface, "any") != 0))
        {
            has_changed = nu_ipaddr_has_interface_addr_changed(cs->interface, cs->listen_addr, &has_addr);
            if ((has_changed) && (has_addr))
            {
                USP_LOG_Error("%s: Restarting CoAP server on interface=%s after IP address change", __FUNCTION__, cs->interface);
                ResetCoapServer(cs);
            }
        }
    }

    // Set next time to poll for IP address change
    #define COAP_SERVER_IP_ADDR_POLL_PERIOD 5
    timeout = COAP_SERVER_IP_ADDR_POLL_PERIOD;
    next_coap_server_if_poll_time = cur_time + timeout;
    is_first_time = false;

exit:
    return timeout;
}

#endif // ENABLE_COAP

