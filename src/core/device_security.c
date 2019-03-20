/*
 *
 * Copyright (C) 2017-2019  ARRIS Enterprises, LLC
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
 * \file device_security.c
 *
 * Implements the Device.Security data model object
 *
 */

#include <time.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>
#include <unistd.h>


#include "common_defs.h"
#include "stomp.h"
#include "data_model.h"
#include "usp_api.h"
#include "device.h"
#include "dm_access.h"
#include "vendor_api.h"
#include "iso8601.h"


//------------------------------------------------------------------------------
// String, set by '-a' command line option to specify a file containing the client cert and private key to use when authenticating this device
char *auth_cert_file = NULL;

//------------------------------------------------------------------------------
// Location of the Device.Security.Certificate table within the data model
#define DEVICE_CERT_ROOT "Device.Security.Certificate"
static const char device_cert_root[] = DEVICE_CERT_ROOT;

//------------------------------------------------------------------------------
// SSL context, holding the trust store
static SSL_CTX *ssl_ctx = NULL;       // Context to hold the trust store

//------------------------------------------------------------------------------
// Vector holding information about each trusted certificate
typedef struct
{
    X509 *cert;                 // Copy of the certificate in the trust store. This is used to seed curl's trust store in DEVICE_SECURITY_SetCurlTrustStore() 

    char *subject;              // Free with OPENSSL_free()
    char *issuer;               // Free with OPENSSL_free()
    char *serial_number;        // Free with OPENSSL_free()
    time_t not_before;
    time_t not_after;
    time_t last_modif;
    char *subject_alt;          // Free with USP_FREE()
    char *signature_algorithm;  // Free with USP_FREE()
    unsigned hash;          // Hash of the DER (binary) form of the certificate
} trust_cert_t;

static trust_cert_t *trust_certs = NULL;
static int num_trust_certs = 0;

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
int GetTrustCert_Count(dm_req_t *req, char *buf, int len);
int GetTrustCert_LastModif(dm_req_t *req, char *buf, int len);
int GetTrustCert_SerialNumber(dm_req_t *req, char *buf, int len);
int GetTrustCert_Issuer(dm_req_t *req, char *buf, int len);
int GetTrustCert_NotBefore(dm_req_t *req, char *buf, int len);
int GetTrustCert_NotAfter(dm_req_t *req, char *buf, int len);
int GetTrustCert_Subject(dm_req_t *req, char *buf, int len);
int GetTrustCert_SubjectAlt(dm_req_t *req, char *buf, int len);
int GetTrustCert_SignatureAlgorithm(dm_req_t *req, char *buf, int len);
trust_cert_t *FindTrustCertByReq(dm_req_t *req);
int TrustCertVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);
int BulkDataTrustCertVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx);
int LoadTrustStore(SSL_CTX *ctx);
int LoadTrustCert(X509_STORE *ssl_store, const unsigned char *cert_data, int cert_len, ctrust_role_t role);
int LoadClientCert(SSL_CTX *ctx);
int LoadClientCertFromFile(SSL_CTX *ctx, char *cert_file);
int AddTrustCert(X509 *cert, ctrust_role_t role);
int ParseCert_LastModif(X509 *cert, time_t *last_modif);
int ParseCert_SerialNumber(X509 *cert, char **p_serial_number);
int ParseCert_NotBefore(X509 *cert, time_t *not_before);
int ParseCert_NotAfter(X509 *cert, time_t *not_after);
time_t Asn1Time_To_UnixTime(ASN1_TIME *cert_time);
int ParseCert_SubjectAlt(X509 *cert, char **p_subject_alt);
int ParseCert_SignatureAlg(X509 *cert, char **p_sig_alg);
int CalcCertHash(X509 *cert, unsigned *p_hash);
int FindMatchingTrustCert(unsigned hash);
bool IsSystemTimeReliable(void);
void LogCertChain(STACK_OF(X509) *cert_chain);
void LogTrustCerts(void);
void LogCert_DER(X509 *cert);

/*********************************************************************//**
**
** DEVICE_SECURITY_Init
**
** Initialises this component, and registers all parameters which it implements
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_SECURITY_Init(void)
{
    int err = USP_ERR_OK;

    // Register parameters implemented by this component
    err |= USP_REGISTER_VendorParam_ReadOnly("Device.Security.CertificateNumberOfEntries", GetTrustCert_Count, DM_UINT);
    err |= USP_REGISTER_Object(DEVICE_CERT_ROOT ".{i}", USP_HOOK_DenyAddInstance, NULL, NULL,   // This table is read only
                                                        USP_HOOK_DenyDeleteInstance, NULL, NULL);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CERT_ROOT ".{i}.LastModif", GetTrustCert_LastModif, DM_DATETIME);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CERT_ROOT ".{i}.SerialNumber", GetTrustCert_SerialNumber, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CERT_ROOT ".{i}.Issuer", GetTrustCert_Issuer, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CERT_ROOT ".{i}.NotBefore", GetTrustCert_NotBefore, DM_DATETIME);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CERT_ROOT ".{i}.NotAfter", GetTrustCert_NotAfter, DM_DATETIME);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CERT_ROOT ".{i}.Subject", GetTrustCert_Subject, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CERT_ROOT ".{i}.SubjectAlt", GetTrustCert_SubjectAlt, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CERT_ROOT ".{i}.SignatureAlgorithm", GetTrustCert_SignatureAlgorithm, DM_STRING);

    // Register unique keys for tables
    char *unique_keys[] = { "SerialNumber", "Issuer" };
    err |= USP_REGISTER_Object_UniqueKey(DEVICE_CERT_ROOT ".{i}", unique_keys, NUM_ELEM(unique_keys));

    // Exit if any errors occurred
    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // Initialise SSL
    SSL_library_init();                 // Initialises lib SSL
    SSL_load_error_strings();

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_SECURITY_Start
**
** Starts this component, adding all instances to the data model
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_SECURITY_Start(void)
{
    int err;
    load_agent_cert_cb_t load_agent_cert_cb;

    // Exit if unable to create an SSL context
    // NOTE: SSLv23_client_method() ensures we negotiate the highest protocol available (ie upto TLSv1.2)
    ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx == NULL)
    {
        USP_ERR_SetMessage("%s: SSL_CTX_new failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Explicitly disallow SSLv2, as it is insecure. See https://arxiv.org/pdf/1407.2168.pdf
    // NOTE: Even without this, SSLv2 ciphers don't seem to appear in the cipher list. Just added in case someone is using an older version of OpenSSL.
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2);
//    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

    // Exit if failed to load certificate trust store
    err = LoadTrustStore(ssl_ctx);
    if (err != USP_ERR_OK)
    {
        SSL_CTX_free(ssl_ctx);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Determine which function to call to load the client cert
    load_agent_cert_cb = vendor_hook_callbacks.load_agent_cert_cb;
    if (load_agent_cert_cb == NULL)
    {
        load_agent_cert_cb = LoadClientCert;  // Fallback to a function which calls the get_agent_cert vendor hook
    }

    // Exit if failed to load client certificate for this Agent
    err = load_agent_cert_cb(ssl_ctx);
    if (err != USP_ERR_OK)
    {
        SSL_CTX_free(ssl_ctx);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Set the verify callback to use for each certificate
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, TrustCertVerifyCallback);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_SECURITY_Stop
**
** Frees all memory used by this component
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void DEVICE_SECURITY_Stop(void)
{
    int i;
    trust_cert_t *tc;

    // Iterate over all trust certs, freeing all memory
    for (i=0; i<num_trust_certs; i++)
    {
        tc = &trust_certs[i];
        X509_free(tc->cert);
        OPENSSL_free(tc->subject);
        OPENSSL_free(tc->issuer);
        OPENSSL_free(tc->serial_number);
        USP_SAFE_FREE(tc->subject_alt);
        USP_SAFE_FREE(tc->signature_algorithm);
    }
    USP_SAFE_FREE(trust_certs);

    // Free the OpenSSL context
    SSL_CTX_free(ssl_ctx);

    // No explicit cleanup of OpenSSL is required.
    // Cleanup routines are now NoOps which have been deprecated. See OpenSSL Changes between 1.0.2h and 1.1.0  [25 Aug 2016]
}

/*********************************************************************//**
**
** DEVICE_SECURITY_GetSSLContext
**
** Returns the SSL context (containing amongst other things, the trust store)
** NOTE: This function is thread-safe since the pointer to the context is created at startup and the pointer is not changed afterwards
**
** \param   None
**
** \return  Pointer to SSL context to use.
**
**************************************************************************/
SSL_CTX *DEVICE_SECURITY_GetSSLContext(void)
{
    return ssl_ctx;
}

/*********************************************************************//**
**
** DEVICE_SECURITY_GetControllerTrust
**
** Obtains the controller trust level to use for controllers attached to this connection
** NOTE: This function is called from the MTP thread, so it should only log errors (not call USP_ERR_SetMessage)
** NOTE: The DM thread owned variables accessed by this function are seeded at startup and are immutable afterwards,
**       therefore this function may safely be called from the MTP thread even though it accesses variables
**       which are owned by the DM thread
**
** \param   cert_chain - pointer to verified certificate chain for this connection
** \param   role - pointer to variable in which to return role permitted by CA cert
** \param   allowed_controllers - pointer to variable in which to return a pointer to a dynamically allocated string
**                     containing the URN of permitted controller endpoint_ids ('from_id's)
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
#define STACK_OF_X509  STACK_OF(X509)  // Define so that ctags works for this function
int DEVICE_SECURITY_GetControllerTrust(STACK_OF_X509 *cert_chain, ctrust_role_t *role, char **allowed_controllers)
{
    int err;
    unsigned num_certs;
    X509 *ca_cert;
    X509 *broker_cert;
    unsigned hash;
    int instance;

    // The cert at position[0] will be the STOMP broker cert
    // The cert at position[1] will be the CA cert that validates the broker cert
    // The certs at higher positions are higher level CA certs, all the way up to one in our trust store

    // Exit if the certificate chain does not contain at least 2 certificates
    num_certs = sk_X509_num(cert_chain);
    if (num_certs < 2)
    {
        USP_LOG_Error("%s: Expected 2 or more certificates in the certificate chain", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to get broker cert
    broker_cert = (X509*) sk_X509_value(cert_chain, 0);
    if (broker_cert == NULL)
    {
        USP_LOG_Error("%s: Unable to get broker cert with sk_X509_value()", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to extract the names of the controllers allowed by the broker cert
    err = ParseCert_SubjectAlt(broker_cert, allowed_controllers);
    if (err != USP_ERR_OK)
    {
        USP_LOG_Error("%s: Unable to obtain the SubjectAltName of a valid controller from the broker certificate", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to get trust store cert
    ca_cert = (X509*) sk_X509_value(cert_chain, num_certs-1);
    if (ca_cert == NULL)
    {
        USP_LOG_Error("%s: Unable to get trust store cert with sk_X509_value()", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to calculate the hash of the trust store cert
    err = CalcCertHash(ca_cert, &hash);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to find the entry in Device.Security.Certificate.{i} that matches the trust store cert in our SSL chain of trust
    // NOTE: This should never occur, as we load the trust certs that Open SSL uses
    instance = FindMatchingTrustCert(hash);
    if (instance == INVALID)
    {
        USP_LOG_Error("%s: CA cert in chain of trust, not found in Device.Security.Certificate", __FUNCTION__);
        LogCertChain(cert_chain);
        LogTrustCerts();
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to get a role associated with the certificate
    *role = DEVICE_CTRUST_GetCertRole(instance);
    if (*role == INVALID_ROLE)
    {
        USP_LOG_Error("%s: CA cert in chain of trust (Instance=%d) did not have an associated role in Device.LocalAgent.ControllerTrust.Credential.{i}", __FUNCTION__, instance);
        LogCertChain(cert_chain);
        LogTrustCerts();
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
**  DEVICE_SECURITY_LoadBulkDataTrustStore
**
**  Callback from curl to install our trust store certificates into curl's SSL context
**  This is called by Bulk Data Collection
**
** \param   curl - pointer to curl context
** \param   curl_sslctx - pointer to curl's SSL context
** \param   userptr - pointer to user data (unused)
**          
** \return  CURLE_OK if successful
**
**************************************************************************/
CURLcode DEVICE_SECURITY_LoadBulkDataTrustStore(CURL *curl, void *curl_sslctx, void *parm)
{
    SSL_CTX *curl_ssl_ctx;
    X509_STORE *curl_trust_store;
    trust_cert_t *tc;
    int i;
    int err;

    // Exit if unable to obtain curl's trust store
    curl_ssl_ctx = (SSL_CTX *) curl_sslctx;
    curl_trust_store = SSL_CTX_get_cert_store(curl_ssl_ctx);
    if (curl_trust_store == NULL)
    {
        USP_LOG_Error("%s: SSL_CTX_get_cert_store() failed", __FUNCTION__);
        return CURLE_ABORTED_BY_CALLBACK;
    }

    // Add all certificates in our trust store to curl's trust store
    for (i=0; i<num_trust_certs; i++)
    {
        tc = &trust_certs[i];
        err = X509_STORE_add_cert(curl_trust_store, tc->cert);
        if (err == 0)
        {
            USP_LOG_Error("%s: X509_STORE_add_cert() failed", __FUNCTION__);
            return CURLE_ABORTED_BY_CALLBACK;
        }
    }

    // Set the verify callback to use for each certificate
    SSL_CTX_set_verify(curl_ssl_ctx, SSL_VERIFY_PEER, BulkDataTrustCertVerifyCallback);

    return CURLE_OK;
}

/*********************************************************************//**
**
** LoadClientCert
**
** Called to load the client certificate authenticating this agent
**
** \param   ctx - pointer to SSL context to load the certificate into
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int LoadClientCert(SSL_CTX *ctx)
{
    int err;
    const unsigned char *in;
    EVP_PKEY *pkey;
    agent_cert_info_t info = {0};
    get_agent_cert_cb_t get_agent_cert_cb;

    // If the client cert file to use is specified on the command line, this overrides all other methods of configuring the client cert
    // NOTE: The string compare test is present in order to allow an invocation of USP Agent to specify no auth cert file using -a "null". Useful, if the -a option is always used in all invocations.
    if ((auth_cert_file != NULL) && (*auth_cert_file != '\0') && (strcmp(auth_cert_file, "null") != 0))
    {
        // Exit if unable to load the client cert and private key from a PEM formattted file
        err = LoadClientCertFromFile(ctx, auth_cert_file);
        if (err != USP_ERR_OK)
        {
            return err;
        }

        // Client certificate and private key was loaded successfully from a file
        goto exit;
    }

    // Determine function to call to get the client cert
    get_agent_cert_cb = vendor_hook_callbacks.get_agent_cert_cb;
    if (get_agent_cert_cb == NULL)
    {
        USP_LOG_Info("%s: Not using a device certificate for connections", __FUNCTION__);
        return USP_ERR_OK;
    }

    // Obtain the agent certificate and key from the vendor
    err = get_agent_cert_cb(&info);
    if (err != USP_ERR_OK)
    {
        USP_ERR_SetMessage("%s: get_agent_cert_cb() failed", __FUNCTION__);
        return err;
    }

    // Exit if no client cert was provided. In this case no client cert will be presented to the broker
    if ((info.cert_data == NULL) || (info.cert_len == 0) || (info.key_data == NULL) || (info.key_len == 0))
    {
        USP_LOG_Info("%s: Not using a device certificate for connections", __FUNCTION__);
        return USP_ERR_OK;
    }
    USP_LOG_Info("%s: Using a device certificate for connections", __FUNCTION__);
    
    // Exit if unable to add this agent's certificate
    err = SSL_CTX_use_certificate_ASN1(ctx, info.cert_len, info.cert_data);
    if (err != 1)
    {
        USP_ERR_SetMessage("%s: SSL_CTX_use_certificate_ASN1() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to read the private key into an EVP_PKEY internal data structure
    // NOTE: The following code is used rather than calling SSL_CTX_use_PrivateKey_ASN1() directly, as we don't know the format of the private key (RSA or DSA)
    // This code is effectively the same as SSL_CTX_use_PrivateKey_ASN1(), but we call d2i_AutoPrivateKey() instead of d2i_PrivateKey().
    // d2i_AutoPrivateKey() determines whether the supplied key is RSA or DSA.
    in = info.key_data;
    pkey = d2i_AutoPrivateKey(NULL, &in, info.key_len);
    if (pkey == NULL)
    {
        USP_ERR_SetMessage("%s: d2i_AutoPrivateKey() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to add the private key
    err = SSL_CTX_use_PrivateKey(ctx, pkey);
    if (err != 1)
    {
        USP_ERR_SetMessage("%s: SSL_CTX_use_PrivateKey() failed", __FUNCTION__);
        EVP_PKEY_free(pkey);
        return USP_ERR_INTERNAL_ERROR;
    }

    EVP_PKEY_free(pkey);

exit:
    // If the code gets here, then a client certificate has been successfully set
    STOMP_NotifyClientCertAvailable();

    return USP_ERR_OK;
}


/*********************************************************************//**
**
** LoadClientCertFromFile
**
** Loads a client certificate and associated private key from a file containing both in PEM format
**
** \param   ctx - pointer to SSL context to load the certificate into
** \param   cert_file - filesystem path to the file containing the PEM formatted cert data concatenated with the PEM formatted private key
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int LoadClientCertFromFile(SSL_CTX *ctx, char *cert_file)
{
    int result;

    // Exit if unable to load the client certificate from the PEM format file
    result = SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM);
    if (result != 1)
    {
        USP_ERR_SetMessage("%s: SSL_CTX_use_certificate_file() failed when reading client certificate from %s", __FUNCTION__, cert_file);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to load the private key from the PEM format file
    result = SSL_CTX_use_PrivateKey_file(ctx, cert_file, SSL_FILETYPE_PEM);
    if (result != 1)
    {
        USP_ERR_SetMessage("%s: SSL_CTX_use_PrivateKey_file() failed when reading private key from %s", __FUNCTION__, cert_file);
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** TrustCertVerifyCallback
**
** Called back from OpenSSL for each certificate in the received server certificate chain of trust
** This function saves the certificate chain into the STOMP connection structure
** This function is used to ignore certificate validation errors caused by system time being incorrect
**
** \param   preverify_ok - set to 1, if the current certificate passed, set to 0 if it did not
** \param   x509_ctx - pointer to context for certificate chain verification
**
** \return  1 if certificate chain should be trusted
**          0 if certificate chain should not be trusted, and connection dropped
**
**************************************************************************/
int TrustCertVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    int cert_err;
    bool is_reliable;
    is_system_time_reliable_cb_t   is_system_time_reliable_cb;
    int err_depth;        // A depth of 0 indicates the server cert, 1=intermediate cert (CA cert) etc
    char *err_string;
    STACK_OF(X509) *cert_chain;
    STACK_OF(X509) **p_cert_chain;
    SSL *ssl;
    char buf[MAX_ISO8601_LEN];

    // Get the parent SSL context
    ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    USP_ASSERT(ssl != NULL);

    // Get the pointer to variable in which to save the certificate chain)
    p_cert_chain = (STACK_OF(X509) **)SSL_get_app_data(ssl);
    USP_ASSERT(p_cert_chain != NULL);

    // Save the certificate chain back into the STOMP connection if not done so already
    // (This function is called for each certificate in the chain, so it might have been done already)
    if (*p_cert_chain == NULL)
    {
        cert_chain = X509_STORE_CTX_get1_chain(x509_ctx);
        if (cert_chain == NULL)
        {
            USP_LOG_Error("%s: X509_STORE_CTX_get1_chain() failed", __FUNCTION__);
            return 0;
        }

        *p_cert_chain = cert_chain;
    }
    
    // Exit if OpenSSL validation has passed
    if (preverify_ok == 1)
    {
        return 1;
    }

    // From this point on, OpenSSL had determined that the certificate could not be trusted
    // Fail validation if the reason the certificate could not be trusted was not one related to validity time
    cert_err = X509_STORE_CTX_get_error(x509_ctx);
    if ((cert_err != X509_V_ERR_CERT_NOT_YET_VALID) && 
        (cert_err != X509_V_ERR_CERT_HAS_EXPIRED) &&
        (cert_err != X509_V_ERR_CRL_NOT_YET_VALID) &&
        (cert_err != X509_V_ERR_CRL_HAS_EXPIRED) )
    {
        err_string = (char *) X509_verify_cert_error_string(cert_err);
        err_depth = X509_STORE_CTX_get_error_depth(x509_ctx);
        USP_LOG_Error("%s: OpenSSL error: %s (err_code=%d) at depth=%d", __FUNCTION__, err_string, cert_err, err_depth);

        LogCertChain(*p_cert_chain);
        LogTrustCerts();
        return 0;
    }

    // Determine function to call to get whether system time is reliable yet
    is_system_time_reliable_cb = vendor_hook_callbacks.is_system_time_reliable_cb;
    if (is_system_time_reliable_cb == NULL)
    {
        is_system_time_reliable_cb = IsSystemTimeReliable;
    }

    // Pass validation if the certificate validity errors are due to system time not being reliable
    is_reliable = is_system_time_reliable_cb();
    if (is_reliable == false)
    {
        X509_STORE_CTX_set_error(x509_ctx, X509_V_OK); // Ensure that SSL_get_verify_result() returns X509_V_OK
        return 1;
    }

    // If the code gets here, then the cert validity time check failed whilst system time was reliable, so fail validation
    USP_LOG_Error("%s: Cert validity time check failed whilst system time was reliable (current system time=%s)", __FUNCTION__, iso8601_cur_time(buf, sizeof(buf)));
    return 0;
}

/*********************************************************************//**
**
** BulkDataTrustCertVerifyCallback
**
** Called back from OpenSSL for each certificate in the received server certificate chain of trust
** This function is used to ignore certificate validation errors caused by system time being incorrect
** NOTE: This code is different from TrustStoreVerifyCallback() in that it does not save the certificate
**       chain for use by ControllerTrust
**
** \param   preverify_ok - set to 1, if the current certificate passed, set to 0 if it did not
** \param   x509_ctx - pointer to context for certificate chain verification
**
** \return  1 if certificate chain should be trusted
**          0 if certificate chain should not be trusted, and connection dropped
**
**************************************************************************/
int BulkDataTrustCertVerifyCallback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    int cert_err;
    bool is_reliable;
    is_system_time_reliable_cb_t   is_system_time_reliable_cb;
    int err_depth;        // A depth of 0 indicates the server cert, 1=intermediate cert (CA cert) etc
    char *err_string;
    STACK_OF(X509) *cert_chain;
    SSL *ssl;
    char buf[MAX_ISO8601_LEN];

    // Get the parent SSL context
    ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    USP_ASSERT(ssl != NULL);

    // Exit if OpenSSL validation has passed
    if (preverify_ok == 1)
    {
        return 1;
    }

    // From this point on, OpenSSL had determined that the certificate could not be trusted
    // Fail validation if the reason the certificate could not be trusted was not one related to validity time
    cert_err = X509_STORE_CTX_get_error(x509_ctx);
    if ((cert_err != X509_V_ERR_CERT_NOT_YET_VALID) && 
        (cert_err != X509_V_ERR_CERT_HAS_EXPIRED) &&
        (cert_err != X509_V_ERR_CRL_NOT_YET_VALID) &&
        (cert_err != X509_V_ERR_CRL_HAS_EXPIRED) )
    {
        err_string = (char *) X509_verify_cert_error_string(cert_err);
        err_depth = X509_STORE_CTX_get_error_depth(x509_ctx);
        USP_LOG_Error("%s: OpenSSL error: %s (err_code=%d) at depth=%d", __FUNCTION__, err_string, cert_err, err_depth);

        cert_chain = X509_STORE_CTX_get1_chain(x509_ctx);
        if (cert_chain == NULL)
        {
            USP_LOG_Error("%s: X509_STORE_CTX_get1_chain() failed", __FUNCTION__);
            return 0;
        }
    
        LogCertChain(cert_chain);
        LogTrustCerts();
        sk_X509_pop_free(cert_chain, X509_free);
        return 0;
    }

    // Determine function to call to get whether system time is reliable yet
    is_system_time_reliable_cb = vendor_hook_callbacks.is_system_time_reliable_cb;
    if (is_system_time_reliable_cb == NULL)
    {
        is_system_time_reliable_cb = IsSystemTimeReliable;
    }

    // Pass validation if the certificate validity errors are due to system time not being reliable
    is_reliable = is_system_time_reliable_cb();
    if (is_reliable == false)
    {
        X509_STORE_CTX_set_error(x509_ctx, X509_V_OK); // Ensure that SSL_get_verify_result() returns X509_V_OK
        return 1;
    }

    // If the code gets here, then the cert validity time check failed whilst system time was reliable, so fail validation
    USP_LOG_Error("%s: Cert validity time check failed whilst system time was reliable (current system time=%s)", __FUNCTION__, iso8601_cur_time(buf, sizeof(buf)));
    return 0;
}

/*********************************************************************//**
**
** LogCertChain
**
** Logs the Subject and Issuer of each certificate in a certificate chain
**
** \param   cert_chain - pointer to chain of certificates
**                       The cert at position[0] will be the STOMP broker cert
**                       The cert at position[1] will be the CA cert that validates the broker cert
**                       The certs at higher positions are higher level CA certs, all the way up to one in our trust store
**
** \return  None
**
**************************************************************************/
void LogCertChain(STACK_OF_X509 *cert_chain)
{
    int i;
    X509 *cert;
    unsigned num_certs;
    char *subject;
    char *issuer;

    // Iterate over all certs in the chain, printing their subject and issuer
    num_certs = sk_X509_num(cert_chain);
    USP_LOG_Info("\nCertificate Chain: STOMP broker cert at position [0], Root cert at position [%d]", num_certs-1);
    for (i=0; i<num_certs; i++)
    {
        cert = (X509*) sk_X509_value(cert_chain, i);
        if (cert == NULL)
        {
            subject = issuer = "Unable to get cert";
        }
        else
        {
            subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        }
        USP_LOG_Info("[%d] Subject: %s", i, subject);
        USP_LOG_Info("[%d]      (Issuer: %s)", i, issuer);
    }
}

/*********************************************************************//**
**
** LogTrustCerts
**
** Logs the Subject and Issuer of each certificate in the trust store
**
** \param   None
**
** \return  None
**
**************************************************************************/
void LogTrustCerts(void)
{
    int i;
    trust_cert_t *tc;

    USP_LOG_Info("\nTrust Store certificates:");
    for (i=0; i<num_trust_certs; i++)
    {
        tc = &trust_certs[i];
        USP_LOG_Info("[%d] Subject: %s", i, tc->subject);
        USP_LOG_Info("[%d]      (Issuer: %s)", i, tc->issuer);
    }        
}

/*********************************************************************//**
**
** LogCert_DER
**
** Logs the specified certificate in DER format
**
** \param   cert - pointer to SSL certificate to log
**
** \return  None
**
**************************************************************************/
void LogCert_DER(X509 *cert)
{
    int len;
    unsigned char *buf = NULL;

    len = i2d_X509(cert, &buf);
    USP_LOG_HexBufferLong("cert", buf, len);
    OPENSSL_free(buf);

}

/*********************************************************************//**
**
** GetTrustCert_Count
**
** Gets the value of Device.Security.CertificateNumberOfEntries
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetTrustCert_Count(dm_req_t *req, char *buf, int len)
{
    val_uint = num_trust_certs;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetTrustCert_LastModif
**
** Gets the value of Device.Security.Certificate.{i}.LastModif
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetTrustCert_LastModif(dm_req_t *req, char *buf, int len)
{
    trust_cert_t *tc;

    // Write the value into the return buffer
    tc = FindTrustCertByReq(req);
    val_datetime = tc->last_modif;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetTrustCert_SerialNumber
**
** Gets the value of Device.Security.Certificate.{i}.SerialNumber
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetTrustCert_SerialNumber(dm_req_t *req, char *buf, int len)
{
    trust_cert_t *tc;

    // Write the value into the return buffer
    tc = FindTrustCertByReq(req);
    USP_SNPRINTF(buf, len, "%s", tc->serial_number);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetTrustCert_Issuer
**
** Gets the value of Device.Security.Certificate.{i}.Issuer
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetTrustCert_Issuer(dm_req_t *req, char *buf, int len)
{
    trust_cert_t *tc;

    // Write the value into the return buffer
    tc = FindTrustCertByReq(req);
    USP_SNPRINTF(buf, len, "%s", tc->issuer);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetTrustCert_NotBefore
**
** Gets the value of Device.Security.Certificate.{i}.NotBefore
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetTrustCert_NotBefore(dm_req_t *req, char *buf, int len)
{
    trust_cert_t *tc;

    // Write the value into the return buffer
    tc = FindTrustCertByReq(req);
    val_datetime = tc->not_before;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetTrustCert_NotAfter
**
** Gets the value of Device.Security.Certificate.{i}.NotAfter
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetTrustCert_NotAfter(dm_req_t *req, char *buf, int len)
{
    trust_cert_t *tc;

    // Write the value into the return buffer
    tc = FindTrustCertByReq(req);
    val_datetime = tc->not_after;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetTrustCert_Subject
**
** Gets the value of Device.Security.Certificate.{i}.Subject
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetTrustCert_Subject(dm_req_t *req, char *buf, int len)
{
    trust_cert_t *tc;

    // Write the value into the return buffer
    tc = FindTrustCertByReq(req);
    USP_SNPRINTF(buf, len, "%s", tc->subject);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetTrustCert_SubjectAlt
**
** Gets the value of Device.Security.Certificate.{i}.SubjectAlt
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetTrustCert_SubjectAlt(dm_req_t *req, char *buf, int len)
{
    trust_cert_t *tc;

    // Write the value into the return buffer
    tc = FindTrustCertByReq(req);
    USP_SNPRINTF(buf, len, "%s", tc->subject_alt);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** GetTrustCert_SignatureAlgorithm
**
** Gets the value of Device.Security.Certificate.{i}.SignatureAlgorithm
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int GetTrustCert_SignatureAlgorithm(dm_req_t *req, char *buf, int len)
{
    trust_cert_t *tc;

    // Write the value into the return buffer
    tc = FindTrustCertByReq(req);
    USP_SNPRINTF(buf, len, "%s", tc->signature_algorithm);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** FindTrustCertByReq
**
** Returns a pointer to the certificate in our trust store vector, based on the specified instance number
**
** \param   req - pointer to structure identifying the subscription
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
trust_cert_t *FindTrustCertByReq(dm_req_t *req)
{
    trust_cert_t *tc;
    int index;

    // Determine which certificate to query
    index = inst1 - 1;
    USP_ASSERT((index >= 0) && (index < num_trust_certs));
    tc = &trust_certs[index];

    return tc;
}

/*********************************************************************//**
**
** AddTrustCert
**
** Adds the specified tructed certificate into a vector, along with its parsed details
** NOTE: Ownership of the certificate structure passes to this function
** NOTE: This function does not attempt to clean up or free memory if an error occurs.
**       (the caller will abort USP Agent in this case).
**
** \param   cert - pointer to the certificate structure to add
** \param   role - role that this CA certificate permits to a broker cert
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int AddTrustCert(X509 *cert, ctrust_role_t role)
{
    int new_num_entries;
    trust_cert_t *tc;
    int err;
    char path[MAX_DM_PATH];

    // First increase the size of the vector, and initialise the new entry to default values
    new_num_entries = num_trust_certs + 1;
    trust_certs = USP_REALLOC(trust_certs, new_num_entries*sizeof(trust_cert_t));

    tc = &trust_certs[ num_trust_certs ];
    memset(tc, 0, sizeof(trust_cert_t));
    num_trust_certs = new_num_entries;

    // Add this certificate into the vector
    tc->cert = cert;

    // Extract Subject and Issuer of the certificate
    tc->subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    tc->issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);

    // Now extract the other details of the specified certificate
    err = USP_ERR_OK;
    err |= ParseCert_LastModif(cert, &tc->last_modif);
    err |= ParseCert_SerialNumber(cert, &tc->serial_number);
    err |= ParseCert_NotBefore(cert, &tc->not_before);
    err |= ParseCert_NotAfter(cert, &tc->not_after);
    err |= ParseCert_SubjectAlt(cert, &tc->subject_alt);
    err |= ParseCert_SignatureAlg(cert, &tc->signature_algorithm);
    err |= CalcCertHash(cert, &tc->hash);

    // Exit if any error occurred when parsing
    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to add the instance into the data model
    USP_SNPRINTF(path, sizeof(path), "%s.%d", device_cert_root, num_trust_certs);
    err = DATA_MODEL_InformInstance(path);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if unable to add the certificate to the Device.LocalAgent.ControllerTrust.Certificate.{i} table
    err = DEVICE_CTRUST_AddCertRole(num_trust_certs, role);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ParseCert_LastModif
**
** Extracts the LastModif field of the specified cert
**
** \param   cert - pointer to the certificate structure to extract the details of
** \param   last_modif - pointer to variable in which to return the value
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ParseCert_LastModif(X509 *cert, time_t *last_modif)
{
    *last_modif = 0;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ParseCert_SerialNumber
**
** Extracts the SerialNumber field of the specified cert
**
** \param   cert - pointer to the certificate structure to extract the details of
** \param   p_serial_number - pointer to variable in which to return a pointer to a dynamically allocated string
**                            The string may be freed by OPENSSL_free()
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ParseCert_SerialNumber(X509 *cert, char **p_serial_number)
{
    ASN1_INTEGER *asn1_number;
    BIGNUM *big_num;
    char *serial_number;
    int num_nibbles;
    int num_octets;
    char *p;
    char *q;
    int i;
    char octet_buf[128];    // This should be plenty. Serial numbers are only supposed to be upto 20 octets in length, which would be 60 characters in this buffer
    int leading_zeros;
    char *final_serial_number;

    // Exit if unable to get the serial number (in static ASN1 form)
    asn1_number = X509_get_serialNumber(cert);
    if (asn1_number == NULL)
    {
        USP_ERR_SetMessage("%s: X509_get_serialNumber() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to convert the ANS1 form to a (dynamically allocated) big number
    big_num = ASN1_INTEGER_to_BN(asn1_number, NULL);
    if (big_num == NULL)
    {
        USP_ERR_SetMessage("%s: ASN1_INTEGER_to_BN() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to convert the big number to a hexadecimal string
    serial_number = BN_bn2hex(big_num);
    if (serial_number == NULL)
    {
        USP_ERR_SetMessage("%s: BN_bn2hec() failed", __FUNCTION__);
        BN_free(big_num);
        return USP_ERR_OK;
    }

    // Determine leading zero padding to make the serial number an even number of full octets, with 2 or more octets
    num_nibbles = strlen(serial_number);
    leading_zeros = 0;
    if (num_nibbles < 4)
    {
        // Ensure that the serial number contains at least 2 octets
        leading_zeros = 4 - num_nibbles;
    }
    else if ((num_nibbles %2) == 1)
    {
        // Ensure that it contains full octets rather than leading with a least significant nibble
        leading_zeros = 1;
    }

    // Add leading zeros to the serial number to make it at least 2 full octets in length, and an even number of nibbles
    memset(octet_buf, '0', 4);
    strncpy(&octet_buf[leading_zeros], serial_number, sizeof(octet_buf)-leading_zeros);

    // Free OpenSSL allocated data
    BN_free(big_num);
    OPENSSL_free(serial_number);

    // Allocate a buffer to store the final format Serial Number
    num_octets = (num_nibbles + leading_zeros) / 2;
    final_serial_number = OPENSSL_malloc(num_octets*3);  // Note: this includes trailing NULL terminator, as we have one less colon than the number of octets
    if (final_serial_number == NULL)
    {
        USP_ERR_SetMessage("%s: BN_bn2hec() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Copy the serial number into the return buffer, inserting colons between octets
    p = final_serial_number;
    q = octet_buf;
    for (i=0; i<num_octets; i++)
    {
        if (i != 0)
        {
            *p++ = ':';
        }
        *p++ = *q++;
        *p++ = *q++;
    }
    *p = '\0';

    // Serial number successfully extracted
    *p_serial_number = final_serial_number;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ParseCert_NotBefore
**
** Extracts the NotBefore time field of the specified cert
**
** \param   cert - pointer to the certificate structure to extract the details of
** \param   not_before - pointer to variable in which to return the value of the extracted field
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ParseCert_NotBefore(X509 *cert, time_t *not_before)
{
    ASN1_TIME *cert_time;

    // Exit if unable to get a not before time
    cert_time = X509_get_notBefore(cert);
    if (cert_time == NULL)
    {
        USP_ERR_SetMessage("%s: X509_get_notBefore() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    *not_before = Asn1Time_To_UnixTime(cert_time);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** ParseCert_NotAfter
**
** Extracts the NotBefore time field of the specified cert
**
** \param   cert - pointer to the certificate structure to extract the details of
** \param   not_after - pointer to variable in which to return the value of the extracted field
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ParseCert_NotAfter(X509 *cert, time_t *not_after)
{
    ASN1_TIME *cert_time;

    // Exit if unable to get a not after time
    cert_time = X509_get_notAfter(cert);
    if (cert_time == NULL)
    {
        USP_ERR_SetMessage("%s: X509_get_notAfter() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    *not_after = Asn1Time_To_UnixTime(cert_time);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Asn1Time_To_UnixTime
**
** Converts a time specified in SSL ASN1 to a unix time
**
** \param   cert_time - pointer to SSL ANS1 time to convert
**
** \return  converted time or INVALID_TIME if failed to convert
**
**************************************************************************/
time_t Asn1Time_To_UnixTime(ASN1_TIME *cert_time)
{
    char *s;
    struct tm tm;
    time_t t;
    int i;

    // Exit if the ASN1 string does not match the format we're expecting (ie "YYMMDDHHMMSSZ")
    s = (char *) cert_time->data;
    if ((strlen(s) != 13) || (s[12] != 'Z'))
    {
        USP_ERR_SetMessage("%s: ASN1 string ('%s') does not match expected format", __FUNCTION__, s);
        return INVALID_TIME;
    }

    // Exit if one of the digits is not numeric
    for (i=0; i<12; i++)
    {
        if ((s[i] < '0') || (s[i] > '9'))
        {
            USP_ERR_SetMessage("%s: ASN1 string ('%s') contains invalid digit ('%c')", __FUNCTION__, s, s[i]);
            return INVALID_TIME;
        }
    }

    // Calculate year since 1900, correcting for years after the millenium
    #define TO_DIGIT(x) (x - '0')
    memset(&tm, 0, sizeof(tm));
    tm.tm_year = 10*TO_DIGIT(s[0]) + TO_DIGIT(s[1]);
    if (tm.tm_year < 70)
    {
        tm.tm_year += 100;
    }

    // Fill in other fields
    tm.tm_mon  = 10*TO_DIGIT(s[2]) + TO_DIGIT(s[3]) - 1; // Month 0-11
    tm.tm_mday = 10*TO_DIGIT(s[4]) + TO_DIGIT(s[5]);     // Day of month 1-31
    tm.tm_hour = 10*TO_DIGIT(s[6]) + TO_DIGIT(s[7]); ;   // Hour 0-23
    tm.tm_min  = 10*TO_DIGIT(s[8]) + TO_DIGIT(s[9]);     // Minute 0-59
    tm.tm_sec  = 10*TO_DIGIT(s[10]) + TO_DIGIT(s[11]);   // Second 0-59


    // Exit if unable to convert the time
    t = timegm(&tm);
    if (t == INVALID_TIME)
    {
        USP_ERR_SetMessage("%s: timegm() failed for ASN1 string ('%s')", __FUNCTION__, s);
        return INVALID_TIME;
    }

    return t;
}

/*********************************************************************//**
**
** ParseCert_SubjectAlt
**
** Extracts the SubjectAltName field of the specified cert
** NOTE: There may be more than one SubjectAlt field. This code extracts only the first
**
** \param   cert - pointer to the certificate structure to extract the details of
** \param   p_subject_alt - pointer to variable in which to return the pointer to a 
**                          dynamically allocated string containing the value
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ParseCert_SubjectAlt(X509 *cert, char **p_subject_alt)
{
    GENERAL_NAMES *subj_alt_names = NULL;
    GENERAL_NAME *gname;
    int count;
    char *str = NULL;
    int str_len = 0;
    char *subject_alt;
    char buf[257];
    int err;
    
    // Exit if unable to get the list of subject alt names
    // NOTE: This is not an error, as subject alt name is an optional field
    subj_alt_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (subj_alt_names == NULL)
    {
        *p_subject_alt = USP_STRDUP("");
        err = USP_ERR_OK;
        goto exit;
    }

    // Log a warning if the certificate contains more than one subject alt name
    count = sk_GENERAL_NAME_num(subj_alt_names);
    if (count > 1)
    {
        USP_LOG_Warning("%s: WARNING: Certificate has more than one SubjectAltName defined. Using only first.", __FUNCTION__);
    }

    // Exit if unable to get the first subject alt name
    gname = sk_GENERAL_NAME_value(subj_alt_names, 0);
    if (gname == NULL)
    {
        USP_ERR_SetMessage("%s: sk_GENERAL_NAME_value() failed", __FUNCTION__);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Make code compatible with older versions of OpenSSL
    #if OPENSSL_VERSION_NUMBER < 0x10100000L  // SSL version 1.1.0
    #define ASN1_STRING_get0_data  ASN1_STRING_data
    #endif

    // Get a pointer to the internal string, depending on the type of SubjectAlt Name
    switch(gname->type)
    {
        case GEN_OTHERNAME:
            str = "Othername not supported";
            str_len = strlen(str);
            break;

        case GEN_EMAIL:
            str = (char *) ASN1_STRING_get0_data(gname->d.rfc822Name);
            str_len = ASN1_STRING_length(gname->d.rfc822Name); // This len does not include NULL terminator

            break;

        case GEN_DNS:
            str = (char *) ASN1_STRING_get0_data(gname->d.dNSName);
            str_len = ASN1_STRING_length(gname->d.dNSName); // This len does not include NULL terminator
            break;

        case GEN_X400:
            str = "x400Address not supported";
            str_len = strlen(str);
            break;

        case GEN_DIRNAME:
            buf[0] = '\0';
            str = X509_NAME_oneline(gname->d.directoryName, buf, sizeof(buf));
            buf[sizeof(buf)-1] = '\0';
            str_len = strlen(str);
            break;

        case GEN_EDIPARTY:
            str = "ediPartyName not supported";
            str_len = strlen(str);
            break;

        case GEN_URI:
            str = (char *) ASN1_STRING_get0_data(gname->d.uniformResourceIdentifier);
            str_len = ASN1_STRING_length(gname->d.uniformResourceIdentifier); // This len does not include NULL terminator
            break;

        case GEN_IPADD:
            str = "IPAddress not supported";
            str_len = strlen(str);
            break;

        case GEN_RID:
            str = "RegisteredID not supported";
            str_len = strlen(str);
            break;

        default:
            str = "Unknown SubjectAlt type";
            str_len = strlen(str);
            break;
    }

    // Exit if the extracted string is still NULL. Note this should not occur.
    if (str == NULL)
    {
        USP_ERR_SetMessage("%s: Unable to extract SubjectAltName for type=%d", __FUNCTION__, gname->type);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Dynamically allocate memory to hold the string, and copy it in
    subject_alt = USP_MALLOC(str_len+1);
    memcpy(subject_alt, str, str_len);
    subject_alt[str_len] = '\0';

    *p_subject_alt = subject_alt;
    err = USP_ERR_OK;

exit:
    if (subj_alt_names != NULL)
    {
        GENERAL_NAMES_free(subj_alt_names);
    }
    return err;
}

/*********************************************************************//**
**
** ParseCert_SignatureAlg
**
** Extracts the SignatureAlg field of the specified cert
**
** \param   cert - pointer to the certificate structure to extract the details of
** \param   p_sig_alg - pointer to variable in which to return the pointer to a 
**                      dynamically allocated string containing the value
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int ParseCert_SignatureAlg(X509 *cert, char **p_sig_alg)
{
#if OPENSSL_VERSION_NUMBER >= 0x1010000FL // SSL version 1.1.0
    #define SSL_X509_ALGOR    const X509_ALGOR
#else
    #define SSL_X509_ALGOR    X509_ALGOR
#endif


#if OPENSSL_VERSION_NUMBER >= 0x1000200FL // SSL version 1.0.2
    SSL_X509_ALGOR *sig_alg_obj;
    int err;
    int result;
    BIO *bp = NULL;
    BUF_MEM *bm;
    char *buf;
    char *p;

    // Exit if unable to create an in-memory BIO
    bp = BIO_new( BIO_s_mem());
    if (bp == NULL)
    {
        USP_ERR_SetMessage("%s: BIO_new() failed", __FUNCTION__);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Get the signature algorithm ASN1 object
    X509_get0_signature(NULL, (SSL_X509_ALGOR **)&sig_alg_obj, cert);

    // Print the signature algorithm to an in-memory BIO
    result = X509_signature_print(bp, (SSL_X509_ALGOR *)sig_alg_obj, NULL);
    if (result <= 0)
    {
        USP_ERR_SetMessage("%s: X509_signature_print() failed", __FUNCTION__);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // X509_signature_print() should create a NON NULL terminated string of the form "  Signature Algorithm: XXX \n"
    // We want to extract the 'XXX' from this string

    // Ensure that the string is terminated by at least one '\n' (NOTE: should not be necessary, but added for extra safety)
    BIO_puts(bp, "\n");

    // Exit if unable to get a pointer to the string written by the BIO
    BIO_get_mem_ptr(bp, &bm);
    if (bm == NULL)
    {
        USP_ERR_SetMessage("%s: BIO_get_mem_ptr() failed", __FUNCTION__);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }
    buf = bm->data;

    // Exit if unable to find the '\n' terminating the string
    p = strchr(buf, '\n');
    if (p == NULL)
    {
        USP_ERR_SetMessage("%s: strchr() failed to find '\n'", __FUNCTION__);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // NULL terminate the string by replacing the first '\n' with '\0'
    *p = '\0';

    // Exit if unable to find the ':', just before the signature algorithm
    p = strchr(buf, ':');
    if (p == NULL)
    {
        USP_ERR_SetMessage("%s: strchr() failed to find ':'", __FUNCTION__);
        err = USP_ERR_INTERNAL_ERROR;
        goto exit;
    }

    // Skip ':' character
    p++;

    // Skip space characters before signature algorithm
    while ((*p == ' ') && (*p != '\0'))
    {
        p++;
    }

    // Copy the algorithmn name into a dynamically allcated buffer controlled by us
    *p_sig_alg = USP_STRDUP(p);
    err = USP_ERR_OK;

exit:
    // Free the BIO (if it was successfully created)
    if (bp != NULL)
    {
        BIO_free(bp);
    }

    return err;

#else
    // Following code is used by versions of OpenSSL prior to 1.0.2
    int alg;
    char *sig_alg;

    // Determine algorithm
    #if OPENSSL_VERSION_NUMBER < 0x10100000L  // SSL version 1.1.0
        alg = OBJ_obj2nid(cert->sig_alg->algorithm);
    #else
        const X509_ALGOR *algor;
        algor = X509_get0_tbs_sigalg(cert);
        alg = OBJ_obj2nid(algor->algorithm);
    #endif

    sig_alg = (char *) OBJ_nid2ln(alg);
    if (sig_alg == NULL)
    {
        sig_alg = "Unknown";
    }

    // Copy the algorithmn name into a dynamically allcated buffer controlled by us
    *p_sig_alg = USP_STRDUP(sig_alg);
    return USP_ERR_OK;
#endif
}

/*********************************************************************//**
**
** CalcCertHash
**
** Implements a 32 bit hash of the DER (binary) form of the specified certificate
** Implemented using the FNV1a algorithm
** NOTE: This function is called from the MTP thread, so it should only log errors (not call USP_ERR_SetMessage)
**
** \param   cert - pointer to the certificate structure to calculate a hash of
** \param   p_hash - pointer to variable in which to return the hash
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int CalcCertHash(X509 *cert, unsigned *p_hash)
{
    #define OFFSET_BASIS (0x811C9DC5)
    #define FNV_PRIME (0x1000193)
    int i;
    unsigned hash = OFFSET_BASIS;
    int len;
    unsigned char *buf = NULL;
    unsigned char *p;

    // Exit if unable to convert the X509 structure to DER form
    // NOTE: OpenSSL allocates memory for the DER form, and stores the pointer to this memory in 'buf'
    len = i2d_X509(cert, &buf);
    if ((len < 0) || (buf == NULL))
    {
        USP_LOG_Error("%s: i2d_X509() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Calculate a hash of the certificate
    p = buf;
    for (i=0; i < len; i++)
    {
        hash = hash * FNV_PRIME;
        hash = hash ^ (*p++);
    }

    // Free the memory allocated by OpenSSL to store the DER form of the cert
    OPENSSL_free(buf);

    *p_hash = hash;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** FindMatchingTrustCert
**
** Finds the certificate in our trust store that matches the given hash
**
** \param   hash - hash of the trusted cert we want to find
**
** \return  Instance number of the certificate within Device.Security.Certificate.{i} table, or INVALID if not found
**
**************************************************************************/
int FindMatchingTrustCert(unsigned hash)
{
    int i;
    trust_cert_t *tc;

    // Iterate over all certificates in our trust store
    for (i=0; i<num_trust_certs; i++)
    {
        // Exit if we've found a matching certificate
        tc = &trust_certs[i];
        if (tc->hash == hash)
        {
            return i+1;
        }
    }

    // If the code gets here, then no match was found
    return INVALID;
}



/*********************************************************************//**
**
** LoadTrustStore
**
** Called to load the trusted root certificate store
**
** \param   ctx - pointer to SSL context to load the trust store into
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int LoadTrustStore(SSL_CTX *ctx)
{
    int i;
    int err;
    X509_STORE *ssl_store;
    const trust_store_t *trusted_certs;
    const trust_store_t *tc;
    int num_trusted_certs;
    get_trust_store_cb_t get_trust_store_cb;

    // Exit if unable to get the trust store that we want to add the trusted certificates to 
    ssl_store = SSL_CTX_get_cert_store(ctx);
    if (ssl_store == NULL)
    {
        USP_ERR_SetMessage("%s: SSL_CTX_get_cert_store() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Determine function to call to get the trust store
    get_trust_store_cb = vendor_hook_callbacks.get_trust_store_cb;
    if (get_trust_store_cb == NULL)
    {
        return USP_ERR_OK;
    }

    // Obtain the list of trusted certificates from the vendor
    trusted_certs = get_trust_store_cb(&num_trusted_certs);
    if (trusted_certs == NULL)
    {
        USP_ERR_SetMessage("%s: get_trust_store_cb() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Iterate over all trusted certificates, adding them to the SSL context's trust store
    for (i=0; i<num_trusted_certs; i++)
    {
        tc = &trusted_certs[i];
        err = LoadTrustCert(ssl_store, tc->cert_data, tc->cert_len, tc->role);
        if (err != USP_ERR_OK)
        {
            return err;
        }
    }


    return USP_ERR_OK;
}

/*********************************************************************//**
**
** LoadTrustCert
**
** Called to add a certificate to the trusted root certificate store
**
** \param   ssl_store - pointer to SSL Trust store to load the cert into
** \param   cert_data - pointer to binary DER format certificate data
** \param   cert_len - number of bytes in the DER format certificate data
** \param   role - controller trust role associated with the certificate
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int LoadTrustCert(X509_STORE *ssl_store, const unsigned char *cert_data, int cert_len, ctrust_role_t role)
{
    int err;
    const unsigned char *in;
    X509 *ssl_cert;

    // Exit if unable to convert the DER format byte array into an internal X509 format (DER to internal - d2i) 
    in = cert_data;
    ssl_cert = d2i_X509(NULL, &in, cert_len);
    if (ssl_cert == NULL)
    {
        USP_ERR_SetMessage("%s: d2i_X509() failed. Error in trusted root cert array", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }
    
    // Exit if unable to add the certificate to the SSL context's trust store
    err = X509_STORE_add_cert(ssl_store, ssl_cert);
    if (err == 0)
    {
        USP_ERR_SetMessage("%s: X509_STORE_add_cert() failed", __FUNCTION__);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if unable to add the certificate's details to our vector
    // NOTE: Ownership of the ssl_cert passes to our vector, so no need to free it in this function
    err = AddTrustCert(ssl_cert, role);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}


/*********************************************************************//**
**
**  IsSystemTimeReliable
**
**  Function to determine whether the system (unix) time has been set on this CPE yet
**  It is expected that system time will only ever transition from not available to available (not back again)
**  This function is called from various places in USP Agent code and should not block for long periods of time
**  Typically, this function is expected to query the value of a global variable, rather than performing any more complex processing
**  If system time has not been set, then USP Agent will disregard system time when processing.
**
** \param   None
**          
** \return  true if system time has been set, false otherwise
**
**************************************************************************/
bool IsSystemTimeReliable(void)
{
    return true;
}

