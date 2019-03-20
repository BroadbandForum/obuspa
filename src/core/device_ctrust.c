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
 * \file device_ctrust.c
 *
 * Implements the data model objects associated with controller trust
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

#include "common_defs.h"
#include "data_model.h"
#include "usp_api.h"
#include "device.h"
#include "dm_access.h"
#include "vendor_api.h"
#include "iso8601.h"

//------------------------------------------------------------------------------
// Location of the controller trust tables within the data model
#define DEVICE_CTRUST_ROOT "Device.LocalAgent.ControllerTrust"
#define DEVICE_ROLE_ROOT "Device.LocalAgent.ControllerTrust.Role.{i}"
#define DEVICE_PERMISSION_ROOT "Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}"
#define DEVICE_CREDENTIAL_ROOT "Device.LocalAgent.ControllerTrust.Credential.{i}"

//------------------------------------------------------------------------------
// Structure for Permission table
typedef struct
{
    char *targets;
    unsigned permission_bitmask;
} permission_t;

//------------------------------------------------------------------------------
// Structure for Role table
typedef struct
{
    char *name;
    int num_permissions;
    permission_t *permissions;
} role_t;

// Array containing data about each role. It is indexed by the role enumeration. ie role table instance number = role enumeration +1
static role_t roles[kCTrustRole_Max];

//------------------------------------------------------------------------------
// Structure for Credential table
typedef struct
{
    ctrust_role_t role;
    int cert_instance;
} credential_t;

// Vector containing credential table entries
static int num_credentials = 0;
static credential_t *credentials = NULL;

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
int Get_RoleNumEntries(dm_req_t *req, char *buf, int len);
int Get_CredentialNumEntries(dm_req_t *req, char *buf, int len);
int Get_RoleName(dm_req_t *req, char *buf, int len);
int Get_PermissionNumEntries(dm_req_t *req, char *buf, int len);
int Get_PermissionOrder(dm_req_t *req, char *buf, int len);
int Get_PermissionTargets(dm_req_t *req, char *buf, int len);
int Get_ParamPermissions(dm_req_t *req, char *buf, int len);
int Get_ObjPermissions(dm_req_t *req, char *buf, int len);
int Get_InstantiatedObjPermissions(dm_req_t *req, char *buf, int len);
int Get_CommandEventPermissions(dm_req_t *req, char *buf, int len);
int Get_CredentialRole(dm_req_t *req, char *buf, int len);
int Get_CredentialCertificate(dm_req_t *req, char *buf, int len);
role_t *CalcRoleFromReq(dm_req_t *req);
permission_t *CalcPermissionFromReq(dm_req_t *req);
credential_t *CalcCredentialFromReq(dm_req_t *req);

/*********************************************************************//**
**
** DEVICE_CTRUST_Init
**
** Initialises this component, and registers all parameters which it implements
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_CTRUST_Init(void)
{
    int err = USP_ERR_OK;

    memset(roles, 0, sizeof(roles));

    // Register parameters implemented by this component
    // Device.LocalAgent.ControllerTrust
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CTRUST_ROOT ".RoleNumberOfEntries", Get_RoleNumEntries, DM_UINT);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CTRUST_ROOT ".CredentialNumberOfEntries", Get_CredentialNumEntries, DM_UINT);


    // Device.LocalAgent.ControllerTrust.Role.{i}
    err |= USP_REGISTER_Object(DEVICE_ROLE_ROOT, USP_HOOK_DenyAddInstance, NULL, NULL,   // This table is read only
                                                 USP_HOOK_DenyDeleteInstance, NULL, NULL);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ROLE_ROOT ".Alias", DM_ACCESS_PopulateAliasParam, DM_STRING);
    err |= USP_REGISTER_Param_Constant(DEVICE_ROLE_ROOT ".Enable", "true", DM_BOOL);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ROLE_ROOT ".Name", Get_RoleName, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_ROLE_ROOT ".PermissionNumberOfEntries", Get_PermissionNumEntries, DM_UINT);


    // Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}
    err |= USP_REGISTER_Object(DEVICE_PERMISSION_ROOT, USP_HOOK_DenyAddInstance, NULL, NULL,   // This table is read only
                                                       USP_HOOK_DenyDeleteInstance, NULL, NULL);

    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PERMISSION_ROOT ".Alias", DM_ACCESS_PopulateAliasParam, DM_STRING);
    err |= USP_REGISTER_Param_Constant(DEVICE_PERMISSION_ROOT ".Enable", "true", DM_BOOL);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PERMISSION_ROOT ".Order", Get_PermissionOrder, DM_UINT);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PERMISSION_ROOT ".Targets", Get_PermissionTargets, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PERMISSION_ROOT ".Param", Get_ParamPermissions, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PERMISSION_ROOT ".Obj", Get_ObjPermissions, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PERMISSION_ROOT ".InstantiatedObj", Get_InstantiatedObjPermissions, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_PERMISSION_ROOT ".CommandEvent", Get_CommandEventPermissions, DM_STRING);

    // Device.LocalAgent.ControllerTrust.Credential.{i}
    err |= USP_REGISTER_Object(DEVICE_CREDENTIAL_ROOT, USP_HOOK_DenyAddInstance, NULL, NULL,   // This table is read only
                                                       USP_HOOK_DenyDeleteInstance, NULL, NULL);

    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CREDENTIAL_ROOT ".Alias", DM_ACCESS_PopulateAliasParam, DM_STRING);
    err |= USP_REGISTER_Param_Constant(DEVICE_CREDENTIAL_ROOT ".Enable", "true", DM_BOOL);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CREDENTIAL_ROOT ".Role", Get_CredentialRole, DM_STRING);
    err |= USP_REGISTER_VendorParam_ReadOnly(DEVICE_CREDENTIAL_ROOT ".Credential", Get_CredentialCertificate, DM_STRING);

    // Register unique keys for tables
    char *alias_unique_key[] = { "Alias" };
    char *name_unique_key[]  = { "Name" };
    char *order_unique_key[]  = { "Order" };
    char *cred_unique_key[]  = { "Credential" };
    
    err |= USP_REGISTER_Object_UniqueKey(DEVICE_ROLE_ROOT, alias_unique_key, NUM_ELEM(alias_unique_key));
    err |= USP_REGISTER_Object_UniqueKey(DEVICE_ROLE_ROOT, name_unique_key, NUM_ELEM(name_unique_key));

    err |= USP_REGISTER_Object_UniqueKey(DEVICE_PERMISSION_ROOT, alias_unique_key, NUM_ELEM(alias_unique_key));
    err |= USP_REGISTER_Object_UniqueKey(DEVICE_PERMISSION_ROOT, order_unique_key, NUM_ELEM(order_unique_key));

    err |= USP_REGISTER_Object_UniqueKey(DEVICE_CREDENTIAL_ROOT, alias_unique_key, NUM_ELEM(alias_unique_key));
    err |= USP_REGISTER_Object_UniqueKey(DEVICE_CREDENTIAL_ROOT,  cred_unique_key, NUM_ELEM(cred_unique_key));

    // Exit if any errors occurred
    if (err != USP_ERR_OK)
    {
        return USP_ERR_INTERNAL_ERROR;
    }

    // If the code gets here, then registration was successful
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_CTRUST_Start
**
** Starts this component, adding all instances to the data model
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_CTRUST_Start(void)
{
    int i;
    int err;
    char path[MAX_DM_PATH];

    // Inform all role table instances to the data model
    for (i=0; i<kCTrustRole_Max; i++)
    {
        // Exit if unable to add role instance into the data model
        USP_SNPRINTF(path, sizeof(path), "Device.LocalAgent.ControllerTrust.Role.%d", i+1);
        err = DATA_MODEL_InformInstance(path);
        if (err != USP_ERR_OK)
        {
            return err;
        }
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_CTRUST_Stop
**
** Frees all memory used by this component
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void DEVICE_CTRUST_Stop(void)
{
    int i, j;
    role_t *rp;
    permission_t *pp;

    // Iterate over all roles, freeing memory
    for (i=0; i<kCTrustRole_Max; i++)
    {
        // Free all permissions for this role
        rp = &roles[i];
        for (j=0; j < rp->num_permissions; j++)
        {
            pp = &rp->permissions[j];
            USP_SAFE_FREE(pp->targets);
        }
        USP_SAFE_FREE(rp->permissions);
        USP_SAFE_FREE(rp->name);
    }

    // Free all credentials
    USP_SAFE_FREE(credentials);
}

/*********************************************************************//**
**
** DEVICE_CTRUST_AddCertRole
**
** Adds a reference to a certificate and its associated role
** This function is called at startup when the Trust Store certificates are registered
**
** \param   cert_instance - instance number of the certificate in Device.Security.Certificate.{i} table
** \param   role - role associated with the certificate
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_CTRUST_AddCertRole(int cert_instance, ctrust_role_t role)
{
    int err;
    int new_num_entries;
    credential_t *cp;
    char path[MAX_DM_PATH];
    
    // First increase the size of the vector
    new_num_entries = num_credentials + 1;
    credentials = USP_REALLOC(credentials, new_num_entries*sizeof(credential_t));

    // Fill in the new entry
    cp = &credentials[ num_credentials ];
    cp->role = role;
    cp->cert_instance = cert_instance;
    num_credentials = new_num_entries;

    // Exit if unable to add credential instance into the data model
    USP_SNPRINTF(path, sizeof(path), "Device.LocalAgent.ControllerTrust.Credential.%d", num_credentials);
    err = DATA_MODEL_InformInstance(path);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_CTRUST_GetCertRole
**
** Gets the role associated with the specified certificate
**
** \param   cert_instance - Instance number of certificate in Device.Security.Certificate.{i}
**                          that we want to find the registered role for
**
** \return  Role associated with the certificate, or INVALID_ROLE, if no matching role found
**
**************************************************************************/
ctrust_role_t DEVICE_CTRUST_GetCertRole(int cert_instance)
{
    int i;
    credential_t *cp;

    // Iterate over all entries in the Credentials table
    for (i=0; i<num_credentials; i++)
    {
        // Exit if we've found a matching certificate
        cp = &credentials[i];
        if (cp->cert_instance == cert_instance)
        {
            return cp->role;
        }
    }

    // If the code gets here, then no match was found
    // NOTE: This should never happen, as we ensure that all certificates in the trust store have an associated role
    return INVALID_ROLE;
}

/*********************************************************************//**
**
** DEVICE_CTRUST_GetInstanceFromRole
**
** Gets the instance number of the specified role in Device.LocalAgent.ControllerTrust.Role.{i}
** This is very simple because the way the code works, there is a direct mapping between
** the role enumeration and it's instance number
**
** \param   role - role to get the instance number of
**
** \return  instance number of the specified role in the Device.LocalAgent.ControllerTrust.Role table, or INVALID if not found
**
**************************************************************************/
int DEVICE_CTRUST_GetInstanceFromRole(ctrust_role_t role)
{
    // Exit if role enumeration is out of bounds
    // NOTE: This may happen if a device has been assigned an INVALID_ROLE
    if (((int)role < 0) || (role >= kCTrustRole_Max))
    {
        return INVALID;
    }

    return (int)role + 1;
}

/*********************************************************************//**
**
** DEVICE_CTRUST_GetRoleFromInstance
**
** Gets the role of the specified instance number in Device.LocalAgent.ControllerTrust.Role.{i}
** This is very simple because the way the code works, there is a direct mapping between
** the role enumeration and it's instance number
**
** \param   instance - instance number in Device.LocalAgent.ControllerTrust.Role.{i} to get the role of
**
** \return  role of the specified instance or INVALID_ROLE if the instance number was invalid
**
**************************************************************************/
ctrust_role_t DEVICE_CTRUST_GetRoleFromInstance(int instance)
{
    instance--;

    // Exit if role enumeration is out of bounds
    // NOTE: This may happen if a device has been assigned an INVALID_ROLE
    if ((instance < 0) || (instance >= kCTrustRole_Max))
    {
        return INVALID_ROLE;
    }

    return (ctrust_role_t) instance;
}

/*********************************************************************//**
**
** DEVICE_CTRUST_AddPermissions
**
** Adds a permission entry to the specified role in Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i} table
**
** \param   role - role to which we want to add a permission
** \param   path_expr - search expression representing the data model nodes which are affected by the permission
** \param   permission_bitmask - bitmask of permissions to apply to the data model nodes, for the specified role
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int DEVICE_CTRUST_AddPermissions(ctrust_role_t role, char *path_expr, unsigned short permission_bitmask)
{
    int err;
    int new_num_entries;
    role_t *rp;
    permission_t *pp;
    char path[MAX_DM_PATH];

    // Determine which role to add permissions to
    USP_ASSERT(role < kCTrustRole_Max);
    rp = &roles[role];
    
    // Increase the size of the permissions vector for this role
    new_num_entries = rp->num_permissions + 1;
    rp->permissions = USP_REALLOC(rp->permissions, new_num_entries*sizeof(permission_t));

    // Fill in the new entry
    pp = &rp->permissions[ rp->num_permissions ];
    pp->targets = USP_STRDUP(path_expr);
    pp->permission_bitmask = permission_bitmask;
    rp->num_permissions = new_num_entries;

    // Exit if unable to add permission instance into the data model
    USP_SNPRINTF(path, sizeof(path), "Device.LocalAgent.ControllerTrust.Role.%d.Permission.%d", role+1, rp->num_permissions);
    err = DATA_MODEL_InformInstance(path);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** DEVICE_CTRUST_RegisterRoleName
**
** Sets the name of a role
**
** \param   role - role to which we want to assign a name
** \param   name - new name of the role
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void DEVICE_CTRUST_RegisterRoleName(ctrust_role_t role, char *name)
{
    role_t *rp;

    // Free the current name (if one exists)
    USP_ASSERT(role < kCTrustRole_Max);
    rp = &roles[role];
    if (rp->name != NULL)
    {
        USP_FREE(rp->name);
    }

    // Set the new name
    rp->name = USP_STRDUP(name);
}

/*********************************************************************//**
**
** Get_RoleNumEntries
**
** Gets the value of Device.LocalAgent.ControllerTrust.RoleNumberOfEntries
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_RoleNumEntries(dm_req_t *req, char *buf, int len)
{
    val_uint = kCTrustRole_Max;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Get_CredentialNumEntries
**
** Gets the value of Device.LocalAgent.ControllerTrust.CredentialNumberOfEntries
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_CredentialNumEntries(dm_req_t *req, char *buf, int len)
{
    val_uint = num_credentials;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Get_RoleName
**
** Gets the value of Device.LocalAgent.ControllerTrust.Role.{i}.Name
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_RoleName(dm_req_t *req, char *buf, int len)
{
    role_t *rp;

    // Copy the name of the role, if one has been set
    rp = CalcRoleFromReq(req);
    if (rp->name != NULL)
    {
        USP_STRNCPY(buf, rp->name, len);
    }
    else
    {
        // This is the default value, if the vendor has not set a name for this role
        *buf = '\0';
    }
    
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Get_PermissionNumEntries
**
** Gets the value of Device.LocalAgent.ControllerTrust.Role.{i}.PermissionNumberOfEntries
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_PermissionNumEntries(dm_req_t *req, char *buf, int len)
{
    role_t *rp;

    rp = CalcRoleFromReq(req);

    val_uint = rp->num_permissions;

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Get_PermissionOrder
**
** Gets the value of Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.Order
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_PermissionOrder(dm_req_t *req, char *buf, int len)
{
    // Since our vendor interface assumes that the vendor has ordered the permissions, this can just return the instance number in the permission table
    val_uint = inst2 - 1;

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Get_PermissionTargets
**
** Gets the value of Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.Targets
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_PermissionTargets(dm_req_t *req, char *buf, int len)
{
    permission_t *pp;

    pp = CalcPermissionFromReq(req);

    USP_STRNCPY(buf, pp->targets, len);
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Get_ParamPermissions
**
** Gets the value of Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.Param
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_ParamPermissions(dm_req_t *req, char *buf, int len)
{
    permission_t *pp;

    #define PERMISSION_CHAR(pp, c, mask) ( ((pp->permission_bitmask & mask) == 0) ? '-' : c )
    pp = CalcPermissionFromReq(req);

    USP_SNPRINTF(buf, len, "%c%c-%c", PERMISSION_CHAR(pp, 'r', PERMIT_GET),
                                      PERMISSION_CHAR(pp, 'w', PERMIT_SET),
                                      PERMISSION_CHAR(pp, 'n', PERMIT_SUBS_VAL_CHANGE) );
    return USP_ERR_OK;
}


/*********************************************************************//**
**
** Get_ObjPermissions
**
** Gets the value of Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.Obj
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_ObjPermissions(dm_req_t *req, char *buf, int len)
{
    permission_t *pp;

    pp = CalcPermissionFromReq(req);
    USP_SNPRINTF(buf, len, "%c%c-%c", PERMISSION_CHAR(pp, 'r', PERMIT_OBJ_INFO),
                                      PERMISSION_CHAR(pp, 'w', PERMIT_ADD),
                                      PERMISSION_CHAR(pp, 'n', PERMIT_SUBS_OBJ_ADD) );
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Get_InstantiatedObjPermissions
**
** Gets the value of Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.InstantiatedObj
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_InstantiatedObjPermissions(dm_req_t *req, char *buf, int len)
{
    permission_t *pp;

    pp = CalcPermissionFromReq(req);
    USP_SNPRINTF(buf, len, "%c%c-%c", PERMISSION_CHAR(pp, 'r', PERMIT_GET_INST),
                                      PERMISSION_CHAR(pp, 'w', PERMIT_DEL),
                                      PERMISSION_CHAR(pp, 'n', PERMIT_SUBS_OBJ_DEL) );
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Get_CommandEventPermissions
**
** Gets the value of Device.LocalAgent.ControllerTrust.Role.{i}.Permission.{i}.CommandEvent
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_CommandEventPermissions(dm_req_t *req, char *buf, int len)
{
    permission_t *pp;

    pp = CalcPermissionFromReq(req);
    USP_SNPRINTF(buf, len, "%c-%c%c", PERMISSION_CHAR(pp, 'r', PERMIT_CMD_INFO),
                                      PERMISSION_CHAR(pp, 'x', PERMIT_OPER),
                                      PERMISSION_CHAR(pp, 'n', PERMIT_SUBS_EVT_OPER_COMP) );
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Get_CredentialRole
**
** Gets the value of Device.LocalAgent.ControllerTrust.Credential.{i}.Role
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_CredentialRole(dm_req_t *req, char *buf, int len)
{
    credential_t *cp;

    cp = CalcCredentialFromReq(req);
    USP_SNPRINTF(buf, len, "Device.LocalAgent.ControllerTrust.Role.%d", cp->role + 1);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** Get_CredentialCertificate
**
** Gets the value of Device.LocalAgent.ControllerTrust.Credential.{i}.Credential
**
** \param   req - pointer to structure identifying the parameter
** \param   buf - pointer to buffer into which to return the value of the parameter (as a textual string)
** \param   len - length of buffer in which to return the value of the parameter
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int Get_CredentialCertificate(dm_req_t *req, char *buf, int len)
{
    credential_t *cp;

    cp = CalcCredentialFromReq(req);
    USP_SNPRINTF(buf, len, "Device.Security.Certificate.%d", cp->cert_instance);

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** CalcRoleFromReq
**
** Gets a pointer to the role structure located by the specified request
**
** \param   req - pointer to structure identifying the parameter
**
** \return  pointer to role structure
**
**************************************************************************/
role_t *CalcRoleFromReq(dm_req_t *req)
{
    int index;
    role_t *rp;

    index = inst1 - 1;
    USP_ASSERT(index < kCTrustRole_Max);
    USP_ASSERT(index >= 0);
    rp = &roles[index];

    return rp;
}

/*********************************************************************//**
**
** CalcPermissionFromReq
**
** Gets a pointer to the internal permission structure located by the specified request
**
** \param   req - pointer to structure identifying the parameter
**
** \return  pointer to permission structure
**
**************************************************************************/
permission_t *CalcPermissionFromReq(dm_req_t *req)
{
    int index;
    role_t *rp;
    permission_t *pp;

    rp = CalcRoleFromReq(req);

    index = inst2 - 1;
    USP_ASSERT(index < rp->num_permissions);

    pp = &rp->permissions[index];
    return pp;
}

/*********************************************************************//**
**
** CalcCredentialFromReq
**
** Gets a pointer to the credential structure located by the specified request
**
** \param   req - pointer to structure identifying the parameter
**
** \return  pointer to credential structure
**
**************************************************************************/
credential_t *CalcCredentialFromReq(dm_req_t *req)
{
    int index;
    credential_t *cp;

    index = inst1 - 1;
    USP_ASSERT(index < num_credentials);
    cp = &credentials[index];

    return cp;
}

