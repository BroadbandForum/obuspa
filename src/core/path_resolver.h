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
 * \file path_resolver.h
 *
 * Header file for API to functions which resolve path exressions into objects and parameters in the data model
 *
 */
#ifndef PATH_RESOLVER_H
#define PATH_RESOLVER_H

#include "str_vector.h"

// Enumeration determining what we are attempting to resolve with the path expression
// This affects whether the path is valid, along with which object/parameter paths are returned
typedef enum
{
    kResolveOp_Get,     // Resolves parameters. Forgiving of permissions and errors.
    kResolveOp_Set,     // Resolves parameters
    kResolveOp_Add,     // Resolves objects that are not fully qualified
    kResolveOp_Del,     // Resolves fully qualified objects that exist
    kResolveOp_Oper,    // Resolves operations (for when a request is made to perform an operation)
    kResolveOp_Event,   // Resolves events (currently not triggered by the code - included for completeness)
    kResolveOp_Instances, // Resolves fully qualified objects that exist

    // The following operations are similar to their conterparts above, other than they check different permission bits
    kResolveOp_SubsValChange, // Resolves the ReferenceList of a value change subscription. Forgiving of errors.
    kResolveOp_SubsAdd, // Resolves the ReferenceList of an object creation subscription
    kResolveOp_SubsDel, // Resolves the ReferenceList of an object deletion subscription
    kResolveOp_SubsOper,// Resolves the ReferenceList of an operation complete subscription
    kResolveOp_SubsEvent,// Resolves the ReferenceList of an event complete subscription

    // Special resolve operations
    kResolveOp_GetBulkData, // Resolves get parameters. Unforgiving of permissions. Only allows partial path and wildcards.

    kResolveOp_Any,     // This just checks that the expression is syntactically correct, but does not check resolved paths for validity
} resolve_op_t;

// Bitmask for the flags argument of PATH_RESOLVER_ResolvePath(). Thse flags control resolving of the path
#define GET_ALL_INSTANCES 0x0001

// API
int PATH_RESOLVER_ResolveDevicePath(char *path, str_vector_t *sv, resolve_op_t op, int *separator_split, combined_role_t *combined_role, unsigned flags);
int PATH_RESOLVER_ResolvePath(char *path, str_vector_t *sv, resolve_op_t op, int *separator_split, combined_role_t *combined_role, unsigned flags);



#endif

