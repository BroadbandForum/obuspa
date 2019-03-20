/*
 *
 * Copyright (C) 2016-2019  ARRIS Enterprises, LLC
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
 * \file usp_err.h
 *
 * Header file for USP error codes and Error buffer
 * The error buffer is used to store error message in the function that generated them, 
 * for use by functions higher up the call chain (eg to put in a USP response message)
 *
 */
#ifndef USP_ERR_H
#define USP_ERR_H

#include "usp_err_codes.h"

//------------------------------------------------------------------------------------
// Functions to set and get the error message associated with the error
#define USP_ERR_MAXLEN 512      // Maximum size of buffer used to store log messages (NOTE: This may be multiple lines eg STOMP header)
void USP_ERR_Init(void);
void USP_ERR_SetMessage_Sql(const char *func, int line, const char *sqlfunc, void *db_handle);
void USP_ERR_SetMessage_SqlParam(const char *func, int line, const char *sqlfunc, void *db_handle);
void USP_ERR_SetMessage_Errno(const char *func, int line, const char *failed_func, int err);
void USP_ERR_ClearMessage(void);
void USP_ERR_ReplaceEmptyMessage(char *fmt, ...) __attribute__((format(printf, 1, 2)));
char *USP_ERR_GetMessage(void);

//------------------------------------------------------------------------------------
// Helper macros, so that the code does not have to provide (__FUNCTION__, __LINE__) to the underlying function
#define USP_ERR_SQL(handle, sqlfunc)  USP_ERR_SetMessage_Sql(__FUNCTION__, __LINE__, sqlfunc, handle)
#define USP_ERR_SQL_PARAM(handle, sqlfunc)  USP_ERR_SetMessage_SqlParam(__FUNCTION__, __LINE__, sqlfunc, handle)
#define USP_ERR_ERRNO(failed_func, err)  USP_ERR_SetMessage_Errno(__FUNCTION__, __LINE__, failed_func, err)

//------------------------------------------------------------------------------------
// Functions to exit USP Agent because an error has occurred
void USP_ERR_Terminate(char *fmt, ...) __attribute__((format(printf, 1, 2)));
void USP_ERR_Terminate_BadCase(const char *func, int line, int value);
void USP_ERR_Terminate_OnAssert(const char *func, int line, char *statement);

//------------------------------------------------------------------------------------
// Helper macros, so that the code does not have to provide (__FUNCTION__, __LINE__) to the underlying function
#define TERMINATE_BAD_CASE(x)  USP_ERR_Terminate_BadCase(__FUNCTION__, __LINE__, x)
#define USP_ASSERT(x) if (!(x)) { USP_ERR_Terminate_OnAssert(__FUNCTION__, __LINE__, #x); }

#endif
