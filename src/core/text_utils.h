/*
 *
 * Copyright (C) 2019, Broadband Forum
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
 * \file text_utils.h
 *
 * Header file for API to convert and validate types from strings
 *
 */
#ifndef TEXT_UTILS_H
#define TEXT_UTILS_H

#include "str_vector.h"
#include "nu_ipaddr.h"

//-------------------------------------------------------------------------
// API functions
int TEXT_UTILS_CalcHash(char *s);
int TEXT_UTILS_StringToUnsigned(char *str, unsigned *value);
int TEXT_UTILS_StringToInteger(char *str, int *value);
int TEXT_UTILS_StringToUnsignedLong(char *str, unsigned long *value);
int TEXT_UTILS_StringToBool(char *str, bool *value);
char *TEXT_UTILS_BoolToString(bool value);
int TEXT_UTILS_StringToEnum(char *str, const enum_entry_t *enums, int num_enums);
char *TEXT_UTILS_EnumToString(int value, const enum_entry_t *enums, int num_enums);
int TEXT_UTILS_StringToDateTime(char *str, time_t *value);
int TEXT_UTILS_StringToBinary(char *str, unsigned char *buf, int len, int *bytes_written);
int TEXT_UTILS_StringToIpAddr(char *str, nu_ipaddr_t *ip_addr);
char *TEXT_UTILS_SplitPath(char *path, char *buf, int len);
char *TEXT_UTILS_SplitPathAtSeparator(char *path, char *buf, int len, int separator_split);
void TEXT_UTILS_SplitString(char *str, str_vector_t *sv, char *separator);
char *TEXT_UTILS_StrStr(char *haystack, char *needle);
int TEXT_UTILS_NullStringCompare(char *str1, char *str2);
char *TEXT_UTILS_UnescapeString(char *buf);
char *TEXT_UTILS_TrimBuffer(char *buf);
bool TEXT_UTILS_IsSymbol(char *buf);
int TEXT_UTILS_HexDigitToValue(char c);
char TEXT_UTILS_ValueToHexDigit(int nibble);
int TEXT_UTILS_ToJSONFormat(char *buf, int len);
void TEXT_UTILS_PathToSchemaForm(char *path, char *buf, int len);
int TEXT_UTILS_CountConsecutiveDigits(char *s);
char *TEXT_UTILS_StrDupWithTrailingDot(char *path);

#endif

