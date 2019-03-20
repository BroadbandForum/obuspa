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
 * \file common_defs.h
 *
 * Header file containing commonly used macros and definitions
 *
 */
#ifndef COMMON_DEFS_H
#define COMMON_DEFS_H

#include <stdbool.h>    // for bool
#include <stddef.h>     // for NULL
#include "vendor_defs.h"
#include "usp_err.h"
#include "usp_log.h"
#include "usp_mem.h"

// Number of elements in an array
#define NUM_ELEM(x) (sizeof((x)) / sizeof((x)[0]))

// Minimum of two values
#define MIN(x, y)  ( ((x) <= (y)) ? (x) : (y) )

// Maximum of two values
#define MAX(x, y)  ( ((x) >= (y)) ? (x) : (y) )

// Whether a character is an alphanumeric symbol character
#define IS_ALPHA(c)  ( ((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) )
#define IS_NUMERIC(c)  ((c >= '0') && (c <= '9'))
#define IS_DASH(c)     ((c == '_') || (c == '-'))
#define IS_ALPHA_NUMERIC(c)  ( IS_ALPHA(c) || IS_NUMERIC(c) || IS_DASH(c) )

// Magic values used to denote invalid
#define INVALID (-1)

// Safe version of snprintf, that ensures buffer is always zero terminated, and does not overrun
extern int USP_SNPRINTF(char *dest, size_t size, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

// Safe version of strncpy, that ensures buffer is always zero terminated, and does not overrun
#define USP_STRNCPY(dest, src, len) strncpy(dest, src, len-1); (dest)[len-1] = '\0';

// Used to make while loops that do not have an outer level exit condition, readable
#define FOREVER 1

//------------------------------------------------------------------------------
// Macro that converts the given pre-processor argument to a string (TO_STR)
#define STRINGIFY(x) #x
#define TO_STR(x) STRINGIFY(x)

//-----------------------------------------------------------------------------------------------
// Macros to write a value to a byte stream buffer (big endian format), updating the pointer
#define WRITE_BYTE(buf, v)  buf[0] = (unsigned char)(v & 0xFF); buf++;
#define WRITE_2_BYTES(buf, v) buf[0] = (unsigned char)((v >> 8) & 0xFF);  buf[1] = (unsigned char)(v & 0xFF); buf += 2;
#define WRITE_3_BYTES(buf, v) buf[0] = (unsigned char)((v >> 16) & 0xFF); buf[1] = (unsigned char)((v >> 8) & 0xFF); buf[2] = (unsigned char)(v & 0xFF); buf += 3;
#define WRITE_4_BYTES(buf, v) buf[0] = (unsigned char)((v >> 24) & 0xFF); buf[1] = (unsigned char)((v >> 16) & 0xFF); buf[2] = (unsigned char)((v >> 8) & 0xFF); buf[3] = (unsigned char)(v & 0xFF); buf += 4;

//-----------------------------------------------------------------------------------------------
// Global variables set by command line
extern bool enable_callstack_debug;


#endif

