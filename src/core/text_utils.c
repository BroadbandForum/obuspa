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
 * \file text_utils.c
 *
 * Implements functions used to convert strings to different types
 *
 */

#include <stdlib.h>
#include <string.h>

#include "common_defs.h"
#include "str_vector.h"
#include "text_utils.h"
#include "iso8601.h"

//-------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them


/*********************************************************************//**
**
** TEXT_UTILS_CalcHash
**
** Implements a 32 bit hash of the specified string
** Implemented using the FNV1a algorithm
**
** \param   s - pointer to string to calculate the hash of
**
** \return  hash value
**
**************************************************************************/
int TEXT_UTILS_CalcHash(char *s)
{
    #define OFFSET_BASIS (0x811C9DC5)
    #define FNV_PRIME (0x1000193)
    unsigned hash = OFFSET_BASIS;

    while (*s != '\0')
    {
        hash = hash * FNV_PRIME;
        hash = hash ^ (*s);
        s++;
    }

    return (int)hash;
}

/*********************************************************************//**
**
** TEXT_UTILS_StringToUnsigned
**
** Converts a string to an unsigned integer
**
** \param   str - string containing value to convert
** \param   value - pointer to variable to return converted value in
**
** \return  USP_ERR_OK if converted successfully
**          USP_ERR_INVALID_TYPE if unable to convert the string
**
**************************************************************************/
int TEXT_UTILS_StringToUnsigned(char *str, unsigned *value)
{
    unsigned long long lvalue;
    int err;

    // Exit if unable to convert to an unsigned number
    err = TEXT_UTILS_StringToUnsignedLongLong(str, &lvalue);
    if (err != USP_ERR_OK)
    {
        return err;
    }

    // Exit if value is not in range
    if (lvalue > UINT_MAX)
    {
        USP_ERR_SetMessage("%s: '%s' is too large for an unsignedInt", __FUNCTION__, str);
        return USP_ERR_INVALID_TYPE;
    }

    // Value was converted successfully
    *value = lvalue;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** TEXT_UTILS_StringToInteger
**
** Converts a string to a signed integer
**
** \param   str - string containing value to convert
** \param   value - pointer to variable to return converted value in
**
** \return  USP_ERR_OK if converted successfully
**          USP_ERR_INVALID_TYPE if unable to convert the string
**
**************************************************************************/
int TEXT_UTILS_StringToInteger(char *str, int *value)
{
    int num_converted;
    
    num_converted = sscanf(str, "%d", value);
    if (num_converted != 1)
    {
        USP_ERR_SetMessage("%s: '%s' is not a valid signed integer", __FUNCTION__, str);
        return USP_ERR_INVALID_TYPE;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** TEXT_UTILS_StringToUnsignedLongLong
**
** Converts a string to an unsigned long long integer (64 bit)
**
** \param   str - string containing value to convert
** \param   value - pointer to variable to return converted value in
**
** \return  USP_ERR_OK if converted successfully
**          USP_ERR_INVALID_TYPE if unable to convert the string
**
**************************************************************************/
int TEXT_UTILS_StringToUnsignedLongLong(char *str, unsigned long long *value)
{
    char *endptr = NULL;

    // Exit if string contains a negative number
    if (strchr(str, '-') != NULL)
    {
        USP_ERR_SetMessage("%s: '%s' is not a valid unsigned number", __FUNCTION__, str);
        return USP_ERR_INVALID_TYPE;
    }

    // Exit if unable to convert
    errno = 0;
    *value = strtoull(str, &endptr, 10);
    if ((endptr == NULL) || (*endptr != '\0') || (errno != 0))
    {
        USP_ERR_SetMessage("%s: '%s' is not a valid unsigned number", __FUNCTION__, str);
        return USP_ERR_INVALID_TYPE;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** TEXT_UTILS_StringToBool
**
** Converts a string to a boolean type
**
** \param   str - string containing value to convert
** \param   value - pointer to variable to return converted value in
**
** \return  USP_ERR_OK if converted successfully
**          USP_ERR_INVALID_TYPE if unable to convert the string
**
**************************************************************************/
int TEXT_UTILS_StringToBool(char *str, bool *value)
{
    // Exit if string matches true
    if ((strcasecmp(str, "true")==0) || (strcmp(str, "1")==0))
    {
        *value = true;
        return USP_ERR_OK;
    }

    // Exit if string matches false
    if ((strcasecmp(str, "false")==0) || (strcmp(str, "0")==0))
    {
        *value = false;
        return USP_ERR_OK;
    }

    // If the code gets here, then the string did not represent a boolean
    USP_ERR_SetMessage("%s: '%s' is not a valid boolean", __FUNCTION__, str);
    return USP_ERR_INVALID_TYPE;
}

/*********************************************************************//**
**
** TEXT_UTILS_BoolToString
**
** Converts a boolean type to a string
**
** \param   value - boolean value to convert
**
** \return  pointer to string representation
**
**************************************************************************/
char *TEXT_UTILS_BoolToString(bool value)
{
    return (value) ? "true" : "false";
}

/*********************************************************************//**
**
** TEXT_UTILS_StringToEnum
**
** Converts a string to an enumerated integer representation
**
** \param   str - pointer to string to convert
** \param   enums - pointer to conversion table containing a list of enumerations and their associated string representation
** \param   num_enums - number of enumerations in the table
**
** \return  Enumerated value or INVALID if unable to convert
**
**************************************************************************/
int TEXT_UTILS_StringToEnum(char *str, const enum_entry_t *enums, int num_enums)
{
    int i;
    const enum_entry_t *e;

    // Iterate over all enumerations in the table, finding the one which matches the string we've just retrieved from the database
    for (i=0; i<num_enums; i++)
    {
        e = &enums[i];
        if (strcmp(str, e->name)==0)
        {
            return e->value;
        }
    }

    // If the code gets here, then the string could not be converted
    USP_ERR_SetMessage("%s: '%s' is not a valid enumerated value", __FUNCTION__, str);
    return INVALID;
}

/*********************************************************************//**
**
** TEXT_UTILS_EnumToString
**
** Converts an enumerated integer to a string representation
**
** \param   value - enumerated integer to convert to a string
** \param   enums - pointer to conversion table containing a list of enumerations and their associated string representation
** \param   num_enums - number of enumerations in the table
**
** \return  pointer to converted string or "UNKNOWN" if unable to convert
**
**************************************************************************/
char *TEXT_UTILS_EnumToString(int value, const enum_entry_t *enums, int num_enums)
{
    int i;
    const enum_entry_t *e;

    // Iterate over all enumerations in the table, finding the one which matches the string we've just retrieved from the database
    for (i=0; i<num_enums; i++)
    {
        e = &enums[i];
        if (e->value == value)
        {
            return e->name;
        }
    }

    // If the code gets here, then the enum could not be converted
    // In this case, still return a string, as this function is used mainly for debug
    return "UNKNOWN";
}

/******************************************************************//**
**
** TEXT_UTILS_StringToDateTime
**
** Converts a string to a time_t type
**
** \param   str - string containing value to convert
** \param   value - pointer to variable to return converted value in
**
** \return  USP_ERR_OK if converted successfully
**          USP_ERR_INVALID_TYPE if unable to convert the string
**
**************************************************************************/
int TEXT_UTILS_StringToDateTime(char *str, time_t *value)
{
    time_t date;

    date = iso8601_to_unix_time(str);
    if (date == INVALID_TIME)
    {
        USP_ERR_SetMessage("%s: '%s' is not a valid ISO8601 dateTime", __FUNCTION__, str);
        return USP_ERR_INVALID_TYPE;
    }

    *value = date;
    return USP_ERR_OK;
}


/*********************************************************************//**
**
** TEXT_UTILS_StringToBinary
**
** Converts a long hexadecimal ASCII format string into it's binary format in a buffer
**
** \param   str - pointer to input string to convert (in ASCII hexadecimal format)
** \param   buf - pointer to buffer in which to write the binary data
** \param   len - length of the buffer
** \param   bytes_written - pointer to variable in which to return the number of bytes written into the buffer
**
** \return  USP_ERR_OK if successful.
**          USP_ERR_INVALID_TYPE if unable to convert the string
**
**************************************************************************/
int TEXT_UTILS_StringToBinary(char *str, unsigned char *buf, int len, int *bytes_written)
{
    int num_nibbles;    // Number of 4 bit nibbles (hex characters) in the string
    int num_bytes;
    int i;
    char *p;
    char c;
    int hi_nibble;
    int lo_nibble;

    // Exit if the string to convert does not represent an integer number of bytes
    num_nibbles = strlen(str);
    if ((num_nibbles % 2) != 0)
    {
        USP_ERR_SetMessage("%s: ASCII hexadecimal string does not contain an integer number of bytes", __FUNCTION__);
        return USP_ERR_INVALID_TYPE;
    }

    // Exit if number of bytes to convert is larger than the buffer provided to return them in
    num_bytes = num_nibbles/2;
    if (num_bytes > len)
    {
        USP_ERR_SetMessage("%s: ASCII hexadecimal string is longer than expected (length=%d, maximum=%d)", __FUNCTION__, num_bytes, len);
        return USP_ERR_INVALID_TYPE;
    }

    p = str;
    for (i=0; i<num_bytes; i++)
    {
        // Exit if unable to convert high nibble in a byte
        c = *p++;
        hi_nibble = TEXT_UTILS_HexDigitToValue(c);
        if (hi_nibble == INVALID)
        {
            USP_ERR_SetMessage("%s: ASCII hexadecimal string contains invalid character '%c' (code=0x%02x)", __FUNCTION__, c, c);
            return USP_ERR_INVALID_TYPE;
        }

        // Exit if unable to convert low nibble in a byte
        c = *p++;
        lo_nibble = TEXT_UTILS_HexDigitToValue(c);
        if (lo_nibble == INVALID)
        {
            USP_ERR_SetMessage("%s: ASCII hexadecimal string contains invalid character '%c' (code=0x%02x)", __FUNCTION__, c, c);
            return USP_ERR_INVALID_TYPE;
        }

        // Pack nibbles into a byte and write to return buffer
        buf[i] = (unsigned char)( (hi_nibble << 4) + lo_nibble );
    }

    *bytes_written = num_bytes;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** TEXT_UTILS_StringToIpAddr
**
** Converts a string to an IP address (IPv4 or IPv6)
** NOTE: An empty string is converted to the zero IP address - this is used by UDP Echo Config
**
** \param   str - string containing comma-delimited substrings
** \param   ip_addr - pointer to variable in which to return the converted IP address
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int TEXT_UTILS_StringToIpAddr(char *str, nu_ipaddr_t *ip_addr)
{
    int err;

    // Exit if the string is empty, this returns as the zero IP address
    if (*str == '\0')
    {
        nu_ipaddr_set_zero(ip_addr);
        return USP_ERR_OK;
    }

    // Exit if unable to convert the string to an IP address
    err = nu_ipaddr_from_str(str, ip_addr);
    if (err != USP_ERR_OK)
    {
        USP_ERR_SetMessage("%s: Unable to convert IP address (%s)", __FUNCTION__, str);
        return USP_ERR_INVALID_TYPE;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** TEXT_UTILS_SplitString
**
** Splits a string on a specified separator into substrings
** NOTE: Substrings are trimmed of whitespace at the start and end
**
** \param   str - string containing comma-delimited substrings
** \param   sv - pointer to vector to return substrings in
** \param   separator - pointer to string containing separator
**
** \return  None
**
**************************************************************************/
void TEXT_UTILS_SplitString(char *str, str_vector_t *sv, char *separator)
{
    char *start;
    char *end;
    char *trimmed;
    int sep_len;
    char buf[MAX_DM_VALUE_LEN];

    // Initialise the string vector to an empty list
    STR_VECTOR_Init(sv);

    // Exit if the input string is empty - nothing to do
    if (*str == '\0')
    {
        return;
    }

    // Copy into a local buffer, as we will be making inline changes to the string
    USP_STRNCPY(buf, str, sizeof(buf));

    // Iterate over all strings delimited by the separator
    // 2DO RH: This function can be made to ignore separators present in the string within quotes by creating a special version of strstr
    sep_len = strlen(separator);
    start = buf;
    end = TEXT_UTILS_StrStr(start, separator);
    while (end != NULL)
    {
        *end = '\0';                    // Temporarily truncate the original string at the separator
        trimmed = TEXT_UTILS_TrimBuffer(start);
        if (*trimmed != '\0')           // Ignore trailing whitespace, double separators, or separators separated by whitespace
        {
            STR_VECTOR_Add(sv, trimmed);
        }
        *end = separator[0];            // Restore the original string

        // Move to after this separator
        start = end + sep_len;

        // Find start of next separator
        end = TEXT_UTILS_StrStr(start, separator);
    }

    // Add the final string (terminated by a NULL terminator)
    trimmed = TEXT_UTILS_TrimBuffer(start);
    if (*trimmed != '\0')           // Ignore trailing whitespace, double separators, or separators separated by whitespace
    {
        STR_VECTOR_Add(sv, trimmed);
    }
}

/*********************************************************************//**
**
** TEXT_UTILS_StrncpyLen
**
** Performs a strncpy() of a source string whose length is specified (rather than being NULL terminated)
**
** \param   dst - pointer to buffer to copy source string into
** \param   dst_len - length of the destination buffer
** \param   src - pointer to buffer containing string to copy
** \param   src_len - length of the source buffer
**
** \return  None
**
**************************************************************************/
void TEXT_UTILS_StrncpyLen(char *dst, int dst_len, char *src, int src_len)
{
    // Deal with case of truncating src string to fit in destination buffer
    if (dst_len < src_len + 1)      // Plus 1 to include NULL terminator
    {
        src_len = dst_len - 1;      // Minus 1 to include NULL terminator
    }

    // Copy the src string into the destination buffer and NULL terminate it
    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
}

/*********************************************************************//**
**
** TEXT_UTILS_StrStr
**
** Finds the first occurrence of the string 'needle' in the string 'haystack'
** NOTE: This differs from the standard library implementation of ststr() in that it skips sub strings
**       enclosed in quotes, embedded in haystack. Thus quoted substrings within haystack may contain 'needle'
**       This is useful for eg ServerSelection diagnostics driven from USP Agent CLI, as HostList also
**       contains the separator character (',')
**
** \param   haystack - string to searh in
** \param   needle - string to search for
**
** \return  Pointer to the beginning of the needle string found (in haystack) or NULL if no string found
**
**************************************************************************/
char *TEXT_UTILS_StrStr(char *haystack, char *needle)
{
    int needle_len;
    char c;
    char *end;

    needle_len = strlen(needle);
    c = *haystack;
    while (c != '\0')
    {
        // Skip sub-strings enclosed in quotes
        if ((c=='\"') || (c=='\''))
        {
            // Exit if sub-string is unterminated by a matching quote character
            end = strchr(&haystack[1], c);
            if (end == NULL)
            {
                return NULL;
            }

            // Skip to the end of the enclosed quoted string
            haystack = end;
        }
        else if (c==*needle)
        {
            // Exit if needle has been found
            if (strncmp(haystack, needle, needle_len)==0)
            {
                return haystack;
            }
        }
        
        // Move to next character
        haystack++;
        c = *haystack;
    }

    // If the code gets here, then the needle has not been found in the haystack
    return NULL;
}

/*********************************************************************//**
**
** TEXT_UTILS_SplitPath
**
** Splits the specified data model path into an object path (returned in a buffer) and the parameter/event/operation name
**
** \param   path - pointer to data model parameter to split
** \param   buf - pointer to buffer in which to return the path of the parent object of the parameter
** \param   len - length of the return buffer
**
** \return  pointer to parameter name - this is within the original 'path' input buffer
**
**************************************************************************/
char *TEXT_UTILS_SplitPath(char *path, char *buf, int len)
{
    char *p;
    int size;

    // Exit if unable to find the last separator in the string
    p = strrchr(path, '.');
    if (p == NULL)
    {
        // If there wasn't a last separator, then don't return anything for 'object'
        *buf = '\0';
        return buf;
    }

    p++;        // Make p point to the name of the event/command/param

    // If the code gets here, p points to the point at which we want to split the string

    // Copy the left-hand-side into the return buffer
    size = p - path;
    size = MIN(size, len-1);
    memcpy(buf, path, size);
    buf[size] = '\0';

    // Return a pointer to the right-hand-side
    return p;

}

/*********************************************************************//**
**
** TEXT_UTILS_SplitPathAtSeparator
**
** Splits the specified data model path into an object path (returned in a buffer) and the parameter/event/operation name
** The position at where to split is based on a count of the number of separators ('.') to include in the object portion
**
** \param   path - pointer to data model parameter to split
** \param   buf - pointer to buffer in which to return the path of the parent object of the parameter
** \param   len - length of the return buffer
** \param   separator_split - count of number of separators included in the 'object' portion of the path
**
** \return  pointer to parameter name - this is within the original 'path' input buffer
**
**************************************************************************/
char *TEXT_UTILS_SplitPathAtSeparator(char *path, char *buf, int len, int separator_split)
{
    char *p;
    int size;

    // If no split is specified, then just split on the last object in the path
    // NOTE: This maybe the case if the path was fully specified and did not require any resolution
    if (separator_split == 0)
    {
        return TEXT_UTILS_SplitPath(path, buf, len);
    }

    // Skip to split point by counting separators
    p = path;
    while (separator_split > 0)
    {
        // Skip to the next separator
        p = strchr(p, '.');

        // If the number of separators to skip is greater than the number in the path string, then just split on the last object in the path
        // NOTE: This should never occur (and does not in automated tests), however leaving code in for safety's sake
        if (p == NULL)
        {
            return TEXT_UTILS_SplitPath(path, buf, len);
        }

        p++;    // Skip the '.' itself
        separator_split--;
    }

    // If the code gets here, p points to the point at which we want to split the string

    // Copy the left-hand-side into the return buffer
    size = p - path;
    size = MIN(size, len-1);
    memcpy(buf, path, size);
    buf[size] = '\0';

    // Return a pointer to the right-hand-side
    return p;
}

/*********************************************************************//**
**
** TEXT_UTILS_KeyValueFromString
**
** Parses a line (read from a file) that contains two strings (a key and a value) separated by whitespace
** NOTE: The key and value are contained in the line buffer. The line buffer is modified by this function.
**
** \param   buf - pointer to buffer containing the line read from the file
** \param   key - pointer to variable in which to return a pointer to the key
** \param   value - pointer to variable in which to return a pointer to the value
**
** \return  USP_ERR_OK if no error occurred.
**          NOTE: Even if no error occurred, key and value may be returned as NULL, if the line is empty or a comment
**
**************************************************************************/
int TEXT_UTILS_KeyValueFromString(char *buf, char **key, char **value)
{
    char *p;
    int len;
    int key_len;
    
    // Set default return parameters
    *key = NULL;
    *value = NULL;
    
    // Exit if this line is a comment - nothing more to do
    if (buf[0] == '#')
    {
        return USP_ERR_OK;
    }

    // Truncate string at newline
    p = strchr(buf, '\n');
    if (p != NULL)
    {
        *p = '\0';
    }
    
    // Truncate string at carriage return
    p = strchr(buf, '\r');
    if (p != NULL)
    {
        *p = '\0';
    }
    
    // Skip leading whitespace
    #define WHITESPACE_CHARS " \t"
    len = strspn(buf, WHITESPACE_CHARS);
    if (len != 0)
    {
        buf += len;
    }

    // Find extent of key
    key_len = strcspn(buf, WHITESPACE_CHARS);
    if (key_len == 0)
    {
        // Skip empty lines
        return USP_ERR_OK;
    }


    // Exit if no value has been specified
    p = TEXT_UTILS_TrimBuffer(&buf[key_len]);
    if (*p == '\0')
    {
        USP_LOG_Error("%s: No value specified for line '%s'", __FUNCTION__, buf);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Exit if value was enclosed in speech marks at one end, but not the other
    #define SPEECH_MARK '\"'
    len = strlen(p);
    if ((*p == SPEECH_MARK) && (p[len-1]) != SPEECH_MARK)
    {
        USP_LOG_Error("%s: Expected \" at end of parameter value (%s)", __FUNCTION__, p);
        return USP_ERR_INTERNAL_ERROR;
    }

    if ((*p != SPEECH_MARK) && (p[len-1]) == SPEECH_MARK)
    {
        USP_LOG_Error("%s: Expected \" at start of parameter value (%s)", __FUNCTION__, p);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Trim value of speech marks (if present)
    if (*p == SPEECH_MARK)
    {
        p[len-1] = '\0';
        p++;
    }

    // Null terminate the key string and setup return values
    buf[key_len] = '\0';
    *key = buf;
    *value = p;

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** TEXT_UTILS_NullStringCompare
**
** Compares two strings, treating string pointers which are NULL as equal
**
** \param   buf - pointer to buffer containing string to trim
**
** \return  USP_ERR_OK if validated successfully
**          USP_ERR_INVALID_TYPE if string value does not represent an unsigned integer
**
**************************************************************************/
int TEXT_UTILS_NullStringCompare(char *str1, char *str2)
{
    // If either of the strings are NULL...
    if ((str1==NULL) || (str2==NULL))
    {
        // Then if both are NULL, it's a match
        if ((str1==NULL) && (str2==NULL))
        {
            return 0;
        }
        else
        {
            // Otherwise, the strings do not match
            return -1;
        }
    }
    
    // Since both strings are non-NULL, compare them with the standard strcmp function
    return strcmp(str1, str2);
}

/*********************************************************************//**
**
** TEXT_UTILS_TrimBuffer
**
** Trims the string in a buffer of leading and trailing whitespace by 
** truncating the string in the buffer and returning a new pointer to the start of the string in the buffer
**
** \param   buf - pointer to buffer containing string to trim
**
** \return  pointer to string in buffer
**
**************************************************************************/
char *TEXT_UTILS_TrimBuffer(char *buf)
{
    char c;
    char *first = NULL;
    char *last = buf;

    // Iterate over all characters in the buffer
    c = *buf;
    while (c != '\0')
    {
        if ((c != ' ') && (c != '\t'))
        {
            // Store a pointer to the first non-whitespace character in the buffer
            if (first == NULL)
            {
                first = buf;
            }

            last = buf;
        }

        buf++;
        c = *buf;
    }

    // Exit if all characters are whitespace, returning an empty string
    if (first == NULL)
    {
        *last = '\0';
        return last;
    }

    // Truncate the string of trailing whitespace
    last[1] = '\0';

    // Return the first non-whitespace character in the buffer
    return first;
}

/*********************************************************************//**
**
** TEXT_UTILS_PercentEncodeString
**
** Converts any non-reserved characters in the input string to percent escaped characters in the output buffer
**
** \param   src - pointer to buffer containing string to percent encode
** \param   dst - pointer to buffer in which to store the percent encoded output string
** \param   dst_len - length of buffer in which to store the percent encoded output string
** \param   safe_char - character which should not be percent encoded
**
** \return  None
**
**************************************************************************/
void TEXT_UTILS_PercentEncodeString(char *src, char *dst, int dst_len, char safe_char)
{
    char c;
    bool is_unreserved;
    int num_required;

    // Reserve space in the destination buffer for a trailing NULL terminator
    USP_ASSERT(dst_len > 0);    
    dst_len--;
    
    c = *src++;
    while (c != '\0')
    {
        // Determine if character is a unreserved character
        is_unreserved =  IS_ALPHA_NUMERIC(c) || (c=='.') || (c=='~');

        // Override for safe character, this is always left unencoded
        if (c == safe_char)
        {
            is_unreserved = true;
        }

        // Exit loop if there is not enough space for the (potentially escaped) character in the output buffer
        num_required = (is_unreserved) ? 1 : 3;
        if (dst_len < num_required)
        {
            goto exit;
        }

        if (is_unreserved)
        {
            // Unreserved characters do not have to be percent encoded
            *dst++ = c;
        }
        else
        {
            *dst++ = '%';
            *dst++ = TEXT_UTILS_ValueToHexDigit( BITS(7, 4, c));
            *dst++ = TEXT_UTILS_ValueToHexDigit( BITS(3, 0, c));
        }

        // Decrement space left in the output buffer and move to next input character
        dst_len -= num_required;
        c = *src++;
    }

exit:
    // Ensure the destination buffer is NULL terminated
    *dst = '\0';
}

/*********************************************************************//**
**
** TEXT_UTILS_PercentDecodeString
**
** Converts any percent escaped characters within a string buffer back to their character
** The changes to the string are made in-place within the input buffer
**
** \param   buf - pointer to buffer containing string to trim
**
** \return  NULL if a 2 digit hex value did not follow any percent, otherwise buf
**
**************************************************************************/
char *TEXT_UTILS_PercentDecodeString(char *buf)
{
    char c;
    char *src;
    char *dest;
    char hex1, hex2;
    int digit1, digit2;
    char unescaped;

    src = buf;
    dest = buf;
    c = *src;
    while (c != '\0')
    {
        if (c == '%')
        {
            // Exit if string ends in a trailing '%' without a 2 digit trailing hex number following
            src++;
            hex1 = *src++;
            if (hex1 == '\0')
            {
                return NULL;
            }

            hex2 = *src++;
            if (hex2 == '\0')
            {
                return NULL;
            }

            // Exit if not a valid hex number            
            digit1 = TEXT_UTILS_HexDigitToValue(hex1);
            digit2 = TEXT_UTILS_HexDigitToValue(hex2);
            if ((digit1 == INVALID) || (digit2==INVALID))
            {
                return NULL;
            }

            unescaped = (char)(16*digit1 + digit2);
            *dest++ = unescaped;
        }
        else
        {
            // Copy down characters
            if (dest != src)
            {
                *dest = *src;
            }

            // Move to next character
            src++;
            dest++;
        }

        c = *src;
    }

    // If the code gets here, we have stepped through all characters in the string converting them
    // So terminate the string
    *dest = '\0';
    return buf;
}

/*********************************************************************//**
**
** TEXT_UTILS_ReplaceCharInString
**
** Replaces all occurrences of the specified character with the specified string
**
** \param   src - pointer to string to convert
** \param   match_char - character to replace
** \param   replacement - pointer to string containing replacement characters for the match_char
** \param   dst - pointer to buffer in which to write the converted string
** \param   dst_len - length of buffer in which to write the converted string
**
** \return  NULL if a 2 digit hex value did not follow any percent, otherwise buf
**
**************************************************************************/
void TEXT_UTILS_ReplaceCharInString(char *src, char match_char, char *replacement, char *dst, int dst_len)
{
    char c;
    int replacement_len;

    // Reserve space for a trailing NULL in the destination buffer
    dst_len--;

    replacement_len = strlen(replacement);

    // Iterate over all characters in the source string, replacing matches
    c = *src++;
    while (c != '\0')
    {
        if (c == match_char)
        {
            // Found the specified character to replace
            // Exit loop if no enough space to store the replacement
            if (replacement_len > dst_len)
            {
                break;
            }

            // Store the replacement
            memcpy(dst, replacement, replacement_len);
            dst += replacement_len;
            dst_len -= replacement_len;
        }
        else
        {
            // If not the specified character to replace, then just copy across the current source character
            *dst++ = c;
            dst_len--;
        }

        // Exit if the destination buffer is full
        if (dst_len == 0)
        {
            break;
        }

        // Move to the next character in the input string
        c = *src++;
    }

    // Ensure destination string is always NULL terminated
    *dst = '\0';
}

/*********************************************************************//**
**
** TEXT_UTILS_IsSymbol
**
** Determines whether the specified string is a valid symbol (ie contains only alpha-numeric characters)
**
** \param   buf - pointer to buffer containing symbol to validate
**
** \return  true if the symbol is valid, false otherwise
**
**************************************************************************/
bool TEXT_UTILS_IsSymbol(char *buf)
{
    int len;
    int i;
    char c;

    // Iterate over all characters in the symbol, testing them for validity
    len = strlen(buf);
    for (i=0; i<len; i++)
    {
        // Exit if encountered an illegal character
        c = buf[i];
        if (IS_ALPHA_NUMERIC(c) == false)
        {
            return false;
        }
    }

    // If the code gets here, then all characters in the symbol were valid
    return true;
}

/*********************************************************************//**
**
** TEXT_UTILS_HexDigitToValue
**
** Converts the specified hex character into a value 0-15
**
** \param   c - character containing hex digit to convert
**
** \return  value of hex digit (nibble), or INVALID if unable to convert the character
**
**************************************************************************/
int TEXT_UTILS_HexDigitToValue(char c)
{
    if (IS_NUMERIC(c))
    {
        return c - '0';
    }

    if ((c >= 'A') && (c <= 'F'))
    {
        return c - 'A' + 10;
    }

    if ((c >= 'a') && (c <= 'f'))
    {
        return c - 'a' + 10;
    }

    // If the code gets here, unable to convert the character
    return INVALID;
}

/*********************************************************************//**
**
** TEXT_UTILS_ValueToHexDigit
**
** Converts the specified value into a hex character (0-F)
**
** \param   nibble - value to convert (0-15)
**
** \return  value of hex digit (nibble), or 'X' if unable to convert the value
**
**************************************************************************/
char TEXT_UTILS_ValueToHexDigit(int nibble)
{
    if ((nibble >=0) && (nibble <=9))
    {
        return nibble + '0';
    }

    if ((nibble >= 10) && (nibble <=15))
    {
        return nibble - 10 + 'A';
    }

    // If the code gets here then the digit could not be converted
    return 'X';
}

/*********************************************************************//**
**
** TEXT_UTILS_PathToSchemaForm
**
** Converts an instantiated data model path into a data model schema path
** by replacing instance numbers with "{i}"
**
** \param   path - Instantiated data model path (may contain instance numbers)
** \param   buf - pointer to buffer in which to return the schema path
** \param   len - length of buffer in which to return the schema path
**
** \return  None
**
**************************************************************************/
void TEXT_UTILS_PathToSchemaForm(char *path, char *buf, int len)
{
    char c;

    c = *path;
    while (c != '\0')
    {
        if (IS_NUMERIC(c))
        {
            // Replace number with schema instance separator in the output buffer
            #define INSTANCE_SEPARATOR "{i}"
            #define INSTANCE_SEPARATOR_LEN (sizeof(INSTANCE_SEPARATOR)-1)       // Minus 1 to not include NULL terminator
            memcpy(buf, INSTANCE_SEPARATOR, INSTANCE_SEPARATOR_LEN);
            buf += INSTANCE_SEPARATOR_LEN;
            len -= INSTANCE_SEPARATOR_LEN;

            // Skip to after number
            path += TEXT_UTILS_CountConsecutiveDigits(path);
        }
        else
        {
            // Copy character into output buffer
            *buf++ = c;
            len--;
            path ++;
        }

        // Exit if not enough space for output
        if (len < INSTANCE_SEPARATOR_LEN+1)        // Plus 1, so that we have enough space to copy the instance separator and a NULL terminator
        {
            goto exit;
        }

        c = *path;
    }

exit:
    *buf = '\0';        // Ensure buffer is zero terminated
}

/*********************************************************************//**
**
** TEXT_UTILS_CountConsecutiveDigits
**
** Determines the number of consecutive numeric digits in the string, 
** terminated by either a non digit character or the NULL terminator
**
** \param   s - pointer to string
**
** \return  Number of digts in the string. Note: This may be 0 if the first character is a non digit
**
**************************************************************************/
int TEXT_UTILS_CountConsecutiveDigits(char *s)
{
    int count = 0;
    char c;

    c = *s;
    while(true)
    {    
        if (IS_NUMERIC(c))
        {
            // Increment count if hit a digit character
            count++;
        }
        else
        {
            // Exit if hit a non-digit character (or NULL terminator)
            return count;
        }

        // Move to next character
        s++;
        c = *s;
    }
}

/*********************************************************************//**
**
** TEXT_UTILS_StrDupWithTrailingDot
**
** Duplicates a string (dynamically allocating it) and adds a trailing '.'
**
** \param   path - data model path to duplicate
**
** \return  pointer to dynamically allocated duplicated string
**
**************************************************************************/
char *TEXT_UTILS_StrDupWithTrailingDot(char *path)
{
    int len;
    char *p;

    // Allocate and copy the affected path (adding a trailing '.')
    len = strlen(path);
    p = USP_MALLOC(len+2); // Plus 2 to include training '.' and NULL terminator
    memcpy(p, path, len);

    // Only add the trailing '.' if necessary (NOTE: We expect that we will always have to add the '.')
    if (path[len-1] != '.')
    {
        p[len] = '.';
        p[len+1] = '\0';
    }
    else
    {
        p[len] = '\0';
    }

    return p;
}

//------------------------------------------------------------------------------------------
// Code to test the TEXT_UTILS_TrimBuffer() function
#if 0
char *trim_buffer_test_cases[] =
{
    // Test case                // Expected result
    "   hello there  \t ",      "hello there",
    "not padded",               "not padded",
    "    \t    ",               ""
};

void TestTrimBuffer(void)
{
    int i;
    char *s;
    char buf[256];

    for (i=0; i < NUM_ELEM(trim_buffer_test_cases); i+=2)
    {
        strcpy(buf, trim_buffer_test_cases[i]);
        s = TEXT_UTILS_TrimBuffer(buf);
        if (strcmp(s, trim_buffer_test_cases[i+1]) != 0)
        {
            printf("ERROR: [%d] Test case result for '%s' is '%s' (expected '%s')\n", i/2, trim_buffer_test_cases[i], s, trim_buffer_test_cases[i+1]);
        }
    }
}
#endif

//------------------------------------------------------------------------------------------
// Code to test the TEXT_UTILS_PercentDecodeString() function
// NOTE '%25' (ASCII character 0x25) is the '%' character
#if 0
char *percent_decode_string_test_cases[] =
{
    // Test case                // Expected result
    "",      "",
    "one",      "one",
    "one%25two",      "one%two",
    "one%25",       "one%",
    "%25one",       "%one",
    "one%25two%25three%25four",       "one%two%three%four",
    "one%2two",       NULL,
    "one%",       NULL,
    "one%2",       NULL,
    "one%X2two",       NULL,
    "one%2Xtwo",       NULL,
    "one%22two",       "one\"two",
};

void TestPercentDecodeString(void)
{
    int i;
    char *s;
    char buf[256];

    for (i=0; i < NUM_ELEM(percent_decode_string_test_cases); i+=2)
    {
        strcpy(buf, percent_decode_string_test_cases[i]);
        s = TEXT_UTILS_PercentDecodeString(buf);
        if (TEXT_UTILS_NullStringCompare(s, percent_decode_string_test_cases[i+1]) != 0)
        {
            printf("ERROR: [%d] Test case result for '%s' is '%s' (expected '%s')\n", i/2, percent_decode_string_test_cases[i], s, percent_decode_string_test_cases[i+1]);
        }
    }
}
#endif

//------------------------------------------------------------------------------------------
// Code to test the TEXT_UTILS_SplitString() function
#if 0
char *split_string_test_cases[] =
{
    // Test case                // Expected values
    "value1 && value2 && value3",   "value1",  "value2", "value3",
    "value1&&value2&&value3",       "value1",  "value2", "value3",
    "value1&&value2&&",             "value1",  "value2", NULL,
    "&&value1&&value2",             "value1",  "value2", NULL,
    "value1 & & value2",            "value1 & & value2", NULL, NULL,
    "value1 & value2",              "value1 & value2", NULL, NULL,
    "value1 value2",                "value1 value2", NULL, NULL,
    "value1 value2 &",              "value1 value2 &", NULL, NULL,
};

void TestSplitString(void)
{
    int i, j;
    char buf[256];
    str_vector_t sv;
    char *result;
    char *expected;
    int count = 0;

    for (i=0; i < NUM_ELEM(split_string_test_cases); i+=4)
    {
        strcpy(buf, split_string_test_cases[i]);

        printf("[%d] %s\n", i/4, buf);
        TEXT_UTILS_SplitString(buf, &sv, "&&");

        // Print error if results do not match those expected
        for (j=0; j<3; j++)
        {
            result = (j < sv.num_entries) ? sv.vector[j] : NULL;
            if (result != NULL)
            {
                printf("  %s\n", result);
            }
            expected = split_string_test_cases[i+1+j];
            if (TEXT_UTILS_NullStringCompare(result, expected) != 0)
            {
                printf("FAIL: [%d] Test case result %d is wrong (got %s, expected %s)", i/4, j, result, expected); 
                count++;
            }
        }

        STR_VECTOR_Destroy(&sv);
    }
    printf("Number of failures=%d\n", count);
}
#endif
//------------------------------------------------------------------------------------------
// Code to test the TEXT_UTILS_StrStr() function
#if 0
char *strstr_test_cases[] =
{
    // Test case (haystack)      (needle)    // Expected values
    "value1,value2",   ",",     ",value2",
    "value1, value2",   ",",     ", value2",
    "value1 && value2",   "&&",     "&& value2",
    "value1 & value2",   "&&",     NULL,
    "value1=\"stuff with,in it\"),value2",   ",",     ",value2",
    "value1=\'stuff with,in it\'),value2",   ",",     ",value2",
    "value1=\"stuff with &&, in it\") && value2",   "&&",     "&& value2",
    "value1=\'stuff with &&, in it\')&&value2",   "&&",     "&&value2",
    "value1=\"stuff with,in it,value2",   ",",     NULL,
    "value1=\'stuff with,in it,value2",   ",",     NULL,
};

void TestStrStr(void)
{
    int i;
    char *result;
    int count = 0;

    for (i=0; i < NUM_ELEM(strstr_test_cases); i+=3)
    {
        printf("[%d] %s\n", i/3, strstr_test_cases[i]);
        result = TEXT_UTILS_StrStr(strstr_test_cases[i], strstr_test_cases[i+1]);
        if (strstr_test_cases[i+2]==NULL)
        {
            if (result != NULL)
            {
                printf("FAIL: [%d] Test case result is wrong (got '%s', expected NULL)\n", i/3, result); 
                count++;
            }
        }
        else
        {
            if (result == NULL)
            {
                printf("FAIL: [%d] Test case result is wrong (got NULL, expected '%s')\n", i/3, strstr_test_cases[i+2]);
                count++;
            }
            else if (strcmp(result, strstr_test_cases[i+2]) != 0)
            {
                printf("FAIL: [%d] Test case result is wrong (got '%s', expected '%s')\n", i/3, result, strstr_test_cases[i+2]);
                count++;
            }
        }
    }
    printf("Number of failures=%d\n", count);
}
#endif

//------------------------------------------------------------------------------------------
// Code to test the TEXT_UTILS_PathToSchemaForm() function
#if 0
char *schema_form_test_cases[] =
{
    // Test case                    // Expected value
    "X.1.Y",                        "X.{i}.Y",
    "Value.1",                      "Value.{i}",
    "Value.1234",                   "Value.{i}",
    "Value.1.",                     "Value.{i}.",
    "Value.12458.",                 "Value.{i}.",
    "Value.14.Stuff.6752.Other",    "Value.{i}.Stuff.{i}.Other",
    "Value.1444.Stuff.2942",        "Value.{i}.Stuff.{i}",
};

void Test_ToSchemaForm(void)
{
    int i;
    char buf[256];
    int count = 0;

    for (i=0; i < NUM_ELEM(schema_form_test_cases); i+=2)
    {
        printf("[%d] %s\n", i/2, schema_form_test_cases[i]);
        TEXT_UTILS_PathToSchemaForm(schema_form_test_cases[i], buf, sizeof(buf));

        // Print error if results do not match those expected
        if (strcmp(buf, schema_form_test_cases[i+1]) != 0)
        {
            printf("FAIL: [%d] Test case result is wrong (got '%s', expected '%s')\n", i/2, buf, schema_form_test_cases[i+1]);
            count++;
        }
    }
    printf("Number of failures=%d\n", count);
}
#endif

//------------------------------------------------------------------------------------------
// Code to test the TEXT_UTILS_KeyValueFromString() function
#if 0
char *to_key_value_test_cases[] =
{
    // Test case                            // Expected key     // Expected value
    "my.key \"  my value \"   \t",          "my.key",           "  my value ",
    "my.key \"\"   \t",                     "my.key",           "",
    "my.key \"stuff",                       NULL,               NULL,
    "my.key stuff\"",                       NULL,               NULL,
    "my.key  \"stuff\"  ",                  "my.key",           "stuff",
    "my.key    \t",                         NULL,               NULL,
    "my.key",                               NULL,               NULL,
    "mykey myvalue\n",                      "mykey",            "myvalue",
    "    \t  mykey   myvalue\n",            "mykey",            "myvalue",
    "my.key  \t  my very long value\r\n",   "my.key",           "my very long value",
    "# Ignore this line\r",                 NULL,               NULL,
    "",                                     NULL,               NULL,
    "\n",                                   NULL,               NULL,
    "\r\n",                                 NULL,               NULL,
    "  \t  ",                               NULL,               NULL,
};

void Test_ToKeyValue(void)
{
    int i;
    int err;
    char *key;
    char *value;
    int count = 0;
    char buf[256];

    for (i=0; i < NUM_ELEM(to_key_value_test_cases); i+=3)
    {
        printf("[%d] '%s'\n", i/3, to_key_value_test_cases[i]);
        USP_STRNCPY(buf, to_key_value_test_cases[i], sizeof(buf));

        err = TEXT_UTILS_KeyValueFromString(buf, &key, &value);

        // Check that returned key is correct
        if (to_key_value_test_cases[i+1] != NULL)
        {
            if (strcmp(key, to_key_value_test_cases[i+1]) != 0)
            {
                printf("FAIL: [%d] Test case result is wrong for key (got '%s', expected '%s')\n", i/3, key, to_key_value_test_cases[i+1]);
                count++;
            }
        }
        else
        {
            if (key != NULL)
            {
                printf("FAIL: [%d] Test case result is wrong for key (got '%s', expected NULL)\n", i/3, key);
                count++;
            }
        }
   
        // Check that returned value is correct
        if (to_key_value_test_cases[i+2] != NULL)
        {
            if (strcmp(value, to_key_value_test_cases[i+2]) != 0)
            {
                printf("FAIL: [%d] Test case result is wrong for value (got '%s', expected '%s')\n", i/3, value, to_key_value_test_cases[i+2]);
                count++;
            }
        }
        else
        {
            if (value != NULL)
            {
                printf("FAIL: [%d] Test case result is wrong for value (got '%s', expected NULL)\n", i/3, value);
                count++;
            }
        }
   
        if (err != USP_ERR_OK)
        {
            if ((key != NULL) || (value != NULL))
            {
                printf("FAIL: [%d] Test case returned err=%d, but key=%p, value=%p (expected NULL)", i/3, err, key, value);
                count++;
            }
        }
    }
    printf("Number of failures=%d\n", count);
}
#endif

//------------------------------------------------------------------------------------------
// Code to test the TEXT_UTILS_ReplaceCharInString() function

#if 0
char *replace_char_test_cases[] =
{
    // Test case                // Expected value when destination buffer is 10 characters
    "os::controller1",              "os\\c\\ccon",
    "os::c1",                       "os\\c\\cc1",
    "1234567:",                     "1234567\\c",
    "12345678:",                    "12345678",
    ":::a::::::",                   "\\c\\c\\ca\\c",
};

void Test_ReplaceCharInString(void)
{
    int i;
    int count = 0;
    char buf[10];

    for (i=0; i < NUM_ELEM(replace_char_test_cases); i+=2)
    {
        
        TEXT_UTILS_ReplaceCharInString(replace_char_test_cases[i], ':', "\\c", buf, sizeof(buf));

        printf("[%d] '%s' => '%s'\n", i/2, replace_char_test_cases[i], buf);
        if (strcmp(buf, replace_char_test_cases[i+1]) != 0)
        {
            printf("FAIL: [%d] Test case result is wrong (got '%s', expected '%s')\n", i/2, buf, replace_char_test_cases[i+1]);
            count++;
        }
    }

    printf("Number of failures=%d\n", count);
}
#endif


//------------------------------------------------------------------------------------------
// Code to test the TEXT_UTILS_PercentEncodeString() function
// NOTE '%25' (ASCII character 0x25) is the '%' character
#if 0
char *percent_encode_string_test_cases[] =
{
    // Test case                // Expected result
//    "",                         "",
//    "one",                      "one",
    "one%two",                  "one%25two",
    "one%",                     "one%25",
    "%one",                     "%25one",

    "one\"two",                 "one%22two",
    "one%two%three%four%five",  "one%25two%25thr",

    // Check that unreserved characters aren't encoded
    "abcdefghijklmno",          "abcdefghijklmno",
    "pqrstuvwxyz",              "pqrstuvwxyz",
    "ABCDEFGHIJKLMNO",          "ABCDEFGHIJKLMNO",
    "PQRSTUVWXYZ",              "PQRSTUVWXYZ",
    "0123456789-_.~",           "0123456789-_.~",

    // check that we don't overflow output buffer (16 characters)
    "onetwothreefour%five",     "onetwothreefour",
    "onetwothreefou%rfive",     "onetwothreefou",
    "onetwothreefo%urfive",     "onetwothreefo",
    "onetwothreef%ourfive",     "onetwothreef%25",
    "onetwothree%fourfive",     "onetwothree%25f",
    "a/@/r",                    "a/%40/r",
};

void TestPercentEncodeString(void)
{
    int i;
    char buf[16];

    for (i=0; i < NUM_ELEM(percent_encode_string_test_cases); i+=2)
    {
        strcpy(buf, percent_encode_string_test_cases[i]);
        TEXT_UTILS_PercentEncodeString(percent_encode_string_test_cases[i], buf, sizeof(buf), '/');
        if (strcmp(buf, percent_encode_string_test_cases[i+1]) != 0)
        {
            printf("ERROR: [%d] Test case result for '%s' is '%s' (expected '%s')\n", i/2, percent_encode_string_test_cases[i], buf, percent_encode_string_test_cases[i+1]);
        }
    }
}
#endif

