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
 * \file int_vector.c
 *
 * Implements a data structure containing a vector of integers
 *
 */
#include <stdlib.h>
#include <string.h>

#include "common_defs.h"
#include "int_vector.h"

/*********************************************************************//**
**
** INT_VECTOR_Init
**
** Initialises an integer vector structure
**
** \param   iv - pointer to structure to initialise
**
** \return  None
**
**************************************************************************/
void INT_VECTOR_Init(int_vector_t *iv)
{
    iv->num_entries = 0;
}

/*********************************************************************//**
**
** INT_VECTOR_Add
**
** Adds the integer into the vector of integers
**
** \param   iv - pointer to structure to add the integer to
** \param   number - integer to insert
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int INT_VECTOR_Add(int_vector_t *iv, int number)
{
    // Exit if unable to add to the vector (array is already full)
    if (iv->num_entries >= MAX_DM_INSTANCES)
    {
        USP_ERR_SetMessage("%s: More than %d instances of object", __FUNCTION__, MAX_DM_INSTANCES);
        return USP_ERR_INTERNAL_ERROR;
    }

    // Add to the vector
    iv->vector[ iv->num_entries ] = (short) number;
    iv->num_entries++;
    return USP_ERR_OK;
}

/*********************************************************************//**
**
** INT_VECTOR_Find
**
** Finds the specified integer in the vector of integers
**
** \param   iv - pointer to structure to search in
** \param   number - integer to match
**
** \return  Index in vector of matching integer, or INVALID if not found
**
**************************************************************************/
int INT_VECTOR_Find(int_vector_t *iv, int number)
{
    int i;

    // Iterate over all entries in the vector    
    for (i=0; i < iv->num_entries; i++)
    {
        // Exit if a match has been found
        if (iv->vector[i] == number)
        {
            return i;
        }
    }

    // If the code gets here, then no match has been found
    return INVALID;
}

/*********************************************************************//**
**
** INT_VECTOR_Destroy
**
** Deinitialises the integer vector
**
** \param   iv - pointer to structure to re-initialize
**
** \return  None
**
**************************************************************************/
void INT_VECTOR_Destroy(int_vector_t *iv)
{
    iv->num_entries = 0;
}




