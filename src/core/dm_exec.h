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
 * \file dm_exec.h
 *
 * Header file for Main execution loop of data model thread
 *
 */
#ifndef DM_EXEC_H
#define DM_EXEC_H

//------------------------------------------------------------------------------
// API functions
int DM_EXEC_Init(void);
void DM_EXEC_Destroy(void);
void DM_EXEC_PostUspRecord(unsigned char *pbuf, int pbuf_len, ctrust_role_t role, char *allowed_controllers, char *stomp_dest, int stomp_instance);
void DM_EXEC_PostStompHandshakeComplete(int stomp_instance, ctrust_role_t role, char *allowed_controllers);
void DM_EXEC_PostMtpThreadExited(void);
void DM_EXEC_HandleStompHandshakeComplete(int stomp_instance, ctrust_role_t role, char *allowed_controllers);
int DM_EXEC_NotifyBdcTransferResult(int profile_id, bool transfer_result);
void *DM_EXEC_Main(void *args);
//------------------------------------------------------------------------------

#endif
