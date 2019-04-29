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
 * \file mtp_exec.h
 *
 * Header file for MTP main execution loop
 *
 */
#ifndef MTP_EXEC_H
#define MTP_EXEC_H

#include "vendor_defs.h"  // for ENABLE_COAP

//-----------------------------------------------------------------------------------------------
// Enumeration of Device.LocalAgent.MTP.{i}.Status
typedef enum
{
    kMtpStatus_Error,
    kMtpStatus_Down,
    kMtpStatus_Up,
} mtp_status_t;

//------------------------------------------------------------------------------
// Enumeration for MTP protocol type. Only the types below are supported by the code
typedef enum
{
    kMtpProtocol_None,      // None setup yet. The default.
    kMtpProtocol_STOMP,
#ifdef ENABLE_COAP
    kMtpProtocol_CoAP,
#endif

    // The following enumeration should always be the last - it is used to size arrays
    kMtpProtocol_Max
} mtp_protocol_t;

//------------------------------------------------------------------------------
// Enumeration used to determine when to action a STOMP reconnect or MTP thread exit
// A reconnect is signalled by calling STOMP_ScheduleReconnect()
// An exit is signalled by calling MTP_EXEC_ScheduleExit()
// But neither of these functions activate a reconnect or exit in themselves, because if they did, the MTP
// thread might perform the action immediately, and we want all response messages to be sent before performing the action
// So, instead, only after the response message has been put on the message queue do we activate (by calling MTP_EXEC_ActivateScheduledActions)
// the actions. Onlce an action has been activated it is then scheduled to occur once all responses have been sent.
typedef enum
{
    kScheduledAction_Off,             // The action is not scheduled
    kScheduledAction_Signalled,       // The action is signalled but not activated (because a response message might need to be put in the message queue).
    kScheduledAction_Activated       // The action occurs when all queued USP response messages have been sent
} scheduled_action_t;

//------------------------------------------------------------------------------
// Global Variables
extern scheduled_action_t mtp_exit_scheduled;
extern bool is_mtp_thread_exited;

//------------------------------------------------------------------------------
// API functions
int MTP_EXEC_Init(void);
void *MTP_EXEC_Main(void *args);
void MTP_EXEC_Wakeup(void);
void MTP_EXEC_ScheduleExit(void);
void MTP_EXEC_ActivateScheduledActions(void);

//------------------------------------------------------------------------------

#endif
