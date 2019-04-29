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
 * \file mtp_exec.c
 *
 * Main loop for MTP thread dealing with STOMP and CoAP Communications
 *
 */
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

#include "common_defs.h"
#include "mtp_exec.h"
#include "dm_exec.h"
#include "stomp.h"
#include "os_utils.h"

#ifdef ENABLE_COAP
#include "usp_coap.h"
#endif

//------------------------------------------------------------------------------
// Unix domain socket pair used to implement a wakeup message queue
// One socket is always used for sending, and the other always used for receiving
static int mtp_mq_sockets[2] = {-1, -1};

#define mq_rx_socket  mtp_mq_sockets[0]
#define mq_tx_socket  mtp_mq_sockets[1]

//------------------------------------------------------------------------------
// Enumeration that is set when a USP Agent stop has been scheduled (for when connections have finished sending and receiving messages)
scheduled_action_t mtp_exit_scheduled = kScheduledAction_Off;

//------------------------------------------------------------------------------
// Flag set to true if the MTP thread has exited
// This gets set after a scheduled exit due to a stop command, Reboot or FactoryReset operation
bool is_mtp_thread_exited = false;

//------------------------------------------------------------------------------
// Forward declarations. Note these are not static, because we need them in the symbol table for USP_LOG_Callstack() to show them
void UpdateMtpSockSet(socket_set_t *set);
void ProcessMtpSocketActivity(socket_set_t *set);
void ProcessMtpWakeupQueueSocketActivity(socket_set_t *set);

/*********************************************************************//**
**
** MTP_EXEC_Init
**
** Initialises the functionality in this module
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
int MTP_EXEC_Init(void)
{
    int err;

    // Exit if unable to initialize the unix domain socket pair used to implement a wakeup message queue
    err = socketpair(AF_UNIX, SOCK_DGRAM, 0, mtp_mq_sockets);
    if (err != 0)
    {
        USP_ERR_ERRNO("socketpair", err);
        return USP_ERR_INTERNAL_ERROR;
    }

    return USP_ERR_OK;
}

/*********************************************************************//**
**
** MTP_EXEC_Wakeup
**
** Posts a message on the MTP thread's queue, to cause it to wakeup from the select()
**
** \param   None
**
** \return  USP_ERR_OK if successful
**
**************************************************************************/
void MTP_EXEC_Wakeup(void)
{
    #define WAKEUP_MESSAGE 'W'
    char msg = WAKEUP_MESSAGE;
    int bytes_sent;
    
    // Send the message
    bytes_sent = send(mq_tx_socket, &msg, sizeof(msg), 0);
    if (bytes_sent != sizeof(msg))
    {
        char buf[USP_ERR_MAXLEN];
        USP_LOG_Error("%s(%d): send failed : (err=%d) %s", __FUNCTION__, __LINE__, errno, strerror_r(errno, buf, sizeof(buf)) );
        return;
    }
}

/*********************************************************************//**
**
** MTP_EXEC_ScheduleExit
**
** Signals that the CPE should exit USP Agent when all queued messages have been sent
** This is also used as part of scheduling a reboot
** See comment header above definition of scheduled_action_t for an explanation of how scheduled actions work, and why
**
** \param   None
**
** \return  None
**
**************************************************************************/
void MTP_EXEC_ScheduleExit(void)
{
    mtp_exit_scheduled = kScheduledAction_Signalled;
}


/*********************************************************************//**
**
** MTP_EXEC_ActivateScheduledActions
**
** Called when all USP response messages have been queued.
** This function activates all scheduled actions which have been signalled
** See comment header above definition of scheduled_action_t for an explanation of how scheduled actions work, and why
**
** \param   None
**
** \return  None
**
**************************************************************************/
void MTP_EXEC_ActivateScheduledActions(void)
{
    // Exit if MTP thread has exited
    if (is_mtp_thread_exited)
    {
        return;
    }

    // Activate the exit action, if signalled
    if (mtp_exit_scheduled == kScheduledAction_Signalled)
    {
        mtp_exit_scheduled = kScheduledAction_Activated;
        MTP_EXEC_Wakeup();
    }

    STOMP_ActivateScheduledActions();
}

/*********************************************************************//**
**
** MTP_EXEC_Main
**
** Main loop of MTP thread
**
** \param   args - arguments (currently unused)
**
** \return  None
**
**************************************************************************/
void *MTP_EXEC_Main(void *args)
{
    int num_sockets;
    socket_set_t set;

    while(FOREVER)
    {
        // Create the socket set to receive/transmit on (with timeout)
        UpdateMtpSockSet(&set);

        // Wait for read/write activity on sockets or timeout
        num_sockets = SOCKET_SET_Select(&set);

        // Process socket activity
        switch(num_sockets)
        {
            case -1:
                // An unrecoverable error has occurred
                USP_LOG_Error("%s: Unrecoverable socket select() error. Aborting MTP thread", __FUNCTION__);
                return NULL;
                break;

                break;

            case 0:
                // No controllers with any activity, but we still may need to process a timeout, so fall-through
            default:
                // Controllers with activity
                ProcessMtpSocketActivity(&set);
                break;
        }

        // Exit this thread, if an exit is scheduled and all responses have been sent
        if (mtp_exit_scheduled == kScheduledAction_Activated)
        {
            if (STOMP_AreAllResponsesSent())
            {
                // Free all memory associated with MTP layer
                STOMP_Destroy();

                #ifdef ENABLE_COAP
                COAP_Destroy();
                #endif

                // Prevent the data model from making any other changes to the MTP thread
                is_mtp_thread_exited = true;

                // Signal the data model thread that this thread has exited
                DM_EXEC_PostMtpThreadExited();
                return NULL;
            }
        }
    }
}

/*********************************************************************//**
**
** UpdateMtpSockSet
**
** Adds all sockets to wait for activity on, into the socket set
** Also updates the associated timeout for activity
** This function must be called every time before the call to select(), as select alters the socket set
**
** \param   set - pointer to socket set structure to update with sockets to wait for activity on
**
** \return  None
**
**************************************************************************/
void UpdateMtpSockSet(socket_set_t *set)
{
    // Add all controller sockets to the socket set
    SOCKET_SET_Clear(set);
    STOMP_UpdateAllSockSet(set);
#ifdef ENABLE_COAP
    COAP_UpdateAllSockSet(set);
#endif

    // Add the message queue receiving socket to the socket set
    #define SECONDS 1000  // in ms
    SOCKET_SET_AddSocketToReceiveFrom(mq_rx_socket, 3600*SECONDS, set);
}

/*********************************************************************//**
**
** ProcessMtpSocketActivity
**
** Processes all activity on sockets (ie receiving messages and sending messages)
**
** \param   set - pointer to socket set structure containing sockets with activity on them
**
** \return  None
**
**************************************************************************/
void ProcessMtpSocketActivity(socket_set_t *set)
{
    // Process the wakeup queue
    ProcessMtpWakeupQueueSocketActivity(set);

    // Process activity on all STOMP message queues
    STOMP_ProcessAllSocketActivity(set);
 
#ifdef ENABLE_COAP
    // Process activity on all CoAP message queues
    COAP_ProcessAllSocketActivity(set);
#endif
}

/*********************************************************************//**
**
** ProcessMtpWakeupQueueSocketActivity
**
** Processes any activity on the message queue receiving socket
**
** \param   set - pointer to socket set structure containing sockets with activity on them
**
** \return  None (any errors that occur are handled internally)
**
**************************************************************************/
void ProcessMtpWakeupQueueSocketActivity(socket_set_t *set)
{
    int bytes_read;
    char msg;

    // Exit if there is no activity on the wakeup message queue socket
    if (SOCKET_SET_IsReadyToRead(mq_rx_socket, set) == 0)
    {
        return;
    }

    // Exit if unable to purge this wakeup message from the queue
    bytes_read = recv(mq_rx_socket, &msg, sizeof(msg), 0);
    if (bytes_read != sizeof(msg))
    {
        USP_LOG_Error("%s: recv() did not return a full message", __FUNCTION__);
        return;
    }

    // Throw the message away, it's only purpose is to break the select()
    USP_ASSERT(msg == WAKEUP_MESSAGE);
}

