/**
 * \file inst_sel_vector.h
 * Copyright (C) 2025, Broadband Forum
 * Copyright (C) 2025, Vantiva Technologies SAS
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

#ifndef INST_SEL_VECTOR_H
#define INST_SEL_VECTOR_H

//-----------------------------------------------------------------------------------------
// API
void INST_SEL_VECTOR_Init(inst_sel_vector_t *isv);
void INST_SEL_VECTOR_Destroy(inst_sel_vector_t *isv, bool destroy_entries);
void INST_SEL_VECTOR_Fill(inst_sel_vector_t *isv, int num_entries, unsigned short permission_bitmask);
void INST_SEL_VECTOR_Add(inst_sel_vector_t *isv, inst_sel_t *sel);
unsigned short INST_SEL_VECTOR_GetPermissionForInstance(inst_sel_vector_t *isv, dm_instances_t *inst, unsigned flags);

#endif
