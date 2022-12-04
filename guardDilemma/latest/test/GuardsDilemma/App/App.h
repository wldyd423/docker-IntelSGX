/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

#if defined(__cplusplus)
extern "C" {
#endif

void edger8r_array_attributes(void);
void edger8r_type_attributes(void);
void edger8r_pointer_attributes(void);
void edger8r_function_attributes(void);

void ecall_libc_functions(void);
void ecall_libcxx_functions(void);
void ecall_thread_functions(void);

#if defined(__cplusplus)
}
#endif


typedef struct _cpu_context_t
{
    uint64_t rax;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rflags;
    uint64_t rip;
} sgx_cpu_context_t;

typedef enum _sgx_exception_vector_t
{
    SGX_EXCEPTION_VECTOR_DE = 0,  /* DIV and DIV instructions */
    SGX_EXCEPTION_VECTOR_DB = 1,  /* For Intel use only */
    SGX_EXCEPTION_VECTOR_BP = 3,  /* INT 3 instruction */
    SGX_EXCEPTION_VECTOR_BR = 5,  /* BOUND instruction */
    SGX_EXCEPTION_VECTOR_UD = 6,  /* UD2 instruction or reserved opcode */
    SGX_EXCEPTION_VECTOR_MF = 16, /* x87 FPU floating-point or WAIT/FWAIT instruction */
    SGX_EXCEPTION_VECTOR_AC = 17, /* Any data reference in memory */
    SGX_EXCEPTION_VECTOR_XM = 19, /* SSE/SSE2/SSE3 floating-point instruction */
} sgx_exception_vector_t;

typedef enum _sgx_exception_type_t
{
    SGX_EXCEPTION_HARDWARE = 3,
    SGX_EXCEPTION_SOFTWARE = 6,
} sgx_exception_type_t;

typedef struct _exception_info_t
{
    sgx_cpu_context_t      cpu_context;
    sgx_exception_vector_t exception_vector;
    sgx_exception_type_t   exception_type;
} sgx_exception_info_t;

typedef struct _ocall_context_t
{
    uintptr_t shadow0;
    uintptr_t shadow1;
    uintptr_t shadow2;
    uintptr_t shadow3;
    uintptr_t ocall_flag;
    uintptr_t ocall_index;
    uintptr_t pre_last_sp;
    uintptr_t r15;
    uintptr_t r14;
    uintptr_t r13;
    uintptr_t r12;
    uintptr_t xbp;
    uintptr_t xdi;
    uintptr_t xsi;
    uintptr_t xbx;
    uintptr_t reserved[3];
    uintptr_t ocall_depth;
    uintptr_t ocall_ret;
} ocall_context_t;

#endif /* !_APP_H_ */


/*
asm_oret:

   0x7fe0a5ad7c17:	mov    %rdi,%rsp
   0x7fe0a5ad7c1a:	mov    %rsi,%rax
   0x7fe0a5ad7c1d:	mov    0x38(%rsp),%r15
   0x7fe0a5ad7c22:	mov    0x40(%rsp),%r14
   0x7fe0a5ad7c27:	mov    0x48(%rsp),%r13
   0x7fe0a5ad7c2c:	mov    0x50(%rsp),%r12
   0x7fe0a5ad7c31:	mov    0x58(%rsp),%rbp
   0x7fe0a5ad7c36:	mov    0x60(%rsp),%rdi
   0x7fe0a5ad7c3b:	mov    0x68(%rsp),%rsi
   0x7fe0a5ad7c40:	mov    0x70(%rsp),%rbx
   0x7fe0a5ad7c45:	add    $0x98,%rsp
   0x7fe0a5ad7c4c:	retq 

continue_execution:

   0x7fe0a5ad7cee:	mov    %rdi,%rcx
   0x7fe0a5ad7cf1:	mov    0x20(%rcx),%rdx
   0x7fe0a5ad7cf5:	mov    %rdx,%rsp
   0x7fe0a5ad7cf8:	sub    $0x8,%rsp
   0x7fe0a5ad7cfc:	mov    0x88(%rcx),%rax
   0x7fe0a5ad7d03:	mov    %rax,(%rsp)
   0x7fe0a5ad7d07:	mov    (%rcx),%rax
   0x7fe0a5ad7d0a:	mov    0x10(%rcx),%rdx
   0x7fe0a5ad7d0e:	mov    0x18(%rcx),%rbx
   0x7fe0a5ad7d12:	mov    0x28(%rcx),%rbp
   0x7fe0a5ad7d16:	mov    0x30(%rcx),%rsi
   0x7fe0a5ad7d1a:	mov    0x38(%rcx),%rdi
   0x7fe0a5ad7d1e:	mov    0x40(%rcx),%r8
   0x7fe0a5ad7d22:	mov    0x48(%rcx),%r9
   0x7fe0a5ad7d26:	mov    0x50(%rcx),%r10
   0x7fe0a5ad7d2a:	mov    0x58(%rcx),%r11
   0x7fe0a5ad7d2e:	mov    0x60(%rcx),%r12
   0x7fe0a5ad7d32:	mov    0x68(%rcx),%r13
   0x7fe0a5ad7d36:	mov    0x70(%rcx),%r14
   0x7fe0a5ad7d3a:	mov    0x78(%rcx),%r15
   0x7fe0a5ad7d3e:	pushq  0x80(%rcx)
   0x7fe0a5ad7d44:	popfq  
   0x7fe0a5ad7d45:	mov    0x8(%rcx),%rcx
   0x7fe0a5ad7d49:	retq 
*/