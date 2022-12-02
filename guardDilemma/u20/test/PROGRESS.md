# Buffer Overflow
Paper states that buffer overflow (or any memory corruption vulnerability) can bootstrap the ORET-CONT loop

I am yet to understand the exact meaning but I have tested some aspects and this is a set of notes for my own reference.


## Basic Buffer Overflow is possible.

The intel sgx sdk compiled application is not invulnerable from every attack. Buffer Overflow is possible but only possible on application layer.

Basically (from my understanding so far) there are two parts Enclave - App (all sample code have these two folders)

If BO vulnerability is in App we can overwrite stack (simple!)
Now since we control the return address we can do what ever we desire within the app but not within the enclave. (important)

So if we have a getkey() function defined on app.cpp we can easily access it.
if we have a within_enclave() function defined in the enclave we can't access it. We know the address (dissassemble within_enclave) but chanigng the return address to this function doesn't work.

But as the paper pointed out that we can access the enclave through normal means (ecall, ocall) we can access 'some features?' in the enclave. Like we can call ecall fnc from buffer overflow. 

Now I have to find out ORET (and how that works in sgxsdk)
or check out if ecall can be used to access fnc. within the enclave (since it seems it is impossible from the outside)

There seems to be multiple OCALL functions defined in Enclave_t.c 
Enclave.c uses these OCALL to print a stream from within the enclave. 



## Finding asm_oret & continue_execution (in progress)

Clearly the most important functions for this exploit: asm_oret and continue_execution
They play key role in context swap between enclave and untrusted code execution. But since SGXSDK is code it can be abused for ROP attack (basic idea of GuardsDilemma paper)



## SnakeGX

SnakeGX seems to be somewhat of an followup to GuardsDilemma. 
It utilize continue_execution to do some form of ROP attack whilst undetected(?) by healthy OS

So poking around the code of SnakeGX I figured out how to find (maybe) asm_oret and contineu_execution

within enclave_signed.io

```
root@0733f5f47830:/home/linuxsgx/sgxsdk/SampleCode/SampleEnclave# nm enclave.signed.so  | grep asm_oret
0000000000008c17 t asm_oret
root@0733f5f47830:/home/linuxsgx/sgxsdk/SampleCode/SampleEnclave# nm enclave.signed.so  | grep continue_execution
0000000000008cee t continue_execution
root@0733f5f47830:/home/linuxsgx/sgxsdk/SampleCode/SampleEnclave# 

```

This section displays (?) address to asm_oret and continue_execution
We start a buffer overflow and use asm_oret to start a ORET-CONT chain?

Not sure ...

## Good News and Bad News.

First I learned basically how to find asm_oret.
First the enclave_signed.io seem to have the address of the functions 
Furthermore, /proc/PID/maps seem to contain mapping information to know the base address of the enclave.

Now the problem.
Since, I am running only SGX SDK (since most PC processers don't support SGX anymore)
I don't have a driver and usually the enclave is identified by isgx (i think its the driver)

So how does everything role when there is no driver?
Furthermore exception is not captured in Simulation mode. This means continue_execution (CONT primitive) might be deactivated.


### Very Good News

Upon further inspection the sgxsdk seems to simulate a half baked version of the enclave. In simulation mode.
The key notice is whether CONT primitive is alive (as it explicitely state that exception is not captured in Simulation mode so no need for continue_execution)

```
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
```

This short assembly code just by looking at it you know its asm_oret()
Using the base address given by the sgxsdk during simulation mode (since no enclave is running it tells us the base address)
(Enclave base address can be acquired through /proc/[PID]/maps)

```
sgxuser@7877f892d194:/proc/6$ cat maps | grep enclave
7f1b0e5df000-7f1b0e5e1000 r--p 00000000 00:41 1814539                    /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1.2.100.3
7f1b0e5e1000-7f1b0e5e6000 r-xp 00002000 00:41 1814539                    /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1.2.100.3
7f1b0e5e6000-7f1b0e5e8000 r--p 00007000 00:41 1814539                    /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1.2.100.3
7f1b0e5e8000-7f1b0e5e9000 r--p 00008000 00:41 1814539                    /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1.2.100.3
7f1b0e5e9000-7f1b0e5ea000 rw-p 00009000 00:41 1814539                    /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1.2.100.3
```

This is from a docker execution within the base linux-sgx repository /linux/installer/docker

Here I executed docker-compose and docker exec ... /bin/bash into the container looked for the map to find that the base address can be acquired this way. (Which is the method used by SnakeGX)

```
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
```
Again using a same method I acquired this.
Similar to asm_oret() but more registers. This is continue_execution. 
Using the base address and the address offset acquired from enclave.signed.so