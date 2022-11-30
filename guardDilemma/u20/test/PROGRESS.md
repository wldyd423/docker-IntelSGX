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