# notes (Taken for the paper to understand how attack works)
SGX creates enclaves. These enclaves cannot be reverse engineered since it is encrypted with a key only available within an enclave.
Typical ROP attacks do not work. (why?)  (probably because address layout of gadgets are unknown)

DarkROP proposes a method to undermine this procedure. Creating a set of oracles that crash leak address layout of gadgets. 
Assuming address layout does not change. These gadgets can be used to launch a ROP attack.

However with an address randomization scheme (ex. SGX Shield) DarkROP does not have a way of extracting gadgets.

The paper proposes a different exploit to undermine these mitigations and launch a ROP attack on SGX. (Seems to use SGX SDK)

## SGX Background

SGX enclave run on same x86 processor as ordinary application. ==> require mechanism to transfer between untrusted and trusted code.
SGX instructions interacting with the enclave are organized as leaf fnc. under two real intructions: ENCLS (kernel-mode operations) and ENCLU (user-mode operations)

SGX accomplish synchronus enclave entry through EENTER leaf fnc (invoked by ENCLU). Entry point is specified in the Thread Control Structure (TCS)
EENTER does not clear CPU registers untrusted code pass additional information to entry point.  To return back enclave use EEXIT leaf fnc. 
just like EENTER, EEXIT does not clear register. 

Enclave can be entered concurrently within same thread. Number of concurrent entries in the same thread is limited by State Save Areas (SSA)
SSA stores enclave state during asynchronus exits. number of SSA (NSSA) field in TCS defines how many SSA are present.
Enclave can exit due to hardware exception, which is handled by the kernel in untrusted mode. This event: AEX (Asynchronus Enclave Exit)
Enclave state is saved in an available SSA when AEX occurs. Register values are replaced with synthetic state before handing control to interrupt handler.
Syntethic state ensure enclave opacity and avoid leakage of secrets. 
Once interrupt is dealt enclave execution is resumed with ERESUME leaf fnc. 

## SGX SDK Internals

SGX software are developed based on SGX SDK, as it abstracts SGX. 
Two SDK provided libraries are vital for this attack: 
Trusted Runtime System (tRTS) and Untrusted Runtime Ssytem (uRTS)
tRTS executes inside enclave, uRTS runs outside enclave.
tRTS and uRTS interact with each other handling transition between trusted and untrusted execution modes.

### ECALLs
ECALL allow untrusted code to call fnc within enclave. Enclave programmer can arbitrarily select which functions are exposed to ECALL interface.
ECALL can also be nested: untrusted code can execute ECALL while handling OCALL.
Programmer can specify which ECALL are allowed at zero nesting level andwhich are allowed for specific OCALL. 
Every ECALL has associated index. To perform ECALL application calls into uRTS library which executes a synchronus enclave entry (EENTER)
passing ECALL index in a register. tRTS check ECALL index is defiend and if it is allowed at current nesting level.  Once function returns:
it performs a synchronus exit (EEXIT) giving control back gto uRTS.
Passing and returning arbitrary memory is possible because SGX enclaves can access untrusted memory. Enclave must expose at least ECALL otherwise there is 
no way to invoke enclave code: from programmer's perspective enclave code executes in ECALL context.

### OCALLs
OCALL mechanism allow trusted code to call untrusted functions defined by the host application.
Need for OCALL stems from the fact that system calls are not allowed inside an enclave. 
Like ECALL, OCALL is identified by an index. When enclave has to perform OCALL it calls into tRTS.
tRTS first pushes an OCALL frame onto trusted thread stack which stores current register states. 
Next it performs synchronus exit to return from the current ECALL passing OCALL index back to uRTS.
uRTX recognize that exit is for an OCALL and executes target functions and executes ECALL varient known as ORET which restore the contesxt from the OCALL frame through function named asm_oret returning to trusted callsite. 
ORET is implemented in tRTS like ECALL data is passed via shared untrusted memory.

### Exception Handling
SDK enclaves can register handlers to catch exception within enclaves. Upon exceptionan asynchronus enclave exit AEX occurs. This saves the faulting state to the state save area (SSA)
Resulting interrupt is handled by the kernel, which delivers an exception to the untrusted application by means of usual exception handling mechanism of OS. 
Exception handler registerd by uRTS performs special ECALL to let enclave handle the exceptions. 
By default SDK enclaves have two SSAs available. Hence, it is possible to re-enter enclave while an AEX is pending.
tRTS copies fualting state from SSA to an exception information structure on the trusted stack, and changes the SSA contents so that ERESUME will continue at a secnd phase handler in the tRTS instead of executing faulting instruction again. 
Once, ECALL returns uRTS issue ERESUME for faulting thread. 
This traverses registered exception handlers which can observe the exception information to determine whether they can handle the exception.
To handle the exception. Handler can modify CPU state contained in the exception informations.
If handler succeeds, tRTS uses fnc. continue_execution to restore CPU registers and resume enclave execution.
If exception cannot be handled, default handler switches the enclave to a crashed state preventing further operations. 

(No idea what this means)

## Threat Model and Assumptions
Previous works on SGX considered strong adversarial model. Attacker has full control over machine. (Malicious Kernel)
Here we consider weaker attacker that has compromised the application that hosts the enclave by exploiting a vulnerability.
In some cases attacker might even be able to perform attack without any control over host process.

### Offensive Capabilities
The attacker can:

Cause memory corruption. Attacker knowns of a vulnerability in enclave that allows him or her to corrupt stack memory or fnc poitner on stack/heap/other memory area. 

Create fake structure. Attacker can place arbitrary data at some memory location accessible by the enclave. Malicious host process can easily do this given the unrestricted access over its own address space. An attacker could also possible achieve this via normal functionality: steering application to allocate attacker controlled data at predictable addresses.

Has Knowledge of coarse grained memory layout. Attacker knows victim enclaves external memory layout. This is known to the process hosting enclave. Alternatively information leakage vulnerabilities inside enclave could provide this knowledge. 

Knowledge of enclave binary. Attacker has access to victim enclave's binary allowing binary analysis on the binary.

### Defensive cpabilities
Enclave has following capabilities:

SDK usage. Victim enclave is devloped by official SGX SDK from intel. SDK is used by almost all realworld enclaves. 
It is development environment endorsed by intel. 

Randomized SGX memory. We assume enclave code is hardened by sophisticated mitigation technologies such as address space layout randomization.
enclave is protected by SGX-Shield. Currently only available ASLR for SGX. 

## The Guard's Dilemma

Novel Code Reuse Attack Against SGX

Technique is applicable to a wide range of vulnerabilities. => Stack overflow, Corrupting function pointers
Ultimate goal = execute sequence of gadgets without crashing victim enclave

Along the lines of any code reuse attack ROP 

However advantage: allow attacker to set all general purpose CPU registers before executing each gadget.
Register control is essential in any code-reuse attack. 

For instance, 
    Preparing data for subsequent gadgets
    Set argument for function calls

In contrast, existing code reuse attack on x86 require:
    attacker to use specific register setting gadgets to set registers (SGX makes this easier?)

Not requiring those gadgets have two benefits: 
    First, reduce amount of application code needed for successful code-reuse attack
    second, it simplifies the payload development since, attacker does not need to find pop gadgets for all relevent registers

    In fact, this attack allows attacker to use whole functions as gadgets. (Working at higher level)
    Making it easier to port exploit between different versions of a binary

Attack exploits functionality tRTS (fundamental library of SGXSDK)

Hence the dilemma:
    SDK is important part in creating secure enclaves, but in this case it is actually exposing them to attacks.

Two primitives are exploited:
    ORET primitive:
        First attack allows attacker to gain access to a critical set of CPU registers by exploiting a stack overflow vulnerability
    
    CONT primitive:
        Second attack is more powerful, allow attacker to gain access to all general purpose registers. Only requires control of a register. + this attack can combined with ORET primitive to apply it to controlled stack situations. 


    Basically: ORET==> Set of CPU Register (So only some) access by stack overflow
    CONT ==> All General-Purpose Registers Access by ??? (Not said) requires control of a register (x86_64: rdi) (Isn't rdi something to do with ret addr?)

## Overview and Attack Workflow

Description of exploit primitive + Attack workflow

### Exploitation Primitive 
Primitive + Preconditions

ORET primitive: 
    Abusing function asm_oret from tRTS library.
    asm_oret is used to restore CPU context after an OCALL(enclave calling untrusted function)
    Prerequisite: Control of instruction pointer (Hijack execution of asm_oret) and Control of stack content. (Any Stack overflow vulnerability)

    ORET primitive gives control of subset of CPU registers. Including registers that holds the first function argument (rdi) and the instruction pointer



```

root@ab15c6e9261c:/home/linuxsgx/sgxsdk/lib64# nm -C libsgx_trts_sim.a | grep oret
                 U do_oret
                 U asm_oret
0000000000000194 T do_oret
00000000000001eb T asm_oret
root@ab15c6e9261c:/home/linuxsgx/sgxsdk/lib64# nm -C libsgx_trts_sim.a | grep continue_execution
                 U continue_execution
00000000000002c2 T continue_execution


```
While evaluating sgx_1.6 trts library (it is compiled so I can't see detailed function definition)
We indeed can find asm_oret and continue_execution function (obviously 1.6 seems to be one of the versions the paper evaluated.)

```
nm: warning: libsgx_trts_sim.a(trts_pic.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010002
nm: warning: libsgx_trts_sim.a(trts_pic.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010001
00000000000002e7 T asm_oret
nm: warning: libsgx_trts_sim.a(metadata_sec.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010002
nm: warning: libsgx_trts_sim.a(metadata_sec.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010001
nm: warning: libsgx_trts_sim.a(xsave_gnu.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010002
nm: warning: libsgx_trts_sim.a(xsave_gnu.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010001

nm: warning: libsgx_trts_sim.a(restore_tls.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010002
nm: warning: libsgx_trts_sim.a(restore_tls.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010001
nm: warning: libsgx_trts_sim.a(trts_pic.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010002
nm: warning: libsgx_trts_sim.a(trts_pic.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010001
nm: 00000000000004cb T continue_execution
warning: libsgx_trts_sim.a(metadata_sec.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010002
nm: warning: libsgx_trts_sim.a(metadata_sec.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010001
nm: warning: libsgx_trts_sim.a(xsave_gnu.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010002
nm: warning: libsgx_trts_sim.a(xsave_gnu.o): unsupported GNU_PROPERTY_TYPE (5) type: 0xc0010001
```
Upon further inspection we find that the most recent version (sgx_2.18) also have both functions. Wonder if the vulnerability is fixed for these recent iterations (although I am not certain attack can be reproduced)

CONT primitive
    Abuse continue_execution from tRTS. It is meant to restore CPU context after an exception
    This primitive requires the ability to call that fnc (which one?) with a controlled rdi.

    Achievable from exploiting memory corruption vulnerability affecting a function pointer
    This yields full control for all general purpose CPU registers.

ORET+CONT 
    Idea:
    use CONT primitive repeatedly to invoke gadgets
    chain requires multiple CONT invocations ==> CONT require specific rdi value
    use ORET to set rdi and invoke CONT ==> ORET+CONT loop

    