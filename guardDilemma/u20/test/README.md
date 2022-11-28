# run
sudo docker build . -t sgx
sudo docker run -it sgx

# notes
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

SGX software are developed based on SGX SDK, as it abstracts