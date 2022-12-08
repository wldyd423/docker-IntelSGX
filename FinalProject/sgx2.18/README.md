# Current 12/7/2022 latest SGX. SGX 2.18. More accurately this was tested with: 4cab8786899d737307d8d1719ea607d6def61a1a commit

# How to run
```
sudo ./up.sh
sudo docker exec -it sgx218_test_1 /bin/bash
sudo ./down.sh
```

## Once inside docker
```
root@...:/home/linuxsgx#  source /opt/intel/sgxsdk/environment
root@...:/home/linuxsgx# cd SampleEnclave
root@...:/home/linuxsgx/SampleEnclave# make SGX_MODE=SIM
root@...:/home/linuxsgx/SampleEnclave# ./app
```

## If Dockerfile Error occurs

This might occur because the docker git clones recent version of sgx.
It is however tested for SGX 2.18. Since SGX can be updated (and has updated) this might cause installation process or execution (within docker container) to not work. A simple fix would be using: git checkout sgx_2.18. As done for sgx1.6.

```
RUN git clone https://github.com/intel/linux-sgx.git
WORKDIR /home/linuxsgx/linux-sgx
RUN git checkout tags/sgx_1.6; \
```