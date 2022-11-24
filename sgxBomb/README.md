# sgxBomb 
# Not in paper but source code found

Uses SGX_2.2


### instructions

sudo docker build . -t sgx:bomb
sudo docker run -it -v /lib/modules:/lib/modules -v /usr/src:/usr/src sgx:bomb


sgxsdk in /home/linuxsgx/linux-sgx/linux/installer/bin/
move to /opt/intel and source environmnet

move Makefile into enclave of sgxbomb