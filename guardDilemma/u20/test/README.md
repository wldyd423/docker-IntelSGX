Tested on sgx_2.18 (Most Recent)

# run
sudo docker build . -t sgx
sudo docker run -it sgx

# Docker compose Run:
sudo docker-compose up -d --build
sudo docker-compose down 

sudo docker exec -it test_test_1 /bin/bash

## Ignore this part (SSH)
/usr/sbin/sshd (for ssh) (not working currently I don't know I don't care) (routing table host machine + virtual machine forwarding + ssh settings (tooooo much not even needed so .... ignore!))

sudo iptables -A FORWARD -i enp0s8 -o test_network -j ACCEPT
route add 10.0.1.0 MASK 255.255.255.0 192.168.56.101(virtual machine address)


