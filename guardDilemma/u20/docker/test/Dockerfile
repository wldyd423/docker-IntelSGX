#Using SGX_1.6 
#Paper mentions asm_oret function in tRTS library
#I can't locate it in recent version of SGX SDK
#ssh doesn't work for ubuntu14 (original target)
FROM ubuntu:14.04
RUN apt-get update && apt-get install -y \
    build-essential \
    ocaml \
    automake \
    autoconf \
    libtool \
    libcurl4-openssl-dev \
    protobuf-compiler \
    protobuf-c-compiler \
    libprotobuf-dev \
    libprotobuf-c0-dev \
    git \
    openssh-server \
    gdb

WORKDIR /home/linuxsgx 
RUN git clone https://github.com/intel/linux-sgx.git
WORKDIR /home/linuxsgx/linux-sgx
RUN git checkout tags/sgx_1.6; \
    ./download_prebuilt.sh; \
    cd sdk && make DEBUG=1; \
    cd .. && make sdk_install_pkg
WORKDIR /opt/intel
RUN echo yes | /home/linuxsgx/linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_1.6.100.34922.bin

#create ssh server (For Debugging)
RUN mkdir /var/run/sshd; \
    echo 'root:root' | chpasswd; \
    sed -i 's/StrictModes yes/#StrictModes yes/' /etc/ssh/sshd_config; \
    sed -i 's/#\?PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config

#sshd_config for ubuntu14 was different (format-wise)
#the rest seem to work the other way so reference other dockerfiles to do ssh

EXPOSE 22
#set password to root
#ssh root@10.0.1.77 (password root)
WORKDIR /home/linuxsgx
COPY . .

CMD ["/usr/sbin/sshd", "-D"]