FROM ubuntu:18.04
RUN apt-get update && apt-get install -y \
    build-essential \
    ocaml \
    ocamlbuild \
    automake \
    autoconf \
    libtool \
    wget \
    python \
    libssl-dev \
    git \
    cmake \
    perl \
    libssl-dev \
    libcurl4-openssl-dev \
    protobuf-compiler \
    libprotobuf-dev \
    debhelper \
    cmake \
    reprepro \
    unzip \
    lsb-release \
    openssh-server

WORKDIR /home/linuxsgx 
RUN git clone https://github.com/intel/linux-sgx.git
WORKDIR /home/linuxsgx/linux-sgx
RUN make preparation; \
     cp /home/linuxsgx/linux-sgx/external/toolset/ubuntu20.04/* /usr/local/bin; \
     make sdk DEBUG=1; \
     make sdk_install_pkg DEBUG=1; \
     cd linux/installer/bin && ./sgx_linux_x64_sdk_2.18.100.3.bin --prefix /home/linuxsgx/sdk
WORKDIR /home/linuxsgx/sdk
SHELL ["/bin/bash", "-c"]
RUN cd sgxsdk && source environment

#create ssh server (For Debugging)
RUN mkdir /var/run/sshd; \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
EXPOSE 22
#set password to root
#ssh root@10.0.1.77 (password root)
RUN echo 'root:root' | chpasswd

CMD ["/usr/sbin/sshd", "-D"]
