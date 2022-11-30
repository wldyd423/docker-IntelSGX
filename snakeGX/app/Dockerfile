#Using SGX_2.11 (but custom version?)
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
    cmake \
    perl \
    libcurl4-openssl-dev \
    protobuf-compiler \
    libprotobuf-dev \
    debhelper \
    reprepro \
    unzip \
    git \
    openssh-server \
    gdb

WORKDIR /home/linuxsgx 
RUN git clone https://github.com/intel/linux-sgx.git
WORKDIR /home/linuxsgx/linux-sgx
RUN git checkout 33f44991; \
    make preparation; \
    cp external/toolset/ubuntu18.04/* /usr/local/bin; \
    make sdk DEBUG=1; \
    make sdk_install_pkg DEBUG=1; \
    cd linux/installer/bin && ./sgx_linux_x64_sdk_2.11.101.2.bin --prefix /opt/intel
WORKDIR /home/linuxsgx
RUN git clone https://github.com/tregua87/snakegx.git

    # cd sdk && make DEBUG=1; \
    # cd .. && make sdk_install_pkg; \
    # cd linux/installer/bin && echo yes | ./sgx_linux_x64_sdk_1.6.100.34922.bin; \
    # cp -r sgxsdk /home/linuxsgx 

#create ssh server (For Debugging)
RUN mkdir /var/run/sshd; \
    echo 'root:root' | chpasswd; \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
    # sed -i 's/StrictModes yes/#StrictModes yes/' /etc/ssh/sshd_config; \
    # sed -i 's/#\?PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config

#sshd_config for ubuntu14 was different (format-wise)
#the rest seem to work the other way so reference other dockerfiles to do ssh

EXPOSE 22
#set password to root
#ssh root@10.0.1.77 (password root)
# RUN sed -i 's/export SGX_SDK=\/home\/linuxsgx\/linux-sgx\/linux\/installer\/bin\/sgxsdk/export SGX_SDK=\/home\/linuxsgx\/sgxsdk/' /home/linuxsgx/sgxsdk/environment


CMD ["/usr/sbin/sshd", "-D"]