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
    lsb-release

WORKDIR /home/linuxsgx 
RUN git clone https://github.com/intel/linux-sgx.git
WORKDIR /home/linuxsgx/linux-sgx
RUN make preparation; \
     cp /home/linuxsgx/linux-sgx/external/toolset/ubuntu18.04/* /usr/local/bin; \
     make sdk DEBUG=1; \
     make sdk_install_pkg DEBUG=1
    #  cd linux/installer/bin && ./sgx_linux_x64_sdk_2.17.101.1.bin --prefix /home/linuxsgx/sdk
WORKDIR /home/linuxsgx/sdk
SHELL ["/bin/bash", "-c"]
RUN cd sgxsdk && source environment

