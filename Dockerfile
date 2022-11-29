# Built for intel-linux sgx for latest version: sgx_2.18
# If it does not build add git checkout sgx_2.18_reproducible or something
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
# Intel linux sgx was updated making this not work. Below (git checkout sgx_2.17_reproducible) is probable(?) solution
# TODO: Check if this actually runs (is it fixed?)
RUN git clone https://github.com/intel/linux-sgx.git; \
    git checkout sgx_2.17_reproducible
WORKDIR /home/linuxsgx/linux-sgx
RUN make preparation; \
     cp /home/linuxsgx/linux-sgx/external/toolset/ubuntu18.04/* /usr/local/bin; \
     make sdk DEBUG=1; \
     make sdk_install_pkg DEBUG=1; \
     cd linux/installer/bin && ./sgx_linux_x64_sdk_2.17.101.1.bin --prefix /home/linuxsgx/sdk
WORKDIR /home/linuxsgx/sdk
SHELL ["/bin/bash", "-c"]
RUN cd sgxsdk && source environment

