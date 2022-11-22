FROM ubuntu:16.04
RUN apt-get update && apt-get install -y \ 
    build-essential \ 
    ocaml \
    automake \
    autoconf \
    libtool \
    wget \
    python \
    libssl-dev \
    libcurl4-openssl-dev \
    protobuf-compiler \
    libprotobuf-dev \
    git

WORKDIR /home/linuxsgx 
RUN git clone https://github.com/intel/linux-sgx.git
WORKDIR /home/linuxsgx/linux-sgx
RUN git checkout tags/sgx_2.2; \
    ./download_prebuilt.sh; \
    cd sdk && make DEBUG=1; \
    cd .. && make sdk_install_pkg; \
    cd linux/installer/bin && echo yes | ./sgx_linux_x64_sdk_2.2.100.45311.bin
SHELL ["/bin/bash", "-c"]
RUN cd linux/installer/bin/sgxsdk && source environment

WORKDIR /home/linuxsgx
COPY . .
