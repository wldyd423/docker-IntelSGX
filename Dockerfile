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
RUN cd linux-sgx && make preparation
RUN cp external/toolset/ubuntu18.04/* /usr/local/bin
RUN make sdk DEBUG=1
RUN cd linux/installer/bin
    

