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
    lsb-release \
    openssh-server \
    gdb

WORKDIR /home/linuxsgx 
RUN git clone https://github.com/intel/linux-sgx.git
WORKDIR /home/linuxsgx/linux-sgx
RUN make preparation; \
     cp /home/linuxsgx/linux-sgx/external/toolset/ubuntu20.04/* /usr/local/bin; \
     make sdk DEBUG=1; \
     make sdk_install_pkg DEBUG=1; \
     cd linux/installer/bin && ./sgx_linux_x64_sdk*.bin --prefix /opt/intel
WORKDIR /home/linuxsgx

RUN mkdir /var/run/sshd; \
    echo 'root:root' | chpasswd; \
    sed -i 's/StrictModes yes/#StrictModes yes/' /etc/ssh/sshd_config; \
    sed -i 's/#\?PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config


EXPOSE 22
COPY . .

CMD ["/usr/sbin/sshd", "-D"]