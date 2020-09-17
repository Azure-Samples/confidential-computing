FROM ubuntu:18.04 as attested_tls

## Install tools required to install openenclave
RUN apt update; apt -y install wget gnupg python apt-transport-https libssl1.0.0 libssl-dev git make

## Adding the Intel and Microsoft repositories to apt
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | tee /etc/apt/sources.list.d/intel-sgx.list \
    && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | tee /etc/apt/sources.list.d/msprod.list \
    && wget -qO - https://packages.microsoft.com/keys/microsoft.asc | apt-key add -

RUN apt-get update && apt-get install -y \
    clang-7 \
    libssl-dev \
    gdb \
    libprotobuf10 \
    libsgx-dcap-ql \
    libsgx-quote-ex \
    az-dcap-client \
    open-enclave \
    gcc \
    g++

## Clone openenclave repo from github
RUN git clone https://github.com/microsoft/openenclave.git

## Set working directory & variables, make the sample
WORKDIR /openenclave/samples/attested_tls
RUN . /opt/openenclave/share/openenclave/openenclaverc \
    && export CC=gcc && export CXX=g++ && export PKG_CONFIG_PATH=/opt/openenclave/share/pkgconfig/ \
    && make

## The following sets the flag for out of proc attestation mode. Alternatively you can set this flag on the deployment files
ENV SGX_AESM_ADDR=1 

CMD make run-server-in-loop
