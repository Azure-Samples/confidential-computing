FROM ubuntu:18.04 as sgx_base
RUN apt-get update && apt-get install -y \
    wget \
    gnupg
## Adding the Intel and Microsoft repositories to apt
RUN echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main" | tee /etc/apt/sources.list.d/intel-sgx.list \
    && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | tee /etc/apt/sources.list.d/msprod.list \
    && wget -qO - https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
FROM sgx_base as oe_helloworld
RUN apt-get update && apt-get install -y \
    clang-7 \
    libssl-dev \
    gdb \
    libprotobuf10 \
    libsgx-dcap-ql \
    libsgx-quote-ex \
    az-dcap-client \
    open-enclave
RUN apt-get update && apt-get install -y git
## Copy over the samples, Source openenclaverc, Set up environment variables, Make the helloworld sample
RUN cp -R /opt/openenclave/share/openenclave/samples . \
&& . /opt/openenclave/share/openenclave/openenclaverc \
&& cd samples/helloworld && export CC=gcc && export CXX=g++ && export PKG_CONFIG_PATH=/opt/openenclave/share/pkgconfig/ \
&& make
## The following sets the flag for out of proc attestation mode. Alternatively you can set this flag on the deployment files
ENV SGX_AESM_ADDR=1 
## Set the command as the helloworld entry point binaries
CMD /samples/helloworld/host/helloworldhost /samples/helloworld/enclave/helloworldenc.signed
