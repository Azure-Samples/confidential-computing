FROM ubuntu:18.04 as oe-attested-tls

ENV PSW_VERSION=2.11

RUN if [ -z "$PSW_VERSION" ]; then echo "Please set PSW_VERSION (e.g. 2.11)." >&2; exit 1; fi

RUN apt-get update && apt-get install -y \
    wget \
    gnupg

# Use the APT preference file to pin sgx packages to specific versions
# Reference https://manpages.debian.org/buster/apt/apt_preferences.5.en.html
# Download the pref file from https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/
# Assuming file name to follow *sgx_<PSW_VERSION>_bionic_custom_version.cfg convention
RUN ["/bin/bash", "-c", "wget -r -l1 --no-parent -nd -A *sgx_$(echo ${PSW_VERSION//./_})_bionic_custom_version.cfg https://download.01.org/intel-sgx/sgx_repo/ubuntu/apt_preference_files/"]
RUN ["/bin/bash", "-c", "mv *sgx_$(echo ${PSW_VERSION//./_})_bionic_custom_version.cfg /etc/apt/preferences.d/intel-sgx.pref"]

# Add the repository to sources, and add the key to the list of
# trusted keys used by the apt to authenticate packages
## Adding the Intel and Microsoft repositories to apt
RUN echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main" | tee /etc/apt/sources.list.d/intel-sgx.list \
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
    git

## Copy over the samples, Source openenclaverc, Set up environment variables, Make the attested-tls sample
RUN cp -R /opt/openenclave/share/openenclave/samples . \
&& . /opt/openenclave/share/openenclave/openenclaverc \ 
&& cd samples/attested_tls \
&& export CC=gcc && export CXX=g++ && export PKG_CONFIG_PATH=/opt/openenclave/share/pkgconfig/ \
&& make

WORKDIR /opt/openenclave/share/openenclave/samples/attested_tls

## The following sets the flag for out of proc attestation mode. Alternatively you can set this flag on the deployment files
ENV SGX_AESM_ADDR=1 

## Set the command to run the attested-tls sample
CMD make run-server-in-loop