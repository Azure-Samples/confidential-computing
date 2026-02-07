# Enclave Aware Container Samples (Intel SGX)

**Last Updated:** February 2026

## Overview

These samples demonstrate Intel SGX enclave-aware containers for Azure Kubernetes Service (AKS). Intel SGX provides hardware-based memory encryption and isolation for sensitive workloads.

> **Note:** For AMD SEV-SNP based confidential containers, see the [ACI Samples](../aci-samples/README.md) and [Multi-Party Samples](../multi-party-samples/README.md).

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│           Intel SGX Enclave Architecture                    │
├───────────────────────────────────────────────────────────┤
│                                                              │
│  ┌───────────────────────────────────────────────────┐   │
│  │                 Container Application                   │   │
│  │  ┌─────────────────────────────────────────────┐    │   │
│  │  │            Intel SGX Enclave                      │    │   │
│  │  │  ┌──────────────────┐  ┌──────────────────┐  │    │   │
│  │  │  │  Trusted Code    │  │  Sealed Data     │  │    │   │
│  │  │  │  (ECALLs)        │  │  (Encrypted)    │  │    │   │
│  │  │  └──────────────────┘  └──────────────────┘  │    │   │
│  │  │  Hardware Memory Encryption (MEE)               │    │   │
│  │  └─────────────────────────────────────────────┘    │   │
│  └───────────────────────────────────────────────────┘   │
│                                                              │
│  ┌───────────────────────────────────────────────────┐   │
│  │  AKS with Intel SGX Node Pool (DCsv2/DCsv3)            │   │
│  └───────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────┘
```

## Samples

The samples include Dockerfiles and Kubernetes YAML files for deploying enclave-aware applications to AKS with [confidential computing nodes](https://docs.microsoft.com/azure/confidential-computing/confidential-nodes-aks-get-started).

### [HelloWorld](helloworld/README.md)

Simple demonstration of enclave creation and function calls:
- Create an Intel SGX enclave
- Call trusted functions inside the enclave
- Print a hello world message from protected memory

### [Attested-TLS](attested-tls/README.md)

Secure communication channel between enclaves:
- Server enclave with TLS endpoint
- Client enclave verifying server attestation
- Mutual attestation handshake
- Encrypted communication channel

## Hardware Requirements

| VM Series | Hardware | Use Case |
|-----------|----------|----------|
| DCsv2 | Intel SGX | Legacy enclave workloads |
| DCsv3 | Intel SGX | Current enclave workloads |

## References

- [Intel SGX Overview](https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/overview.html)
- [AKS Confidential Computing Nodes](https://docs.microsoft.com/azure/confidential-computing/confidential-nodes-aks-get-started)
- [Open Enclave SDK](https://openenclave.io/sdk/)
