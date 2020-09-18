# Enclave Aware Container Samples

The samples include respective Dockerfile and yaml files. You can use the Dockerfile to build sample application docker image, and push to Microsoft container registry or docker hub. You can use yaml file for your [Azure Kubernetes Service (AKS) deployments with confidential computing nodes](https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-aks-getstarted) .

## [HelloWorld](helloworld/README.md)

- Simple HelloWorld application to create an enclave and to call simple function inside enclave to print a hello world message.

## [Attested-TLS](attested-tls/README.md)

- This sample showcases two applications with one in an enclave that establishes an attested tls channel for communication between them.
