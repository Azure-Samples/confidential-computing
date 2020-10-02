# The attested_tls sample

The sample source codes are from [the attested_tls sample of the Open Enclave SDK](https://github.com/openenclave/openenclave/tree/master/samples/attested_tls).

The corresponding docker image was published in Docker Hub. Please see [attested_tls/Dockerfile](Dockerfile) for details of the docker image.

You can use yaml files for your Azure Kubernetes Service deployment. There are two pods, TLS server and TLS client. TLS server can be deployed by using [attested_tls_server.yaml](helm/server/templates/attested_tls_server.yaml). Before TLS client deployment, please populate external server IP in [attested_tls_client.yaml](helm/client/templates/attested_tls_client.yaml).

You can also use helm to deploy the TLS server, and then TLS client by running the following commands: \
*helm install tls-server ./helm/server/* \
*helm install tls-client ./helm/client/ --set server.ip=$(./helm/utils/get_server_ip.sh)* \
\
(get_server_ip.sh is an utility script which helps you to get external TLS server IP).
