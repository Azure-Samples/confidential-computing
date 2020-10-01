# The helloworld sample

The sample source codes are from [the helloworld sample of the Open Enclave SDK](https://github.com/openenclave/openenclave/tree/master/samples/helloworld).

The corresponding docker image was published in Docker Hub. Please see [helloworld/Dockerfile](Dockerfile) for details of the docker image.

You can use this [helloworld.yaml](helm/templates/helloworld.yaml) file for your Azure Kubernetes Service deployment, it will deploy one job (oe-helloworld). You can also helm to deploy it by running the following command: helm install helloworld ./helm/ 
