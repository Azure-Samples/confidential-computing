# The helloworld sample

The sample source codes are from [the helloworld sample of the Open Enclave SDK](https://github.com/openenclave/openenclave/tree/master/samples/helloworld).

The corresponding docker image was published in Docker Hub. Please see [helloworld/Dockerfile](Dockerfile) for details of the docker image.

You can use this yaml file for your Azure Kubernetes Service deployment. There is one pod, oe-helloworld, which can be deployed by using [helloworld/helm/helloworld/templates/helloworld.yaml](helloworld/helm/helloworld/templates/helloworld.yam).
