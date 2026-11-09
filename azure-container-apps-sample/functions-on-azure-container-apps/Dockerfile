FROM mcr.microsoft.com/azure-functions/node:4-node24

ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true \
    FUNCTIONS_WORKER_RUNTIME=node

WORKDIR /home/site/wwwroot
COPY package.json package-lock.json ./
RUN node --version && npm ci --omit=dev
COPY host.json ./
COPY src ./src

EXPOSE 80
