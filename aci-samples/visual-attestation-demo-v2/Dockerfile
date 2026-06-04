# Visual Attestation Demo v2 image for Azure Container Instances.
#
# Talks to the ACI SKR sidecar (mcr.microsoft.com/aci/skr) on localhost:8080
# to fetch a Microsoft Azure Attestation (MAA) JWT.
#
#   - ACI Confidential SKU + skr sidecar  -> attestation succeeds (sevsnpvm)
#   - ACI Standard   SKU (no sidecar)     -> attestation fails (educational)
#
# Built server-side by `az acr build`, no local Docker required.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SKR_SIDECAR_URL=http://localhost:8080 \
    PORT=80

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY templates/ /app/templates/

EXPOSE 80
CMD ["python", "/app/app.py"]
